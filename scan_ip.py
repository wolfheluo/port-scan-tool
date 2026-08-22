#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_ip.py — 單一 IP Port 風險自動化掃描（JSON 指令庫驅動版）
================================================================
依「常見port_測試指令.json」（72 port × 190 指令）自動化執行。

流程：
  1. 前置檢查（工具缺失 → 自動 apt-get install，失敗則跳過該測試）
  2. 載入 JSON 指令庫 → 轉換層（msf6> 解析、變數填充、已知修正、自動重試）
  3. 目標確認（顯示目標與測試數量，自動開始執行）
  4. nmap 偵測開啟 port（TCP top-1000∪表格埠∪web埠；UDP 表格內定點掃）
  5. 依 JSON 指令庫派發測試（--jobs 並行）
  6. 每測試判讀 PASS / WARN / RISK / FAIL / SKIP（每 port 關鍵字表）
  7. 產出 runs/<時間戳>_<IP>/ { scan.log, results.json, summary.txt, raw/*.txt }

用法：
  python3 scan_ip.py <IP> [--passwords FILE] [--userlist FILE] [--jobs N]
                       [--timeout N] [--no-install] [--out DIR]
                       [--gentle] [--user U] [--password P] [--full-port]
                       [--table FILE] [--dry-run]
                       [--check-tools] [--install-tools]

模式：
  - 預設（爆破）：爆破類指令載入完整字典（--passwords/--userlist）
  - --gentle：爆破類指令只嘗試單一帳密（--user/--password，預設 admin/password）
  - --dry-run：不連目標，逐一驗證 190 指令可執行性（binary + msf 模組載入）

安全邊界：
  - exploit 模組（java_rmi_server、cve_2021_38647_omigod）預設會執行；
    可用 --no-exploit 改為一律 SKIP
  - 只做觀測，不對目標寫入/刪除/修改
"""

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

BASE = Path(__file__).resolve().parent
RUNS = BASE / "runs"

# sudo 的 secure_path 常缺 /usr/local/bin（mongosh/odat/testssl 安裝處）
# → 啟動時自行補上，否則 sudo 跑掃描時這些工具會被誤判缺失
os.environ["PATH"] = "/usr/local/bin:" + os.environ.get("PATH", "")


def resolve_table(explicit):
    """--table 未指定時依序尋找: repo 目錄 → /root。回傳絕對路徑或 None。"""
    if explicit:
        return os.path.abspath(explicit)
    for cand in (BASE / "common_ports_test_commands.json",
                 Path("/root/common_ports_test_commands.json")):
        if cand.is_file():
            return str(cand)
    return None

# ---------------------------------------------------------------------------
# 工具 → 套件對照（缺失時 apt-get install；None = 不自動安裝）
# ---------------------------------------------------------------------------
TOOL_PACKAGES = {
    "nmap": None, "nc": None, "ncat": None, "hydra": None, "sslscan": None,
    "smbclient": None, "smbmap": None, "rpcclient": None, "mysql": None,
    "dnsrecon": None, "telnet": None, "msfconsole": None, "curl": None,
    "masscan": None, "nikto": None, "sqlmap": None, "enum4linux": None,
    "crackmapexec": None, "evil-winrm": None,
    "redis-cli": "redis-tools", "nbtscan": "nbtscan",
    "smtp-user-enum": "smtp-user-enum", "thc-pptp-bruter": "thc-pptp-bruter",
    "showmount": "nfs-common", "rpcinfo": "nfs-common",
    "snmpwalk": "snmp", "tftp": "tftp-hpa", "ntpq": "ntpsec",
    "ldapsearch": "ldap-utils", "dig": "dnsutils", "nmblookup": "samba-common-bin",
    "psql": "postgresql-client", "sqsh": "sqsh", "ipmitool": "ipmitool",
    "etcdctl": "etcd-client", "vncviewer": "tigervnc-viewer",
    "xfreerdp3": "freerdp3-x11",
    "rusers": "rusers", "onesixtyone": "onesixtyone", "ike-scan": "ike-scan",
    "proxychains4": "proxychains4", "swaks": "swaks",
    "impacket-rpcdump": "python3-impacket",
    "impacket-mssqlclient": "python3-impacket",
    "impacket-GetNPUsers": "python3-impacket",
}

# 無對應 apt 套件（Kali 專屬/外部 repo/手動安裝）→ 缺則 SKIP
NO_APT_TOOLS = {"snmp-check", "odat", "odat.py", "mongosh", "testssl.sh"}

# 分級 timeout（秒）：detect / scan / brute / interactive；--timeout 可整體覆蓋
TIMEOUTS = {"detect": 60, "scan": 120, "brute": 300, "interactive": 25}

# HTTP TRACE 測試的候選 web port（另加上 nmap 判為 http* 的 port）
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9080, 3000, 5000, 9090, 7001, 8161, 9000, 10000}

# 互動式工具（stdin 等待）→ 歸類 interactive，縮短 timeout
INTERACTIVE_BINS = {"sqsh", "psql", "tftp", "rlogin", "telnet", "vncviewer", "xfreerdp3", "mongosh"}

# 需圖形環境的工具（headless 直接 SKIP）
GUI_BINS = {"vncviewer", "xfreerdp3"}

# ---------------------------------------------------------------------------
# 已知修正（對照舊版 scan_ip README「Deviations from the Source Table」）
# 格式: (regex, replacement) 依序套用於原始指令字串
# ---------------------------------------------------------------------------
KNOWN_FIXES = [
    # msf 模組路徑 typo
    (r"auxiliary/sanner/", "auxiliary/scanner/"),
    (r"auxiliary/scanner/mysql/mssql_login", "auxiliary/scanner/mssql/mssql_login"),
    (r"use scanner/http/", "use auxiliary/scanner/http/"),
    (r"auxiliary/scanner/sip/option\b", "auxiliary/scanner/sip/options"),
    (r"scanner/sip/option\b", "scanner/sip/options"),
    # msf6> 前綴無空格
    (r"^msf6>\s*use", "msf6> use"),
    (r"^msf6\s*>\s*use", "msf6> use"),
    # nmap script 不存在
    (r"--script=msrpc-enum\b", "--script=msrpc-enum-users"),
    (r"--script msrpc-enum\b", "--script msrpc-enum-users"),
    # nbtscan-unixwiz → nbtscan
    (r"nbtscan-unixwiz", "nbtscan"),
    # impacket .py 後綴 → 系統 binary
    (r"impacket-rpcdump\.py", "impacket-rpcdump"),
    (r"impacket-mssqlclient\.py", "impacket-mssqlclient"),
    (r"impacket-GetNPUsers\.py", "impacket-GetNPUsers"),
    # msf 模組不存在 → 改用實際存在的模組
    (r"auxiliary/scanner/http/ajp_requests", "auxiliary/admin/http/tomcat_ghostcat"),
    (r"auxiliary/scanner/http/webmin_login", "auxiliary/admin/webmin/file_disclosure"),
    # omigod 原文缺 exploit/ 前綴 → 補上（預設會執行 exploit 模組）
    (r"linux/misc/cve_2021_38647_omigod", "exploit/linux/misc/cve_2021_38647_omigod"),
    # nc 舊式旗標 → -w 5（不用 -n：hostname 目標會被 -n 擋下 Can't parse）
    (r"nc -nvc ", "nc -w 5 "),
    (r"nc -ncv ", "nc -w 5 "),
    (r"nc -nvc\b", "nc -w 5"),
    (r"nc -nv ", "nc -w 5 "),  # 無 -w 的 nc 會等 stdin 逾時
    # nc 缺 port（表格 25 原文 nc -nvc {IP}）→ 補 {PORT}
    (r"nc -w 5 \{IP\}$", "nc -w 5 {IP} {PORT}"),
    (r"nc -n -w 5 ", "nc -w 5 "),  # 殘留 -n 一律剝除
    # netcat-traditional 的 -w 不可靠（tty 下停用、實測約 2x 失真）→ GNU timeout 硬包
    (r"^nc -w 5 ", "timeout 8 nc "),
    # redis-cli 無子指令 → 補 PING（避免進入互動模式卡死）
    (r"^redis-cli -h \{IP\} -p (\d+|\{PORT\})$", r"redis-cli -h {IP} -p \1 PING"),
    # mysql -p（互動式密碼提示）→ 溫和模式單一密碼
    (r" -p -P ", " -p{PASSWORD} -P "),
    (r" -p$", " -p{PASSWORD}"),
    # MySQL 8 預設 TLS：client 驗證不了伺服器憑證會直接 ERROR 2026 卡住測試
    # 用 --skip-ssl（MySQL 與 MariaDB client 都支援；--ssl-mode 只有 MySQL client 認）
    (r"^mysql -h \{IP\} -u ", "mysql -h {IP} --skip-ssl -u "),
    # onesixtyone 需要 dict.txt → 改用內建社群字串清單
    (r"onesixtyone -c dict\.txt", "onesixtyone"),
    # openssl s_client 互動 → 包 echo 餵 stdin EOF + timeout 硬上限（993/995 伺服器不關連線會掛 60s）
    (r"^openssl s_client ", "echo | timeout 12 openssl s_client "),
    # sslscan 指令庫把「或」混進指令字串（{IP}or{IP} / {IP} 或 sslscan ...）→ 取有效形式
    (r"sslscan \{IP\}or\{IP\}:\{PORT\}", "sslscan {IP}:{PORT}"),
    (r"sslscan \{IP\} 或 sslscan \{IP\}:\{PORT\}", "sslscan {IP}:{PORT}"),
    # 表格「->註解」（如 ->SSL憑證資訊）會被 bash 當重新導向 → 剝除
    (r"\s+->\s*[^\s]*$", ""),
    # 多餘空白
    (r"\s{2,}", " "),
]

# 自動重試修正規則（msf 模組載入失敗時依序嘗試）
MSF_RETRY_FIXES = [
    lambda m: m,
    lambda m: "auxiliary/" + m if not m.startswith(("auxiliary/", "exploit/")) else m,
    lambda m: "exploit/" + m if not m.startswith(("auxiliary/", "exploit/")) else m,
    lambda m: m.replace("auxiliary/sanner/", "auxiliary/scanner/"),
    lambda m: m.replace("scanner/mysql/mssql_login", "scanner/mssql/mssql_login"),
    lambda m: m.replace("scanner/sip/option", "scanner/sip/options"),
    lambda m: m.replace("scanner/http/jboss_vulnscan", "auxiliary/scanner/http/jboss_vulnscan"),
]

# exploit 模組（絕不執行）
EXPLOIT_MARKERS = ("exploit/", "omigod", "cve_2021_38647", "java_rmi_server")

log_lock = threading.Lock()


def log_line(log_path, text):
    """執行緒安全的流水帳寫入（scan.log + stdout）。"""
    line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), text)
    with log_lock:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        print(line, flush=True)


# ---------------------------------------------------------------------------
# JSON 指令庫載入 + 轉換層
# ---------------------------------------------------------------------------
def load_library(path):
    """載入 JSON 指令庫，回傳 (ports_meta, groups)。
    groups: {port_key(str): {"name":..., "commands":[cmd_str,...], "note":...}}
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("錯誤: JSON 指令庫不存在: %s" % path)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("錯誤: JSON 指令庫格式錯誤 %s: %s" % (path, e))
        sys.exit(1)
    groups = {}
    for p in data.get("ports", []):
        groups[str(p["port"])] = {
            "name": p.get("name", ""),
            "commands": list(p.get("commands", [])),
            "note": p.get("note", ""),
        }
    return data, groups


def fix_command(cmd):
    """套用已知修正 + 正規化，回傳修正後指令字串。"""
    out = cmd
    for pat, repl in KNOWN_FIXES:
        out = re.sub(pat, repl, out)
    return out.strip()


def parse_msf_module(cmd):
    """從 'msf6> use <module>' 解析模組路徑；非 msf 指令回傳 None。"""
    m = re.match(r"^\s*msf6>\s*use\s+(\S+)", cmd)
    return m.group(1) if m else None


def is_login_module(mod):
    return "_login" in mod


def is_exploit_module(mod):
    return any(mk in mod.lower() for mk in EXPLOIT_MARKERS)


def msf_to_argv(mod, ip, port, user, password, userlist, passwords, gentle):
    """msf6> 指令 → msfconsole argv。
    一律用 USER_FILE/PASS_FILE（溫和模式時 cfg 已指向單行臨時檔，只試一組）。
    """
    cmds = ["use %s" % mod, "set RHOSTS %s" % ip]
    if port:
        cmds.append("set RPORT %d" % port)
    if is_login_module(mod):
        cmds.append("set USER_FILE %s" % userlist)
        cmds.append("set PASS_FILE %s" % passwords)
        cmds.append("set STOP_ON_SUCCESS true")
    cmds += ["run", "exit"]
    return ["msfconsole", "-q", "-x", "; ".join(cmds)]


def classify_kind(cmd, mod=None):
    """依指令內容分類 timeout 等級。"""
    low = cmd.lower()
    if mod and is_login_module(mod):
        return "brute"
    if any(k in low for k in ("hydra ", "hydra-", "thc-pptp-bruter", "snmp-brute",
                              "pgsql-brute", "oracle-sid-brute", "onesixtyone")):
        return "brute"
    if any(k in low for k in ("nmap ", "sslscan", "dnsrecon", "ike-scan", "crackmapexec",
                              "enum4linux", "showmount", "rpcinfo", "impacket-",
                              "dig ", "testssl", "swaks")):
        return "scan"
    return "detect"


# ---------------------------------------------------------------------------
# 每 port 關鍵字表（分級判讀用）
# risk: 命中 = RISK；warn: 命中 = WARN；皆無 = PASS
# ---------------------------------------------------------------------------
GENERIC_KEYWORDS = {
    "risk": [r"(?<!NOT )vulnerable", r"CVE-\d{4}", r"login successful", r"\[SUCCESS\]",
             r"anonymous", r"no auth", r"none auth", r"unauthorized",
             r"public", r"PONG"],
    "warn": [r"banner", r"version", r"220 ", r"\+OK", r"exists", r"valid",
             r"title", r"server", r"200 OK", r"timed out", r"no response",
             r"connection refused", r"connect error", r"cracking protection"],
}

PORT_KEYWORDS = {
    21: {"risk": [r"anonymous ftp login allowed", r"anonymous.*logged in",
                  r"login:\s*\S+\s*password:", r"\[SUCCESS\]"],
         "warn": [r"ftp", r"220 "]},
    22: {"risk": [r"login:\s*\S+\s*password:", r"\[SUCCESS\]", r"login successful"],
         "warn": [r"kex_algorithms", r"encryption_algorithms", r"compression_algorithms",
                  r"ssh-"]},
    23: {"risk": [r"login:\s*\S+\s*password:", r"\[SUCCESS\]", r"login successful"],
         "warn": [r"telnet", r"login:"]},
    25: {"risk": [r"(?<!NOT )vulnerable", r"cve-\d{4}-\d+", r"is vulnerable"],
         "warn": [r"250", r"220 ", r"esmtp", r"smtp", r"exists", r"valid"]},
    53: {"risk": [r"zone transfer was successful", r"transfer successful", r"recursion"],
         "warn": [r"nsid", r"id\.server", r"SOA", r"NS\s", r"records"]},
    69: {"risk": [r"writable"],
         "warn": [r"tftp"]},
    80: {"risk": [r"DEBUG.{0,10}enabled"],
         "warn": [r"HTTP/1\.[01]", r"title", r"server:", r"200 OK"]},
    "80,443": {"risk": [r"DEBUG.{0,10}enabled"],
               "warn": [r"HTTP/1\.[01]", r"title", r"server:"]},
    88: {"risk": [r"AS-REP", r"has AS-REP"],
         "warn": [r"krb5", r"realm"]},
    110: {"risk": [r"login successful", r"successful", r"\+ .*:110 - .*success"],
          "warn": [r"\+OK", r"ready"]},
    111: {"risk": [],
          "warn": [r"program", r"portmapper", r"nfs", r"mountd", r"server:"]},
    123: {"risk": [r"monlist", r"MONLIST"],
          "warn": [r"ntp", r"ntpq"]},
    135: {"risk": [r"domain users", r"users:"],
          "warn": [r"computer name", r"server", r"domain", r"hidden", r"protocol",
                   r"endpoint", r"remote procedure call"]},
    139: {"risk": [r"sharename", r"disk\s", r"IPC\$"],
          "warn": [r"\d+\.\d+\.\d+\.\d+\s+\S+", r"netbios"]},
    161: {"risk": [r"public", r"private", r"community"],
          "warn": [r"snmp", r"iso\.", r"system"]},
    179: {"risk": [],
          "warn": [r"bgp", r"open"]},
    389: {"risk": [],
          "warn": [r"namingContexts", r"ldap", r"dc=", r"rootDSE"]},
    443: {"risk": [r"SSLv2\s*(enabled|:)", r"SSLv3\s*(enabled|:)", r"TLSv1\.0\s*(enabled|:)",
                   r"TLSv1\.1\s*(enabled|:)"],
          "warn": [r"self-signed", r"not valid after", r"subject", r"accepted",
                   r"least strength", r"tlsv1"]},
    445: {"risk": [r"SMBv1", r"MS17-010", r"VULNERABLE", r"READ", r"WRITE",
                   r"sharename", r"disk\s", r"IPC\$"],
          "warn": [r"computer name", r"os:", r"workgroup", r"server:\[",
                   r"hostname", r"smb"]},
    500: {"risk": [r"PSK"],
          "warn": [r"ike", r"ISAKMP"]},
    512: {"risk": [],
          "warn": [r"login", r"rusers"]},
    513: {"risk": [],
          "warn": [r"login", r"root"]},
    514: {"risk": [],
          "warn": [r"syslog", r"rsh"]},
    515: {"risk": [],
          "warn": [r"lpd", r"printer"]},
    548: {"risk": [],
          "warn": [r"afp", r"serverinfo"]},
    623: {"risk": [r"admin"],
          "warn": [r"ipmi", r"version"]},
    636: {"risk": [],
          "warn": [r"namingContexts", r"ldap", r"subject", r"ssl"]},
    873: {"risk": [r"writable", r"\S+@\S+"],
          "warn": [r"rsync", r"module"]},
    993: {"risk": [],
          "warn": [r"ssl", r"imap", r"subject"]},
    995: {"risk": [],
          "warn": [r"ssl", r"pop3", r"subject"]},
    1080: {"risk": [r"open proxy", r"PROXY"],
           "warn": [r"socks"]},
    1099: {"risk": [r"classloader", r"vulnerable"],
           "warn": [r"rmi", r"java"]},
    1194: {"risk": [],
           "warn": [r"openvpn"]},
    1352: {"risk": [],
           "warn": [r"domino", r"users"]},
    1433: {"risk": [r"login successful", r"successful", r"xp_cmdshell", r"empty password"],
           "warn": [r"mssql", r"version", r"sa"]},
    1521: {"risk": [r"SID"],
           "warn": [r"oracle"]},
    1723: {"risk": [r"success", r"authenticated", r"CHAP.*OK"],
           "warn": [r"MSCHAP", r"pptp"]},
    1883: {"risk": [r"subscribe"],
           "warn": [r"mqtt"]},
    2049: {"risk": [r"^/", r"export"],
           "warn": [r"nfs", r"mountd"]},
    2181: {"risk": [],
           "warn": [r"zookeeper", r"envi"]},
    2375: {"risk": [r"ApiVersion", r"version"],
           "warn": [r"docker"]},
    2379: {"risk": [],
           "warn": [r"etcd", r"health"]},
    3000: {"risk": [r"admin"],
           "warn": [r"grafana", r"title"]},
    3128: {"risk": [r"open proxy", r"PROXY"],
           "warn": [r"squid"]},
    3268: {"risk": [],
           "warn": [r"ldap", r"GC"]},
    3306: {"risk": [r"VERSION\(", r"^\d+\.\d+", r"login successful"],
           "warn": [r"access denied", r"ERROR 1045", r"mysql"]},
    3389: {"risk": [r"login:\s*\S+\s*password:", r"\[SUCCESS\]",
                    r"SSLv2\s*(enabled|:)", r"SSLv3\s*(enabled|:)", r"TLSv1\.0\s*(enabled|:)",
                    r"TLSv1\.1\s*(enabled|:)"],
           "warn": [r"least strength", r"ntlm", r"rdp"]},
    4369: {"risk": [],
           "warn": [r"erlang", r"rabbitmq"]},
    5000: {"risk": [r"docker registry", r"ApiVersion"],
           "warn": [r"title", r"http"]},
    5060: {"risk": [r"200 OK", r"trying"],
           "warn": [r"SIP device", r"sip"]},
    5432: {"risk": [r"login successful", r"successful"],
           "warn": [r"postgres", r"psql"]},
    5601: {"risk": [],
           "warn": [r"kibana", r"title"]},
    5672: {"risk": [r"guest"],
           "warn": [r"amqp", r"rabbitmq"]},
    5900: {"risk": [r"None[- ]Auth", r"login success", r"successful"],
           "warn": [r"vnc", r"title", r"protocol version"]},
    5985: {"risk": [],
           "warn": [r"401", r"WS-Man", r"200"]},
    6379: {"risk": [r"PONG", r"redis_version"],
           "warn": [r"NOAUTH", r"DENIED", r"ERR", r"redis"]},
    7001: {"risk": [r"console"],
           "warn": [r"weblogic", r"title"]},
    8009: {"risk": [r"ajp", r"ghostcat"],
           "warn": [r"ajp"]},
    8080: {"risk": [],
           "warn": [r"HTTP/1\.[01]", r"tomcat", r"jenkins", r"title", r"server:"]},
    8161: {"risk": [],
           "warn": [r"activemq", r"title"]},
    8443: {"risk": [r"SSLv2\s*(enabled|:)", r"SSLv3\s*(enabled|:)", r"TLSv1\.0\s*(enabled|:)",
                    r"TLSv1\.1\s*(enabled|:)"],
           "warn": [r"self-signed", r"least strength"]},
    8888: {"risk": [],
           "warn": [r"jupyter", r"title"]},
    9000: {"risk": [],
           "warn": [r"title", r"http"]},
    9080: {"risk": [r"vulnerable", r"CVE-\d{4}", r"jmx", r"admin-console"],
           "warn": [r"JBoss", r"title"]},
    9092: {"risk": [],
           "warn": [r"kafka"]},
    9200: {"risk": [r"indices", r"open"],
           "warn": [r"elasticsearch", r"cluster_name"]},
    10000: {"risk": [r"login successful", r"successful"],
            "warn": [r"webmin", r"title"]},
    11211: {"risk": [r"STAT"],
            "warn": [r"memcached"]},
    27017: {"risk": [r"ok"],
            "warn": [r"mongodb", r"version"]},
    50070: {"risk": [],
            "warn": [r"namenode", r"dfshealth"]},
    61616: {"risk": [],
            "warn": [r"activemq", r"openwire"]},
}


def keywords_for(port_key):
    """依 port key 取關鍵字表（含 '80,443' 字串鍵與 int 鍵）。"""
    for k in (port_key, int(port_key) if str(port_key).isdigit() else None):
        if k is not None and k in PORT_KEYWORDS:
            return PORT_KEYWORDS[k]
    return GENERIC_KEYWORDS


# ---------------------------------------------------------------------------
# 測試組裝
# ---------------------------------------------------------------------------
def trace_test(port):
    """HTTP TRACE / TRACK 測試（動態 port 版，取代 JSON 的 telnet 交談文字）。"""
    scheme = "https" if port in (443, 8443) else "http"
    return {
        "name": "http-trace", "kind": "detect", "argv": None,
        "cmd": "curl -s -i -k --max-time 10 -X TRACE %s://%s:%d/" % (scheme, "{IP}", port),
        "risk": [r"HTTP/1\.[01] 200"],
        "warn": [r"HTTP/1\.[01] 405", r"HTTP/1\.[01] 501", r"not allowed", r"not implemented"],
        "src": "表格: HTTP TRACE — telnet {IP} {PORT} + TRACE / HTTP/1.1（以 curl -X TRACE 取代）",
        "timeout": 30, "mod": None, "needs_domain": False,
    }


def build_commands_for_port(port, groups, cfg, gentle):
    """為指定 port 組裝測試清單。
    回傳 list of dict: {name, kind, argv|cmd, mod, src, risk, warn, timeout,
                        needs_domain, skip_reason}
    """
    tests = []
    port_key = str(port)
    candidates = []
    # 1. 精確 port key 對應（含 "80,443" 逗號展開）
    for key, g in groups.items():
        if key == port_key:
            candidates.append((key, g))
        elif "," in key and port_key in [x.strip() for x in key.split(",")]:
            candidates.append((key, g))

    seen = set()
    for key, g in candidates:
        kw = keywords_for(key)
        for idx, raw_cmd in enumerate(g["commands"]):
            cmd = fix_command(raw_cmd)
            mod = parse_msf_module(cmd)
            # exploit 模組：預設執行；--no-exploit 時 SKIP
            if mod and is_exploit_module(mod):
                if cfg.get("no_exploit"):
                    tests.append({
                        "name": "msf-%s" % mod.rsplit("/", 1)[-1], "kind": "scan",
                        "argv": None, "cmd": "", "mod": mod, "src": raw_cmd,
                        "risk": [], "warn": [], "timeout": 60,
                        "skip_reason": "exploit 模組不執行（--no-exploit）",
                    })
                    continue
                # 執行模式：當一般模組處理（timeout 覆寫在 classify_kind 之後）
            # 非指令（telnet 交談文字等）→ 跳過（HTTP TRACE 另以 curl 取代）
            if cmd.startswith(("TRACE ", "Host:", "(", "修補:")) or cmd == "":
                continue
            # GUI 工具 → SKIP
            bin0 = extract_bin0(cmd)
            if mod and not bin0:
                bin0 = "msf-%s" % mod.rsplit("/", 1)[-1]
            if not bin0:
                continue  # 中文說明行
            if bin0 in GUI_BINS:
                tests.append({
                    "name": "gui-%s" % bin0, "kind": "detect", "argv": None,
                    "cmd": cmd, "mod": None, "src": raw_cmd, "risk": [], "warn": [],
                    "timeout": 10, "skip_reason": "需圖形環境（headless 環境 SKIP）",
                })
                continue
            name = "%02d-%s" % (idx + 1, bin0 or "cmd")
            if name in seen:
                name = name + "-%d" % idx
            seen.add(name)
            needs_domain = "{DOMAIN}" in raw_cmd
            kind = classify_kind(cmd, mod)
            timeout = TIMEOUTS.get(kind, 60)
            if mod and is_exploit_module(mod):
                kind = "scan"  # exploit 模組預設執行，給予較長 timeout
                timeout = max(timeout, 120)
            if bin0 in INTERACTIVE_BINS:
                kind = "interactive"
                timeout = TIMEOUTS["interactive"]
            if "enum4linux" in cmd:
                timeout = 300
            if kind == "brute" and gentle:
                timeout = min(timeout, 90)  # 溫和模式單一帳密，不需要 300s
            tests.append({
                "name": name, "kind": kind, "argv": None, "cmd": cmd, "mod": mod,
                "src": raw_cmd, "risk": kw["risk"], "warn": kw["warn"],
                "timeout": timeout, "needs_domain": needs_domain, "skip_reason": None,
            })

    return tests


def extract_bin0(cmd):
    """從指令字串取第一個 binary 名稱。
    處理: env 前綴（ETCDCTL_API=3 cmd）、中文說明行、msf6> 前綴。
    """
    c = cmd.strip()
    if not c or not re.search(r"[A-Za-z]", c):
        return ""
    if c.startswith(("TRACE ", "Host:", "(", "修補:", "msf6>", "msf6 >")):
        return ""
    toks = c.split()
    # timeout N <bin> ... → 剝掉包裝前綴，取真實 binary（測試名與缺失檢查用）
    if toks and toks[0] == "timeout" and len(toks) > 2 and toks[1].isdigit():
        toks = toks[2:]
    for t in toks:
        if "=" in t and not t.startswith(("/", "-", "{", "http")):
            continue  # env 前綴
        if t.startswith(("msf6", "{", "-")):
            continue
        return t.split("/")[-1]
    return toks[0].split("/")[-1] if toks else ""


# ---------------------------------------------------------------------------
# 工具安裝（--install-tools / --check-tools）
# ---------------------------------------------------------------------------
# TOOL_PACKAGES 標 None（Kali 預裝）但在 Kali/Debian 其實有套件的
# 值為候選套件清單（依序嘗試，裝到第一個成功）
KALI_APT = {
    "crackmapexec": ["crackmapexec"],
    "ncat": ["ncat", "nmap"],
    "msfconsole": ["metasploit-framework"],
    "nikto": ["nikto"],
    "sqlmap": ["sqlmap"],
    "enum4linux": ["enum4linux"],
    "evil-winrm": ["evil-winrm"],
    "smbclient": ["smbclient"],
    "smbmap": ["smbmap"],
    "rpcclient": ["samba-common-bin"],
    "sslscan": ["sslscan"],
    "hydra": ["hydra"],
    "nmap": ["nmap"],
    "nc": ["netcat-openbsd"],
    "curl": ["curl"],
    "masscan": ["masscan"],
    "dnsrecon": ["dnsrecon"],
    "telnet": ["telnet"],
    "snmp-check": ["snmpcheck"],
    "rlogin": ["rsh-redone-client", "rsh-client"],
}

# 無 apt 來源 → 特殊安裝函式
SPECIAL_INSTALLERS = {
    "mongosh": "_install_mongosh",
    "odat": "_install_odat",
    "odat.py": "_install_odat",
    "testssl.sh": "_install_testssl",
}

# 安裝位置（/usr/local/bin 或 /opt），供 PATH 之外的最終判定
INSTALL_PATHS = {
    "mongosh": ("/usr/local/bin/mongosh",),
    "odat": ("/opt/odat/odat.py",),
    "odat.py": ("/opt/odat/odat.py",),
    "testssl.sh": ("/opt/testssl.sh/testssl.sh",),
}


def _is_tool_installed(bin_name):
    if shutil.which(bin_name):
        return True
    return any(os.access(p, os.X_OK) for p in INSTALL_PATHS.get(bin_name, ()))


def _sudo_cmd(cmd):
    """非 root 時自動加 sudo 前綴。"""
    if os.geteuid() == 0:
        return cmd
    if shutil.which("sudo"):
        return ["sudo"] + cmd
    print("錯誤: 需要 root 或 sudo 才能執行: %s" % " ".join(cmd))
    sys.exit(1)


def _run_install_cmd(cmd, timeout=600):
    print("[install] $ %s" % " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.stdout.strip():
        print("[install]   " + r.stdout.strip()[-500:], flush=True)
    if r.stderr.strip():
        print("[install]   ! " + r.stderr.strip()[-500:], flush=True)
    return r


def _http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "port-scan-tool"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def _install_mongosh():
    if _is_tool_installed("mongosh"):
        return
    print("[install] 安裝 mongosh（MongoDB 官方 tgz，查最新版號）...", flush=True)
    api = "https://api.github.com/repos/mongodb-js/mongosh/releases/latest"
    tag = json.loads(_http_get(api).decode()).get("tag_name", "").lstrip("v")
    if not re.match(r"^\d+\.\d+\.\d+", tag):
        print("[install] 錯誤: 無法取得 mongosh 最新版號（%r）" % tag, flush=True)
        return
    url = "https://downloads.mongodb.com/compass/mongosh-%s-linux-x64.tgz" % tag
    print("[install] 下載 %s" % url, flush=True)
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "mongosh.tgz"
        tgz.write_bytes(_http_get(url, timeout=120))
        out = Path(td) / "extract"
        out.mkdir()
        with tarfile.open(tgz) as t:
            t.extractall(out, filter="data")
        bins = list(out.rglob("bin/mongosh"))
        if not bins:
            print("[install] 錯誤: tgz 內找不到 bin/mongosh", flush=True)
            return
        _run_install_cmd(_sudo_cmd(["install", "-m", "755", str(bins[0]),
                                    "/usr/local/bin/mongosh"]))
    print("[install] mongosh 安裝完成" if _is_tool_installed("mongosh")
          else "[install] mongosh 安裝失敗", flush=True)


def _install_odat():
    if _is_tool_installed("odat.py"):
        return
    dest = Path("/opt/odat")
    print("[install] 安裝 odat（clone quentinhardy/odat → %s）..." % dest, flush=True)
    if not (dest / ".git").exists():
        _run_install_cmd(_sudo_cmd(["git", "clone", "--depth", "1",
                                    "https://github.com/quentinhardy/odat.git", str(dest)]),
                         timeout=600)
    req = dest / "requirements.txt"
    if req.exists():
        r = _run_install_cmd(_sudo_cmd(["pip3", "install", "-r", str(req),
                                        "--break-system-packages"]), timeout=600)
        if r.returncode != 0:
            print("[install] 警告: odat 依賴安裝未完全成功（掃描時 odat 測試可能無法執行）", flush=True)
    if not shutil.which("odat.py"):
        _run_install_cmd(_sudo_cmd(["ln", "-sf", str(dest / "odat.py"),
                                    "/usr/local/bin/odat.py"]))
    print("[install] odat 安裝完成" if _is_tool_installed("odat.py")
          else "[install] odat 安裝失敗", flush=True)


def _install_testssl():
    if _is_tool_installed("testssl.sh"):
        return
    dest = Path("/opt/testssl.sh")
    print("[install] 安裝 testssl.sh（clone testssl/testssl.sh → %s）..." % dest, flush=True)
    if not (dest / ".git").exists():
        _run_install_cmd(_sudo_cmd(["git", "clone", "--depth", "1",
                                    "https://github.com/testssl/testssl.sh.git", str(dest)]),
                         timeout=600)
    if not shutil.which("testssl.sh"):
        _run_install_cmd(_sudo_cmd(["ln", "-sf", str(dest / "testssl.sh"),
                                    "/usr/local/bin/testssl.sh"]))
    print("[install] testssl.sh 安裝完成" if _is_tool_installed("testssl.sh")
          else "[install] testssl.sh 安裝失敗", flush=True)


def install_tools_main(check_only=False):
    """--install-tools / --check-tools 入口。回傳 True = 全部齊全。"""
    all_bins = list(TOOL_PACKAGES) + list(NO_APT_TOOLS)
    missing = sorted({b for b in all_bins if not _is_tool_installed(b)})
    if not missing:
        print("所有工具都已安裝，無需動作。")
        return True
    print("缺失工具 (%d): %s" % (len(missing), ", ".join(missing)))
    if check_only:
        return False

    apt_missing = [b for b in missing if b not in SPECIAL_INSTALLERS]
    special = [b for b in missing if b in SPECIAL_INSTALLERS]
    print("  將以 apt 安裝: %s" % (", ".join(apt_missing) or "（無）"))
    print("  將以特殊來源安裝: %s" % (", ".join(special) or "（無）"))

    # apt 安裝（依序嘗試候選套件，第一個成功即停）
    _run_install_cmd(_sudo_cmd(["apt-get", "update", "-qq"]), timeout=600)
    installed_pkgs = set()
    for b in apt_missing:
        cands = TOOL_PACKAGES.get(b) or KALI_APT.get(b) or []
        if isinstance(cands, str):
            cands = [cands]
        for c in cands:
            if not c or c in installed_pkgs:
                continue
            r = _run_install_cmd(_sudo_cmd(["apt-get", "install", "-y", c]), timeout=600)
            if r.returncode == 0:
                installed_pkgs.add(c)
                break

    # 特殊來源
    for b in special:
        globals()[SPECIAL_INSTALLERS[b]]()

    # 中文字體（PNG 匯出中文渲染用；fonts-noto-cjk 非 binary，單獨處理）
    cjk_font_paths = PNG_FONT_CANDIDATES[:8]
    if not any(Path(p).exists() for p in cjk_font_paths):
        print("[install] 安裝中文字體 fonts-noto-cjk（PNG 匯出中文渲染）...", flush=True)
        _run_install_cmd(_sudo_cmd(["apt-get", "install", "-y", "fonts-noto-cjk"]), timeout=600)

    print("\n=== 安裝結果 ===")
    ok = True
    for b in sorted(missing):
        if _is_tool_installed(b):
            print("  [OK]   %s" % b)
        else:
            ok = False
            print("  [FAIL] %s" % b)
    return ok


# ---------------------------------------------------------------------------
# 前置檢查
# ---------------------------------------------------------------------------
def preflight(no_install, log_path):
    missing = [b for b in TOOL_PACKAGES if not _is_tool_installed(b)]
    missing += [b for b in NO_APT_TOOLS if not _is_tool_installed(b)]
    missing = sorted(set(missing))
    if not missing:
        log_line(log_path, "工具檢查: 全部齊全")
        return set()
    if no_install:
        log_line(log_path, "工具檢查: 缺少 %s（--no-install 已指定，相關測試將跳過）" % ", ".join(missing))
        return set(missing)
    # 三分類: apt 可裝 / 特殊安裝器 / 無安裝途徑（→ SKIP）
    apt_missing, special_missing, no_path_missing = [], [], []
    for b in missing:
        cands = TOOL_PACKAGES.get(b) or KALI_APT.get(b) or []
        if isinstance(cands, str):
            cands = [cands]
        if cands:
            apt_missing.append(b)
        elif b in SPECIAL_INSTALLERS:
            special_missing.append(b)
        else:
            no_path_missing.append(b)
    for b in no_path_missing:
        log_line(log_path, "工具 %s 缺失（無安裝途徑）→ 相關測試 SKIP" % b)
    if not (apt_missing or special_missing):
        log_line(log_path, "工具檢查: 缺少 %s（無可自動安裝之套件）→ 相關測試將跳過" % ", ".join(no_path_missing))
        return set(no_path_missing)
    # root/sudo 門檻: apt 與特殊安裝器都需要（特殊安裝器內部用 _sudo_cmd）
    if os.geteuid() != 0 and not shutil.which("sudo"):
        log_line(log_path, "非 root 且無 sudo，無法自動安裝；相關測試將跳過")
        return set(missing)
    # apt 安裝（依序嘗試候選套件，第一個成功即停）
    if apt_missing:
        pkgs = set()
        for b in apt_missing:
            cands = TOOL_PACKAGES.get(b) or KALI_APT.get(b) or []
            if isinstance(cands, str):
                cands = [cands]
            pkgs.update(c for c in cands if c)
        log_line(log_path, "工具檢查: 缺少 %s，開始自動安裝（套件: %s）" % (
            ", ".join(apt_missing), ", ".join(sorted(pkgs)) or "無對應套件"))
        try:
            r = subprocess.run(_sudo_cmd(["apt-get", "update", "-qq"]), capture_output=True,
                               text=True, timeout=180)
            log_line(log_path, "apt-get update 結束 code=%d" % r.returncode)
        except subprocess.TimeoutExpired:
            log_line(log_path, "apt-get update 逾時，續行安裝（可能失敗）")
        for b in apt_missing:
            cands = TOOL_PACKAGES.get(b) or KALI_APT.get(b) or []
            if isinstance(cands, str):
                cands = [cands]
            for pkg in cands:
                if not pkg:
                    continue
                try:
                    r = subprocess.run(_sudo_cmd(["apt-get", "install", "-y", pkg]),
                                       capture_output=True, text=True, timeout=300)
                    if r.returncode == 0:
                        log_line(log_path, "已安裝套件: %s（%s）" % (pkg, b))
                        break
                    log_line(log_path, "安裝失敗 %s (code=%d): %s" % (
                        pkg, r.returncode, (r.stderr or r.stdout).strip()[-200:]))
                except subprocess.TimeoutExpired:
                    log_line(log_path, "安裝 %s 逾時" % pkg)
    # 特殊來源安裝器（mongosh / odat / odat.py / testssl.sh；同一安裝器去重）
    seen_installers = set()
    for b in special_missing:
        fn = SPECIAL_INSTALLERS[b]
        if fn in seen_installers:
            continue
        seen_installers.add(fn)
        log_line(log_path, "工具 %s 缺失，以特殊來源安裝..." % b)
        try:
            globals()[fn]()
        except Exception as e:
            log_line(log_path, "特殊安裝 %s 失敗: %s" % (b, e))
    still_missing = {b for b in missing if not _is_tool_installed(b)}
    for b in sorted(still_missing):
        log_line(log_path, "工具 %s 仍缺失 → 相關測試跳過 (WARN)" % b)
    return still_missing


# ---------------------------------------------------------------------------
# nmap 掃描
# ---------------------------------------------------------------------------
def _parse_nmap_xml(xml_text, include_open_filtered=False):
    """解析 nmap -oX - 輸出 → ({port: proto}, {port: service})。"""
    open_ports, services = {}, {}
    root = ElementTree.fromstring(xml_text)
    for host in root.iter("host"):
        for port in host.iter("port"):
            st = port.find("state")
            if st is None:
                continue
            state = st.get("state")
            if state != "open" and not (include_open_filtered and state == "open|filtered"):
                continue
            pid = int(port.get("portid") or 0)
            open_ports[pid] = port.get("protocol", "tcp")
            svc = port.find("service")
            services[pid] = svc.get("name", "") if svc is not None else ""
    return open_ports, services


def scan_ports(ip, log_path, full_port, groups):
    """TCP + UDP 掃描。回傳 ({port: proto}, {port: service})。"""
    # 表格 + web 埠（nmap top-1000 之外的補掃清單）
    table_ports = set()
    for key in groups:
        for piece in key.split(","):
            if piece.strip().isdigit():
                table_ports.add(int(piece))
    table_ports |= WEB_PORTS

    # fallback 埠清單 = 表格 + web 埠（nmap 故障時的 Python connect 掃描用）
    fallback_ports = set(table_ports)

    udp_ports = set()
    for key, g in groups.items():
        for raw_cmd in g["commands"]:
            if "-sU" in raw_cmd:
                m = re.search(r"-p\s+([0-9,]+)", raw_cmd)
                if m:
                    for piece in m.group(1).split(","):
                        if piece.strip().isdigit():
                            udp_ports.add(int(piece))

    open_ports, services = {}, {}

    # TCP：nmap 內建 top-1000（nmap 自身維護，不需自備清單）
    # -p 會覆蓋 --top-ports，故表格/web 埠另以短清單補掃
    if full_port:
        scans = [("-p-", "全埠 -p-")]
    else:
        scans = [("--top-ports 1000", "nmap top-1000"),
                 ("-p " + ",".join(str(p) for p in sorted(table_ports)),
                  "表格+web 埠(%d)" % len(table_ports))]
    try:
        for plist_cmd, desc in scans:
            log_line(log_path, "掃描: nmap -Pn -sT -T4 --unprivileged %s %s（TCP %s）" % (
                plist_cmd, ip, desc))
            r = subprocess.run(["nmap", "-Pn", "-sT", "-T4", "--unprivileged"]
                               + plist_cmd.split() + ["-oX", "-", ip],
                               capture_output=True, text=True, timeout=600)
            o, sv = _parse_nmap_xml(r.stdout)
            open_ports.update(o)
            services.update(sv)
    except Exception as e:
        log_line(log_path, "nmap TCP 失敗（%s），改用 Python connect fallback" % e)
        open_ports.update(python_connect_scan(ip, log_path, sorted(fallback_ports)))

    # UDP（表格內定點）
    if udp_ports:
        udp_list = ",".join(str(p) for p in sorted(udp_ports))
        log_line(log_path, "掃描: nmap -Pn -sU -T4 --max-retries 1 -p %s %s（UDP 定點 %d 埠）" % (
            udp_list, ip, len(udp_ports)))
        try:
            r = subprocess.run(["nmap", "-Pn", "-sU", "-T4", "--max-retries", "1",
                                "-p", udp_list, "-oX", "-", ip],
                               capture_output=True, text=True, timeout=600)
            o, sv = _parse_nmap_xml(r.stdout, include_open_filtered=True)
            for pid in o:
                open_ports.setdefault(pid, o[pid])
                services.setdefault(pid, sv.get(pid, ""))
        except Exception as e:
            log_line(log_path, "nmap UDP 失敗: %s" % e)

    log_line(log_path, "掃描完成: 開啟 %d 個 port: %s" % (
        len(open_ports), ", ".join(str(p) for p in sorted(open_ports)) or "無"))
    return open_ports, services


def python_connect_scan(ip, log_path, plist, timeout=1.5, workers=200):
    """nmap 不可用時的 TCP connect 掃描 fallback。"""
    log_line(log_path, "Python connect 掃描: %d ports, timeout=%.1fs" % (len(plist), timeout))
    open_ports = {}
    lock = threading.Lock()

    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                with lock:
                    open_ports[p] = "tcp"
        except Exception:
            pass
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(probe, plist))
    return open_ports


def nmap_sv_unknown(ip, ports, open_ports, services, log_path):
    """對表外 port 抓 service 名稱（banner）；依 proto 分 TCP/UDP 掃描。"""
    if not ports:
        return
    tcp_ports = [p for p in ports if open_ports.get(p) != "udp"]
    udp_ports = [p for p in ports if open_ports.get(p) == "udp"]
    for plist, scan_type in ((tcp_ports, "-sT"), (udp_ports, "-sU")):
        if not plist:
            continue
        pstr = ",".join(str(p) for p in sorted(plist))
        log_line(log_path, "表外 port 抓 banner: nmap -Pn %s -sV --version-light -p %s %s" % (scan_type, pstr, ip))
        try:
            argv = ["nmap", "-Pn", scan_type, "-sV", "--version-light"]
            if scan_type == "-sT":
                argv.append("--unprivileged")
            r = subprocess.run(argv + ["-p", pstr, "-oX", "-", ip],
                               capture_output=True, text=True, timeout=120)
            root = ElementTree.fromstring(r.stdout)
            for host in root.iter("host"):
                for port in host.iter("port"):
                    svc = port.find("service")
                    if svc is not None and svc.get("name"):
                        services[int(port.get("portid"))] = svc.get("name")
        except Exception as e:
            log_line(log_path, "表外 port banner 抓取失敗（%s）: %s" % (scan_type, e))


# ---------------------------------------------------------------------------
# Python fallback（工具缺失時的同功能實作，零依賴）
# ---------------------------------------------------------------------------
def fb_redis_ping(ip, port, cfg):
    try:
        s = socket.create_connection((ip, port), timeout=5)
    except OSError as e:
        return "連線失敗: %s" % e, 1
    s.settimeout(5)
    s.sendall(b"PING\r\n")
    data = b""
    while True:
        try:
            chunk = s.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 512:
            break
    s.close()
    return data.decode(errors="replace"), 0


def fb_smtp_user_enum(ip, port, cfg):
    users = [ln.strip() for ln in open(cfg["userlist"], encoding="utf-8") if ln.strip()]
    try:
        s = socket.create_connection((ip, port), timeout=5)
    except OSError as e:
        return "連線失敗: %s" % e, 1
    s.settimeout(8)
    f = s.makefile("rwb")
    out = ""
    try:
        banner = f.readline().decode(errors="replace")
        f.write(b"EHLO scan.local\r\n")
        f.flush()
        while True:
            ln = f.readline()
            if not ln or ln.startswith(b"250 "):
                break
        out = banner
        for u in users:
            f.write(("VRFY %s\r\n" % u).encode())
            f.flush()
            try:
                out += f.readline().decode(errors="replace")
            except socket.timeout:
                out += "(timeout)\n"
        f.write(b"QUIT\r\n")
        f.flush()
    except OSError as e:
        out += "(連線中斷: %s)\n" % e
    finally:
        try:
            s.close()
        except OSError:
            pass
    return out, 0


FALLBACK_BIN = {"redis-cli": fb_redis_ping, "smtp-user-enum": fb_smtp_user_enum}


def _killpg(proc):
    """殺掉整個 process group（start_new_session=True 的 Popen 其 pid 即 pgid）。"""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _missing_bin_in_cmd(cmd_str, missing_bins):
    """管線/多段指令中任一 binary 缺失即回傳該 binary；全部存在回傳 None。"""
    for seg in re.split(r"[|<>;&]", cmd_str):
        toks = seg.split()
        while toks and "=" in toks[0] and not toks[0].startswith(("-", "/", "{")):
            toks.pop(0)  # env 前綴（VAR=val cmd）
        if toks and toks[0] == "timeout" and len(toks) > 2 and toks[1].isdigit():
            toks = toks[2:]  # timeout N 包裝
        if not toks:
            continue
        b = toks[0].split("/")[-1]
        if b in missing_bins and b not in FALLBACK_BIN:
            return b
    return None


def _safe_run(ip, port, test, cfg, missing_bins, out_dir, log_path):
    """run_one 的頂層兜底：任何未預期例外轉成 FAIL 結果，不讓整個掃描中止。"""
    try:
        return run_one(ip, port, test, cfg, missing_bins, out_dir, log_path)
    except Exception as e:
        log_line(log_path, "[%s][%s] 未預期例外: %r" % (port, test["name"], e))
        return {"port": port, "test": test["name"], "kind": test.get("kind", "detect"),
                "status": "FAIL", "summary": "未預期例外: %s" % e, "raw": "",
                "duration": 0, "cmd": test.get("cmd", "")}


# ---------------------------------------------------------------------------
# 測試執行
# ---------------------------------------------------------------------------
def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def make_gentle_lists(out_dir, user, password):
    """溫和模式：建立單行帳密檔，讓所有爆破指令只試一組。
    回傳 (password_path, userlist_path) — 對應 main 的 cfg["passwords"]/cfg["userlist"]。
    """
    u = out_dir / "gentle_userlist.txt"
    p = out_dir / "gentle_passwords.txt"
    u.write_text(user + "\n", encoding="utf-8")
    p.write_text(password + "\n", encoding="utf-8")
    return str(p), str(u)


def run_one(ip, port, test, cfg, missing_bins, out_dir, log_path):
    t0 = time.time()
    raw_dir = out_dir / "raw"
    name = test["name"]
    gentle = cfg["gentle"]

    # SKIP 判定
    if test.get("skip_reason"):
        log_line(log_path, "[%s][%s] SKIP: %s" % (port, name, test["skip_reason"]))
        return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                "summary": test["skip_reason"], "raw": "", "duration": 0, "cmd": test.get("cmd", "")}

    # domain（僅含 {DOMAIN} 的指令需要；無反解 → SKIP）
    domain = ""
    if test.get("needs_domain"):
        domain = resolve_domain(ip)
        if not domain:
            log_line(log_path, "[%s][%s] SKIP: 無 PTR 反解（{DOMAIN} 無法填充）" % (port, name))
            return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                    "summary": "無 PTR 反解", "raw": "", "duration": time.time() - t0, "cmd": ""}

    # 組 argv（溫和模式：字典已指向單行臨時檔，見 main）
    cmd = test["cmd"]
    if test.get("mod"):
        argv = msf_to_argv(test["mod"], ip, port, cfg["user"], cfg["password"],
                           cfg["userlist"], cfg["passwords"], gentle)
        shell_wrap = False
        src_display = test["src"]
    else:
        # UDP 掃描需 root（非 root 環境 nmap -sU 直接 QUIT）→ SKIP 而非 FAIL
        if os.geteuid() != 0 and "-sU" in cmd:
            log_line(log_path, "[%s][%s] SKIP: UDP 掃描需要 root 權限（非 root 環境）" % (port, name))
            return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                    "summary": "UDP 掃描需要 root 權限", "raw": "", "duration": time.time() - t0, "cmd": cmd}
        # hydra/nc/onesixtyone 的解析器在並行 DNS 負載下易 EAI_AGAIN / Unknown host
        # → 目標為 hostname 時預先解析成數字 IP（banner/爆破測試不需要 hostname）
        if not re.match(r"^\d+(\.\d+){3}$", ip) and any(
                t in ("nc", "hydra", "onesixtyone") for t in cmd.split()[:4]):
            try:
                ip = socket.gethostbyname(ip)
            except socket.gaierror:
                pass
        rendered = cmd
        # 注入防護：所有插值一律 shell 跳脫（bash -c 與 shlex.split 兩路皆安全）
        repl = {"{IP}": shlex.quote(ip), "{PORT}": str(port), "{DOMAIN}": shlex.quote(domain),
                "{USER}": shlex.quote(cfg["user"]), "{PASSWORD}": shlex.quote(cfg["password"]),
                "{USERLIST}": shlex.quote(cfg["userlist"]),
                "{PASSWORDS}": shlex.quote(cfg["passwords"]),
                "{PATH}": shlex.quote(cfg.get("path", "/"))}
        for k, v in repl.items():
            rendered = rendered.replace(k, v)
        bin0 = rendered.split()[0].split("/")[-1] if rendered.split() else ""
        # shell 字元偵測：| > < && ; " ' 或行首 env 前綴（VAR=val cmd）
        # 注意: --script=xxx 的 = 不是 shell 字元，不需 bash -c
        shell_chars = any(ch in rendered for ch in ("|", ">", "<", "&&", ";", '"', "'")) \
            or bool(re.match(r"^\s*\w+=", rendered))
        if shell_chars:
            argv = ["bash", "-c", rendered]
            shell_wrap = True
        else:
            try:
                argv = shlex.split(rendered)
            except ValueError as e:
                # 插值已 quote 仍解析失敗 → 指令庫資料本身有未閉合引號，SKIP 而非升級成 shell 執行
                log_line(log_path, "[%s][%s] SKIP: 指令無法解析（%s）" % (port, name, e))
                return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                        "summary": "指令無法解析: %s" % e, "raw": "", "duration": time.time() - t0,
                        "cmd": cmd}
        src_display = test["src"]

    # docker / 非 root 環境（無 raw socket）：nmap 指令自動補 --unprivileged
    not_root = os.path.exists("/.dockerenv") or os.geteuid() != 0
    if not test.get("mod") and argv and argv[0].split("/")[-1] == "nmap" \
            and "--unprivileged" not in argv and not_root:
        argv.insert(1, "--unprivileged")
        log_line(log_path, "[%s][%s] 非 root/docker 環境：nmap 自動加 --unprivileged" % (port, name))

    # 工具缺失檢查（有 fallback 的例外）
    if test.get("mod"):
        bin0 = "msfconsole"
    elif argv and argv[0] == "bash" and len(argv) > 2:
        # bash -c 包裝：檢查管線內所有 binary（echo | openssl ... 的 openssl 也要查）
        miss = _missing_bin_in_cmd(argv[2], missing_bins)
        if miss:
            log_line(log_path, "[%s][%s] SKIP: 工具缺失 %s" % (port, name, miss))
            return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                    "summary": "工具缺失: %s" % miss, "raw": "", "duration": time.time() - t0, "cmd": cmd}
        bin0 = "bash"
    else:
        bin0 = argv[0].split("/")[-1] if argv else "?"
    if bin0 == "timeout" and len(argv) >= 3:
        bin0 = argv[2].split("/")[-1]  # timeout 8 nc ... → 真實 binary 是 nc
    if bin0 in missing_bins and bin0 not in FALLBACK_BIN:
        log_line(log_path, "[%s][%s] SKIP: 工具缺失 %s" % (port, name, bin0))
        return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                "summary": "工具缺失: %s" % bin0, "raw": "", "duration": time.time() - t0, "cmd": ""}
    use_fallback = bin0 in missing_bins and bin0 in FALLBACK_BIN

    timeout = cfg["timeout"] if cfg["timeout"] else test["timeout"]
    cmd_display = " ".join(argv) if not test["mod"] else "msfconsole -q -x \"%s\"" % "; ".join(argv[3:])
    log_line(log_path, "[%s][%s] 執行(%ss): %s%s" % (
        port, name, timeout, cmd_display, " [Python fallback]" if use_fallback else ""))
    if test["src"] and test["src"] != cmd_display:
        log_line(log_path, "[%s][%s] 表格原文: %s" % (port, name, test["src"][:200]))

    out, err, rc, timed_out = "", "", -1, False
    try:
        if use_fallback:
            out, rc = FALLBACK_BIN[bin0](ip, port, cfg)
        else:
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, errors="replace", start_new_session=True,
                                 env={**os.environ, "TERM": "dumb"})
            try:
                out, err = p.communicate(timeout=timeout)
                rc = p.returncode
            except subprocess.TimeoutExpired:
                _killpg(p)  # 殺整個 process group（含 bash -c 衍生的孫程序）
                out, err = p.communicate()
                timed_out = True
                rc = p.returncode
    except FileNotFoundError:
        return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                "summary": "工具不存在", "raw": "", "duration": time.time() - t0, "cmd": cmd_display}
    except OSError as e:
        return {"port": port, "test": name, "kind": test["kind"], "status": "FAIL",
                "summary": "執行錯誤: %s" % e, "raw": "", "duration": time.time() - t0, "cmd": cmd_display}

    dur = time.time() - t0
    combined = out + "\n" + err

    # msf 模組載入失敗 → 自動重試修正（僅限載入錯誤，網路失敗不觸發）
    if test["mod"] and re.search(r"failed to load module|is not a valid module|unknown module", combined, re.I):
        tried = [test["mod"]]
        for fix in MSF_RETRY_FIXES[1:]:
            m2 = fix(test["mod"])
            if m2 in tried or m2 == test["mod"]:
                continue
            tried.append(m2)
            if is_exploit_module(m2) and cfg.get("no_exploit"):
                continue
            log_line(log_path, "[%s][%s] 模組載入失敗，重試 %s" % (port, name, m2))
            argv2 = msf_to_argv(m2, ip, port, cfg["user"], cfg["password"],
                                cfg["userlist"], cfg["passwords"], gentle)
            timed_out = False  # 每次嘗試各自記錄逾時旗標
            try:
                p = subprocess.Popen(argv2, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, errors="replace", start_new_session=True,
                                     env={**os.environ, "TERM": "dumb"})
                out, err = p.communicate(timeout=timeout)
                rc = p.returncode
            except subprocess.TimeoutExpired:
                _killpg(p)
                out, err = p.communicate()
                timed_out = True
            except FileNotFoundError:
                log_line(log_path, "[%s][%s] 模組重試失敗：工具不存在" % (port, name))
                break
            combined = out + "\n" + err
            if not re.search(r"failed to load module|is not a valid module|unknown module", combined, re.I):
                log_line(log_path, "[%s][%s] 重試成功 → 模組 %s" % (port, name, m2))
                break

    # 原始輸出存檔
    raw_name = "%s_%s.txt" % (port, name)
    raw_path = raw_dir / raw_name
    with open(raw_path, "w", encoding="utf-8", errors="replace") as f:
        f.write("$ %s\n[rc=%d, %.1fs%s]\n\n--- stdout ---\n%s\n--- stderr ---\n%s\n"
                % (cmd_display, rc, dur, ", 逾時" if timed_out else "", out, err))

    # 判讀（有輸出時安全訊號優先：RISK → WARN → 執行異常 → PASS；
    #  not-found/模組失敗檢查放關鍵字之後，避免遮蓋真實發現）
    if not combined.strip():
        if timed_out:
            status, summary = "WARN", "逾時無輸出(%ds)" % timeout
        elif rc != 0:
            status, summary = "WARN", "執行失敗(rc=%d) 無輸出（連線逾時/拒絕等網路級負面）" % rc
        else:
            status, summary = "PASS", "無異常輸出"
    else:
        risk_hit = next((ln.strip() for ln in combined.splitlines()
                         if any(re.search(pat, ln, re.I) for pat in test["risk"])), None) if test["risk"] else None
        if risk_hit:
            status, summary = "RISK", risk_hit[:140]
        else:
            warn_hit = next((ln.strip() for ln in combined.splitlines()
                             if any(re.search(pat, ln, re.I) for pat in test["warn"])), None) if test["warn"] else None
            if warn_hit:
                status, summary = "WARN", warn_hit[:140]
            elif re.search(r"not found|invalid script|failed to compile|no such script|command not found|"
                           r"failed to load module|is not a valid module|unknown module", combined, re.I):
                status, summary = "FAIL", "指令/script 不可用（輸出含 not found / 模組載入失敗等）"
            elif timed_out or rc == 124:
                status, summary = "WARN", "逾時(%ds)，輸出已截斷" % timeout
            elif rc != 0:
                status, summary = "FAIL", "執行失敗(rc=%d)：%s" % (rc, (err or out).strip()[-120:])
            else:
                status, summary = "PASS", "無異常輸出"

    log_line(log_path, "[%s][%s] %s: %s (%.1fs)" % (port, name, status, summary, dur))
    return {"port": port, "test": name, "kind": test["kind"], "status": status,
            "summary": summary, "raw": "raw/%s" % raw_name, "duration": round(dur, 1),
            "cmd": cmd_display, "src": test.get("src", "")}


# ---------------------------------------------------------------------------
# dry-run：驗證 190 指令可執行性（不連目標）
# ---------------------------------------------------------------------------
def dry_run(table_path, out_dir, no_exploit=False):
    data, groups = load_library(table_path)
    log_path = out_dir / "dryrun.log"
    lines = []
    lines.append("=== Dry-run: 指令可執行性驗證 === 來源: %s" % table_path)
    total, ok_bin, ok_msf, fail, skip = 0, 0, 0, 0, 0
    bad_bins, bad_mods = [], []

    # 收集所有 binary
    bins = set()
    mods = []
    for key, g in groups.items():
        for raw_cmd in g["commands"]:
            cmd = fix_command(raw_cmd)
            mod = parse_msf_module(cmd)
            if mod:
                if is_exploit_module(mod) and no_exploit:
                    skip += 1
                    lines.append("[SKIP] exploit 不執行（--no-exploit）: %s" % mod)
                    continue
                mods.append(mod)
                continue
            if cmd.startswith(("TRACE ", "Host:", "(", "修補:")) or cmd == "":
                continue
            bin0 = extract_bin0(cmd)
            if not bin0:
                continue  # 中文說明行（如「項目3可將字典檔置換為簡易字典」）
            bins.add(bin0)

    # binary 檢查
    for b in sorted(bins):
        total += 1
        if shutil.which(b):
            ok_bin += 1
            lines.append("[OK]   binary: %s" % b)
        else:
            fail += 1
            bad_bins.append(b)
            lines.append("[FAIL] binary 缺失: %s" % b)

    # trace_test（動態 HTTP TRACE 測試）可執行性：curl 存在 + argv 可組
    for tport in (80, 443):
        total += 1
        t = trace_test(tport)
        rendered = t["cmd"].replace("{IP}", "127.0.0.1")
        try:
            argv = shlex.split(rendered)
        except ValueError:
            argv = []
        if argv and argv[0] == "curl" and shutil.which("curl"):
            ok_bin += 1
            lines.append("[OK]   trace_test(%s): %s" % (tport, rendered))
        else:
            fail += 1
            bad_bins.append("trace_test(%s)" % tport)
            lines.append("[FAIL] trace_test(%s) 無法執行: %s" % (tport, rendered))

    # msf 模組批量載入檢查（單次 msfconsole 啟動，逐模組 use）
    if mods:
        unique_mods = list(dict.fromkeys(mods))
        load_cmds = "; ".join("use %s" % m for m in unique_mods) + "; exit"
        lines.append("批次驗證 %d 個 msf 模組（單次 msfconsole）..." % len(unique_mods))
        failed_mods = set()
        try:
            r = subprocess.run(["msfconsole", "-q", "-x", load_cmds],
                               capture_output=True, text=True, timeout=600)
            combined = r.stdout + r.stderr
            # 失敗模組會輸出 "[-] Failed to load module: <mod>"；成功則無輸出
            failed_mods = set(re.findall(r"failed to load module:\s*(\S+)", combined, re.I))
            for m in unique_mods:
                total += 1
                if m in failed_mods:
                    fail += 1
                    bad_mods.append(m)
                    lines.append("[FAIL] msf 模組: %s" % m)
                else:
                    ok_msf += 1
                    lines.append("[OK]   msf 模組: %s" % m)
        except subprocess.TimeoutExpired:
            lines.append("[FAIL] msfconsole 批次驗證逾時")
            for m in unique_mods:
                total += 1
                fail += 1
                bad_mods.append(m)
                lines.append("[FAIL] msf 模組（逾時未驗）: %s" % m)

    lines.append("")
    lines.append("=== 總結: 總 %d | binary OK %d | msf OK %d | FAIL %d | SKIP %d ===" % (
        total, ok_bin, ok_msf, fail, skip))
    if bad_bins:
        lines.append("缺失 binary: %s" % ", ".join(sorted(set(bad_bins))))
    if bad_mods:
        lines.append("載入失敗模組: %s" % ", ".join(sorted(set(bad_mods))))
    report = "\n".join(lines)
    with open(out_dir / "dryrun_report.txt", "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(report)
    return fail == 0


# ---------------------------------------------------------------------------
# PNG 匯出（掃描結果自動轉圖片；暗色 Cyberpunk 風格，中文優先字體）
# ---------------------------------------------------------------------------
PNG_FONT_CANDIDATES = [
    # CJK 優先（報告含中文）
    "/usr/share/fonts/opentype/noto/NotoSansMonoCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "C:/Windows/Fonts/msyh.ttc",     # 微軟正黑
    "C:/Windows/Fonts/msjh.ttc",     # 微軟正黑體
    "C:/Windows/Fonts/simhei.ttf",   # 黑體
    "/System/Library/Fonts/PingFang.ttc",
    # 等寬 fallback（無中文字形時，中文會變方塊）
    "C:/Windows/Fonts/consola.ttf",
    "C:/Windows/Fonts/cour.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]
PNG_MAX_COLS = 120
PNG_FONT_SIZE = 20
PNG_PADDING_X, PNG_PADDING_Y = 35, 30
PNG_LINE_GAP = 7
PNG_BG = (10, 10, 12)        # 黑底
PNG_TEXT = (225, 225, 225)   # 一般文字
PNG_CMD = (126, 211, 33)     # Kali 綠（$ 開頭指令行）


def _png_get_font():
    """依候選清單取字體（CJK 優先）；全缺回傳 None。"""
    from PIL import ImageFont
    for font_path in PNG_FONT_CANDIDATES:
        if Path(font_path).exists():
            try:
                return ImageFont.truetype(font_path, PNG_FONT_SIZE)
            except Exception:
                continue
    return None


def _png_wrap_line(line):
    line = line.expandtabs(4).rstrip("\r\n")
    if not line:
        return [""]
    return textwrap.wrap(line, width=PNG_MAX_COLS, replace_whitespace=False,
                         drop_whitespace=False, break_long_words=True,
                         break_on_hyphens=False) or [""]


def _png_read_txt(path):
    for encoding in ("utf-8", "utf-8-sig", "big5", "cp950"):
        try:
            return Path(path).read_text(encoding=encoding)
        except UnicodeDecodeError:
            pass
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _png_render_txt(txt_path, png_path, font):
    from PIL import Image, ImageDraw
    text = _png_read_txt(txt_path)
    lines = []
    for raw_line in text.splitlines():
        lines.extend(_png_wrap_line(raw_line))
    if not lines:
        lines = [""]
    bbox = font.getbbox("Ag")
    line_height = bbox[3] - bbox[1] + PNG_LINE_GAP
    max_width = max(font.getlength(line) for line in lines)
    image_width = int(max(900, PNG_PADDING_X * 2 + max_width + 20))
    image_height = int(max(300, PNG_PADDING_Y * 2 + len(lines) * line_height + 20))
    image = Image.new("RGB", (image_width, image_height), PNG_BG)
    draw = ImageDraw.Draw(image)
    y = PNG_PADDING_Y
    for line in lines:
        color = PNG_CMD if line.lstrip().startswith("$ ") else PNG_TEXT
        draw.text((PNG_PADDING_X, y), line, font=font, fill=color)
        y += line_height
    png_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(png_path, "PNG", optimize=True)


def export_png(out_dir, log_path):
    """掃描結果目錄內所有 .txt → PNG/（保留相對結構）。
    缺 Pillow 時自動 pip 安裝；失敗只 log，不影響掃描結果。
    """
    try:
        import PIL  # noqa: F401  觸發自動安裝判定
    except ImportError:
        log_line(log_path, "PNG 匯出: Pillow 未安裝，嘗試自動安裝...")
        try:
            r = subprocess.run(_sudo_cmd([sys.executable, "-m", "pip", "install", "--quiet",
                                          "--break-system-packages", "pillow"]),
                               capture_output=True, text=True, timeout=180)
            if r.returncode == 0:
                import PIL  # noqa: F401
            else:
                log_line(log_path, "PNG 匯出: pip 安裝 pillow 失敗（%s）→ 跳過" % (r.stderr or r.stdout).strip()[-150:])
                return
        except Exception as e:
            log_line(log_path, "PNG 匯出: pip 安裝 pillow 失敗: %s → 跳過" % e)
            return
    font = _png_get_font()
    if font is None:
        log_line(log_path, "PNG 匯出: 找不到可用字體（建議 apt install fonts-noto-cjk）→ 跳過")
        return
    out_dir = Path(out_dir)
    txt_files = sorted(p for p in out_dir.rglob("*.txt")
                       if p.name not in ("gentle_userlist.txt", "gentle_passwords.txt")
                       and "PNG" not in p.parts)
    if not txt_files:
        log_line(log_path, "PNG 匯出: 無 .txt 可轉")
        return
    png_root = out_dir / "PNG"
    png_root.mkdir(parents=True, exist_ok=True)
    ok_count = 0
    for i, txt in enumerate(txt_files, 1):
        rel = txt.relative_to(out_dir)
        try:
            _png_render_txt(txt, png_root / rel.with_suffix(".png"), font)
            ok_count += 1
        except Exception as e:
            log_line(log_path, "PNG 匯出失敗 %s: %s" % (rel, e))
        print("[PNG] (%d/%d) %s" % (i, len(txt_files), rel), flush=True)
    log_line(log_path, "PNG 匯出完成: %d/%d 張 → %s" % (ok_count, len(txt_files), png_root))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="單一 IP Port 風險自動化掃描（JSON 指令庫驅動）")
    ap.add_argument("ip", nargs="?", help="目標 IP（--dry-run 時可省略）")
    ap.add_argument("--passwords", default=str(BASE / "password.txt"), help="爆破密碼檔（預設內建 password.txt）")
    ap.add_argument("--userlist", default=str(BASE / "userlist.txt"), help="爆破帳號清單檔（預設內建 userlist.txt）")
    ap.add_argument("--jobs", type=int, default=4, help="並行 worker 數（預設 4）")
    ap.add_argument("--timeout", type=int, default=0, help="整體覆蓋 timeout（秒）")
    ap.add_argument("--no-install", action="store_true", help="不自動 apt-get install 缺漏工具")
    ap.add_argument("--out", default=str(RUNS), help="輸出根目錄（預設 runs/）")
    ap.add_argument("--gentle", action="store_true", help="爆破類指令只嘗試單一帳密（預設載入完整字典）")
    ap.add_argument("--user", default="admin", help="--gentle 模式單一帳號（預設 admin）")
    ap.add_argument("--password", default="password", help="--gentle 模式單一密碼（預設 password）")
    ap.add_argument("--full-port", action="store_true", help="TCP 全埠掃描 -p-（預設 nmap top-1000 + 表格埠）")
    ap.add_argument("--table", default=None, help="JSON 指令庫路徑（預設依序找 repo 目錄或 /root 下的 common_ports_test_commands.json）")
    ap.add_argument("--dry-run", action="store_true", help="不連目標，驗證指令庫可執行性")
    ap.add_argument("--install-tools", action="store_true", help="安裝所有缺失的外部工具後結束（需要 root/sudo）")
    ap.add_argument("--check-tools", action="store_true", help="只列出缺失的外部工具，不安裝")
    ap.add_argument("--no-exploit", action="store_true", help="不執行 exploit 模組（預設會執行）")
    args = ap.parse_args()

    # 工具安裝模式：不需要指令庫/目標
    if args.check_tools or args.install_tools:
        ok = install_tools_main(check_only=args.check_tools)
        sys.exit(0 if ok else 1)

    table = resolve_table(args.table)
    if table is None:
        print("錯誤: 找不到 JSON 指令庫。請用 --table 指定，或將 common_ports_test_commands.json 放入 %s 或 /root/" % BASE)
        sys.exit(1)
    args.table = table

    if args.dry_run:
        out_root = Path(args.out)
        out_root.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dry_dir = out_root / ("%s_dryrun" % ts)
        dry_dir.mkdir(parents=True, exist_ok=True)
        ok = dry_run(args.table, dry_dir, args.no_exploit)
        sys.exit(0 if ok else 1)

    if not args.ip:
        if sys.stdin.isatty():
            # 互動模式：提示輸入目標
            try:
                args.ip = input("請輸入目標 IP 或域名: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n已取消")
                sys.exit(1)
        else:
            # 非互動：支援管線輸入（echo target | python3 scan_ip.py）
            line = sys.stdin.readline().strip()
            if line:
                args.ip = line
        if not args.ip:
            print("錯誤: 需要目標 IP（或使用 --dry-run）")
            sys.exit(1)

    ip = args.ip
    # 容忍誤貼完整 URL（剝離 scheme 與路徑，避免 nmap 解析失敗白跑）
    m = re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?([^/\s]+)", ip)
    if m:
        ip = m.group(1)
    # 注入防護：目標僅允許 IP/主機名字元集（堵住 bash -c / msf -x 的注入鏈）
    if not re.match(r"^[A-Za-z0-9._\-:\[\]]+$", ip):
        print("錯誤: 目標 %r 含非法字元（僅允許 IP 或主機名）" % ip)
        sys.exit(1)
    args.ip = ip
    passwords = os.path.abspath(args.passwords)
    userlist = os.path.abspath(args.userlist)
    for f, label in ((passwords, "密碼檔"), (userlist, "帳號清單")):
        if not os.path.isfile(f):
            print("錯誤: %s %s 不存在" % (label, f))
            sys.exit(1)

    data, groups = load_library(args.table)
    gentle = args.gentle

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = out_root / ("%s_%s" % (ts, ip))
    (out_dir / "raw").mkdir(parents=True)
    log_path = out_dir / "scan.log"
    log_line(log_path, "=== Port 風險掃描開始 目標=%s 時間=%s ===" % (ip, datetime.now().isoformat(timespec="seconds")))
    log_line(log_path, "指令庫: %s（%d port 群組）" % (args.table, len(groups)))
    log_line(log_path, "模式: %s | exploit: %s | 帳號: %s | 密碼: %s" % (
        "爆破（完整字典）" if not gentle else "溫和（單一帳密 %s/%s）" % (args.user, args.password),
        "跳過（--no-exploit）" if args.no_exploit else "執行",
        os.path.basename(userlist), os.path.basename(passwords)))

    # 1. 前置檢查
    missing_bins = preflight(args.no_install, log_path)

    # 2. 掃描
    open_ports, services = scan_ports(ip, log_path, args.full_port, groups)
    known_keys = set()
    for key in groups:
        known_keys |= {int(p) for p in key.split(",") if p.strip().isdigit()}
    unknown = [p for p in open_ports if p not in known_keys]
    nmap_sv_unknown(ip, unknown, open_ports, services, log_path)

    # 3. 組測試清單 + 確認
    cfg = {
        "passwords": passwords, "userlist": userlist, "timeout": args.timeout,
        "gentle": gentle, "user": args.user, "password": args.password,
        "path": "/", "no_exploit": args.no_exploit,
    }
    if gentle:
        # 溫和模式：字典指向單行臨時檔（爆破指令只試一組帳密）
        pl, ul = make_gentle_lists(out_dir, args.user, args.password)
        cfg["passwords"], cfg["userlist"] = pl, ul
        log_line(log_path, "溫和模式: 字典指向單行臨時檔 %s / %s" % (pl, ul))
    jobs = []
    for port in sorted(open_ports):
        is_web = "http" in services.get(port, "") or port in WEB_PORTS
        tests = build_commands_for_port(port, groups, cfg, gentle)
        for t in tests:
            jobs.append((port, t))
        if is_web:
            jobs.append((port, trace_test(port)))
        if port not in known_keys and not is_web:
            log_line(log_path, "[%s] 偵測到但無對應測試（service=%s）→ 僅記錄 banner" % (
                port, services.get(port, "?")))
    log_line(log_path, "共 %d 個測試待執行（並行 %d）" % (len(jobs), args.jobs))

    print("\n========== 目標確認 ==========")
    print("目標 IP        : %s" % ip)
    print("開啟 port      : %s" % (", ".join(str(p) for p in sorted(open_ports)) or "無"))
    print("將執行測試數   : %d" % len(jobs))
    print("模式           : %s" % ("溫和（單一帳密）" if gentle else "爆破（完整字典）"))
    print("輸出目錄       : %s" % out_dir)
    print("（資訊確認完畢，自動開始執行；Ctrl-C 可中斷）")

    # 4. 執行
    results = []
    ex = ThreadPoolExecutor(max_workers=max(1, args.jobs))
    futs = {ex.submit(_safe_run, ip, port, t, cfg, missing_bins, out_dir, log_path): (port, t["name"])
            for port, t in jobs}
    try:
        for fut in as_completed(futs):
            results.append(fut.result())
    except KeyboardInterrupt:
        log_line(log_path, "!!! 使用者中斷，輸出部分結果 !!!")
        ex.shutdown(wait=False, cancel_futures=True)  # 取消未開始的測試，不等待
        for fut in futs:
            if fut.done() and not fut.cancelled():
                try:
                    results.append(fut.result())
                except Exception:
                    pass
    else:
        ex.shutdown(wait=True)

    # 5. 結果統計 + 產出
    stats = {"total": len(results), "RISK": 0, "WARN": 0, "PASS": 0, "FAIL": 0, "SKIP": 0}
    for r in results:
        stats[r["status"]] = stats.get(r["status"], 0) + 1

    res = {
        "target": ip,
        "started_at": ts,
        "mode": "gentle" if gentle else "brute",
        "library": args.table,
        "nmap": {"open_ports": sorted(open_ports),
                 "services": {str(k): v for k, v in services.items()}},
        "tests": sorted(results, key=lambda r: (r["port"], r["test"])),
        "stats": stats,
    }
    with open(out_dir / "results.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)

    # summary.txt
    lines = []
    lines.append("=== Port 風險掃描總結 ===")
    lines.append("目標: %s    時間: %s" % (ip, ts))
    lines.append("掃描: %s    開啟 port: %d 個" % (
        "全埠 -p-" if args.full_port else "nmap top-1000 + 表格埠", len(open_ports)))
    lines.append("模式: %s" % ("溫和（單一帳密 %s/%s）" % (args.user, args.password) if gentle else "爆破（完整字典）"))
    lines.append("測試: 總 %d   RISK %d   WARN %d   PASS %d   FAIL %d   SKIP %d" % (
        stats["total"], stats["RISK"], stats["WARN"], stats["PASS"], stats["FAIL"], stats["SKIP"]))
    lines.append("")
    for st in ("RISK", "WARN", "FAIL", "SKIP"):
        items = [r for r in res["tests"] if r["status"] == st]
        if items:
            lines.append("[%s] 共 %d 項:" % (st, len(items)))
            for r in items:
                extra = "  (raw/%s)" % r["raw"].split("/")[-1] if r.get("raw") else ""
                lines.append("  [%s] %s: %s%s" % (r["port"], r["test"], r["summary"], extra))
            lines.append("")
    extra = [p for p in sorted(open_ports) if p not in known_keys]
    if extra:
        lines.append("額外開啟 port（無對應測試，僅 banner）:")
        for p in extra:
            lines.append("  %s (%s)" % (p, services.get(p, "?")))
        lines.append("")
    lines.append("原始輸出: raw/   流水帳: scan.log   結構化結果: results.json")
    with open(out_dir / "summary.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("\n" + "\n".join(lines))
    export_png(out_dir, log_path)
    log_line(log_path, "=== 完成: %d 測試, RISK=%d WARN=%d PASS=%d FAIL=%d SKIP=%d ===" % (
        stats["total"], stats["RISK"], stats["WARN"], stats["PASS"], stats["FAIL"], stats["SKIP"]))


if __name__ == "__main__":
    main()
