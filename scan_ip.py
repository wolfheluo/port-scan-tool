#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_ip.py — 單一 IP Port 風險自動化掃描（JSON 指令庫驅動版）
================================================================
依「常見port_測試指令.json」（72 port × 190 指令）自動化執行。

流程：
  1. 前置檢查（工具缺失 → 自動 apt-get install，失敗則跳過該測試）
  2. 載入 JSON 指令庫 → 轉換層（msf6> 解析、變數填充、已知修正、自動重試）
  3. 目標確認（顯示目標與測試數量，Enter 才繼續；非互動環境自動通過）
  4. nmap 偵測開啟 port（TCP top-1000∪表格埠∪web埠；UDP 表格內定點掃）
  5. 依 JSON 指令庫派發測試（--jobs 並行）
  6. 每測試判讀 PASS / WARN / RISK / FAIL / SKIP（每 port 關鍵字表）
  7. 產出 runs/<時間戳>_<IP>/ { scan.log, results.json, summary.txt, raw/*.txt }

用法：
  python3 scan_ip.py <IP> [--wordlist FILE] [--userlist FILE] [--jobs N]
                       [--timeout N] [--no-install] [--out DIR]
                       [--brute] [--user U] [--password P] [--full-port]
                       [--table FILE] [--dry-run]

模式：
  - 預設（溫和）：爆破類指令只嘗試單一帳密（--user/--password，預設 admin/password）
  - --brute：爆破類指令載入完整字典（--wordlist/--userlist）
  - --dry-run：不連目標，逐一驗證 190 指令可執行性（binary + msf 模組載入）

安全邊界：
  - exploit 模組（java_rmi_server、cve_2021_38647_omigod）一律 SKIP，永不執行
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
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

BASE = Path(__file__).resolve().parent
RUNS = BASE / "runs"


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
    "xfreerdp": "freerdp3-x11", "rlogin": "rsh-redone-client",
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
INTERACTIVE_BINS = {"sqsh", "psql", "tftp", "rlogin", "telnet", "vncviewer", "xfreerdp", "mongosh"}

# 需圖形環境的工具（headless 直接 SKIP）
GUI_BINS = {"vncviewer", "xfreerdp"}

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
             r"public", r"PONG", r"200 OK"],
    "warn": [r"banner", r"version", r"220 ", r"\+OK", r"exists", r"valid",
             r"title", r"server", r"timed out", r"no response",
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
    80: {"risk": [r"DEBUG.{0,10}enabled", r"HTTP/1\.[01] 200"],
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
    443: {"risk": [r"SSLv2\s*(enabled|:)", r"SSLv3\s*(enabled|:)", r"TLSv1\.0\s*(enabled|:)"],
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
    873: {"risk": [r"writable", r"@"],
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
                    r"SSLv2\s*(enabled|:)", r"SSLv3\s*(enabled|:)", r"TLSv1\.0\s*(enabled|:)"],
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
    8080: {"risk": [r"HTTP/1\.[01] 200"],
           "warn": [r"tomcat", r"jenkins", r"title", r"server:"]},
    8161: {"risk": [],
           "warn": [r"activemq", r"title"]},
    8443: {"risk": [r"SSLv2\s*(enabled|:)", r"SSLv3\s*(enabled|:)", r"TLSv1\.0\s*(enabled|:)"],
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
        "cmd": "curl -s -i --max-time 10 -X TRACE %s://%s:%d/" % (scheme, "{IP}", port),
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
            # exploit → SKIP
            if mod and is_exploit_module(mod):
                tests.append({
                    "name": "msf-%s" % mod.rsplit("/", 1)[-1], "kind": "scan",
                    "argv": None, "cmd": "", "mod": mod, "src": raw_cmd,
                    "risk": [], "warn": [], "timeout": 60,
                    "skip_reason": "exploit 模組不執行（安全邊界）",
                })
                continue
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
# 前置檢查
# ---------------------------------------------------------------------------
def preflight(no_install, log_path):
    missing = [b for b in TOOL_PACKAGES if shutil.which(b) is None]
    missing += [b for b in NO_APT_TOOLS if shutil.which(b) is None]
    # 無 apt 套件的工具：缺則 SKIP（不嘗試安裝）
    no_apt_missing = sorted(set(missing) & NO_APT_TOOLS)
    for b in no_apt_missing:
        log_line(log_path, "工具 %s 缺失（無 apt 套件）→ 相關測試 SKIP" % b)
    install_missing = sorted(set(missing) - NO_APT_TOOLS)
    if not missing:
        log_line(log_path, "工具檢查: 全部齊全")
        return set()
    if no_install:
        log_line(log_path, "工具檢查: 缺少 %s（--no-install 已指定，相關測試將跳過）" % ", ".join(missing))
        return set(missing)
    pkgs = sorted({TOOL_PACKAGES[b] for b in install_missing if TOOL_PACKAGES.get(b)})
    log_line(log_path, "工具檢查: 缺少 %s，開始自動安裝（套件: %s）" % (
        ", ".join(install_missing), ", ".join(pkgs) or "無對應套件"))
    if pkgs and os.geteuid() != 0:
        log_line(log_path, "非 root，無法自動安裝；相關測試將跳過")
        return set(install_missing)
    if pkgs and os.geteuid() == 0:
        try:
            r = subprocess.run(["apt-get", "update", "-qq"], capture_output=True,
                               text=True, timeout=180)
            log_line(log_path, "apt-get update 結束 code=%d" % r.returncode)
        except subprocess.TimeoutExpired:
            log_line(log_path, "apt-get update 逾時，續行安裝（可能失敗）")
        for pkg in pkgs:
            try:
                r = subprocess.run(["apt-get", "install", "-y", pkg],
                                   capture_output=True, text=True, timeout=300)
                if r.returncode == 0:
                    log_line(log_path, "已安裝套件: %s" % pkg)
                else:
                    log_line(log_path, "安裝失敗 %s (code=%d): %s" % (
                        pkg, r.returncode, (r.stderr or r.stdout).strip()[-200:]))
            except subprocess.TimeoutExpired:
                log_line(log_path, "安裝 %s 逾時" % pkg)
    still_missing = {b for b in missing if shutil.which(b) is None}
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

    # top1000.txt：僅作 nmap 不可用時的 Python connect fallback 埠清單
    fallback_ports = set()
    bad_tokens = []
    with open(BASE / "top1000.txt", encoding="utf-8") as f:
        for chunk in f:
            for x in chunk.split(","):
                x = x.strip()
                if not x:
                    continue
                if x.isdigit() and 0 <= int(x) <= 65535:
                    fallback_ports.add(int(x))
                else:
                    bad_tokens.append(x)
    if bad_tokens:
        log_line(log_path, "警告: top1000.txt 含無效 port token（已忽略）: %s" % ", ".join(bad_tokens[:5]))
    fallback_ports |= table_ports

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


def nmap_sv_unknown(ip, ports, services, log_path):
    """對表外 port 抓 service 名稱（banner）。"""
    if not ports:
        return
    plist = ",".join(str(p) for p in sorted(ports))
    log_line(log_path, "表外 port 抓 banner: nmap -Pn -sV --version-light -p %s %s" % (plist, ip))
    try:
        r = subprocess.run(["nmap", "-Pn", "-sT", "-sV", "--version-light", "--unprivileged",
                            "-p", plist, "-oX", "-", ip],
                           capture_output=True, text=True, timeout=120)
        root = ElementTree.fromstring(r.stdout)
        for host in root.iter("host"):
            for port in host.iter("port"):
                svc = port.find("service")
                if svc is not None and svc.get("name"):
                    services[int(port.get("portid"))] = svc.get("name")
    except Exception as e:
        log_line(log_path, "表外 port banner 抓取失敗: %s" % e)


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
    回傳 (wordlist_path, userlist_path) — 對應 main 的 cfg["wordlist"]/cfg["userlist"]。
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
                           cfg["userlist"], cfg["wordlist"], gentle)
        shell_wrap = False
        src_display = test["src"]
    else:
        # UDP 掃描需 root（非 root 環境 nmap -sU 直接 QUIT）→ SKIP 而非 FAIL
        if os.geteuid() != 0 and "-sU" in cmd:
            log_line(log_path, "[%s][%s] SKIP: UDP 掃描需要 root 權限（非 root 環境）" % (port, name))
            return {"port": port, "test": name, "kind": test["kind"], "status": "SKIP",
                    "summary": "UDP 掃描需要 root 權限", "raw": "", "duration": time.time() - t0, "cmd": cmd}
        # onesixtyone 只接受數字 IP（hostname 會 Malformed IP address）
        if "onesixtyone" in cmd and not re.match(r"^\d+(\.\d+){3}$", ip):
            try:
                ip = socket.gethostbyname(ip)
            except socket.gaierror:
                pass
        rendered = cmd
        # 注入防護：所有插值一律 shell 跳脫（bash -c 與 shlex.split 兩路皆安全）
        repl = {"{IP}": shlex.quote(ip), "{PORT}": str(port), "{DOMAIN}": shlex.quote(domain),
                "{USER}": shlex.quote(cfg["user"]), "{PASSWORD}": shlex.quote(cfg["password"]),
                "{USERLIST}": shlex.quote(cfg["userlist"]),
                "{PASSWORDS}": shlex.quote(cfg["wordlist"]),
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
        bin0 = argv[2].split()[0].split("/")[-1]
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

    # msf 模組載入失敗 → 自動重試修正
    if test["mod"] and (rc != 0 or re.search(r"failed to load module|is not a valid module|unknown module", combined, re.I)):
        tried = [test["mod"]]
        for fix in MSF_RETRY_FIXES[1:]:
            m2 = fix(test["mod"])
            if m2 in tried or m2 == test["mod"]:
                continue
            tried.append(m2)
            if is_exploit_module(m2):
                continue
            log_line(log_path, "[%s][%s] 模組載入失敗，重試 %s" % (port, name, m2))
            argv2 = msf_to_argv(m2, ip, port, cfg["user"], cfg["password"],
                                cfg["userlist"], cfg["wordlist"], gentle)
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

    # 判讀
    if timed_out and not combined.strip():
        status, summary = "WARN", "逾時無輸出(%ds)" % timeout
    elif timed_out:
        status, summary = "WARN", "逾時(%ds)，輸出已截斷" % timeout
    elif rc != 0 and not combined.strip():
        status, summary = "WARN", "執行失敗(rc=%d) 無輸出（連線逾時/拒絕等網路級負面）" % rc
    elif re.search(r"not found|invalid script|failed to compile|no such script|command not found", combined, re.I):
        status, summary = "FAIL", "指令/script 不可用（輸出含 not found 等）"
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
def dry_run(table_path, out_dir):
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
                if is_exploit_module(mod):
                    skip += 1
                    lines.append("[SKIP] exploit 不執行: %s" % mod)
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
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="單一 IP Port 風險自動化掃描（JSON 指令庫驅動）")
    ap.add_argument("ip", nargs="?", help="目標 IP（--dry-run 時可省略）")
    ap.add_argument("--wordlist", default=str(BASE / "wordlist.txt"), help="爆破字典檔（--brute 模式；預設內建迷你字典）")
    ap.add_argument("--userlist", default=str(BASE / "userlist.txt"), help="帳號清單檔（--brute 模式；預設內建）")
    ap.add_argument("--jobs", type=int, default=4, help="並行 worker 數（預設 4）")
    ap.add_argument("--timeout", type=int, default=0, help="整體覆蓋 timeout（秒）")
    ap.add_argument("--no-install", action="store_true", help="不自動 apt-get install 缺漏工具")
    ap.add_argument("--out", default=str(RUNS), help="輸出根目錄（預設 runs/）")
    ap.add_argument("--brute", action="store_true", help="爆破類指令載入完整字典（預設僅單一帳密溫和嘗試）")
    ap.add_argument("--user", default="admin", help="溫和模式單一帳號（預設 admin）")
    ap.add_argument("--password", default="password", help="溫和模式單一密碼（預設 password）")
    ap.add_argument("--full-port", action="store_true", help="TCP 全埠掃描 -p-（預設 top1000+表格聯集）")
    ap.add_argument("--table", default=None, help="JSON 指令庫路徑（預設依序找 repo 目錄或 /root 下的 common_ports_test_commands.json）")
    ap.add_argument("--dry-run", action="store_true", help="不連目標，驗證指令庫可執行性")
    args = ap.parse_args()

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
        ok = dry_run(args.table, dry_dir)
        sys.exit(0 if ok else 1)

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
    wordlist = os.path.abspath(args.wordlist)
    userlist = os.path.abspath(args.userlist)
    for f, label in ((wordlist, "字典檔"), (userlist, "帳號清單")):
        if not os.path.isfile(f):
            print("錯誤: %s %s 不存在" % (label, f))
            sys.exit(1)

    data, groups = load_library(args.table)
    gentle = not args.brute

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = out_root / ("%s_%s" % (ts, ip))
    (out_dir / "raw").mkdir(parents=True)
    log_path = out_dir / "scan.log"
    log_line(log_path, "=== Port 風險掃描開始 目標=%s 時間=%s ===" % (ip, datetime.now().isoformat(timespec="seconds")))
    log_line(log_path, "指令庫: %s（%d port 群組）" % (args.table, len(groups)))
    log_line(log_path, "模式: %s | 帳號: %s | 密碼: %s" % (
        "溫和（單一帳密 %s/%s）" % (args.user, args.password) if gentle else "爆破（完整字典）",
        os.path.basename(userlist), os.path.basename(wordlist)))

    # 1. 前置檢查
    missing_bins = preflight(args.no_install, log_path)

    # 2. 掃描
    open_ports, services = scan_ports(ip, log_path, args.full_port, groups)
    known_keys = set()
    for key in groups:
        known_keys |= {int(p) for p in key.split(",") if p.strip().isdigit()}
    unknown = [p for p in open_ports if p not in known_keys]
    nmap_sv_unknown(ip, unknown, services, log_path)

    # 3. 組測試清單 + 確認
    cfg = {
        "wordlist": wordlist, "userlist": userlist, "timeout": args.timeout,
        "gentle": gentle, "user": args.user, "password": args.password,
        "path": "/",
    }
    if gentle:
        # 溫和模式：字典指向單行臨時檔（爆破指令只試一組帳密）
        wl, ul = make_gentle_lists(out_dir, args.user, args.password)
        cfg["wordlist"], cfg["userlist"] = wl, ul
        log_line(log_path, "溫和模式: 字典指向單行臨時檔 %s / %s" % (wl, ul))
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
    if sys.stdin.isatty():
        try:
            input("按 Enter 開始（Ctrl-C 取消）...")
        except EOFError:
            print("（stdin EOF，自動繼續）")
        except KeyboardInterrupt:
            print("已取消")
            sys.exit(1)
    else:
        print("（非互動環境，自動繼續）")

    # 4. 執行
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = {ex.submit(_safe_run, ip, port, t, cfg, missing_bins, out_dir, log_path): (port, t["name"])
                for port, t in jobs}
        try:
            for fut in as_completed(futs):
                results.append(fut.result())
        except KeyboardInterrupt:
            log_line(log_path, "!!! 使用者中斷，輸出部分結果 !!!")

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
    log_line(log_path, "=== 完成: %d 測試, RISK=%d WARN=%d PASS=%d FAIL=%d SKIP=%d ===" % (
        stats["total"], stats["RISK"], stats["WARN"], stats["PASS"], stats["FAIL"], stats["SKIP"]))


if __name__ == "__main__":
    main()
