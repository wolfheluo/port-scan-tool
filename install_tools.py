#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install_tools.py — 安裝 port-scan-tool 依賴的所有外部工具（冪等）

用法:
  sudo python3 install_tools.py            # 安裝所有缺失工具
  python3 install_tools.py --check         # 只列出缺失工具，不安裝
  python3 install_tools.py --no-apt        # 跳過 apt，只裝特殊來源工具
                                           #   (mongosh / odat / testssl.sh)

工具來源:
  - 有 apt 套件者          → apt-get install（非 root 自動加 sudo）
  - crackmapexec/ncat 等   → Kali/Debian apt 套件（KALI_APT 對照表）
  - mongosh                → MongoDB 官方 tgz（GitHub API 取最新版號）
  - odat / odat.py         → GitHub quentinhardy/odat → /opt/odat + symlink
  - testssl.sh             → GitHub drwetter/testssl.sh → /opt/testssl.sh + symlink

安全邊界: 僅安裝工具本身，不執行掃描、不連目標。
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
import scan_ip  # 重用 TOOL_PACKAGES / NO_APT_TOOLS（工具 → apt 套件對照）

# sudo 的 secure_path 常缺 /usr/local/bin（本腳本的安裝位置）
# → 啟動時自行補上，否則安裝後 which() 看不到而誤報 FAIL
os.environ["PATH"] = "/usr/local/bin:" + os.environ.get("PATH", "")

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
}

# 無 apt 來源 → 特殊安裝函式
SPECIAL_INSTALLERS = {
    "mongosh": "install_mongosh",
    "odat": "install_odat",
    "odat.py": "install_odat",
    "testssl.sh": "install_testssl",
}

UA = {"User-Agent": "install_tools.py/1.0 (port-scan-tool)"}


def log(msg):
    print("[install] %s" % msg, flush=True)


def sudo_cmd(cmd):
    """非 root 時自動加 sudo 前綴。"""
    if os.geteuid() == 0:
        return cmd
    if shutil.which("sudo"):
        return ["sudo"] + cmd
    print("錯誤: 需要 root 或 sudo 才能執行: %s" % " ".join(cmd))
    sys.exit(1)


def run(cmd, check=False, timeout=600, **kw):
    log("$ %s" % " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    if r.stdout.strip():
        log("  " + r.stdout.strip()[-500:])
    if r.stderr.strip():
        log("  ! " + r.stderr.strip()[-500:])
    if check and r.returncode != 0:
        log("失敗: %s (rc=%d)" % (" ".join(cmd), r.returncode))
        sys.exit(1)
    return r


def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    return urllib.request.urlopen(req, timeout=timeout).read()


# 安裝位置（/usr/local/bin 或 /opt），供 PATH 之外的最終判定
INSTALL_PATHS = {
    "mongosh": ("/usr/local/bin/mongosh",),
    "odat": ("/opt/odat/odat.py",),
    "odat.py": ("/opt/odat/odat.py",),
    "testssl.sh": ("/opt/testssl.sh/testssl.sh",),
}


def is_installed(bin_name):
    if shutil.which(bin_name):
        return True
    return any(os.access(p, os.X_OK) for p in INSTALL_PATHS.get(bin_name, ()))


def missing_tools():
    bins = list(scan_ip.TOOL_PACKAGES) + list(scan_ip.NO_APT_TOOLS)
    return sorted({b for b in bins if not is_installed(b)})


# ---------------------------------------------------------------------------
# apt 安裝
# ---------------------------------------------------------------------------
def apt_install_tools(missing, no_apt):
    """回傳安裝失敗的工具清單。"""
    pkgs = set()
    for b in missing:
        cands = scan_ip.TOOL_PACKAGES.get(b) or KALI_APT.get(b) or []
        if isinstance(cands, str):
            cands = [cands]
        for c in cands:
            pkgs.add(c)
    pkgs.discard(None)
    if not pkgs:
        return []
    if no_apt:
        log("--no-apt 已指定，跳過 apt 安裝: %s" % ", ".join(sorted(pkgs)))
        return []
    log("apt 套件: %s" % ", ".join(sorted(pkgs)))
    run(sudo_cmd(["apt-get", "update", "-qq"]), timeout=600)
    run(sudo_cmd(["apt-get", "install", "-y"] + sorted(pkgs)), timeout=1200)
    # 驗證每個工具是否裝上（apt 缺套件時 apt 會失敗但部分工具可能已裝）
    still = [b for b in missing if shutil.which(b) is None
             and b not in SPECIAL_INSTALLERS and not (scan_ip.TOOL_PACKAGES.get(b) or KALI_APT.get(b))]
    return still


# ---------------------------------------------------------------------------
# mongosh — MongoDB 官方 tgz（GitHub API 取最新版）
# ---------------------------------------------------------------------------
def install_mongosh():
    if shutil.which("mongosh"):
        return
    log("安裝 mongosh（MongoDB 官方 tgz，查最新版號）...")
    api = "https://api.github.com/repos/mongodb-js/mongosh/releases/latest"
    tag = json.loads(http_get(api).decode()).get("tag_name", "").lstrip("v")
    if not re.match(r"^\d+\.\d+\.\d+", tag):
        log("錯誤: 無法取得 mongosh 最新版號（%r）" % tag)
        return
    url = "https://downloads.mongodb.com/compass/mongosh-%s-linux-x64.tgz" % tag
    log("下載 %s" % url)
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "mongosh.tgz"
        tgz.write_bytes(http_get(url, timeout=120))
        out = Path(td) / "extract"
        out.mkdir()
        with tarfile.open(tgz) as t:
            t.extractall(out, filter="data")
        bins = list(out.rglob("bin/mongosh"))
        if not bins:
            log("錯誤: tgz 內找不到 bin/mongosh")
            return
        run(sudo_cmd(["install", "-m", "755", str(bins[0]), "/usr/local/bin/mongosh"]))
    log("mongosh 安裝完成" if is_installed("mongosh") else "mongosh 安裝失敗")


# ---------------------------------------------------------------------------
# odat — Oracle Database Attacking Tool（GitHub）
# ---------------------------------------------------------------------------
def install_odat():
    if shutil.which("odat.py"):
        return
    dest = Path("/opt/odat")
    log("安裝 odat（clone quentinhardy/odat → %s）..." % dest)
    if not (dest / ".git").exists():
        run(sudo_cmd(["git", "clone", "--depth", "1",
                      "https://github.com/quentinhardy/odat.git", str(dest)]),
            timeout=600)
    # 依賴（best-effort；cx_Oracle 等可能需要 Oracle client，失敗不阻斷）
    req = dest / "requirements.txt"
    if req.exists():
        r = run(sudo_cmd(["pip3", "install", "-r", str(req), "--break-system-packages"]),
                timeout=600)
        if r.returncode != 0:
            log("警告: odat 依賴安裝未完全成功（掃描時 odat 測試可能無法執行）")
    if not shutil.which("odat.py"):
        run(sudo_cmd(["ln", "-sf", str(dest / "odat.py"), "/usr/local/bin/odat.py"]))
    log("odat 安裝完成" if is_installed("odat.py") else "odat 安裝失敗")


# ---------------------------------------------------------------------------
# testssl.sh — GitHub 單檔工具
# ---------------------------------------------------------------------------
def install_testssl():
    if shutil.which("testssl.sh"):
        return
    dest = Path("/opt/testssl.sh")
    log("安裝 testssl.sh（clone drwetter/testssl.sh → %s）..." % dest)
    if not (dest / ".git").exists():
        run(sudo_cmd(["git", "clone", "--depth", "1",
                      "https://github.com/testssl/testssl.sh.git", str(dest)]),
            timeout=600)
    if not shutil.which("testssl.sh"):
        run(sudo_cmd(["ln", "-sf", str(dest / "testssl.sh"), "/usr/local/bin/testssl.sh"]))
    log("testssl.sh 安裝完成" if is_installed("testssl.sh") else "testssl.sh 安裝失敗")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="安裝 port-scan-tool 依賴的外部工具（冪等）")
    ap.add_argument("--check", action="store_true", help="只列出缺失工具，不安裝")
    ap.add_argument("--no-apt", action="store_true", help="跳過 apt 安裝（只裝特殊來源工具）")
    args = ap.parse_args()

    missing = missing_tools()
    if not missing:
        print("所有工具都已安裝，無需動作。")
        return

    print("缺失工具 (%d): %s" % (len(missing), ", ".join(missing)))
    if args.check:
        return

    apt_missing = [b for b in missing if b not in SPECIAL_INSTALLERS]
    special = [b for b in missing if b in SPECIAL_INSTALLERS]
    print("  將以 apt 安裝: %s" % (", ".join(apt_missing) or "（無）"))
    print("  將以特殊來源安裝: %s" % (", ".join(special) or "（無）"))

    failed = apt_install_tools(apt_missing, args.no_apt)

    for b in special:
        globals()[SPECIAL_INSTALLERS[b]]()

    print("\n=== 安裝結果 ===")
    ok = True
    for b in sorted(missing):
        if is_installed(b):
            print("  [OK]   %s" % b)
        else:
            ok = False
            print("  [FAIL] %s" % b)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
