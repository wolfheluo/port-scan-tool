#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E2E 測試用假服務：25(SMTP) / 110(POP3) / 6379(Redis) / 8080(HTTP+TRACE) / 12345(未知 banner)"""
import socket
import threading


def serve(port, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(16)
    print("listening %d" % port, flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handler, args=(c,), daemon=True).start()


def smtp(c):
    f = c.makefile("rwb")
    f.write(b"220 test.local ESMTP ready\r\n")
    f.flush()
    while True:
        line = f.readline()
        if not line:
            break
        cmd = line.decode(errors="replace").strip().upper()
        if cmd.startswith("EHLO") or cmd.startswith("HELO"):
            f.write(b"250-test.local\r\n250 OK\r\n")
        elif cmd.startswith("VRFY"):
            f.write(b"250 user exists\r\n")
        elif cmd.startswith("QUIT"):
            f.write(b"221 bye\r\n")
            break
        else:
            f.write(b"250 OK\r\n")
        f.flush()
    c.close()


def pop3(c):
    f = c.makefile("rwb")
    f.write(b"+OK POP3 ready\r\n")
    f.flush()
    while True:
        line = f.readline()
        if not line:
            break
        cmd = line.decode(errors="replace").strip().upper()
        if cmd.startswith("USER"):
            f.write(b"+OK user ok\r\n")
        elif cmd.startswith("PASS"):
            # 真實 POP3 伺服器認證失敗會關閉連線（hydra 等這個）
            f.write(b"-ERR auth failed\r\n")
            f.flush()
            f.close()
            c.close()
            return
        elif cmd.startswith("QUIT"):
            f.write(b"+OK bye\r\n")
            break
        else:
            f.write(b"+OK\r\n")
        f.flush()
    c.close()


def redis(c):
    f = c.makefile("rwb")
    while True:
        # 只處理 inline command（redis-cli 預設 inline PING）
        data = f.readline()
        if not data:
            break
        line = data.decode(errors="replace").strip().upper()
        if line == "PING":
            f.write(b"+PONG\r\n")
        else:
            f.write(b"-ERR unknown command\r\n")
        f.flush()
    c.close()


def http8080(c):
    f = c.makefile("rwb")
    req = b""
    while b"\r\n\r\n" not in req:
        chunk = f.readline()
        if not chunk:
            break
        req += chunk
    method = req.split(b" ", 1)[0].decode(errors="replace") if req else ""
    if method == "TRACE":
        f.write(b"HTTP/1.1 200 OK\r\nContent-Type: message/http\r\nContent-Length: 5\r\n\r\nTRACE")
    elif method == "GET":
        f.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 15\r\n\r\n<html>hi</html>")
    else:
        f.write(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
    f.flush()
    c.close()


def raw12345(c):
    c.sendall(b"hello unknown banner\r\n")
    c.close()


if __name__ == "__main__":
    for p, h in [(25, smtp), (110, pop3), (6379, redis), (8080, http8080), (12345, raw12345)]:
        threading.Thread(target=serve, args=(p, h), daemon=True).start()
    import time
    while True:
        time.sleep(60)
