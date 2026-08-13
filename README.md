# scan_ip.py — Single-IP Port Risk Scanner (JSON Library Driven)

An automated penetration-testing utility driven by a JSON command library
(`common_ports_test_commands.json`, 72 ports × 190 commands). Given a single
IP address, the tool detects open ports, executes the service-specific tests
defined in the library, grades each result, and produces a complete audit
trail for subsequent offline analysis.

## Workflow

1. **Preflight** — verifies required binaries; missing tools are installed
   automatically via `apt-get install` (skippable with `--no-install`). Tests
   whose binary remains unavailable (e.g. Kali-only tools) are skipped and
   logged as `SKIP`.
2. **Library loading & conversion** — loads the JSON command library and
   applies a conversion layer:
   - `msf6>` prefixes are parsed into `msfconsole -q -x` invocations.
   - Placeholders (`{IP}`, `{PORT}`, `{DOMAIN}`, `{USER}`, `{PASSWORD}`,
     `{USERLIST}`, `{PASSWORDS}`, `{PATH}`) are filled at runtime.
   - Known typos in the source table are corrected (each logged as
     "表格原文 vs 修正後").
   - msf modules that fail to load are retried with automatic fixes
     (`auxiliary/` prefix, common misspellings).
3. **Scanning** — `nmap -Pn -sT -T4` enumerates TCP ports
   (top-1000 ∪ table ports ∪ web ports; `--full-port` switches to `-p-`).
   UDP ports referenced by the library (`-sU` commands) are probed
   point-targeted. Ports outside the table are fingerprinted with
   `nmap -sV --version-light` and recorded as "open with no matching test".
4. **Execution** — tests are dispatched per open port with configurable
   parallelism (`--jobs 4` by default). Every log line carries an
   `[HH:MM:SS][port][test]` prefix for post-hoc correlation.
5. **Grading** — each test is classified by a per-port keyword table:
   - `RISK` — security-relevant finding (e.g. HTTP TRACE enabled, anonymous
     FTP, SMBv1, weak TLS, unauthenticated Redis PONG, MS17-010).
   - `WARN` — informational exposure (banner, version, user enumeration).
   - `PASS` — no anomalous output.
   - `FAIL` — command failed to execute (rc≠0, timeout with no output,
     missing script/module).
   - `SKIP` — test not executed (exploit module, missing tool, no PTR
     reverse for `{DOMAIN}`, GUI tool in headless environment).
6. **Artifacts** — written to `runs/<YYYYMMDD_HHMMSS>_<IP>/`:
   - `scan.log` — chronological audit trail of every command and outcome.
   - `results.json` — structured machine-readable results.
   - `summary.txt` — human-readable summary (RISK/WARN/FAIL/SKIP lists).
   - `raw/<port>_<test>.txt` — full raw output of each test (evidence).

## Usage

```bash
python3 scan_ip.py <IP> [options]
```

| Option | Default | Description |
|---|---|---|
| `--wordlist FILE` | `wordlist.txt` | Password list for brute-force tests (`--brute` mode). |
| `--userlist FILE` | `userlist.txt` | Username list for brute-force/enumeration tests. |
| `--jobs N` | `4` | Number of parallel test workers. |
| `--timeout N` | graded | Override per-test timeout (seconds). |
| `--no-install` | off | Do not auto-install missing tools via apt. |
| `--out DIR` | `runs/` | Output root directory. |
| `--brute` | off | Full-wordlist brute force (default: single credential pair). |
| `--user U` | `admin` | Single username for gentle-mode brute attempts. |
| `--password P` | `password` | Single password for gentle-mode brute attempts. |
| `--full-port` | off | Full TCP scan `-p-` (default: top1000+table union). |
| `--table FILE` | `/root/common_ports_test_commands.json` | JSON command library path. |
| `--dry-run` | off | Validate all library commands are executable without targeting a host. |

### Modes

- **Gentle (default)** — brute-force commands try a single credential pair
  (`--user/--password`). The library's wordlist placeholders are pointed at
  one-line temp files, so hydra/msf/thc-pptp-bruter all attempt exactly one
  combination.
- **Brute (`--brute`)** — brute-force commands load the full
  `--wordlist/--userlist`.
- **Dry-run (`--dry-run`)** — verifies every library command's binary exists
  and every msf module loads (batched in a single msfconsole session),
  producing `dryrun_report.txt` without touching a target.

## Covered Services

FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53), TFTP (69), HTTP (80),
Kerberos (88), POP3 (110), Portmapper (111), NTP (123), MSRPC (135),
NetBIOS (139), SNMP (161), BGP (179), LDAP (389), HTTPS (443), SMB (445),
ISAKMP (500), r* services (512-514), LPD (515), AFP (548), IPMI (623),
LDAPS (636), rsync (873), IMAPS (993), POP3S (995), SOCKS (1080),
Java RMI (1099), OpenVPN (1194), Lotus Domino (1352), MSSQL (1433),
Oracle (1521), PPTP (1723), MQTT (1883), NFS (2049), ZooKeeper (2181),
Docker API (2375), etcd (2379), Grafana (3000), Squid (3128),
AD Global Catalog (3268), MySQL (3306), RDP (3389), Erlang (4369),
HTTP alt (5000), SIP (5060), PostgreSQL (5432), Kibana (5601),
AMQP (5672), VNC (5900), WinRM (5985), Redis (6379), WebLogic (7001),
AJP (8009), HTTP alt (8080), ActiveMQ (8161), HTTPS alt (8443),
Jupyter (8888), HTTP alt (9000), JBoss (9080), Kafka (9092),
Elasticsearch (9200), Webmin (10000), Memcached (11211), MongoDB (27017),
Hadoop NameNode (50070), ActiveMQ OpenWire (61616), HTTP TRACE/TRACK.

## Safety Boundaries

- **Exploit modules are never executed.** Modules such as
  `exploit/multi/misc/java_rmi_server` and
  `linux/misc/cve_2021_38647_omigod` are classified as exploit and skipped
  with a `SKIP` result.
- The tool never writes to, modifies, or deletes anything on the target; it
  is purely observational.
- Brute-force is single-credential by default; full wordlists require an
  explicit `--brute` flag.
- GUI tools (`vncviewer`, `xfreerdp`) are skipped in headless environments.

## Verification

- **Dry-run** — all 190 library commands verified: 43 binaries present,
  18/18 msf modules load successfully. 4 Kali-only tools without apt
  packages (snmp-check, odat.py, mongosh, testssl.sh) are SKIP-listed.
- **End-to-end** — verified against a local harness (`test_server.py`)
  exposing simulated SMTP, POP3, Redis, HTTP (TRACE-enabled), and an
  unclassified banner port on `127.0.0.1`:
  - 5 ports detected, 20 tests dispatched, `FAIL 0`.
  - `http-trace` correctly graded `RISK` (HTTP/1.1 200 OK to TRACE).
  - SMTP/POP3 banners graded `WARN`; msf login modules `PASS`.
  - "NOT VULNERABLE" negative output correctly excluded from RISK.
  - `runs/` artifacts complete (scan.log, results.json, summary.txt, raw/).

## Known Issues

- hydra's POP3 module hangs against the simulated `test_server.py` POP3
  service in docker (waits for connection close after `-ERR`); real POP3
  servers close the connection on auth failure, so this is a harness-only
  limitation.
- `top1000.txt` contains one corrupt token (`282116379` — two ports merged);
  the scanner logs a warning and ignores it.

## Dependencies

Python 3 standard library only (no pip packages). External tools detected at
runtime and installed on demand: nmap, nc, hydra, sslscan, smbclient, smbmap,
rpcclient, mysql, dnsrecon, msfconsole, impacket-rpcdump, curl, masscan,
redis-tools, nbtscan, smtp-user-enum, thc-pptp-bruter, nfs-common, snmp,
tftp-hpa, ntpsec, ldap-utils, dnsutils, samba-common-bin, postgresql-client,
sqsh, ipmitool, etcd-client, tigervnc-viewer, freerdp3-x11, rsh-redone-client,
rusers, onesixtyone, ike-scan, proxychains4, swaks, python3-impacket.
