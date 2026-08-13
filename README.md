# scan_ip.py — Single-IP Port Risk Scanner

An automated penetration-testing utility derived from the
`網頁&滲透風險說明表 - 常見port 說明.csv` ("Web & Penetration Risk Description
Table — Common Ports") maintained by the author. Given a single IP address,
the tool detects open ports, executes the service-specific tests defined in
the table, grades each result, and produces a complete audit trail for
subsequent offline analysis.

## Workflow

1. **Preflight** — verifies required binaries; missing tools are installed
   automatically via `apt-get install` (skippable with `--no-install`). Tests
   whose binary remains unavailable are skipped and logged as `WARN`.
2. **Target confirmation** — prints the target, the number of open ports, and
   the number of tests to be executed, then waits for `Enter` before
   proceeding (interactive sessions only; non-interactive sessions continue
   automatically).
3. **Scanning** — `nmap -Pn -T4 --top-ports 1000` enumerates open TCP ports.
   Ports outside the test table are fingerprinted with
   `nmap -sV --version-light` and recorded as "open with no matching test".
4. **Execution** — tests are dispatched per open port with configurable
   parallelism (`--jobs 4` by default). Every log line carries an
   `[HH:MM:SS][port][test]` prefix for post-hoc correlation.
5. **Grading** — each test is classified as one of:
   - `RISK` — a security-relevant finding (e.g. anonymous FTP login, SMB null
     session, weak TLS protocol, unauthenticated Redis, HTTP TRACE enabled).
   - `WARN` — informational exposure (banner, version, user enumeration, OS
     fingerprint).
   - `PASS` — no anomalous output.
   - `SKIP` — test not executed (missing tool or missing wordlist).
6. **Artifacts** — written to `runs/<YYYYMMDD_HHMMSS>_<IP>/`:
   - `scan.log` — chronological audit trail of every command and outcome.
   - `results.json` — structured machine-readable results.
   - `summary.txt` — human-readable summary (RISK/WARN/SKIP lists, open ports).
   - `raw/<port>_<test>.txt` — full raw output of each test (evidence).

## Usage

```bash
python3 scan_ip.py <IP> [options]
```

| Option | Default | Description |
|---|---|---|
| `--wordlist FILE` | `wordlist.txt` | Password list for brute-force tests. |
| `--userlist FILE` | `userlist.txt` | Username list for brute-force/enumeration tests. |
| `--jobs N` | `4` | Number of parallel test workers. |
| `--timeout N` | graded | Override per-test timeout (seconds). Defaults: detect 60, scan 120, brute 300. |
| `--no-install` | off | Do not auto-install missing tools via apt. |
| `--out DIR` | `runs/` | Output root directory. |

## Covered Services

FTP (21), SSH (22), SMTP (25), DNS (53), POP3 (110), DCE/RPC (135),
NetBIOS (139), HTTPS (443), SMB (445), RPC dynamic range (49152–65535),
MSSQL (1433), Oracle (1521), PPTP (1723), MySQL (3306), RDP (3389),
SIP (5060), VNC (5900), WinRM (5985), Redis (6379), JBoss (9080),
ASP.NET debug (80/443), HTTP TRACE/TRACK, Portmapper (111), NFS (2049).

## Deviations from the Source Table

The source table is a human-oriented reference and contains several
instructions that are not directly executable. The following corrections are
applied (each logged under "表格原文" for traceability):

- `auxiliary/sanner/pop3/pop3_login` → `auxiliary/scanner/pop3/pop3_login`
  (typo in module path).
- `auxiliary/scanner/mysql/mssql_login` → `auxiliary/scanner/mssql/mssql_login`
  (module resides under the mssql scanner tree).
- `scanner/http/jboss_vulnscan` → `auxiliary/scanner/http/jboss_vulnscan`
  (missing `auxiliary/` prefix).
- `auxiliary/scanner/sip/option` → `auxiliary/scanner/sip/options`
  (module name).
- `nmap --script=msrpc-enum` → `msrpc-enum-users` (the former script does not
  exist in nmap).
- `nbtscan-unixwiz -n` → `nbtscan` (the Debian package ships `nbtscan`).
- `rpcdump.py` → `impacket-rpcdump` (equivalent Impacket tool).
- Port 5985: the table cites the `cve_2021_38647_omigod` **exploit** module.
  This tool deliberately performs **detection only** (WS-Man probe) and never
  fires an exploit.
- HTTP TRACE is probed with `curl -X TRACE` instead of an interactive
  `telnet` session.
- Hydra invocations are normalized (`-L/-P` list files, `-f` to stop at the
  first credential pair).

## Operational Boundaries

- Single IP only; CIDR/range input is out of scope by design.
- TCP scanning only (top-1000). UDP tests are limited to the DNS NSID probe;
  full UDP coverage requires a separate scan.
- Brute-force tests execute only when a wordlist is available; the bundled
  `wordlist.txt` is a minimal weak-password list intended as a starting point.
- The tool never writes to, modifies, or deletes anything on the target; it is
  purely observational.
- Exploit modules are never executed.

## Verification

End-to-end verification was performed against a local harness
(`test_server.py`) exposing simulated SMTP, POP3, Redis, HTTP (TRACE-enabled),
and an unclassified banner port on `127.0.0.1`, exercising the full
pipeline: preflight tool installation, nmap discovery, test dispatch,
grading, and artifact generation.

## Dependencies

Python 3 standard library only (no pip packages). External tools are
detected at runtime and installed on demand: nmap, nc, hydra, sslscan,
smbclient, smbmap, rpcclient, mysql, dnsrecon, msfconsole,
impacket-rpcdump, curl, masscan, redis-tools, nbtscan, smtp-user-enum,
thc-pptp-bruter, nfs-common.
