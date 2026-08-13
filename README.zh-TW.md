# scan_ip.py — 單一 IP Port 風險掃描器（JSON 指令庫驅動）

[English](README.md) | [繁體中文](README.zh-TW.md)

由 JSON 指令庫（`common_ports_test_commands.json`，72 port × 190 指令）驅動的自動化滲透測試輔助工具。給定單一 IP，工具會偵測開啟的 port、執行指令庫定義的服務特定測試、分級每個結果，並產出完整的稽核軌跡供事後離線分析。

## 工作流程

1. **前置檢查** — 檢查所需 binary；缺失工具會以 `apt-get install` 自動安裝（可用 `--no-install` 關閉）。binary 仍不可用的測試（如 Kali 限定工具）會以 `SKIP` 記錄。
2. **指令庫載入與轉換** — 載入 JSON 指令庫並套用轉換層：
   - `msf6>` 前綴解析為 `msfconsole -q -x` 呼叫。
   - 佔位符（`{IP}`、`{PORT}`、`{DOMAIN}`、`{USER}`、`{PASSWORD}`、`{USERLIST}`、`{PASSWORDS}`、`{PATH}`）於執行時填充。
   - 修正來源表格的已知 typo（每筆以「表格原文 vs 修正後」記錄）。
   - msf 模組載入失敗時以自動修正重試（補 `auxiliary/` 前綴、常見拼寫錯誤）。
3. **掃描** — `nmap -Pn -sT -T4` 列舉 TCP port（nmap 內建 top-1000 ∪ 表格埠 ∪ web 埠；`--full-port` 改為 `-p-`）。指令庫引用的 UDP 埠（`-sU` 指令）做定點探測。表格外的 port 以 `nmap -sV --version-light` 抓取特徵並記錄為「開啟但無對應測試」。
4. **執行** — 依開啟的 port 派發測試，可設定並行度（預設 `--jobs 4`）。每行 log 帶 `[HH:MM:SS][port][test]` 前綴便於事後關聯。
5. **判讀** — 每個測試依各 port 關鍵字表分類：
   - `RISK` — 安全相關發現（如 HTTP TRACE 開啟、FTP 匿名登入、SMBv1、弱 TLS、未認證 Redis PONG、MS17-010）。
   - `WARN` — 資訊性暴露（banner、版本、使用者列舉）。
   - `PASS` — 無異常輸出。
   - `FAIL` — 指令執行失敗（rc≠0、逾時無輸出、script/模組缺失）。
   - `SKIP` — 測試未執行（exploit 模組、工具缺失、`{DOMAIN}` 無 PTR 反解、headless 環境的 GUI 工具）。
6. **產出** — 寫入 `runs/<YYYYMMDD_HHMMSS>_<IP>/`：
   - `scan.log` — 每個指令與結果的流水帳稽核軌跡。
   - `results.json` — 結構化機器可讀結果。
   - `summary.txt` — 人讀總結（RISK/WARN/FAIL/SKIP 清單）。
   - `raw/<port>_<test>.txt` — 每個測試的完整原始輸出（證據）。

## 使用方式

```bash
python3 scan_ip.py <IP> [options]
```

`<IP>` 可省略：互動模式下會提示輸入（也可用管線餵入：`echo example.com | python3 scan_ip.py`）。

| 選項 | 預設值 | 說明 |
|---|---|---|
| `--wordlist FILE` | `wordlist.txt` | 爆破測試用的密碼清單（`--brute` 模式）。 |
| `--userlist FILE` | `userlist.txt` | 爆破/列舉測試用的帳號清單。 |
| `--jobs N` | `4` | 並行測試 worker 數。 |
| `--timeout N` | 分級 | 覆寫單一測試逾時（秒）。 |
| `--no-install` | off | 不自動以 apt 安裝缺失工具。 |
| `--out DIR` | `runs/` | 輸出根目錄。 |
| `--brute` | off | 載入完整字典爆破（預設為單一帳密）。 |
| `--user U` | `admin` | 溫和模式單一帳號。 |
| `--password P` | `password` | 溫和模式單一密碼。 |
| `--full-port` | off | TCP 全埠掃描 `-p-`（預設 nmap top-1000 + 表格/web 埠）。 |
| `--table FILE` | 自動 | JSON 指令庫路徑（預設依序找 repo 目錄、`/root/common_ports_test_commands.json`）。 |
| `--dry-run` | off | 不連目標，驗證指令庫可執行性。 |
| `--check-tools` | off | 列出缺失的外部工具（不安裝）。 |
| `--install-tools` | off | 安裝所有缺失的外部工具後結束（需 root/sudo；apt + mongosh/odat/testssl.sh 特殊來源）。 |

### 模式

- **溫和（預設）** — 爆破類指令只嘗試單一帳密（`--user/--password`）。指令庫的字典佔位符指向單行臨時檔，hydra/msf/thc-pptp-bruter 都只試一組組合。
- **爆破（`--brute`）** — 爆破類指令載入完整 `--wordlist/--userlist`。
- **乾跑（`--dry-run`）** — 驗證每條指令庫指令的 binary 存在、每個 msf 模組可載入（單次 msfconsole 批次），產出 `dryrun_report.txt`，不碰目標。

## 涵蓋服務

FTP (21)、SSH (22)、Telnet (23)、SMTP (25)、DNS (53)、TFTP (69)、HTTP (80)、Kerberos (88)、POP3 (110)、Portmapper (111)、NTP (123)、MSRPC (135)、NetBIOS (139)、SNMP (161)、BGP (179)、LDAP (389)、HTTPS (443)、SMB (445)、ISAKMP (500)、r* 服務 (512-514)、LPD (515)、AFP (548)、IPMI (623)、LDAPS (636)、rsync (873)、IMAPS (993)、POP3S (995)、SOCKS (1080)、Java RMI (1099)、OpenVPN (1194)、Lotus Domino (1352)、MSSQL (1433)、Oracle (1521)、PPTP (1723)、MQTT (1883)、NFS (2049)、ZooKeeper (2181)、Docker API (2375)、etcd (2379)、Grafana (3000)、Squid (3128)、AD Global Catalog (3268)、MySQL (3306)、RDP (3389)、Erlang (4369)、HTTP 備用埠 (5000)、SIP (5060)、PostgreSQL (5432)、Kibana (5601)、AMQP (5672)、VNC (5900)、WinRM (5985)、Redis (6379)、WebLogic (7001)、AJP (8009)、HTTP 備用埠 (8080)、ActiveMQ (8161)、HTTPS 備用埠 (8443)、Jupyter (8888)、HTTP 備用埠 (9000)、JBoss (9080)、Kafka (9092)、Elasticsearch (9200)、Webmin (10000)、Memcached (11211)、MongoDB (27017)、Hadoop NameNode (50070)、ActiveMQ OpenWire (61616)、HTTP TRACE/TRACK。

## 安全邊界

- **exploit 模組永不執行。** 如 `exploit/multi/misc/java_rmi_server`、`linux/misc/cve_2021_38647_omigod` 這類模組會被分類為 exploit 並以 `SKIP` 跳過。
- 工具絕不寫入、修改或刪除目標上的任何東西；純粹觀測。
- 爆破預設為單一帳密；完整字典需明確加 `--brute`。
- GUI 工具（`vncviewer`、`xfreerdp`）在 headless 環境自動 SKIP。

## 驗證

- **乾跑** — 190 條指令全數驗證：18/18 msf 模組載入成功；環境中存在的 binary 通過，缺失者（如 crackmapexec、mongosh、testssl.sh）列為 SKIP 並可用 `--install-tools` 安裝。
- **端對端** — 本機模擬服務（SMTP、POP3、Redis、HTTP TRACE、未分類 banner port）驗證：port 偵測、測試派發、判讀與 artifacts 完整（`FAIL 0`）；另於真實目標 mail-cretech.com.tw 多輪實測收斂至 46 測試 `FAIL 0`（含 MySQL 8 TLS 弱密碼測試、TLSv1.1 偵測等）。

## 已知問題

- hydra 對「認證失敗後不關閉連線」的模擬 POP3 服務會掛住（等待連線關閉）；真實 POP3 伺服器認證失敗會關閉連線，故此限制僅存在於模擬環境。

## 依賴

僅 Python 3 標準函式庫（無 pip 套件）。外部工具於執行時偵測並隨需安裝：nmap、nc、hydra、sslscan、smbclient、smbmap、rpcclient、mysql、dnsrecon、msfconsole、impacket-rpcdump、curl、masscan、redis-tools、nbtscan、smtp-user-enum、thc-pptp-bruter、nfs-common、snmp、tftp-hpa、ntpsec、ldap-utils、dnsutils、samba-common-bin、postgresql-client、sqsh、ipmitool、etcd-client、tigervnc-viewer、freerdp3-x11、rsh-redone-client、rusers、onesixtyone、ike-scan、proxychains4、swaks、python3-impacket、crackmapexec、ncat、mongosh、odat、testssl.sh。
