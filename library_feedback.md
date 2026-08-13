# 指令庫問題回饋（common_ports_test_commands.json → build_port_cmds.py）

> 由 scan_ip.py v2（JSON 驅動版）dry-run + E2E 驗證發現。
> 掃描器已在轉換層自動處理以下問題（log 標註「表格原文 vs 修正後」），
> 此文件供更新 build_port_cmds.py 的 EXTRA dict 時一併修正原始資料。

## 一、msf 模組路徑錯誤（4 項）

| port | 原文 | 修正 |
|---|---|---|
| 110 | `auxiliary/sanner/pop3/pop3_login` | `auxiliary/scanner/pop3/pop3_login`（typo sanner） |
| 1433 | `auxiliary/scanner/mysql/mssql_login` | `auxiliary/scanner/mssql/mssql_login`（路徑錯誤） |
| 9080 | `scanner/http/jboss_vulnscan` | `auxiliary/scanner/http/jboss_vulnscan`（缺 auxiliary/） |
| 5060 | `auxiliary/scanner/sip/option` | `auxiliary/scanner/sip/options`（模組名） |

## 二、模組不存在 → 需替換（2 項）

| port | 原文 | 問題 | 建議替換 |
|---|---|---|---|
| 8009 | `auxiliary/scanner/http/ajp_requests` | 模組不存在 | `auxiliary/admin/http/tomcat_ghostcat`（Ghostcat 讀檔） |
| 10000 | `auxiliary/scanner/http/webmin_login` | 模組不存在 | `auxiliary/admin/webmin/file_disclosure` |

## 三、EXPLOIT 模組（2 項）— 掃描器一律 SKIP 不執行

| port | 模組 |
|---|---|
| 1099 | `exploit/multi/misc/java_rmi_server` |
| 5985 | `linux/misc/cve_2021_38647_omigod`（原文缺 exploit/ 前綴） |

## 四、nc 指令問題（7 項）

| port | 原文 | 問題 |
|---|---|---|
| 25 | `nc -nvc {IP}` | 無 port → 補 `{PORT}` |
| 25 | `nc -nvc {IP} 25` | `-c` 舊旗標（openbsd nc 不支援）→ `-n -w 5` |
| 110 | `nc -ncv {IP} {PORT}` | `-c` 舊旗標 → `-n -w 5` |
| 23/110/512/513/514 | `nc -nv {IP} <port>` | 無 `-w` 逾時 → 會等 stdin 卡死，補 `-w 5` |

## 五、互動式/GUI 工具（3 項）

| port | 指令 | 問題 |
|---|---|---|
| 3389 | `xfreerdp /v:...` | GUI 需圖形環境，headless SKIP |
| 5900 | `vncviewer {IP}` | GUI 需圖形環境，headless SKIP |
| 5900 | `項目3可將字典檔置換為簡易字典` | **說明文字混入 commands 清單**（非指令） |

## 六、其他（6 項）

| port | 指令 | 問題 |
|---|---|---|
| 6379 | `redis-cli -h {IP} -p 6379` | 無子指令 → 互動模式卡死，補 `PING` |
| 3306 | `mysql -h {IP} -u {USER} -p -P 3306` | `-p` 互動密碼提示 → 補 `-p{PASSWORD}` |
| 88 | `impacket-GetNPUsers.py ...` | `.py` 後綴，系統 binary 為 `impacket-GetNPUsers` |
| 111 | `impacket-rpcdump.py ...` | 同上 → `impacket-rpcdump` |
| 1433 | `impacket-mssqlclient.py ...` | 同上 → `impacket-mssqlclient` |
| 5900 | `msf6> use auxiliary/scanner/vnc/vnc_none_auth` | 正常（無問題，僅列供對照） |

## 七、掃描器自動處理機制（對應 scan_ip.py 的 KNOWN_FIXES）

1. msf6> 前綴解析 → `msfconsole -q -x "use <mod>; set RHOSTS ...; run; exit"`
2. 上述 4 項 msf typo 已知修正
3. msf 模組載入失敗 → 自動重試（補 auxiliary/、sanner→scanner 等 5 條規則）
4. exploit 模組偵測 → SKIP（永不執行）
5. nc 旗標正規化 + 補 port/`-w 5`
6. redis-cli 補 PING、mysql 補 `-p{PASSWORD}`
7. impacket `.py` 後綴剝除
8. GUI 工具 headless SKIP、中文說明行過濾
9. `{DOMAIN}` 需 PTR 反解，失敗 → SKIP
10. docker 環境 nmap 自動補 `--unprivileged`
