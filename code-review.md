# Code Review — port-scan-tool

- 審查日期: 2026-08-13
- 審查對象: `scan_ip.py` (1253 行, Python 3 標準函式庫) + `common_ports_test_commands.json` (指令庫, 72 port × 190 指令) + `README.md`
- 審查方法:
  1. 靜態安全掃描 (硬編碼密鑰 / shell=True / eval-exec / pickle)
  2. **獨立 reviewer 子代理**完整閱讀原始碼 + 交叉比對指令庫 (21 條含佔位符指令、38 條含 shell 字元指令、約 10 條 bash -c 包裝)
  3. 多輪 E2E 實測 (假服務 + 真實目標 www.cretech.com.tw 五輪掃描, root/非 root 各若干輪)
- 工具性質: 單一 IP port 風險掃描 (滲透測試輔助), 指令庫驅動 190 條測試, 分級 PASS/WARN/RISK/FAIL/SKIP。安全邊界: exploit 模組永不執行、只觀測不寫入目標

---

## 一、靜態掃描結果

| 檢查項 | 結果 |
|---|---|
| 硬編碼密鑰 / token | ✅ 無 |
| `subprocess(..., shell=True)` | ✅ 無 |
| `eval()` / `exec()` | ✅ 無 |
| `pickle.loads()` | ✅ 無 |

## 二、已核對無問題的項目 (獨立 reviewer 確認)

- `log_lock` 執行緒安全使用正確, 無跨執行緒共享衝突
- results/raw 寫入無 race
- 無路徑穿越 (IP 已剝離 `/`; raw 檔名由 int port + binary basename 組成)
- exploit 模組 (1099 java_rmi_server / 5985 omigod) 確實全數 SKIP, 安全邊界生效

---

## 三、安全發現

### S1 (HIGH) — bash -c 包裝存在本機命令注入
- 位置: `run_one()` L846-865 (插值 + shell_chars 判定 + bash -c 包裝)
- 問題 (兩條可被外部控制的注入鏈, 均已實測確認):
  1. **PTR 反解注入**: 443 埠測試 `echo | timeout 12 openssl s_client -connect {IP}:443 -servername {DOMAIN}` 含管道必走 bash -c。`{DOMAIN}` 來自目標 IP 的 PTR 反解 — **被掃描的目標可控制自己的 DNS PTR 記錄**, 若 PTR 含 `;`、`|`、`$()` 即形成「目標 → 掃描機本機任意命令執行」鏈。
  2. **shlex 失敗 fallback**: 指令原無 shell 字元時走 `shlex.split`; 但 `{PASSWORD}` 等值含單引號 (密碼含引號很常見) 時 shlex 丟 ValueError, L861-865 強制 fallback 到 `bash -c` — 密碼 `';id` 即執行任意命令。
  3. 值含空白 (wordlist/--out 路徑、密碼) 也會破壞 argv 結構。
- 實測: 目標參數 `1.2.3.4; id` 確認原樣注入 bash -c 字串。
- 實際風險說明: 使用情境是使用者對自己授權的目標掃描, 但 PTR 鏈使「掃描目標」本身成為攻擊者, 屬真實缺陷。
- 建議修法: 對模板先 `shlex.split` 成 argv 再以 argv 元素替換佔位符 (完全不經 shell); 必須保留 bash -c 時對每個插值 `shlex.quote()`; 刪除「shlex 失敗 → bash -c」的 fallback (失敗應記錄並 SKIP, 而非升級成 shell 執行)。

### S2 (LOW) — 憑證明文落盤
- 位置: main 模式列印、`run_one()` 指令記錄、raw/*.txt
- 問題: 「模式: 溫和（單一帳密 admin/password)」寫入 scan.log/summary.txt; 所有含 `{PASSWORD}` 的實際執行指令 (如 `-p{PASSWORD}`、`impacket xxx:PASSWORD@IP`) 連同真實密碼寫入 raw 檔與流水帳。
- 建議: 模式行只記帳號; raw/log 對密碼值遮罩; 或文檔聲明憑證會落盤並建議掃描後清 runs/。

---

## 四、邏輯問題 (獨立 reviewer, 按嚴重度)

### L1 (中高) — timeout 只殺直接子程序, 孫程序存活且可能死鎖
- 位置: `run_one()` L902-912
- 問題: bash -c 包裝的管線指令 (openssl/nc/etcdctl 等約 10 條) 衍生孫程序; `p.kill()` 只殺 bash。孫程序若繼承 stdout/stderr pipe, kill 後的 `p.communicate()` 會因 pipe 未關閉**永久阻塞** → worker 執行緒卡死、整個掃描掛住。部分管線內已套 `timeout` 工具 (有界), 但非全部。
- 建議: Popen 加 `start_new_session=True`, timeout 時 `os.killpg()` 殺整個 process group。

### L2 — msf 模組重試被網路失敗誤觸發
- 位置: `run_one()` msf 重試迴圈 L920-946
- 問題: 重試條件是「rc != 0 **或** 載入錯誤」— 連線被拒、目標無回應等純網路失敗也會把模組換名重跑最多 4 次, 每次都是對目標的完整 run (重複掃描、放大流量)。
- 建議: 僅在輸出含「failed to load module / is not a valid module / unknown module」時重試。

### L3 — timed_out 旗標跨重試未重置, 且逾時輸出跳過關鍵字判讀
- 位置: 重試迴圈 + 判讀段
- 問題: 第一次逾時後重試成功, `timed_out` 仍為 True → 誤判 WARN「逾時輸出已截斷」; 逾時但輸出含 `login successful` 等 RISK 關鍵字時也一律不判讀, 吞掉真實發現。
- 建議: 每次嘗試各自記錄 timed_out; 逾時但有輸出時先跑 risk 關鍵字匹配。

### L4 — msf 模組載入失敗窮盡重試後不判 FAIL (假陰性)
- 位置: L962 FAIL 正則
- 問題: 全部重試仍失敗時, 輸出含「failed to load module」但 FAIL 正則 (not found|invalid script|failed to compile|no such script|command not found) 不含該字串 → 落入關鍵字判讀, 常因模組路徑含 mysql/mssql 等字樣被判 WARN 甚至 PASS, 與 README「模組缺失 = FAIL」矛盾。
- 建議: 「failed to load module|is not a valid module|unknown module」加入 FAIL 判別。

### L5 (中) — 200 OK / HTTP/1.x 200 讓正常網站必 RISK
- 位置: GENERIC_KEYWORDS、PORT_KEYWORDS 80 / 8080
- 問題: risk 清單含「200 OK」與「HTTP/1\.[01] 200」— 任何正常 HTTP 200 回應 (curl -I 首頁、nmap http-title 輸出) 都判 RISK, 一般網站每條 HTTP 測試必 RISK; GENERIC 的 200 OK 也讓無專表埠 (5601/8888/9000 等) 任何 web 200 都 RISK, 嚴重淹沒真實發現。合理用途只有 http-trace (該測試已自帶 risk 正則)。
- 建議: 從 GENERIC / 80 / 8080 risk 移除, 需要的話放 warn。

### L6 — bash 包裝指令的 bin0 提取錯誤 → 缺工具時不 SKIP 反變 FAIL
- 位置: L878-883
- 問題: bash 包裝路徑 bin0 取到管線第一段 (echo/printf), 真實 binary (nc/openssl) 不在 missing_bins 檢查範圍 → 工具缺失時不 SKIP, 執行後 rc=127 → FAIL, 與非包裝路徑 (缺工具 → SKIP) 行為不一致。
- 建議: 包裝路徑先剝 timeout 前綴再取首 token 當 bin0, 或對管線內所有 binary 逐一檢查。

### L7 — Ctrl-C 中斷不即時且結果殘缺
- 位置: main 執行段
- 問題: `with ThreadPoolExecutor` 退出時 `shutdown(wait=True)` 會等所有 in-flight 測試跑完 (單個最長 300s), 中斷既不即時; 已跑完但未被 `as_completed` 收集的結果也不進 results.json。
- 建議: except KeyboardInterrupt 內 `ex.shutdown(cancel_futures=True, wait=False)`。

### L8 — top1000.txt 無防護 open
- 位置: `scan_ports()` L622
- 問題: 檔案缺失即 FileNotFoundError 整個程式崩潰, 即使 nmap 可用、根本用不到該 fallback 清單。
- 建議: `is_file()` 檢查或 try/except 記警告。

### L9 — fb_* fallback 未捕 socket 錯誤 → 整個掃描崩潰
- 位置: `fb_redis_ping` / `fb_smtp_user_enum` + main `fut.result()`
- 問題: 目標埠關閉時 `create_connection` 丟 ConnectionRefusedError、EHLO 迴圈 `socket.timeout` 未捕; 例外經 `fut.result()` 直達 main — run_one 無頂層兜底 except → **整個掃描中止、不產出 results.json**。
- 建議: fallback 內捕 OSError/socket.timeout 回傳錯誤字串; run_one 包一層 try/except 把未預期例外轉 FAIL。

### L10 (LOW) — rsync 873 risk 含裸「@」
- 位置: PORT_KEYWORDS 873
- 問題: 任何含 @ 的行都判 RISK, 接近隨機命中。
- 建議: 改 `\S+@\S+` 或降為 warn。

---

## 五、建議 (非阻斷)

| # | 位置 | 建議 |
|---|---|---|
| N1 | 27017 | mongo risk 用子字串「ok」會命中 broken/OK/cookie 等 → 改 `ok\s*:\s*1` 錨定 |
| N2 | scan_ports | 兩階段 TCP 掃描共用一個 try: 第一階段失敗會跳過第二階段並整體退回 fallback → 每階段各自 try/except |
| N3 | 3306 | risk 含 `^\d+\.\d+` 會把版本 banner 判 RISK, 與「banner 屬 WARN」語義矛盾 → 移 warn |
| N4 | run_one | 每個含 {DOMAIN} 的測試各自做 PTR 反解無快取 → main 層快取一次 |
| N5 | 993/995 | Dovecot 不主動關連線, 原本掛 60s (已加 timeout 12 緩解); 自家服務可考慮 `s_client -brief` |
| N6 | top1000.txt | 已降級為 fallback 專用, 建議註明或刪除避免誤解 |
| N7 | 目標確認 | TTY 等待 Enter 是刻意設計, 建議同時印出預估測試數與時間, 避免誤以為卡死 |

---

## 六、本輪驗證期間已修復項目

| 項目 | 問題 | 狀態 |
|---|---|---|
| **S1 指令注入面** | bash -c 插值未跳脫 (PTR/密碼注入鏈) | ✅ 已修 — 插值一律 shlex.quote + 目標字元集白名單 + 刪除 shlex 失敗→bash-c fallback, 單元測試 + bash -n 驗證 |
| **L1 孫程序存活** | timeout 只殺直接子程序, 可能死鎖 | ✅ 已修 — Popen start_new_session + killpg 殺整個 process group |
| **L2 msf 重試誤觸發** | 網路失敗也換名重跑最多 4 次 | ✅ 已修 — 僅載入錯誤觸發重試 |
| **L3 timed_out 未重置** | 重試成功仍判逾時、逾時輸出吞掉 RISK | ✅ 已修 — 每次嘗試獨立旗標 + 有輸出先跑關鍵字匹配 |
| **L4 載入失敗不判 FAIL** | 模組缺失落入關鍵字判讀 (假陰性) | ✅ 已修 — failed to load module 等加入 FAIL 判別 |
| **L5 200 OK 假陽性** | 正常網站每條 HTTP 測試必 RISK | ✅ 已修 — 200 OK 從 GENERIC/80/8080 risk 移入 warn |
| **L6 bash 包裝 bin0** | 管線內真實 binary 不在缺工具檢查範圍 | ✅ 已修 — _missing_bin_in_cmd 檢查管線內所有 binary |
| **L7 Ctrl-C 即時性** | 中斷等待 in-flight 測試、結果殘缺 | ✅ 已修 — shutdown(cancel_futures=True, wait=False) + 收集已完成結果 |
| **L8 top1000 防護** | 檔案缺失直接崩潰 | ✅ 已修 — is_file 檢查, 缺失僅警告 |
| **L9 fallback 崩潰** | fb_* 未捕 socket 錯誤 → 全掃描中止 | ✅ 已修 — fb_* 內部捕 OSError + run_one 捕 OSError + _safe_run 頂層兜底 |
| **L10 rsync @** | 裸 @ 接近隨機命中 | ✅ 已修 — 改 \S+@\S+ |
| 溫和模式帳密互換 | hydra -L/-P、msf USER_FILE/PASS_FILE 全裝反 | ✅ 已修 + 單元測試 |
| nc -n + hostname | 4 個測試 Can't parse IP | ✅ 已修 |
| 非 root UDP | 8 個 -sU 測試誤判 FAIL | ✅ 改 SKIP |
| SSLv2/3 disabled | 安全狀態誤判 RISK | ✅ 需 enabled 才命中 |
| aspnet-debug ERROR | 「use -d to debug」撞 DEBUG 關鍵字 | ✅ DEBUG.{0,10}enabled |
| NOT vulnerable | 否定句誤判 RISK | ✅ (?<!NOT ) 後視 |
| sslscan「或」混入 | 指令變成掃不存在的 host | ✅ KNOWN_FIXES 正規化 |
| ->SSL憑證資訊 註解 | 被 bash 當重新導向, 輸出寫入垃圾檔 | ✅ 剝除 + 清檔 |
| netcat-traditional -w | banner 抓取掛 60s | ✅ GNU timeout 硬包裝 |
| 網路級負面結果 | timed out/refused 誤判 FAIL | ✅ 改 WARN |
| 指令庫路徑 | /root 硬編碼非 root 讀不到 | ✅ repo → /root 自動解析 |
| Popen 編碼 | 非 UTF-8 位元組 UnicodeDecodeError 崩潰 | ✅ errors=replace |
| top1000.txt 資料 | 尾端 token 損壞 (282116379) | ✅ 拆分修復 |
| URL 誤貼 | https://... 當目標白跑 | ✅ 自動剝離 scheme |
| TCP 掃描方式 | 1100 埠長清單 + 自備 top1000 | ✅ nmap --top-ports 1000 + 表格埠補掃 |

---

## 七、結論

- **整體架構**: 良好。職責分離清楚 (轉換層/執行層/判讀層), 併發處理正確, exploit 安全邊界確實生效, 多輪實測 (含真實目標) 穩定產出完整 artifacts。
- **Verdict (獨立 reviewer 初審)**: not passed — 1 個 HIGH 注入面 + 多處邏輯缺陷。
- **覆審狀態**: 初審與複審列出的 S1、L1–L10 **已全部修復**, 經單元測試 + bash -n 語法驗證 + 本機 E2E 冒煙測試 (redis PONG → RISK、msf 正常執行無誤觸發重試、nc 8s 內完成、FAIL 0)。
- **剩餘待辦** (均非阻斷): 第五節 N1–N7 強化建議 (mongo ok 錨定、每階段獨立 try、3306 版本 banner 移 warn、PTR 快取、s_client -brief、top1000 註明、確認畫面印預估時間)
