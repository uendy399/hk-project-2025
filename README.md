# MITM攻擊與防禦演示系統

## 📋 專案簡介

本專案是一個完整的中間人攻擊（Man-in-the-Middle Attack）與防禦演示系統，專為網路安全教育和研究設計。系統提供了完整的攻擊工具套件和相應的防禦檢測機制，幫助學習者深入理解網路攻擊原理和防禦策略。

### 主要目的

1. **攻擊演示**：實現ARP欺騙、DNS欺騙、SSL剝離等中間人攻擊技術
2. **密碼捕獲**：捕獲網路中的明文密碼和雜湊值
3. **密碼破解**：使用hashcat和John the Ripper進行密碼破解
4. **攻擊檢測**：即時檢測網路中的異常活動和攻擊行為
5. **防禦對策**：提供針對各種攻擊的防禦建議和措施

### 適用場景

- 網路安全課程教學
- 滲透測試學習
- 安全研究實驗
- 網路防禦培訓

---

## ✨ 功能特性

### 攻擊工具模組

1. **ARP欺騙（ARP Spoofing）**
   - 實現中間人攻擊的第一步
   - 將攻擊者偽裝成閘道或目標主機
   - 支援即時啟動和停止，自動恢復ARP表

2. **DNS欺騙（DNS Spoofing）**
   - 將特定網域名稱解析到攻擊者指定的IP位址
   - 支援多網域名稱同時欺騙
   - 使用netfilterqueue進行資料包攔截和修改

3. **SSL剝離（SSL Stripping）**
   - 將HTTPS連線降級為HTTP
   - 捕獲明文傳輸的密碼和敏感資訊
   - 即時提取HTTP POST請求中的憑證

4. **密碼捕獲（Password Capture）**
   - 捕獲HTTP、FTP等協定的明文密碼
   - 支援多種密碼格式識別
   - 即時顯示捕獲的憑證

5. **密碼破解（Password Cracking）**
   - 整合hashcat和John the Ripper
   - 支援多種雜湊演算法（MD5、SHA1、SHA256等）
   - 使用字典攻擊破解密碼雜湊

### 防禦工具模組

1. **攻擊檢測（Attack Detection）**
   - 即時監控網路流量
   - 檢測ARP欺騙攻擊
   - 檢測DNS欺騙攻擊
   - 檢測SSL剝離攻擊
   - 產生詳細的攻擊報告

2. **防禦對策（Countermeasures）**
   - ARP保護建議
   - HTTPS強制使用
   - DNS安全設定
   - 防火牆規則建議
   - 入侵檢測系統建議

### 輔助工具模組

1. **網路掃描（Network Scanner）**
   - 掃描區域網路中的活動主機
   - 取得主機IP、MAC位址和主機名稱
   - 識別網路拓撲

2. **資料包分析（Packet Analyzer）**
   - 捕獲和分析網路資料包
   - SSL/TLS握手協定分析
   - 異常流量檢測

### 圖形使用者介面

- 直觀的標籤頁設計
- 即時日誌顯示
- 攻擊結果視覺化
- 一鍵啟動/停止攻擊
- 防禦報告產生

---

## 🛠️ 系統要求

### 作業系統

- **Kali Linux** (推薦) 或 Ubuntu/Debian
- Python 3.7 或更高版本

### 硬體要求

- 至少 2GB RAM
- 網路介面卡（支援混雜模式）
- 足夠的磁碟空間（用於日誌和捕獲資料）

### 軟體依賴

- Python 3.7+
- root權限（某些功能需要）
- 網路工具（nmap, iptables等）

---

## 📦 安裝步驟

### 1. 複製或下載專案

```bash
cd /path/to/your/project
# 如果使用git
git clone <repository_url>
cd HK_Project
```

### 2. 安裝系統依賴（Kali Linux）

在安裝 Python 套件之前，需要先安裝系統級的依賴函式庫：

```bash
# 更新套件管理器
sudo apt update

# 安裝Python開發套件和編譯工具
sudo apt install python3 python3-pip python3-dev

# 安裝tkinter所需的系統套件（GUI介面需要）
sudo apt install python3-tk

# 安裝netfilterqueue所需的系統函式庫
sudo apt install libnetfilter-queue-dev

# 安裝pcapy所需的系統函式庫
sudo apt install libpcap-dev

# 安裝其他編譯依賴
sudo apt install build-essential libssl-dev libffi-dev
```

### 3. 安裝Python依賴

```bash
# 安裝專案依賴
pip3 install -r requirements.txt --break-system-packages
```

### 4. 安裝系統工具

```bash
# 安裝nmap
sudo apt install nmap

# 安裝netfilterqueue（用於資料包攔截）
sudo apt install python3-netfilterqueue

# 安裝hashcat（可選，用於密碼破解）
sudo apt install hashcat

# 安裝John the Ripper（可選，用於密碼破解）
sudo apt install john

# 安裝Wireshark（用於資料包分析）
sudo apt install wireshark
```

### 5. 設定iptables（用於資料包轉發）

```bash
# 啟用IP轉發
sudo sysctl -w net.ipv4.ip_forward=1

# 使IP轉發永久生效
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

### 6. 設定權限

```bash
# 某些功能需要root權限
# 建議使用sudo執行程式
sudo python3 main.py
```

---

## 🚀 使用方法

### 啟動程式

```bash
# 使用root權限執行（推薦）
sudo python3 main.py

# 或使用一般使用者（部分功能可能受限）
python3 main.py
```

### 基本操作流程

#### 1. 網路掃描

1. 開啟「網路掃描」標籤頁
2. 輸入網路範圍（如：`192.168.1.0/24`）
3. 點擊「開始掃描」
4. 查看掃描結果，選擇目標主機

#### 2. 執行ARP欺騙

1. 開啟「攻擊工具」標籤頁
2. 在「ARP欺騙」部分輸入：
   - 目標IP：要攻擊的主機IP
   - 閘道IP：網路閘道IP
3. 點擊「開始ARP欺騙」
4. 觀察日誌輸出

#### 3. 執行DNS欺騙

1. 在「DNS欺騙」部分輸入：
   - 欺騙網域名稱：要欺騙的網域名稱（多個用逗號分隔）
   - 重新導向IP：要重新導向到的IP位址
2. 點擊「開始DNS欺騙」

#### 4. 執行SSL剝離

1. 點擊「開始SSL剝離」
2. 系統將嘗試將HTTPS連線降級為HTTP
3. 捕獲的憑證將顯示在「捕獲的憑證」區域

#### 5. 密碼捕獲

1. 點擊「開始密碼捕獲」
2. 系統將監控網路流量並提取密碼
3. 捕獲的密碼將即時顯示

#### 6. 攻擊檢測

1. 開啟「防禦工具」標籤頁
2. 點擊「開始檢測」
3. 系統將即時監控並檢測攻擊
4. 點擊「產生報告」查看詳細報告

#### 7. 應用防禦對策

1. 在「防禦工具」標籤頁
2. 點擊「應用防禦對策」
3. 查看系統提供的防禦建議

---

## 🔬 實驗環境搭建

### 推薦實驗拓撲

```
[攻擊者] ---- [交換器] ---- [閘道] ---- [網際網路]
              |         |
         [受害者1]  [受害者2]
```

### 實驗步驟

#### 實驗1：ARP欺騙攻擊

1. **準備環境**
   - 攻擊者：執行本系統的Kali Linux
   - 受害者：任意連接到同一網路的裝置
   - 使用Wireshark監控網路流量

2. **執行攻擊**
   - 啟動ARP欺騙
   - 在受害者裝置上ping閘道
   - 使用Wireshark觀察ARP資料包

3. **分析結果**
   - 檢查ARP表中的MAC位址變化
   - 分析Wireshark捕獲的資料包
   - 觀察網路流量的重新導向

#### 實驗2：DNS欺騙攻擊

1. **準備環境**
   - 確保ARP欺騙已啟動
   - 受害者裝置連接到網路

2. **執行攻擊**
   - 設定DNS欺騙（例如：將`example.com`解析到攻擊者IP）
   - 在受害者裝置上存取目標網域名稱
   - 觀察流量被重新導向

3. **分析結果**
   - 使用Wireshark分析DNS回應
   - 檢查DNS快取中的記錄
   - 驗證網域名稱解析結果

#### 實驗3：SSL剝離攻擊

1. **準備環境**
   - 啟動ARP欺騙和SSL剝離
   - 受害者裝置嘗試存取HTTPS網站

2. **執行攻擊**
   - 受害者存取HTTPS網站
   - 系統嘗試將連線降級為HTTP
   - 捕獲明文傳輸的密碼

3. **分析結果**
   - 檢查捕獲的憑證
   - 使用Wireshark分析SSL/TLS握手
   - 驗證HTTPS到HTTP的降級

#### 實驗4：密碼破解

1. **準備雜湊值**
   - 從捕獲的資料中提取密碼雜湊
   - 或使用已知的測試雜湊

2. **執行破解**
   - 使用hashcat或John the Ripper
   - 選擇合適的字典檔案
   - 等待破解結果

3. **分析結果**
   - 比較破解時間
   - 分析密碼強度
   - 評估字典攻擊效果

#### 實驗5：攻擊檢測

1. **啟動檢測**
   - 在防禦者裝置上執行攻擊檢測
   - 同時執行攻擊

2. **觀察檢測結果**
   - 查看即時檢測日誌
   - 分析檢測到的攻擊類型
   - 產生檢測報告

3. **應用防禦**
   - 根據檢測結果應用防禦對策
   - 驗證防禦措施的有效性

---

## 📚 技術原理

### ARP欺騙原理

ARP（Address Resolution Protocol）用於將IP位址對應到MAC位址。ARP欺騙攻擊透過傳送偽造的ARP回應包，使目標主機將攻擊者的MAC位址誤認為是閘道的MAC位址，從而將流量重新導向到攻擊者。

**防禦方法**：
- 使用靜態ARP條目
- 啟用ARP監控工具
- 使用網路分段

### DNS欺騙原理

DNS欺騙透過偽造DNS回應包，將網域名稱解析到攻擊者指定的IP位址。攻擊者需要先進行ARP欺騙以攔截DNS請求。

**防禦方法**：
- 使用DNSSEC
- 使用可信的DNS伺服器
- 驗證DNS回應的一致性

### SSL剝離原理

SSL剝離攻擊利用使用者可能透過HTTP存取HTTPS網站的行為，在中間人位置將HTTPS連線降級為HTTP，從而可以捕獲明文資料。

**防禦方法**：
- 使用HSTS（HTTP Strict Transport Security）
- 瀏覽器擴充功能（如HTTPS Everywhere）
- 憑證固定（Certificate Pinning）

### 密碼破解原理

密碼破解通常使用字典攻擊或暴力破解。字典攻擊使用常見密碼清單，暴力破解嘗試所有可能的組合。

**防禦方法**：
- 使用強密碼
- 啟用多因素認證
- 使用密碼雜湊加鹽
- 限制登入嘗試次數

---

## ⚠️ 注意事項

### 法律聲明

1. **僅用於教育和研究目的**
   - 本工具僅用於授權的安全測試和教育環境
   - 禁止用於非法活動

2. **使用限制**
   - 僅在您擁有或已獲得明確授權的網路上使用
   - 未經授權使用本工具可能違反法律

3. **責任聲明**
   - 使用者需自行承擔使用本工具的所有責任
   - 開發者不對任何誤用或濫用負責

### 安全建議

1. **實驗環境隔離**
   - 在隔離的實驗室環境中進行實驗
   - 不要在生產網路中使用

2. **權限管理**
   - 僅在必要時使用root權限
   - 實驗結束後及時清理iptables規則

3. **資料保護**
   - 妥善保管捕獲的敏感資料
   - 實驗結束後刪除捕獲的資料

---

## 🔧 故障排除

### 常見問題

#### 1. 權限不足錯誤

**問題**：`Permission denied` 或需要root權限

**解決方案**：
```bash
sudo python3 main.py
```

#### 2. 缺少系統依賴（python-xyz 或編譯錯誤）

**問題**：安裝 Python 套件時提示需要 `python-xyz` 或出現編譯錯誤

**解決方案**：
```bash
# 安裝所有必需的系統依賴
sudo apt update
sudo apt install python3-dev python3-tk libnetfilter-queue-dev libpcap-dev build-essential libssl-dev libffi-dev

# 然後重新安裝 Python 依賴
pip3 install -r requirements.txt --break-system-packages
```

#### 3. tkinter 安裝錯誤

**問題**：`ERROR: Could not find a version that satisfies the requirement tkinter`

**解決方案**：
```bash
# tkinter 不是 pip 套件，需要透過系統套件管理器安裝
sudo apt install python3-tk

# 如果 requirements.txt 中有 tkinter，請移除它（tkinter 是 Python 標準函式庫的一部分）
```

#### 4. pcapy 版本錯誤

**問題**：`ERROR: Could not find a version that satisfies the requirement pcapy>=0.11.5`

**解決方案**：
```bash
# pcapy 的最高可用版本是 0.11.4，已更新 requirements.txt
# 如果仍有問題，可以手動安裝：
pip3 install pcapy==0.11.4 --break-system-packages

# 或者使用系統套件（如果可用）
sudo apt install python3-pcapy
```

#### 5. netfilterqueue安裝失敗

**問題**：無法安裝netfilterqueue

**解決方案**：
```bash
sudo apt update
sudo apt install python3-dev libnetfilter-queue-dev
pip3 install netfilterqueue --break-system-packages
```

#### 6. IP轉發未啟用

**問題**：資料包無法轉發

**解決方案**：
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

#### 7. iptables規則衝突

**問題**：iptables規則衝突或無法刪除

**解決方案**：
```bash
# 查看當前規則
sudo iptables -L -n -v

# 清理規則（謹慎使用）
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
```

#### 8. 網路介面未找到

**問題**：無法找到網路介面

**解決方案**：
```bash
# 查看可用網路介面
ip addr show
# 或
ifconfig

# 在程式碼中指定正確的介面名稱
```

#### 9. nmap 模組未找到

**問題**：`ImportError: No module named 'nmap'`

**解決方案**：
```bash
# 安裝 python-nmap 套件
pip3 install python-nmap --break-system-packages

# 或重新安裝所有依賴
pip3 install -r requirements.txt --break-system-packages
```

**注意**：如果 `python-nmap` 無法安裝，程式會自動使用 `scapy` 進行網路掃描，功能可能略有差異。

#### 10. 依賴套件缺失

**問題**：匯入錯誤或模組未找到

**解決方案**：
```bash
# 重新安裝所有依賴
pip3 install -r requirements.txt --upgrade --break-system-packages
```

---

## 📖 使用Wireshark分析

### 分析ARP欺騙

1. 啟動Wireshark
2. 選擇網路介面
3. 使用過濾器：`arp`
4. 觀察ARP請求和回應
5. 檢查MAC位址對應的一致性

### 分析DNS欺騙

1. 使用過濾器：`dns`
2. 查找DNS查詢和回應
3. 檢查DNS回應的IP位址
4. 驗證網域名稱解析的正確性

### 分析SSL/TLS握手

1. 使用過濾器：`tcp.port == 443`
2. 查找Client Hello和Server Hello
3. 分析憑證交換過程
4. 檢查是否有異常或降級

---

## 🎓 學習資源

### 推薦閱讀

1. **網路協定**
   - ARP協定詳解
   - DNS協定原理
   - SSL/TLS握手過程

2. **安全工具**
   - Wireshark使用指南
   - Scapy文件
   - Nmap參考手冊

3. **防禦技術**
   - 網路入侵檢測系統
   - 防火牆設定
   - 加密通訊協定

### 相關工具

- **Wireshark**：網路協定分析器
- **Ettercap**：綜合MITM攻擊工具
- **Bettercap**：現代MITM框架
- **Burp Suite**：Web應用安全測試
- **Metasploit**：滲透測試框架

---

## 📝 專案結構

```
HK_Project/
├── main.py                 # 主程式入口
├── requirements.txt        # Python依賴
├── README.md              # 專案文件
│
├── attacks/               # 攻擊模組
│   ├── __init__.py
│   ├── arp_spoof.py       # ARP欺騙
│   ├── dns_spoof.py       # DNS欺騙
│   ├── ssl_strip.py       # SSL剝離
│   └── password_capture.py # 密碼捕獲
│
├── defense/               # 防禦模組
│   ├── __init__.py
│   ├── attack_detector.py # 攻擊檢測
│   └── countermeasures.py # 防禦對策
│
├── utils/                 # 工具模組
│   ├── __init__.py
│   ├── network_scanner.py # 網路掃描
│   └── packet_analyzer.py # 資料包分析
│
└── gui/                   # 圖形介面
    ├── __init__.py
    └── main_window.py     # 主視窗
```

---

## 🤝 貢獻指南

歡迎提交問題報告和改進建議。在提交之前，請確保：

1. 程式碼符合PEP 8規範
2. 新增適當的註解和文件
3. 測試新功能
4. 更新README（如需要）

---

## 📄 授權

本專案僅用於教育和研究目的。使用者需遵守當地法律法規。

---

## 👥 作者

專業資安研究團隊

---

## 🔄 更新日誌

### v1.0.0 (2024)
- 初始版本發布
- 實現ARP欺騙、DNS欺騙、SSL剝離
- 實現密碼捕獲和破解
- 實現攻擊檢測和防禦
- 圖形使用者介面

---

## 📞 聯絡方式

如有問題或建議，請透過以下方式聯絡：

- 提交Issue
- 傳送郵件

---

## 🙏 致謝

感謝以下開源專案和工具：

- Scapy - 資料包操作函式庫
- Python-nmap - Nmap Python介面
- NetfilterQueue - 資料包佇列處理
- Tkinter - GUI框架

---

**⚠️ 再次提醒：本工具僅用於合法的安全測試和教育目的。請確保在授權環境中使用，並遵守相關法律法規。**

