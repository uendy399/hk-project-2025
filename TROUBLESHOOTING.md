# 故障排除指南

## SSL監聽和密碼截取功能問題

### 常見問題和解決方案

#### 1. 權限問題
**症狀**: 功能啟動但沒有捕獲任何資料包

**解決方案**:
- 確保以root權限執行程式：
  ```bash
  sudo python3 main.py
  ```
- 在Kali Linux上，使用scapy捕獲網路流量需要root權限

#### 2. 網路介面問題
**症狀**: 錯誤訊息顯示 "No such device" 或 "Device not found"

**解決方案**:
- 檢查可用的網路介面：
  ```bash
  ip link show
  # 或
  ifconfig
  ```
- 常見的介面名稱：
  - 有線網路: `eth0`, `ens33`, `enp0s3`
  - 無線網路: `wlan0`, `wlp2s0`
  - 回環介面: `lo` (不應該使用)

#### 3. 沒有HTTP流量
**症狀**: 程式運行正常，但沒有捕獲到憑證

**解決方案**:
- 確保目標正在使用HTTP（端口80）而不是HTTPS（端口443）
- 在測試環境中，可以：
  1. 啟動一個簡單的HTTP伺服器：
     ```bash
     python3 -m http.server 80
     ```
  2. 使用瀏覽器訪問並提交表單
  3. 或者使用curl發送POST請求：
     ```bash
     curl -X POST http://localhost/login -d "username=test&password=test123"
     ```

#### 4. ARP欺騙未啟動
**症狀**: 無法看到目標的流量

**解決方案**:
- SSL監聽和密碼截取功能需要先啟動ARP欺騙才能看到目標的流量
- 步驟：
  1. 先啟動ARP欺騙（指定目標IP和閘道IP）
  2. 然後啟動SSL監聽或密碼截取
  3. 讓目標進行登入操作

#### 5. 防火牆阻擋
**症狀**: 無法捕獲資料包

**解決方案**:
- 檢查iptables規則：
  ```bash
  sudo iptables -L
  ```
- 如果防火牆阻擋，可以暫時關閉：
  ```bash
  sudo iptables -F
  ```

### 調試技巧

#### 檢查程式是否在運行
- 查看終端輸出，應該會看到：
  ```
  [+] SSL剝離已啟動 (介面: eth0)
  [*] 開始捕獲HTTP流量 (過濾器: tcp port 80)
  [*] 已處理 1000 個資料包...
  ```

#### 測試網路捕獲
- 使用tcpdump測試是否可以捕獲HTTP流量：
  ```bash
  sudo tcpdump -i eth0 -n 'tcp port 80' -v
  ```
- 如果tcpdump可以捕獲，但程式不行，可能是程式碼問題
- 如果tcpdump也不能捕獲，可能是權限或介面問題

#### 檢查資料包統計
- 程式會每1000個資料包輸出一次狀態
- 如果看到 "已處理 X 個資料包"，說明捕獲功能正常
- 如果沒有看到任何資料包，可能是：
  - 沒有HTTP流量經過
  - 網路介面選擇錯誤
  - 需要先啟動ARP欺騙

### 在Kali Linux上的特殊注意事項

1. **網路介面名稱**: Kali Linux可能使用不同的介面命名（如 `ens33` 而不是 `eth0`）

2. **權限**: 即使以root執行，某些系統配置可能仍會限制網路捕獲

3. **測試環境**: 建議在虛擬機環境中測試，確保：
   - 目標機器在同一網路
   - 可以進行ARP欺騙
   - 有實際的HTTP流量

### 驗證功能是否正常

1. **啟動ARP欺騙**:
   - 目標IP: 192.168.1.100（範例）
   - 閘道IP: 192.168.1.1（範例）

2. **啟動SSL監聽或密碼截取**

3. **在目標機器上**:
   - 訪問一個HTTP網站（不是HTTPS）
   - 進行登入操作
   - 提交包含username和password的表單

4. **檢查結果**:
   - 查看GUI中的"捕獲的憑證"區域
   - 查看終端輸出是否有捕獲訊息

### 如果仍然無法工作

1. 檢查Python版本（需要3.7+）:
   ```bash
   python3 --version
   ```

2. 檢查依賴是否安裝:
   ```bash
   pip3 list | grep scapy
   ```

3. 查看詳細錯誤訊息:
   - 程式現在會輸出更詳細的錯誤訊息
   - 注意權限錯誤、介面錯誤等訊息

4. 測試scapy是否正常工作:
   ```python
   python3 -c "from scapy.all import sniff; print('Scapy OK')"
   ```

