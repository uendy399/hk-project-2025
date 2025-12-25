# CA證書設置指南

## 概述

SSL中間人攻擊功能使用自簽名CA證書來攔截和解密HTTPS流量。這允許您監聽所有HTTPS連接並捕獲其中的憑證。

## 設置步驟

### 1. 安裝依賴

```bash
pip3 install cryptography --break-system-packages
```

或安裝所有依賴：

```bash
pip3 install -r requirements.txt --break-system-packages
```

### 2. 啟動SSL中間人功能

1. 在GUI中點擊"開始SSL中間人"
2. 系統會自動創建CA證書（如果不存在）
3. CA證書會保存在 `ca_cert.pem`，私鑰在 `ca_key.pem`

### 3. 配置iptables重定向

將HTTPS流量（端口443）重定向到SSL中間人代理端口（預設8443）：

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

### 4. 啟用IP轉發

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### 5. 安裝CA證書到目標系統

#### Linux系統

```bash
# 複製證書到目標系統
sudo cp ca_cert.pem /usr/local/share/ca-certificates/mitm-ca.crt

# 更新證書存儲
sudo update-ca-certificates
```

#### Windows系統

1. 將 `ca_cert.pem` 複製到Windows系統
2. 重命名為 `ca_cert.crt`
3. 雙擊證書文件
4. 選擇"安裝證書"
5. 選擇"本地計算機"
6. 選擇"將所有證書放入下列存儲"
7. 選擇"受信任的根證書頒發機構"
8. 完成安裝

#### macOS系統

1. 將 `ca_cert.pem` 複製到macOS系統
2. 雙擊證書文件
3. 在"鑰匙串訪問"中找到證書
4. 雙擊證書
5. 展開"信任"
6. 將"使用此證書時"設置為"始終信任"

#### Android系統

1. 將 `ca_cert.pem` 複製到Android設備
2. 設置 > 安全性 > 加密與憑證
3. 從存儲設備安裝
4. 選擇證書文件
5. 為證書命名（如"MITM CA"）
6. 選擇"VPN和應用程式"

#### iOS系統

1. 將 `ca_cert.pem` 通過郵件或AirDrop發送到iOS設備
2. 在iOS設備上打開證書
3. 設置 > 一般 > 關於本機 > 憑證信任設定
4. 啟用對根憑證的完全信任

### 6. 驗證設置

1. 確保ARP欺騙已啟動
2. 確保SSL中間人已啟動
3. 在目標系統上訪問HTTPS網站
4. 檢查是否有證書警告（如果CA未安裝）
5. 如果CA已正確安裝，不應該有警告

## 使用流程

1. **啟動ARP欺騙**
   - 目標IP: 目標設備的IP
   - 閘道IP: 路由器的IP

2. **啟動SSL中間人**
   - 監聽端口: 8443（或自定義）
   - 點擊"開始SSL中間人"

3. **配置iptables**（如果尚未配置）
   ```bash
   sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
   ```

4. **在目標系統上安裝CA證書**（見上方步驟）

5. **讓目標進行HTTPS登入**
   - 訪問任何HTTPS網站
   - 進行登入操作

6. **查看捕獲的憑證**
   - 在GUI的"捕獲的憑證"區域查看結果

## 清理

停止SSL中間人後，可以清理iptables規則：

```bash
sudo iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

## 注意事項

1. **法律合規**: 僅在您擁有或已獲得明確授權的系統上安裝CA證書

2. **證書安全**: CA私鑰 (`ca_key.pem`) 必須保密，不要分享給他人

3. **證書有效期**: CA證書有效期為10年，生成的網站證書有效期為1年

4. **瀏覽器警告**: 如果CA未安裝，瀏覽器會顯示證書警告，這可能引起目標注意

5. **HSTS**: 某些網站使用HSTS（HTTP Strict Transport Security），可能無法進行中間人攻擊

6. **證書固定**: 某些應用程式使用證書固定，即使安裝了CA也無法攔截

## 故障排除

### 問題：無法捕獲HTTPS流量

**可能原因**:
- iptables規則未正確配置
- IP轉發未啟用
- CA證書未安裝到目標系統
- 目標使用證書固定

**解決方案**:
1. 檢查iptables規則: `sudo iptables -t nat -L -n -v`
2. 檢查IP轉發: `sysctl net.ipv4.ip_forward`
3. 驗證CA證書是否正確安裝
4. 檢查目標應用是否使用證書固定

### 問題：證書警告

**原因**: CA證書未安裝到目標系統

**解決方案**: 按照上方步驟安裝CA證書

### 問題：連接被拒絕

**可能原因**: 端口被佔用或防火牆阻擋

**解決方案**:
1. 檢查端口是否被佔用: `sudo netstat -tulpn | grep 8443`
2. 檢查防火牆規則: `sudo iptables -L -n -v`
3. 嘗試使用其他端口

## 進階配置

### 自定義端口

在GUI中修改"監聽端口"欄位，或直接修改程式碼中的預設端口。

### 證書緩存

系統會自動緩存為每個域名生成的證書，避免重複生成。緩存在記憶體中，重啟後會清除。

### 日誌記錄

所有捕獲的憑證都會記錄在GUI的"捕獲的憑證"區域，並保存在記憶體中直到程式關閉。

