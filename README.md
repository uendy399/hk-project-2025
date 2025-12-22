# MITM攻击与防御演示系统

## 📋 项目简介

本项目是一个完整的中间人攻击（Man-in-the-Middle Attack）与防御演示系统，专为网络安全教育和研究设计。系统提供了完整的攻击工具套件和相应的防御检测机制，帮助学习者深入理解网络攻击原理和防御策略。

### 主要目的

1. **攻击演示**：实现ARP欺骗、DNS欺骗、SSL剥离等中间人攻击技术
2. **密码捕获**：捕获网络中的明文密码和哈希值
3. **密码破解**：使用hashcat和John the Ripper进行密码破解
4. **攻击检测**：实时检测网络中的异常活动和攻击行为
5. **防御对策**：提供针对各种攻击的防御建议和措施

### 适用场景

- 网络安全课程教学
- 渗透测试学习
- 安全研究实验
- 网络防御培训

---

## ✨ 功能特性

### 攻击工具模块

1. **ARP欺骗（ARP Spoofing）**
   - 实现中间人攻击的第一步
   - 将攻击者伪装成网关或目标主机
   - 支持实时启动和停止，自动恢复ARP表

2. **DNS欺骗（DNS Spoofing）**
   - 将特定域名解析到攻击者指定的IP地址
   - 支持多域名同时欺骗
   - 使用netfilterqueue进行数据包拦截和修改

3. **SSL剥离（SSL Stripping）**
   - 将HTTPS连接降级为HTTP
   - 捕获明文传输的密码和敏感信息
   - 实时提取HTTP POST请求中的凭据

4. **密码捕获（Password Capture）**
   - 捕获HTTP、FTP等协议的明文密码
   - 支持多种密码格式识别
   - 实时显示捕获的凭据

5. **密码破解（Password Cracking）**
   - 集成hashcat和John the Ripper
   - 支持多种哈希算法（MD5、SHA1、SHA256等）
   - 使用字典攻击破解密码哈希

### 防御工具模块

1. **攻击检测（Attack Detection）**
   - 实时监控网络流量
   - 检测ARP欺骗攻击
   - 检测DNS欺骗攻击
   - 检测SSL剥离攻击
   - 生成详细的攻击报告

2. **防御对策（Countermeasures）**
   - ARP保护建议
   - HTTPS强制使用
   - DNS安全配置
   - 防火墙规则建议
   - 入侵检测系统建议

### 辅助工具模块

1. **网络扫描（Network Scanner）**
   - 扫描局域网中的活动主机
   - 获取主机IP、MAC地址和主机名
   - 识别网络拓扑

2. **数据包分析（Packet Analyzer）**
   - 捕获和分析网络数据包
   - SSL/TLS握手协议分析
   - 异常流量检测

### 图形用户界面

- 直观的标签页设计
- 实时日志显示
- 攻击结果可视化
- 一键启动/停止攻击
- 防御报告生成

---

## 🛠️ 系统要求

### 操作系统

- **Kali Linux** (推荐) 或 Ubuntu/Debian
- Python 3.7 或更高版本

### 硬件要求

- 至少 2GB RAM
- 网络接口卡（支持混杂模式）
- 足够的磁盘空间（用于日志和捕获数据）

### 软件依赖

- Python 3.7+
- root权限（某些功能需要）
- 网络工具（nmap, iptables等）

---

## 📦 安装步骤

### 1. 克隆或下载项目

```bash
cd /path/to/your/project
# 如果使用git
git clone <repository_url>
cd HK_Project
```

### 2. 安装Python依赖

```bash
# 更新包管理器
sudo apt update

# 安装Python和pip（如果未安装）
sudo apt install python3 python3-pip

# 安装项目依赖
pip3 install -r requirements.txt
```

### 3. 安装系统工具

```bash
# 安装nmap
sudo apt install nmap

# 安装netfilterqueue（用于数据包拦截）
sudo apt install python3-netfilterqueue

# 安装hashcat（可选，用于密码破解）
sudo apt install hashcat

# 安装John the Ripper（可选，用于密码破解）
sudo apt install john

# 安装Wireshark（用于数据包分析）
sudo apt install wireshark
```

### 4. 配置iptables（用于数据包转发）

```bash
# 启用IP转发
sudo sysctl -w net.ipv4.ip_forward=1

# 使IP转发永久生效
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

### 5. 设置权限

```bash
# 某些功能需要root权限
# 建议使用sudo运行程序
sudo python3 main.py
```

---

## 🚀 使用方法

### 启动程序

```bash
# 使用root权限运行（推荐）
sudo python3 main.py

# 或使用普通用户（部分功能可能受限）
python3 main.py
```

### 基本操作流程

#### 1. 网络扫描

1. 打开"网络扫描"标签页
2. 输入网络范围（如：`192.168.1.0/24`）
3. 点击"开始扫描"
4. 查看扫描结果，选择目标主机

#### 2. 执行ARP欺骗

1. 打开"攻击工具"标签页
2. 在"ARP欺骗"部分输入：
   - 目标IP：要攻击的主机IP
   - 网关IP：网络网关IP
3. 点击"开始ARP欺骗"
4. 观察日志输出

#### 3. 执行DNS欺骗

1. 在"DNS欺骗"部分输入：
   - 欺骗域名：要欺骗的域名（多个用逗号分隔）
   - 重定向IP：要重定向到的IP地址
2. 点击"开始DNS欺骗"

#### 4. 执行SSL剥离

1. 点击"开始SSL剥离"
2. 系统将尝试将HTTPS连接降级为HTTP
3. 捕获的凭据将显示在"捕获的凭据"区域

#### 5. 密码捕获

1. 点击"开始密码捕获"
2. 系统将监控网络流量并提取密码
3. 捕获的密码将实时显示

#### 6. 攻击检测

1. 打开"防御工具"标签页
2. 点击"开始检测"
3. 系统将实时监控并检测攻击
4. 点击"生成报告"查看详细报告

#### 7. 应用防御对策

1. 在"防御工具"标签页
2. 点击"应用防御对策"
3. 查看系统提供的防御建议

---

## 🔬 实验环境搭建

### 推荐实验拓扑

```
[攻击者] ---- [交换机] ---- [网关] ---- [互联网]
              |         |
         [受害者1]  [受害者2]
```

### 实验步骤

#### 实验1：ARP欺骗攻击

1. **准备环境**
   - 攻击者：运行本系统的Kali Linux
   - 受害者：任意连接到同一网络的设备
   - 使用Wireshark监控网络流量

2. **执行攻击**
   - 启动ARP欺骗
   - 在受害者设备上ping网关
   - 使用Wireshark观察ARP数据包

3. **分析结果**
   - 检查ARP表中的MAC地址变化
   - 分析Wireshark捕获的数据包
   - 观察网络流量的重定向

#### 实验2：DNS欺骗攻击

1. **准备环境**
   - 确保ARP欺骗已启动
   - 受害者设备连接到网络

2. **执行攻击**
   - 配置DNS欺骗（例如：将`example.com`解析到攻击者IP）
   - 在受害者设备上访问目标域名
   - 观察流量被重定向

3. **分析结果**
   - 使用Wireshark分析DNS响应
   - 检查DNS缓存中的记录
   - 验证域名解析结果

#### 实验3：SSL剥离攻击

1. **准备环境**
   - 启动ARP欺骗和SSL剥离
   - 受害者设备尝试访问HTTPS网站

2. **执行攻击**
   - 受害者访问HTTPS网站
   - 系统尝试将连接降级为HTTP
   - 捕获明文传输的密码

3. **分析结果**
   - 检查捕获的凭据
   - 使用Wireshark分析SSL/TLS握手
   - 验证HTTPS到HTTP的降级

#### 实验4：密码破解

1. **准备哈希值**
   - 从捕获的数据中提取密码哈希
   - 或使用已知的测试哈希

2. **执行破解**
   - 使用hashcat或John the Ripper
   - 选择合适的字典文件
   - 等待破解结果

3. **分析结果**
   - 比较破解时间
   - 分析密码强度
   - 评估字典攻击效果

#### 实验5：攻击检测

1. **启动检测**
   - 在防御者设备上运行攻击检测
   - 同时执行攻击

2. **观察检测结果**
   - 查看实时检测日志
   - 分析检测到的攻击类型
   - 生成检测报告

3. **应用防御**
   - 根据检测结果应用防御对策
   - 验证防御措施的有效性

---

## 📚 技术原理

### ARP欺骗原理

ARP（Address Resolution Protocol）用于将IP地址映射到MAC地址。ARP欺骗攻击通过发送伪造的ARP响应包，使目标主机将攻击者的MAC地址误认为是网关的MAC地址，从而将流量重定向到攻击者。

**防御方法**：
- 使用静态ARP条目
- 启用ARP监控工具
- 使用网络分段

### DNS欺骗原理

DNS欺骗通过伪造DNS响应包，将域名解析到攻击者指定的IP地址。攻击者需要先进行ARP欺骗以拦截DNS请求。

**防御方法**：
- 使用DNSSEC
- 使用可信的DNS服务器
- 验证DNS响应的一致性

### SSL剥离原理

SSL剥离攻击利用用户可能通过HTTP访问HTTPS网站的行为，在中间人位置将HTTPS连接降级为HTTP，从而可以捕获明文数据。

**防御方法**：
- 使用HSTS（HTTP Strict Transport Security）
- 浏览器扩展（如HTTPS Everywhere）
- 证书固定（Certificate Pinning）

### 密码破解原理

密码破解通常使用字典攻击或暴力破解。字典攻击使用常见密码列表，暴力破解尝试所有可能的组合。

**防御方法**：
- 使用强密码
- 启用多因素认证
- 使用密码哈希加盐
- 限制登录尝试次数

---

## ⚠️ 注意事项

### 法律声明

1. **仅用于教育和研究目的**
   - 本工具仅用于授权的安全测试和教育环境
   - 禁止用于非法活动

2. **使用限制**
   - 仅在您拥有或已获得明确授权的网络上使用
   - 未经授权使用本工具可能违反法律

3. **责任声明**
   - 使用者需自行承担使用本工具的所有责任
   - 开发者不对任何误用或滥用负责

### 安全建议

1. **实验环境隔离**
   - 在隔离的实验室环境中进行实验
   - 不要在生产网络中使用

2. **权限管理**
   - 仅在必要时使用root权限
   - 实验结束后及时清理iptables规则

3. **数据保护**
   - 妥善保管捕获的敏感数据
   - 实验结束后删除捕获的数据

---

## 🔧 故障排除

### 常见问题

#### 1. 权限不足错误

**问题**：`Permission denied` 或需要root权限

**解决方案**：
```bash
sudo python3 main.py
```

#### 2. netfilterqueue安装失败

**问题**：无法安装netfilterqueue

**解决方案**：
```bash
sudo apt update
sudo apt install python3-dev libnetfilter-queue-dev
pip3 install netfilterqueue
```

#### 3. IP转发未启用

**问题**：数据包无法转发

**解决方案**：
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

#### 4. iptables规则冲突

**问题**：iptables规则冲突或无法删除

**解决方案**：
```bash
# 查看当前规则
sudo iptables -L -n -v

# 清理规则（谨慎使用）
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
```

#### 5. 网络接口未找到

**问题**：无法找到网络接口

**解决方案**：
```bash
# 查看可用网络接口
ip addr show
# 或
ifconfig

# 在代码中指定正确的接口名称
```

#### 6. 依赖包缺失

**问题**：导入错误或模块未找到

**解决方案**：
```bash
# 重新安装所有依赖
pip3 install -r requirements.txt --upgrade
```

---

## 📖 使用Wireshark分析

### 分析ARP欺骗

1. 启动Wireshark
2. 选择网络接口
3. 使用过滤器：`arp`
4. 观察ARP请求和响应
5. 检查MAC地址映射的一致性

### 分析DNS欺骗

1. 使用过滤器：`dns`
2. 查找DNS查询和响应
3. 检查DNS响应的IP地址
4. 验证域名解析的正确性

### 分析SSL/TLS握手

1. 使用过滤器：`tcp.port == 443`
2. 查找Client Hello和Server Hello
3. 分析证书交换过程
4. 检查是否有异常或降级

---

## 🎓 学习资源

### 推荐阅读

1. **网络协议**
   - ARP协议详解
   - DNS协议原理
   - SSL/TLS握手过程

2. **安全工具**
   - Wireshark使用指南
   - Scapy文档
   - Nmap参考手册

3. **防御技术**
   - 网络入侵检测系统
   - 防火墙配置
   - 加密通信协议

### 相关工具

- **Wireshark**：网络协议分析器
- **Ettercap**：综合MITM攻击工具
- **Bettercap**：现代MITM框架
- **Burp Suite**：Web应用安全测试
- **Metasploit**：渗透测试框架

---

## 📝 项目结构

```
HK_Project/
├── main.py                 # 主程序入口
├── requirements.txt        # Python依赖
├── README.md              # 项目文档
│
├── attacks/               # 攻击模块
│   ├── __init__.py
│   ├── arp_spoof.py       # ARP欺骗
│   ├── dns_spoof.py       # DNS欺骗
│   ├── ssl_strip.py       # SSL剥离
│   └── password_capture.py # 密码捕获
│
├── defense/               # 防御模块
│   ├── __init__.py
│   ├── attack_detector.py # 攻击检测
│   └── countermeasures.py # 防御对策
│
├── utils/                 # 工具模块
│   ├── __init__.py
│   ├── network_scanner.py # 网络扫描
│   └── packet_analyzer.py # 数据包分析
│
└── gui/                   # 图形界面
    ├── __init__.py
    └── main_window.py     # 主窗口
```

---

## 🤝 贡献指南

欢迎提交问题报告和改进建议。在提交之前，请确保：

1. 代码符合PEP 8规范
2. 添加适当的注释和文档
3. 测试新功能
4. 更新README（如需要）

---

## 📄 许可证

本项目仅用于教育和研究目的。使用者需遵守当地法律法规。

---

## 👥 作者

专业资安研究团队

---

## 🔄 更新日志

### v1.0.0 (2024)
- 初始版本发布
- 实现ARP欺骗、DNS欺骗、SSL剥离
- 实现密码捕获和破解
- 实现攻击检测和防御
- 图形用户界面

---

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交Issue
- 发送邮件

---

## 🙏 致谢

感谢以下开源项目和工具：

- Scapy - 数据包操作库
- Python-nmap - Nmap Python接口
- NetfilterQueue - 数据包队列处理
- Tkinter - GUI框架

---

**⚠️ 再次提醒：本工具仅用于合法的安全测试和教育目的。请确保在授权环境中使用，并遵守相关法律法规。**

