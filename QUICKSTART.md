# 快速开始指南

## 5分钟快速上手

### 1. 安装（2分钟）

```bash
# 克隆或进入项目目录
cd HK_Project

# 运行安装脚本
sudo ./install.sh

# 或手动安装
sudo apt update
sudo apt install python3 python3-pip nmap python3-netfilterqueue
pip3 install -r requirements.txt
sudo sysctl -w net.ipv4.ip_forward=1
```

### 2. 启动程序（30秒）

```bash
sudo python3 main.py
```

### 3. 基本操作（2分钟）

#### 扫描网络
1. 打开"网络扫描"标签
2. 输入网络范围：`192.168.1.0/24`
3. 点击"开始扫描"
4. 选择目标主机

#### 执行攻击
1. 打开"攻击工具"标签
2. **ARP欺骗**：
   - 输入目标IP和网关IP
   - 点击"开始ARP欺骗"
3. **DNS欺骗**：
   - 输入要欺骗的域名
   - 输入重定向IP
   - 点击"开始DNS欺骗"
4. **SSL剥离**：
   - 点击"开始SSL剥离"
5. **密码捕获**：
   - 点击"开始密码捕获"

#### 检测防御
1. 打开"防御工具"标签
2. 点击"开始检测"
3. 查看检测结果
4. 点击"生成报告"
5. 点击"应用防御对策"

## 常用命令

### 查看网络接口
```bash
ip addr show
# 或
ifconfig
```

### 查看ARP表
```bash
arp -a
```

### 启用IP转发
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### 查看iptables规则
```bash
sudo iptables -L -n -v
```

### 清理iptables规则（谨慎使用）
```bash
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
```

## 典型实验流程

### 实验1：ARP欺骗演示

```
1. 启动程序
   sudo python3 main.py

2. 扫描网络，找到目标主机

3. 在"攻击工具"中：
   - 目标IP: 192.168.1.100
   - 网关IP: 192.168.1.1
   - 点击"开始ARP欺骗"

4. 在目标主机上ping网关，观察流量

5. 使用Wireshark分析ARP数据包

6. 停止攻击
```

### 实验2：完整MITM攻击

```
1. 启动ARP欺骗
2. 启动DNS欺骗（将example.com指向攻击者IP）
3. 启动SSL剥离
4. 启动密码捕获
5. 让目标主机访问example.com并登录
6. 查看捕获的凭据
7. 停止所有攻击
```

### 实验3：攻击检测

```
1. 在防御者机器上启动攻击检测
2. 在攻击者机器上执行攻击
3. 观察检测结果
4. 生成报告
5. 应用防御对策
```

## 故障排除快速参考

| 问题 | 解决方案 |
|------|---------|
| 权限不足 | 使用 `sudo python3 main.py` |
| netfilterqueue错误 | `sudo apt install python3-netfilterqueue` |
| IP转发未启用 | `sudo sysctl -w net.ipv4.ip_forward=1` |
| 找不到网络接口 | 使用 `ip addr show` 查看接口名 |
| iptables规则冲突 | 清理规则：`sudo iptables -F` |

## 重要提示

⚠️ **法律声明**：本工具仅用于授权的安全测试和教育环境

⚠️ **安全建议**：
- 在隔离的实验室环境中使用
- 实验结束后清理iptables规则
- 妥善保管捕获的敏感数据

## 下一步

- 阅读完整的 [README.md](README.md)
- 查看 [EXAMPLES.md](EXAMPLES.md) 获取详细示例
- 使用Wireshark分析网络流量
- 尝试不同的攻击组合
- 测试防御措施的有效性

---

**需要帮助？** 查看README.md中的详细文档和故障排除部分。

