#!/usr/bin/env python3
"""
防御对策模块
提供针对各种攻击的防御措施
"""

import subprocess
import sys

class Countermeasures:
    def __init__(self):
        """初始化防御对策"""
        pass
    
    def enable_arp_protection(self):
        """启用ARP保护"""
        print("[*] 启用ARP保护...")
        
        try:
            # 设置静态ARP条目（需要管理员权限）
            # 这可以防止ARP欺骗
            print("提示: 手动设置静态ARP条目可以防止ARP欺骗")
            print("命令示例: arp -s <gateway_ip> <gateway_mac>")
            return True
        except Exception as e:
            print(f"启用ARP保护错误: {e}")
            return False
    
    def enable_https_only(self):
        """强制使用HTTPS"""
        print("[*] 启用HTTPS强制...")
        print("提示: 使用浏览器扩展如 'HTTPS Everywhere' 可以强制使用HTTPS")
        print("提示: 在服务器端配置HSTS (HTTP Strict Transport Security)")
        return True
    
    def enable_dns_security(self):
        """启用DNS安全"""
        print("[*] 启用DNS安全...")
        
        try:
            # 使用DNSSEC验证DNS响应
            print("提示: 配置DNSSEC可以防止DNS欺骗")
            print("提示: 使用可信的DNS服务器（如8.8.8.8, 1.1.1.1）")
            
            # 检查当前DNS设置
            result = subprocess.run(['cat', '/etc/resolv.conf'], 
                                  capture_output=True, text=True)
            print(f"当前DNS配置:\\n{result.stdout}")
            
            return True
        except Exception as e:
            print(f"启用DNS安全错误: {e}")
            return False
    
    def install_intrusion_detection(self):
        """安装入侵检测系统"""
        print("[*] 安装入侵检测系统...")
        print("提示: 可以使用以下工具:")
        print("  - Snort: 网络入侵检测系统")
        print("  - Suricata: 高性能IDS/IPS")
        print("  - OSSEC: 主机入侵检测系统")
        return True
    
    def enable_firewall_rules(self):
        """配置防火墙规则"""
        print("[*] 配置防火墙规则...")
        
        try:
            # 示例防火墙规则
            rules = [
                "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",  # SSH
                "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",  # HTTP
                "iptables -A INPUT -p tcp --dport 443 -j ACCEPT", # HTTPS
                "iptables -A INPUT -j DROP",  # 默认拒绝
            ]
            
            print("示例防火墙规则:")
            for rule in rules:
                print(f"  {rule}")
            
            print("\\n注意: 这些规则需要根据实际需求调整")
            return True
        except Exception as e:
            print(f"配置防火墙错误: {e}")
            return False
    
    def monitor_network_traffic(self):
        """监控网络流量"""
        print("[*] 网络流量监控建议...")
        print("提示: 使用以下工具监控网络:")
        print("  - Wireshark: 数据包分析")
        print("  - tcpdump: 命令行数据包捕获")
        print("  - netstat: 网络连接监控")
        print("  - iftop: 实时流量监控")
        return True
    
    def enable_certificate_pinning(self):
        """启用证书固定"""
        print("[*] 证书固定建议...")
        print("提示: 在应用程序中实现证书固定可以防止中间人攻击")
        print("提示: 验证SSL证书的有效性和完整性")
        return True
    
    def apply_all_countermeasures(self):
        """应用所有防御对策"""
        print("=" * 50)
        print("应用防御对策")
        print("=" * 50)
        
        self.enable_arp_protection()
        self.enable_https_only()
        self.enable_dns_security()
        self.install_intrusion_detection()
        self.enable_firewall_rules()
        self.monitor_network_traffic()
        self.enable_certificate_pinning()
        
        print("\\n[+] 防御对策建议已提供")
        print("注意: 某些对策需要手动配置或管理员权限")


