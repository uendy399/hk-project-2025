#!/usr/bin/env python3
"""
攻击检测模块
检测各种中间人攻击和异常活动
"""

from scapy.all import sniff, ARP, IP, DNS, TCP
from collections import defaultdict
import time

class AttackDetector:
    def __init__(self):
        """初始化攻击检测器"""
        self.detecting = False
        self.arp_table = {}
        self.dns_cache = {}
        self.detected_attacks = []
        self.ssl_connections = {}
    
    def detect_arp_spoofing(self, packet):
        """检测ARP欺骗攻击"""
        if packet.haslayer(ARP):
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            # 检查是否有多个MAC地址映射到同一个IP
            if ip in self.arp_table:
                if self.arp_table[ip] != mac:
                    attack = {
                        'type': 'ARP Spoofing',
                        'ip': ip,
                        'old_mac': self.arp_table[ip],
                        'new_mac': mac,
                        'timestamp': time.time(),
                        'severity': 'HIGH'
                    }
                    self.detected_attacks.append(attack)
                    print(f"[!] 检测到ARP欺骗: IP {ip} 的MAC地址从 {self.arp_table[ip]} 变为 {mac}")
                    return attack
            else:
                self.arp_table[ip] = mac
        
        return None
    
    def detect_dns_spoofing(self, packet):
        """检测DNS欺骗攻击"""
        if packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS response
            try:
                domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                
                if packet[DNS].an:
                    resolved_ip = packet[DNS].an.rdata
                    
                    # 检查DNS响应是否与缓存不一致
                    if domain in self.dns_cache:
                        if self.dns_cache[domain] != resolved_ip:
                            attack = {
                                'type': 'DNS Spoofing',
                                'domain': domain,
                                'old_ip': self.dns_cache[domain],
                                'new_ip': resolved_ip,
                                'timestamp': time.time(),
                                'severity': 'HIGH'
                            }
                            self.detected_attacks.append(attack)
                            print(f"[!] 检测到DNS欺骗: {domain} 从 {self.dns_cache[domain]} 解析到 {resolved_ip}")
                            return attack
                    else:
                        self.dns_cache[domain] = resolved_ip
            except:
                pass
        
        return None
    
    def detect_ssl_stripping(self, packet):
        """检测SSL剥离攻击"""
        if packet.haslayer(TCP):
            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}"
            
            # 检测443端口到80端口的异常重定向
            if packet[TCP].dport == 443:
                connection_key = f"{src}->{dst}"
                self.ssl_connections[connection_key] = {
                    'timestamp': time.time(),
                    'expected_https': True
                }
            
            # 如果之前有HTTPS连接，但现在看到HTTP流量，可能是SSL剥离
            if packet[TCP].dport == 80:
                connection_key = f"{src}->{dst}"
                if connection_key in self.ssl_connections:
                    conn = self.ssl_connections[connection_key]
                    if conn['expected_https'] and time.time() - conn['timestamp'] < 10:
                        attack = {
                            'type': 'SSL Stripping',
                            'connection': connection_key,
                            'timestamp': time.time(),
                            'severity': 'CRITICAL'
                        }
                        self.detected_attacks.append(attack)
                        print(f"[!] 检测到SSL剥离攻击: {connection_key}")
                        return attack
        
        return None
    
    def detect_mitm_activity(self, packet):
        """检测中间人攻击活动"""
        # 检测异常大量的ARP请求
        if packet.haslayer(ARP):
            if packet[ARP].op == 1:  # ARP request
                # 统计ARP请求频率
                pass
        
        # 检测异常DNS响应
        if packet.haslayer(DNS):
            if packet[DNS].qr == 1:  # DNS response
                # 检查DNS响应的TTL是否异常
                if packet.haslayer(IP):
                    ttl = packet[IP].ttl
                    # 正常DNS响应的TTL通常在64-255之间
                    if ttl < 32:
                        attack = {
                            'type': 'Suspicious DNS Activity',
                            'ttl': ttl,
                            'timestamp': time.time(),
                            'severity': 'MEDIUM'
                        }
                        self.detected_attacks.append(attack)
                        return attack
        
        return None
    
    def start_detection(self, interface=None):
        """开始攻击检测"""
        def process_packet(packet):
            self.detect_arp_spoofing(packet)
            self.detect_dns_spoofing(packet)
            self.detect_ssl_stripping(packet)
            self.detect_mitm_activity(packet)
        
        self.detecting = True
        print("[+] 攻击检测已启动")
        sniff(iface=interface, prn=process_packet, stop_filter=lambda x: not self.detecting)
    
    def stop_detection(self):
        """停止攻击检测"""
        self.detecting = False
        print("[+] 攻击检测已停止")
    
    def get_detected_attacks(self):
        """获取检测到的攻击列表"""
        return self.detected_attacks
    
    def generate_report(self):
        """生成攻击检测报告"""
        report = {
            'total_attacks': len(self.detected_attacks),
            'attack_types': defaultdict(int),
            'severity_breakdown': defaultdict(int),
            'attacks': self.detected_attacks
        }
        
        for attack in self.detected_attacks:
            report['attack_types'][attack['type']] += 1
            report['severity_breakdown'][attack['severity']] += 1
        
        return report


