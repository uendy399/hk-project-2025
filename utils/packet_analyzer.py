#!/usr/bin/env python3
"""
数据包分析工具模块
用于分析网络数据包，检测异常流量
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import dpkt
import socket

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.suspicious_activities = []
    
    def start_capture(self, interface=None, count=0, filter_str=""):
        """
        开始捕获数据包
        
        Args:
            interface: 网络接口
            count: 捕获数量（0表示无限）
            filter_str: BPF过滤器
        """
        try:
            sniff(iface=interface, prn=self._process_packet, 
                  count=count, filter=filter_str, store=True)
        except Exception as e:
            print(f"捕获数据包错误: {e}")
    
    def _process_packet(self, packet):
        """处理捕获的数据包"""
        self.packets.append(packet)
        
        # 检测可疑活动
        self._detect_suspicious_activity(packet)
    
    def _detect_suspicious_activity(self, packet):
        """检测可疑的网络活动"""
        if packet.haslayer(ARP):
            # 检测ARP欺骗
            if packet[ARP].op == 2:  # ARP reply
                # 检查是否有多个IP映射到不同MAC
                pass
        
        if packet.haslayer(DNS):
            # 检测DNS欺骗
            if packet[DNS].qr == 1:  # DNS response
                # 检查DNS响应是否可疑
                pass
        
        if packet.haslayer(TCP):
            # 检测SSL/TLS握手异常
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                # 分析SSL/TLS流量
                pass
    
    def analyze_ssl_handshake(self, packets):
        """分析SSL握手协议"""
        ssl_handshakes = []
        
        for packet in packets:
            if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    # 检查SSL/TLS握手消息
                    if len(payload) > 0:
                        # SSL/TLS记录类型
                        if payload[0] == 0x16:  # Handshake
                            ssl_handshakes.append({
                                'src': packet[IP].src,
                                'dst': packet[IP].dst,
                                'timestamp': packet.time,
                                'data': payload.hex()
                            })
        
        return ssl_handshakes
    
    def detect_arp_spoofing(self, packets):
        """检测ARP欺骗攻击"""
        arp_table = {}
        spoofing_detected = []
        
        for packet in packets:
            if packet.haslayer(ARP):
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc
                
                if ip in arp_table:
                    if arp_table[ip] != mac:
                        spoofing_detected.append({
                            'ip': ip,
                            'old_mac': arp_table[ip],
                            'new_mac': mac,
                            'timestamp': packet.time
                        })
                else:
                    arp_table[ip] = mac
        
        return spoofing_detected
    
    def detect_dns_spoofing(self, packets):
        """检测DNS欺骗攻击"""
        dns_responses = {}
        spoofing_detected = []
        
        for packet in packets:
            if packet.haslayer(DNS) and packet[DNS].qr == 1:
                domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                resolved_ip = packet[DNS].an.rdata if packet[DNS].an else None
                
                if domain in dns_responses:
                    if dns_responses[domain] != resolved_ip:
                        spoofing_detected.append({
                            'domain': domain,
                            'old_ip': dns_responses[domain],
                            'new_ip': resolved_ip,
                            'timestamp': packet.time
                        })
                else:
                    dns_responses[domain] = resolved_ip
        
        return spoofing_detected


