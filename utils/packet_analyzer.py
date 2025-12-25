#!/usr/bin/env python3
"""
資料包分析工具模組
用於分析網路資料包，檢測異常流量
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, ARP
import dpkt
import socket

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.suspicious_activities = []
    
    def start_capture(self, interface=None, count=0, filter_str=""):
        """
        開始捕獲資料包
        
        Args:
            interface: 網路介面
            count: 捕獲數量（0表示無限）
            filter_str: BPF過濾器
        """
        try:
            sniff(iface=interface, prn=self._process_packet, 
                  count=count, filter=filter_str, store=True)
        except Exception as e:
            print(f"捕獲資料包錯誤: {e}")
    
    def _process_packet(self, packet):
        """處理捕獲的資料包"""
        self.packets.append(packet)
        
        # 檢測可疑活動
        self._detect_suspicious_activity(packet)
    
    def _detect_suspicious_activity(self, packet):
        """檢測可疑的網路活動"""
        if packet.haslayer(ARP):
            # 檢測ARP欺騙
            if packet[ARP].op == 2:  # ARP reply
                # 檢查是否有多個IP映射到不同MAC
                pass
        
        if packet.haslayer(DNS):
            # 檢測DNS欺騙
            if packet[DNS].qr == 1:  # DNS response
                # 檢查DNS回應是否可疑
                pass
        
        if packet.haslayer(TCP):
            # 檢測SSL/TLS握手異常
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                # 分析SSL/TLS流量
                pass
    
    def analyze_ssl_handshake(self, packets):
        """分析SSL握手協定"""
        ssl_handshakes = []
        
        for packet in packets:
            if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    # 檢查SSL/TLS握手訊息
                    if len(payload) > 0:
                        # SSL/TLS記錄類型
                        if payload[0] == 0x16:  # Handshake
                            ssl_handshakes.append({
                                'src': packet[IP].src,
                                'dst': packet[IP].dst,
                                'timestamp': packet.time,
                                'data': payload.hex()
                            })
        
        return ssl_handshakes
    
    def detect_arp_spoofing(self, packets):
        """檢測ARP欺騙攻擊"""
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
        """檢測DNS欺騙攻擊"""
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


