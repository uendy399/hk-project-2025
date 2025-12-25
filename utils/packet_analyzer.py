#!/usr/bin/env python3
"""
Packet Analyzer Tool Module
Used to analyze network packets and detect abnormal traffic
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
        Start capturing packets
        
        Args:
            interface: Network interface
            count: Number of packets to capture (0 means unlimited)
            filter_str: BPF filter
        """
        try:
            sniff(iface=interface, prn=self._process_packet, 
                  count=count, filter=filter_str, store=True)
        except Exception as e:
            print(f"Error capturing packets: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        self.packets.append(packet)
        
        # Detect suspicious activities
        self._detect_suspicious_activity(packet)
    
    def _detect_suspicious_activity(self, packet):
        """Detect suspicious network activities"""
        if packet.haslayer(ARP):
            # Detect ARP spoofing
            if packet[ARP].op == 2:  # ARP reply
                # Check if multiple IPs map to different MACs
                pass
        
        if packet.haslayer(DNS):
            # Detect DNS spoofing
            if packet[DNS].qr == 1:  # DNS response
                # Check if DNS response is suspicious
                pass
        
        if packet.haslayer(TCP):
            # Detect SSL/TLS handshake anomalies
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                # Analyze SSL/TLS traffic
                pass
    
    def analyze_ssl_handshake(self, packets):
        """Analyze SSL handshake protocol"""
        ssl_handshakes = []
        
        for packet in packets:
            if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    # Check SSL/TLS handshake message
                    if len(payload) > 0:
                        # SSL/TLS record type
                        if payload[0] == 0x16:  # Handshake
                            ssl_handshakes.append({
                                'src': packet[IP].src,
                                'dst': packet[IP].dst,
                                'timestamp': packet.time,
                                'data': payload.hex()
                            })
        
        return ssl_handshakes
    
    def detect_arp_spoofing(self, packets):
        """Detect ARP spoofing attacks"""
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
        """Detect DNS spoofing attacks"""
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


