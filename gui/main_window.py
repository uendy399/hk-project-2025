#!/usr/bin/env python3
"""
主GUI窗口
提供图形用户界面来执行攻击和防御操作
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.network_scanner import NetworkScanner
from attacks.arp_spoof import ARPSpoofer
from attacks.dns_spoof import DNSSpoofer
from attacks.ssl_strip import SSLStripper
from attacks.password_capture import PasswordCapture
from defense.attack_detector import AttackDetector
from defense.countermeasures import Countermeasures

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("MITM攻击与防御演示系统")
        self.root.geometry("1200x800")
        
        # 初始化组件
        self.network_scanner = NetworkScanner()
        self.arp_spoofer = None
        self.dns_spoofer = None
        self.ssl_stripper = None
        self.password_capture = PasswordCapture()
        self.attack_detector = AttackDetector()
        self.countermeasures = Countermeasures()
        
        # 创建界面
        self._create_widgets()
    
    def _create_widgets(self):
        """创建GUI组件"""
        # 创建Notebook（标签页）
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 网络扫描标签页
        self.scan_frame = ttk.Frame(notebook)
        notebook.add(self.scan_frame, text="网络扫描")
        self._create_scan_tab()
        
        # 攻击工具标签页
        self.attack_frame = ttk.Frame(notebook)
        notebook.add(self.attack_frame, text="攻击工具")
        self._create_attack_tab()
        
        # 防御工具标签页
        self.defense_frame = ttk.Frame(notebook)
        notebook.add(self.defense_frame, text="防御工具")
        self._create_defense_tab()
        
        # 日志标签页
        self.log_frame = ttk.Frame(notebook)
        notebook.add(self.log_frame, text="日志")
        self._create_log_tab()
    
    def _create_scan_tab(self):
        """创建网络扫描标签页"""
        # 扫描配置
        config_frame = ttk.LabelFrame(self.scan_frame, text="扫描配置")
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(config_frame, text="网络范围:").grid(row=0, column=0, padx=5, pady=5)
        self.network_range = ttk.Entry(config_frame, width=20)
        self.network_range.insert(0, "192.168.1.0/24")
        self.network_range.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(config_frame, text="开始扫描", 
                  command=self._start_scan).grid(row=0, column=2, padx=5, pady=5)
        
        # 扫描结果
        result_frame = ttk.LabelFrame(self.scan_frame, text="扫描结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建树形视图
        columns = ("IP", "主机名", "MAC地址", "状态")
        self.scan_tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_attack_tab(self):
        """创建攻击工具标签页"""
        # ARP欺骗
        arp_frame = ttk.LabelFrame(self.attack_frame, text="ARP欺骗")
        arp_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(arp_frame, text="目标IP:").grid(row=0, column=0, padx=5, pady=5)
        self.target_ip = ttk.Entry(arp_frame, width=15)
        self.target_ip.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(arp_frame, text="网关IP:").grid(row=0, column=2, padx=5, pady=5)
        self.gateway_ip = ttk.Entry(arp_frame, width=15)
        self.gateway_ip.grid(row=0, column=3, padx=5, pady=5)
        
        self.arp_start_btn = ttk.Button(arp_frame, text="开始ARP欺骗", 
                                        command=self._start_arp_spoof)
        self.arp_start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.arp_stop_btn = ttk.Button(arp_frame, text="停止ARP欺骗", 
                                       command=self._stop_arp_spoof, state=tk.DISABLED)
        self.arp_stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        # DNS欺骗
        dns_frame = ttk.LabelFrame(self.attack_frame, text="DNS欺骗")
        dns_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="欺骗域名:").grid(row=0, column=0, padx=5, pady=5)
        self.spoof_domains = ttk.Entry(dns_frame, width=30)
        self.spoof_domains.insert(0, "example.com,test.com")
        self.spoof_domains.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="重定向IP:").grid(row=0, column=2, padx=5, pady=5)
        self.redirect_ip = ttk.Entry(dns_frame, width=15)
        self.redirect_ip.insert(0, "192.168.1.100")
        self.redirect_ip.grid(row=0, column=3, padx=5, pady=5)
        
        self.dns_start_btn = ttk.Button(dns_frame, text="开始DNS欺骗", 
                                        command=self._start_dns_spoof)
        self.dns_start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.dns_stop_btn = ttk.Button(dns_frame, text="停止DNS欺骗", 
                                       command=self._stop_dns_spoof, state=tk.DISABLED)
        self.dns_stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        # SSL剥离
        ssl_frame = ttk.LabelFrame(self.attack_frame, text="SSL剥离")
        ssl_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.ssl_start_btn = ttk.Button(ssl_frame, text="开始SSL剥离", 
                                        command=self._start_ssl_strip)
        self.ssl_start_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.ssl_stop_btn = ttk.Button(ssl_frame, text="停止SSL剥离", 
                                       command=self._stop_ssl_strip, state=tk.DISABLED)
        self.ssl_stop_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # 密码捕获
        pwd_frame = ttk.LabelFrame(self.attack_frame, text="密码捕获")
        pwd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.pwd_start_btn = ttk.Button(pwd_frame, text="开始密码捕获", 
                                        command=self._start_password_capture)
        self.pwd_start_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.pwd_stop_btn = ttk.Button(pwd_frame, text="停止密码捕获", 
                                       command=self._stop_password_capture, state=tk.DISABLED)
        self.pwd_stop_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # 捕获的凭据显示
        cred_frame = ttk.LabelFrame(self.attack_frame, text="捕获的凭据")
        cred_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.cred_text = scrolledtext.ScrolledText(cred_frame, height=10)
        self.cred_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_defense_tab(self):
        """创建防御工具标签页"""
        # 攻击检测
        detect_frame = ttk.LabelFrame(self.defense_frame, text="攻击检测")
        detect_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.detect_start_btn = ttk.Button(detect_frame, text="开始检测", 
                                           command=self._start_detection)
        self.detect_start_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.detect_stop_btn = ttk.Button(detect_frame, text="停止检测", 
                                          command=self._stop_detection, state=tk.DISABLED)
        self.detect_stop_btn.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(detect_frame, text="生成报告", 
                  command=self._generate_report).grid(row=0, column=2, padx=5, pady=5)
        
        # 检测结果
        result_frame = ttk.LabelFrame(self.defense_frame, text="检测结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.detect_text = scrolledtext.ScrolledText(result_frame, height=15)
        self.detect_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 防御对策
        counter_frame = ttk.LabelFrame(self.defense_frame, text="防御对策")
        counter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(counter_frame, text="应用防御对策", 
                  command=self._apply_countermeasures).pack(padx=5, pady=5)
    
    def _create_log_tab(self):
        """创建日志标签页"""
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=30)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(self.log_frame, text="清空日志", 
                  command=lambda: self.log_text.delete(1.0, tk.END)).pack(padx=5, pady=5)
    
    def _log(self, message):
        """记录日志"""
        self.log_text.insert(tk.END, f"{message}\\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def _start_scan(self):
        """开始网络扫描"""
        network_range = self.network_range.get()
        if not network_range:
            messagebox.showerror("错误", "请输入网络范围")
            return
        
        self._log(f"[*] 开始扫描网络: {network_range}")
        
        def scan():
            hosts = self.network_scanner.scan_network(network_range)
            self.scan_tree.delete(*self.scan_tree.get_children())
            
            for host in hosts:
                self.scan_tree.insert("", tk.END, values=(
                    host['ip'], host['hostname'], host['mac'], host['status']
                ))
            
            self._log(f"[+] 扫描完成，发现 {len(hosts)} 台主机")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def _start_arp_spoof(self):
        """开始ARP欺骗"""
        target = self.target_ip.get()
        gateway = self.gateway_ip.get()
        
        if not target or not gateway:
            messagebox.showerror("错误", "请输入目标IP和网关IP")
            return
        
        self.arp_spoofer = ARPSpoofer(target, gateway)
        if self.arp_spoofer.start():
            self.arp_start_btn.config(state=tk.DISABLED)
            self.arp_stop_btn.config(state=tk.NORMAL)
            self._log(f"[+] ARP欺骗已启动: {target} <-> {gateway}")
    
    def _stop_arp_spoof(self):
        """停止ARP欺骗"""
        if self.arp_spoofer:
            self.arp_spoofer.stop()
            self.arp_start_btn.config(state=tk.NORMAL)
            self.arp_stop_btn.config(state=tk.DISABLED)
            self._log("[+] ARP欺骗已停止")
    
    def _start_dns_spoof(self):
        """开始DNS欺骗"""
        domains_str = self.spoof_domains.get()
        redirect = self.redirect_ip.get()
        
        if not domains_str or not redirect:
            messagebox.showerror("错误", "请输入欺骗域名和重定向IP")
            return
        
        domains = [d.strip() for d in domains_str.split(',')]
        self.dns_spoofer = DNSSpoofer(spoof_domains=domains, redirect_ip=redirect)
        
        if self.dns_spoofer.start():
            self.dns_start_btn.config(state=tk.DISABLED)
            self.dns_stop_btn.config(state=tk.NORMAL)
            self._log(f"[+] DNS欺骗已启动: {domains} -> {redirect}")
    
    def _stop_dns_spoof(self):
        """停止DNS欺骗"""
        if self.dns_spoofer:
            self.dns_spoofer.stop()
            self.dns_start_btn.config(state=tk.NORMAL)
            self.dns_stop_btn.config(state=tk.DISABLED)
            self._log("[+] DNS欺骗已停止")
    
    def _start_ssl_strip(self):
        """开始SSL剥离"""
        self.ssl_stripper = SSLStripper()
        if self.ssl_stripper.start():
            self.ssl_start_btn.config(state=tk.DISABLED)
            self.ssl_stop_btn.config(state=tk.NORMAL)
            self._log("[+] SSL剥离已启动")
    
    def _stop_ssl_strip(self):
        """停止SSL剥离"""
        if self.ssl_stripper:
            self.ssl_stripper.stop()
            self.ssl_start_btn.config(state=tk.NORMAL)
            self.ssl_stop_btn.config(state=tk.DISABLED)
            self._log("[+] SSL剥离已停止")
            
            # 显示捕获的凭据
            creds = self.ssl_stripper.get_captured_credentials()
            self.cred_text.delete(1.0, tk.END)
            for cred in creds:
                self.cred_text.insert(tk.END, f"用户名: {cred['username']}, 密码: {cred['password']}\\n")
    
    def _start_password_capture(self):
        """开始密码捕获"""
        if self.password_capture.start():
            self.pwd_start_btn.config(state=tk.DISABLED)
            self.pwd_stop_btn.config(state=tk.NORMAL)
            self._log("[+] 密码捕获已启动")
    
    def _stop_password_capture(self):
        """停止密码捕获"""
        self.password_capture.stop()
        self.pwd_start_btn.config(state=tk.NORMAL)
        self.pwd_stop_btn.config(state=tk.DISABLED)
        self._log("[+] 密码捕获已停止")
        
        # 显示捕获的密码
        passwords = self.password_capture.get_captured_passwords()
        self.cred_text.delete(1.0, tk.END)
        for pwd in passwords:
            self.cred_text.insert(tk.END, 
                f"类型: {pwd['type']}, 用户名: {pwd['username']}, 密码: {pwd['password']}\\n")
    
    def _start_detection(self):
        """开始攻击检测"""
        def detect():
            self.attack_detector.start_detection()
        
        threading.Thread(target=detect, daemon=True).start()
        self.detect_start_btn.config(state=tk.DISABLED)
        self.detect_stop_btn.config(state=tk.NORMAL)
        self._log("[+] 攻击检测已启动")
    
    def _stop_detection(self):
        """停止攻击检测"""
        self.attack_detector.stop_detection()
        self.detect_start_btn.config(state=tk.NORMAL)
        self.detect_stop_btn.config(state=tk.DISABLED)
        self._log("[+] 攻击检测已停止")
    
    def _generate_report(self):
        """生成检测报告"""
        report = self.attack_detector.generate_report()
        
        self.detect_text.delete(1.0, tk.END)
        self.detect_text.insert(tk.END, f"总攻击数: {report['total_attacks']}\\n\\n")
        self.detect_text.insert(tk.END, "攻击类型统计:\\n")
        for atype, count in report['attack_types'].items():
            self.detect_text.insert(tk.END, f"  {atype}: {count}\\n")
        
        self.detect_text.insert(tk.END, "\\n严重程度统计:\\n")
        for severity, count in report['severity_breakdown'].items():
            self.detect_text.insert(tk.END, f"  {severity}: {count}\\n")
        
        self.detect_text.insert(tk.END, "\\n详细攻击列表:\\n")
        for attack in report['attacks']:
            self.detect_text.insert(tk.END, f"  {attack}\\n")
    
    def _apply_countermeasures(self):
        """应用防御对策"""
        self.countermeasures.apply_all_countermeasures()
        self._log("[+] 防御对策建议已提供")

def main():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()

