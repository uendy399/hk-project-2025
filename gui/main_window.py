#!/usr/bin/env python3
"""
Main GUI Window
Provides graphical user interface to execute attack operations
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os
import matplotlib
matplotlib.use('TkAgg')  # Use TkAgg backend
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# Add project root directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.network_scanner import NetworkScanner
from utils.traffic_analyzer import TrafficAnalyzer
from attacks.arp_spoof import ARPSpoofer
from attacks.dns_spoof import DNSSpoofer

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("MITM Attack Demonstration System")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.network_scanner = NetworkScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        self.arp_spoofer = None
        self.dns_spoofer = None
        
        # Create interface
        self._create_widgets()
    
    def _create_widgets(self):
        """Create GUI components"""
        # Create Notebook (tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Network scan tab
        self.scan_frame = ttk.Frame(notebook)
        notebook.add(self.scan_frame, text="Network Scan")
        self._create_scan_tab()
        
        # Attack tools tab
        self.attack_frame = ttk.Frame(notebook)
        notebook.add(self.attack_frame, text="Attack Tools")
        self._create_attack_tab()
        
        # Traffic analysis tab
        self.analysis_frame = ttk.Frame(notebook)
        notebook.add(self.analysis_frame, text="Traffic Analysis")
        self._create_analysis_tab()
        
        # Log tab
        self.log_frame = ttk.Frame(notebook)
        notebook.add(self.log_frame, text="Log")
        self._create_log_tab()
    
    def _create_scan_tab(self):
        """Create network scan tab"""
        # Scan settings
        config_frame = ttk.LabelFrame(self.scan_frame, text="Scan Settings")
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Network Range:").grid(row=0, column=0, padx=5, pady=5)
        self.network_range = ttk.Entry(config_frame, width=20)
        self.network_range.insert(0, "192.168.1.0/24")
        self.network_range.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(config_frame, text="Start Scan", 
                  command=self._start_scan).grid(row=0, column=2, padx=5, pady=5)
        
        # Scan results
        result_frame = ttk.LabelFrame(self.scan_frame, text="Scan Results")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tree view
        columns = ("IP", "Hostname", "MAC Address", "Status")
        self.scan_tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_attack_tab(self):
        """Create attack tools tab"""
        # ARP spoofing
        arp_frame = ttk.LabelFrame(self.attack_frame, text="ARP Spoofing")
        arp_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(arp_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.target_ip = ttk.Entry(arp_frame, width=15)
        self.target_ip.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(arp_frame, text="Gateway IP:").grid(row=0, column=2, padx=5, pady=5)
        self.gateway_ip = ttk.Entry(arp_frame, width=15)
        self.gateway_ip.grid(row=0, column=3, padx=5, pady=5)
        
        self.arp_start_btn = ttk.Button(arp_frame, text="Start ARP Spoofing", 
                                        command=self._start_arp_spoof)
        self.arp_start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.arp_stop_btn = ttk.Button(arp_frame, text="Stop ARP Spoofing", 
                                       command=self._stop_arp_spoof, state=tk.DISABLED)
        self.arp_stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        # DNS spoofing
        dns_frame = ttk.LabelFrame(self.attack_frame, text="DNS Spoofing")
        dns_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="Spoof Domain:").grid(row=0, column=0, padx=5, pady=5)
        self.spoof_domains = ttk.Entry(dns_frame, width=30)
        self.spoof_domains.insert(0, "example.com,test.com")
        self.spoof_domains.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dns_frame, text="Redirect IP:").grid(row=0, column=2, padx=5, pady=5)
        self.redirect_ip = ttk.Entry(dns_frame, width=15)
        self.redirect_ip.insert(0, "192.168.1.100")
        self.redirect_ip.grid(row=0, column=3, padx=5, pady=5)
        
        self.dns_start_btn = ttk.Button(dns_frame, text="Start DNS Spoofing", 
                                        command=self._start_dns_spoof)
        self.dns_start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.dns_stop_btn = ttk.Button(dns_frame, text="Stop DNS Spoofing", 
                                       command=self._stop_dns_spoof, state=tk.DISABLED)
        self.dns_stop_btn.grid(row=0, column=5, padx=5, pady=5)
    
    def _create_analysis_tab(self):
        """Create traffic analysis tab"""
        # Control panel
        control_frame = ttk.LabelFrame(self.analysis_frame, text="Analysis Control")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Network Interface:").grid(row=0, column=0, padx=5, pady=5)
        self.analysis_interface = ttk.Combobox(control_frame, width=20, state="readonly")
        self.analysis_interface.grid(row=0, column=1, padx=5, pady=5)
        
        # Get available network interfaces
        try:
            from scapy.all import get_if_list
            interfaces = [iface for iface in get_if_list() if not iface.startswith('lo')]
            self.analysis_interface['values'] = interfaces
            if interfaces:
                self.analysis_interface.current(0)
        except:
            self.analysis_interface['values'] = ['auto']
            self.analysis_interface.current(0)
        
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=2, padx=5, pady=5)
        self.analysis_filter = ttk.Entry(control_frame, width=30)
        self.analysis_filter.insert(0, "")
        self.analysis_filter.grid(row=0, column=3, padx=5, pady=5)
        
        self.analysis_start_btn = ttk.Button(control_frame, text="Start Analysis", 
                                             command=self._start_analysis)
        self.analysis_start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.analysis_stop_btn = ttk.Button(control_frame, text="Stop Analysis", 
                                            command=self._stop_analysis, state=tk.DISABLED)
        self.analysis_stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Export Statistics", 
                  command=self._export_statistics).grid(row=0, column=6, padx=5, pady=5)
        
        # Statistics display area
        stats_notebook = ttk.Notebook(self.analysis_frame)
        stats_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Overview tab
        overview_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(overview_frame, text="Overview")
        self._create_overview_tab(overview_frame)
        
        # L7 protocol statistics tab
        l7_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(l7_frame, text="L7 Protocol Statistics")
        self._create_l7_tab(l7_frame)
        
        # DLP events tab
        dlp_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(dlp_frame, text="DLP Events")
        self._create_dlp_tab(dlp_frame)
        
        # Chart analysis tab
        chart_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(chart_frame, text="Chart Analysis")
        self._create_chart_tab(chart_frame)
        
        # HTTP requests tab
        http_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(http_frame, text="HTTP Requests")
        self._create_http_tab(http_frame)
        
        # DNS queries tab
        dns_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(dns_frame, text="DNS Queries")
        self._create_dns_tab(dns_frame)
        
        # ML/DL Analysis tab
        ml_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(ml_frame, text="ML/DL Analysis")
        self._create_ml_tab(ml_frame)
    
    def _create_overview_tab(self, parent):
        """Create overview tab"""
        self.overview_text = scrolledtext.ScrolledText(parent, height=20)
        self.overview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(parent, text="Refresh Statistics", 
                  command=self._update_overview).pack(padx=5, pady=5)
    
    def _create_l7_tab(self, parent):
        """Create L7 protocol statistics tab"""
        # Create left-right split
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left: table
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)
        
        columns = ("Protocol", "Packet Count", "Percentage")
        self.l7_tree = ttk.Treeview(left_frame, columns=columns, show="headings")
        
        for col in columns:
            self.l7_tree.heading(col, text=col)
            self.l7_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.l7_tree.yview)
        self.l7_tree.configure(yscrollcommand=scrollbar.set)
        
        self.l7_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(left_frame, text="Refresh", 
                  command=self._update_l7_stats).pack(padx=5, pady=5)
        
        # Right: chart
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)
        
        self.l7_figure = Figure(figsize=(6, 4), dpi=100)
        self.l7_canvas = FigureCanvasTkAgg(self.l7_figure, right_frame)
        self.l7_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _create_dlp_tab(self, parent):
        """Create DLP events tab"""
        # Create top-bottom split
        paned = ttk.PanedWindow(parent, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top: table
        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=2)
        
        columns = ("Time", "Type", "Matched Content", "Source IP", "Destination IP", "Protocol")
        self.dlp_tree = ttk.Treeview(top_frame, columns=columns, show="headings")
        
        for col in columns:
            self.dlp_tree.heading(col, text=col)
            self.dlp_tree.column(col, width=120)
        
        scrollbar = ttk.Scrollbar(top_frame, orient=tk.VERTICAL, command=self.dlp_tree.yview)
        self.dlp_tree.configure(yscrollcommand=scrollbar.set)
        
        self.dlp_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(top_frame, text="Refresh", 
                  command=self._update_dlp_events).pack(padx=5, pady=5)
        
        # Bottom: chart
        bottom_frame = ttk.Frame(paned)
        paned.add(bottom_frame, weight=1)
        
        self.dlp_figure = Figure(figsize=(8, 4), dpi=100)
        self.dlp_canvas = FigureCanvasTkAgg(self.dlp_figure, bottom_frame)
        self.dlp_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _create_chart_tab(self, parent):
        """Create chart analysis tab"""
        # Create Notebook to organize multiple charts
        chart_notebook = ttk.Notebook(parent)
        chart_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # L7 protocol distribution chart
        l7_chart_frame = ttk.Frame(chart_notebook)
        chart_notebook.add(l7_chart_frame, text="L7 Protocol Distribution")
        self.l7_chart_figure = Figure(figsize=(10, 6), dpi=100)
        self.l7_chart_canvas = FigureCanvasTkAgg(self.l7_chart_figure, l7_chart_frame)
        self.l7_chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        ttk.Button(l7_chart_frame, text="Refresh Chart", 
                  command=self._update_l7_chart).pack(padx=5, pady=5)
        
        # DLP event statistics chart
        dlp_chart_frame = ttk.Frame(chart_notebook)
        chart_notebook.add(dlp_chart_frame, text="DLP Event Statistics")
        self.dlp_chart_figure = Figure(figsize=(10, 6), dpi=100)
        self.dlp_chart_canvas = FigureCanvasTkAgg(self.dlp_chart_figure, dlp_chart_frame)
        self.dlp_chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        ttk.Button(dlp_chart_frame, text="Refresh Chart", 
                  command=self._update_dlp_chart).pack(padx=5, pady=5)
        
        # Traffic trend chart
        traffic_chart_frame = ttk.Frame(chart_notebook)
        chart_notebook.add(traffic_chart_frame, text="Traffic Trend")
        self.traffic_chart_figure = Figure(figsize=(10, 6), dpi=100)
        self.traffic_chart_canvas = FigureCanvasTkAgg(self.traffic_chart_figure, traffic_chart_frame)
        self.traffic_chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        ttk.Button(traffic_chart_frame, text="Refresh Chart", 
                  command=self._update_traffic_chart).pack(padx=5, pady=5)
    
    def _create_http_tab(self, parent):
        """Create HTTP requests tab"""
        columns = ("Time", "Method", "Host", "Path", "Source IP", "Destination IP")
        self.http_tree = ttk.Treeview(parent, columns=columns, show="headings")
        
        for col in columns:
            self.http_tree.heading(col, text=col)
            self.http_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.http_tree.yview)
        self.http_tree.configure(yscrollcommand=scrollbar.set)
        
        self.http_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(parent, text="Refresh", 
                  command=self._update_http_requests).pack(padx=5, pady=5)
    
    def _create_dns_tab(self, parent):
        """Create DNS queries tab"""
        columns = ("Time", "Query", "Response", "Source IP", "Destination IP")
        self.dns_tree = ttk.Treeview(parent, columns=columns, show="headings")
        
        for col in columns:
            self.dns_tree.heading(col, text=col)
            self.dns_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.dns_tree.yview)
        self.dns_tree.configure(yscrollcommand=scrollbar.set)
        
        self.dns_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(parent, text="Refresh", 
                  command=self._update_dns_queries).pack(padx=5, pady=5)
    
    def _create_ml_tab(self, parent):
        """Create ML/DL analysis tab"""
        # Create notebook for ML sub-tabs
        ml_notebook = ttk.Notebook(parent)
        ml_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # ML Overview tab
        ml_overview_frame = ttk.Frame(ml_notebook)
        ml_notebook.add(ml_overview_frame, text="Overview")
        self._create_ml_overview_tab(ml_overview_frame)
        
        # Anomaly Detection tab
        ml_anomaly_frame = ttk.Frame(ml_notebook)
        ml_notebook.add(ml_anomaly_frame, text="Anomaly Detection")
        self._create_ml_anomaly_tab(ml_anomaly_frame)
        
        # Traffic Classification tab
        ml_classification_frame = ttk.Frame(ml_notebook)
        ml_notebook.add(ml_classification_frame, text="Traffic Classification")
        self._create_ml_classification_tab(ml_classification_frame)
        
        # Model Training tab
        ml_training_frame = ttk.Frame(ml_notebook)
        ml_notebook.add(ml_training_frame, text="Model Training")
        self._create_ml_training_tab(ml_training_frame)
    
    def _create_ml_overview_tab(self, parent):
        """Create ML overview tab"""
        self.ml_overview_text = scrolledtext.ScrolledText(parent, height=20)
        self.ml_overview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(parent, text="Refresh Statistics", 
                  command=self._update_ml_overview).pack(padx=5, pady=5)
    
    def _create_ml_anomaly_tab(self, parent):
        """Create ML anomaly detection tab"""
        # Create top-bottom split
        paned = ttk.PanedWindow(parent, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top: anomaly list
        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=2)
        
        columns = ("Time", "Type", "Score", "Details")
        self.ml_anomaly_tree = ttk.Treeview(top_frame, columns=columns, show="headings")
        
        for col in columns:
            self.ml_anomaly_tree.heading(col, text=col)
            self.ml_anomaly_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(top_frame, orient=tk.VERTICAL, command=self.ml_anomaly_tree.yview)
        self.ml_anomaly_tree.configure(yscrollcommand=scrollbar.set)
        
        self.ml_anomaly_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(top_frame, text="Refresh", 
                  command=self._update_ml_anomalies).pack(padx=5, pady=5)
        
        # Bottom: chart
        bottom_frame = ttk.Frame(paned)
        paned.add(bottom_frame, weight=1)
        
        self.ml_anomaly_figure = Figure(figsize=(8, 4), dpi=100)
        self.ml_anomaly_canvas = FigureCanvasTkAgg(self.ml_anomaly_figure, bottom_frame)
        self.ml_anomaly_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _create_ml_classification_tab(self, parent):
        """Create ML traffic classification tab"""
        # Create left-right split
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left: classification table
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)
        
        columns = ("Time", "Traffic Type", "Confidence", "Details")
        self.ml_classification_tree = ttk.Treeview(left_frame, columns=columns, show="headings")
        
        for col in columns:
            self.ml_classification_tree.heading(col, text=col)
            self.ml_classification_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.ml_classification_tree.yview)
        self.ml_classification_tree.configure(yscrollcommand=scrollbar.set)
        
        self.ml_classification_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(left_frame, text="Refresh", 
                  command=self._update_ml_classifications).pack(padx=5, pady=5)
        
        # Right: chart
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)
        
        self.ml_classification_figure = Figure(figsize=(6, 4), dpi=100)
        self.ml_classification_canvas = FigureCanvasTkAgg(self.ml_classification_figure, right_frame)
        self.ml_classification_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _create_ml_training_tab(self, parent):
        """Create ML model training tab"""
        # Training controls
        control_frame = ttk.LabelFrame(parent, text="Model Training")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Training Status:").grid(row=0, column=0, padx=5, pady=5)
        self.ml_training_status = ttk.Label(control_frame, text="Not Trained")
        self.ml_training_status.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Train Isolation Forest", 
                  command=self._train_isolation_forest).grid(row=1, column=0, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Train Traffic Classifier", 
                  command=self._train_traffic_classifier).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Build LSTM Model", 
                  command=self._build_lstm_model).grid(row=1, column=2, padx=5, pady=5)
        
        # Training log
        log_frame = ttk.LabelFrame(parent, text="Training Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.ml_training_log = scrolledtext.ScrolledText(log_frame, height=15)
        self.ml_training_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_log_tab(self):
        """Create log tab"""
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=30)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Button(self.log_frame, text="Clear Log", 
                  command=lambda: self.log_text.delete(1.0, tk.END)).pack(padx=5, pady=5)
    
    def _log(self, message):
        """Log message"""
        self.log_text.insert(tk.END, f"{message}\\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def _start_scan(self):
        """Start network scan"""
        network_range = self.network_range.get()
        if not network_range:
            messagebox.showerror("Error", "Please enter network range")
            return
        
        self._log(f"[*] Starting network scan: {network_range}")
        
        def scan():
            hosts = self.network_scanner.scan_network(network_range)
            self.scan_tree.delete(*self.scan_tree.get_children())
            
            for host in hosts:
                self.scan_tree.insert("", tk.END, values=(
                    host['ip'], host['hostname'], host['mac'], host['status']
                ))
            
            self._log(f"[+] Scan completed, found {len(hosts)} hosts")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def _start_arp_spoof(self):
        """Start ARP spoofing"""
        target = self.target_ip.get()
        gateway = self.gateway_ip.get()
        
        if not target or not gateway:
            messagebox.showerror("Error", "Please enter target IP and gateway IP")
            return
        
        self.arp_spoofer = ARPSpoofer(target, gateway)
        if self.arp_spoofer.start():
            self.arp_start_btn.config(state=tk.DISABLED)
            self.arp_stop_btn.config(state=tk.NORMAL)
            self._log(f"[+] ARP spoofing started: {target} <-> {gateway}")
    
    def _stop_arp_spoof(self):
        """Stop ARP spoofing"""
        if self.arp_spoofer:
            self.arp_spoofer.stop()
            self.arp_start_btn.config(state=tk.NORMAL)
            self.arp_stop_btn.config(state=tk.DISABLED)
            self._log("[+] ARP spoofing stopped")
    
    def _start_dns_spoof(self):
        """Start DNS spoofing"""
        domains_str = self.spoof_domains.get()
        redirect = self.redirect_ip.get()
        
        if not domains_str or not redirect:
            messagebox.showerror("Error", "Please enter spoof domain and redirect IP")
            return
        
        domains = [d.strip() for d in domains_str.split(',')]
        self.dns_spoofer = DNSSpoofer(spoof_domains=domains, redirect_ip=redirect)
        
        if self.dns_spoofer.start():
            self.dns_start_btn.config(state=tk.DISABLED)
            self.dns_stop_btn.config(state=tk.NORMAL)
            self._log(f"[+] DNS spoofing started: {domains} -> {redirect}")
    
    def _stop_dns_spoof(self):
        """Stop DNS spoofing"""
        if self.dns_spoofer:
            self.dns_spoofer.stop()
            self.dns_start_btn.config(state=tk.NORMAL)
            self.dns_stop_btn.config(state=tk.DISABLED)
            self._log("[+] DNS spoofing stopped")
    
    def _start_analysis(self):
        """Start traffic analysis"""
        interface = self.analysis_interface.get()
        if interface == 'auto' or not interface:
            interface = None
        
        filter_str = self.analysis_filter.get().strip()
        if not filter_str:
            filter_str = ""
        
        if self.traffic_analyzer.start_analysis(interface, filter_str):
            self.analysis_start_btn.config(state=tk.DISABLED)
            self.analysis_stop_btn.config(state=tk.NORMAL)
            self._log(f"[+] Traffic analysis started")
            if interface:
                self._log(f"[*] Using network interface: {interface}")
            if filter_str:
                self._log(f"[*] Filter: {filter_str}")
            
            # Start scheduled updates
            self._schedule_stats_update()
    
    def _stop_analysis(self):
        """Stop traffic analysis"""
        self.traffic_analyzer.stop_analysis()
        self.analysis_start_btn.config(state=tk.NORMAL)
        self.analysis_stop_btn.config(state=tk.DISABLED)
        self._log("[+] Traffic analysis stopped")
        self._update_all_stats()
    
    def _schedule_stats_update(self):
        """Schedule statistics update"""
        if self.traffic_analyzer.analyzing:
            self._update_all_stats()
            self.root.after(2000, self._schedule_stats_update)  # Update every 2 seconds
    
    def _update_all_stats(self):
        """Update all statistics"""
        self._update_overview()
        self._update_l7_stats()
        self._update_dlp_events()
        self._update_http_requests()
        self._update_dns_queries()
        # Update charts on chart analysis page
        self._update_l7_chart()
        self._update_dlp_chart()
        self._update_traffic_chart()
        # Update ML/DL stats
        self._update_ml_overview()
        self._update_ml_anomalies()
        self._update_ml_classifications()
    
    def _update_l7_chart(self):
        """Update L7 protocol distribution chart"""
        stats = self.traffic_analyzer.get_statistics()
        l7_protocols = stats['l7_protocols']
        
        if not l7_protocols:
            self.l7_chart_figure.clear()
            ax = self.l7_chart_figure.add_subplot(111)
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center', fontsize=16)
            self.l7_chart_canvas.draw()
            return
        
        self.l7_chart_figure.clear()
        
        # Create two subplots
        ax1 = self.l7_chart_figure.add_subplot(121)
        ax2 = self.l7_chart_figure.add_subplot(122)
        
        # Sort and take top 10
        sorted_protocols = sorted(l7_protocols.items(), key=lambda x: x[1], reverse=True)[:10]
        protocols = [p[0] for p in sorted_protocols]
        counts = [p[1] for p in sorted_protocols]
        
        # Left: pie chart
        ax1.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
        ax1.set_title('L7 Protocol Distribution (Top 10)')
        
        # Right: bar chart
        ax2.barh(protocols, counts, color='steelblue', alpha=0.7)
        ax2.set_xlabel('Packet Count')
        ax2.set_title('L7 Protocol Packet Statistics')
        
        self.l7_chart_figure.tight_layout()
        self.l7_chart_canvas.draw()
    
    def _update_dlp_chart(self):
        """Update DLP event statistics chart"""
        stats = self.traffic_analyzer.get_statistics()
        dlp_events = stats['dlp_events']
        
        if not dlp_events:
            self.dlp_chart_figure.clear()
            ax = self.dlp_chart_figure.add_subplot(111)
            ax.text(0.5, 0.5, 'No DLP events', ha='center', va='center', fontsize=16)
            self.dlp_chart_canvas.draw()
            return
        
        self.dlp_chart_figure.clear()
        
        # Create two subplots
        ax1 = self.dlp_chart_figure.add_subplot(121)
        ax2 = self.dlp_chart_figure.add_subplot(122)
        
        # Count DLP events by type
        from collections import Counter
        event_types = Counter([event['type'] for event in dlp_events])
        
        types = list(event_types.keys())
        counts = list(event_types.values())
        
        # Left: pie chart
        ax1.pie(counts, labels=types, autopct='%1.1f%%', startangle=90)
        ax1.set_title('DLP Event Type Distribution')
        
        # Right: bar chart
        ax2.bar(types, counts, color='coral', alpha=0.7)
        ax2.set_xlabel('DLP Event Type')
        ax2.set_ylabel('Event Count')
        ax2.set_title('DLP Event Type Statistics')
        ax2.tick_params(axis='x', rotation=45)
        
        self.dlp_chart_figure.tight_layout()
        self.dlp_chart_canvas.draw()
    
    def _update_traffic_chart(self):
        """Update traffic trend chart"""
        stats = self.traffic_analyzer.get_statistics()
        
        self.traffic_chart_figure.clear()
        ax = self.traffic_chart_figure.add_subplot(111)
        
        # Protocol distribution bar chart
        protocol_dist = stats['protocol_distribution']
        if protocol_dist:
            protocols = list(protocol_dist.keys())
            counts = list(protocol_dist.values())
            
            ax.bar(protocols, counts, color='teal', alpha=0.7)
            ax.set_xlabel('Protocol Type')
            ax.set_ylabel('Packet Count')
            ax.set_title('Protocol Distribution Statistics')
            ax.tick_params(axis='x', rotation=45)
        else:
            ax.text(0.5, 0.5, 'No traffic data', ha='center', va='center', fontsize=16)
        
        self.traffic_chart_figure.tight_layout()
        self.traffic_chart_canvas.draw()
    
    def _update_overview(self):
        """Update overview"""
        stats = self.traffic_analyzer.get_statistics()
        
        self.overview_text.delete(1.0, tk.END)
        
        self.overview_text.insert(tk.END, "=" * 60 + "\\n")
        self.overview_text.insert(tk.END, "Traffic Analysis Overview\\n")
        self.overview_text.insert(tk.END, "=" * 60 + "\\n\\n")
        
        self.overview_text.insert(tk.END, f"Total Packets: {stats['total_packets']:,}\\n")
        self.overview_text.insert(tk.END, f"Total Traffic: {stats['total_bytes']:,} bytes ({stats['total_bytes'] / 1024 / 1024:.2f} MB)\\n")
        
        if stats['duration'] > 0:
            self.overview_text.insert(tk.END, f"Runtime: {stats['duration']:.2f} seconds\\n")
            self.overview_text.insert(tk.END, f"Packet Rate: {stats['packets_per_second']:.2f} packets/sec\\n")
            self.overview_text.insert(tk.END, f"Traffic Rate: {stats['bytes_per_second']:.2f} bytes/sec ({stats['bytes_per_second'] / 1024:.2f} KB/s)\\n")
        
        self.overview_text.insert(tk.END, "\\n" + "-" * 60 + "\\n")
        self.overview_text.insert(tk.END, "Protocol Distribution:\\n")
        for proto, count in sorted(stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
            self.overview_text.insert(tk.END, f"  {proto}: {count:,} ({percentage:.2f}%)\\n")
        
        self.overview_text.insert(tk.END, "\\n" + "-" * 60 + "\\n")
        self.overview_text.insert(tk.END, "Top Talkers (Top 10):\\n")
        for ip, bytes_count in list(stats['top_talkers'].items())[:10]:
            self.overview_text.insert(tk.END, f"  {ip}: {bytes_count:,} bytes\\n")
        
        self.overview_text.insert(tk.END, "\\n" + "-" * 60 + "\\n")
        self.overview_text.insert(tk.END, f"DLP Events: {len(stats['dlp_events'])}\\n")
        self.overview_text.insert(tk.END, f"HTTP Requests: {len(stats['http_requests'])}\\n")
        self.overview_text.insert(tk.END, f"DNS Queries: {len(stats['dns_queries'])}\\n")
    
    def _update_l7_stats(self):
        """Update L7 protocol statistics"""
        stats = self.traffic_analyzer.get_statistics()
        
        # Clear existing data
        for item in self.l7_tree.get_children():
            self.l7_tree.delete(item)
        
        total = stats['total_packets']
        for protocol, count in sorted(stats['l7_protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            self.l7_tree.insert("", tk.END, values=(
                protocol, f"{count:,}", f"{percentage:.2f}%"
            ))
        
        # Update chart
        self._update_l7_chart_inline()
    
    def _update_l7_chart_inline(self):
        """Update L7 protocol statistics inline chart (in L7 tab)"""
        stats = self.traffic_analyzer.get_statistics()
        l7_protocols = stats['l7_protocols']
        
        if not l7_protocols:
            return
        
        self.l7_figure.clear()
        ax = self.l7_figure.add_subplot(111)
        
        # Sort and take top 10
        sorted_protocols = sorted(l7_protocols.items(), key=lambda x: x[1], reverse=True)[:10]
        protocols = [p[0] for p in sorted_protocols]
        counts = [p[1] for p in sorted_protocols]
        
        # Create pie chart
        ax.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
        ax.set_title('L7 Protocol Distribution (Top 10)')
        
        self.l7_canvas.draw()
    
    def _update_dlp_events(self):
        """Update DLP events"""
        stats = self.traffic_analyzer.get_statistics()
        
        # Clear existing data
        for item in self.dlp_tree.get_children():
            self.dlp_tree.delete(item)
        
        # Display recent DLP events (up to 100)
        for event in stats['dlp_events'][-100:]:
            from datetime import datetime
            timestamp = datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S')
            matched_text = event['matched_text'][:50] if len(event['matched_text']) > 50 else event['matched_text']
            self.dlp_tree.insert("", tk.END, values=(
                timestamp,
                event['type'],
                matched_text,
                event['src_ip'],
                event['dst_ip'],
                event['protocol']
            ))
        
        # Update chart
        self._update_dlp_chart_inline()
    
    def _update_dlp_chart_inline(self):
        """Update DLP events inline chart (in DLP tab)"""
        stats = self.traffic_analyzer.get_statistics()
        dlp_events = stats['dlp_events']
        
        if not dlp_events:
            return
        
        self.dlp_figure.clear()
        ax = self.dlp_figure.add_subplot(111)
        
        # Count DLP events by type
        from collections import Counter
        event_types = Counter([event['type'] for event in dlp_events])
        
        types = list(event_types.keys())
        counts = list(event_types.values())
        
        # Create bar chart
        ax.bar(types, counts, color='steelblue', alpha=0.7)
        ax.set_xlabel('DLP Event Type')
        ax.set_ylabel('Event Count')
        ax.set_title('DLP Event Type Statistics')
        ax.tick_params(axis='x', rotation=45)
        
        self.dlp_canvas.draw()
    
    def _update_http_requests(self):
        """Update HTTP requests"""
        stats = self.traffic_analyzer.get_statistics()
        
        # Clear existing data
        for item in self.http_tree.get_children():
            self.http_tree.delete(item)
        
        # Display recent HTTP requests (up to 100)
        for req in stats['http_requests'][-100:]:
            from datetime import datetime
            timestamp = datetime.fromtimestamp(req['timestamp']).strftime('%H:%M:%S')
            method = req.get('method', 'Unknown')
            host = req.get('host', 'Unknown')
            path = req.get('path', 'Unknown')
            src_ip = req.get('src_ip', 'Unknown')
            dst_ip = req.get('dst_ip', 'Unknown')
            
            self.http_tree.insert("", tk.END, values=(
                timestamp, method, host, path, src_ip, dst_ip
            ))
    
    def _update_dns_queries(self):
        """Update DNS queries"""
        stats = self.traffic_analyzer.get_statistics()
        
        # Clear existing data
        for item in self.dns_tree.get_children():
            self.dns_tree.delete(item)
        
        # Display recent DNS queries (up to 100)
        for query in stats['dns_queries'][-100:]:
            from datetime import datetime
            timestamp = datetime.fromtimestamp(query['timestamp']).strftime('%H:%M:%S')
            query_name = query.get('query', 'Unknown')
            answers = query.get('answers', [])
            answer_str = ', '.join(answers) if answers else 'N/A'
            src_ip = query.get('src_ip', 'Unknown')
            dst_ip = query.get('dst_ip', 'Unknown')
            
            self.dns_tree.insert("", tk.END, values=(
                timestamp, query_name, answer_str, src_ip, dst_ip
            ))
    
    def _export_statistics(self):
        """Export statistics"""
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                self.traffic_analyzer.export_statistics(filename)
                messagebox.showinfo("Success", f"Statistics exported to: {filename}")
                self._log(f"[+] Statistics exported to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
                self._log(f"[!] Export failed: {e}")
    
    def _update_ml_overview(self):
        """Update ML overview"""
        stats = self.traffic_analyzer.get_statistics()
        
        self.ml_overview_text.delete(1.0, tk.END)
        
        if 'ml_analysis' not in stats:
            self.ml_overview_text.insert(tk.END, "ML/DL Analysis not available or not enabled.\n")
            self.ml_overview_text.insert(tk.END, "Please ensure scikit-learn and TensorFlow are installed.\n")
            return
        
        ml_stats = stats['ml_analysis']
        
        self.ml_overview_text.insert(tk.END, "=" * 60 + "\n")
        self.ml_overview_text.insert(tk.END, "ML/DL Analysis Overview\n")
        self.ml_overview_text.insert(tk.END, "=" * 60 + "\n\n")
        
        self.ml_overview_text.insert(tk.END, f"Total Packets Analyzed: {ml_stats['total_packets_analyzed']:,}\n")
        self.ml_overview_text.insert(tk.END, f"Anomalies Detected: {ml_stats['anomalies_detected']}\n")
        
        if ml_stats['duration'] > 0:
            self.ml_overview_text.insert(tk.END, f"Runtime: {ml_stats['duration']:.2f} seconds\n")
            self.ml_overview_text.insert(tk.END, f"Packets per Second: {ml_stats['total_packets_analyzed'] / ml_stats['duration']:.2f}\n")
        
        self.ml_overview_text.insert(tk.END, f"\nAverage Feature Extraction Time: {ml_stats.get('avg_feature_extraction_time', 0):.6f} seconds\n")
        self.ml_overview_text.insert(tk.END, f"Average ML Inference Time: {ml_stats.get('avg_ml_inference_time', 0):.6f} seconds\n")
        
        self.ml_overview_text.insert(tk.END, "\n" + "-" * 60 + "\n")
        self.ml_overview_text.insert(tk.END, "Traffic Classifications:\n")
        for traffic_type, count in sorted(ml_stats['traffic_classifications'].items(), key=lambda x: x[1], reverse=True):
            self.ml_overview_text.insert(tk.END, f"  {traffic_type}: {count:,}\n")
        
        self.ml_overview_text.insert(tk.END, "\n" + "-" * 60 + "\n")
        self.ml_overview_text.insert(tk.END, f"Model Status:\n")
        self.ml_overview_text.insert(tk.END, f"  Isolation Forest: {'Trained' if ml_stats.get('isolation_forest_trained', False) else 'Not Trained'}\n")
        self.ml_overview_text.insert(tk.END, f"  Traffic Classifier: {'Trained' if ml_stats.get('classifier_trained', False) else 'Not Trained'}\n")
        self.ml_overview_text.insert(tk.END, f"  LSTM Model: {'Trained' if ml_stats.get('lstm_trained', False) else 'Not Trained'}\n")
    
    def _update_ml_anomalies(self):
        """Update ML anomaly detection"""
        stats = self.traffic_analyzer.get_statistics()
        
        # Clear existing data
        for item in self.ml_anomaly_tree.get_children():
            self.ml_anomaly_tree.delete(item)
        
        if 'ml_analysis' not in stats:
            return
        
        ml_stats = stats['ml_analysis']
        recent_anomalies = ml_stats.get('recent_anomalies', [])
        attack_predictions = ml_stats.get('attack_predictions', [])
        
        # Display recent anomalies
        for anomaly in recent_anomalies[-50:]:
            if anomaly.get('is_anomaly', False):
                from datetime import datetime
                timestamp = datetime.fromtimestamp(anomaly['timestamp']).strftime('%H:%M:%S')
                self.ml_anomaly_tree.insert("", tk.END, values=(
                    timestamp,
                    "Anomaly",
                    f"{anomaly['score']:.4f}",
                    "Isolation Forest Detection"
                ))
        
        # Display attack predictions
        for prediction in attack_predictions[-50:]:
            from datetime import datetime
            timestamp = datetime.fromtimestamp(prediction['timestamp']).strftime('%H:%M:%S')
            details = f"Score: {prediction.get('score', 0):.4f}"
            self.ml_anomaly_tree.insert("", tk.END, values=(
                timestamp,
                prediction.get('type', 'Unknown'),
                f"{prediction.get('score', 0):.4f}",
                details
            ))
        
        # Update chart
        self._update_ml_anomaly_chart(recent_anomalies)
    
    def _update_ml_anomaly_chart(self, anomalies):
        """Update ML anomaly chart"""
        self.ml_anomaly_figure.clear()
        ax = self.ml_anomaly_figure.add_subplot(111)
        
        if anomalies:
            scores = [a['score'] for a in anomalies[-100:]]
            timestamps = list(range(len(scores)))
            
            ax.plot(timestamps, scores, 'b-', alpha=0.7, label='Anomaly Score')
            ax.axhline(y=0, color='r', linestyle='--', alpha=0.5, label='Threshold')
            ax.set_xlabel('Sample Index')
            ax.set_ylabel('Anomaly Score')
            ax.set_title('Anomaly Detection Scores Over Time')
            ax.legend()
            ax.grid(True, alpha=0.3)
        else:
            ax.text(0.5, 0.5, 'No anomaly data', ha='center', va='center', fontsize=16)
        
        self.ml_anomaly_figure.tight_layout()
        self.ml_anomaly_canvas.draw()
    
    def _update_ml_classifications(self):
        """Update ML traffic classifications"""
        stats = self.traffic_analyzer.get_statistics()
        
        # Clear existing data
        for item in self.ml_classification_tree.get_children():
            self.ml_classification_tree.delete(item)
        
        if 'ml_analysis' not in stats:
            return
        
        ml_stats = stats['ml_analysis']
        recent_predictions = ml_stats.get('recent_predictions', [])
        
        # Display recent predictions
        for pred in recent_predictions[-100:]:
            from datetime import datetime
            timestamp = datetime.fromtimestamp(pred['timestamp']).strftime('%H:%M:%S')
            self.ml_classification_tree.insert("", tk.END, values=(
                timestamp,
                pred.get('type', 'Unknown'),
                f"{pred.get('confidence', 0):.4f}",
                f"Confidence: {pred.get('confidence', 0)*100:.2f}%"
            ))
        
        # Update chart
        self._update_ml_classification_chart(ml_stats['traffic_classifications'])
    
    def _update_ml_classification_chart(self, classifications):
        """Update ML classification chart"""
        self.ml_classification_figure.clear()
        ax = self.ml_classification_figure.add_subplot(111)
        
        if classifications:
            types = list(classifications.keys())
            counts = list(classifications.values())
            
            ax.barh(types, counts, color='steelblue', alpha=0.7)
            ax.set_xlabel('Count')
            ax.set_ylabel('Traffic Type')
            ax.set_title('Traffic Classification Distribution')
        else:
            ax.text(0.5, 0.5, 'No classification data', ha='center', va='center', fontsize=16)
        
        self.ml_classification_figure.tight_layout()
        self.ml_classification_canvas.draw()
    
    def _train_isolation_forest(self):
        """Train Isolation Forest model"""
        if not self.traffic_analyzer.ml_analyzer:
            messagebox.showerror("Error", "ML analyzer not available")
            return
        
        try:
            features_list = list(self.traffic_analyzer.ml_analyzer.feature_buffer)
            if len(features_list) < 100:
                messagebox.showwarning("Warning", f"Not enough data. Need at least 100 samples, got {len(features_list)}")
                return
            
            self.ml_training_log.insert(tk.END, f"[*] Training Isolation Forest on {len(features_list)} samples...\n")
            self.ml_training_log.see(tk.END)
            self.root.update()
            
            success = self.traffic_analyzer.ml_analyzer.train_isolation_forest(features_list)
            
            if success:
                self.ml_training_log.insert(tk.END, "[+] Isolation Forest trained successfully\n")
                self.ml_training_status.config(text="Isolation Forest: Trained")
            else:
                self.ml_training_log.insert(tk.END, "[!] Training failed\n")
            
            self.ml_training_log.see(tk.END)
        except Exception as e:
            self.ml_training_log.insert(tk.END, f"[!] Error: {e}\n")
            self.ml_training_log.see(tk.END)
    
    def _train_traffic_classifier(self):
        """Train traffic classifier"""
        messagebox.showinfo("Info", "Traffic classifier training requires labeled data.\nThis feature will be implemented with a training dataset.")
        self.ml_training_log.insert(tk.END, "[*] Traffic classifier training requires labeled dataset\n")
        self.ml_training_log.see(tk.END)
    
    def _build_lstm_model(self):
        """Build LSTM model"""
        if not self.traffic_analyzer.ml_analyzer:
            messagebox.showerror("Error", "ML analyzer not available")
            return
        
        try:
            # Build model with default input shape
            input_shape = (self.traffic_analyzer.ml_analyzer.window_size, 20)  # (timesteps, features)
            model = self.traffic_analyzer.ml_analyzer.build_lstm_anomaly_detector(input_shape)
            
            if model:
                self.ml_training_log.insert(tk.END, "[+] LSTM model built successfully\n")
                self.ml_training_log.insert(tk.END, "[*] Note: Model needs to be trained with labeled data\n")
                self.ml_training_status.config(text="LSTM: Built (needs training)")
            else:
                self.ml_training_log.insert(tk.END, "[!] Failed to build LSTM model\n")
            
            self.ml_training_log.see(tk.END)
        except Exception as e:
            self.ml_training_log.insert(tk.END, f"[!] Error: {e}\n")
            self.ml_training_log.see(tk.END)
    
def main():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()


