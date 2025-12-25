#!/usr/bin/env python3
"""
网络扫描工具模块
用于扫描局域网中的设备
"""

import nmap
import socket
from scapy.all import ARP, Ether, srp
import ipaddress

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_network(self, network_range):
        """
        扫描指定网络范围内的活动主机
        
        Args:
            network_range: 网络范围，例如 '192.168.1.0/24'
        
        Returns:
            list: 活动主机列表
        """
        try:
            # 使用nmap扫描
            self.nm.scan(hosts=network_range, arguments='-sn')
            hosts = []
            
            for host in self.nm.all_hosts():
                hostname = self.nm[host].hostname() if self.nm[host].hostname() else 'Unknown'
                mac = self._get_mac(host)
                hosts.append({
                    'ip': host,
                    'hostname': hostname,
                    'mac': mac,
                    'status': 'up'
                })
            
            return hosts
        except Exception as e:
            print(f"扫描错误: {e}")
            return []
    
    def _get_mac(self, ip):
        """获取IP地址对应的MAC地址"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            return "Unknown"
        except:
            return "Unknown"
    
    def get_gateway(self):
        """获取默认网关"""
        try:
            # 读取路由表获取网关
            import subprocess
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                parts = result.stdout.split()
                if 'via' in parts:
                    gateway_ip = parts[parts.index('via') + 1]
                    gateway_mac = self._get_mac(gateway_ip)
                    return {'ip': gateway_ip, 'mac': gateway_mac}
        except Exception as e:
            print(f"获取网关错误: {e}")
        return None


