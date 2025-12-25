#!/usr/bin/env python3
"""
网络扫描工具模块
用于扫描局域网中的设备
"""

import socket
from scapy.all import ARP, Ether, srp
import ipaddress

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("警告: nmap 模組未安裝，某些掃描功能可能受限")
    print("請安裝: pip3 install python-nmap --break-system-packages")

class NetworkScanner:
    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def scan_network(self, network_range):
        """
        扫描指定网络范围内的活动主机
        
        Args:
            network_range: 网络范围，例如 '192.168.1.0/24'
        
        Returns:
            list: 活动主机列表
        """
        if not NMAP_AVAILABLE or self.nm is None:
            # 如果nmap不可用，使用scapy进行ARP扫描
            return self._scan_with_scapy(network_range)
        
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
            # 如果nmap扫描失败，回退到scapy
            return self._scan_with_scapy(network_range)
    
    def _scan_with_scapy(self, network_range):
        """使用scapy进行网络扫描（nmap不可用时的备用方案）"""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = []
            
            # 使用ARP请求扫描
            arp_request = ARP(pdst=str(network_range))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = 'Unknown'
                
                hosts.append({
                    'ip': ip,
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


