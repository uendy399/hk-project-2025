#!/usr/bin/env python3
"""
網路掃描工具模組
用於掃描區域網路中的裝置
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
        掃描指定網路範圍內的活動主機
        
        Args:
            network_range: 網路範圍，例如 '192.168.1.0/24'
        
        Returns:
            list: 活動主機列表
        """
        if not NMAP_AVAILABLE or self.nm is None:
            # 如果nmap不可用，使用scapy進行ARP掃描
            return self._scan_with_scapy(network_range)
        
        try:
            # 使用nmap掃描
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
            print(f"掃描錯誤: {e}")
            # 如果nmap掃描失敗，回退到scapy
            return self._scan_with_scapy(network_range)
    
    def _scan_with_scapy(self, network_range):
        """使用scapy進行網路掃描（nmap不可用時的備用方案）"""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = []
            
            # 使用ARP請求掃描
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
            print(f"掃描錯誤: {e}")
            return []
    
    def _get_mac(self, ip):
        """獲取IP位址對應的MAC位址"""
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
        """獲取預設閘道"""
        try:
            # 讀取路由表獲取閘道
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
            print(f"獲取閘道錯誤: {e}")
        return None


