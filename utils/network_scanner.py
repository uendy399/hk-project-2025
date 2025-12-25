#!/usr/bin/env python3
"""
Network Scanner Tool Module
Used to scan devices in local network
"""

import socket
from scapy.all import ARP, Ether, srp
import ipaddress

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: nmap module not installed, some scanning features may be limited")
    print("Please install: pip3 install python-nmap --break-system-packages")

class NetworkScanner:
    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def scan_network(self, network_range):
        """
        Scan for active hosts in specified network range
        
        Args:
            network_range: Network range, e.g. '192.168.1.0/24'
        
        Returns:
            list: List of active hosts
        """
        if not NMAP_AVAILABLE or self.nm is None:
            # If nmap unavailable, use scapy for ARP scanning
            return self._scan_with_scapy(network_range)
        
        try:
            # Use nmap to scan
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
            print(f"Scan error: {e}")
            # If nmap scan fails, fall back to scapy
            return self._scan_with_scapy(network_range)
    
    def _scan_with_scapy(self, network_range):
        """Use scapy for network scanning (fallback when nmap unavailable)"""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = []
            
            # Use ARP requests to scan
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
            print(f"Scan error: {e}")
            return []
    
    def _get_mac(self, ip):
        """Get MAC address corresponding to IP address"""
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
        """Get default gateway"""
        try:
            # Read routing table to get gateway
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
            print(f"Error getting gateway: {e}")
        return None


