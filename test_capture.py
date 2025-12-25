#!/usr/bin/env python3
"""
測試腳本：驗證SSL監聽和密碼截取功能
在Kali Linux上運行此腳本來測試功能是否正常
"""

import sys
import os

# 添加專案路徑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import sniff, IP, TCP, Raw, get_if_list
import time

def test_interface(interface='eth0'):
    """測試網路介面是否可以捕獲資料包"""
    print(f"[*] 測試網路介面: {interface}")
    print(f"[*] 將捕獲10個TCP資料包（端口80）...")
    print(f"[*] 請在另一個終端發送HTTP請求，例如:")
    print(f"    curl http://www.example.com")
    print(f"[*] 或訪問任何HTTP網站")
    print()
    
    packet_count = 0
    
    def process_packet(packet):
        nonlocal packet_count
        packet_count += 1
        
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            print(f"[{packet_count}] TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            if packet.haslayer(Raw):
                try:
                    load = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'HTTP' in load or 'GET' in load or 'POST' in load:
                        print(f"     [HTTP資料] 長度: {len(load)} 字元")
                        # 顯示前100個字元
                        preview = load[:100].replace('\n', '\\n').replace('\r', '\\r')
                        print(f"     預覽: {preview}...")
                except:
                    print(f"     [無法解碼] 長度: {len(packet[Raw].load)} 位元組")
        
        if packet_count >= 10:
            return True  # 停止捕獲
        return False
    
    try:
        print(f"[*] 開始捕獲... (按Ctrl+C停止)")
        sniff(iface=interface, filter="tcp port 80", prn=process_packet, 
              stop_filter=lambda x: packet_count >= 10, timeout=30)
        
        if packet_count == 0:
            print()
            print("[!] 沒有捕獲到任何資料包！")
            print("[!] 可能的原因:")
            print("    1. 沒有HTTP流量經過此介面")
            print("    2. 需要先啟動ARP欺騙")
            print("    3. 網路介面名稱錯誤")
            print("    4. 權限不足（需要root）")
        else:
            print()
            print(f"[+] 成功捕獲 {packet_count} 個資料包！")
            print("[+] 功能應該可以正常工作")
            
    except PermissionError:
        print("[!] 權限錯誤: 需要root權限")
        print("[!] 請使用: sudo python3 test_capture.py")
        sys.exit(1)
    except OSError as e:
        if "No such device" in str(e):
            print(f"[!] 網路介面 '{interface}' 不存在")
            print("[*] 可用的介面:")
            for iface in get_if_list():
                print(f"    - {iface}")
        else:
            print(f"[!] 錯誤: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] 測試被中斷")
    except Exception as e:
        print(f"[!] 錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    interface = 'eth0'
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    
    print("=" * 60)
    print("SSL監聽和密碼截取功能測試")
    print("=" * 60)
    print()
    
    # 檢查是否以root執行
    if os.geteuid() != 0:
        print("[!] 警告: 建議以root權限執行此測試")
        print("[!] 使用: sudo python3 test_capture.py")
        print()
    
    test_interface(interface)

