#!/usr/bin/env python3
"""
MITM攻擊演示系統
主程式入口
"""

import sys
import os

# 檢查Python版本
if sys.version_info < (3, 7):
    print("錯誤: 需要Python 3.7或更高版本")
    sys.exit(1)

# 檢查是否以root權限執行（某些功能需要）
if os.geteuid() != 0:
    print("警告: 某些功能需要root權限")
    print("建議使用: sudo python3 main.py")

try:
    from gui.main_window import MainWindow
    import tkinter as tk
except ImportError as e:
    print(f"匯入錯誤: {e}")
    print("請確保已安裝所有依賴:")
    print("  pip3 install -r requirements.txt --break-system-packages")
    print("如果缺少系統依賴，請先執行:")
    print("  sudo apt install python3-tk python3-dev libnetfilter-queue-dev libpcap-dev")
    sys.exit(1)

def main():
    """主函式"""
    print("=" * 60)
    print("MITM攻擊演示系統")
    print("=" * 60)
    print("注意: 此工具僅用於教育和研究目的")
    print("請確保在合法授權的環境中使用")
    print("=" * 60)
    
    root = tk.Tk()
    app = MainWindow(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\\n[!] 程式被使用者中斷")
        sys.exit(0)

if __name__ == "__main__":
    main()


