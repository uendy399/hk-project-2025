#!/usr/bin/env python3
"""
MITM Attack Demonstration System
Main program entry point
"""

import sys
import os

# Check Python version
if sys.version_info < (3, 7):
    print("Error: Python 3.7 or higher is required")
    sys.exit(1)

# Check if running with root privileges (required for some features)
if os.geteuid() != 0:
    print("Warning: Some features require root privileges")
    print("Recommended: sudo python3 main.py")

try:
    from gui.main_window import MainWindow
    import tkinter as tk
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all dependencies are installed:")
    print("  pip3 install -r requirements.txt --break-system-packages")
    print("If system dependencies are missing, please run:")
    print("  sudo apt install python3-tk python3-dev libnetfilter-queue-dev libpcap-dev")
    sys.exit(1)

def main():
    """Main function"""
    print("=" * 60)
    print("MITM Attack Demonstration System")
    print("=" * 60)
    print("Note: This tool is for educational and research purposes only")
    print("Please ensure you are using it in a legally authorized environment")
    print("=" * 60)
    
    root = tk.Tk()
    app = MainWindow(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\\n[!] Program interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()


