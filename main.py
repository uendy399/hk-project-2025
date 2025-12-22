#!/usr/bin/env python3
"""
MITM攻击与防御演示系统
主程序入口
"""

import sys
import os

# 检查Python版本
if sys.version_info < (3, 7):
    print("错误: 需要Python 3.7或更高版本")
    sys.exit(1)

# 检查是否以root权限运行（某些功能需要）
if os.geteuid() != 0:
    print("警告: 某些功能需要root权限")
    print("建议使用: sudo python3 main.py")

try:
    from gui.main_window import MainWindow
    import tkinter as tk
except ImportError as e:
    print(f"导入错误: {e}")
    print("请确保已安装所有依赖: pip install -r requirements.txt")
    sys.exit(1)

def main():
    """主函数"""
    print("=" * 60)
    print("MITM攻击与防御演示系统")
    print("=" * 60)
    print("注意: 此工具仅用于教育和研究目的")
    print("请确保在合法授权的环境中使用")
    print("=" * 60)
    
    root = tk.Tk()
    app = MainWindow(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\\n[!] 程序被用户中断")
        sys.exit(0)

if __name__ == "__main__":
    main()

