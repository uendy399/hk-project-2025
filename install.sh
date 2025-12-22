#!/bin/bash
# MITM攻击与防御演示系统 - 安装脚本

echo "=========================================="
echo "MITM攻击与防御演示系统 - 安装程序"
echo "=========================================="
echo ""

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then 
    echo "警告: 某些功能需要root权限"
    echo "建议使用: sudo ./install.sh"
    echo ""
fi

# 检查Python版本
echo "[*] 检查Python版本..."
python3 --version
if [ $? -ne 0 ]; then
    echo "[!] 错误: 未找到Python3"
    exit 1
fi

# 更新包管理器
echo ""
echo "[*] 更新包管理器..."
sudo apt update

# 安装系统依赖
echo ""
echo "[*] 安装系统依赖..."
sudo apt install -y python3 python3-pip nmap wireshark

# 安装netfilterqueue依赖
echo ""
echo "[*] 安装netfilterqueue依赖..."
sudo apt install -y python3-dev libnetfilter-queue-dev

# 安装密码破解工具（可选）
echo ""
read -p "是否安装密码破解工具 (hashcat, john)? [y/N]: " install_crack
if [[ $install_crack =~ ^[Yy]$ ]]; then
    sudo apt install -y hashcat john
fi

# 安装Python依赖
echo ""
echo "[*] 安装Python依赖..."
pip3 install -r requirements.txt

# 配置IP转发
echo ""
echo "[*] 配置IP转发..."
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# 设置执行权限
echo ""
echo "[*] 设置执行权限..."
chmod +x main.py
chmod +x install.sh

echo ""
echo "=========================================="
echo "安装完成！"
echo "=========================================="
echo ""
echo "使用方法:"
echo "  sudo python3 main.py"
echo ""
echo "注意: 某些功能需要root权限"
echo ""

