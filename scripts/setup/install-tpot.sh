#!/bin/bash

echo "=== T-Pot Installation Script ==="

# 시스템 업데이트
echo "[1/5] Updating system..."
sudo apt update && sudo apt upgrade -y

# Git 설치
echo "[2/5] Installing Git..."
sudo apt install -y git

# T-Pot 다운로드
echo "[3/5] Cloning T-Pot repository..."
cd /opt
sudo git clone https://github.com/telekom-security/tpotce

# T-Pot 설치
echo "[4/5] Installing T-Pot..."
cd tpotce
sudo ./install.sh --type=user

echo "[5/5] Installation complete!"
echo "System will reboot in 10 seconds..."
echo "After reboot, access Web UI at: https://YOUR_EC2_IP:64297"
sleep 10
sudo reboot
