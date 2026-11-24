#!/bin/bash
# 碎冰 Icefall —— macOS 启动/重启（已安装过用这个）

set -u
cd "$(dirname "$0")" || exit 1

if [ ! -x icefall ]; then
  echo "[!] 还没安装，先跑：bash install.sh"
  read -n 1 -s -r -p "按任意键关闭…"
  exit 1
fi

PLIST="$HOME/Library/LaunchAgents/com.icefall.proxy.plist"
if [ ! -f "$PLIST" ]; then
  echo "[!] 找不到后台服务配置，重跑 bash install.sh"
  read -n 1 -s -r -p "按任意键关闭…"
  exit 1
fi

launchctl unload "$PLIST" 2>/dev/null
launchctl load "$PLIST" 2>/dev/null
sleep 1.5

./icefall setproxy pac

if nc -z 127.0.0.1 8899 2>/dev/null; then
  echo "已启动，系统代理已切到 PAC 模式"
else
  echo "[!] 代理没起来，看 proxy.log"
fi

echo ""
read -n 1 -s -r -p "按任意键关闭…"
echo ""
