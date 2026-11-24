#!/bin/bash
# 碎冰 Icefall —— macOS 卸载
# 还原系统代理、移除开机自启、结束进程。

set -u
cd "$(dirname "$0")" || exit 1

if [ -x icefall ]; then
  ./icefall noautostart
  ./icefall unsetproxy
fi

pkill -f "icefall proxy" 2>/dev/null
sleep 0.5

echo ""
echo "已还原系统代理并结束进程。"
echo "策略表 strategy.json 和二进制留在目录里，删掉整个文件夹即可彻底清除。"
echo ""
read -n 1 -s -r -p "按任意键关闭…"
echo ""
