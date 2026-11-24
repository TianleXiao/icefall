#!/bin/bash
# 双击包装：调 install.sh
cd "$(dirname "$0")" || exit 1
bash install.sh
read -n 1 -s -r -p "按任意键关闭…"
echo ""
