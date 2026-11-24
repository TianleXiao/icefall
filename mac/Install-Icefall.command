#!/bin/bash
# 碎冰 Icefall —— 一键安装
#
# 双击我。会做三件事：
#   1. 如果还在下载目录/桌面，把自己这套文件搬到 ~/Icefall（防止被清空站误删）
#   2. 补上可执行权限、去掉 quarantine
#   3. 调 install.sh

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/Icefall"

echo "============================================"
echo "  碎冰 Icefall —— 一键安装"
echo "============================================"

# ---------- 1. 搬到固定位置 ----------
if [ "$HERE" != "$DEST" ]; then
  echo "当前在：$HERE"
  echo "搬到：  $DEST"
  mkdir -p "$DEST" || { echo "[!] 建目录失败"; read -n 1 -s -r -p "按任意键关闭…"; exit 1; }
  # ditto 是 macOS 原生，保留权限和扩展属性；退路是 cp -R
  if command -v ditto >/dev/null 2>&1; then
    ditto "$HERE" "$DEST" || { echo "[!] 复制失败"; read -n 1 -s -r -p "按任意键关闭…"; exit 1; }
  else
    cp -R "$HERE"/. "$DEST"/ || { echo "[!] 复制失败"; read -n 1 -s -r -p "按任意键关闭…"; exit 1; }
  fi
  cd "$DEST" || exit 1
else
  echo "已在：$DEST"
  cd "$DEST" || exit 1
fi

# ---------- 2. 权限 ----------
chmod +x ./*.command ./*.sh 2>/dev/null
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null
echo "已补可执行权限、去掉隔离属性"

# ---------- 3. 装 ----------
if [ ! -f install.sh ]; then
  echo "[!] 找不到 install.sh，压缩包不完整"
  read -n 1 -s -r -p "按任意键关闭…"
  exit 1
fi

echo ""
bash install.sh

echo ""
echo "安装结束。这个窗口可以关掉了。"
echo "以后想手动启动就双击 $DEST/Icefall.app"
echo ""
read -n 1 -s -r -p "按任意键关闭…"
echo ""
