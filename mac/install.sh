#!/bin/bash
# 碎冰 Icefall —— macOS 安装（终端里跑：bash install.sh）
# 这是唯一入口。install.command 是它的双击包装。

set -u
cd "$(dirname "$0")" || exit 1

chmod +x ./*.command ./*.sh ./icefall-darwin-* 2>/dev/null

echo "============================================"
echo "  碎冰 Icefall —— macOS 安装"
echo "============================================"

# ---------- 1. 合出 universal2 二进制 ----------
ARCH=$(uname -m)
case "$ARCH" in
  arm64)  SRC=icefall-darwin-arm64 ;;
  x86_64) SRC=icefall-darwin-amd64 ;;
  *)      echo "[!] 未知架构 $ARCH"; exit 1 ;;
esac

if [ ! -f "$SRC" ]; then
  echo "[!] 找不到 $SRC，压缩包不完整"
  exit 1
fi

if command -v lipo >/dev/null 2>&1 && [ -f icefall-darwin-arm64 ] && [ -f icefall-darwin-amd64 ]; then
  lipo -create icefall-darwin-arm64 icefall-darwin-amd64 -output icefall 2>/dev/null \
    && echo "[1/6] 已合成 universal2（Intel + Apple Silicon 通吃）" \
    || { cp -f "$SRC" icefall; echo "[1/6] lipo 失败，已用 $SRC"; }
else
  cp -f "$SRC" icefall
  echo "[1/6] 已选用 $SRC（$ARCH）"
fi
chmod +x icefall
xattr -d com.apple.quarantine icefall 2>/dev/null

# ---------- 2. 打包成 .app ----------
APP="Icefall.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -f Info.plist "$APP/Contents/Info.plist"
cp -f app-launcher.sh "$APP/Contents/MacOS/icefall"
chmod +x "$APP/Contents/MacOS/icefall"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null
echo "[2/6] 已生成 Icefall.app（双击即启动，无终端窗口）"

# ---------- 3. 探测封锁情况 ----------
if [ -f strategy.json ]; then
  echo "[3/6] strategy.json 已存在，跳过探测"
else
  echo "[3/6] 正在探测本机网络的封锁情况（约 10 秒）…"
  ./icefall discover
fi

# ---------- 4. 找 Clash 端口（可选兜底） ----------
UP=""
for p in 7897 7890 7891 1080; do
  if nc -z 127.0.0.1 "$p" 2>/dev/null; then
    UP="$p"
    break
  fi
done

# ---------- 5. 装开机自启（顺便立刻拉起进程） ----------
echo "[5/6] 安装后台服务…"
./icefall noautostart >/dev/null 2>&1
if [ -n "$UP" ]; then
  echo "      发现本机代理 127.0.0.1:$UP，用作兜底上游"
  ./icefall autostart proxy 127.0.0.1:8899 "127.0.0.1:$UP"
else
  echo "      没发现本机代理，非分片流量将直连"
  ./icefall autostart proxy 127.0.0.1:8899
fi

PLIST="$HOME/Library/LaunchAgents/com.icefall.proxy.plist"
launchctl unload "$PLIST" 2>/dev/null
launchctl load "$PLIST" 2>/dev/null
sleep 2

if ! nc -z 127.0.0.1 8899 2>/dev/null; then
  echo "[!] 代理未起来，看日志："
  tail -20 proxy.log 2>/dev/null
  exit 1
fi
echo "      代理已在 127.0.0.1:8899 运行"

# ---------- 6. 设系统代理（PAC 模式） ----------
echo "[6/6] 设置系统代理（PAC 自动分流）…"
./icefall setproxy pac

echo ""
echo "完成。打开浏览器试试 bilibili.com。"
echo ""
echo "  双击 Icefall.app        启动/确认运行"
echo "  双击 uninstall.command  完全卸载并还原"
echo ""
echo "  策略表  strategy.json   ← 想改行为就改这个"
echo "  日志    proxy.log"
echo "  原始代理设置备份 proxy-backup.json"
echo ""
echo "PAC 模式说明：只有策略表里被封锁的域名走本机代理，"
echo "百度、GitHub 这些本来就通的完全不经过本程序，不多绕一跳。"
echo ""
echo "注意：Safari / Chrome 跟随系统代理；终端里的 curl 需要手动设："
echo "      export https_proxy=http://127.0.0.1:8899"
echo ""
