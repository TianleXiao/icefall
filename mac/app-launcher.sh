#!/bin/bash
# Icefall.app 的启动脚本。
#
# 为什么不直接把 Go 二进制放进 Contents/MacOS：
# 那样 os.Executable() 会落在 .app 内部，strategy.json / proxy.log
# 全被写进 bundle，升级或替换 app 就全丢了。
# 这里 exec 到上层目录的真实二进制，exeDir() 才是对的。

DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$DIR" || exit 1

if [ ! -x ./icefall ]; then
  osascript -e 'display alert "碎冰还没安装" message "先运行 install.sh"' >/dev/null 2>&1
  exit 1
fi

UP=""
for p in 7897 7890 7891 1080; do
  if nc -z 127.0.0.1 "$p" 2>/dev/null; then
    UP="127.0.0.1:$p"
    break
  fi
done

if [ -n "$UP" ]; then
  exec ./icefall proxy 127.0.0.1:8899 "$UP"
fi
exec ./icefall proxy 127.0.0.1:8899
