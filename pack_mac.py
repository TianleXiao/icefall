#!/usr/bin/env python3
# pack_mac.py —— 打 macOS 分发包。
#
# 为什么不用 Windows 的 tar：
#   bsdtar 在 Windows 上拿不到 POSIX 权限，只能存 0644，
#   解压到 Mac 后 .command 双击会「没有执行权限」。
#   这里用 tarfile 显式写 0755，解压即可双击。

import os
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "mac")
OUT = os.path.abspath(os.path.join(HERE, "..", "dist", "Icefall-mac.tar.gz"))

# 需要可执行位的文件
EXEC_NAMES = {
    "install.sh",
    "install.command",
    "activate.command",
    "uninstall.command",
    "Install-Icefall.command",
    "app-launcher.sh",
    "icefall-darwin-arm64",
    "icefall-darwin-amd64",
}

FILES = [
    "Install-Icefall.command",
    "install.sh",
    "install.command",
    "activate.command",
    "uninstall.command",
    "app-launcher.sh",
    "Info.plist",
    "README.md",
    "icefall-darwin-arm64",
    "icefall-darwin-amd64",
]


def main() -> int:
    missing = [f for f in FILES if not os.path.isfile(os.path.join(SRC, f))]
    if missing:
        print("missing:", ", ".join(missing))
        return 1

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    now = int(time.time())

    with tarfile.open(OUT, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for name in FILES:
            path = os.path.join(SRC, name)
            data = open(path, "rb").read()

            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o755 if name in EXEC_NAMES else 0o644
            ti.mtime = now
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, fileobj=__import__("io").BytesIO(data))
            print(f"  {oct(ti.mode)[2:]}  {len(data):>10}  {name}")

    print(f"\n{OUT}  {os.path.getsize(OUT)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
