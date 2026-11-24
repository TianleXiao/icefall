# 碎冰 Icefall —— macOS 版

绕开校园网 / 单位网对网站的封锁。不改 DNS、不改证书、不装内核扩展。

**只对 HTTP/HTTPS 生效**（浏览器、大部分 App）。走 UDP 的东西（游戏串流、部分语音）需要 TUN，这一版没有。

---

## 开始

**双击 `Install-Icefall.command`。** 完事。

它自己会做四件事：

1. 如果你还在下载目录或桌面，把自己整套搬到 `~/Icefall`（免得被清理工具删掉）
2. 补可执行权限、去掉 Gatekeeper 的 quarantine 属性
3. 探测本机封锁情况、装后台服务、设 PAC 系统代理
4. 打印结果

全程不到 20 秒，只有一个终端窗口，跑完可以关。

### 被 Gatekeeper 挡住的话

提示「无法打开，因为来自身份不明的开发者」→ 系统设置 → 隐私与安全性 → 最下面「仍要打开」。

或者干脆绕开，在终端里跑：

```bash
cd ~/Downloads && xattr -dr com.apple.quarantine Icefall-mac
cd Icefall-mac && bash install.sh
```

装完多出一个 **`Icefall.app`**——双击就启动，不弹终端窗口，不占 Dock（`LSUIElement`）。真正的后台服务由 launchd 管着，双击 app 只是手动确认它在跑。

---

## 代理方式：PAC 自动分流，不是固定代理

系统代理设成 **PAC**（`networksetup -setautoproxyurl`），指向 `http://127.0.0.1:8899/proxy.pac`——这个 PAC 是程序**按 `strategy.json` 现生成**的。

好处很直接：

| | 固定代理 | PAC |
|---|---|---|
| 百度、GitHub 这些没被封的 | 也要绕经 8899 | **DIRECT，完全不经过** |
| 被封的站 | 走 8899 | 走 8899 |
| 系统侧设置 | web + secure + bypass 三项逐项配 | 一个 autoproxy URL |
| 换了策略表 | 要手改设置 | 重启服务自动重生成 |

性能上，固定代理让**所有**流量都进本程序拷贝一遍；PAC 之后只有真正需要分片的域名才进来，其余直连。这是这一版比 v1 更优雅的地方。

想退回固定代理：

```bash
./icefall setproxy 127.0.0.1:8899
```

想看 PAC 长什么样：

```bash
./icefall pac | head -20
```

---

## 它自动做了什么

| 步骤 | 做什么 |
|---|---|
| 探测 | 拿本机网络挨个试 36 个国内常见站，分成「没被封 / 分片能救 / 救不了 / 解析失败」四档，结果写进 `strategy.json` |
| 起服务 | 在 `127.0.0.1:8899` 起一个本地 HTTP 代理，后台常驻 |
| 系统代理 | 对每个网络服务（Wi-Fi、Ethernet、雷雳网桥…）执行 `networksetup -setwebproxy` / `-setsecurewebproxy` |
| 开机自启 | 写 `~/Library/LaunchAgents/com.icefall.proxy.plist`，登录即启动 |

原来这些位置的代理设置会被记进 `proxy-backup.json`，卸载时还原。

---

## 原理

学校多数是用**深度包检测**按 TLS 握手里的 SNI 字段精确阻断：它看见 `ClientHello` 里写着 `www.bilibili.com` 就回一个 RST，连接立刻断。

绕过办法不是伪装 SNI，而是**把 ClientHello 拆成两个 TCP 记录分两次发出去**。内容一个字没改，所以 TLS 1.3 的握手校验完全一致；但检测器要在单个包/单条记录里找那个完整域名，拆开之后就找不到了。

- 只改「怎么发」，不改「发什么」→ 不会触发 MAC 错误、不会掉证书
- 服务器收到拼起来的完整握手，毫无察觉
- 每个域名的最佳切点不同（取决于客户端 hello 的结构），所以程序会**从中间向两侧逐字节试**，直到握手成功

检测器规则不透明，同域名不同客户端（Safari / Chrome / curl）的 hello 长度和偏移都不一样，所以是「实测」而不是「公式」。

---

## 生效范围

**生效**：Safari、Chrome、Edge、大部分走系统代理的 App；终端里手动设了 `https_proxy` 的命令。

**不生效**：微信、游戏客户端、串流软件 —— 它们不读系统代理。这些要 TUN 模式，这一版没有。

---

## 探测结果怎么读

`install.sh` 跑完会打印四行统计：

```
分片可绕 25      ← 被封了，但分片能过（这是主力）
分片救不了 2     ← 学校封 + 服务器也挑 SNI，只能走境外/国内中转
未判定 1        ← 域名本身解析不出来
未封锁 8        ← 本来就能开，直连即可
```

想看明细：`./icefall discover`。

---

## 策略表 strategy.json

```json
{ "entries": {
    "bilibili.com": "fragment",
    "short.weixin.qq.com": "upstream",
    "www.baidu.com": "direct"
  } }
```

三种模式：

- `fragment` —— 分片。**主力**，不用服务器，延迟不增加。
- `upstream` —— 整条转给兜底上游（安装时自动探测 7897 / 7890 / 7891 / 1080，通常是你已有的 Clash）。分片救不了的走这个。
- `direct` —— 直连。没被封的别浪费性能。

后缀匹配，写 `bilibili.com` 就覆盖所有子域。想临时禁用某个站，改成 `direct` 即可。

没装 Clash 也能用，只是 `upstream` 那几条会失败。

---

## 文件表

| 文件 | 说明 |
|---|---|
| `Icefall.app` | 双击启动（不想开终端时用） |
| `icefall` | 实际跑的可执行文件，安装时用 `lipo` 合出的 universal2 |
| `icefall-darwin-arm64` | Apple Silicon (M1/M2/M3/M4) |
| `icefall-darwin-amd64` | Intel Mac |
| `install.sh` | 安装（唯一入口） |
| `install.command` | 双击包装 |
| `activate.command` | 重启代理服务 |
| `uninstall.command` | 还原系统代理、移除自启、结束进程 |
| `strategy.json` | 策略表，PAC 由它生成，可手改 |
| `proxy-backup.json` | 原始代理设置备份 |
| `proxy.log` | 运行日志 |

---

## 命令行

```bash
./icefall discover                    # 重新探测，更新 strategy.json
./icefall proxy 127.0.0.1:8899        # 前台跑代理（调试用）
./icefall proxy 127.0.0.1:8899 127.0.0.1:7890   # 带兜底上游
./icefall setproxy 127.0.0.1:8899     # 设系统代理
./icefall unsetproxy                  # 还原
./icefall autostart proxy 127.0.0.1:8899        # 装开机自启
./icefall noautostart                 # 移除
./icefall check                       # 经代理实测一批域名
```

---

## 排查

**双击 install.command 提示「无法打开，因为来自身份不明的开发者」**

系统拦了未签名程序。两条路：

1. 系统设置 → 隐私与安全性 → 底部「仍要打开」
2. 或者直接在终端跑 `bash install.sh`（这样不经过 Gatekeeper）

**装完浏览器还是打不开 B 站**

先确认代理活着：

```bash
nc -z 127.0.0.1 8899 && echo alive
tail -30 proxy.log
```

日志里应该有 `fragment@1XX OK (try N/M)`。如果全是 `fragment@.. RST`，说明这个站的切点规律变了，跑 `./icefall discover` 重扫。

**终端里 curl 打不开**

终端不读系统代理，手动设：

```bash
export https_proxy=http://127.0.0.1:8899
export http_proxy=http://127.0.0.1:8899
```

**Safari 打不开但 Chrome 能开**

Safari 有时会缓存连接。关掉重开，或者清理 `~/Library/Caches/com.apple.Safari`。

**想彻底卸载**

```bash
bash uninstall.command   # 或者双击
rm -rf ~/Icefall         # 删目录
```

---

## 已知边界

- 走 UDP 的（游戏串流、WebRTC、部分语音）—— 抓不到，需要 TUN
- 微信内置浏览器/视频号 —— 不读系统代理，需要 TUN
- 纯境外站（Google / YouTube）—— 学校同时封了 IP 层，分片救不了，必须境外中转
- 学校如果以后改成按 IP 段封或者全量 TLS 代理，这招失效
