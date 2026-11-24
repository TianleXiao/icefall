# 碎冰 Icefall

用 TLS record 分片绕过校园网 / 企业网的 SNI 封锁。Windows + macOS。

不需要服务器，不需要境外节点，不碰加密内容。
同一个 WiFi 下别的设备被封，你这台能开。

---

## 它解决什么

很多学校的网关不封 IP、不封端口，只做一件事：**检查 TLS ClientHello 里的明文 SNI**，看到黑名单里的域名就回一个 RST，连接当场断。

表现是：

- `ping` 通、TCP 443 能连
- 浏览器报 `ERR_CONNECTION_RESET` / `连接已重置`
- 换一台不在黑名单的机器或换手机流量，同一个站能开

碎冰的做法：在 ClientHello 发出去之前，把它**切成两个 TLS record**。
SNI 字符串被劈成两半落在不同 record 里，检测设备抓不到完整域名；到服务器那边再拼回去，握手完全正常。

只改「怎么发」，不改「发什么」，所以 TLS 1.3 的 transcript 一致，不会出现 `bad record MAC`。

## 为什么不是改 SNI

改 SNI 字节是最直觉的想法，但**数学上不成立**：

RFC 8446 里 `Transcript-Hash(ClientHello)` 参与 key schedule 派生。
服务端拿改过的 hello 算，客户端拿自己发的原始 hello 算 → 两边 `client_handshake_traffic_secret` 不同 → 所有应用数据 MAC 全错。

实测三种客户端全挂：

| 客户端 | 报错 |
|---|---|
| Python ssl | `DECRYPTION_FAILED_OR_BAD_RECORD_MAC` |
| Go crypto/tls | `local error: tls: bad record MAC` |
| Windows schannel | `SEC_E_DECRYPT_FAILURE (0x80090330)` |

分片没有这个问题：内容一个字节没动。

## 安装

### Windows

1. 下载 `Icefall-v1.zip`，解压到 `C:\Icefall\`（别放桌面或下载目录，清理工具会删）
2. 双击 `activate.bat`
   - 第一次会自己跑一遍探测（约 5 秒），生成本机专用的 `strategy.json`
   - 然后用 `reg add` 把系统代理指向 `127.0.0.1:8899`
3. 开浏览器

卸载：双击 `uninstall.bat`。

### macOS

1. 下载 `Icefall-mac.tar.gz`，解压
2. 双击 `Install-Icefall.command`
   - 第一次被 Gatekeeper 拦 → 右键「打开」→ 再点「打开」
   - 会自动搬到 `~/Icefall`、用 `lipo` 合成 universal2、建 `Icefall.app`、装 launchd 开机自启、设 PAC
3. 开浏览器

卸载：`~/Icefall/uninstall.command`。

## 它做了什么

```
浏览器 ──PAC/系统代理──> 127.0.0.1:8899 碎冰 ──分片──> 目标站
                                │
                                └──不在策略表──> 兜底上游（Clash）或直连
```

- **PAC 自动分流**：只把策略表里的域名导进碎冰，其余 DIRECT。百度、GitHub 不会多绕一跳。
- **切点并发竞速 + 缓存**：检测规则不透明，不同站点有效切点不同（B站 `+4~+15`，bilivideo CDN `+16~+25`）。首次连接同时发 4 个切点，谁先收到 ServerHello 就用谁；命中的切点按「域名 + ClientHello 长度 + SNI 偏移」缓存，同一页面后续几十个连接直接一次打中。
- **自动学习未收录站点**：策略表里没有的域名不再干等上游。先直连嗅一下（1.2 秒），通了就记住 direct；不通就读 ClientHello 让分片和上游同时竞速，哪个先通就用哪个。分片赢的会**立刻写进 `strategy.json`**，下次直接命中。所以你不用预先准备域名清单，正常上网它就自己长出来。
- **IP 层不通直接走上游**：TCP 都连不上的站（境外 IP 被封），分片帮不上忙，不再白试 4 个切点，直接交给上游。
- **兜底上游**：不在策略表里的流量整条转给 Clash，境外站原有能力不受影响。没装 Clash 也能用（纯直连）。

## 生效范围

| 类别 | 说明 |
|---|---|
| 浏览器 | 全自动（读系统代理 / PAC） |
| 走系统代理的程序 | 自动 |
| 支持 SOCKS5 的程序 | 手动填 `127.0.0.1:8899`，同一个端口，协议自动识别，判定逻辑与浏览器完全一致（含自动学习） |
| 完全不读代理的程序 | 微信客户端、部分游戏启动器：**需要 TUN，尚未实现** |
| UDP 流量 | 未实现（走 Clash TUN） |

## 命令行

```bash
icefall proxy [addr] [upstream]   # 启动代理，默认 127.0.0.1:8899
icefall discover                  # 探测本机网络，生成 strategy.json
icefall check                     # 经代理逐个验证站点
icefall pac                       # 打印生成的 PAC
icefall setproxy [addr|pac]       # 设系统代理
icefall unsetproxy                # 还原
icefall autostart [args...]       # 开机自启
icefall noautostart               # 取消自启
icefall probe <domain>            # 单域名三级判定：DNS / TCP / TLS
icefall cut <domain>              # 扫单域名有效切点
```

## SOCKS5

`127.0.0.1:8899` 同时是 HTTP 代理和 SOCKS5 代理，靠首字节区分（SOCKS5 是 `0x05`，HTTP 方法全是 ASCII）。

```bash
curl --socks5-hostname 127.0.0.1:8899 https://www.bilibili.com
```

UDP ASSOCIATE 未实现，会明确回 `0x07 command not supported`，不会假装支持然后静默丢包。

SOCKS5 和 HTTP 走的是同一套判定：查策略表 → 查运行时记忆 → 未收录就现场研判并学习。实测（本校网络）：

| 目标 | HTTP 代理 | SOCKS5 |
|---|---|---|
| bilibili（分片） | 161 ms | 141 ms |
| 抖音（分片） | 149 ms | 186 ms |
| 知乎（直连） | 137 ms | 228 ms |
| youtube（上游） | 6.9 s | 6.9 s |

## 实测（本校网络，29 个域名）

`icefall check` 一次跑完，可打开 18 / 可疑 10（301、302、403、444 全是站点自己的风控，正常）/ 打不开 1（twitter，上游节点问题）。

关键延迟（冷启动 → 缓存命中）：

| 目标 | 优化前 | 现在 |
|---|---|---|
| www.bilibili.com | 767 ms | 145 ms |
| www.facebook.com | 2988 ms | 1641 ms |
| api.github.com | 4258 ms | 1448 ms |
| www.google.com | 5073 ms | 2006 ms（首连 3.5 s） |
| registry.npmjs.org | 1731 ms | 794 ms |
| claude.ai | 1804 ms | 708 ms |

## 探测结果怎么读

`icefall discover` 输出四档：

| 结果 | 含义 | 处理 |
|---|---|---|
| 未封锁 | 真 SNI 直连就通 | 走 DIRECT |
| 分片可绕 | 真 SNI 被 RST，分片后握手成功 | `fragment` |
| 分片救不了 | 所有切点都 RST，或服务器只认白名单 SNI | `upstream` |
| 未判定 | DNS 解析失败（域名本身不存在） | 跳过 |

`strategy.json` 就是这张表，可以手改：

```json
{
  "entries": {
    "bilibili.com": "fragment",
    "short.weixin.qq.com": "upstream"
  }
}
```

匹配规则是后缀匹配，`bilibili.com` 覆盖 `www.bilibili.com` / `api.bilibili.com` / `cn-jsnt-ct-01-02.bilivideo.com` 之外的所有子域。

## 编译

```bash
go build -o icefall.exe .
GOOS=darwin GOARCH=arm64 go build -o icefall-darwin-arm64 .
GOOS=darwin GOARCH=amd64 go build -o icefall-darwin-amd64 .
```

依赖只有 `utls`（拿 Chrome 的 ClientHello 指纹）。分片逻辑是纯 `net` + 字节操作，与平台无关。

打包 macOS 包必须用 `pack_mac.py`：Windows 的 bsdtar 存不了 POSIX 权限位，`.command` 解压到 Mac 后双击会报没有执行权限。

## 已知边界

- **TUN 未实现**。gVisor 的 `pkg/tcpip/stack` 在 Go 1.27 下编译失败（`found packages stack and bridge`，来自 `bridge_test.go` 声明 `package bridge_test`；且 `pkg/sync` 的 codegen 只覆盖到 go1.26），Windows 建 TUN 网卡还要管理员权限。代码在 `_tun_wip/`，架构已画好，缺一个能编译的用户态栈。
- **UDP 未实现**。海马云电脑、部分游戏的串流走 UDP/WebRTC，HTTP 代理和 SOCKS5 TCP 都碰不到。
- **微信视频号在客户端内不通**。微信不读系统代理，`short/long.weixin.qq.com` 且是「学校 RST + 腾讯只认白名单 SNI」双重限制，分片救不了，只能上游。
- **境外站靠上游，不靠分片**。`google.com` / `youtube.com` 是 DNS 污染 + IP 层封锁，分片救不了（实测 `www.google.com` 被解析到 Twitter 的 IP，真实 IP 的 443 也不通）。未收录时会自动判到 upstream 并记住，前提是配了兜底上游（Clash）；没配就只剩直连。

## 目录

```
*.go              代理核心：proxy / snipatch / cuts / cutcache / strategy / pac / socks / discover
sysproxy_*.go     平台层：系统代理、开机自启
mac/              macOS 包脚本、Info.plist、app launcher
_tun_wip/         TUN 模式半成品（未编译通过）
CONCLUSION.md     为什么改 SNI 不成立的技术结论
```

## 免责

只用于自己网络下恢复被误封的正常访问。别拿它做别的事。

## License

MIT
