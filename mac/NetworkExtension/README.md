# Icefall 透明代理扩展（macOS NetworkExtension）

让**不读系统代理**的程序（微信客户端、游戏启动器、Electron 应用）也走碎冰分片。

这个目录是**可直接编译的源码骨架**，但不是现成能装的包。原因在文末的「前置条件」。

---

## 为什么是 AppProxy 而不是 PacketTunnel

| | NEPacketTunnelProvider | NEAppProxyProvider |
|---|---|---|
| 拿到什么 | 裸 IP 包 | 已组装的 flow（host + port + 字节流） |
| 需要用户态 TCP/IP 栈 | **需要**（gVisor 之类） | **不需要** |
| 能接管 | 整机 | 显式加入 VPN 的 App（或全部，用 `includeAllNetworks`） |
| UDP | 要自己实现 | 系统给 `NEAppProxyUDPFlow`，可以直接拒或转发 |

Windows 版 TUN 卡死的地方就是「需要用户态栈」——gVisor 的 `pkg/tcpip/stack` 在 Go 1.27 编译不过。
macOS 上走 AppProxy，`NEFlow` 已经把 TCP 接好了，我们只要把字节流转给本地碎冰的 SOCKS5（`127.0.0.1:8899`），
分片发生在碎冰内部，扩展本身十几行核心逻辑。

## 文件

| 文件 | 作用 |
|---|---|
| `AppProxyProvider.swift` | 扩展主体。`handleNewFlow` 里把 TCP flow 接到 SOCKS5 |
| `Socks5.swift` | 最小 SOCKS5 客户端（CONNECT + 双向搬运），`NWConnection` 实现 |
| `TunnelInstaller.swift` | 主 App 侧：创建 `NETunnelProviderManager`、启动/卸载 |
| `AppProxyProvider.entitlements` | 扩展需要的 entitlement：`app-proxy-provider` |

## 数据流

```
被代理的 App ──TCP──> 扩展 handleNewFlow
                        │  取 remoteEndpoint.host/port
                        ▼
                   Socks5Connection ──CONNECT host:port──> 127.0.0.1:8899 碎冰
                        │                                        │
                        │                                        │ 分片
                        ▼                                        ▼
                   pipe 双向搬运  ────────────────────>  目标服务器
```

碎冰必须已经在跑（`icefall proxy 127.0.0.1:8899`，或 launchd 服务）。
扩展里 `127.0.0.1` 指向宿主机的回环，符合预期。

## 前置条件（这是它还不能一键装的原因）

1. **Apple Developer Program，99 美元/年。**
   NetworkExtension 是受限 entitlement，免费账号签不出来，编译过但装不上。

2. **entitlement 要在开发者后台单独申请并通过人工审核。**
   `com.apple.developer.networking.networkextension` 里的 `app-proxy-provider` 值，
   提交后等待审核（通常几天）。通过后才有对应的 provision profile。

3. **必须在 Mac 上用 Xcode 构建。**
   交叉编译不行（Swift + Xcode 工程 + 签名链），Windows 上完全做不了。
   本仓库的开发者只在 Windows，所以这里给的是源码，不是 .appex。

4. **需要一个 Xcode 工程把两个 target 串起来：**
   - Target A：主 App（`com.icefall.proxy`），带 `TunnelInstaller.swift`
   - Target B：App Extension（`com.icefall.proxy.AppProxy`，类型 App Proxy Provider），
     带 `AppProxyProvider.swift` + `Socks5.swift`，挂 `AppProxyProvider.entitlements`
   - 两者共享 App Group `group.com.icefall.proxy`

## 建工程的步骤

1. Xcode → New Project → macOS App，Bundle ID `com.icefall.proxy`，语言 Swift
2. File → New → Target → **Network Extension** → 类型选 **App Proxy Provider**，
   名字 `AppProxy`，Bundle ID `com.icefall.proxy.AppProxy`
3. 把 `AppProxyProvider.swift`、`Socks5.swift` 拖进扩展 target
4. 把 `TunnelInstaller.swift` 拖进主 App target
5. 扩展 target → Signing & Capabilities → 加 **App Groups**、**Network Extensions**
   （勾 App Proxy），确认 entitlements 与 `AppProxyProvider.entitlements` 一致
6. 主 App 里调 `TunnelInstaller.installAndStart { }`，系统会弹「Icefall 想要添加 VPN 配置」
7. 用户同意后，被代理的 App 流量就会进扩展

## 已知缺失

- **不接管 UDP**：`handleNewFlow` 对 `NEAppProxyUDPFlow` 返回 `false`（交回系统直连）。
  视频号、游戏串流的 UDP 部分还没覆盖。要做的话在扩展里实现 UDP ASSOCIATE 中继，
  同时碎冰本体要补 SOCKS5 UDP ASSOCIATE（目前明确回 `0x07 command not supported`）。
- **不包含 .xcodeproj**：见前置条件第 3 条。工程要在 Mac 上建一次，之后就能反复构建。
- **未做 `includeAllNetworks`**：默认只接管被显式纳入的 App。想全网接管，
  在 `NETunnelProviderProtocol` 上打开该选项，并在系统设置里确认。

## 没有开发者账号怎么办

用现成的两条路，不需要 NetworkExtension：

- 读系统代理的程序：PAC 自动分流已经覆盖（`icefall setproxy pac`）
- 支持 SOCKS5 的程序：手动填 `127.0.0.1:8899`
- 微信客户端这类：目前覆盖不到，等这个扩展，或在本机跑 Clash 的 TUN 模式兜底
