# 校园网 SNI 封锁 —— 技术路线结论

## 已证伪的方案

**直接改写客户端 ClientHello 的 SNI 字节，然后原样转发。**

实测结果：服务器正常返回完整 ServerHello + ChangeCipherSpec + Finished，但客户端全部报
`bad record MAC` / `DECRYPTION_FAILED_OR_BAD_RECORD_MAC`。

原因（TLS 1.3 RFC 8446 §4.4）：

    Transcript-Hash(ClientHello) 参与 key_schedule 的每一步派生

- 服务端：用**改写后的** ClientHello 算 transcript
- 客户端：用**自己发出去的原始** ClientHello 算 transcript
- 两边 transcript hash 不同 → `client_handshake_traffic_secret` 不同 → 所有应用数据 MAC 全错

TLS 1.2 时代这条路勉强能走（PRF 只用 random + 手工算 master secret），
TLS 1.3 下行不通。B站/小红书/知乎现在全走 TLS 1.3。

## 两个可行方案

### 方案 A：本地 MITM 代理（需要装根证书）

代理自己跟两边分别握手：

    浏览器 --[TLS, SNI=www.bilibili.com]--> 代理
    代理   --[TCP, 目标IP]--> 真的 www.bilibili.com
    代理   --[TLS, SNI=www.baidu.com, 相同的目标IP]--> 目标

- 代理对浏览器出示自己签的证书（由本地根 CA 签发，SAN 含 `*.bilibili.com`）
- 代理对目标出示真实 ClientHello（但 SNI 得是假值，否则被 RST）
- 中间明文转发（HTTP 层）

**问题：** 代理跟目标的握手，SNI 还得是假的。所以仍需 `InsecureSkipVerify`
+ 手工 `VerifyHostname`。这一步在 Go 里做得到：

    cfg := &tls.Config{ServerName: "www.baidu.com", InsecureSkipVerify: true}
    // 握手后：
    leaf := conn.ConnectionState().PeerCertificates[0]
    if err := leaf.VerifyHostname("www.bilibili.com"); err != nil { reject }

**代价：** 浏览器/系统要装本地根证书。App 做起来要给用户一键装证书。

### 方案 B：SNI 分片 / 域前置

**B1. TLS record 分片（最轻，不用证书、不用服务器）**

把 ClientHello 拆成多个 TLS record 发送，让 SNI 字符串跨 record 边界。
学校的 RST 设备多数只解析单个 record 里的 SNI：

    record1: [type=0x16][ver][len=小] + 前 N 字节 hello（切断 SNI 字符串中间）
    record2: [type=0x16][ver][len=剩余] + 剩余字节

服务端会把多个 record 拼起来还原完整 handshake，客户端也用同一份字节算
transcript —— **transcript hash 完全一致，不会有 MAC 错。**

这条路是真正对症的：客户端原始字节不变，只是发送方式被拆散。

**B2. 域前置（Domain Fronting）**

用一个大站的 SNI（如 `www.baidu.com`）+ B站的 IP。**不行**，
服务端按 SNI 选虚拟主机，会返回百度的证书和内容，拿不到 B站数据。
除非目标站点在同一 CDN 后面且 CDN 按 Host 头分流（B站 CDN 不满足）。

## 结论

1. 本地「纯改写 SNI 字节」方案在 TLS 1.3 下**数学上不成立**，已经实测确认。
2. **B1 分片**是唯一不用服务器、不用证书的路子 —— 下一步实现。
3. 如果目标改成按 IP 封（不只是 SNI），分片也没用，那时才需要国内中转服务器。
