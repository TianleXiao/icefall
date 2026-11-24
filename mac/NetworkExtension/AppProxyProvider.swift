//
//  AppProxyProvider.swift
//  Icefall 的 macOS 透明代理扩展
//
//  为什么选 NEAppProxyProvider 而不是 NEPacketTunnelProvider：
//    PacketTunnel 拿到的是裸 IP 包，必须自带用户态 TCP/IP 栈（gVisor 之类）才能
//    把 TCP 重新接起来 —— 那正是 Windows 版 TUN 卡住的地方。
//    AppProxy 拿到的是已经组装好的 flow（host + port + 字节流），
//    直接连本地碎冰的 SOCKS5 就行，一个栈都不用。
//
//  代价：只能拦截显式加入 VPN 的 App，不能像 TUN 那样接管整机。
//  对「微信客户端里看视频号」这种场景刚好够用。
//

import NetworkExtension

final class AppProxyProvider: NEAppProxyProvider {

    private let proxyHost = "127.0.0.1"
    private let proxyPort: UInt16 = 8899

    override func startProxy(options: [String: Any]? = nil,
                            completionHandler: @escaping (Error?) -> Void) {
        // 扩展跑在独立进程里，127.0.0.1 指向宿主机，符合预期。
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // UDP：视频号/游戏/串流大量走 UDP，但碎冰目前不实现 UDP ASSOCIATE，
        // 直接拒掉，让系统把它交给直连（不接管），而不是静默丢包。
        guard let tcp = flow as? NEAppProxyTCPFlow else {
            return false
        }

        guard let endpoint = tcp.remoteEndpoint as? NWHostEndpoint else {
            return false
        }
        let host = endpoint.hostname
        let port = UInt16(endpoint.port) ?? 443

        let socks = Socks5Connection(host: host, port: port,
                                     proxyHost: proxyHost, proxyPort: proxyPort)

        socks.open { [weak self] result in
            switch result {
            case .failure:
                tcp.closeWrite(withError: nil)
                tcp.closeRead(withError: nil)
            case .success:
                self?.pump(tcp: tcp, socks: socks)
            }
        }
        return true
    }

    /// 双向搬运：App → SOCKS5，SOCKS5 → App。
    private func pump(tcp: NEAppProxyTCPFlow, socks: Socks5Connection) {
        // App 侧读
        func readApp() {
            tcp.readData { data, error in
                if let error {
                    socks.cancel()
                    tcp.closeWrite(withError: error)
                    return
                }
                guard let data, !data.isEmpty else {
                    tcp.closeWrite(withError: nil)
                    socks.cancel()
                    return
                }
                socks.send(data) { err in
                    if let err {
                        tcp.closeRead(withError: err)
                        socks.cancel()
                        return
                    }
                    readApp()
                }
            }
        }

        // 网络侧读
        socks.readLoop({ data in
            tcp.write(data) { err in
                if let err { tcp.closeRead(withError: err) }
            }
        }, onEnd: { err in
            tcp.closeRead(withError: err)
        })

        readApp()
    }
}
