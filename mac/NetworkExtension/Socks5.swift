//
//  Socks5.swift
//  Icefall AppProxy 扩展用的最小 SOCKS5 客户端
//
//  只做两件事：CONNECT 握手、把两边的字节互相抄。
//  分片逻辑在 icefall 本体里，这里只管转发 —— 所以扩展不需要用户态 TCP/IP 栈。
//

import Foundation
import Network

enum Socks5Error: Error {
    case handshake(String)
    case refused
}

/// 连到本地碎冰代理（默认 127.0.0.1:8899）并请求打洞到 host:port。
final class Socks5Connection {
    private let conn: NWConnection
    private let queue: DispatchQueue
    private var buffer = Data()

    init(host: String, port: UInt16, proxyHost: String = "127.0.0.1", proxyPort: UInt16 = 8899) {
        let p = NWParameters.tcp
        p.allowLocalEndpointReuse = true
        conn = NWConnection(host: NWEndpoint.Host(proxyHost),
                            port: NWEndpoint.Port(rawValue: proxyPort)!,
                            using: p)
        queue = DispatchQueue(label: "icefall.socks5.\(host):\(port)")
        self.targetHost = host
        self.targetPort = port
    }

    private let targetHost: String
    private let targetPort: UInt16

    /// 建立到目标的 SOCKS5 隧道。成功后才允许读写。
    func open(completion: @escaping (Result<Void, Error>) -> Void) {
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.performHandshake(completion: completion)
            case .failed(let e), .waiting(let e):
                completion(.failure(Socks5Error.handshake("connect: \(e)")))
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func performHandshake(completion: @escaping (Result<Void, Error>) -> Void) {
        // 1) 问候：VER=5, NMETHODS=1, METHOD=0（无认证）
        send(Data([0x05, 0x01, 0x00])) { [weak self] err in
            guard let self else { return }
            if let err { return completion(.failure(err)) }
            self.recv(exactly: 2) { r in
                switch r {
                case .failure(let e):
                    completion(.failure(e))
                case .success(let b):
                    guard b[0] == 0x05, b[1] == 0x00 else {
                        return completion(.failure(Socks5Error.handshake("no acceptable auth: \(b as NSData)")))
                    }
                    self.sendRequest(completion: completion)
                }
            }
        }
    }

    private func sendRequest(completion: @escaping (Result<Void, Error>) -> Void) {
        var req = Data([0x05, 0x01, 0x00])   // VER, CMD=CONNECT, RSV
        let hostBytes = Array(targetHost.utf8)
        if hostBytes.count > 255 {
            return completion(.failure(Socks5Error.handshake("hostname too long")))
        }
        req.append(0x03)                    // ATYP=域名（让代理自己解析，避免扩展里做 DNS）
        req.append(UInt8(hostBytes.count))
        req.append(contentsOf: hostBytes)
        req.append(UInt8(targetPort >> 8))
        req.append(UInt8(targetPort & 0xff))

        send(req) { [weak self] err in
            guard let self else { return }
            if let err { return completion(.failure(err)) }
            self.recv(exactly: 4) { r in
                switch r {
                case .failure(let e):
                    completion(.failure(e))
                case .success(let head):
                    guard head[0] == 0x05, head[1] == 0x00 else {
                        return completion(.failure(Socks5Error.refused))
                    }
                    // 跳过 BND.ADDR + BND.PORT
                    let skip: Int
                    switch head[3] {
                    case 0x01: skip = 4 + 2
                    case 0x04: skip = 16 + 2
                    case 0x03: skip = 0   // 需要先读长度字节
                    default: return completion(.failure(Socks5Error.handshake("bad atyp")))
                    }
                    if skip > 0 {
                        self.recv(exactly: skip) { _ in completion(.success(())) }
                    } else {
                        self.recv(exactly: 1) { r2 in
                            guard case .success(let l) = r2 else { return completion(.failure(Socks5Error.handshake("bnd"))) }
                            self.recv(exactly: Int(l[0]) + 2) { _ in completion(.success(())) }
                        }
                    }
                }
            }
        }
    }

    // MARK: - 原始收发

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        conn.send(content: data, completion: .contentProcessed { completion($0) })
    }

    func recv(exactly n: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        conn.receive(minimumIncompleteLength: n, maximumLength: n) { [weak self] data, _, isComplete, error in
            if let error { return completion(.failure(error)) }
            guard let data, data.count == n else {
                return completion(.failure(Socks5Error.handshake("closed during handshake")))
            }
            _ = self
            completion(.success(data))
        }
    }

    /// 把 SOCKS5 隧道里的数据源源不断读出来交给上层。
    func readLoop(_ onData: @escaping (Data) -> Void, onEnd: @escaping (Error?) -> Void) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty { onData(data) }
            if let error { return onEnd(error) }
            if isComplete { return onEnd(nil) }
            self?.readLoop(onData, onEnd: onEnd)
        }
    }

    func cancel() { conn.cancel() }
}
