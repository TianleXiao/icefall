//
//  TunnelInstaller.swift
//  主 App 侧：把扩展装进「系统设置 → 隐私与安全性 → 网络」并启动。
//
//  这一段放主 App（不是扩展）里。扩展本身只负责搬字节，配置由主 App 创建。
//

import NetworkExtension

enum TunnelInstaller {

    static let bundleID = "com.icefall.proxy.AppProxy"
    static let configName = "Icefall"

    /// 安装（或复用）App Proxy 配置并启动。
    static func installAndStart(completion: @escaping (Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error { return completion(error) }

            let manager = managers?.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == bundleID
            } ?? NETunnelProviderManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = bundleID
            proto.serverAddress = "127.0.0.1:8899"   // 仅用于界面显示
            proto.providerConfiguration = [
                "proxyHost": "127.0.0.1",
                "proxyPort": 8899,
            ]
            manager.protocolConfiguration = proto
            manager.localizedDescription = configName
            manager.isEnabled = true

            manager.saveToPreferences { error in
                if let error { return completion(error) }
                // 保存后必须重新 load，否则 startVPNTunnel 会拿到旧对象
                manager.loadFromPreferences { error in
                    if let error { return completion(error) }
                    do {
                        try manager.connection.startVPNTunnel()
                        completion(nil)
                    } catch {
                        completion(error)
                    }
                }
            }
        }
    }

    /// 停止并移除配置。
    static func uninstall(completion: @escaping (Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error { return completion(error) }
            let our = (managers ?? []).filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == bundleID
            }
            guard !our.isEmpty else { return completion(nil) }
            for m in our {
                m.connection.stopVPNTunnel()
                m.removeFromPreferences { _ in }
            }
            completion(nil)
        }
    }
}
