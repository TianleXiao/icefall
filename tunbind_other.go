//go:build !windows

package main

import (
	"net"
	"syscall"
	"time"
)

// 非 Windows 平台没有 IP_UNICAST_IF 这套东西（macOS 用 NetworkExtension 或系统代理）。
// 这里留空实现，保证同一份代码能交叉编译。
func bindControl(network, address string, c syscall.RawConn) error {
	return nil
}

func newDialer(d time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: d, Control: bindControl}
}
