//go:build windows

package main

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// ipUnicastIf 是 Windows 的 IP_UNICAST_IF 套接字选项（31）。
// TUN 一挂上，0.0.0.0/1 路由会吃掉所有出站流量；本程序自己去连目标时
// 如果也走 TUN，就会「读自己的包 → 再连 → 再读」无限递归。
// 用这个选项把套接字钉在物理网卡上，绕过路由表选择。
const ipUnicastIf = 31

// bypassIf 是物理网卡索引，runTun 启动时填。
var bypassIf uint32

func bindControl(network, address string, c syscall.RawConn) error {
	idx := atomic.LoadUint32(&bypassIf)
	if idx == 0 {
		return nil
	}
	// 到回环/本机的连接不能钉网卡，否则 127.0.0.1:7897 这类上游直接连不上。
	if host, _, err := net.SplitHostPort(address); err == nil {
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		// 文档要求网络字节序：把索引按大端塞进一个 uint32 再交给内核
		b := [4]byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24)}
		v := int(binary.BigEndian.Uint32(b[:]))
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, v)
	}); err != nil {
		return err
	}
	return serr
}

// newDialer 返回带 bindControl 的拨号器。所有真正出网的代码都该用它。
func newDialer(d time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: d, Control: bindControl}
}
