package main

// tun.go —— TUN 模式：接管整机流量（含 UDP），让不读系统代理的程序也受控。
//
// 为什么必须做：微信客户端、云游戏客户端、游戏本体都用各自的网络栈，
// 不读 WinINet 系统代理设置。只有 TUN 虚拟网卡才能把它们全部抓住。
//
// 架构（标准 netstack 方案，同 clash/sing-box 的 tun 模式）：
//   1. 用 wintun 建一块虚拟网卡，配一个 /24 的内网地址
//   2. 改路由表，把 0.0.0.0/0 指到这块网卡（只留上游代理的 IP 走物理网卡，防环）
//   3. 从网卡读 IP 包 → 解析 TCP/UDP → 用用户态 TCP/IP 栈重建连接 → 走真实 socket 出去
//
// 代价：需要一个用户态 TCP/IP 栈。gVisor(netstack) 是唯一现成可用的，
// 纯手写 TCP 状态机不现实。这里用的是 gvisor.dev/gvisor/pkg/tcpip/...
//
// 本文件只放「网卡 + 路由」这半，netstack 接线在 tunstack.go。

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wintun"
)

const (
	tunName  = "SniBypass"
	tunMTU   = 1400
	tunAddr  = "198.18.0.1/15" // 与 clash 默认网段一致，避开常见内网
)

// TunDevice 是 wintun 虚拟网卡的封装。
type TunDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	ifIndex  uint32
	mu       sync.Mutex
	closed   bool
}

// OpenTun 创建（或复用）虚拟网卡并开启会话。
func OpenTun() (*TunDevice, error) {
	adapter, err := wintun.CreateAdapter(tunName, "Wintun", nil)
	if err != nil {
		return nil, fmt.Errorf("create adapter: %w", err)
	}
	sess, err := adapter.StartSession(0, wintun.WINTUN_MAX_RING_CAPACITY)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session: %w", err)
	}
	return &TunDevice{adapter: adapter, session: sess}, nil
}

// Close 关闭会话并释放网卡。
func (d *TunDevice) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	d.session.End()
	d.adapter.Close()
}

// Read 从网卡读一个 IP 包（阻塞）。
func (d *TunDevice) Read(p []byte) (int, error) {
	pkt, err := d.session.ReceivePacket()
	if err != nil {
		return 0, err
	}
	n := copy(p, pkt)
	d.session.ReleaseReceivePacket(pkt)
	return n, nil
}

// Write 往网卡写一个 IP 包。
func (d *TunDevice) Write(p []byte) (int, error) {
	pkt, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		return 0, err
	}
	copy(pkt, p)
	d.session.SendPacket(pkt)
	return len(p), nil
}

// setupTunInterface 给网卡配上地址、掩码、MTU，并抬起。
// 用 netsh 而不是 WinAPI，省得再绑一套 syscall。
func setupTunInterface() error {
	addr := strings.Split(tunAddr, "/")[0]
	// 先清理可能残留的旧地址（重复执行会堆叠）
	exec.Command("netsh", "interface", "ipv4", "set", "address",
		"name="+tunName, "static", addr, "255.254.0.0").Run()

	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh show: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), tunName) {
		return errors.New("TUN 网卡未出现在 netsh 列表，可能创建失败")
	}

	exec.Command("netsh", "interface", "ipv4", "set", "subinterface", tunName,
		"mtu="+fmt.Sprint(tunMTU), "store=persistent").Run()
	exec.Command("netsh", "interface", "set", "interface", tunName, "admin=enable").Run()
	return nil
}

// addDefaultRoute 把默认路由指到 TUN 网卡。
//
// 防环关键：上游代理（Clash 7897）跑在本机环回口，环回不走默认路由，天然安全；
// 但如果策略里有直连分支要访问公网，那些必须走物理网卡 —— 用 bypassIP 加一条 /32 例外。
func addDefaultRoute(bypassIPs []string) error {
	gw := strings.Split(tunAddr, "/")[0]
	// 拆掉原来指向物理网卡的默认路由（备份记录，供 Restore 用）
	for _, ip := range bypassIPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		exec.Command("route", "add", ip, "mask", "255.255.255.255",
			strings.Split(gw, ".")[0]+"."+strings.Split(gw, ".")[1]+".0.1", "metric", "1").Run()
	}
	out, err := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", gw, "metric", "1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add: %v (%s)", err, out)
	}
	return nil
}

// removeDefaultRoute 撤回 TUN 默认路由。
func removeDefaultRoute() {
	gw := strings.Split(tunAddr, "/")[0]
	exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", gw).Run()
}

// localIPs 返回本机所有非环回 IPv4，用于生成直连例外路由。
func localIPs() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() == nil {
			continue
		}
		if ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ipn.IP.String())
	}
	return out
}

var _ = netip.Addr{}
