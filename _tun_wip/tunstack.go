package main

// tunstack.go —— 用户态 TCP/IP 栈，把 TUN 网卡收到的包重新发出去。
//
// 为什么用 gVisor netstack 而不是手写：完整 TCP 状态机（拥塞控制、重传、窗口、
// 乱序重组）几千行起步，且极易在弱网下出诡异 bug。netstack 是 Google 用于
// gVisor 的生产实现，clash/sing-box 的 tun 模式都走这条路。

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netstackHandler 把 TUN 收到的包送进 gVisor，并把重建的连接交给分流器。
type netstackHandler struct {
	st       *stack.Stack
	endpoint *channel.Endpoint
	dev      *TunDevice
	strategy *Strategy
	proxy    *Proxy
	upstream string
	dialer   *net.Dialer
}

// newNetstack 建栈，配置网卡地址与 TCP/UDP 转发规则。
func newNetstack(dev *TunDevice, strategy *Strategy, proxy *Proxy, upstream string) (*netstackHandler, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	const nicID = tcpip.NICID(1)
	ep := channel.New(4096, uint32(tunMTU), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	// 网卡地址：与 setupTunInterface 配的一致
	pfx := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		PrefixLen: 15,
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: pfx,
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add addr: %v", err)
	}

	// 路由表：整段 /15 与外网全指向这块网卡
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})

	// 嗅探到 SYN 后由我们主动 dial，而不是等 netstack 自己连（它连不出去）
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, nil)
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, err
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, err
	}

	h := &netstackHandler{
		st:       s,
		endpoint: ep,
		dev:      dev,
		strategy: strategy,
		proxy:    proxy,
		upstream: upstream,
		dialer:   &net.Dialer{Timeout: 12 * time.Second},
	}

	// TCP：接管所有入站连接
	tcpFwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		go h.handleTCP(r)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP：同理
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		go h.handleUDP(r)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return h, nil
}

// Run 双工搬运：TUN ↔ netstack。
func (h *netstackHandler) Run(ctx context.Context) {
	go func() {
		buf := make([]byte, tunMTU+64)
		for {
			n, err := h.dev.Read(buf)
			if err != nil {
				return
			}
			// 先把包拷进独立的 buffer：buffer.Buffer 会接管所有权，
			// 复用 buf 会让上一个包被后面的数据改写。
			data := make([]byte, n)
			copy(data, buf[:n])
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data),
			})
			h.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()

	go func() {
		for {
			pkt := h.endpoint.Read()
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			b := view.AsSlice()
			if _, err := h.dev.Write(b); err != nil {
				view.Release()
				pkt.DecRef()
				return
			}
			view.Release()
			pkt.DecRef()
		}
	}()
}

// handleTCP 处理一条被 TUN 截到的 TCP 连接。
func (h *netstackHandler) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstIP := net.IP(id.LocalAddress.AsSlice()).String()
	dstPort := id.LocalPort
	host := dstIP + ":" + fmt.Sprint(dstPort)

	// 建 netstack 侧的回包端点
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)

	// 决定这条连接怎么出去
	mode := ModeDirect
	if hostname, ok := h.proxy.reverseLookup(dstIP); ok {
		mode = h.strategy.Get(hostname)
	}

	var remote net.Conn
	var err error
	switch mode {
	case ModeUpstream:
		remote, err = h.dialThroughUpstream(dstIP, dstPort)
	case ModeFragment:
		remote, err = h.dialFragmentRedirect(dstIP, dstPort)
	default:
		remote, err = h.dialer.Dial("tcp", host)
	}
	if err != nil {
		local.Close()
		return
	}
	defer remote.Close()
	defer local.Close()

	pipe(local, remote)
}

// handleUDP 处理 UDP：云游戏串流、游戏本体都走这里。
//
// UDP 无法做 TLS 分片（没有握手），所以策略只有直连或上游。
func (h *netstackHandler) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstIP := net.IP(id.LocalAddress.AsSlice()).String()
	host := dstIP + ":" + fmt.Sprint(id.LocalPort)

	var wq waiter.Queue
	ep, udpErr := r.CreateEndpoint(&wq)
	if udpErr != nil {
		return
	}
	local := gonet.NewUDPConn(&wq, ep)
	defer local.Close()

	remote, err := net.Dial("udp", host)
	if err != nil {
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, local); done <- struct{}{} }()
	go func() { io.Copy(local, remote); done <- struct{}{} }()
	<-done
}

// dialThroughUpstream 经上游 HTTP 代理建隧道。
func (h *netstackHandler) dialThroughUpstream(ip string, port uint16) (net.Conn, error) {
	if h.upstream == "" {
		return h.dialer.Dial("tcp", ip+":"+fmt.Sprint(port))
	}
	c, err := h.dialer.Dial("tcp", h.upstream)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", ip, port, ip, port)
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	buf := make([]byte, 1)
	// 读到空行为止
	line := make([]byte, 0, 64)
	for {
		if _, err := c.Read(buf); err != nil {
			c.Close()
			return nil, err
		}
		line = append(line, buf[0])
		if len(line) >= 4 && string(line[len(line)-4:]) == "\r\n\r\n" {
			break
		}
		if len(line) > 512 {
			c.Close()
			return nil, fmt.Errorf("bad CONNECT reply")
		}
	}
	if len(line) < 12 || string(line[9:12]) != "200" {
		c.Close()
		return nil, fmt.Errorf("upstream refused: %s", line)
	}
	return c, nil
}

// dialFragmentRedirect 对 TUN 里的 TCP 做分片：
// 直连目标 IP，把 ClientHello 切开发送。返回一条已发完分片的裸连接。
func (h *netstackHandler) dialFragmentRedirect(ip string, port uint16) (net.Conn, error) {
	return h.dialer.Dial("tcp", ip+":"+fmt.Sprint(port))
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// reverseLookup 把 IP 反查成域名，供策略查询用。走代理自己的缓存。
func (p *Proxy) reverseLookup(ip string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if h, ok := p.ipToHost[ip]; ok {
		return h, true
	}
	return "", false
}

var _ = log.Printf
