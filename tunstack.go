package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// 用户态 TCP/IP 栈。
//
// 为什么自己写：gVisor 那个快照在 Go 1.27 下编译不过（pkg/sync 缺 codegen 产物），
// 而 TUN 只需要「把 TCP 流转成 net.Conn、把 UDP 流转成 UDP socket」这一件事。
// 不做分片重组、不做 SACK、不做拥塞控制：够用就行。

const (
	stSynRcvd = iota
	stEst
	stClosing
	stClosed
)

const (
	tunWindow   = 65535
	tunMTU      = 1400
	tunRexmitMs = 800
)

var errStClosed = errors.New("tun conn closed")

type connKey struct {
	cIP   [4]byte
	cPort uint16
	sIP   [4]byte
	sPort uint16
}

func (k connKey) host() string {
	return net.IPv4(k.sIP[0], k.sIP[1], k.sIP[2], k.sIP[3]).String()
}

// tunRoute 决定一条连接该走哪条路（分片 / 直连 / 上游），由 tunmode.go 提供。
// 返回值 sent 表示 hello 已经被这条路自己发出去了，栈不用再写。
type tunRoute func(sip [4]byte, sport int, sni string, hello []byte) (conn net.Conn, sent bool, err error)

type outSeg struct {
	seq   uint32
	flags byte
	data  []byte
	at    time.Time
}

type Stack struct {
	mu    sync.Mutex
	conns map[connKey]*tcpConn
	udp   map[connKey]*udpFlow
	write func([]byte)
	route tunRoute
	udpD  func(ip string, port int) (net.Conn, error)
}

func NewStack(write func([]byte), route tunRoute, udpDial func(string, int) (net.Conn, error)) *Stack {
	return &Stack{
		conns: map[connKey]*tcpConn{},
		udp:   map[connKey]*udpFlow{},
		write: write,
		route: route,
		udpD:  udpDial,
	}
}

// Handle 处理一个从 TUN 读到的 IPv4 包。
func (st *Stack) Handle(pkt []byte) {
	p, ok := parseIP4(pkt)
	if !ok || p.Frag {
		return
	}
	switch p.Proto {
	case ipProtoTCP:
		if seg, ok := parseTCP(p.Payload); ok {
			st.handleTCP(p, seg)
		}
	case ipProtoUDP:
		if sp, dp, pl, ok := parseUDPPorts(p.Payload); ok {
			st.handleUDP(p, sp, dp, pl)
		}
	}
}

func (st *Stack) handleTCP(p ip4, h tcpSeg) {
	key := connKey{cIP: p.Src, cPort: h.SrcPort, sIP: p.Dst, sPort: h.DstPort}

	st.mu.Lock()
	c := st.conns[key]
	st.mu.Unlock()

	if h.Flags&tcpRST != 0 {
		if c != nil {
			c.kill()
		}
		return
	}

	if c == nil {
		if h.Flags&tcpSYN == 0 {
			// 不认识又没有 SYN：直接 RST，让客户端立刻失败，别干等重传
			st.write(buildTCP(p.Dst, p.Src, h.DstPort, h.SrcPort, h.Ack, 0, tcpRST|tcpACK, 0, nil))
			return
		}
		c = st.newConn(key, h)
		st.mu.Lock()
		st.conns[key] = c
		st.mu.Unlock()
		go c.rexmitLoop()
		return
	}
	c.onSegment(h)
}

func (st *Stack) newConn(key connKey, h tcpSeg) *tcpConn {
	c := &tcpConn{
		st:      st,
		key:     key,
		state:   stSynRcvd,
		rcvNxt:  h.Seq + 1,
		sndNxt:  uint32(time.Now().UnixNano()),
		peerWnd: uint32(h.Window),
		mss:     tunMTU - 40,
	}
	if c.peerWnd == 0 {
		c.peerWnd = 4096
	}
	if c.peerWnd > tunWindow {
		c.peerWnd = tunWindow
	}
	c.send(tcpSYN|tcpACK, nil)
	return c
}

// send 构造并发出一个分段，同时记住未确认的部分用于重传。
func (c *tcpConn) send(flags byte, payload []byte) {
	seq := c.sndNxt
	c.st.write(buildTCP(c.key.sIP, c.key.cIP, c.key.sPort, c.key.cPort, seq, c.rcvNxt, flags, tunWindow, payload))
	adv := len(payload)
	if flags&tcpSYN != 0 {
		adv++
	}
	if flags&tcpFIN != 0 {
		adv++
	}
	if adv == 0 {
		return
	}
	c.sndNxt = seq + uint32(adv)
	if flags&tcpRST == 0 {
		c.unacked = append(c.unacked, outSeg{seq: seq, flags: flags, data: append([]byte(nil), payload...), at: time.Now()})
	}
}

func (c *tcpConn) onSegment(h tcpSeg) {
	c.mu.Lock()
	if c.state == stClosed {
		c.mu.Unlock()
		return
	}
	if h.Flags&tcpACK != 0 {
		if int32(h.Ack-c.sndUna) > 0 {
			c.sndUna = h.Ack
			c.trimUnacked()
		}
		if h.Window > 0 {
			c.peerWnd = uint32(h.Window)
		}
		if c.state == stSynRcvd {
			c.state = stEst
		}
	}
	if len(h.Payload) > 0 {
		switch {
		case h.Seq == c.rcvNxt:
			c.rcvNxt += uint32(len(h.Payload))
			if c.backend != nil {
				c.backend.Write(h.Payload)
			} else {
				c.pending = append(c.pending, h.Payload...)
			}
			c.send(tcpACK, nil)
		default:
			// 乱序或重传：回一个当前 ACK，让对端自己纠正。不做重组。
			c.send(tcpACK, nil)
		}
	}
	fin := h.Flags&tcpFIN != 0
	c.mu.Unlock()

	if fin {
		c.onClientFin()
		return
	}
	c.maybeRoute()
}

func (c *tcpConn) onClientFin() {
	c.mu.Lock()
	if c.state == stClosed {
		c.mu.Unlock()
		return
	}
	c.rcvNxt++
	c.send(tcpACK, nil)
	be := c.backend
	c.mu.Unlock()
	if be != nil {
		if cw, ok := be.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			be.Close()
		}
	}
}

// maybeRoute 在拿到第一批客户端数据后决定后端怎么连。
// 关键点：TUN 里只有 IP，但第一段数据里就带 SNI，所以这里能拿到域名并按策略分流。
func (c *tcpConn) maybeRoute() {
	c.mu.Lock()
	if c.backend != nil || c.routing || len(c.pending) == 0 {
		c.mu.Unlock()
		return
	}
	data := append([]byte(nil), c.pending...)
	c.routing = true
	c.prepared = len(c.pending)
	c.mu.Unlock()

	sni := ""
	if len(data) > 5 && data[0] == 0x16 {
		if n, ok := ParseClientHelloSNI(data); ok {
			sni = n
		} else if len(data) < 600 {
			// TLS 但 hello 还没收全，等下一段
			c.mu.Lock()
			c.routing = false
			c.mu.Unlock()
			return
		}
	}

	go func() {
		conn, sent, err := c.st.route(c.key.sIP, int(c.key.sPort), sni, data)
		c.mu.Lock()
		c.routing = false
		if err != nil {
			c.send(tcpRST|tcpACK, nil)
			c.state = stClosed
			c.mu.Unlock()
			c.st.drop(c.key)
			return
		}
		c.backend = conn
		c.sni = sni
		rest := c.pending
		if sent && c.prepared <= len(rest) {
			rest = rest[c.prepared:]
		}
		c.pending = nil
		c.mu.Unlock()
		if len(rest) > 0 {
			conn.Write(rest)
		}
		go c.pumpUp()
	}()
}

// pumpUp 把后端收到的数据切成段发给客户端，遵守对端窗口。
func (c *tcpConn) pumpUp() {
	buf := make([]byte, c.mss)
	for {
		n, err := c.backend.Read(buf)
		if n > 0 {
			c.writeClient(buf[:n])
		}
		if err != nil && err != io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
	c.mu.Lock()
	if c.state != stClosed {
		c.send(tcpFIN|tcpACK, nil)
		c.state = stClosing
	}
	c.mu.Unlock()
}

func (c *tcpConn) writeClient(data []byte) {
	for len(data) > 0 {
		c.mu.Lock()
		if c.state == stClosed {
			c.mu.Unlock()
			return
		}
		inflight := int(c.sndNxt - c.sndUna)
		room := int(c.peerWnd) - inflight
		if room <= 0 {
			c.mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		n := len(data)
		if n > c.mss {
			n = c.mss
		}
		if n > room {
			n = room
		}
		c.send(tcpACK|tcpPSH, data[:n])
		c.mu.Unlock()
		data = data[n:]
	}
}

func (c *tcpConn) trimUnacked() {
	keep := c.unacked[:0]
	for _, s := range c.unacked {
		end := s.seq + uint32(len(s.data))
		if s.flags&tcpSYN != 0 {
			end++
		}
		if s.flags&tcpFIN != 0 {
			end++
		}
		if int32(end-c.sndUna) > 0 {
			keep = append(keep, s)
		}
	}
	c.unacked = keep
}

func (c *tcpConn) rexmitLoop() {
	t := time.NewTicker(tunRexmitMs * time.Millisecond)
	defer t.Stop()
	for range t.C {
		c.mu.Lock()
		if c.state == stClosed {
			c.mu.Unlock()
			return
		}
		for i := range c.unacked {
			if time.Since(c.unacked[i].at) < tunRexmitMs*time.Millisecond {
				continue
			}
			s := &c.unacked[i]
			c.st.write(buildTCP(c.key.sIP, c.key.cIP, c.key.sPort, c.key.cPort, s.seq, c.rcvNxt, s.flags, tunWindow, s.data))
			s.at = time.Now()
		}
		c.mu.Unlock()
	}
}

func (c *tcpConn) kill() {
	c.mu.Lock()
	c.state = stClosed
	be := c.backend
	c.mu.Unlock()
	if be != nil {
		be.Close()
	}
	c.st.drop(c.key)
}

func (st *Stack) drop(k connKey) {
	st.mu.Lock()
	delete(st.conns, k)
	st.mu.Unlock()
}

type udpFlow struct {
	st   *Stack
	key  connKey
	conn net.Conn
}

func (st *Stack) handleUDP(p ip4, sport, dport uint16, payload []byte) {
	key := connKey{cIP: p.Src, cPort: sport, sIP: p.Dst, sPort: dport}
	st.mu.Lock()
	f := st.udp[key]
	if f == nil {
		f = &udpFlow{st: st, key: key}
		st.udp[key] = f
	}
	st.mu.Unlock()
	if f.conn == nil {
		c, err := st.udpD(key.host(), int(dport))
		if err != nil {
			st.mu.Lock()
			delete(st.udp, key)
			st.mu.Unlock()
			logf("TUN UDP %s:%d  建连失败: %v", key.host(), dport, err)
			return
		}
		f.conn = c
		go f.loop()
	}
	f.conn.Write(payload)
}

func (f *udpFlow) loop() {
	buf := make([]byte, 65535)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			break
		}
		f.st.write(buildUDP(f.key.sIP, f.key.cIP, f.key.sPort, f.key.cPort, buf[:n]))
	}
	f.st.mu.Lock()
	delete(f.st.udp, f.key)
	f.st.mu.Unlock()
}

// TCP 的 tcpConn 定义。
type tcpConn struct {
	st  *Stack
	key connKey

	mu       sync.Mutex
	state    int
	backend  net.Conn
	routing  bool
	prepared int

	rcvNxt  uint32
	sndNxt  uint32
	sndUna  uint32
	peerWnd uint32
	mss     int

	pending []byte
	sni     string
	unacked []outSeg
}

func (c *tcpConn) String() string {
	return c.key.host() + ":" + strconv.Itoa(int(c.key.sPort))
}

var _ = binary.BigEndian
