package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Proxy 是本地 HTTP CONNECT 代理，对指定域名做 TLS record 分片绕过 SNI 封锁。
//
// 原理（为什么不改写 SNI 字节）：
//   TLS 1.3 里 Transcript-Hash(ClientHello) 参与 key_schedule，
//   改字节会让客户端和服务端的 transcript 不一致 → bad record MAC。
//   分片只改「发送方式」不改「发送内容」，transcript 完全一致。
//
// 做法：
//   读浏览器发的完整 ClientHello（单 record），
//   在 SNI 字符串起点处切成两个 TLS record 再发给目标。
//   检测设备看不到完整 SNI 就不 RST，服务端拼回原样照常握手。
type Proxy struct {
	Addr string
	// Upstream 是兜底上游 HTTP 代理（如 Clash 的 127.0.0.1:7897）；空表示直连
	Upstream string
	// Strategy 是策略表，用来生成 PAC；可为 nil
	Strategy *Strategy

	mu     sync.RWMutex
	rules  map[string]Rule
	dialer *net.Dialer
}

type Rule struct {
	// Fragment 为 true 时对该域名做 record 分片
	Fragment bool
	// Cut 是分片点（相对 handshake body 的字节偏移）；0 表示自动定位 SNI
	Cut int
}

func NewProxy(addr string) *Proxy {
	return &Proxy{
		Addr:   addr,
		rules:  map[string]Rule{},
		dialer: &net.Dialer{Timeout: 10 * time.Second},
	}
}

func (p *Proxy) SetRule(host string, r Rule) {
	p.mu.Lock()
	p.rules[strings.ToLower(host)] = r
	p.mu.Unlock()
}

func (p *Proxy) lookup(host string) (Rule, bool) {
	host = strings.ToLower(host)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if r, ok := p.rules[host]; ok {
		return r, true
	}
	for k, r := range p.rules {
		if strings.HasSuffix(host, "."+k) {
			return r, true
		}
	}
	return Rule{}, false
}

func (p *Proxy) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return err
	}
	logf("proxy listening on %s", p.Addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handle(c)
	}
}

func (p *Proxy) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)
	// SOCKS5 与 HTTP 共用端口：SOCKS 首字节固定 0x05，HTTP 方法都是 ASCII。
	if b, err := br.Peek(1); err == nil && b[0] == 0x05 {
		p.handleSocks(conn, br)
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	// PAC 下发：系统代理设成 http://<addr>/proxy.pac 时会来这里取
	if req.URL != nil && req.URL.Path == pacURLPath {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		p.servePAC(conn, req)
		return
	}

	if req.Method != http.MethodConnect {
		p.handlePlainHTTP(conn, br, req)
		return
	}

	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, port = req.Host, "443"
	}

	rule, hit := p.lookup(host)
	if !hit || !rule.Fragment {
		// 不在分片名单：有兜底上游就整条隧道转给上游（Clash），
		// 没有就直连。这样别人机器上不装 Clash 也能用。
		if p.Upstream != "" {
			p.handleUpstream(conn, br, req)
			return
		}
		target, err := p.dialer.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			logf("CONNECT %s:%s  dial fail: %v", host, port, err)
			return
		}
		defer target.Close()
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		logf("CONNECT %s  direct", host)
		conn.SetDeadline(time.Time{})
		target.SetDeadline(time.Time{})
		tunnel(conn, target)
		return
	}

	fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	logf("CONNECT %s  fragment", host)
	if err := p.fragmentTunnel(conn, br, host, port); err != nil {
		logf("CONNECT %s  %v", host, err)
	}
}

func (p *Proxy) handlePlainHTTP(conn net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	target, err := p.dialer.Dial("tcp", host)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer target.Close()

	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = req.Host
	if err := req.Write(target); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	target.SetDeadline(time.Time{})
	tunnel(conn, target)
}

func tunnel(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// readClientHello 读出完整 ClientHello。
//
// 注意：ClientHello 可能被拆成多个 TLS record 发送（OpenSSL 在扩展多时会这样）。
// 必须先按 handshake 头的 3 字节长度读到完整握手消息，不能只读第一个 record，
// 否则分片后 transcript 错乱 → 服务器直接关连接。
func readClientHello(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x16 {
		return nil, fmt.Errorf("not TLS handshake, type=0x%02x", hdr[0])
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	if len(body) < 4 {
		return append(hdr, body...), nil
	}
	// handshake 消息总长（含 4 字节头）
	hsTotal := 4 + int(body[1])<<16 + int(body[2])<<8 + int(body[3])
	if hsTotal <= len(body) {
		return append(hdr, body...), nil
	}

	// 需要继续从后续 record 里取字节，拼成完整握手消息
	rest := hsTotal - len(body)
	var tail []byte
	for rest > 0 {
		rh := make([]byte, 5)
		if _, err := io.ReadFull(br, rh); err != nil {
			return nil, err
		}
		if rh[0] != 0x16 {
			return nil, fmt.Errorf("interleaved record type=0x%02x", rh[0])
		}
		rn := int(rh[3])<<8 | int(rh[4])
		if rn > rest {
			rn = rest
		}
		chunk := make([]byte, rn)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, err
		}
		tail = append(tail, chunk...)
		rest -= rn
	}
	return append(append(hdr, body...), tail...), nil
}

func logf(format string, a ...any) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}

var _ = os.Stdout
// handleUpstream 把整条 CONNECT 隧道转给上游 HTTP 代理（Clash）。
//
// 这样本工具只接管被封域名，其余流量照旧走 Clash，
// 境外站、GitHub 等原有能力不受影响。
func (p *Proxy) handleUpstream(conn net.Conn, br *bufio.Reader, req *http.Request) {
	up, err := p.dialer.Dial("tcp", p.Upstream)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		logf("CONNECT %s  upstream dial fail: %v", req.Host, err)
		return
	}
	defer up.Close()

	// 把原始 CONNECT 请求原样转述给上游
	if err := req.Write(up); err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	ubr := bufio.NewReader(up)
	resp, err := http.ReadResponse(ubr, req)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		logf("CONNECT %s  upstream resp fail: %v", req.Host, err)
		return
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		logf("CONNECT %s  upstream refused %d", req.Host, resp.StatusCode)
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	logf("CONNECT %s  -> upstream %s", req.Host, p.Upstream)

	conn.SetDeadline(time.Time{})
	up.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, ubr); done <- struct{}{} }()
	<-done
}

// fragmentTunnel 在已经向客户端回复「成功」之后调用。
//
// 分片点用「记录内绝对偏移」表示，fragmentHello 内部减 5 换算成 handshake body 偏移。
// 单切点不可靠：实测 B站 www 是名字起点 +4~+15 有效，bilivideo CDN 是 +16~+25 有效，
// 检测器规则不透明且随站变化。所以按候选列表逐个试：
// 每次新建一条到目标的 TCP，发一个候选切点，等服务器首个响应——
// 收到 TLS record 说明握手被接受，立刻把这条连接交给客户端；
// RST/无响应就换下一个切点。
func (p *Proxy) fragmentTunnel(conn net.Conn, br *bufio.Reader, host, port string) error {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	hello, err := readClientHello(br)
	if err != nil {
		return fmt.Errorf("read hello fail: %w", err)
	}

	rule, hit := p.lookup(host)
	var cands []int
	if hit && rule.Cut > 0 {
		cands = []int{rule.Cut}
	} else {
		cands = cutCandidates(hello)
	}
	if len(cands) == 0 {
		cands = []int{len(hello) / 2}
	}

	var good net.Conn
	for i, c := range cands {
		if c <= 5 || c >= len(hello)-5 {
			continue
		}
		tc, err := p.dialer.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			continue
		}
		tc.SetDeadline(time.Now().Add(6 * time.Second))
		payload := fragmentHello(hello, c-5)
		if _, err := tc.Write(payload); err != nil {
			tc.Close()
			continue
		}
		hdr := make([]byte, 5)
		n, err := io.ReadFull(tc, hdr)
		if err != nil || n < 5 {
			tc.Close()
			logf("  cut=%-4d RST/EOF", c)
			continue
		}
		if hdr[0] == 0x15 {
			tc.Close()
			logf("  cut=%-4d ALERT", c)
			continue
		}
		if hdr[0] != 0x16 {
			tc.Close()
			logf("  cut=%-4d unexpected type=0x%02x", c, hdr[0])
			continue
		}
		good = tc
		conn.Write(hdr)
		logf("  fragment@%d OK  (try %d/%d)  %d->%d bytes  2 records",
			c, i+1, len(cands), len(hello), len(payload))
		break
	}
	if good == nil {
		return fmt.Errorf("all %d cuts failed", len(cands))
	}
	defer good.Close()
	good.SetDeadline(time.Time{})
	conn.SetDeadline(time.Time{})
	tunnel(conn, good)
	return nil
}
