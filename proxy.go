package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
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
	cuts   *cutCache

	// memo 是本次运行的「未收录域名」判定缓存：直连 / 分片 / 上游。
	// 没有它，每个境外未知域名都要吃一次 1.2s 嗅探。
	memoMu sync.RWMutex
	memo   map[string]Mode

	pacMu  sync.Mutex
	pacStr string
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
		cuts:   newCutCache(),
		memo:   map[string]Mode{},
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

	mode, known := p.modeOf(host)
	switch {
	case mode == ModeFragment:
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		logf("CONNECT %s  fragment", host)
		if err := p.fragmentTunnel(conn, br, host, port); err != nil {
			logf("CONNECT %s  %v", host, err)
		}
		return
	case mode == ModeUpstream:
		if p.Upstream != "" {
			p.handleUpstream(conn, br, req)
			return
		}
		// 没配上游：这一档本来是「分片救不了」，只能死马当活马试分片
		fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		logf("CONNECT %s  upstream（未配上游，改试分片）", host)
		if err := p.fragmentTunnel(conn, br, host, port); err != nil {
			logf("CONNECT %s  %v", host, err)
		}
		return
	case known:
		// 明确标了直连：别再绕上游，白加一跳延迟
		p.handleDirect(conn, br, host, port)
		return
	}

	// 表里没有的域名：443 先直连嗅一下，被断了自动学分片，分片不行再甩上游
	if port == "443" {
		p.handleUnknown(conn, br, host, port)
		return
	}
	if p.Upstream != "" {
		p.handleUpstream(conn, br, req)
		return
	}
	p.handleDirect(conn, br, host, port)
}

// modeOf 用一个域名决定怎么走。rules 手工项优先于策略表。
func (p *Proxy) modeOf(host string) (Mode, bool) {
	if r, ok := p.lookup(host); ok {
		if r.Fragment {
			return ModeFragment, true
		}
		return ModeUpstream, true
	}
	if m, ok := p.memoGet(host); ok {
		return m, true
	}
	if p.Strategy != nil {
		return p.Strategy.GetKnown(host)
	}
	return ModeDirect, false
}

func (p *Proxy) memoGet(host string) (Mode, bool) {
	p.memoMu.RLock()
	defer p.memoMu.RUnlock()
	m, ok := p.memo[host]
	return m, ok
}

func (p *Proxy) memoSet(host string, m Mode) {
	p.memoMu.Lock()
	p.memo[host] = m
	p.memoMu.Unlock()
}

// handleDirect 直连，不做任何分片。
func (p *Proxy) handleDirect(conn net.Conn, br *bufio.Reader, host, port string) {
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
	// ReadRequest 之后 br 里可能还压着客户端已经发来的字节，先倒给目标
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		if _, err := target.Write(b); err != nil {
			return
		}
		br.Discard(n)
	}
	tunnel(conn, target)
}

// handleUnknown 处理策略表里没有的 443 域名，三级降级：
//
//	1. 直连嗅一下目标首字节（1.2s）——通就直接用，绝大多数新站走这里
//	2. 被 RST/无响应 → 试分片；通了就写进 strategy.json（下次直接命中，PAC 同步更新）
//	3. 分片也不行 → 有上游就转发兜底
//
// 这是「新站不用手工加表」的那条路。
func (p *Proxy) handleUnknown(conn net.Conn, br *bufio.Reader, host, port string) {
	fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	p.tunnelUnknown(conn, br, host, port)
}

// tunnelUnknown 是 handleUnknown 的正文，不含 HTTP 应答那一步 —— SOCKS5 也要用。
func (p *Proxy) tunnelUnknown(conn net.Conn, br *bufio.Reader, host, port string) {

	// 1) 直连嗅一下：通了就直接用，省掉一切猜测
	target, derr := p.dialShort(net.JoinHostPort(host, port), 1500*time.Millisecond)
	if derr == nil {
		target.SetDeadline(time.Now().Add(1200 * time.Millisecond))
		first := make([]byte, 4096)
		n, rerr := target.Read(first)
		if n > 0 {
			target.SetDeadline(time.Time{})
			conn.SetDeadline(time.Time{})
			conn.Write(first[:n])
			flushBr(br, target)
			p.memoSet(host, ModeDirect)
			logf("CONNECT %s  direct（未收录，直连通过，已记忆）", host)
			tunnel(conn, target)
			target.Close()
			return
		}
		target.Close()
		logf("CONNECT %s  直连无响应（%v，%s），分片/上游并发试", host, rerr, blockedWord(isBlockedErr(rerr)))
	} else {
		logf("CONNECT %s  直连失败（%v）", host, derr)
	}

	// 2) 读 ClientHello；读不出来说明不是 TLS，只能甩上游
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	hello, herr := readClientHello(br)
	if herr != nil {
		logf("CONNECT %s  %v", host, herr)
		if p.Upstream != "" {
			if up, err := p.dialViaUpstream(host, atoiPort(port)); err == nil {
				flushBr(br, up)
				conn.SetDeadline(time.Time{})
				p.memoSet(host, ModeUpstream)
				logf("CONNECT %s  -> upstream %s（非 TLS，兜底，已记忆）", host, p.Upstream)
				tunnel(conn, up)
				up.Close()
			}
		}
		return
	}

	// 3a) TCP 层就打不通 = 境外 IP 被封，分片救不了（分片只骗 SNI 检测，不打通 IP）
	//     直接走上游，省掉白试 4 个切点的 4 秒。
	if derr != nil && p.Upstream != "" {
		up, uerr := p.dialViaUpstream(host, atoiPort(port))
		if uerr != nil {
			logf("CONNECT %s  upstream fail: %v", host, uerr)
			return
		}
		up.Write(hello)
		flushBr(br, up)
		conn.SetDeadline(time.Time{})
		p.memoSet(host, ModeUpstream)
		logf("CONNECT %s  IP 层不通 → upstream %s（已记忆，跳过分片）", host, p.Upstream)
		tunnel(conn, up)
		up.Close()
		return
	}

	// 3) 分片和上游同时试，谁先通就用谁
	//    境外站分片必失败（IP 层封），串行试会白等一整个批次；国内站上游又不该碰。
	tc, hdr, mode, cut, failed, err := p.openUnknown(host, port, hello)
	for _, c := range failed {
		p.cuts.markBad(host, hello, c)
	}
	if err != nil {
		logf("CONNECT %s  %v", host, err)
		return
	}

	switch mode {
	case ModeFragment:
		p.cuts.put(host, hello, cut)
		conn.Write(hdr)
		conn.SetDeadline(time.Time{})
		tc.SetDeadline(time.Time{})
		flushBr(br, tc)
		logf("CONNECT %s  未收录 → 分片@%d 通了", host, cut)
		tunnel(conn, tc)
		tc.Close()
		p.learn(host)
	default:
		flushBr(br, tc)
		conn.SetDeadline(time.Time{})
		p.memoSet(host, ModeUpstream)
		logf("CONNECT %s  -> upstream %s（已记忆）", host, p.Upstream)
		tunnel(conn, tc)
		tc.Close()
	}
}

// openUnknown 并发试「分片」和「上游」，返回先打通的那条。
//
// 未收录域名只试前 4 个切点：扫满全表要 3~4 批，收益远低于让 Clash 直接接走。
func (p *Proxy) openUnknown(host, port string, hello []byte) (net.Conn, []byte, Mode, int, []int, error) {
	type res struct {
		conn   net.Conn
		hdr    []byte
		mode   Mode
		cut    int
		failed []int
		err    error
	}
	cands := cutCandidates(hello)
	if len(cands) > cutRaceBatch {
		cands = cands[:cutRaceBatch]
	}
	hasUp := p.Upstream != ""
	if !hasUp && len(cands) == 0 {
		return nil, nil, "", 0, nil, fmt.Errorf("no cut candidate")
	}

	ch := make(chan res, 2)
	if len(cands) > 0 {
		go func() {
			cut, tc, hdr, failed, err := p.raceCuts(host, port, hello, cands)
			ch <- res{conn: tc, hdr: hdr, mode: ModeFragment, cut: cut, failed: failed, err: err}
		}()
	}
	if hasUp {
		go func() {
			up, err := p.dialViaUpstream(host, atoiPort(port))
			if err == nil {
				if _, werr := up.Write(hello); werr != nil {
					up.Close()
					err = werr
				}
			}
			ch <- res{conn: up, mode: ModeUpstream, err: err}
		}()
	}

	want := 1
	if hasUp && len(cands) > 0 {
		want = 2
	}
	var failed []int
	for i := 0; i < want; i++ {
		r := <-ch
		failed = append(failed, r.failed...)
		if r.err != nil {
			if r.conn != nil {
				r.conn.Close()
			}
			continue
		}
		// 谁先通用谁：立刻返回，另一条后台收尾，绝不等它超时
		go func(left int) {
			for ; left < want; left++ {
				if x := <-ch; x.conn != nil {
					x.conn.Close()
				}
			}
		}(i + 1)
		return r.conn, r.hdr, r.mode, r.cut, failed, nil
	}
	return nil, nil, "", 0, failed, fmt.Errorf("fragment+upstream 都不通")
}

// isBlockedErr 判断这个错误像「被主动切断」而不是「服务器就是慢」。
func isBlockedErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "reset")
}

func blockedWord(rst bool) string {
	if rst {
		return "被 RST"
	}
	return "更像超时"
}

// flushBr 把 bufio 里已经读进来的客户端字节倒给目标，避免吞包。
func flushBr(br *bufio.Reader, w io.Writer) {
	n := br.Buffered()
	if n == 0 {
		return
	}
	b, _ := br.Peek(n)
	if _, err := w.Write(b); err == nil {
		br.Discard(n)
	}
}

// learn 把「这个域名需要分片」记进规则表和 strategy.json。
func (p *Proxy) learn(host string) {
	p.SetRule(host, Rule{Fragment: true})
	if p.Strategy == nil {
		return
	}
	p.Strategy.Set(host, ModeFragment)
	if err := p.Strategy.Save(strategyPath()); err != nil {
		logf("已发现 %s 需分片，但写 strategy.json 失败: %v", host, err)
		return
	}
	p.invalidatePAC()
	logf("已学习：%s → fragment（已写入 strategy.json）", host)
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
	return p.fragmentWith(conn, br, host, port, hello)
}

// fragmentWith 用已读出的 hello 做分片（handleUnknown 需要自己先读 hello 才能兜底上游）。
func (p *Proxy) fragmentWith(conn net.Conn, br *bufio.Reader, host, port string, hello []byte) error {
	rule, hit := p.lookup(host)
	var cands []int
	switch {
	case hit && rule.Cut > 0:
		cands = []int{rule.Cut}
	default:
		if c, ok := p.cuts.get(host, hello); ok {
			cands = append(cands, c) // 缓存命中：第 1 个就试，通常一次成
		}
		cands = append(cands, cutCandidates(hello)...)
	}

	// 去掉已确认的死点和越界点
	use := make([]int, 0, len(cands))
	seen := map[int]bool{}
	for _, c := range cands {
		if seen[c] || c <= 5 || c >= len(hello)-5 {
			continue
		}
		seen[c] = true
		if p.cuts.isBad(host, hello, c) {
			continue
		}
		use = append(use, c)
	}
	if len(use) == 0 {
		return fmt.Errorf("no usable cut (len=%d)", len(hello))
	}

	cut, tc, hdr, failed, err := p.raceCuts(host, port, hello, use)
	for _, c := range failed {
		p.cuts.markBad(host, hello, c)
	}
	if err != nil {
		return err
	}
	p.cuts.put(host, hello, cut)

	conn.Write(hdr)
	logf("  fragment@%d OK  %d->%d bytes  2 records", cut, len(hello), len(hello)+5)
	defer tc.Close()
	tc.SetDeadline(time.Time{})
	conn.SetDeadline(time.Time{})

	// 客户端在 hello 之后可能已经又发了数据（Early Data / 第二段 record），先倒过去
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		if _, err := tc.Write(b); err != nil {
			return err
		}
		br.Discard(n)
	}
	tunnel(conn, tc)
	return nil
}

// atoiPort 把端口字符串转成 int，解析失败退回 443。
func atoiPort(s string) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return 443
}

// dialShort 用更短的超时拨号：未收录域名探测时不能沿用 10s，
// 否则一个坏 IP 就把整条连接拖到客户端超时。
func (p *Proxy) dialShort(addr string, d time.Duration) (net.Conn, error) {
	dd := &net.Dialer{Timeout: d}
	return dd.Dial("tcp", addr)
}
