package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// tunmode.go 负责「栈拿到的一条连接该走哪条路」，以及把 TUN 读循环接到栈上。
// 与平台无关：Windows 的网卡创建在 tun_windows.go。

// readAheadConn 把已经读出来的字节（ServerHello 头 5 字节）重新吐给上层。
type readAheadConn struct {
	net.Conn
	mu   sync.Mutex
	head []byte
}

func (r *readAheadConn) Read(b []byte) (int, error) {
	r.mu.Lock()
	if len(r.head) > 0 {
		n := copy(b, r.head)
		r.head = r.head[n:]
		r.mu.Unlock()
		return n, nil
	}
	r.mu.Unlock()
	return r.Conn.Read(b)
}

func ip4String(a [4]byte) string {
	return net.IPv4(a[0], a[1], a[2], a[3]).String()
}

// dialForTun 是 Stack.route 的实现。
//
// 有 SNI 就按策略表走（分片 / 直连 / 上游），没有 SNI 就先直连 IP，失败再上游。
func (p *Proxy) dialForTun(sip [4]byte, sport int, sni string, hello []byte) (net.Conn, bool, error) {
	ip := ip4String(sip)
	portStr := strconv.Itoa(sport)

	if sni != "" {
		mode, known := p.modeOf(sni)
		switch {
		case known && mode == ModeFragment:
			if c, hdr, err := p.dialFragmentOnly(sni, portStr, hello); err == nil {
				return &readAheadConn{Conn: c, head: hdr}, true, nil
			}
		case known && mode == ModeUpstream:
			if p.Upstream != "" {
				if c, err := p.dialViaUpstream(sni, sport); err == nil {
					c.Write(hello)
					return c, true, nil
				}
			}
		case known && mode == ModeDirect:
			if c, err := p.dialPlain(sni, portStr); err == nil {
				c.Write(hello)
				return c, true, nil
			}
		default:
			// 未收录：分片和直连同时试，谁先通用谁；都不行再上游
			if c, hdr, err := p.raceTunUnknown(sni, portStr, hello); err == nil {
				return &readAheadConn{Conn: c, head: hdr}, true, nil
			}
			if p.Upstream != "" {
				if c, err := p.dialViaUpstream(sni, sport); err == nil {
					c.Write(hello)
					return c, true, nil
				}
			}
		}
	}

	// 没有 SNI（非 TLS）或域名那条路全挂：直连 IP，再退上游 IP
	if c, err := p.dialPlain(ip, portStr); err == nil {
		if len(hello) > 0 {
			c.Write(hello)
		}
		if sni == "" {
			p.memoSet(ip, ModeDirect)
		}
		return c, true, nil
	}
	if p.Upstream != "" {
		if c, err := p.dialViaUpstream(ip, sport); err == nil {
			if len(hello) > 0 {
				c.Write(hello)
			}
			return c, true, nil
		}
	}
	return nil, false, fmt.Errorf("所有路径都不通：%s:%d（SNI=%q）", ip, sport, sni)
}

func (p *Proxy) dialPlain(host, port string) (net.Conn, error) {
	return p.dialShort(net.JoinHostPort(host, port), 5*time.Second)
}

func (p *Proxy) dialFragmentOnly(host, port string, hello []byte) (net.Conn, []byte, error) {
	cands := cutCandidates(hello)
	// 跳过已知坏切点：同域名同形状的 hello 试过的死区不必再试
	if good := cands[:0]; true {
		for _, c := range cands {
			if !p.cuts.isBad(host, hello, c) {
				good = append(good, c)
			}
		}
		if len(good) > 0 {
			cands = good
		}
	}
	cut, conn, hdr, failed, err := p.raceCuts(host, port, hello, cands)
	for _, c := range failed {
		p.cuts.markBad(host, hello, c)
	}
	if err != nil {
		return nil, nil, err
	}
	p.cuts.put(host, hello, cut)
	return conn, hdr, nil
}

// raceTunUnknown 对未收录域名做「分片 vs 直连」竞速。
func (p *Proxy) raceTunUnknown(host, port string, hello []byte) (net.Conn, []byte, error) {
	cands := cutCandidates(hello)
	if len(cands) > cutRaceBatch {
		cands = cands[:cutRaceBatch]
	}

	type res struct {
		conn net.Conn
		hdr  []byte
		err  error
	}
	ch := make(chan res, 2)

	go func() {
		c, hdr, err := p.dialFragmentOnly(host, port, hello)
		ch <- res{c, hdr, err}
	}()
	go func() {
		c, err := p.dialPlain(host, port)
		if err == nil {
			c.Write(hello)
			if br := bufio.NewReader(c); br != nil {
				c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				first := make([]byte, 5)
				n, rerr := io.ReadFull(br, first)
				c.SetReadDeadline(time.Time{})
				if rerr != nil || n == 0 {
					c.Close()
					ch <- res{err: fmt.Errorf("direct 无响应")}
					return
				}
				// 把读掉的字节塞回去
				head := append([]byte(nil), first[:n]...)
				if rest := br.Buffered(); rest > 0 {
					more, _ := br.Peek(rest)
					head = append(head, more...)
					br.Discard(rest)
				}
				ch <- res{&readAheadConn{Conn: c, head: head}, nil, nil}
				return
			}
			ch <- res{c, nil, nil}
			return
		}
		ch <- res{err: err}
	}()

	var failed bool
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil {
			go func(left int) {
				for ; left < 2-i; left++ {
					if x := <-ch; x.conn != nil {
						x.conn.Close()
					}
				}
			}(1)
			p.learn(host)
			return r.conn, r.hdr, nil
		}
		failed = true
	}
	if failed {
		return nil, nil, fmt.Errorf("分片和直连都不通")
	}
	return nil, nil, fmt.Errorf("未知")
}

// runTunLoop 从 TUN 读包喂给栈。read 由平台层提供。
func runTunLoop(read func([]byte) (int, error), st *Stack) {
	buf := make([]byte, 65535)
	for {
		n, err := read(buf)
		if err != nil {
			logf("TUN 读失败: %v", err)
			return
		}
		if n <= 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		st.Handle(pkt)
	}
}
