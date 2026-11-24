package main

// cutcache.go —— 记住每个域名/每种 ClientHello 形状的成功切点，并并行试探候选切点。
//
// 为什么要缓存：一个页面会开几十个连接，每个连接都从十几个候选切点里线性试，
// 冷启动那次要吃掉 3~5 个 RTT。成功一次后记住，后续连接第 1 次就命中。
//
// 为什么要并行：有效切点区间随 hello 形状变化（同一个 CDN，Go 的 hello 偏移 117、
// OpenSSL 的偏移 127，有效区间完全不重叠），缓存未命中时线性试太慢。
// 一次并发试 4 个，谁先拿到 ServerHello 就用谁。

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	cutDialTimeout = 4 * time.Second
	cutRaceBatch   = 4
)

var errCutSkipped = errors.New("skipped")

// cutKey 把「域名 + ClientHello 形状」当缓存键。
// 只算域名不够：同一个域名下不同客户端的 hello 结构不同，最佳切点也不同。
type cutKey struct {
	host string
	hlen int // ClientHello 总长
	off  int // SNI 名字在记录内的偏移
}

type cutCache struct {
	mu  sync.RWMutex
	win map[cutKey]int          // 该形状下验证成功的切点
	bad map[cutKey]map[int]bool // 该形状下已确认失败的切点
	hip map[string]int          // 域名级兜底（形状变化时先试一次）
}

func newCutCache() *cutCache {
	return &cutCache{
		win: map[cutKey]int{},
		bad: map[cutKey]map[int]bool{},
		hip: map[string]int{},
	}
}

func keyOf(host string, hello []byte) cutKey {
	return cutKey{host: host, hlen: len(hello), off: sniNameOffset(hello)}
}

func (c *cutCache) get(host string, hello []byte) (int, bool) {
	k := keyOf(host, hello)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v, ok := c.win[k]; ok {
		return v, true
	}
	if v, ok := c.hip[host]; ok {
		return v, true
	}
	return 0, false
}

func (c *cutCache) put(host string, hello []byte, cut int) {
	k := keyOf(host, hello)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.win[k] = cut
	c.hip[host] = cut
	if bs := c.bad[k]; bs != nil {
		delete(bs, cut)
	}
}

func (c *cutCache) isBad(host string, hello []byte, cut int) bool {
	k := keyOf(host, hello)
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bad[k][cut]
}

func (c *cutCache) markBad(host string, hello []byte, cut int) {
	k := keyOf(host, hello)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bad[k] == nil {
		c.bad[k] = map[int]bool{}
	}
	c.bad[k][cut] = true
	if c.win[k] == cut {
		delete(c.win, k)
	}
	if c.hip[host] == cut {
		delete(c.hip, host)
	}
}

// tryCut 用某一个切点新建连接并发送分片 hello，等服务器首字节。
// 收到 0x16（handshake）说明握手被接受，返回这条连接和已读的 5 字节记录头。
func (p *Proxy) tryCut(host, port string, hello []byte, c int) (net.Conn, []byte, error) {
	if c <= 5 || c >= len(hello)-5 {
		return nil, nil, errCutSkipped
	}
	// 用短超时拨号：坏 IP 上 10s 硬等会把「首批 4 个切点」拖成 40s
	tc, err := p.dialShort(net.JoinHostPort(host, port), cutDialTimeout)
	if err != nil {
		return nil, nil, err
	}
	tc.SetDeadline(time.Now().Add(cutDialTimeout))
	if _, err := tc.Write(fragmentHello(hello, c-5)); err != nil {
		tc.Close()
		return nil, nil, err
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(tc, hdr); err != nil {
		tc.Close()
		return nil, nil, err
	}
	if hdr[0] != 0x16 {
		tc.Close()
		return nil, nil, fmt.Errorf("type=0x%02x", hdr[0])
	}
	return tc, hdr, nil
}

type cutTry struct {
	cut  int
	conn net.Conn
	hdr  []byte
	err  error
}

// raceCuts 分批并发试探切点，返回第一个成功的，以及确认失败的切点列表。
func (p *Proxy) raceCuts(host, port string, hello []byte, cuts []int) (int, net.Conn, []byte, []int, error) {
	var failed []int
	stop := make(chan struct{})

	for i := 0; i < len(cuts); i += cutRaceBatch {
		end := i + cutRaceBatch
		if end > len(cuts) {
			end = len(cuts)
		}
		ch := make(chan cutTry, end-i)
		for _, c := range cuts[i:end] {
			go func(c int) {
				select {
				case <-stop:
					ch <- cutTry{cut: c, err: errCutSkipped}
					return
				default:
				}
				conn, hdr, err := p.tryCut(host, port, hello, c)
				ch <- cutTry{cut: c, conn: conn, hdr: hdr, err: err}
			}(c)
		}

		var win *cutTry
		got := 0
		for ; got < end-i; got++ {
			r := <-ch
			if r.err != nil {
				if !errors.Is(r.err, errCutSkipped) {
					failed = append(failed, r.cut)
					logf("  cut=%-4d %v", r.cut, shortCutErr(r.err))
				}
				continue
			}
			if win == nil {
				win = &r
				close(stop)
			} else {
				r.conn.Close()
			}
		}
		if win != nil {
			// 收尾：并发里剩下的成功连接没人要，关掉，别漏 socket
			go func(left int) {
				for ; left < end-i; left++ {
					if r := <-ch; r.conn != nil {
						r.conn.Close()
					}
				}
			}(got + 1)
			return win.cut, win.conn, win.hdr, failed, nil
		}
	}
	return 0, nil, nil, failed, fmt.Errorf("all %d cuts failed", len(cuts))
}

func shortCutErr(err error) string {
	s := err.Error()
	if len(s) > 40 {
		return s[:40]
	}
	return s
}
