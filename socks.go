package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// SOCKS5 —— 让不走系统代理的程序也能用上分片。
//
// 典型场景：
//   - tun2socks：TUN 网卡收到的 TCP 全部转给 SOCKS5
//   - 微信客户端 / 游戏启动器：很多国产客户端无视系统代理，但支持 SOCKS5
//   - 命令行工具：curl --socks5-hostname 127.0.0.1:8899
//
// 与 HTTP 代理共用同一端口（8899）：SOCKS5 首字节固定 0x05，
// HTTP 方法（CONNECT/GET/...）全是 ASCII，两者不会撞车。

const (
	socksVer     = 0x05
	socksNoAuth  = 0x00
	socksCmdConn = 0x01
	socksCmdUDP  = 0x03
)

func (p *Proxy) handleSocks(conn net.Conn, br *bufio.Reader) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// 握手：VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != socksVer {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == socksNoAuth {
			noAuth = true
			break
		}
	}
	if !noAuth {
		conn.Write([]byte{socksVer, 0xff})
		return
	}
	if _, err := conn.Write([]byte{socksVer, socksNoAuth}); err != nil {
		return
	}

	// 请求：VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != socksVer {
		return
	}
	host, err := readSocksHost(br, req[3])
	if err != nil {
		socksReply(conn, 0x08) // address type not supported
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])

	switch req[1] {
	case socksCmdConn:
		// 和 HTTP 路径共用同一套策略判定：modeOf 会查手工规则 → 运行时 memo → strategy.json
		mode, known := p.modeOf(host)

		// 分片段：直接分片
		if mode == ModeFragment || (mode == ModeUpstream && p.Upstream == "") {
			if err := socksReply(conn, 0x00); err != nil {
				return
			}
			logf("SOCKS5 %s:%d  fragment", host, port)
			if err := p.fragmentTunnel(conn, br, host, strconv.Itoa(port)); err != nil {
				logf("SOCKS5 %s  %v", host, err)
			}
			return
		}

		// 未收录：交给和 HTTP 一样的研判流程（直连嗅探 → 分片/上游并发 → 自动学习）
		if !known {
			if err := socksReply(conn, 0x00); err != nil {
				return
			}
			p.tunnelUnknown(conn, br, host, strconv.Itoa(port))
			return
		}

		var target net.Conn
		via := "direct"
		if mode == ModeUpstream {
			target, err = p.dialViaUpstream(host, port)
			via = "upstream " + p.Upstream
		} else {
			target, err = p.dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		}
		if err != nil {
			socksReply(conn, 0x05) // connection refused
			logf("SOCKS5 %s:%d  dial fail: %v", host, port, err)
			return
		}
		defer target.Close()
		if err := socksReply(conn, 0x00); err != nil {
			return
		}
		logf("SOCKS5 %s:%d  %s", host, port, via)
		conn.SetDeadline(time.Time{})
		target.SetDeadline(time.Time{})
		flushBr(br, target)
		tunnel(conn, target)

	case socksCmdUDP:
		// UDP 需要单独的中继实现（UDP ASSOCIATE + 分片封装）。
		// 现在明确回「命令不支持」，让调用方（tun2socks）自己把 UDP 走别的出口，
		// 而不是假装支持然后静默丢包。
		socksReply(conn, 0x07)
		logf("SOCKS5 UDP ASSOCIATE %s:%d  未实现（UDP 请走 Clash 的 TUN）", host, port)

	default:
		socksReply(conn, 0x07)
	}
}

// readSocksHost 解析 ATYP + 地址部分。
func readSocksHost(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03: // 域名
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	}
	return "", fmt.Errorf("unknown atyp 0x%02x", atyp)
}

// socksReply 回 SOCKS5 应答。BND.ADDR 固定回 0.0.0.0:0，客户端不关心。
func socksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socksVer, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// dialViaUpstream 经兜底 HTTP 代理（Clash）建 CONNECT 隧道。
//
// SOCKS5 客户端拿到的上游地址是 HTTP 代理，所以这里替它做一次 CONNECT 握手，
// 之后拿到的就是裸 TCP，直接转给客户端。
func (p *Proxy) dialViaUpstream(host string, port int) (net.Conn, error) {
	up, err := p.dialer.Dial("tcp", p.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream dial: %w", err)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if _, err := fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
		up.Close()
		return nil, err
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(up), &http.Request{Method: http.MethodConnect})
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("upstream resp: %w", err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		up.Close()
		return nil, fmt.Errorf("upstream refused %d", resp.StatusCode)
	}
	up.SetDeadline(time.Time{})
	return up, nil
}
