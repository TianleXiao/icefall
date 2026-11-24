package main

// pac.go —— 生成 PAC（Proxy Auto-Config）并对外提供。
//
// 为什么用 PAC 而不是固定代理：
//   - 固定代理让**所有**流量都进本程序，百度、GitHub 这些本来通的也要多绕一跳；
//   - PAC 只把策略表里标了 fragment/upstream 的域名指过来，其余 DIRECT；
//   - 系统侧只改一个设置（autoproxy），不用逐项配 web/secure/bypass。

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// pacURLPath 是 PAC 文件的访问路径。
const pacURLPath = "/proxy.pac"

// pacAddr 是 PAC 里要返回的代理地址。
func pacAddr(proxyAddr string) string { return proxyAddr }

// buildPAC 按策略表生成 PAC 脚本。
//
// 只用 PAC 的最小子集（FindProxyForURL + dnsDomainIs + shExpMatch），
// 不依赖任何扩展函数 —— Safari、Chrome、curl 都认。
func buildPAC(strat *Strategy, proxyAddr string) string {
	var frag, up []string
	if strat != nil {
		s := strat.snapshot()
		for k, m := range s {
			switch m {
			case ModeFragment:
				frag = append(frag, k)
			case ModeUpstream:
				up = append(up, k)
			}
		}
	}
	sort.Strings(frag)
	sort.Strings(up)

	var b strings.Builder
	b.WriteString("// 碎冰 Icefall —— 自动生成的 PAC，别手改，改 strategy.json\n")
	b.WriteString("// 策略表更新后重启代理即可重新生成。\n")
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n")

	// 分片组：本机代理
	if len(frag) > 0 {
		b.WriteString("\n  // —— 分片组：走本机代理，按 TLS record 拆分穿过 SNI 检测 ——\n")
		for _, d := range frag {
			fmt.Fprintf(&b, "  if (dnsDomainIs(host, %q)) return \"PROXY %s\";\n", "."+d, proxyAddr)
			fmt.Fprintf(&b, "  if (host === %q) return \"PROXY %s\";\n", d, proxyAddr)
		}
	}

	// 上游组：同样走本机代理（本程序内部再转给 Clash）
	if len(up) > 0 {
		b.WriteString("\n  // —— 上游组：本机代理转交给 Clash 等上游 ——\n")
		for _, d := range up {
			fmt.Fprintf(&b, "  if (dnsDomainIs(host, %q)) return \"PROXY %s\";\n", "."+d, proxyAddr)
			fmt.Fprintf(&b, "  if (host === %q) return \"PROXY %s\";\n", d, proxyAddr)
		}
	}

	b.WriteString("\n  // 其余一律直连：不浪费转发，也不给本机代理添负载\n")
	b.WriteString("  return \"DIRECT\";\n")
	b.WriteString("}\n")
	return b.String()
}

// pacText 返回生成的 PAC，并缓存。
//
// 浏览器每次导航都可能回来取 PAC，重新拼一遍没意义；
// 策略表变了（自动学习新域名）才 invalidate 重算。
func (p *Proxy) pacText() string {
	p.pacMu.Lock()
	defer p.pacMu.Unlock()
	if p.pacStr == "" {
		p.pacStr = buildPAC(p.Strategy, pacAddr(p.Addr))
	}
	return p.pacStr
}

func (p *Proxy) invalidatePAC() {
	p.pacMu.Lock()
	p.pacStr = ""
	p.pacMu.Unlock()
}

// servePAC 把 PAC 脚本回给请求方。
func (p *Proxy) servePAC(conn interface {
	Write([]byte) (int, error)
}, _ *http.Request) {
	body := p.pacText()
	hdr := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/x-ns-proxy-autoconfig\r\n"+
			"Content-Length: %d\r\n"+
			"Cache-Control: no-store\r\n"+
			"Connection: close\r\n\r\n", len(body))
	conn.Write([]byte(hdr))
	conn.Write([]byte(body))
}

// probeSelf 判断 addr 上是否已经有本程序在跑。
//
// 用 PAC 里的特征字符串认亲，而不是只看端口通不通 ——
// 端口被别的程序占着时也要能区分出来，否则会误判成「已在运行」而不启动。
func probeSelf(addr string) (bool, error) {
	c, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
	if err != nil {
		return false, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", pacURLPath, addr)
	b, _ := io.ReadAll(io.LimitReader(c, 4096))
	return strings.Contains(string(b), "FindProxyForURL"), nil
}
