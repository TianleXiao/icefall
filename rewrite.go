package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

var fakeSNIPool = []string{
	"www.baidu.com",
	"www.qq.com",
	"www.microsoft.com",
	"www.aliyun.com",
	"www.taobao.com",
}

func pickFakeSNI(idx int) string {
	return fakeSNIPool[idx%len(fakeSNIPool)]
}

// RewriteProbe 验证"改写 SNI 后能否握手成功，且拿到的证书是否仍属于目标域名"。
// 这是判定 PolicyRewrite 是否可用的唯一依据。
func RewriteProbe(domain string, fakeSNI string, timeout time.Duration) ProbeResult {
	res := ProbeResult{Domain: domain}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil || len(ips) == 0 {
		res.Verdict = DNSFail
		return res
	}
	res.ResolvedIP = ips[0]

	start := time.Now()
	addr := net.JoinHostPort(ips[0], "443")
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Verdict = IPBlocked
		res.Latency = time.Since(start)
		res.Err = err.Error()
		return res
	}
	defer raw.Close()

	cfg := &utls.Config{
		ServerName:         fakeSNI, // 握手用假 SNI，绕过学校名单
		InsecureSkipVerify: true,
	}

	u := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	if err := u.HandshakeContext(ctx); err != nil {
		res.Latency = time.Since(start)
		res.Verdict = SNIBlocked
		res.Err = err.Error()
		return res
	}

	st := u.ConnectionState()
	if len(st.PeerCertificates) > 0 {
		cert := st.PeerCertificates[0]
		res.CertCN = cert.Subject.CommonName
		// 关键校验：证书 SAN 是否仍覆盖真实目标域名
		if err := cert.VerifyHostname(domain); err != nil {
			res.Verdict = Unknown
			res.Err = "cert does not cover target: " + err.Error()
			res.Latency = time.Since(start)
			return res
		}
	}

	// 在握手成功的连接上做一次真实 HTTP 请求，确认应用层可用
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", domain)
	if _, err := u.Write([]byte(req)); err == nil {
		raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		if n, _ := u.Read(buf); n > 0 {
			head := string(buf[:n])
			if !strings.HasPrefix(head, "HTTP/") {
				res.Err = "non-http response: " + strings.SplitN(head, "\r\n", 2)[0]
			}
		}
	}

	res.Verdict = OK
	res.Latency = time.Since(start)
	return res
}

// CertOnly 只取证书 CN，用于给真实 SNI 探测补信息。
func CertOnly(domain string, timeout time.Duration) string {
	return Probe(domain, timeout).CertCN
}
