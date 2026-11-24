package main

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"sync"
	"time"
)

// Verdict 表示一次探测对"该域名直连是否被阻断"的判定。
type Verdict int

const (
	OK Verdict = iota
	SNIBlocked
	IPBlocked
	DNSFail
	Timeout
	Unknown
)

func (v Verdict) String() string {
	switch v {
	case OK:
		return "OK"
	case SNIBlocked:
		return "SNI_BLOCKED"
	case IPBlocked:
		return "IP_BLOCKED"
	case DNSFail:
		return "DNS_FAIL"
	case Timeout:
		return "TIMEOUT"
	}
	return "UNKNOWN"
}

// ProbeResult 是单个域名的探测结果。
type ProbeResult struct {
	Domain     string
	Verdict    Verdict
	Latency    time.Duration
	ResolvedIP string
	CertCN     string
	Err        string
}

// Probe 判断域名直连的阻断层级：
//
//	DNS 解析失败      -> DNSFail
//	TCP 443 连不上    -> IPBlocked   （按 IP 封，本地改写无解）
//	TCP 通但 TLS 失败 -> SNIBlocked  （按 SNI 封，本地改写可解）
//	TLS 成功          -> OK
func Probe(domain string, timeout time.Duration) ProbeResult {
	res := ProbeResult{Domain: domain}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil || len(ips) == 0 {
		res.Verdict = DNSFail
		if err != nil {
			res.Err = err.Error()
		}
		return res
	}
	res.ResolvedIP = ips[0]

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ips[0], "443"))
	if err != nil {
		res.Latency = time.Since(start)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			res.Verdict = Timeout
		} else {
			res.Verdict = IPBlocked
		}
		res.Err = err.Error()
		return res
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // 探测阶段只看握手成败
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		res.Latency = time.Since(start)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			res.Verdict = Timeout
		} else {
			res.Verdict = SNIBlocked
		}
		res.Err = err.Error()
		return res
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		res.CertCN = state.PeerCertificates[0].Subject.CommonName
	}
	res.Verdict = OK
	res.Latency = time.Since(start)
	return res
}

// ProbeAll 并发探测一组域名，返回按 verdict 分组的结果。
func ProbeAll(domains []string, concurrency int, timeout time.Duration) []ProbeResult {
	out := make([]ProbeResult, 0, len(domains))
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := Probe(domain, timeout)
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(d)
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Verdict != out[j].Verdict {
			return out[i].Verdict < out[j].Verdict
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}
