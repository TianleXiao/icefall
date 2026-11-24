package main

// checkall.go —— 通过本地代理 127.0.0.1:8899 实测一批域名当前能否打开。
//
// 为什么要单独写：探针 Probe() 用的是直连，测的是「学校封不封」；
// 这里要测的是「经我代理后能不能打开」，两者结论可能不同（代理有 bug 也会挂）。

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type CheckResult struct {
	Domain  string
	Status  int
	Bytes   int
	Ms      int64
	Err     string
	Via     string // "fragment" 或 "upstream"
}

// checkOne 经代理拉一次首页，记录状态码/字节数/耗时。
func checkOne(proxyAddr, domain string, timeout time.Duration) CheckResult {
	res := CheckResult{Domain: domain}
	u, _ := url.Parse("https://" + domain + "/")
	pu, _ := url.Parse("http://" + proxyAddr)
	tr := &http.Transport{
		Proxy: http.ProxyURL(pu),
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"}, // 强制 http/1.1，方便数字节
		},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	c := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	t0 := time.Now()
	resp, err := c.Get(u.String())
	res.Ms = time.Since(t0).Milliseconds()
	if err != nil {
		res.Err = shortErr(err)
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	buf := make([]byte, 32*1024)
	for {
		n, e := resp.Body.Read(buf)
		res.Bytes += n
		if e != nil || res.Bytes > 1<<20 {
			break
		}
	}
	return res
}

// shortErr 把常见错误压成短标签。
func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded"):
		return "TIMEOUT"
	case strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed") || strings.Contains(s, "EOF"):
		return "RST/EOF"
	case strings.Contains(s, "no such host"):
		return "DNS"
	case strings.Contains(s, "refused"):
		return "REFUSED"
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// checkAll 并发经代理检查一批域名。
func checkAll(proxyAddr string, domains []string, concurrency int, timeout time.Duration) []CheckResult {
	out := make([]CheckResult, len(domains))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = checkOne(proxyAddr, d, timeout)
		}(i, d)
	}
	wg.Wait()
	return out
}

// printCheckAll 打印检查结果表。
func printCheckAll(proxyAddr string, domains []string) {
	fmt.Printf("经代理 %s 实测 %d 个域名...\n\n", proxyAddr, len(domains))
	rs := checkAll(proxyAddr, domains, 8, 12*time.Second)

	var ok, bad, mid []CheckResult
	for _, r := range rs {
		switch {
		case r.Err != "":
			bad = append(bad, r)
		case r.Status >= 200 && r.Status < 400 && r.Bytes > 200:
			ok = append(ok, r)
		default:
			mid = append(mid, r)
		}
	}

	fmt.Printf("[可打开] %d\n", len(ok))
	for _, r := range ok {
		fmt.Printf("  %-45s %d  %6dB  %5dms\n", r.Domain, r.Status, r.Bytes, r.Ms)
	}
	if len(mid) > 0 {
		fmt.Printf("\n[可疑：连上了但响应不对] %d\n", len(mid))
		for _, r := range mid {
			fmt.Printf("  %-45s %d  %6dB  %5dms\n", r.Domain, r.Status, r.Bytes, r.Ms)
		}
	}
	if len(bad) > 0 {
		fmt.Printf("\n[打不开] %d\n", len(bad))
		for _, r := range bad {
			fmt.Printf("  %-45s %-12s %5dms\n", r.Domain, r.Err, r.Ms)
		}
	}
}
