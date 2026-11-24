package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// fragTest 测「TLS record 分片能否绕过学校 SNI 检测」。
//
// 原理：把 ClientHello 拆成多个 TLS record 发送，让 SNI 字符串跨 record
// 边界。检测设备通常只解析单 record 内的 SNI，看不到完整字符串就不 RST。
// 服务端会把多个 record 内容拼接还原，客户端 transcript 不变 → 无 MAC 错。
func fragTest(domain string, cutPoints []int) {
	ip := resolveForTest(domain)
	if ip == "" {
		fmt.Printf("%s: 解析失败\n", domain)
		return
	}
	fmt.Printf("\n=== %s (%s) ===\n", domain, ip)

	// 1) 基线：完整单 record，真 SNI → 应被 RST
	hello := buildHelloFor(domain)
	if hello == nil {
		fmt.Println("  无法构造 hello")
		return
	}
	fmt.Printf("  基线(单record,真SNI): %s\n", trySend(ip, hello, 8*time.Second))

	// 2) 分片，真 SNI
	for _, cut := range cutPoints {
		if cut <= 0 || cut >= len(hello)-5 {
			continue
		}
		frag := fragmentHello(hello, cut)
		res := trySend(ip, frag, 8*time.Second)
		fmt.Printf("  分片@%-4d (%d records): %s\n", cut, countRecords(frag), res)
	}
}

func resolveForTest(domain string) string {
	addrs, err := net.LookupHost(domain)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	return addrs[0]
}

func trySend(ip string, data []byte, timeout time.Duration) string {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return "DIAL-FAIL " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(data); err != nil {
		return "WRITE-FAIL " + err.Error()
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return "READ-FAIL " + err.Error()
	}
	if n == 0 {
		return "EMPTY"
	}
	switch buf[0] {
	case 0x16:
		return fmt.Sprintf("SERVER-HELLO OK (%dB)", n)
	case 0x15:
		if n >= 7 {
			return fmt.Sprintf("ALERT 0x%02x", buf[6])
		}
		return "ALERT"
	}
	return fmt.Sprintf("type=0x%02x", buf[0])
}



// buildHelloFor 用 crypto/tls 的 MemoryBIO 抠一个真实 ClientHello。
func buildHelloFor(domain string) []byte {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := &tls.Config{ServerName: domain, InsecureSkipVerify: true}
	cl := tls.Client(c1, cfg)
	go func() { _ = cl.Handshake() }()

	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	if _, err := readFull(c2, hdr); err != nil {
		return nil
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, n)
	if _, err := readFull(c2, body); err != nil {
		return nil
	}
	return append(hdr, body...)
}

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
