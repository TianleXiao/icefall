package main

import (
	"os"
	"fmt"
	"net"
	"time"
)

// perIPFragTest 对同一域名的所有 A 记录逐个测「单 record vs 分片」。
// B站这类多 CDN 的站，不同 IP 的封锁态度可能不同。
func perIPFragTest(domain string) {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		fmt.Printf("%s: DNS 失败 %v\n", domain, err)
		return
	}
	hello := buildHelloFor(domain)
	if hello == nil {
		fmt.Printf("%s: 无法构造 hello\n", domain)
		return
	}
	off := sniNameOffset(hello)
	frag := fragmentHello(hello, off-5)

	fmt.Printf("\n=== %s (SNI 名偏移 %d) ===\n", domain, off)
	fmt.Printf("%-18s %-14s %-14s %s\n", "IP", "单record", "分片", "结论")
	fmt.Println("--------------------------------------------------------------")

	okCount := 0
	for _, ip := range addrs {
		if net.ParseIP(ip) == nil {
			continue
		}
		base := shortVerdict(trySend(ip, hello, 5*time.Second))
		fv := shortVerdict(trySend(ip, frag, 5*time.Second))
		concl := "-"
		if base == "RST" && fv == "OK" {
			concl = "可绕开"
			okCount++
		} else if base == "OK" {
			concl = "未封锁"
		} else if base == "RST" && fv == "RST" {
			concl = "封死"
		}
		fmt.Printf("%-18s %-14s %-14s %s\n", ip, base, fv, concl)
	}
	fmt.Printf("可用 IP: %d/%d\n", okCount, len(addrs))
}

// cutTest 对同一域名扫多个切点，找出能绕过检测的位置。
func cutTest(domain string) {
	ip := resolveForTest(domain)
	if ip == "" {
		fmt.Printf("%s: DNS 失败\n", domain)
		return
	}
	hello := buildHelloFor(domain)
	if hello == nil {
		fmt.Printf("%s: 无法构造 hello\n", domain)
		return
	}
	off := sniNameOffset(hello)
	fmt.Printf("\n=== %s (%s) SNI名偏移=%d 记录共%d字节 ===\n", domain, ip, off, len(hello))
	// 名字总长（从 off-2 读 name_len）
	nlen := int(hello[off-2])<<8 | int(hello[off-1])

	// 先测基线
	fmt.Printf("  基线(不分片): %s\n", shortVerdict(trySend(ip, hello, 5*time.Second)))
	// 覆盖整段 SNI 名字区域扫切点
	for c := off - 8; c <= off+nlen+8; c++ {
		if c <= 5 || c >= len(hello)-5 {
			continue
		}
		v := shortVerdict(trySend(ip, fragmentHello(hello, c-5), 5*time.Second))
		mark := ""
		if v == "OK" {
			mark = "  <== 成功"
		}
		fmt.Printf("  cut=%-4d %s%s\n", c, v, mark)
	}
}

// fileCutTest 用落盘的真实 hello 扫切点。
func fileCutTest(path, ip string) {
	hello, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	off := sniNameOffset(hello)
	nlen := 0
	if off > 0 && off >= 2 && off-2 < len(hello) {
		nlen = int(hello[off-2])<<8 | int(hello[off-1])
	}
	fmt.Printf("\n=== %s (%s) hello=%d SNI偏移=%d 名长=%d ===\n", path, ip, len(hello), off, nlen)
	fmt.Printf("  基线: %s\n", shortVerdict(trySend(ip, hello, 5*time.Second)))
	for c := off - 10; c <= off+nlen+10; c++ {
		if c <= 5 || c >= len(hello)-5 {
			continue
		}
		v := shortVerdict(trySend(ip, fragmentHello(hello, c-5), 5*time.Second))
		mark := ""
		if v == "OK" {
			mark = "  <== 成功"
		}
		fmt.Printf("  cut=%-4d %s%s\n", c, v, mark)
	}
}
