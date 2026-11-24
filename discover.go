package main

// discover.go —— 首次运行的自动探测：找出本机网络下被 SNI 封锁的域名，
// 写入 strategy.json，之后启动就不再靠内置清单猜测。
//
// 判定逻辑：
//   直连 TLS 握手成功         -> 不封，不处理
//   直连 TLS 被 RST/EOF       -> 疑似 SNI 封，再做一次分片验证
//   分片后握手成功            -> 确认可绕，策略标 fragment
//   分片也失败                -> 标 upstream（留给兜底上游，或直连失败由用户处理）

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// candidateDomains 是自动探测的候选池。
//
// 选取原则：国内常见、且历史上出现过 SNI 封锁的服务；不包含纯境外站——
// 境外站的失败原因通常是 IP 层封锁或 DNS 污染，分片救不了，混进来只会
// 让探测结果失真。用户可在 strategy.json 里自己加。
var candidateDomains = []string{
	// B站
	"www.bilibili.com", "api.bilibili.com", "upos-sz-mirrorcos.bilivideo.com",
	"cn-jsnt-ct-01-02.bilivideo.com", "i0.hdslb.com",
	// 字节
	"www.douyin.com", "live.douyin.com", "www.toutiao.com",
	// 小红书
	"www.xiaohongshu.com", "edith.xiaohongshu.com",
	// 腾讯 / 微信
	"channels.weixin.qq.com", "finder.video.qq.com", "dldir1.qq.com",
	"short.weixin.qq.com", "long.weixin.qq.com", "mp.weixin.qq.com",
	"lol.qq.com", "dnf.qq.com", "cf.qq.com", "pvp.qq.com", "game.qq.com",
	"www.wegame.com.cn",
	// 米哈游
	"www.mihoyo.com", "api-takumi.mihoyo.com", "hk4e-api.mihoyo.com",
	"ys-api.mihoyo.com", "webstatic.mihoyo.com",
	// 鹰角
	"ak.hypergryph.com", "ak-gs-api.hypergryph.com",
	// 网易
	"www.163.com", "xyq.163.com",
	// 海马
	"api.haimacloud.com", "www.haimacloud.com",
	// 对照组：本不该被封的国内大站，若这些也失败说明网络本身有问题
	"www.baidu.com", "www.taobao.com", "www.zhihu.com",
}

// DiscoverResult 是单个域名的探测结论。
type DiscoverResult struct {
	Domain   string `json:"domain"`
	Direct   string `json:"direct"`   // OK / RST / TIMEOUT / DNS / OTHER
	Fragment string `json:"fragment"` // OK / RST / SKIP
	Mode     string `json:"mode"`     // fragment / upstream / ""
}

// discover 探测 candidateDomains，返回结论表。
//
// 并发 8、单域名超时 5s；分片验证只在直连失败时才做，所以整体耗时
// 大致等于「最慢的那批直连探测」加上少量分片重试。
func discover(concurrency int, timeout time.Duration) []DiscoverResult {
	out := make([]DiscoverResult, 0, len(candidateDomains))
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, d := range candidateDomains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := DiscoverResult{Domain: domain, Fragment: "SKIP"}
			direct, ip := directVerdict(domain, timeout)
			r.Direct = direct
			switch direct {
			case "OK":
				// 没被封，不需要任何处理
			case "RST":
				// 疑似 SNI 封锁：试分片
				if ip != "" && fragWorks(domain, ip, timeout) {
					r.Fragment = "OK"
					r.Mode = "fragment"
				} else {
					r.Fragment = "RST"
					r.Mode = "upstream"
				}
			default:
				// DNS 失败 / 超时 / 其它：不是 SNI 层的锅，标记待定
				r.Mode = ""
			}

			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(d)
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// directVerdict 直连探测：返回 (结论, 首个解析 IP)。
func directVerdict(domain string, timeout time.Duration) (string, string) {
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return "DNS", ""
	}
	ip := ips[0]

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return "TIMEOUT", ip
		}
		return "OTHER", ip
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	tc := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.Handshake(); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return "TIMEOUT", ip
		}
		// RST / EOF / bad record MAC 都归到这里：TCP 握了手，TLS 层被打断
		return "RST", ip
	}
	return "OK", ip
}

// fragWorks 用多候选切点试分片，任一成功即返回 true。
func fragWorks(domain, ip string, timeout time.Duration) bool {
	hello := buildHelloFor(domain)
	if hello == nil {
		return false
	}
	for _, c := range cutCandidates(hello) {
		if c <= 5 || c >= len(hello)-5 {
			continue
		}
		if strings.HasPrefix(trySend(ip, fragmentHello(hello, c-5), timeout), "SERVER-HELLO OK") {
			return true
		}
	}
	return false
}

// applyDiscovery 把探测结果合并进策略表：
// 只新增/更新「被封锁」的条目，不删用户手写的。
func applyDiscovery(results []DiscoverResult) map[string]string {
	entries := map[string]string{}
	for _, r := range results {
		if r.Mode != "" {
			entries[r.Domain] = r.Mode
		}
	}
	return entries
}

// mergeStrategy 把探测结果写进 strategy.json（保留已有手写项）。
func mergeStrategy(path string, found map[string]string) error {
	st := struct {
		Entries map[string]string `json:"entries"`
	}{Entries: map[string]string{}}

	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &st)
		if st.Entries == nil {
			st.Entries = map[string]string{}
		}
	}
	added := 0
	for d, m := range found {
		if _, ok := st.Entries[d]; !ok {
			added++
		}
		st.Entries[d] = m
	}

	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// printDiscover 打印探测结果表。
func printDiscover(results []DiscoverResult) {
	var frag, up, clean, undecided []string
	for _, r := range results {
		switch r.Mode {
		case "fragment":
			frag = append(frag, r.Domain)
		case "upstream":
			up = append(up, r.Domain)
		default:
			if r.Direct == "OK" {
				clean = append(clean, r.Domain)
			} else {
				undecided = append(undecided, fmt.Sprintf("%s(%s)", r.Domain, r.Direct))
			}
		}
	}

	fmt.Printf("\n探测完成：%d 个域名\n\n", len(results))
	fmt.Printf("[分片可绕] %d\n", len(frag))
	for _, d := range frag {
		fmt.Printf("    %s\n", d)
	}
	if len(up) > 0 {
		fmt.Printf("\n[分片救不了，走兜底上游] %d\n", len(up))
		for _, d := range up {
			fmt.Printf("    %s\n", d)
		}
	}
	if len(undecided) > 0 {
		fmt.Printf("\n[未判定] %d\n", len(undecided))
		for _, d := range undecided {
			fmt.Printf("    %s\n", d)
		}
	}
	fmt.Printf("\n[未封锁] %d（不需要处理）\n\n", len(clean))
}

// runDiscover 是 `icefall discover` 子命令的实现。
func runDiscover(proxyPath string) {
	fmt.Println("正在探测本机网络下的封锁情况（约 20 秒）...")
	start := time.Now()
	results := discover(8, 5*time.Second)
	printDiscover(results)

	found := applyDiscovery(results)
	if len(found) == 0 {
		fmt.Println("没发现被 SNI 封锁的域名。当前网络不需要碎冰。")
		return
	}
	if err := mergeStrategy(proxyPath, found); err != nil {
		fmt.Printf("写入策略表失败: %v\n", err)
		return
	}
	fmt.Printf("已写入 %d 条策略 -> %s  (耗时 %.1fs)\n", len(found), proxyPath, time.Since(start).Seconds())
}

