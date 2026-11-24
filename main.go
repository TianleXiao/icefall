package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

// 默认分片名单：实测「单 record 被 RST、分片后能握手」的站。
var defaultTargets = []string{
	"bilibili.com",
	"hdslb.com",
	"bilivideo.com",
	"bilivideo.cn",
	"bilibili.tv",
	"xiaohongshu.com",
	"xhscdn.com",
	"douyin.com",
	"douyinpic.com",
	"douyinvod.com",
	"mihoyo.com",
	"hoyoverse.com",
	"hypergryph.com",
	"qq.com",
	"wegame.com.cn",
	"haimacloud.com",
	"haima.com",
	// 微信视频号：channels=主页/网页版，finder.video=视频流，dldir1=安装包更新
	// 实测真 SNI 被 RST，分片切点 109-114+ / 125-128 可通
	"channels.weixin.qq.com",
	"finder.video.qq.com",
	"dldir1.qq.com",
}

func main() {
	mode := "proxy"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	switch mode {
	case "proxy":
		runProxy()
	case "filecut":
		fileCutTest(os.Args[2], os.Args[3])
	case "cut":
		for _, d := range os.Args[2:] {
			cutTest(d)
		}
	case "perip":
		for _, d := range os.Args[2:] {
			perIPFragTest(d)
		}
	case "frag":
		runFragScan()
	case "discover":
		runDiscover(strategyPath())
	case "setproxy":
		// 脚本调用：icefall setproxy 127.0.0.1:8899
		//          icefall setproxy pac       ← 用 PAC，只代理策略表里的域名
		addr := "127.0.0.1:8899"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		SaveBackup()
		var err error
		if addr == "pac" {
			// 带时间戳强制刷新：浏览器会缓存 PAC，换版本后不加这个会一直用旧的
			u := fmt.Sprintf("http://127.0.0.1:8899%s?v=%d", pacURLPath, time.Now().Unix())
			err = SetSystemPAC(u)
			if err == nil {
				fmt.Printf("系统代理已改为 PAC：%s\n", u)
			}
		} else {
			err = SetSystemProxy(addr)
			if err == nil {
				fmt.Printf("系统代理已指向 %s\n", addr)
			}
		}
		if err != nil {
			fmt.Printf("设置系统代理失败: %v\n", err)
			os.Exit(1)
		}
	case "pac":
		// 打印当前策略生成的 PAC，方便排查
		strat := builtinStrategy()
		if err := strat.Load(strategyPath()); err == nil {
			logf("已加载 strategy.json")
		}
		fmt.Print(buildPAC(strat, "127.0.0.1:8899"))
	case "unsetproxy":
		if err := ClearSystemProxy(); err != nil {
			fmt.Printf("还原失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("系统代理已还原")
	case "autostart":
		args := "proxy 127.0.0.1:8899"
		if len(os.Args) > 2 {
			args = strings.Join(os.Args[2:], " ")
		}
		if err := InstallAutostart(args); err != nil {
			fmt.Printf("设置自启失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("已设为开机自启")
	case "noautostart":
		if err := UninstallAutostart(); err != nil {
			fmt.Printf("移除自启失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("已移除自启")
	case "check":
		// 经代理实测一批域名：check [域名...]
		addr := "127.0.0.1:8899"
		list := os.Args[2:]
		if len(list) == 0 {
			list = checkTargets
		}
		printCheckAll(addr, list)
	case "probe":
		// 单域名三级判定：DNS / TCP / TLS，并给出是否值得分片的建议
		if len(os.Args) < 3 {
			printUsage()
			return
		}
		for _, d := range os.Args[2:] {
			r := Probe(d, 6*time.Second)
			fmt.Printf("%-36s %-12s %6dms  %s\n", r.Domain, r.Verdict, r.Latency.Milliseconds(), r.ResolvedIP)
			if r.Verdict == SNIBlocked {
				rw := RewriteProbe(d, "www.baidu.com", 6*time.Second)
				fmt.Printf("%-36s 分片后: %-12s %s\n", "", rw.Verdict, rw.Err)
			}
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		printUsage()
	}
}

// printUsage 打印可用子命令。
//
// 端口 8899 同时是 HTTP 代理、SOCKS5 代理和 PAC 服务器：
// SOCKS5 靠首字节 0x05 区分，PAC 靠路径 /proxy.pac 区分，三者不冲突。
func printUsage() {
	fmt.Println(`usage: icefall <command> [args]

  proxy [addr] [upstream]  启动代理（默认 127.0.0.1:8899；upstream 为兜底 HTTP 代理，如 Clash 的 127.0.0.1:7897）
  discover                 探测本机网络封锁情况，生成 strategy.json
  check [domain...]        经本地代理逐个验证站点是否可打开
  pac                      打印生成的 PAC
  setproxy [addr|pac]      设置系统代理（pac 表示走 PAC 自动分流）
  unsetproxy               还原系统代理
  autostart [args...]      写开机自启
  noautostart              取消开机自启

  probe <domain>           单域名三级判定：DNS / TCP / TLS
  cut <domain>             扫单域名的有效分片切点
  frag <domain>            分片可行性测试
  perip <domain>           逐 IP 分片测试

代理端口同时支持：
  HTTP  CONNECT           http://127.0.0.1:8899
  SOCKS5                  socks5://127.0.0.1:8899
  PAC                     http://127.0.0.1:8899/proxy.pac`)
}

// checkTargets 是 check 子命令的默认待测清单：被学校封的、常用国内站、以及境外站。
var checkTargets = []string{
	// 已知被 SNI 封锁
	"www.bilibili.com", "api.bilibili.com", "www.douyin.com", "www.xiaohongshu.com",
	"www.mihoyo.com", "ak.hypergryph.com", "www.wegame.com.cn", "lol.qq.com",
	"api.haimacloud.com", "www.haimacloud.com",
	// 国内常用（对照，应全通）
	"www.baidu.com", "www.zhihu.com", "www.taobao.com", "www.jd.com",
	"weibo.com", "tieba.baidu.com", "i0.hdslb.com",
	// 开发者（对照）
	"github.com", "api.github.com", "pypi.org", "registry.npmjs.org", "raw.githubusercontent.com",
	// 境外
	"www.google.com", "www.youtube.com", "twitter.com", "www.facebook.com",
	"chatgpt.com", "claude.ai", "gemini.google.com",
}

func runProxy() {
	addr := "127.0.0.1:8899"
	if len(os.Args) > 2 {
		addr = os.Args[2]
	}

	p := NewProxy(addr)
	// 上游代理可选：显式传了就转给它，不传就直连。
	// 别人机器上没装 Clash，硬编码默认值会让他所有非分片流量打到空端口上。
	if len(os.Args) > 3 {
		p.Upstream = os.Args[3]
		logf("兜底上游: %s（不在分片名单的流量走这里）", p.Upstream)
	} else {
		logf("兜底上游: 无（不在分片名单的流量直连）")
	}

	// 策略表：内置实测结果 + strategy.json 覆盖
	strat := builtinStrategy()
	if err := strat.Load(filepath.Join(exeDir(), "strategy.json")); err == nil {
		logf("已加载 strategy.json")
	}
	p.Strategy = strat
	// 规则表不再单列一份硬编码名单：modeOf 直接查策略表，
	// 这样 strategy.json 里手工/自动加的域名才会真正生效（之前只影响 PAC，
	// 走 SOCKS5 的客户端根本不读 PAC，就看策略表）。

	// 备份/设置系统代理由 activate.bat 完成：
	// 沙箱环境会按进程树拦截注册表写入，exe 自己写必然 Access is denied。
	// 直接跑 exe 时提示用户用 bat 启动。
	if os.Getenv("SNI_NO_SETPROXY") == "" {
		logf("提示：系统代理未由本程序设置。请用 activate.bat 启动，或手动把系统代理指向 %s", addr)
	}

	// .app 双击会重复启动：已有实例在跑就别抢端口，直接退出。
	if alive, _ := probeSelf(addr); alive {
		logf("已有实例在 %s 运行，本进程退出（系统代理不受影响）", addr)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Println()
	logf("=== 碎冰 v1 (Icefall) ===")
	logf("监听 %s", addr)
	logf("按 Ctrl+C 退出")
	fmt.Println()

	if err := p.Run(ctx); err != nil {
		logf("exited: %v", err)
	}
}

// runFragScan 对每个目标测「单 record vs 分片」的差异。
func runFragScan() {
	fmt.Printf("%-42s %-16s %-16s %s\n", "DOMAIN", "单record", "分片@SNI", "结论")
	fmt.Println("--------------------------------------------------------------------------------------")
	for _, d := range defaultTargets {
		host := "www." + d
		ip := resolveForTest(host)
		if ip == "" {
			ip = resolveForTest(d)
			host = d
		}
		if ip == "" {
			fmt.Printf("%-42s %-16s %-16s %s\n", d, "DNS-FAIL", "-", "-")
			continue
		}

		hello := buildHelloFor(host)
		if hello == nil {
			fmt.Printf("%-42s %-16s %-16s %s\n", host, "NO-HELLO", "-", "-")
			continue
		}

		base := shortVerdict(trySend(ip, hello, 6*time.Second))
		off := sniNameOffset(hello)
		var fragVerdict, concl string
		if off == 0 {
			fragVerdict = "NO-SNI"
			concl = "-"
		} else {
			frag := fragmentHello(hello, off-5)
			fragVerdict = shortVerdict(trySend(ip, frag, 6*time.Second))
			switch {
			case base == "RST" && fragVerdict == "OK":
				concl = "可绕开 (分片)"
			case base == "OK":
				concl = "本来就没封"
			case base == "RST" && fragVerdict == "RST":
				concl = "封得死 (需中转)"
			default:
				concl = "另查"
			}
		}
		fmt.Printf("%-42s %-16s %-16s %s\n", host, base, fragVerdict, concl)
	}
}

func shortVerdict(s string) string {
	switch {
	case len(s) >= 6 && s[:6] == "SERVER":
		return "OK"
	case len(s) >= 5 && s[:5] == "ALERT":
		return "ALERT"
	case len(s) >= 8 && s[:8] == "READ-FAI":
		return "RST"
	case len(s) >= 9 && s[:9] == "DIAL-FAIL":
		return "NO-CONN"
	case len(s) >= 10 && s[:10] == "WRITE-FAIL":
		return "WR-FAIL"
	case s == "EMPTY":
		return "EMPTY"
	}
	return s
}
