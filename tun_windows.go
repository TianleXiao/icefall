//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	tunIfaceName = "Icefall"
	tunIfaceType = "Icefall"
	tunLocalIP   = "10.7.0.1"
	tunMask      = "255.255.255.0"
	tunRingCap   = 0x400000 // 4MB 环形缓冲
	ifOperUp     = 1

	gaaSkipAnycast   = 0x0002
	gaaSkipMulticast = 0x0004
	gaaSkipDNSServer = 0x0008
	gaaIncludeGateway = 0x0080
)

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func cmdOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ensureWintunDLL：wintun 是懒加载的（LoadLibraryEx + APPLICATION_DIR|SYSTEM32），
// 所以 exe 同目录放一份 dll 就行，不必进 System32。本机 Tailscale/迅游都带这个 dll。
func ensureWintunDLL() error {
	for _, p := range []string{
		filepath.Join(exeDir(), "wintun.dll"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "wintun.dll"),
	} {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return nil
		}
	}
	for _, src := range []string{
		`C:\Program Files\Tailscale\wintun.dll`,
		`C:\Program Files (x86)\xunyou\wintun.dll`,
		`C:\Program Files (x86)\WireGuard\wintun.dll`,
		`C:\Program Files\WireGuard\wintun.dll`,
	} {
		b, err := os.ReadFile(src)
		if err == nil && len(b) > 0 {
			dst := filepath.Join(exeDir(), "wintun.dll")
			if err := os.WriteFile(dst, b, 0o644); err != nil {
				return err
			}
			logf("已复制 %s → %s", src, dst)
			return nil
		}
	}
	return fmt.Errorf("找不到 wintun.dll，请手动复制一份到 %s", exeDir())
}

// physicalIfIndex 找有默认网关且已连上的物理网卡索引。
func physicalIfIndex() uint32 {
	size := uint32(16384)
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		rc := windows.GetAdaptersAddresses(windows.AF_INET,
			gaaSkipAnycast|gaaSkipMulticast|gaaSkipDNSServer|gaaIncludeGateway, 0, aa, &size)
		if rc == nil {
			for a := aa; a != nil; a = a.Next {
				if a.OperStatus != ifOperUp || a.FirstGatewayAddress == nil {
					continue
				}
				return a.IfIndex
			}
			return 0
		}
		if rc != windows.ERROR_BUFFER_OVERFLOW {
			logf("枚举网卡失败: %v", rc)
			return 0
		}
	}
	return 0
}

// setupTunNet 给新建的网卡配 IP/MTU 并改路由。
// 不改 0.0.0.0/0，而是抢两条 /1（0.0.0.0/1 与 128.0.0.0/1）：
// 它们合起来覆盖整个 IPv4，却比默认路由更具体，同时退出时好删干净。
func setupTunNet() error {
	if _, err := cmdOut("netsh", "interface", "ipv4", "set", "address",
		"name="+tunIfaceName, "static", tunLocalIP, tunMask); err != nil {
		return fmt.Errorf("设置网卡 IP 失败（管理员权限？）: %v", err)
	}
	cmdOut("netsh", "interface", "ipv4", "set", "subinterface", tunIfaceName,
		"mtu="+strconv.Itoa(tunMTU), "store=active")
	for _, pfx := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if out, err := cmdOut("netsh", "interface", "ipv4", "add", "route",
			"prefix="+pfx, "interface="+tunIfaceName, "nexthop=0.0.0.0",
			"metric=1", "store=active"); err != nil {
			return fmt.Errorf("加路由 %s 失败: %v %s", pfx, err, out)
		}
	}
	return nil
}

func cleanupTunNet() {
	for _, pfx := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		cmdOut("netsh", "interface", "ipv4", "delete", "route",
			"prefix="+pfx, "interface="+tunIfaceName, "store=active")
	}
	logf("已撤回 TUN 路由")
}

func readTunPacket(sess wintun.Session, buf []byte) (int, error) {
	ev := sess.ReadWaitEvent()
	for {
		pkt, err := sess.ReceivePacket()
		if err == nil && len(pkt) > 0 {
			n := copy(buf, pkt)
			sess.ReleaseReceivePacket(pkt)
			return n, nil
		}
		windows.WaitForSingleObject(ev, 500)
	}
}

func writeTunPacket(sess wintun.Session, pkt []byte) {
	out, err := sess.AllocateSendPacket(len(pkt))
	if err != nil {
		return // 环形缓冲满就丢，TCP 有重传兜底
	}
	copy(out, pkt)
	sess.SendPacket(out)
}

func udpDialDirect(ip string, port int) (net.Conn, error) {
	return newDialer(5 * time.Second).Dial("udp", net.JoinHostPort(ip, strconv.Itoa(port)))
}

// runTun：整机流量进 TUN，用户态栈拿到完整明文（含 SNI），按策略表分片或走上游。
// 这样不读系统代理的程序（微信客户端、游戏、云游戏）也能生效。
func runTun() {
	if !isAdmin() {
		fmt.Println("TUN 模式需要管理员权限：右键 activate-tun.bat →「以管理员身份运行」。")
		return
	}
	addr, up := "127.0.0.1:8899", ""
	if len(os.Args) > 2 {
		addr = os.Args[2]
	}
	if len(os.Args) > 3 {
		up = os.Args[3]
	}

	if err := ensureWintunDLL(); err != nil {
		logf("%v", err)
		return
	}
	if idx := physicalIfIndex(); idx != 0 {
		atomic.StoreUint32(&bypassIf, idx)
	} else {
		logf("警告：没找到带网关的物理网卡，自身出站可能被 TUN 吃进去形成自环")
	}
	logf("物理网卡索引: %d（自身出站绑它，避免自环）", atomic.LoadUint32(&bypassIf))

	adapter, err := wintun.CreateAdapter(tunIfaceName, tunIfaceType, nil)
	if err != nil {
		logf("创建 TUN 网卡失败: %v", err)
		return
	}
	defer adapter.Close()

	if err := setupTunNet(); err != nil {
		logf("%v", err)
		return
	}
	defer cleanupTunNet()

	sess, err := adapter.StartSession(tunRingCap)
	if err != nil {
		logf("启动 TUN 会话失败: %v", err)
		return
	}
	defer sess.End()

	p := setupProxy(addr, up)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Println()
	logf("=== 碎冰 v1 (Icefall) TUN 模式 ===")
	logf("网卡 %s  地址 %s  MTU %d", tunIfaceName, tunLocalIP, tunMTU)
	logf("本机代理仍在 %s（HTTP / SOCKS5 / PAC 都能用）", addr)
	logf("按 Ctrl+C 退出（会自动撤回路由）")
	fmt.Println()

	go func() {
		if err := p.Run(ctx); err != nil {
			logf("代理监听退出: %v", err)
		}
	}()

	st := NewStack(
		func(pkt []byte) { writeTunPacket(sess, pkt) },
		p.dialForTun,
		udpDialDirect,
	)
	runTunLoop(func(b []byte) (int, error) { return readTunPacket(sess, b) }, st)
}

// cleanTun 清残留路由：进程被 taskkill 强杀时 defer 不会跑，
// 两条 /1 路由留在表里会让整机断网，必须有单独的命令来收拾。
func cleanTun() {
	if !isAdmin() {
		fmt.Println("需要管理员权限：右键 stop-tun.bat →「以管理员身份运行」。")
		return
	}
	cleanupTunNet()
	fmt.Println("已清理 TUN 路由。若仍无网络，检查 ipconfig 确认默认网关还在。")
}
