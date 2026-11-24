//go:build darwin

package main

// sysproxy_darwin.go —— macOS 的系统代理设置与开机自启。
//
// macOS 没有全局代理注册表，代理是「按网络服务（Wi-Fi、Ethernet…）」
// 分别配置的，用 networksetup 命令操作。开机自启走 LaunchAgents plist。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const launchLabel = "com.icefall.proxy"

// backupPath 记住原始代理状态，退出时还原。
func backupPath() string { return filepath.Join(exeDir(), "proxy-backup.json") }

// svcState 是一个网络服务的原始代理状态。
type svcState struct {
	Service string `json:"service"`
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
}

// listServices 列出所有启用的网络服务。
//
// `networksetup -listallnetworkservices` 第一行是说明文字，
// 禁用的服务名前缀 `*`，都要跳过。
func listServices() []string {
	out, err := runCmd("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var svcs []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" {
			continue
		}
		if strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs
}

// getProxy 读某个服务的网页代理状态。
func getProxy(svc string) svcState {
	st := svcState{Service: svc}
	out, _ := runCmd("networksetup", "-getsecurewebproxy", svc)
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			st.Enabled = strings.EqualFold(v, "Yes")
		case "Server":
			st.Server = v
		case "Port":
			fmt.Sscanf(v, "%d", &st.Port)
		}
	}
	return st
}

// SaveBackup 记录当前所有网络服务的代理状态。
func SaveBackup() error {
	if _, err := os.Stat(backupPath()); err == nil {
		return nil
	}
	var states []svcState
	for _, svc := range listServices() {
		states = append(states, getProxy(svc))
	}
	b, _ := json.MarshalIndent(states, "", "  ")
	return os.WriteFile(backupPath(), b, 0o644)
}

// SetSystemProxy 在所有网络服务上开启 HTTP/HTTPS 代理。
func SetSystemProxy(addr string) error {
	host, port, ok := strings.Cut(addr, ":")
	if !ok {
		return fmt.Errorf("bad addr %q, want host:port", addr)
	}
	svcs := listServices()
	if len(svcs) == 0 {
		return fmt.Errorf("no network service found")
	}
	var firstErr error
	for _, svc := range svcs {
		for _, cmd := range [][]string{
			{"-setwebproxy", svc, host, port},
			{"-setsecurewebproxy", svc, host, port},
			{"-setproxybypassdomains", svc, "localhost", "127.0.0.1", "*.local", "10.*", "192.168.*", "172.16.*"},
			{"-setwebproxystate", svc, "on"},
			{"-setsecurewebproxystate", svc, "on"},
		} {
			if out, err := runCmd("networksetup", cmd...); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s: %v %s", svc, err, out)
			}
		}
	}
	return firstErr
}

// SetSystemPAC 用 PAC 自动代理。
//
// 比固定代理细：只有策略表里的域名走本机代理，其余 DIRECT。
// 代价是多一次 PAC 下载和脚本求值，但换来的是不相关流量不绕道。
func SetSystemPAC(url string) error {
	svcs := listServices()
	if len(svcs) == 0 {
		return fmt.Errorf("no network service found")
	}
	var firstErr error
	for _, svc := range svcs {
		for _, cmd := range [][]string{
			{"-setautoproxyurl", svc, url},
			{"-setautoproxystate", svc, "on"},
			{"-setwebproxystate", svc, "off"},
			{"-setsecurewebproxystate", svc, "off"},
		} {
			if out, err := runCmd("networksetup", cmd...); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s: %v %s", svc, err, out)
			}
		}
	}
	return firstErr
}

// ClearSystemProxy 还原：把备份里的状态重新应用，没有备份就全关。
func ClearSystemProxy() error {
	var states []svcState
	if b, err := os.ReadFile(backupPath()); err == nil {
		json.Unmarshal(b, &states)
	}
	bySvc := map[string]svcState{}
	for _, s := range states {
		bySvc[s.Service] = s
	}

	for _, svc := range listServices() {
		runCmd("networksetup", "-setautoproxystate", svc, "off")
		if st, ok := bySvc[svc]; ok && st.Enabled && st.Server != "" {
			runCmd("networksetup", "-setsecurewebproxy", svc, st.Server, fmt.Sprint(st.Port))
			runCmd("networksetup", "-setsecurewebproxystate", svc, "on")
			continue
		}
		runCmd("networksetup", "-setwebproxystate", svc, "off")
		runCmd("networksetup", "-setsecurewebproxystate", svc, "off")
	}
	return nil
}

// xmlEscape 转义 plist 里不能出现的字符（路径可能含 & < >）。
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// InstallAutostart 写 LaunchAgent，登录时自动启动代理。
func InstallAutostart(args string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	argv := []string{exe}
	argv = append(argv, strings.Fields(args)...)
	var sb strings.Builder
	for _, a := range argv {
		fmt.Fprintf(&sb, "    <string>%s</string>\n", xmlEscape(a))
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, launchLabel, sb.String(),
		xmlEscape(filepath.Join(exeDir(), "proxy.log")),
		xmlEscape(filepath.Join(exeDir(), "proxy.log")))

	p := filepath.Join(dir, launchLabel+".plist")
	return os.WriteFile(p, []byte(plist), 0o644)
}

// UninstallAutostart 卸载 LaunchAgent。
func UninstallAutostart() error {
	p := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", launchLabel+".plist")
	runCmd("launchctl", "unload", p)
	if _, err := os.Stat(p); err == nil {
		return os.Remove(p)
	}
	return nil
}
