//go:build windows

package main

// sysproxy_windows.go —— Windows 的系统代理设置与开机自启。
//
// 系统代理走 WinINet 注册表；开机自启写启动文件夹的 vbs（无窗口）。

import (
	"fmt"
	"os"
	"path/filepath"
)

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// SaveBackup 把当前 Internet Settings 导出成 proxy-backup.reg，便于还原。
func SaveBackup() error {
	p := filepath.Join(exeDir(), "proxy-backup.reg")
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	out, err := runCmd("reg", "export", "HKCU\\"+regPath, p, "/y")
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// SetSystemProxy 开启系统代理。
//
// 用 reg.exe 而非 registry 包：受限环境（沙箱/低权限令牌）下
// KEY_SET_VALUE 会被拒，reg.exe 走完整令牌能成功。
func SetSystemProxy(addr string) error {
	if err := regAdd("ProxyServer", "REG_SZ", addr); err != nil {
		return fmt.Errorf("ProxyServer: %w", err)
	}
	regAdd("ProxyOverride", "REG_SZ", "localhost;127.*;10.*;192.168.*;172.16.*;<local>")
	return regAdd("ProxyEnable", "REG_DWORD", "1")
}

// SetSystemPAC 用 PAC 自动代理（AutoConfigURL），比固定代理更细：
// 只有策略表里的域名走 8899，其余直连。
func SetSystemPAC(url string) error {
	if err := regAdd("AutoConfigURL", "REG_SZ", url); err != nil {
		return fmt.Errorf("AutoConfigURL: %w", err)
	}
	return regAdd("ProxyEnable", "REG_DWORD", "0")
}

// ClearSystemProxy 关闭系统代理（固定和 PAC 都关）。
func ClearSystemProxy() error {
	// AutoConfigURL 可能不存在，删失败无所谓
	runCmd("reg", "delete", "HKCU\\"+regPath, "/v", "AutoConfigURL", "/f")
	return regAdd("ProxyEnable", "REG_DWORD", "0")
}

func regAdd(name, typ, value string) error {
	out, err := runCmd("reg", "add", "HKCU\\"+regPath, "/v", name, "/t", typ, "/d", value, "/f")
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// InstallAutostart 把当前 exe 写进用户启动文件夹的 vbs（无窗口启动）。
func InstallAutostart(args string) error {
	dir := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	vbs := fmt.Sprintf(
		"Set s = CreateObject(\"WScript.Shell\")\r\ns.Run Chr(34) & \"%s\" & Chr(34) & \" %s\", 0, False\r\n",
		exe, args)
	return os.WriteFile(filepath.Join(dir, "Icefall.vbs"), []byte(vbs), 0o644)
}

// UninstallAutostart 删掉自启项。
func UninstallAutostart() error {
	p := filepath.Join(os.Getenv("APPDATA"),
		`Microsoft\Windows\Start Menu\Programs\Startup\Icefall.vbs`)
	if _, err := os.Stat(p); err == nil {
		return os.Remove(p)
	}
	return nil
}
