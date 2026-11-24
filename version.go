package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// version 由构建时的 -ldflags "-X main.version=x.y.z" 注入；go run / go build 默认值。
var version = "dev"

// buildStamp 同理，记构建时间，方便判断本地跑的是哪个包。
var buildStamp = ""

// releaseRepo 是分发仓库，update 从这里查最新 tag。
const releaseRepo = "TianleXiao/icefall"

// exeAssetName 是各平台在 release 里对应的资产名。
func exeAssetName() string {
	switch runtime.GOOS {
	case "darwin":
		return "icefall-darwin-" + runtime.GOARCH
	default:
		return "icefall.exe"
	}
}

// versionString 是给人看的版本串。
func versionString() string {
	s := version
	if buildStamp != "" {
		s += " (" + buildStamp + ")"
	}
	return s + " " + runtime.GOOS + "/" + runtime.GOARCH
}

// releaseInfo 是 GitHub release 的最小字段集。
type releaseInfo struct {
	Tag    string `json:"tag_name"`
	Name   string `json:"name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// fetchLatestRelease 查最新 release。github.com 在部分网络下被墙，但 api.github.com 通常可达；
// 都不可达就走已配置的上游代理。
func fetchLatestRelease(upstream string) (*releaseInfo, error) {
	u := "https://api.github.com/repos/" + releaseRepo + "/releases/latest"
	client := &http.Client{Timeout: 15 * time.Second}
	if upstream != "" {
		client.Transport = &http.Transport{Proxy: http.ProxyURL(mustURL("http://" + upstream))}
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "icefall-updater/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("GitHub 返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var r releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// semverLess 比较 a、b 两个版本号（去掉 v 前缀，按数字段比较）。a<b 返回 true。
func semverLess(a, b string) bool {
	pa := splitVer(a)
	pb := splitVer(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

func splitVer(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	// 只取到第一个非数字非点的字符（如 v1.2.0-rc1 的 -rc1）
	if i := strings.IndexFunc(s, func(r rune) bool {
		return (r < '0' || r > '9') && r != '.'
	}); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}

// runUpdate 处理 icefall update [--check] [upstream]。
// 换 exe 用「改名 → 下载 → 覆盖」三步，因为 Windows 上正在运行的 exe 不能直接写。
func runUpdate(args []string) {
	checkOnly := false
	upstream := ""
	for _, a := range args {
		if a == "--check" || a == "-c" {
			checkOnly = true
		} else {
			upstream = a
		}
	}

	rel, err := fetchLatestRelease(upstream)
	if err != nil {
		fmt.Printf("检查更新失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("当前版本: %s\n", versionString())
	fmt.Printf("最新版本: %s\n", rel.Tag)

	if !semverLess(version, rel.Tag) {
		fmt.Println("已是最新，无需更新。")
		return
	}
	if checkOnly {
		fmt.Println("有新版本，运行 icefall update 即可升级。")
		return
	}

	want := exeAssetName()
	var url string
	var size int64
	for _, a := range rel.Assets {
		if a.Name == want {
			url, size = a.URL, a.Size
			break
		}
	}
	if url == "" {
		fmt.Printf("release %s 里没有 %s，可能该平台还没打包。\n", rel.Tag, want)
		os.Exit(1)
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Printf("定位自身失败: %v\n", err)
		os.Exit(1)
	}
	self, _ = filepath.EvalSymlinks(self)

	tmp := self + ".new"
	fmt.Printf("下载 %s (%d 字节)...\n", want, size)
	if err := downloadFile(url, tmp, upstream); err != nil {
		os.Remove(tmp)
		fmt.Printf("下载失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		fmt.Printf("设置权限失败（macOS 可能可以忽略）: %v\n", err)
	}

	// Windows 不能覆盖正在运行的文件，但能改名。当前进程继续用旧映像跑完，下次启动就是新的。
	if runtime.GOOS == "windows" {
		bak := self + ".old"
		os.Remove(bak)
		if err := os.Rename(self, bak); err != nil {
			os.Remove(tmp)
			fmt.Printf("替换失败（旧文件改名不成）: %v\n", err)
			os.Exit(1)
		}
		if err := os.Rename(tmp, self); err != nil {
			os.Rename(bak, self) // 回滚
			fmt.Printf("替换失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("已更新到 %s。请重启 Icefall 生效（%s 可以删）。\n", rel.Tag, filepath.Base(bak))
		return
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		fmt.Printf("替换失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已更新到 %s。重启 Icefall 生效。\n", rel.Tag)
}

// downloadFile 下载并写盘，同时打印进度百分比。
func downloadFile(url, dst, upstream string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	if upstream != "" {
		client.Transport = &http.Transport{Proxy: http.ProxyURL(mustURL("http://" + upstream))}
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "icefall-updater/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	total := resp.ContentLength
	var got int64
	buf := make([]byte, 64*1024)
	lastPct := -1
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			got += int64(n)
			if total > 0 {
				if pct := int(got * 100 / total); pct != lastPct && pct%10 == 0 {
					fmt.Printf("  %d%%\n", pct)
					lastPct = pct
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return f.Sync()
}

// fileSHA256 算文件摘要，给 --check 用不上，但排查「下载坏没坏」时用。
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
