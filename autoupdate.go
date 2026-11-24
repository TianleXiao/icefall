package main

import (
	"os"
	"time"
)

// autoUpdateCheck 在 proxy / tun 启动时后台查一次新版，有新版本就在日志里提示。
// 只提示不自动装：装了一半换掉 exe 会让正在跑的分片会话断掉，交给用户挑时机。
// 想彻底关掉：设环境变量 ICEFALL_NO_UPDATE=1。
func autoUpdateCheck(upstream string) {
	if os.Getenv("ICEFALL_NO_UPDATE") != "" {
		return
	}
	// version 是 dev 说明是本地 go build，跟 release 比没意义。
	if version == "dev" {
		return
	}
	go func() {
		// 错开启动，别和用户刚打开的第一个页面抢带宽。
		time.Sleep(15 * time.Second)
		rel, err := fetchLatestRelease(upstream)
		if err != nil {
			return
		}
		if !semverLess(version, rel.Tag) {
			return
		}
		logf("发现新版本 %s（当前 %s），运行 icefall update 升级", rel.Tag, version)
	}()
}
