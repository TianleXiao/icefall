//go:build !windows

package main

import "fmt"

// TUN 模式依赖 wintun 与 Windows 路由表；macOS 侧走 NetworkExtension 或系统代理。
func runTun() {
	fmt.Println("TUN 模式仅支持 Windows。macOS 请用 activate.command / setproxy pac。")
}

func cleanTun() {
	fmt.Println("仅 Windows 需要清理 TUN 路由。")
}
