package main

// paths.go —— 跨平台路径工具。

import (
	"os"
	"path/filepath"
)

// exeDir 返回可执行文件所在目录。
//
// 策略表、日志、备份都放这里，保证整个程序是「绿色」的：
// 解压到哪就在哪工作，卸载就是删目录。
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	// macOS/Linux 上可能经过符号链接，解到真实路径
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Dir(exe)
}

// strategyPath 返回策略表路径。
func strategyPath() string {
	return filepath.Join(exeDir(), "strategy.json")
}
