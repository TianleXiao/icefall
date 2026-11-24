package main

// exec.go —— 跨平台的外部命令执行。

import (
	"os/exec"
	"strings"
)

// runCmd 跑一条外部命令，返回合并后的输出。
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
