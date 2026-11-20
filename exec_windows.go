//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// hideWindow 隐藏子进程窗口，避免扫描时闪烁命令行黑框
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
