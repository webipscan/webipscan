//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// processRunningByName 扫描 /proc 中的进程名，不调用 pgrep 等外部程序。
// 无 /proc 的平台返回 false。
func processRunningByName(names ...string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(data))
		for _, want := range names {
			if strings.EqualFold(comm, want) {
				return true
			}
		}
	}
	return false
}

// watchAria2cChild 非 Windows 平台没有 Job 对象，由 exitMain 统一关闭子进程。
func watchAria2cChild(cmd *exec.Cmd) func() {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return func() { _ = cmd.Process.Kill() }
}
