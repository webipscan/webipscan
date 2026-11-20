package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// whoHoldsPort 查出占用指定端口的进程，返回可读描述。
// 仅在端口绑定失败时调用，用于告诉用户"是谁占了"，失败时返回空串（不影响主流程）。
func whoHoldsPort(port string) string {
	switch runtime.GOOS {
	case "windows":
		return windowsPortHolder(port)
	default:
		return unixPortHolder(port)
	}
}

// windowsPortHolder 解析 netstat -ano 的 LISTENING 行
func windowsPortHolder(port string) string {
	out, err := exec.Command("netstat", "-ano", "-p", "tcp").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		up := strings.ToUpper(line)
		if !strings.Contains(up, "LISTEN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// 本地地址形如 0.0.0.0:8080 或 [::]:8080
		if !strings.HasSuffix(fields[1], ":"+port) {
			continue
		}
		pid := fields[len(fields)-1]
		if name := windowsProcessName(pid); name != "" {
			return fmt.Sprintf("PID %s (%s)", pid, name)
		}
		return "PID " + pid
	}
	return ""
}

// windowsProcessName 用 tasklist 反查进程名
func windowsProcessName(pid string) string {
	out, err := exec.Command("tasklist", "/FI", "PID eq "+pid, "/NH", "/FO", "CSV").Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if strings.HasPrefix(line, "INFO:") || line == "" {
		return ""
	}
	parts := strings.Split(line, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.Trim(parts[0], `"`)
}

// unixPortHolder 用 lsof 查询（macOS / Linux）
func unixPortHolder(port string) string {
	out, err := exec.Command("lsof", "-nP", "-iTCP:"+port, "-sTCP:LISTEN").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return ""
	}
	f := strings.Fields(lines[1])
	if len(f) >= 2 {
		return fmt.Sprintf("PID %s (%s)", f[1], f[0])
	}
	return ""
}
