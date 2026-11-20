package main

import (
	"os/exec"
	"runtime"
)

// openBrowser 用系统默认浏览器打开地址。
// Windows 下走 rundll32，相比 cmd /c start 不会闪出控制台黑框。
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
