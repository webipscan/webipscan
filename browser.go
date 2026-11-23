package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// openExternalChrome 用外部 Chrome 的新窗口打开地址，并尽量按配置指定窗口尺寸。
// 找不到 Chrome 时回退系统默认浏览器。
func openExternalChrome(url string, size windowSize) error {
	path := findChromePath()
	if path == "" {
		fmt.Println("  未找到外部 Chrome，改用系统默认浏览器")
		return openBrowser(url)
	}
	args := []string{"--new-window"}
	if size.width > 0 && size.height > 0 {
		args = append(args, fmt.Sprintf("--window-size=%d,%d", size.width, size.height))
	}
	args = append(args, url)
	return exec.Command(path, args...).Start()
}

// findChromePath 在常见安装位置与 PATH 中查找 Chrome 可执行文件。
func findChromePath() string {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		for _, env := range []string{"LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
			if dir := os.Getenv(env); dir != "" {
				candidates = append(candidates, filepath.Join(dir, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
	case "darwin":
		candidates = append(candidates,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			filepath.Join(os.Getenv("HOME"), "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	for _, name := range []string{"chrome", "chrome.exe", "google-chrome-stable", "google-chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
