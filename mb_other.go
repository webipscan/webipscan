//go:build !windows

package main

import "errors"

// startMbWindow 仅 Windows 支持 miniblink 窗口，其他平台回退到默认浏览器。
func startMbWindow(_, _, _ string, _ bool) error {
	return errors.New("miniblink 窗口仅支持 Windows")
}

// openMbWindow 仅 Windows 支持从托盘打开内嵌内核窗口。
func openMbWindow(_, _, _ string, _ bool) error {
	return errors.New("miniblink 窗口仅支持 Windows")
}

// mbAllClosed 非 Windows 平台没有 miniblink 会话，返回永不关闭的通道。
func mbAllClosed() <-chan struct{} { return nil }

// prepareMbWindow 非 Windows 平台不存在 mb132_x64.dll 窗口模式。
func prepareMbWindow(_ bool) string { return "" }

// setConsoleVisible 非 Windows 平台无需处理。
func setConsoleVisible(_ bool) {}
