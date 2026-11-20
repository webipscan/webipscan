//go:build !windows

package main

import "errors"

// runMbWindow 仅 Windows 支持 miniblink 窗口，其他平台回退到默认浏览器
func runMbWindow(_, _, _ string, _ bool) error {
	return errors.New("miniblink 窗口仅支持 Windows")
}

// prepareMbWindow 非 Windows 平台不存在 mb132_x64.dll 窗口模式
func prepareMbWindow(_ bool) string { return "" }

// setConsoleVisible 非 Windows 平台无需处理
func setConsoleVisible(_ bool) {}
