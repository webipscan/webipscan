//go:build !windows

package main

import "errors"

// startMpvPlayer 仅 Windows 支持在当前进程用 libmpv 打开播放窗口。
func startMpvPlayer(_, _ string) error {
	return errors.New("libmpv 播放器仅支持 Windows")
}

// waitMpvWindowsClosed 非 Windows 平台没有 libmpv 窗口。
func waitMpvWindowsClosed() {}
