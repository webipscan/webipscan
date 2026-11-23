//go:build !windows

package main

// runMpvPlayerProcess 非 Windows 平台没有 libmpv 播放器子进程。
func runMpvPlayerProcess(_, _ string) {}
