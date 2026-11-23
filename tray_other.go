//go:build !windows

package main

// startTrayIfDesktop 非 Windows 平台没有系统托盘，直接返回 false。
func startTrayIfDesktop(_ trayConfig) bool { return false }

// trayActive 非 Windows 平台没有系统托盘。
func trayActive() bool { return false }

// stopTrayIfActive 非 Windows 平台没有系统托盘，无需清理。
func stopTrayIfActive() {}
