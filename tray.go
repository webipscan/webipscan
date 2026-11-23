package main

// trayConfig 托盘菜单命令所需的运行时信息。
type trayConfig struct {
	homeURL      string
	clipboardURL string
	aria2cURL    string
	tools        []toolEntry
	version      string
	mbDLL        string // 可用的 mb132_x64.dll 路径；为空时回退系统浏览器
}
