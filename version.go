package main

// AppVersion 文件版本，可通过构建参数注入：
//
//	go build -ldflags="-s -w -X main.AppVersion=1.2.3" -o ipscan.exe .
//
// 若 exe 带有 Windows 版本资源，则优先使用资源中的真实文件版本。
var AppVersion = "1.0.4"
