package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const (
	sunloginExeName     = "SunloginSOS_1.2.1.61234_x64.exe"
	sunloginDownloadURL = "https://d-cdn.oray.com/sunlogin/windows/" + sunloginExeName
)

var sunloginMu sync.Mutex

func sunloginLog(format string, args ...any) {
	fmt.Printf("[sunlogin %s] %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// sunloginDataDir 返回向日葵 SOS 的存放目录，与播放器 DLL、虚拟内网共用用户目录。
func sunloginDataDir() string {
	if p, err := userDataRoot(); err == nil && p != "" {
		return p
	}
	return runtimeDir
}

// sunloginInstalled 判断用户目录中是否已存在向日葵 SOS 可执行文件。
func sunloginInstalled(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, sunloginExeName))
	return err == nil && !st.IsDir()
}

// ensureSunloginSOS 先确保 aria2c RPC 就绪，下载到用户目录的 .aria2c 中，
// 再复制到用户目录；已存在可执行文件时直接返回其路径。
func ensureSunloginSOS(pageURL string) (string, error) {
	sunloginMu.Lock()
	defer sunloginMu.Unlock()

	dir := sunloginDataDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("创建目录 %s 失败：%w", dir, err)
	}
	exePath := filepath.Join(dir, sunloginExeName)
	if sunloginInstalled(dir) {
		return exePath, nil
	}

	downloadDir := filepath.Join(dir, ".aria2c")
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return "", fmt.Errorf("创建下载目录 %s 失败：%w", downloadDir, err)
	}

	ensureAria2cFromURL(pageURL)
	if err := waitAria2RPC(mpvRPCWaitTimeout); err != nil {
		return "", err
	}

	downloaded := filepath.Join(downloadDir, sunloginExeName)
	sunloginLog("开始下载：%s", sunloginDownloadURL)
	if err := aria2cRPCDownloadAs(sunloginDownloadURL, downloaded, downloadDir, sunloginExeName); err != nil {
		return "", err
	}

	tmpPath := exePath + ".tmp"
	src, err := os.Open(downloaded)
	if err != nil {
		return "", err
	}
	dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		_ = src.Close()
		return "", err
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	_ = src.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", closeErr
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("复制到 %s 失败：%w", exePath, err)
	}
	sunloginLog("已就绪：%s", exePath)
	return exePath, nil
}

// startSunloginSOS 启动用户目录中的向日葵 SOS。
func startSunloginSOS(exe string) error {
	cmd := exec.Command(exe)
	cmd.Dir = filepath.Dir(exe)
	return cmd.Start()
}
