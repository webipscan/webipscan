//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// mbExpectedSHA256 是随程序分发的 mb132_x64.dll 的 SHA256，用于判断是否需要重新释放
	mbExpectedSHA256 = "ae797512d56c3482119d279c4a4d3e016dc4974112c659c4df2652cd4e24cb40"
	mbArchivePath    = "static/mb132_x64.7z"
	mb7zrPath        = "static/7zr.exe"
	mbDllName        = "mb132_x64.dll"

	// CREATE_NO_WINDOW：避免解压工具闪出控制台窗口
	createNoWindow = 0x08000000
)

// fileSHA256 计算文件的 SHA256（小写 hex）
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ensureMbDll 确保运行时目录下存在哈希正确的 mb132_x64.dll。
// 用户模式下该目录为 %USERPROFILE%\webipscan，否则为 exe 所在目录。
// 文件缺失或哈希不符时，从内嵌的 7z 资源解压覆盖；成功返回 DLL 绝对路径。
func ensureMbDll() (string, error) {
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return "", fmt.Errorf("创建运行文件目录 %s 失败：%w", runtimeDir, err)
	}
	dllPath := filepath.Join(runtimeDir, mbDllName)

	if sum, err := fileSHA256(dllPath); err == nil && sum == mbExpectedSHA256 {
		return dllPath, nil
	}

	if err := extractMbDll(runtimeDir, dllPath); err != nil {
		return "", err
	}
	return dllPath, nil
}

// extractMbDll 从 embed 资源释放 7z 到临时文件，解压到 destDir，并校验结果
func extractMbDll(destDir, dllPath string) error {
	data, err := staticFS.ReadFile(mbArchivePath)
	if err != nil {
		return fmt.Errorf("读取内嵌 %s 失败：%w", mbArchivePath, err)
	}

	tmp, err := os.CreateTemp(destDir, "mb132-*.7z")
	if err != nil {
		return fmt.Errorf("在目录 %s 创建临时压缩包失败：%w", destDir, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入临时压缩包失败：%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时压缩包失败：%w", err)
	}

	if err := unzipMbArchive(tmpPath, destDir); err != nil {
		return err
	}

	sum, err := fileSHA256(dllPath)
	if err != nil {
		return fmt.Errorf("校验解压后的 DLL 失败：%w", err)
	}
	if sum != mbExpectedSHA256 {
		return fmt.Errorf("解压后的 DLL 哈希不符：%s（期望 %s）", sum, mbExpectedSHA256)
	}
	return nil
}

// unzipMbArchive 从 embed 资源释放 7zr.exe，把压缩包中的 mb132_x64.dll 解压到目标目录。
// 无论成功或失败，返回前都会清理传入的临时压缩包和临时 7zr.exe。
func unzipMbArchive(archive, dest string) error {
	defer os.Remove(archive)

	data, err := staticFS.ReadFile(mb7zrPath)
	if err != nil {
		return fmt.Errorf("读取内嵌 %s 失败：%w", mb7zrPath, err)
	}

	tmp, err := os.CreateTemp(dest, "7zr-*.exe")
	if err != nil {
		return fmt.Errorf("创建临时 7zr.exe 失败：%w", err)
	}
	sevenZr := tmp.Name()
	defer os.Remove(sevenZr)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入临时 7zr.exe 失败：%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时 7zr.exe 失败：%w", err)
	}

	cmd := exec.Command(sevenZr, "x", "-y", "-o"+dest, archive, mbDllName)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("7zr.exe 解压失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}
	return nil
}
