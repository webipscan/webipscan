package main

import (
	"bytes"
	"debug/pe"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	mpvDllName         = "libmpv-2.dll"
	mpvArchiveName     = "mpv-dev.7z"
	mpv7zrPath         = "static/7zr.exe"
	mpvImageFileDLL    = 0x2000
	mpvRPCWaitTimeout  = 5 * time.Second
	mpvDownloadTimeout = 15 * time.Minute
)

// mpvRPCURL 为 aria2c RPC 地址，测试时可替换。
var mpvRPCURL = "http://127.0.0.1:" + aria2cRPCPort + "/jsonrpc"

// mpvDownloadURLs 摘自 links.txt：原站与三个镜像，按顺序尝试直到下载成功。
var mpvDownloadURLs = []string{
	"https://gh-proxy.com/github.com/zhongfly/mpv-winbuild/releases/download/2026-11-22-da09f092ad/mpv-dev-x86_64-v3-20261122-git-da09f092ad.7z",
	"https://gh-proxy.org/github.com/zhongfly/mpv-winbuild/releases/download/2026-11-22-da09f092ad/mpv-dev-x86_64-v3-20261122-git-da09f092ad.7z",
	"https://ghfast.top/github.com/zhongfly/mpv-winbuild/releases/download/2026-11-22-da09f092ad/mpv-dev-x86_64-v3-20261122-git-da09f092ad.7z",
	"https://github.com/zhongfly/mpv-winbuild/releases/download/2026-11-22-da09f092ad/mpv-dev-x86_64-v3-20261122-git-da09f092ad.7z",
}

var mpvMu sync.Mutex

func mpvLog(format string, args ...any) {
	fmt.Printf("[mpv %s] %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// playerFileSize 把字节数格式化为可读大小，供播放器日志与下载进度共用。
func playerFileSize(n int64) string {
	if n < 0 {
		return "未知"
	}
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// validMpvDLL 检查文件是否为有效的 x64 PE DLL；文件大小与 PE 头都要正常。
func validMpvDLL(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() < 64*1024 {
		return false
	}
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || f.Characteristics&mpvImageFileDLL == 0 {
		return false
	}
	return true
}

// mpvDataDir 返回 libmpv-2.dll 的存放目录：用户模式下为 %USERPROFILE%\webipscan。
func mpvDataDir() string {
	if p, err := userDataRoot(); err == nil && p != "" {
		return p
	}
	return runtimeDir
}

// ensureMpvDLL 确保用户目录中存在可用的 libmpv-2.dll。
// pageURL 为当前可用的 AriaNg 页面地址：先确保该页面的 aria2c RPC 就绪，再通过 JSON-RPC 提交下载。
func ensureMpvDLL(pageURL string) (string, error) {
	mpvMu.Lock()
	defer mpvMu.Unlock()

	dir := mpvDataDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("创建目录 %s 失败：%w", dir, err)
	}
	dllPath := filepath.Join(dir, mpvDllName)
	if validMpvDLL(dllPath) {
		return dllPath, nil
	}
	mpvLog("%s 缺失或不是有效的 x64 DLL，准备下载", dllPath)

	ensureAria2cFromURL(pageURL)
	if err := waitAria2RPC(mpvRPCWaitTimeout); err != nil {
		return "", err
	}

	tmpDir, err := os.MkdirTemp("", "ipscan-mpv-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)
	archive := filepath.Join(tmpDir, mpvArchiveName)

	var lastErr error
	for i, u := range mpvDownloadURLs {
		mpvLog("下载第 %d/%d 个地址：%s", i+1, len(mpvDownloadURLs), u)
		if err := aria2cRPCDownload(u, archive, tmpDir); err != nil {
			lastErr = err
			mpvLog("下载失败：%v", err)
			continue
		}
		if err := extractMpvDLL(archive, dllPath); err != nil {
			lastErr = err
			mpvLog("解压失败：%v", err)
			continue
		}
		if validMpvDLL(dllPath) {
			mpvLog("已就绪：%s", dllPath)
			return dllPath, nil
		}
		lastErr = fmt.Errorf("解压得到的 %s 不是有效的 x64 DLL", dllPath)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有配置下载地址")
	}
	return "", lastErr
}

// aria2RPCRequest / aria2RPCResponse 是 aria2c JSON-RPC 的最小信封结构。
type aria2RPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params,omitempty"`
}

type aria2RPCResponse struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// aria2RPC 向本机 aria2c RPC 发送一次 JSON-RPC 请求。
func aria2RPC(method string, params ...any) (json.RawMessage, error) {
	body, err := json.Marshal(aria2RPCRequest{JSONRPC: "2.0", ID: "ipscan-mpv", Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(mpvRPCURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aria2c RPC 返回 %s：%s", resp.Status, strings.TrimSpace(string(data)))
	}
	var out aria2RPCResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("aria2c RPC %s 错误 %d：%s", method, out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

// waitAria2RPC 等待 RPC 服务就绪：AriaNg 页面触发的 aria2c 启动是异步的。
func waitAria2RPC(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := aria2RPC("aria2.getVersion", []any{}); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("aria2c RPC %s 不可用：%w", mpvRPCURL, lastErr)
}

// aria2cRPCDownload 通过 aria2.addUri 提交下载任务，并轮询直到完成或失败。
func aria2cRPCDownload(downloadURL, dest, workDir string) error {
	_ = os.Remove(dest)
	result, err := aria2RPC("aria2.addUri",
		[]string{downloadURL},
		map[string]string{
			"dir":                workDir,
			"out":                mpvArchiveName,
			"allow-overwrite":    "true",
			"auto-file-renaming": "false",
			"continue":           "false",
			"max-tries":          "1",
			"connect-timeout":    "15",
			"timeout":            "60",
		})
	if err != nil {
		return err
	}
	var gid string
	if err := json.Unmarshal(result, &gid); err != nil || gid == "" {
		return fmt.Errorf("aria2c 未返回有效 GID：%s", string(result))
	}
	mpvLog("aria2c 任务 GID=%s", gid)

	type aria2Status struct {
		Status          string `json:"status"`
		TotalLength     string `json:"totalLength"`
		CompletedLength string `json:"completedLength"`
		DownloadSpeed   string `json:"downloadSpeed"`
		ErrorCode       string `json:"errorCode"`
		ErrorMessage    string `json:"errorMessage"`
	}
	deadline := time.Now().Add(mpvDownloadTimeout)
	lastLog := time.Time{}
	for time.Now().Before(deadline) {
		raw, err := aria2RPC("aria2.tellStatus", gid, []string{
			"status", "totalLength", "completedLength", "downloadSpeed", "errorCode", "errorMessage",
		})
		if err != nil {
			return err
		}
		var st aria2Status
		if err := json.Unmarshal(raw, &st); err != nil {
			return fmt.Errorf("解析下载状态失败：%w", err)
		}
		switch st.Status {
		case "complete":
			if info, err := os.Stat(dest); err == nil && !info.IsDir() && info.Size() > 0 {
				return nil
			}
			return fmt.Errorf("下载完成但 %s 不可用", dest)
		case "error", "removed":
			return fmt.Errorf("下载失败：%s %s", st.ErrorCode, st.ErrorMessage)
		}
		if time.Since(lastLog) >= 3*time.Second {
			lastLog = time.Now()
			total, _ := strconv.ParseInt(st.TotalLength, 10, 64)
			done, _ := strconv.ParseInt(st.CompletedLength, 10, 64)
			percent := float64(0)
			if total > 0 {
				percent = float64(done) * 100 / float64(total)
			}
			mpvLog("下载中 %.1f%%（%s / %s，速度 %s B/s）", percent, playerFileSize(done), playerFileSize(total), st.DownloadSpeed)
		}
		time.Sleep(500 * time.Millisecond)
	}
	_, _ = aria2RPC("aria2.remove", gid)
	return fmt.Errorf("下载超时：%s", downloadURL)
}

// extractMpvDLL 用内嵌 7zr.exe 解压压缩包，并递归找出 libmpv-2.dll 放到目标路径。
func extractMpvDLL(archive, dest string) error {
	data, err := staticFS.ReadFile(mpv7zrPath)
	if err != nil {
		return fmt.Errorf("读取内嵌 %s 失败：%w", mpv7zrPath, err)
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(dest), "mpv-unpack-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	sevenZr := filepath.Join(tmpDir, "7zr.exe")
	if err := os.WriteFile(sevenZr, data, 0755); err != nil {
		return fmt.Errorf("写入临时 7zr.exe 失败：%w", err)
	}
	outDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	cmd := exec.Command(sevenZr, "x", "-y", "-o"+outDir, archive)
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("7zr.exe 解压失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}

	var found string
	_ = filepath.WalkDir(outDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.EqualFold(d.Name(), mpvDllName) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if found == "" {
		return fmt.Errorf("压缩包中未找到 %s", mpvDllName)
	}
	_ = os.Remove(dest)
	if err := os.Rename(found, dest); err != nil {
		return fmt.Errorf("替换 %s 失败：%w", dest, err)
	}
	return nil
}
