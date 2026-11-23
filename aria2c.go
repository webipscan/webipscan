package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	aria2cRPCPort = "6800"
	aria2cArchive = "aria2c.7z"
	aria2c7zrPath = "static/7zr.exe"
	aria2cConfRel = ".aria2c/aria2c.conf"
)

var (
	aria2cMu       sync.Mutex
	aria2cStarted  bool
	aria2cCmd      *exec.Cmd
	aria2cCleanup  func()
	aria2cStopping bool
)

func aria2cLog(format string, args ...any) {
	fmt.Printf("[aria2c %s] %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// reopenableLogWriter 把子进程输出写入日志文件。
// 每次写入都重新打开文件并立即关闭：子进程只持有管道、不持有日志文件句柄，
// 因此日志文件不会被锁定；文件被删除后，下一次写入会自动创建新的日志文件。
type reopenableLogWriter struct {
	mu   sync.Mutex
	path string
}

func (w *reopenableLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return len(p), nil
	}
	n, err := f.Write(p)
	_ = f.Close()
	return n, err
}

// handleAria2cExe 把 aria2c.exe 作为服务资源暴露，供加载 AriaNg 页面时更新本地副本。
// 仅允许本机访问，避免把可执行文件暴露到局域网。
func handleAria2cExe(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "无法识别来源地址", http.StatusForbidden)
		return
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		http.Error(w, "仅允许本机访问", http.StatusForbidden)
		return
	}
	path := aria2cSourcePath()
	if path == "" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, path)
}

// aria2cSourcePath 依次在运行时目录、exe 所在目录、当前目录查找 aria2c.exe
func aria2cSourcePath() string {
	var dirs []string
	seen := make(map[string]bool)
	add := func(d string) {
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		dirs = append(dirs, d)
	}
	add(runtimeDir)
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		add(cwd)
	}
	for _, dir := range dirs {
		p := filepath.Join(dir, "aria2c.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			return p
		}
	}
	return ""
}

// aria2cProcessRunning 判断系统当前是否已有 aria2c 进程。
// 具体实现按平台通过系统 API / /proc 枚举，不依赖 tasklist、pgrep 等外部程序。
func aria2cProcessRunning() bool {
	return processRunningByName("aria2c.exe", "aria2c")
}

// shutdownAria2c 关闭由本程序启动的 aria2c；主程序退出路径统一调用。
func shutdownAria2c() {
	aria2cMu.Lock()
	defer aria2cMu.Unlock()

	if aria2cCleanup != nil {
		aria2cStopping = true
		aria2cCleanup()
		aria2cCleanup = nil
		aria2cLog("aria2c.exe 已随主程序退出关闭")
	} else if aria2cCmd != nil && aria2cCmd.Process != nil {
		aria2cStopping = true
		_ = aria2cCmd.Process.Kill()
		aria2cLog("aria2c.exe 已随主程序退出关闭")
	}
	aria2cCmd = nil
	aria2cStarted = false
}

// portInUse 判断端口是否被占用：先查监听进程，再分别探测 IPv4/IPv6，
// 避免只绑定 127.0.0.1 或只绑定 [::] 时漏判。
func portInUse(port string) bool {
	if whoHoldsPort(port) != "" {
		return true
	}
	for _, host := range []string{"", "127.0.0.1", "::1"} {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
		if err != nil {
			return true
		}
		ln.Close()
	}
	return false
}

func aria2cServiceBase(pageURL string) string {
	u, err := url.Parse(pageURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// updateAria2cExe 从当前服务的 /aria2c.7z 下载压缩包，用内嵌的 7zr.exe 解压出 aria2c.exe
func updateAria2cExe(base string) error {
	if base == "" {
		return fmt.Errorf("无法从页面地址推导服务地址")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(base + "/" + aria2cArchive)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务返回 %s", resp.Status)
	}
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return fmt.Errorf("创建运行文件目录 %s 失败：%w", runtimeDir, err)
	}
	tmp, err := os.CreateTemp(runtimeDir, "aria2c-*.7z.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("下载内容为空")
	}
	dest := filepath.Join(runtimeDir, "aria2c.exe")
	if err := extractAria2cExe(tmpPath, dest); err != nil {
		return err
	}
	aria2cLog("已从 %s/%s 解压更新 %s（压缩包 %d 字节）", base, aria2cArchive, dest, n)
	return nil
}

// extractAria2cExe 用内嵌的 7zr.exe 从压缩包中解压出 aria2c.exe 并替换目标文件
func extractAria2cExe(archive, dest string) error {
	data, err := staticFS.ReadFile(aria2c7zrPath)
	if err != nil {
		return fmt.Errorf("读取内嵌 %s 失败：%w", aria2c7zrPath, err)
	}
	tmpDir, err := os.MkdirTemp(runtimeDir, "aria2c-unpack-")
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

	cmd := exec.Command(sevenZr, "x", "-y", "-o"+outDir, archive, "aria2c.exe")
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("7zr.exe 解压失败：%w（%s）", err, strings.TrimSpace(string(out)))
	}

	extracted := filepath.Join(outDir, "aria2c.exe")
	st, err := os.Stat(extracted)
	if err != nil {
		return fmt.Errorf("解压结果 %s 不可用：%w", extracted, err)
	}
	if st.IsDir() || st.Size() == 0 {
		return fmt.Errorf("解压结果 %s 不是有效文件", extracted)
	}
	return os.Rename(extracted, dest)
}

// aria2cDefaultConf 返回 aria2c 默认配置内容，选项与启动参数保持一致。
func aria2cDefaultConf() string {
	return fmt.Sprintf(`# aria2c 配置文件，不存在时由程序自动生成，可按需修改
enable-rpc=true
rpc-allow-origin-all=true
continue=true
rpc-listen-port=%s
force-save=true
dir=.aria2c/
save-session-interval=3
max-connection-per-server=16
split=64
min-split-size=4M
save-session=.aria2c/.session
input-file=.aria2c/.session
`, aria2cRPCPort)
}

// ensureAria2cConf 确保配置文件存在，不存在时写入默认配置。
func ensureAria2cConf(dataDir string) {
	confPath := filepath.Join(dataDir, "aria2c.conf")
	if _, err := os.Stat(confPath); err == nil {
		return
	}
	if err := os.WriteFile(confPath, []byte(aria2cDefaultConf()), 0644); err != nil {
		aria2cLog("创建 %s 失败：%v", confPath, err)
		return
	}
	aria2cLog("已创建默认配置文件 %s", confPath)
}

// ensureAria2cFromURL 在加载本机 AriaNg 页面时检查 aria2c 与 6800 端口，
// 均未占用时更新 aria2c.exe、准备目录并以后台子进程方式启动 RPC。
func ensureAria2cFromURL(pageURL string) {
	aria2cMu.Lock()
	defer aria2cMu.Unlock()

	if aria2cStopping {
		return
	}
	if aria2cProcessRunning() {
		aria2cLog("aria2c 已在运行，跳过启动")
		return
	}
	if portInUse(aria2cRPCPort) {
		aria2cLog("端口 %s 已被占用，跳过启动", aria2cRPCPort)
		return
	}
	if aria2cStarted {
		aria2cLog("aria2c 子进程已启动，跳过重复启动")
		return
	}

	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		aria2cLog("创建运行文件目录 %s 失败：%v", runtimeDir, err)
		return
	}
	local := filepath.Join(runtimeDir, "aria2c.exe")
	_, statErr := os.Stat(local)
	if err := updateAria2cExe(aria2cServiceBase(pageURL)); err != nil {
		if statErr != nil {
			aria2cLog("更新 %s 失败：%v", local, err)
			return
		}
		aria2cLog("更新 %s 失败，继续使用现有文件：%v", local, err)
	}

	dataDir := filepath.Join(runtimeDir, ".aria2c")
	for _, dir := range []string{dataDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			aria2cLog("创建目录 %s 失败：%v", dir, err)
			return
		}
	}

	sessionPath := filepath.Join(dataDir, ".session")
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		f, err := os.OpenFile(sessionPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			aria2cLog("创建 %s 失败：%v", sessionPath, err)
		} else {
			_ = f.Close()
			aria2cLog("已创建空的 session 文件 %s", sessionPath)
		}
	}
	ensureAria2cConf(dataDir)

	abs, err := filepath.Abs(local)
	if err != nil {
		abs = local
	}
	cmd := exec.Command(abs,
		"--conf-path="+aria2cConfRel,
		"--enable-rpc=true",
		"--rpc-allow-origin-all=true",
		"--continue=true",
		"--rpc-listen-port="+aria2cRPCPort,
		"--force-save=true",
		"--dir=.aria2c/",
		"--save-session-interval=3",
		"--max-connection-per-server=16", //# 单服务器最大连接数
		"--split=64",                     // # 单任务最大分段数
		"--min-split-size=4M",            // # 最小分段大小
		"--save-session=.aria2c/.session",
		"--input-file=.aria2c/.session",
	)
	cmd.Dir = runtimeDir
	hideWindow(cmd)
	logWriter := &reopenableLogWriter{path: filepath.Join(dataDir, "aria2c.log")}
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter
	if err := cmd.Start(); err != nil {
		aria2cLog("启动 aria2c.exe 失败：%v", err)
		return
	}
	aria2cCmd = cmd
	aria2cCleanup = watchAria2cChild(cmd)
	aria2cStarted = true
	aria2cLog("已启动 %s（PID %d），RPC 端口 %s，目录 %s，日志 %s", local, cmd.Process.Pid, aria2cRPCPort, runtimeDir, logWriter.path)

	go func() {
		err := cmd.Wait()
		aria2cMu.Lock()
		aria2cStarted = false
		stopping := aria2cStopping
		if aria2cCleanup != nil {
			aria2cCleanup()
			aria2cCleanup = nil
		}
		aria2cCmd = nil
		aria2cMu.Unlock()
		if stopping {
			aria2cLog("aria2c.exe 已随主程序退出关闭")
		} else if err != nil {
			aria2cLog("aria2c.exe 退出：%v", err)
		} else {
			aria2cLog("aria2c.exe 已退出")
		}
	}()
}
