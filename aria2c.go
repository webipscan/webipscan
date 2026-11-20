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
	"sync"
	"time"
)

const aria2cRPCPort = "6800"

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

// aria2cSourcePath 依次在 exe 所在目录、当前目录查找 aria2c.exe
func aria2cSourcePath() string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
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

// updateAria2cExe 从当前服务的 /aria2c.exe 下载并替换当前目录下的 aria2c.exe
func updateAria2cExe(base string) error {
	if base == "" {
		return fmt.Errorf("无法从页面地址推导服务地址")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(base + "/aria2c.exe")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务返回 %s", resp.Status)
	}
	tmp, err := os.CreateTemp(".", "aria2c-*.exe.tmp")
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
	if err := os.Rename(tmpPath, "aria2c.exe"); err != nil {
		return err
	}
	aria2cLog("已从 %s/aria2c.exe 更新本地文件（%d 字节）", base, n)
	return nil
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

	local := "aria2c.exe"
	_, statErr := os.Stat(local)
	if err := updateAria2cExe(aria2cServiceBase(pageURL)); err != nil {
		if statErr != nil {
			aria2cLog("更新 %s 失败：%v", local, err)
			return
		}
		aria2cLog("更新 %s 失败，继续使用现有文件：%v", local, err)
	}

	for _, dir := range []string{".aria2c"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			aria2cLog("创建目录 %s 失败：%v", dir, err)
			return
		}
	}

	sessionPath := filepath.Join(".aria2c", ".session")
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		f, err := os.OpenFile(sessionPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			aria2cLog("创建 %s 失败：%v", sessionPath, err)
		} else {
			_ = f.Close()
			aria2cLog("已创建空的 session 文件 %s", sessionPath)
		}
	}

	abs, err := filepath.Abs(local)
	if err != nil {
		abs = local
	}
	cmd := exec.Command(abs,
		"--enable-rpc=true",
		"--rpc-allow-origin-all=true",
		"--continue=true",
		"--rpc-listen-port="+aria2cRPCPort,
		"--dir=.aria2c/",
		"--save-session-interval=3",
		"--save-session=.aria2c/.session",
		"--input-file=.aria2c/.session",
	)
	hideWindow(cmd)
	logWriter := &reopenableLogWriter{path: filepath.Join(".aria2c", "aria2c.log")}
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter
	if err := cmd.Start(); err != nil {
		aria2cLog("启动 aria2c.exe 失败：%v", err)
		return
	}
	aria2cCmd = cmd
	aria2cCleanup = watchAria2cChild(cmd)
	aria2cStarted = true
	aria2cLog("已启动 aria2c.exe（PID %d），RPC 端口 %s，日志 aria2c.log", cmd.Process.Pid, aria2cRPCPort)

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
