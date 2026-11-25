package main

import (
	"archive/zip"
	"debug/pe"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	easytierDownloadPage    = "https://www.easytier.cn/guide/download.html"
	easytierExeName         = "easytier-core.exe"
	easytierWebEmbedExeName = "easytier-web-embed.exe"
	easytierArchiveName     = "easytier-windows-x86_64.zip"
	easytierWebEmbedLogName = "easytier-web-embed.log"
	easytierCoreConfName    = "easytier-core.conf"
	easytierCoreLogName     = "easytier-core.log"
	easytierConfigServerURL = "ws://127.0.0.1:22020/admin"
	easytierWebAdminURL     = "http://localhost:11211/"
	easytierFetchTimeout    = 20 * time.Second
)

var (
	easytierMu sync.Mutex

	// easytier-web-embed 子进程状态，启动流程参考 ensureAria2cFromURL。
	easytierWebMu       sync.Mutex
	easytierWebCmd      *exec.Cmd
	easytierWebCleanup  func()
	easytierWebStarted  bool
	easytierWebStopping bool

	// easytier-core 子进程状态，配置文件就绪且 web 控制台已启动后才启动。
	easytierCoreMu       sync.Mutex
	easytierCoreCmd      *exec.Cmd
	easytierCoreCleanup  func()
	easytierCoreStarted  bool
	easytierCoreStopping bool

	// 官网链接指向 GitHub Release，按项目现有习惯依次尝试加速镜像，最后直连。
	easytierMirrors = []string{
		"https://gh-proxy.com/",
		"https://gh-proxy.org/",
		"https://ghfast.top/",
		"",
	}

	easytierRowRE  = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	easytierCellRE = regexp.MustCompile(`(?is)<td[^>]*>(.*?)</td>`)
	easytierHrefRE = regexp.MustCompile(`(?is)href\s*=\s*["']([^"']+)["']`)
	easytierTagRE  = regexp.MustCompile(`(?s)<[^>]*>`)

	// CLI 压缩包需要释放到用户目录的完整文件清单，驱动与 DLL 必须与主程序同目录。
	easytierRequiredFiles = []string{
		"easytier-core.exe",
		"easytier-web.exe",
		easytierWebEmbedExeName,
		"Packet.dll",
		"WinDivert64.sys",
		"wintun.dll",
	}
)

func easytierLog(format string, args ...any) {
	fmt.Printf("[easytier %s] %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// easytierDataDir 返回 easytier-core.exe 的存放目录，与播放器 DLL 共用用户目录。
func easytierDataDir() string {
	if p, err := userDataRoot(); err == nil && p != "" {
		return p
	}
	return runtimeDir
}

// validEasyTierCore 检查文件是否为有效的 x64 可执行程序。
func validEasyTierCore(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() < 64*1024 {
		return false
	}
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Machine == pe.IMAGE_FILE_MACHINE_AMD64
}

// easytierInstalled 检查主程序与驱动、DLL 是否都已释放到用户目录。
func easytierInstalled(dir string) bool {
	for _, name := range easytierRequiredFiles {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.IsDir() || st.Size() == 0 {
			return false
		}
	}
	return validEasyTierCore(filepath.Join(dir, easytierExeName))
}

// fetchEasyTierCLIURL 从官网下载页解析 Windows x86_64 的命令行程序 CLI 压缩包地址。
func fetchEasyTierCLIURL() (string, error) {
	client := &http.Client{Timeout: easytierFetchTimeout}
	req, err := http.NewRequest(http.MethodGet, easytierDownloadPage, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("下载页返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}

	page := string(body)
	for _, row := range easytierRowRE.FindAllString(page, -1) {
		cells := easytierCellRE.FindAllStringSubmatch(row, -1)
		if len(cells) < 4 {
			continue
		}
		platform := strings.TrimSpace(html.UnescapeString(easytierTagRE.ReplaceAllString(cells[0][1], "")))
		arch := strings.TrimSpace(html.UnescapeString(easytierTagRE.ReplaceAllString(cells[1][1], "")))
		if !strings.EqualFold(platform, "Windows") || !strings.EqualFold(arch, "x86_64") {
			continue
		}
		for _, href := range easytierHrefRE.FindAllStringSubmatch(row, -1) {
			u := html.UnescapeString(href[1])
			lower := strings.ToLower(u)
			if !strings.HasPrefix(lower, "https://github.com/easytier/easytier/releases/download/") ||
				!strings.Contains(lower, "easytier-windows-x86_64") || !strings.HasSuffix(lower, ".zip") {
				continue
			}
			return u, nil
		}
	}
	return "", fmt.Errorf("下载页中未找到 Windows x86_64 的 CLI 压缩包链接")
}

func easytierDownloadURLs(direct string) []string {
	urls := make([]string, 0, len(easytierMirrors))
	for _, mirror := range easytierMirrors {
		if mirror == "" {
			urls = append(urls, direct)
		} else {
			urls = append(urls, mirror+strings.TrimPrefix(direct, "https://"))
		}
	}
	return urls
}

// easytierArchiveNameFromURL 从下载链接取带版本号的文件名，版本更新后不会复用旧压缩包。
func easytierArchiveNameFromURL(direct string) string {
	name := direct
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.IndexAny(name, "?#"); i >= 0 {
		name = name[:i]
	}
	if name == "" || !strings.HasSuffix(strings.ToLower(name), ".zip") {
		return easytierArchiveName
	}
	return name
}

// ensureEasyTierCore 确保用户目录中存在可用的 CLI 程序、驱动与 DLL。
func ensureEasyTierCore(pageURL string) (string, error) {
	easytierMu.Lock()
	defer easytierMu.Unlock()

	dir := easytierDataDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("创建目录 %s 失败：%w", dir, err)
	}
	exe := filepath.Join(dir, easytierExeName)
	if easytierInstalled(dir) {
		return exe, nil
	}

	direct, err := fetchEasyTierCLIURL()
	if err != nil {
		return "", err
	}
	easytierLog("解析到 CLI 下载地址：%s", direct)

	archiveDir := filepath.Join(dir, ".aria2c")
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return "", fmt.Errorf("创建下载目录 %s 失败：%w", archiveDir, err)
	}
	archiveName := easytierArchiveNameFromURL(direct)
	archive := filepath.Join(archiveDir, archiveName)

	// 已下载过的压缩包直接复用，只有解压失败或文件不完整时才重新下载。
	if st, err := os.Stat(archive); err == nil && !st.IsDir() && st.Size() > 0 {
		easytierLog("复用已下载压缩包：%s", archive)
		if err := extractEasyTierArchive(archive, dir); err != nil {
			easytierLog("已有压缩包解压失败，准备重新下载：%v", err)
		} else if !easytierInstalled(dir) {
			easytierLog("已有压缩包内容不完整，准备重新下载")
		} else {
			easytierLog("已就绪：%s", exe)
			return exe, nil
		}
		_ = os.Remove(archive)
	}

	ensureAria2cFromURL(pageURL)
	if err := waitAria2RPC(mpvRPCWaitTimeout); err != nil {
		return "", err
	}

	urls := easytierDownloadURLs(direct)
	var lastErr error
	for i, u := range urls {
		easytierLog("下载第 %d/%d 个地址：%s", i+1, len(urls), u)
		if err := aria2cRPCDownloadAs(u, archive, archiveDir, archiveName); err != nil {
			lastErr = err
			easytierLog("下载失败：%v", err)
			continue
		}
		if err := extractEasyTierArchive(archive, dir); err != nil {
			lastErr = err
			easytierLog("解压失败：%v", err)
			continue
		}
		if easytierInstalled(dir) {
			easytierLog("已就绪：%s", exe)
			return exe, nil
		}
		lastErr = fmt.Errorf("解压得到的 %s 中文件不完整", dir)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有配置下载地址")
	}
	return "", lastErr
}

// extractEasyTierArchive 把 CLI 压缩包中的程序、驱动与 DLL 全部释放到用户目录。
// 压缩包内可能带一层版本目录，这里统一取文件名平铺，保证驱动与主程序同目录。
func extractEasyTierArchive(archive, dir string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("打开压缩包失败：%w", err)
	}
	defer r.Close()

	found := make(map[string]bool, len(easytierRequiredFiles))
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := path.Base(strings.ReplaceAll(f.Name, "\\", "/"))
		if name == "" || name == "." || name == ".." {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, name)
		tmp := dest + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			_ = src.Close()
			return err
		}
		_, copyErr := io.Copy(out, src)
		outErr := out.Close()
		srcErr := src.Close()
		if copyErr != nil {
			_ = os.Remove(tmp)
			return copyErr
		}
		if outErr != nil {
			_ = os.Remove(tmp)
			return outErr
		}
		if srcErr != nil {
			_ = os.Remove(tmp)
			return srcErr
		}
		if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, dest); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("替换 %s 失败：%w", dest, err)
		}
		for _, required := range easytierRequiredFiles {
			if strings.EqualFold(name, required) {
				found[required] = true
			}
		}
	}

	var missing []string
	for _, required := range easytierRequiredFiles {
		if !found[required] {
			missing = append(missing, required)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("压缩包缺少文件：%s", strings.Join(missing, "、"))
	}
	return nil
}

// easytierWebProcessRunning 判断系统当前是否已有 easytier-web-embed 进程。
func easytierWebProcessRunning() bool {
	return processRunningByName(easytierWebEmbedExeName, "easytier-web-embed")
}

// waitEasyTierWebReady 等待 Web 控制台开始响应 HTTP 请求，避免刚启动时打开空白页。
func waitEasyTierWebReady(timeout time.Duration) error {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(easytierWebAdminURL)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("Web 控制台 %s 不可用：%w", easytierWebAdminURL, lastErr)
}

// ensureEasyTierWebEmbedFromURL 参考 ensureAria2cFromURL：已有进程或子进程时不重复启动，
// 否则确保 CLI 程序就绪后，以用户目录 webipscan 为主目录后台启动 easytier-web-embed.exe。
func ensureEasyTierWebEmbedFromURL(pageURL string) error {
	easytierWebMu.Lock()
	defer easytierWebMu.Unlock()

	if easytierWebStopping {
		return nil
	}
	if easytierWebProcessRunning() {
		easytierLog("easytier-web-embed 已在运行，跳过启动")
		return nil
	}
	if easytierWebStarted {
		easytierLog("easytier-web-embed 子进程已启动，跳过重复启动")
		return nil
	}

	coreExe, err := ensureEasyTierCore(pageURL)
	if err != nil {
		return err
	}
	dir := filepath.Dir(coreExe)
	exe := filepath.Join(dir, easytierWebEmbedExeName)
	if st, err := os.Stat(exe); err != nil || st.IsDir() || st.Size() == 0 {
		return fmt.Errorf("未找到可用的 %s", exe)
	}
	logDir := filepath.Join(dir, ".aria2c")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录 %s 失败：%w", logDir, err)
	}

	cmd := exec.Command(exe, "--disable-registration", "-p", "ws", "--web-server-addr", "127.0.0.1")
	cmd.Dir = dir
	hideWindow(cmd)
	logWriter := &reopenableLogWriter{path: filepath.Join(logDir, easytierWebEmbedLogName)}
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 %s 失败：%w", exe, err)
	}

	easytierWebCmd = cmd
	easytierWebCleanup = watchAria2cChild(cmd)
	easytierWebStarted = true
	easytierLog("已启动 %s（PID %d），参数 --disable-registration -p ws，主目录 %s，日志 %s",
		exe, cmd.Process.Pid, dir, logWriter.path)

	go func() {
		err := cmd.Wait()
		easytierWebMu.Lock()
		easytierWebStarted = false
		stopping := easytierWebStopping
		if easytierWebCleanup != nil {
			easytierWebCleanup()
			easytierWebCleanup = nil
		}
		easytierWebCmd = nil
		easytierWebMu.Unlock()
		if stopping {
			easytierLog("easytier-web-embed 已随主程序退出关闭")
		} else if err != nil {
			easytierLog("easytier-web-embed 退出：%v", err)
		} else {
			easytierLog("easytier-web-embed 已退出")
		}
	}()
	return nil
}

// shutdownEasyTierWebEmbed 关闭由本程序启动的 web 控制台子进程；主程序退出路径统一调用。
func shutdownEasyTierWebEmbed() {
	easytierWebMu.Lock()
	defer easytierWebMu.Unlock()

	if easytierWebCleanup != nil {
		easytierWebStopping = true
		easytierWebCleanup()
		easytierWebCleanup = nil
	} else if easytierWebCmd != nil && easytierWebCmd.Process != nil {
		easytierWebStopping = true
		_ = easytierWebCmd.Process.Kill()
	}
	easytierWebCmd = nil
	easytierWebStarted = false
}

// easytierCoreProcessRunning 判断系统当前是否已有 easytier-core 进程。
func easytierCoreProcessRunning() bool {
	return processRunningByName(easytierExeName, "easytier-core")
}

// ensureEasyTierCoreFromConfig 启动虚拟内网：先确认 easytier-core.conf 存在，
// 再确保前置的 easytier-web-embed.exe 已启动，最后用配置文件启动 easytier-core.exe。
func ensureEasyTierCoreFromConfig(pageURL string) error {
	easytierCoreMu.Lock()
	defer easytierCoreMu.Unlock()

	if easytierCoreStopping {
		return nil
	}
	if easytierCoreProcessRunning() {
		easytierLog("easytier-core 已在运行，跳过启动")
		return nil
	}
	if easytierCoreStarted {
		easytierLog("easytier-core 子进程已启动，跳过重复启动")
		return nil
	}

	dir := easytierDataDir()
	confPath := filepath.Join(dir, easytierCoreConfName)
	if st, err := os.Stat(confPath); err != nil || st.IsDir() || st.Size() == 0 {
		return fmt.Errorf("未找到配置文件 %s，请先通过 Web 控制台生成", confPath)
	}

	exe, err := ensureEasyTierCore(pageURL)
	if err != nil {
		return err
	}
	if err := ensureEasyTierWebEmbedFromURL(pageURL); err != nil {
		return fmt.Errorf("前置启动 easytier-web-embed 失败：%w", err)
	}

	logDir := filepath.Join(dir, ".aria2c")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录 %s 失败：%w", logDir, err)
	}

	cmd := exec.Command(exe, "--config-server", easytierConfigServerURL, "--config-file", easytierCoreConfName)
	cmd.Dir = dir
	hideWindow(cmd)
	logWriter := &reopenableLogWriter{path: filepath.Join(logDir, easytierCoreLogName)}
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 %s 失败：%w", exe, err)
	}

	easytierCoreCmd = cmd
	easytierCoreCleanup = watchAria2cChild(cmd)
	easytierCoreStarted = true
	easytierLog("已启动 %s（PID %d），参数 --config-server %s --config-file %s，主目录 %s，日志 %s",
		exe, cmd.Process.Pid, easytierConfigServerURL, easytierCoreConfName, dir, logWriter.path)

	go func() {
		err := cmd.Wait()
		easytierCoreMu.Lock()
		easytierCoreStarted = false
		stopping := easytierCoreStopping
		if easytierCoreCleanup != nil {
			easytierCoreCleanup()
			easytierCoreCleanup = nil
		}
		easytierCoreCmd = nil
		easytierCoreMu.Unlock()
		if stopping {
			easytierLog("easytier-core 已随主程序退出关闭")
		} else if err != nil {
			easytierLog("easytier-core 退出：%v", err)
		} else {
			easytierLog("easytier-core 已退出")
		}
	}()
	return nil
}

// shutdownEasyTierCore 关闭由本程序启动的 easytier-core 子进程；主程序退出路径统一调用。
func shutdownEasyTierCore() {
	easytierCoreMu.Lock()
	defer easytierCoreMu.Unlock()

	if easytierCoreCleanup != nil {
		easytierCoreStopping = true
		easytierCoreCleanup()
		easytierCoreCleanup = nil
	} else if easytierCoreCmd != nil && easytierCoreCmd.Process != nil {
		easytierCoreStopping = true
		_ = easytierCoreCmd.Process.Kill()
	}
	easytierCoreCmd = nil
	easytierCoreStarted = false
}
