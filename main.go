package main

import (
	"crypto/sha256"
	"debug/pe"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed static
var staticFS embed.FS

// staticRoot 把 static 目录作为网站根目录，页面请求路径直接对应其中的文件
var staticRoot, _ = fs.Sub(staticFS, "static")

const (
	// defaultPort 默认监听端口
	defaultPort = "9801"
	// maxPortAttempts 端口被占用时向上探测的最大次数
	maxPortAttempts = 100
)

// serverPort 为 listenPort 探测后实际监听的端口，供前端生成可访问的分享地址
var serverPort string

// aboutHandler 返回当前 exe 的版本与哈希信息
func aboutHandler(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"name":      "ipscan",
		"version":   AppVersion,
		"goVersion": runtime.Version(),
	}
	if exe, err := os.Executable(); err == nil {
		if b, err := os.ReadFile(exe); err == nil {
			sum := sha256.Sum256(b)
			info["sha256"] = hex.EncodeToString(sum[:])
			info["size"] = len(b)
			info["path"] = exe
		}
		if v := peFileVersion(exe); v != "" {
			info["fileVersion"] = v
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(info)
}

// peFileVersion 解析 Windows exe 的 VERSIONINFO 资源，返回如 "1.2.3.4"；
// 非 Windows 或无可解析版本资源时返回空串
func peFileVersion(path string) string {
	defer func() { _ = recover() }()
	f, err := pe.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var rsrc *pe.Section
	for _, s := range f.Sections {
		if s.Name == ".rsrc" {
			rsrc = s
			break
		}
	}
	if rsrc == nil {
		return ""
	}
	data, err := rsrc.Data()
	if err != nil || len(data) < 16 {
		return ""
	}

	// 读取资源目录；返回该目录下的所有条目（id, offsetToData）
	readDir := func(off int) ([]struct {
		id, off uint32
	}, bool) {
		if off < 0 || off+16 > len(data) {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint16(data[off+12:off+14])) +
			int(binary.LittleEndian.Uint16(data[off+14:off+16]))
		off += 16
		var ents []struct {
			id, off uint32
		}
		for i := 0; i < n; i++ {
			if off+8 > len(data) {
				break
			}
			ents = append(ents, struct {
				id, off uint32
			}{
				binary.LittleEndian.Uint32(data[off : off+4]),
				binary.LittleEndian.Uint32(data[off+4 : off+8]),
			})
			off += 8
		}
		return ents, true
	}

	// 第一层：Type，找 RT_VERSION(16)
	ents, ok := readDir(0)
	if !ok {
		return ""
	}
	var typeOff uint32
	found := false
	for _, e := range ents {
		if e.id == 16 { // RT_VERSION
			typeOff = e.off & 0x7fffffff
			found = true
			break
		}
	}
	if !found {
		return ""
	}
	// 第二层：Name/Id，取第一个（通常为 1）
	ents, ok = readDir(int(typeOff))
	if !ok || len(ents) == 0 {
		return ""
	}
	// 第三层：Language，取第一个
	ents, ok = readDir(int(ents[0].off & 0x7fffffff))
	if !ok || len(ents) == 0 {
		return ""
	}
	dataOff := int(ents[0].off & 0x7fffffff)
	if dataOff+16 > len(data) {
		return ""
	}
	// IMAGE_RESOURCE_DATA_ENTRY：OffsetToData(4) + Size(4) + CodePage(4) + Reserved(4)
	rva := binary.LittleEndian.Uint32(data[dataOff : dataOff+4])
	size := binary.LittleEndian.Uint32(data[dataOff+4 : dataOff+8])
	fileOff := int(rva) - int(rsrc.VirtualAddress)
	if fileOff < 0 || fileOff+int(size) > len(data) || size < 16 {
		return ""
	}
	vb := data[fileOff : fileOff+int(size)]

	// VS_VERSIONINFO：wLength(2) wValueLength(2) wType(2) szKey("VS_VERSION_INFO" UTF-16)
	wValueLength := binary.LittleEndian.Uint16(vb[2:4])
	// 键名 "VS_VERSION_INFO" 占 (15+1)*2 = 32 字节，按 4 字节对齐
	valueStart := 6 + 32
	valueStart = (valueStart + 3) &^ 3
	if wValueLength == 0 || valueStart+52 > len(vb) {
		return ""
	}
	// VS_FIXEDFILEINFO：signature(4)=0xFEEF04BD, strucVer(4), fileVerMS(4), fileVerLS(4)...
	if binary.LittleEndian.Uint32(vb[valueStart:]) != 0xfeef04bd {
		return ""
	}
	ms := binary.LittleEndian.Uint32(vb[valueStart+8 : valueStart+12])
	ls := binary.LittleEndian.Uint32(vb[valueStart+12 : valueStart+16])
	return fmt.Sprintf("%d.%d.%d.%d",
		ms>>16, ms&0xffff, ls>>16, ls&0xffff)
}

// launchOptions 启动参数
type launchOptions struct {
	port        string
	showConsole bool   // --console：显示控制台窗口并输出参数说明（默认隐藏）
	noLinks     bool   // --no-links：禁止 miniblink 窗口内点击链接跳转
	noTray      bool   // --no-tray：即使处于 Windows 桌面也不创建托盘
	userMode    bool   // --user / --user-mode：显式声明用户模式（默认已开启，保留兼容）
	noUser      bool   // --no-user / --no-user-mode：关闭用户模式，改回 exe 所在目录
	targetURL   string // --url：存在 mb132_x64.dll 时用 miniblink 打开该地址（默认不开窗）
	mediaFile   string // 位置参数为媒体文件：用 libmpv 播放，跳过运行时独占检查
	directURL   string // 位置参数为网页 URL：用 openWindow 打开，跳过运行时独占检查
}

// isPortNumber 判断字符串是否为合法端口数字（1-65535）。
// 端口是否已被占用由后续 listenPort 顺延处理，这里只做格式与范围校验。
func isPortNumber(s string) bool {
	if s == "" {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

// isExistingFile 判断参数是否为已存在的普通文件。
func isExistingFile(s string) bool {
	info, err := os.Stat(s)
	return err == nil && !info.IsDir()
}

// mediaExtensions 是交给 libmpv 打开播放的常见音视频与图片扩展名。
var mediaExtensions = map[string]bool{
	".mp4": true, ".m4v": true, ".mkv": true, ".avi": true, ".mov": true, ".wmv": true,
	".flv": true, ".webm": true, ".ts": true, ".m2ts": true, ".vob": true, ".rmvb": true,
	".rm": true, ".mpg": true, ".mpeg": true, ".3gp": true, ".ogv": true,
	".mp3": true, ".wav": true, ".flac": true, ".aac": true, ".m4a": true, ".ogg": true,
	".wma": true, ".opus": true,
	".jpg": true, ".jpeg": true, ".jfif": true, ".png": true, ".apng": true,
	".gif": true, ".bmp": true, ".webp": true, ".tif": true, ".tiff": true,
	".ico": true, ".avif": true, ".heic": true, ".heif": true,
}

// isMediaFile 优先识别媒体文件：扩展名命中，或文件头被检测为音视频/图片内容。
func isMediaFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if mediaExtensions[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	ct := http.DetectContentType(buf[:n])
	return strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") || strings.HasPrefix(ct, "image/")
}

// detectFileType 综合扩展名与文件头部内容给出可读的文件类型描述。
func detectFileType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	parts := make([]string, 0, 3)
	if ext != "" {
		parts = append(parts, "扩展名 "+ext)
		if mt := mime.TypeByExtension(ext); mt != "" {
			parts = append(parts, "MIME "+mt)
		}
	}
	if f, err := os.Open(path); err == nil {
		buf := make([]byte, 512)
		if n, _ := f.Read(buf); n > 0 {
			parts = append(parts, "内容检测 "+http.DetectContentType(buf[:n]))
		}
		_ = f.Close()
	}
	if len(parts) == 0 {
		return "未知类型"
	}
	return strings.Join(parts, "，")
}

// parseLaunchArgs 解析启动参数：位置参数依次识别为端口、文件、URL。
func parseLaunchArgs(args []string) (launchOptions, error) {
	o := launchOptions{port: defaultPort}
	portSet := false
	positionalSeen := false
	next := func(i *int, name string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s 缺少参数值", name)
		}
		*i++
		return strings.Trim(strings.TrimSpace(args[*i]), "\"'"), nil
	}
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		switch {
		case a == "--console":
			o.showConsole = true
		case a == "--daemon" || a == "-d" || a == "--noopen" || a == "-n":
			// 旧参数保留兼容：不打开页面已是默认行为，控制台显示只由 --console 决定。
		case a == "--no-links":
			o.noLinks = true
		case a == "--no-tray":
			o.noTray = true
		case a == "--user" || a == "--user-mode":
			o.userMode = true
		case a == "--no-user" || a == "--no-user-mode":
			o.noUser = true
			o.userMode = false
		case a == "-p" || a == "--port":
			v, err := next(&i, a)
			if err != nil {
				return o, err
			}
			if !isPortNumber(v) {
				return o, fmt.Errorf("端口无效：%s", v)
			}
			o.port = v
			portSet = true
		case strings.HasPrefix(a, "-p=") || strings.HasPrefix(a, "--port="):
			v := strings.Trim(strings.TrimSpace(strings.SplitN(a, "=", 2)[1]), "\"'")
			if !isPortNumber(v) {
				return o, fmt.Errorf("端口无效：%s", v)
			}
			o.port = v
			portSet = true
		case a == "--url":
			v, err := next(&i, "--url")
			if err != nil {
				return o, err
			}
			o.targetURL = v
		case strings.HasPrefix(a, "--url="):
			o.targetURL = strings.Trim(strings.TrimSpace(strings.SplitN(a, "=", 2)[1]), "\"'")
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("未知参数：%s", a)
		default:
			if positionalSeen {
				return o, fmt.Errorf("多余的参数：%s", a)
			}
			positionalSeen = true
			// 优先识别媒体文件与网页 URL，其次才是端口和普通文件。
			switch {
			case isMediaFile(a):
				o.mediaFile = a
				fmt.Printf("  位置参数识别为媒体文件（含图片），将用 libmpv 打开：%s\n", a)
			case isHTTPURL(a):
				o.directURL = a
				fmt.Printf("  位置参数识别为网页 URL，将打开窗口：%s\n", a)
			case !portSet && isPortNumber(a):
				o.port = a // 兼容旧用法：webipscan.exe 9200
			case isExistingFile(a):
				fmt.Printf("  位置参数识别为文件：%s\n", a)
				fmt.Printf("  文件类型：%s\n", detectFileType(a))
			default:
				return o, fmt.Errorf("无法识别的位置参数：%s", a)
			}
		}
	}
	return o, nil
}

// printLaunchHelp 输出全部启动参数说明；参数错误以及带 --console 启动时都会打印。
func printLaunchHelp() {
	fmt.Println("用法：webipscan.exe [-p 端口] [端口|文件|URL] [--console] [--url 地址] [--no-links] [--no-tray] [--user|--user-mode] [--no-user|--no-user-mode]")
	fmt.Println("  -p <端口> / --port <端口> / -p=<端口> / --port=<端口>  指定监听端口（1-65535），被占用时自动向上顺延")
	fmt.Println("  [媒体文件(含图片)|网页URL|端口|文件]  位置参数优先识别：媒体文件（音视频/图片）用 libmpv 打开；网页 URL 用 openWindow 打开；两者均跳过运行时独占检查且不创建系统托盘。端口用作监听端口；其它文件仅输出类型检测")
	fmt.Println("  --console  显示控制台窗口并输出本说明；默认隐藏控制台且不打开页面，可通过托盘菜单打开")
	fmt.Println("  --daemon / -d / --noopen / -n  旧参数兼容，等价于默认行为（不打开页面、控制台仍默认隐藏）")
	fmt.Println("  --url <地址> / --url=<地址>  有可用 mb132_x64.dll 时用内嵌内核窗口打开该地址（默认不开窗，仅此参数会主动开窗）")
	fmt.Println("  --no-links  禁止 miniblink 窗口内点击链接/提交表单跳转；默认允许并在当前窗口跳转")
	fmt.Println("  --no-tray  即使处于 Windows 桌面也不创建托盘")
	fmt.Println("  --user / --user-mode  显式声明用户模式（默认已开启，保留兼容）")
	fmt.Println("  --no-user / --no-user-mode  关闭用户模式，改回 exe 所在目录（环境变量 WEBIPSCAN_USER_MODE=0 同效）")
}

// openWindow 用内嵌 miniblink 窗口打开地址，内核不可用时回退系统浏览器；
// 返回值表示是否由内嵌窗口打开，供调用方决定是否等待窗口关闭。
func openWindow(dllPath, target, homeURL string, allowLinks bool, size windowSize) bool {
	if dllPath != "" {
		if err := openMbWindow(dllPath, target, homeURL, allowLinks, size); err == nil {
			return true
		} else {
			fmt.Println("  内嵌内核打开窗口失败：" + err.Error() + "，改用默认浏览器")
		}
	}
	if err := openBrowser(target); err != nil {
		setConsoleVisible(true)
		fmt.Println("  打开页面失败：" + err.Error())
	}
	return false
}

// openMediaFile 确保 libmpv 可用后播放媒体文件，与托盘播放器使用同一套 DLL 准备逻辑；
// 返回值表示播放器线程是否已启动。
func openMediaFile(file, pageURL string) bool {
	dll, err := ensureMpvDLL(pageURL)
	if err != nil {
		setConsoleVisible(true)
		fmt.Println("  libmpv-2.dll 准备失败：" + err.Error())
		return false
	}
	setDllSearchDir(dll)
	fmt.Println("  libmpv 打开：" + file)
	if err := startMpvPlayer(dll, file); err != nil {
		setConsoleVisible(true)
		fmt.Println("  libmpv 播放器启动失败：" + err.Error())
		return false
	}
	return true
}

func main() {
	opts, err := parseLaunchArgs(os.Args[1:])
	if err != nil {
		fmt.Println("启动参数错误：" + err.Error())
		printLaunchHelp()
		exitMain(1)
		return
	}
	if opts.showConsole {
		printLaunchHelp()
	}

	// 默认用户模式：目录为 %USERPROFILE%\<exe 文件名>，仅 --no-user 时回退 exe 目录。
	// 位置参数被判定为媒体/图片文件或网页 URL 时属于直接打开模式：跳过独占检查，也不创建系统托盘。
	directOpen := opts.mediaFile != "" || opts.directURL != ""
	skipInstanceLock := directOpen
	if err := initRuntimeDir(opts.noUser && !opts.userMode, skipInstanceLock); err != nil {
		if ae, ok := err.(*anotherInstanceError); ok {
			fmt.Println("==============================================")
			fmt.Println("  同一运行时目录已有主程序在运行，本次启动取消")
			fmt.Println("  运行时目录: " + ae.dir)
			if ae.pid > 0 {
				fmt.Printf("  主程序 PID: %d\n", ae.pid)
			}
			fmt.Println("  同一运行时目录只允许运行一个主程序。")
			fmt.Println("==============================================")
			exitMain(1)
			return
		}
		fmt.Println("运行时目录初始化失败：" + err.Error())
		exitMain(1)
		return
	}

	// Ctrl+C / SIGTERM 也走统一退出入口，确保关闭 aria2c 子进程
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("收到退出信号，程序退出")
		exitMain(0)
	}()

	port := opts.port

	// 端口被占用时自动向上顺延：9100 -> 9101 -> 9102 ...
	ln, actual, err := listenPort(port)
	if err != nil {
		fmt.Println("启动失败：" + err.Error())
		exitMain(1)
	}
	serverPort = actual

	http.HandleFunc("/", handleStatic)
	// http.HandleFunc("/aria2c.exe", handleAria2cExe)
	http.HandleFunc("/api/scan", handleScan)
	http.HandleFunc("/api/trace", handleTrace)
	http.HandleFunc("/api/nat", handleNat)
	http.HandleFunc("/api/about", aboutHandler)
	http.HandleFunc("/api/localnet", handleLocalNet)
	http.HandleFunc("/api/interfaces", handleInterfaces)
	// 指定主机：全端口扫描 / IP 反查域名 / 域名备案查询
	http.HandleFunc("/api/portscan", handlePortScan)
	http.HandleFunc("/api/reversedns/sources", handleReverseDNSSources)
	http.HandleFunc("/api/reversedns", handleReverseDNS)
	http.HandleFunc("/api/icp", handleICP)
	// IP 属地查询 + DNS / DoH 记录查询
	http.HandleFunc("/api/geoip/status", handleGeoIPStatus)
	http.HandleFunc("/api/geoip/update", handleGeoIPUpdate)
	http.HandleFunc("/api/geoip/query", handleGeoIPQuery)
	http.HandleFunc("/api/dns/servers", handleDNSServers)
	http.HandleFunc("/api/dns/query", handleDNSQuery)
	http.HandleFunc("/api/publicip", handlePublicIP)
	// 网址可访问性检测：迷你浏览器跳转前由服务端校验
	http.HandleFunc("/api/url/check", handleURLCheck)
	// 网络剪贴板：仅交换 WebRTC 连接信息（SDP），内容与文件在浏览器间直传
	http.HandleFunc("/api/clip/", handleClipAPI)

	ifaces := ListLocalIfaces()
	url := "http://127.0.0.1:" + actual

	// 默认隐藏控制台；--console 才保留显示。DLL 校验后仅记录路径，是否开窗由 --url 决定。
	if !opts.showConsole {
		setConsoleVisible(false)
	}
	// 仅打开媒体/图片文件时不需要 miniblink：跳过 mb132_x64.dll 的释放、加载与校验，降低内存占用。
	// 若同时指定了 --url，仍需准备 DLL 给内嵌窗口使用。
	mediaOnly := opts.mediaFile != "" && opts.targetURL == ""
	mbPath := ""
	if !mediaOnly {
		mbPath = prepareMbWindow()
	}
	openURL := url
	if opts.targetURL != "" {
		if mbPath != "" {
			openURL = opts.targetURL
		} else {
			fmt.Println("  --url 需要可用的 mb132_x64.dll，当前未找到，已忽略该地址")
		}
	}

	fmt.Println("==============================================")
	fmt.Println("  局域网 IP 占用查询工具")
	fmt.Println("  运行模式: " + runtimeDirLabel())
	fmt.Println("  访问地址: " + url)
	if actual != port {
		fmt.Printf("  !! 端口 %s 不可用，已自动改用 %s\n", port, actual)
		if holder := whoHoldsPort(port); holder != "" {
			fmt.Printf("     占用者: %s  （关闭它后重开本程序即可用回 %s）\n", holder, port)
		}
	}
	fmt.Printf("  本机 IP（共 %d 个）：\n", len(ifaces))
	for _, it := range ifaces {
		fmt.Printf("    %-16s %-4s %-8s %s\n", it.IP, it.Kind, it.CIDR, it.Name)
	}
	fmt.Println("  可用地址：")
	fmt.Printf("    http://127.0.0.1:%s   （本机）\n", actual)
	for _, it := range ifaces {
		if it.Kind == "回环" {
			continue
		}
		fmt.Printf("    http://%s:%s   （%s）\n", it.IP, actual, it.Kind)
	}
	switch {
	case opts.mediaFile != "":
		fmt.Println("  媒体/图片：libmpv 打开 " + opts.mediaFile)
	case opts.directURL != "":
		fmt.Println("  页面显示：openWindow 打开 " + opts.directURL)
	case opts.targetURL != "" && mbPath != "":
		fmt.Println("  页面显示：miniblink 窗口打开 --url 指定地址")
	case opts.targetURL != "":
		fmt.Println("  未找到可用的 mb132_x64.dll，--url 未生效")
	case opts.showConsole:
		fmt.Println("  后台模式：不打开页面（--console 仅显示控制台），可通过托盘菜单打开")
	default:
		fmt.Println("  后台模式：不打开页面、控制台已隐藏，可通过托盘菜单打开")
	}
	if skipInstanceLock {
		fmt.Println("  直接打开模式：已跳过运行时独占检查")
	}
	if mediaOnly {
		fmt.Println("  内存优化：媒体/图片直接打开模式未准备/加载 mb132_x64.dll")
	}
	if opts.showConsole {
		fmt.Println("  控制台窗口：已显示（--console）")
	}
	if opts.targetURL != "" && mbPath != "" {
		fmt.Println("  --url 目标：" + openURL)
	}
	fmt.Println("==============================================")

	// Windows 桌面会话下创建系统托盘；服务会话、非 Windows 平台、--no-tray 或媒体/URL 直接打开时跳过。
	tools := loadTools()
	if !opts.noTray && !directOpen {
		if startTrayIfDesktop(trayConfig{
			homeURL:      url,
			clipboardURL: url + "/clip.html",
			aria2cURL:    url + "/AriaNg.html",
			tools:        tools,
			version:      AppVersion,
			mbDLL:        mbPath,
		}) {
			fmt.Printf("  系统托盘已启用（右键菜单：主页(aria2c) / 网络占用扫描 / 剪贴板")
			if len(tools) > 0 {
				fmt.Printf(" / 工具(%d)", len(tools))
			}
			fmt.Println(" / 地址 / 控制台 / 关于 / 退出）")
		}
	} else if directOpen {
		fmt.Println("  直接打开媒体/图片文件或网页 URL：不创建系统托盘")
	}

	// HTTP 服务放到后台：miniblink 消息循环运行在独立的 UI 线程上。
	serveErr := make(chan error, 1)
	go func() { serveErr <- http.Serve(ln, nil) }()

	// 等服务就绪后再拉起页面：默认不开窗，仅位置参数或 --url 显式指定时打开。
	time.Sleep(400 * time.Millisecond)
	mbWindowStarted := false
	if mbPath != "" && opts.targetURL != "" {
		if err := startMbWindow(mbPath, openURL, url, !opts.noLinks, defaultToolWindowSize); err != nil {
			// 初始化/创建窗口失败：恢复控制台让错误信息可见
			setConsoleVisible(true)
			fmt.Println("  miniblink 窗口启动失败：" + err.Error())
			fmt.Println("  服务保持运行，可通过托盘菜单打开页面")
		} else {
			mbWindowStarted = true
		}
	}
	if opts.directURL != "" {
		mbWindowStarted = openWindow(mbPath, opts.directURL, url, !opts.noLinks, defaultToolWindowSize) || mbWindowStarted
	}
	mediaPlayerStarted := false
	if opts.mediaFile != "" {
		mediaPlayerStarted = openMediaFile(opts.mediaFile, url+"/AriaNg.html")
		if mediaPlayerStarted && !mbWindowStarted {
			waitMpvWindowsClosed()
			fmt.Println("  播放器窗口已关闭，程序退出")
			exitMain(0)
		}
	}
	if mediaOnly && !mediaPlayerStarted {
		fmt.Println("  媒体/图片打开失败，且未启用托盘，程序退出")
		exitMain(1)
	}

	// 托盘命令打开的内嵌窗口与启动窗口共享会话；最后一个窗口关闭时退出。
	select {
	case <-mbAllClosed():
		fmt.Println("  所有窗口（含播放器）已关闭，程序退出")
		exitMain(0)
	case err := <-serveErr:
		if err != nil {
			log.Println(err)
		}
	}
	exitMain(1)
}

// exitMain 统一退出入口：先清理托盘图标，再关闭由本程序启动的 aria2c 与虚拟内网子进程，最后退出进程。
func exitMain(code int) {
	stopTrayIfActive()
	shutdownAria2c()
	shutdownEasyTierCore()
	shutdownEasyTierWebEmbed()
	clipShutdown()
	os.Exit(code)
}

// listenPort 绑定端口；首选端口被占用时逐端口向上顺延（如 9100 -> 9101 -> 9102 ...）
func listenPort(preferred string) (net.Listener, string, error) {
	p, convErr := strconv.Atoi(preferred)
	if convErr != nil || p <= 0 || p > 65535 {
		return nil, "", fmt.Errorf("端口号无效：%s（应为 1-65535 的数字）", preferred)
	}

	last := p + maxPortAttempts - 1
	if last > 65535 {
		last = 65535
	}
	for candidate := p; candidate <= last; candidate++ {
		port := strconv.Itoa(candidate)
		ln, err := net.Listen("tcp", ":"+port)
		if err == nil {
			return ln, port, nil
		}
	}
	return nil, "", fmt.Errorf("端口 %d-%d 均不可用", p, last)
}

// handleStatic 以 static 为网站根目录提供页面：/ 对应 index.html，
// /AriaNg.html 等其他路径直接对应 static 下的同名文件（均已打包进 exe）。
func handleStatic(w http.ResponseWriter, r *http.Request) {
	http.FileServer(http.FS(staticRoot)).ServeHTTP(w, r)
}

// handleInterfaces 返回本机所有 IPv4 地址
func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(ListLocalIfaces())
}

// handleLocalNet 推测本机所在网段，并返回实际监听端口，便于前端生成局域网分享地址
func handleLocalNet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cidr":   guessLocalCIDR(),
		"port":   serverPort,
		"ifaces": ListLocalIfaces(),
	})
}

// handleScan SSE 实时推送扫描结果
func handleScan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	cfg := ScanConfig{MaxHosts: 4096}

	// 端口
	if ps := strings.TrimSpace(q.Get("ports")); ps != "" {
		for _, s := range strings.Split(ps, ",") {
			s = strings.TrimSpace(s)
			if p, err := strconv.Atoi(s); err == nil && p > 0 && p < 65536 {
				cfg.Ports = append(cfg.Ports, p)
			}
		}
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = DefaultPorts
	}

	// 超时（毫秒）
	cfg.Timeout = 400 * time.Millisecond
	if t := q.Get("timeout"); t != "" {
		if ms, err := strconv.Atoi(t); err == nil && ms > 0 && ms <= 10000 {
			cfg.Timeout = time.Duration(ms) * time.Millisecond
		}
	}

	// 并发（默认 20）
	cfg.Concurrency = DefaultConcurrency
	if c := q.Get("concurrency"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n > 0 && n <= 1000 {
			cfg.Concurrency = n
		}
	}

	cfg.UsePing = q.Get("ping") == "1" || q.Get("ping") == "true"
	cfg.CIDR = strings.TrimSpace(q.Get("cidr"))

	// SSE 响应头
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "当前连接不支持流式响应", http.StatusInternalServerError)
		return
	}

	emit := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(b))
		flusher.Flush()
	}

	summary, err := Scan(cfg, func(hr HostResult) {
		emit("result", hr)
	})
	if err != nil {
		emit("error", map[string]string{"message": err.Error()})
		return
	}
	emit("done", summary)
}
