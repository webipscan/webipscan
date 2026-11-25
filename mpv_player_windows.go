//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	mpvWindowClassName = "mpv"
	mpvWindowWaitMax   = 20 * time.Second
	mpvWMNCDestroy     = 0x0082
	wmKeyDown          = 0x0100
	vkKeyQ             = 0x51
	mpvCloseWaitMax    = 500 * time.Millisecond
)

var (
	procEnumWindows              = modUser32.NewProc("EnumWindows")
	procGetWindowThreadProcessId = modUser32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible          = modUser32.NewProc("IsWindowVisible")
	procGetClassNameW            = modUser32.NewProc("GetClassNameW")
	procGetCurrentProcessId      = modKernel32.NewProc("GetCurrentProcessId")

	mpvStartMu  sync.Mutex
	mpvEnumMu   sync.Mutex
	mpvEnumOnce sync.Once
	mpvEnumCB   uintptr
	mpvScan     mpvWindowScan

	mpvSubOnce sync.Once
	mpvSubCB   uintptr
	mpvSubsMu  sync.Mutex
	mpvSubs    = make(map[uintptr]*mpvSubclass)
)

// mpvSubclass 记录播放器窗口的原始窗口过程与关闭通知通道。
type mpvSubclass struct {
	orig uintptr
	quit chan struct{}
}

type mpvWindowScan struct {
	pid            uint32
	console        uintptr
	collect        map[uintptr]bool
	skipRegistered bool
	found          uintptr
}

// startMpvPlayer 在当前进程的新线程中用 libmpv-2.dll 打开播放文件。
// 播放文件不存在时仍打开空播放窗口，便于用户后续拖入文件。
// 每次调用创建独立的 mpv 实例和窗口，窗口 HWND 计入全局窗口总数。
func startMpvPlayer(dllPath, filePath string) error {
	if dllPath == "" {
		return fmt.Errorf("libmpv DLL 路径为空")
	}
	if _, err := os.Stat(dllPath); err != nil {
		return fmt.Errorf("libmpv DLL 不可用：%w", err)
	}
	dllAbs, err := filepath.Abs(dllPath)
	if err != nil {
		dllAbs = dllPath
	}
	fileAbs := ""
	if isExistingFile(filePath) {
		fileAbs, err = filepath.Abs(filePath)
		if err != nil {
			fileAbs = filePath
		}
		mpvLog("准备启动播放器线程：DLL=%s，文件=%s", dllAbs, fileAbs)
	} else {
		mpvLog("播放文件不存在，打开空播放窗口：%s", filePath)
	}
	go runMpvPlayerThread(dllAbs, fileAbs)
	return nil
}

// waitMpvWindowsClosed 等待本进程创建的 libmpv 窗口全部关闭。
// 位置参数为媒体文件时进程只承担播放职责，窗口关闭即可退出。
func waitMpvWindowsClosed() {
	deadline := time.Now().Add(mpvWindowWaitMax)
	for extraWindowCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	for extraWindowCount() > 0 {
		time.Sleep(200 * time.Millisecond)
	}
}

// runMpvPlayerThread 完成一次播放器实例的创建、窗口绑定与生命周期跟踪。
func runMpvPlayerThread(dllPath, filePath string) {
	procs, h, hwnd, err := func() (map[string]*syscall.LazyProc, uintptr, uintptr, error) {
		// 串行化启动：等待属于本次调用的新窗口出现，跳过已登记的活动窗口。
		mpvStartMu.Lock()
		defer mpvStartMu.Unlock()

		procs, err := loadMpvProcs(dllPath)
		if err != nil {
			return nil, 0, 0, err
		}
		h, err := openMpvPlayer(procs, filePath)
		if err != nil {
			return nil, 0, 0, err
		}

		deadline := time.Now().Add(mpvWindowWaitMax)
		var hwnd uintptr
		for time.Now().Before(deadline) && hwnd == 0 {
			hwnd = findNewMpvWindow()
			if hwnd == 0 {
				time.Sleep(200 * time.Millisecond)
			}
		}
		if hwnd == 0 {
			procs["mpv_terminate_destroy"].Call(h)
			return nil, 0, 0, fmt.Errorf("未找到 libmpv 播放器窗口")
		}
		registerExtraWindow(hwnd)
		return procs, h, hwnd, nil
	}()
	if err != nil {
		mpvLog("libmpv 播放器启动失败：%v", err)
		return
	}
	defer procs["mpv_terminate_destroy"].Call(h)
	if filePath == "" {
		mpvLog("播放器窗口已打开 HWND=%d，空播放窗口", hwnd)
	} else {
		mpvLog("播放器窗口已打开 HWND=%d，循环播放 %s", hwnd, filePath)
	}

	quitCh := make(chan struct{}, 1)
	if err := installMpvSubclass(hwnd, quitCh); err != nil {
		mpvLog("接管播放器窗口消息失败：%v", err)
	} else {
		defer removeMpvSubclass(hwnd)
	}

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	running := true
	for running {
		select {
		case <-quitCh:
			mpvLog("收到播放器退出请求 HWND=%d，发送 quit 并关闭窗口", hwnd)
			if err := mpvCommand(procs, h, "quit"); err != nil {
				mpvLog("发送 quit 命令失败：%v", err)
			}
			closeMpvWindow(hwnd)
			waitMpvWindowClosed(hwnd)
			unregisterExtraWindow(hwnd)
			running = false
		case <-ticker.C:
			alive, _, _ := procIsWindow.Call(hwnd)
			vis, _, _ := procIsWindowVisible.Call(hwnd)
			if alive == 0 || vis == 0 {
				mpvLog("检测到播放器窗口消失或隐藏 HWND=%d alive=%d visible=%d", hwnd, alive, vis)
				_ = mpvCommand(procs, h, "quit")
				closeMpvWindow(hwnd)
				waitMpvWindowClosed(hwnd)
				unregisterExtraWindow(hwnd)
				running = false
			}
		}
	}
	unregisterExtraWindow(hwnd)
	mpvLog("播放器线程退出，HWND=%d", hwnd)
}

// closeMpvWindow 还原窗口过程后向窗口线程投递 WM_CLOSE。
// mpv 内核响应 quit 时可能只结束文件而没有销毁窗口，主动关窗避免出现
// “文件已退出、窗口仍在却无法再接收新文件”的空窗口。
func closeMpvWindow(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	if alive, _, _ := procIsWindow.Call(hwnd); alive == 0 {
		return
	}
	removeMpvSubclass(hwnd)
	procPostMessageW.Call(hwnd, wmClose, 0, 0)
	mpvLog("已向播放器窗口投递 WM_CLOSE HWND=%d", hwnd)
}

// waitMpvWindowClosed 等待窗口真正销毁后再注销 HWND：
// 过早注销会让尚未销毁的旧窗口被下一次启动误认为新窗口，
// 而销毁后不及时注销又会让复用同一 HWND 的新窗口被漏掉。
func waitMpvWindowClosed(hwnd uintptr) {
	deadline := time.Now().Add(mpvCloseWaitMax)
	for time.Now().Before(deadline) {
		if alive, _, _ := procIsWindow.Call(hwnd); alive == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	mpvLog("等待播放器窗口关闭超时 HWND=%d", hwnd)
}

// installMpvSubclass 接管播放器窗口过程，用于响应关闭按钮并记录消息。
func installMpvSubclass(hwnd uintptr, quit chan struct{}) error {
	mpvSubOnce.Do(func() { mpvSubCB = syscall.NewCallback(mpvWindowProc) })
	orig := setWindowLongPtr(hwnd, gwlpWndProc, mpvSubCB)
	if orig == 0 {
		return fmt.Errorf("SetWindowLongPtrW(GWLP_WNDPROC) 失败")
	}
	mpvSubsMu.Lock()
	mpvSubs[hwnd] = &mpvSubclass{orig: orig, quit: quit}
	mpvSubsMu.Unlock()
	mpvLog("已接管播放器窗口消息 HWND=%d 原窗口过程=%d", hwnd, orig)
	return nil
}

func removeMpvSubclass(hwnd uintptr) {
	mpvSubsMu.Lock()
	sub := mpvSubs[hwnd]
	delete(mpvSubs, hwnd)
	mpvSubsMu.Unlock()
	if sub == nil {
		return
	}
	if alive, _, _ := procIsWindow.Call(hwnd); alive != 0 {
		setWindowLongPtr(hwnd, gwlpWndProc, sub.orig)
		mpvLog("已还原播放器窗口过程 HWND=%d", hwnd)
	}
}

// mpvWindowProc 是播放器窗口的消息响应函数，运行在窗口所属线程。
func mpvWindowProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	mpvSubsMu.Lock()
	sub := mpvSubs[hwnd]
	mpvSubsMu.Unlock()
	if sub == nil || sub.orig == 0 {
		return 0
	}
	switch msg {
	case wmClose:
		mpvLog("播放器窗口事件：WM_CLOSE HWND=%d wParam=%d lParam=%d", hwnd, wParam, lParam)
		notifyMpvQuit(sub)
		return 0
	case wmKeyDown:
		// mpv 的默认 q 绑定会直接关闭内核但可能留下空窗口，这里先接管，
		// 由播放器线程统一执行 quit、关窗和资源释放。
		if wParam == vkKeyQ {
			mpvLog("播放器窗口事件：按下 q HWND=%d", hwnd)
			notifyMpvQuit(sub)
			return 0
		}
	case mpvWMNCDestroy:
		mpvLog("播放器窗口事件：WM_NCDESTROY HWND=%d", hwnd)
		mpvSubsMu.Lock()
		if cur := mpvSubs[hwnd]; cur == sub {
			delete(mpvSubs, hwnd)
		}
		mpvSubsMu.Unlock()
		// 窗口由 mpv 自行销毁（例如其内部的 quit 先生效）时也要收尾。
		notifyMpvQuit(sub)
	}
	ret, _, _ := procCallWindowProcW.Call(sub.orig, hwnd, msg, wParam, lParam)
	return ret
}

// notifyMpvQuit 把关闭请求送给播放器线程，重复消息只保留一个。
func notifyMpvQuit(sub *mpvSubclass) {
	if sub == nil {
		return
	}
	select {
	case sub.quit <- struct{}{}:
	default:
	}
}

// loadMpvProcs 从指定 DLL 读取创建播放器所需的导出函数。
func loadMpvProcs(dllPath string) (map[string]*syscall.LazyProc, error) {
	dll := syscall.NewLazyDLL(dllPath)
	procs := make(map[string]*syscall.LazyProc)
	for _, name := range []string{
		"mpv_create", "mpv_initialize", "mpv_set_option_string",
		"mpv_command", "mpv_terminate_destroy",
	} {
		p := dll.NewProc(name)
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("libmpv 缺少导出 %s：%w", name, err)
		}
		procs[name] = p
	}
	return procs, nil
}

// openMpvPlayer 创建并初始化一个使用自身窗口播放文件的 mpv 实例。
func openMpvPlayer(procs map[string]*syscall.LazyProc, filePath string) (uintptr, error) {
	h, _, _ := procs["mpv_create"].Call()
	if h == 0 {
		return 0, fmt.Errorf("mpv_create 失败")
	}
	mpvLog("mpv 实例已创建 handle=%d", h)
	ready := false
	defer func() {
		if !ready {
			procs["mpv_terminate_destroy"].Call(h)
		}
	}()

	opts := [][2]string{
		{"loop-file", "inf"},
		{"force-window", "yes"},
		{"input-default-bindings", "yes"},
	}
	if filePath == "" {
		opts = append(opts, [2]string{"idle", "yes"})
	}
	for _, opt := range opts {
		if err := mpvSetOption(procs, h, opt[0], opt[1]); err != nil {
			return 0, err
		}
	}
	if r, _, _ := procs["mpv_initialize"].Call(h); int(int32(r)) != 0 {
		return 0, fmt.Errorf("mpv_initialize 失败（%d）", int(int32(r)))
	}
	mpvLog("mpv_initialize 完成 handle=%d", h)

	// 再尝试绑定一次 CLOSE_WIN；真正的关闭响应由窗口消息钩子负责。
	if err := mpvCommand(procs, h, "define-key", "CLOSE_WIN", "quit"); err != nil {
		mpvLog("define-key CLOSE_WIN 未生效：%v", err)
	}
	if filePath != "" {
		if err := mpvCommand(procs, h, "loadfile", filepath.ToSlash(filePath), "replace"); err != nil {
			return 0, err
		}
		mpvLog("mpv 已加载文件 handle=%d file=%s", h, filePath)
	} else {
		mpvLog("mpv 以空播放窗口启动 handle=%d", h)
	}
	ready = true
	return h, nil
}

// mpvCommand 以参数数组形式调用 mpv_command，避免命令字符串转义问题。
func mpvCommand(procs map[string]*syscall.LazyProc, h uintptr, args ...string) error {
	ptrs := make([]*byte, len(args))
	argv := make([]uintptr, len(args)+1)
	for i, s := range args {
		p, err := syscall.BytePtrFromString(s)
		if err != nil {
			return err
		}
		ptrs[i] = p
		argv[i] = uintptr(unsafe.Pointer(p))
	}
	argv[len(args)] = 0
	r, _, _ := procs["mpv_command"].Call(h, uintptr(unsafe.Pointer(&argv[0])))
	runtime.KeepAlive(ptrs)
	if code := int(int32(r)); code != 0 {
		return fmt.Errorf("mpv 命令 %s 失败（%d）", strings.Join(args, " "), code)
	}
	return nil
}

func mpvSetOption(procs map[string]*syscall.LazyProc, h uintptr, name, value string) error {
	n, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	v, err := syscall.BytePtrFromString(value)
	if err != nil {
		return err
	}
	r, _, _ := procs["mpv_set_option_string"].Call(h,
		uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(v)))
	runtime.KeepAlive(n)
	runtime.KeepAlive(v)
	if code := int(int32(r)); code != 0 {
		return fmt.Errorf("设置 %s=%s 失败（%d）", name, value, code)
	}
	return nil
}

// mpvEnumWindowProc 只枚举当前进程可见的 mpv 窗口（类名 "mpv"）。
func mpvEnumWindowProc(hwnd, _ uintptr) uintptr {
	scan := &mpvScan
	if hwnd == 0 || hwnd == scan.console {
		return 1
	}
	var pid uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid != scan.pid {
		return 1
	}
	if vis, _, _ := procIsWindowVisible.Call(hwnd); vis == 0 {
		return 1
	}
	var buf [80]uint16
	n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || !strings.EqualFold(syscall.UTF16ToString(buf[:n]), mpvWindowClassName) {
		return 1
	}
	if scan.collect != nil {
		scan.collect[hwnd] = true
		return 1
	}
	// 只按“已登记的活动窗口”排除：旧窗口关闭后 HWND 可能被新窗口复用，
	// 用启动前的 HWND 快照排除会把新窗口误判为旧窗口，导致按 q 后无法重开。
	if scan.skipRegistered && mpvWindowRegistered(hwnd) {
		return 1
	}
	scan.found = hwnd
	return 0
}

func scanMpvWindows(collect map[uintptr]bool, skipRegistered bool) uintptr {
	mpvEnumMu.Lock()
	defer mpvEnumMu.Unlock()
	mpvEnumOnce.Do(func() { mpvEnumCB = syscall.NewCallback(mpvEnumWindowProc) })
	mpvScan = mpvWindowScan{
		pid:            uint32(mpvProcessID()),
		collect:        collect,
		skipRegistered: skipRegistered,
	}
	mpvScan.console, _, _ = procGetConsoleWindow.Call()
	procEnumWindows.Call(mpvEnumCB, 0)
	return mpvScan.found
}

func findNewMpvWindow() uintptr {
	return scanMpvWindows(nil, true)
}

func mpvWindowRegistered(hwnd uintptr) bool {
	extraWinMu.Lock()
	ok := extraWindows[hwnd]
	extraWinMu.Unlock()
	return ok
}

func mpvProcessID() uint32 {
	id, _, _ := procGetCurrentProcessId.Call()
	return uint32(id)
}
