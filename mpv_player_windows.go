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
	before         map[uintptr]bool
	collect        map[uintptr]bool
	skipRegistered bool
	found          uintptr
}

// startMpvPlayer 在当前进程的新线程中用 libmpv-2.dll 打开播放文件。
// 每次调用创建独立的 mpv 实例和窗口，窗口 HWND 计入全局窗口总数。
func startMpvPlayer(dllPath, filePath string) error {
	if dllPath == "" {
		return fmt.Errorf("libmpv DLL 路径为空")
	}
	if _, err := os.Stat(dllPath); err != nil {
		return fmt.Errorf("libmpv DLL 不可用：%w", err)
	}
	if !isExistingFile(filePath) {
		return fmt.Errorf("播放文件不存在：%s", filePath)
	}
	dllAbs, err := filepath.Abs(dllPath)
	if err != nil {
		dllAbs = dllPath
	}
	fileAbs, err := filepath.Abs(filePath)
	if err != nil {
		fileAbs = filePath
	}
	mpvLog("准备启动播放器线程：DLL=%s，文件=%s", dllAbs, fileAbs)
	go runMpvPlayerThread(dllAbs, fileAbs)
	return nil
}

// runMpvPlayerThread 完成一次播放器实例的创建、窗口绑定与生命周期跟踪。
func runMpvPlayerThread(dllPath, filePath string) {
	procs, h, hwnd, err := func() (map[string]*syscall.LazyProc, uintptr, uintptr, error) {
		// 串行化启动：先快照已有窗口，再等待属于本次调用的新窗口出现。
		mpvStartMu.Lock()
		defer mpvStartMu.Unlock()

		before := snapshotMpvWindows()
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
			hwnd = findNewMpvWindow(before)
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
	mpvLog("播放器窗口已打开 HWND=%d，循环播放 %s", hwnd, filePath)

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
			mpvLog("收到窗口关闭按钮消息 HWND=%d，发送 quit 命令", hwnd)
			if err := mpvCommand(procs, h, "quit"); err != nil {
				mpvLog("发送 quit 命令失败：%v", err)
			}
			running = false
		case <-ticker.C:
			alive, _, _ := procIsWindow.Call(hwnd)
			vis, _, _ := procIsWindowVisible.Call(hwnd)
			if alive == 0 || vis == 0 {
				mpvLog("检测到播放器窗口消失或隐藏 HWND=%d alive=%d visible=%d", hwnd, alive, vis)
				running = false
			}
		}
	}
	unregisterExtraWindow(hwnd)
	mpvLog("播放器线程退出，HWND=%d", hwnd)
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
		select {
		case sub.quit <- struct{}{}:
		default:
		}
		return 0
	case mpvWMNCDestroy:
		mpvLog("播放器窗口事件：WM_NCDESTROY HWND=%d", hwnd)
		mpvSubsMu.Lock()
		if cur := mpvSubs[hwnd]; cur == sub {
			delete(mpvSubs, hwnd)
		}
		mpvSubsMu.Unlock()
	}
	ret, _, _ := procCallWindowProcW.Call(sub.orig, hwnd, msg, wParam, lParam)
	return ret
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

	for _, opt := range [][2]string{
		{"loop-file", "inf"},
		//	{"keep-open", "yes"},
		{"force-window", "yes"},
		//	{"drag-and-drop", "yes"},
		{"input-default-bindings", "yes"},
	} {
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
	if err := mpvCommand(procs, h, "loadfile", filepath.ToSlash(filePath), "replace"); err != nil {
		return 0, err
	}
	mpvLog("mpv 已加载文件 handle=%d file=%s", h, filePath)
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
	if scan.before[hwnd] {
		// 旧窗口可能已关闭且 HWND 被新窗口复用，仍存在的才排除。
		if alive, _, _ := procIsWindow.Call(hwnd); alive != 0 {
			return 1
		}
	}
	if scan.skipRegistered && mpvWindowRegistered(hwnd) {
		return 1
	}
	scan.found = hwnd
	return 0
}

func scanMpvWindows(before, collect map[uintptr]bool, skipRegistered bool) uintptr {
	mpvEnumMu.Lock()
	defer mpvEnumMu.Unlock()
	mpvEnumOnce.Do(func() { mpvEnumCB = syscall.NewCallback(mpvEnumWindowProc) })
	mpvScan = mpvWindowScan{
		pid:            uint32(mpvProcessID()),
		before:         before,
		collect:        collect,
		skipRegistered: skipRegistered,
	}
	mpvScan.console, _, _ = procGetConsoleWindow.Call()
	procEnumWindows.Call(mpvEnumCB, 0)
	return mpvScan.found
}

func snapshotMpvWindows() map[uintptr]bool {
	windows := make(map[uintptr]bool)
	scanMpvWindows(nil, windows, false)
	return windows
}

func findNewMpvWindow(before map[uintptr]bool) uintptr {
	return scanMpvWindows(before, nil, true)
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
