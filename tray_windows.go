//go:build windows

package main

import (
	_ "embed"
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

//go:embed static/icon.ico
var trayIconICO []byte

const (
	trayIconID          = 1
	trayCallbackMessage = 0x0400 + 1  // WM_USER + 1
	hwndMessage         = ^uintptr(2) // HWND_MESSAGE(-3)

	wmNull         = 0x0000
	wmCommand      = 0x0111
	wmLButtonDbl   = 0x0203
	wmRButtonUp    = 0x0205
	wmDestroy      = 0x0002
	csDoubleClicks = 0x0008

	nimAdd     = 0
	nimDelete  = 2
	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04

	mfString       = 0x0000
	mfPopup        = 0x0010
	mfSeparator    = 0x0800
	tpmRightButton = 0x0002

	imageIcon      = 1
	lrLoadFromFile = 0x0008
	idiApplication = 32512
	cfUnicodeText  = 13
	gmemMoveable   = 0x0002

	uoiName            = 2
	desktopReadObjects = 0x0001

	mbIconInformation = 0x00000040
)

// 固定菜单项数量（不含分隔符）与一级菜单项上限。
const (
	fixedTrayMenuItems = 9
	maxFlatTrayItems   = 32
)

// 托盘菜单命令 ID，每个 ID 对应一个独立的命令函数。
const (
	cmdTrayOpenHome = iota + 1001
	cmdTrayOpenClipboard
	cmdTrayOpenAria2c
	cmdTrayOpenPlayer
	cmdTrayCopyAddress
	cmdTrayShowConsole
	cmdTrayHideConsole
	cmdTrayAbout
	cmdTrayExit
)

// tools.txt 中的工具菜单从该 ID 开始顺序分配，避免与固定命令冲突。
const cmdTrayToolBase = 2000

var (
	modShell32Tray  = syscall.NewLazyDLL("shell32.dll")
	modUser32Tray   = syscall.NewLazyDLL("user32.dll")
	modKernel32Tray = syscall.NewLazyDLL("kernel32.dll")

	procShellNotifyIconW        = modShell32Tray.NewProc("Shell_NotifyIconW")
	procExtractIconExW          = modShell32Tray.NewProc("ExtractIconExW")
	procCreatePopupMenu         = modUser32Tray.NewProc("CreatePopupMenu")
	procAppendMenuW             = modUser32Tray.NewProc("AppendMenuW")
	procTrackPopupMenuEx        = modUser32Tray.NewProc("TrackPopupMenuEx")
	procDestroyMenu             = modUser32Tray.NewProc("DestroyMenu")
	procGetCursorPos            = modUser32Tray.NewProc("GetCursorPos")
	procSetForegroundWindow     = modUser32Tray.NewProc("SetForegroundWindow")
	procPostMessageW            = modUser32Tray.NewProc("PostMessageW")
	procLoadImageW              = modUser32Tray.NewProc("LoadImageW")
	procLoadIconW               = modUser32Tray.NewProc("LoadIconW")
	procDestroyIcon             = modUser32Tray.NewProc("DestroyIcon")
	procRegisterClassExW        = modUser32Tray.NewProc("RegisterClassExW")
	procCreateWindowExW         = modUser32Tray.NewProc("CreateWindowExW")
	procGetMessageW             = modUser32Tray.NewProc("GetMessageW")
	procTranslateMessage        = modUser32Tray.NewProc("TranslateMessage")
	procDispatchMessageW        = modUser32Tray.NewProc("DispatchMessageW")
	procDefWindowProcW          = modUser32Tray.NewProc("DefWindowProcW")
	procPostQuitMessage         = modUser32Tray.NewProc("PostQuitMessage")
	procMessageBoxW             = modUser32Tray.NewProc("MessageBoxW")
	procOpenClipboard           = modUser32Tray.NewProc("OpenClipboard")
	procCloseClipboard          = modUser32Tray.NewProc("CloseClipboard")
	procEmptyClipboard          = modUser32Tray.NewProc("EmptyClipboard")
	procSetClipboardData        = modUser32Tray.NewProc("SetClipboardData")
	procOpenInputDesktop        = modUser32Tray.NewProc("OpenInputDesktop")
	procCloseDesktop            = modUser32Tray.NewProc("CloseDesktop")
	procGetUserObjectInfoW      = modUser32Tray.NewProc("GetUserObjectInformationW")
	procGetProcessWindowStation = modUser32Tray.NewProc("GetProcessWindowStation")
	procGetModuleHandleW        = modKernel32Tray.NewProc("GetModuleHandleW")
	procGlobalAlloc             = modKernel32Tray.NewProc("GlobalAlloc")
	procGlobalLock              = modKernel32Tray.NewProc("GlobalLock")
	procGlobalUnlock            = modKernel32Tray.NewProc("GlobalUnlock")
	procGlobalFree              = modKernel32Tray.NewProc("GlobalFree")
	procRtlMoveMemory           = modKernel32Tray.NewProc("RtlMoveMemory")
)

type trayPoint struct {
	X int32
	Y int32
}

type trayMSG struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      trayPoint
}

type trayWNDCLASSEXW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  uintptr
	lpszClassName uintptr
	hIconSm       uintptr
}

// NOTIFYICONDATAW（Vista+，x64 下大小 976 字节）
type trayNOTIFYICONDATAW struct {
	cbSize           uint32
	hwnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type trayApp struct {
	cfg         trayConfig
	mu          sync.Mutex // 保护 hwnd/hicon 的跨线程访问
	hwnd        uintptr
	hicon       uintptr
	wndProcCB   uintptr
	ready       chan struct{}
	done        chan struct{}
	readyOnce   sync.Once
	cleanupOnce sync.Once
	actions     map[uint32]func()
}

var (
	trayStateMu  sync.Mutex
	activeTray   *trayApp
	trayCallback []any // 保持 syscall.NewCallback 生成的函数指针存活
)

// isWindowsDesktopSession 判断是否处于可交互的 Windows 桌面会话。
// 服务进程通常使用 Service-0x... 窗口站且无法打开输入桌面，因此不会创建托盘。
func isWindowsDesktopSession() bool {
	hWinSta, _, _ := procGetProcessWindowStation.Call()
	if hWinSta == 0 {
		return false
	}
	var name [128]uint16
	var needed uint32
	ok, _, _ := procGetUserObjectInfoW.Call(hWinSta, uoiName,
		uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2),
		uintptr(unsafe.Pointer(&needed)))
	if ok == 0 || !strings.EqualFold(syscall.UTF16ToString(name[:]), "WinSta0") {
		return false
	}
	hDesk, _, _ := procOpenInputDesktop.Call(0, 0, desktopReadObjects)
	if hDesk == 0 {
		return false
	}
	procCloseDesktop.Call(hDesk)
	return true
}

// startTrayIfDesktop 仅在 Windows 桌面会话中启动托盘；启动成功返回 true。
func startTrayIfDesktop(cfg trayConfig) bool {
	if !isWindowsDesktopSession() {
		return false
	}
	app := &trayApp{
		cfg:     cfg,
		ready:   make(chan struct{}),
		done:    make(chan struct{}),
		actions: make(map[uint32]func()),
	}
	app.actions[cmdTrayOpenHome] = app.commandOpenHome
	app.actions[cmdTrayOpenClipboard] = app.commandOpenClipboard
	app.actions[cmdTrayOpenAria2c] = app.commandOpenAria2c
	app.actions[cmdTrayOpenPlayer] = app.commandOpenPlayer
	app.actions[cmdTrayCopyAddress] = app.commandCopyAddress
	app.actions[cmdTrayShowConsole] = app.commandShowConsole
	app.actions[cmdTrayHideConsole] = app.commandHideConsole
	app.actions[cmdTrayAbout] = app.commandAbout
	app.actions[cmdTrayExit] = app.commandExit
	for i, tool := range app.cfg.tools {
		t := tool
		app.actions[uint32(cmdTrayToolBase+i)] = func() { app.openTool(t) }
	}

	trayStateMu.Lock()
	activeTray = app
	trayStateMu.Unlock()
	go app.run()

	select {
	case <-app.ready:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func (a *trayApp) signalReady() { a.readyOnce.Do(func() { close(a.ready) }) }

func (a *trayApp) run() {
	defer close(a.done)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer a.signalReady()

	hInst, _, _ := procGetModuleHandleW.Call(0)
	// 使用进程相关的类名，避免同时运行多个实例时 RegisterClassEx 冲突。
	className, err := syscall.UTF16PtrFromString(fmt.Sprintf("IPScanTrayWindow_%d", os.Getpid()))
	if err != nil {
		return
	}
	windowName, _ := syscall.UTF16PtrFromString("ipscan tray")

	a.wndProcCB = syscall.NewCallback(a.wndProc)
	trayCallback = append(trayCallback, a.wndProcCB)

	wc := trayWNDCLASSEXW{
		cbSize:        uint32(unsafe.Sizeof(trayWNDCLASSEXW{})),
		style:         csDoubleClicks,
		lpfnWndProc:   a.wndProcCB,
		hInstance:     hInst,
		lpszClassName: uintptr(unsafe.Pointer(className)),
	}
	if atom, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		return
	}

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0, 0, 0, 0, 0,
		hwndMessage, 0, hInst, 0,
	)
	if hwnd == 0 {
		return
	}
	a.mu.Lock()
	a.hwnd = hwnd
	a.mu.Unlock()

	hicon := loadTrayIcon()
	a.mu.Lock()
	a.hicon = hicon
	a.mu.Unlock()
	a.addIcon()
	a.signalReady()

	var m trayMSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	a.cleanup()
}

func (a *trayApp) notifyData() trayNOTIFYICONDATAW {
	a.mu.Lock()
	hwnd, hicon := a.hwnd, a.hicon
	a.mu.Unlock()
	d := trayNOTIFYICONDATAW{
		cbSize:           uint32(unsafe.Sizeof(trayNOTIFYICONDATAW{})),
		hwnd:             hwnd,
		uID:              trayIconID,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: trayCallbackMessage,
		hIcon:            hicon,
	}
	tip, _ := syscall.UTF16FromString("ipscan - 局域网 IP 占用查询工具")
	copy(d.szTip[:], tip)
	return d
}

func (a *trayApp) addIcon() {
	d := a.notifyData()
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&d)))
}

func (a *trayApp) deleteIcon() {
	d := a.notifyData()
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&d)))
}

// cleanup 幂等地移除托盘图标并释放 HICON，可由托盘线程或退出流程调用。
func (a *trayApp) cleanup() {
	a.mu.Lock()
	hwnd := a.hwnd
	a.mu.Unlock()
	if hwnd == 0 {
		return
	}
	a.cleanupOnce.Do(func() {
		a.mu.Lock()
		hicon := a.hicon
		a.mu.Unlock()
		a.deleteIcon()
		if hicon != 0 {
			procDestroyIcon.Call(hicon)
			a.mu.Lock()
			a.hicon = 0
			a.mu.Unlock()
		}
	})
}

// trayActive 判断当前进程是否启用了托盘；窗口全部关闭时据此决定是否退出。
func trayActive() bool {
	trayStateMu.Lock()
	defer trayStateMu.Unlock()
	return activeTray != nil
}

// stopTrayIfActive 在进程退出前通知托盘线程结束并清理图标；
// 若托盘线程未能及时响应，则直接清理，确保 os.Exit 前图标已移除。
func stopTrayIfActive() {
	trayStateMu.Lock()
	app := activeTray
	trayStateMu.Unlock()
	if app == nil {
		return
	}

	select {
	case <-app.ready:
	case <-time.After(time.Second):
	}

	app.mu.Lock()
	hwnd := app.hwnd
	app.mu.Unlock()
	if hwnd != 0 {
		procPostMessageW.Call(hwnd, wmDestroy, 0, 0)
		select {
		case <-app.done:
			return
		case <-time.After(2 * time.Second):
		}
	}
	app.cleanup()
}

// loadTrayIcon 从内嵌的 static/icon.ico 创建 HICON；临时文件加载后立即删除。
// ICO 内是 PNG 压缩图像，LoadImageW 无法读取，因此使用 ExtractIconExW。
func loadTrayIcon() uintptr {
	f, err := os.CreateTemp("", "ipscan-tray-*.ico")
	if err != nil {
		h, _, _ := procLoadIconW.Call(0, idiApplication)
		return h
	}
	name := f.Name()
	_, err = f.Write(trayIconICO)
	_ = f.Close()
	defer os.Remove(name)

	if err == nil {
		if p, pErr := syscall.UTF16PtrFromString(name); pErr == nil {
			var hSmall uintptr
			n, _, _ := procExtractIconExW.Call(uintptr(unsafe.Pointer(p)), 0,
				0, uintptr(unsafe.Pointer(&hSmall)), 1)
			if n > 0 && hSmall != 0 {
				return hSmall
			}
		}
	}
	h, _, _ := procLoadIconW.Call(0, idiApplication)
	return h
}

func (a *trayApp) wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case wmCommand:
		id := uint32(wParam & 0xffff)
		if fn := a.actions[id]; fn != nil {
			safeTrayCall(fn)
		}
		return 0
	case trayCallbackMessage:
		// Shell_NotifyIcon 把鼠标消息放在 lParam，图标 ID 放在 wParam；
		// 直接等待 WM_RBUTTONUP 永远不会收到。
		switch uint32(lParam) {
		case wmRButtonUp:
			a.showMenu()
		case wmLButtonDbl:
			if fn := a.actions[cmdTrayOpenHome]; fn != nil {
				safeTrayCall(fn)
			}
		}
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func safeTrayCall(fn func()) {
	defer func() { _ = recover() }()
	fn()
}

func (a *trayApp) showMenu() {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	appendItem := func(id uint32, label string) {
		p, err := syscall.UTF16PtrFromString(label)
		if err != nil {
			return
		}
		procAppendMenuW.Call(hMenu, mfString, uintptr(id), uintptr(unsafe.Pointer(p)))
		runtime.KeepAlive(p)
	}

	appendItem(cmdTrayOpenHome, "打开主页")
	if len(a.cfg.tools) > 0 {
		if fixedTrayMenuItems+len(a.cfg.tools) < maxFlatTrayItems {
			// 菜单项不多时直接平铺，减少一次子菜单操作。
			for i, tool := range a.cfg.tools {
				appendItem(uint32(cmdTrayToolBase+i), tool.Name)
			}
		} else if hTools, _, _ := procCreatePopupMenu.Call(); hTools != 0 {
			for i, tool := range a.cfg.tools {
				p, err := syscall.UTF16PtrFromString(tool.Name)
				if err != nil {
					continue
				}
				procAppendMenuW.Call(hTools, mfString, uintptr(cmdTrayToolBase+i), uintptr(unsafe.Pointer(p)))
				runtime.KeepAlive(p)
			}
			label, _ := syscall.UTF16PtrFromString("工具")
			procAppendMenuW.Call(hMenu, mfPopup, hTools, uintptr(unsafe.Pointer(label)))
			runtime.KeepAlive(label)
		}
	}

	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendItem(cmdTrayOpenClipboard, "打开网络剪贴板")
	appendItem(cmdTrayOpenAria2c, "打开 aria2c 页面")
	appendItem(cmdTrayOpenPlayer, "播放器")

	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendItem(cmdTrayShowConsole, "显示控制台")
	appendItem(cmdTrayHideConsole, "隐藏控制台")
	appendItem(cmdTrayCopyAddress, "复制访问地址")
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendItem(cmdTrayAbout, "关于 ipscan")
	appendItem(cmdTrayExit, "退出")

	var pt trayPoint
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(a.hwnd)
	procTrackPopupMenuEx.Call(hMenu, tpmRightButton, uintptr(pt.X), uintptr(pt.Y), a.hwnd, 0)
	procPostMessageW.Call(a.hwnd, wmNull, 0, 0)
}

// 以下是各菜单项对应的独立命令函数。

// openWindow 用内嵌 miniblink 窗口打开地址；内核不可用时回退系统浏览器。
// size 为零值表示主页的大窗口，其他窗口由调用方传入配置尺寸或 800x600。
func (a *trayApp) openWindow(url string, size windowSize) {
	if a.cfg.mbDLL != "" {
		if err := openMbWindow(a.cfg.mbDLL, url, a.cfg.homeURL, true, size); err == nil {
			return
		} else {
			fmt.Println("  内嵌内核打开窗口失败：" + err.Error() + "，改用默认浏览器")
		}
	}
	_ = openBrowser(url)
}

// openTool 按 tools.txt 配置的打开方式打开工具。
func (a *trayApp) openTool(t toolEntry) {
	switch t.Mode {
	case toolModeSystem:
		_ = openBrowser(t.URL)
	case toolModeChrome:
		_ = openExternalChrome(t.URL, t.Size)
	default:
		a.openWindow(t.URL, t.Size)
	}
}

func (a *trayApp) commandOpenHome() { a.openWindow(a.cfg.homeURL, windowSize{}) }

func (a *trayApp) commandOpenClipboard() { a.openWindow(a.cfg.clipboardURL, defaultToolWindowSize) }

// commandOpenAria2c 先确保 aria2c RPC 就绪，再打开 AriaNg 页面。
func (a *trayApp) commandOpenAria2c() {
	go func() {
		ensureAria2cFromURL(a.cfg.aria2cURL)
		a.openWindow(a.cfg.aria2cURL, defaultToolWindowSize)
	}()
}

// commandOpenPlayer 在新线程中用 libmpv 打开播放窗口，不打开页面与其它无关模块。
func (a *trayApp) commandOpenPlayer() {
	go func() {
		demo := filepath.Join(mpvDataDir(), "demo.mp4")
		if !isExistingFile(demo) {
			return
		}
		dll, err := ensureMpvDLL(a.cfg.aria2cURL)
		if err != nil {
			fmt.Println("  libmpv-2.dll 准备失败：" + err.Error())
			return
		}
		fmt.Println("  播放器启动：" + dll + ",文件	" + demo)
		if err := startMpvPlayer(dll, demo); err != nil {
			fmt.Println("  libmpv 播放器启动失败：" + err.Error())
		}
	}()
}

func (a *trayApp) commandCopyAddress() { _ = copyTextToClipboard(a.cfg.homeURL) }

func (a *trayApp) commandShowConsole() { setConsoleVisible(true) }

func (a *trayApp) commandHideConsole() { setConsoleVisible(false) }

func (a *trayApp) commandAbout() {
	exe, err := os.Executable()
	if err != nil {
		exe = "(未知路径)"
	}
	text := fmt.Sprintf("ipscan %s\n\n地址：%s\n程序：%s", a.cfg.version, a.cfg.homeURL, exe)
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("关于 ipscan")
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), mbIconInformation)
	runtime.KeepAlive(t)
	runtime.KeepAlive(c)
}

func (a *trayApp) commandExit() {
	a.cleanup()
	// 退出流程需要等待托盘线程结束；放到新 goroutine 避免在当前托盘线程上自等待。
	go exitMain(0)
}

// copyTextToClipboard 使用 Win32 剪贴板写入 Unicode 文本。
func copyTextToClipboard(s string) bool {
	u, err := syscall.UTF16FromString(s)
	if err != nil || len(u) == 0 {
		return false
	}
	size := uintptr(len(u) * 2)
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return false
	}
	procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), size)
	runtime.KeepAlive(&u[0])
	procGlobalUnlock.Call(h)

	if r, _, _ := procOpenClipboard.Call(0); r == 0 {
		procGlobalFree.Call(h)
		return false
	}
	procEmptyClipboard.Call()
	r, _, _ := procSetClipboardData.Call(cfUnicodeText, h)
	procCloseClipboard.Call()
	if r == 0 {
		procGlobalFree.Call(h)
	}
	return r != 0
}
