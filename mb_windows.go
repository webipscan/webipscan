//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// mb.h 中 MB_WINDOW_TYPE_POPUP = 0，即普通带边框的顶层窗口
const (
	mbWindowTypePopup = 0
	wmQuit            = 0x0012
	smCXScreen        = 0
	smCYScreen        = 1
	swHide            = 0
	swShow            = 5

	// mbNavigationType（mb.h）
	mbNavLinkClick    = 0
	mbNavFormSubmit   = 1
	mbNavBackForward  = 2
	mbNavReload       = 3
	mbNavFormResubmit = 4
	mbNavOther        = 5
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modUser32   = syscall.NewLazyDLL("user32.dll")

	procSetDllDirectoryW      = modKernel32.NewProc("SetDllDirectoryW")
	procGetConsoleWindow      = modKernel32.NewProc("GetConsoleWindow")
	procGetConsoleProcessList = modKernel32.NewProc("GetConsoleProcessList")
	procFreeConsole           = modKernel32.NewProc("FreeConsole")
	procAllocConsole          = modKernel32.NewProc("AllocConsole")
	procGetCurrentThreadId    = modKernel32.NewProc("GetCurrentThreadId")
	procPostThreadMessageW    = modUser32.NewProc("PostThreadMessageW")
	procIsWindow              = modUser32.NewProc("IsWindow")
	procGetSystemMetrics      = modUser32.NewProc("GetSystemMetrics")
	procShowWindowW           = modUser32.NewProc("ShowWindow")
	procGetForegroundWindow   = modUser32.NewProc("GetForegroundWindow")
	procGetAsyncKeyState      = modUser32.NewProc("GetAsyncKeyState")
	procMapVirtualKeyW        = modUser32.NewProc("MapVirtualKeyW")
	procGetKeyNameTextW       = modUser32.NewProc("GetKeyNameTextW")

	// C 侧可能长期持有这些字符串指针，放在包级避免被 GC 回收
	mbUTF16Strings []*uint16

	// 共享控制台模式下是否通过 FreeConsole 脱离过控制台
	mbConsoleDetached bool

	// mb132_x64.dll 必须导出的 API（mb.h: MB_FOR_EACH_DEFINE_FUNCTION / mbInit）
	mbRequiredProcs = []string{
		"mbInit", "mbCreateWebWindow", "mbShowWindow", "mbLoadURL", "mbRunMessageLoop",
	}
)

// utf16Arg 把字符串转为 Windows UTF-16 指针，并长期持有该内存
func utf16Arg(s string) uintptr {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return 0
	}
	mbUTF16Strings = append(mbUTF16Strings, p)
	return uintptr(unsafe.Pointer(p))
}

// mbGoCallbacks 保持回调闭包存活，直到进程退出
var mbGoCallbacks []any

// mbNewCallback 创建并持有 Go 回调（stdcall，与 MB_CALL_TYPE 一致）
func mbNewCallback(fn any) uintptr {
	cb := syscall.NewCallback(fn)
	mbGoCallbacks = append(mbGoCallbacks, fn)
	return cb
}

// mbUTF8String 读取 miniblink 回调传入的 UTF-8 字符串（以 NUL 结尾）
func mbUTF8String(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	var out []byte
	for i := 0; i < 8192; i++ {
		c := *(*byte)(unsafe.Add(p, uintptr(i)))
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

// mbLogEvent 把浏览器事件输出到主控制台窗口
func mbLogEvent(event, detail string) {
	if detail == "" {
		fmt.Printf("[mb %s] %s\n", time.Now().Format("15:04:05.000"), event)
		return
	}
	fmt.Printf("[mb %s] %s: %s\n", time.Now().Format("15:04:05.000"), event, detail)
}

func mbNavTypeName(t uintptr) string {
	switch t {
	case mbNavLinkClick:
		return "链接点击"
	case mbNavFormSubmit:
		return "表单提交"
	case mbNavBackForward:
		return "前进/后退"
	case mbNavReload:
		return "刷新"
	case mbNavFormResubmit:
		return "重复提交"
	case mbNavOther:
		return "其他"
	default:
		return fmt.Sprintf("未知(%d)", t)
	}
}

// 下载相关常量（mb.h）
const (
	mbDownloadOptCancel    = 0
	mbDownloadOptCacheData = 1
	mbLoadingSucceeded     = 0
	mbLoadingFailed        = 1
	mbLoadingCanceled      = 2
	mbDialogMagic          = 0x6f64626d // 'mbdo'
)

// 与 mb.h 中 C 结构体内存布局一致，传给 mbPopupDialogAndDownload
type mbNetJobDataBind struct {
	param          uintptr
	recvCallback   uintptr
	finishCallback uintptr
}

type mbDownloadBind struct {
	param             uintptr
	recvCallback      uintptr
	finishCallback    uintptr
	saveNameCallback  uintptr
	beginSaveCallback uintptr
}

type mbDialogOptions struct {
	magic                   int32
	title                   uintptr
	defaultPath             uintptr
	buttonLabel             uintptr
	filters                 uintptr
	filtersCount            int32
	prop                    int32
	message                 uintptr
	securityScopedBookmarks int32
}

type mbDownloadInfo struct {
	url      string
	expected uintptr
	total    int64
	lastLog  int64
}

var (
	mbUTF8Mu        sync.Mutex
	mbUTF8Strings   [][]byte
	mbDownloads     sync.Map // job -> *mbDownloadInfo
	mbDownloadBinds sync.Map // job -> *mbDownloadBindsHold（保持 C 结构体内存存活）
)

type mbDownloadBindsHold struct {
	dataBind *mbNetJobDataBind
	bind     *mbDownloadBind
	dialog   *mbDialogOptions
}

// mbUTF8Arg 分配以 NUL 结尾的 UTF-8 字符串（miniblink 的 const char* 参数）
func mbUTF8Arg(s string) uintptr {
	b := append([]byte(s), 0)
	mbUTF8Mu.Lock()
	mbUTF8Strings = append(mbUTF8Strings, b)
	mbUTF8Mu.Unlock()
	return uintptr(unsafe.Pointer(&b[0]))
}

// mbUTF16StringN 读取以 NUL 结尾的 WCHAR 字符串
func mbUTF16StringN(p unsafe.Pointer, max int) string {
	if p == nil {
		return ""
	}
	buf := make([]uint16, 0, max)
	for i := 0; i < max; i++ {
		c := *(*uint16)(unsafe.Add(p, uintptr(i)*2))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return syscall.UTF16ToString(buf)
}

func mbSizeText(n uintptr) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func mbDownloadDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, "Downloads")
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return p
	}
	return ""
}

// 虚拟键码与按键状态位（winuser.h）
const (
	vkShift    = 0x10
	vkControl  = 0x11
	vkAlt      = 0x12
	vkLWin     = 0x5B
	vkRWin     = 0x5C
	vkHome     = 0x24
	vkLeft     = 0x25
	vkRight    = 0x27
	vkR        = 0x42
	vkF5       = 0x74
	keyDownBit = 0x8000
)

// mbMod 修饰键组合（位掩码），用于精确匹配快捷键
type mbMod uint8

const (
	mbModCtrl mbMod = 1 << iota
	mbModShift
	mbModAlt
	mbModWin
)

// mbSpecialVKNames 常用非字符键的可读名称；字符键与 F 键在 mbKeyName 中按范围生成
var mbSpecialVKNames = map[uintptr]string{
	0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter", 0x1B: "Esc", 0x20: "Space",
	0x21: "PageUp", 0x22: "PageDown", 0x23: "End", 0x24: "Home",
	0x25: "Left", 0x26: "Up", 0x27: "Right", 0x28: "Down",
	0x2D: "Insert", 0x2E: "Delete", 0x2A: "PrintScreen", 0x2F: "Help",
	0x90: "NumLock", 0x91: "ScrollLock",
	0xA0: "LShift", 0xA1: "RShift", 0xA2: "LCtrl", 0xA3: "RCtrl", 0xA4: "LAlt", 0xA5: "RAlt",
	0x5B: "LWin", 0x5C: "RWin", 0x5D: "Apps",
	0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
	0xC0: "`", 0xDB: "[", 0xDC: `\`, 0xDD: "]", 0xDE: "'",
}

func mbIsModifierKey(vk uintptr) bool {
	switch vk {
	case vkShift, vkControl, vkAlt, vkLWin, vkRWin, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5:
		return true
	}
	return false
}

func mbKeyDown(vk uintptr) bool {
	state, _, _ := procGetAsyncKeyState.Call(vk)
	return state&keyDownBit != 0
}

// mbCurrentMods 读取当前按住的 Ctrl/Shift/Alt/Win，返回修饰键位掩码
func mbCurrentMods() mbMod {
	var m mbMod
	if mbKeyDown(vkControl) {
		m |= mbModCtrl
	}
	if mbKeyDown(vkShift) {
		m |= mbModShift
	}
	if mbKeyDown(vkAlt) {
		m |= mbModAlt
	}
	if mbKeyDown(vkLWin) || mbKeyDown(vkRWin) {
		m |= mbModWin
	}
	return m
}

// text 返回如 "Ctrl+Alt+" 的前缀；无修饰键时返回空串
func (m mbMod) text() string {
	var parts []string
	if m&mbModCtrl != 0 {
		parts = append(parts, "Ctrl")
	}
	if m&mbModShift != 0 {
		parts = append(parts, "Shift")
	}
	if m&mbModAlt != 0 {
		parts = append(parts, "Alt")
	}
	if m&mbModWin != 0 {
		parts = append(parts, "Win")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "+") + "+"
}

// mbKeyLabel 组成可读按键名，如 "Ctrl+Home"
func mbKeyLabel(mods mbMod, vk uintptr) string {
	return mods.text() + mbKeyName(vk)
}

// mbKeyName 取按键可读名称，优先用内建表，其次走系统键名翻译
func mbKeyName(vk uintptr) string {
	switch {
	case vk >= '0' && vk <= '9', vk >= 'A' && vk <= 'Z':
		return string(rune(vk))
	case vk >= 0x70 && vk <= 0x87:
		return fmt.Sprintf("F%d", vk-0x6F)
	case vk >= 0x60 && vk <= 0x69:
		return fmt.Sprintf("Num%d", vk-0x60)
	}
	if name, ok := mbSpecialVKNames[vk]; ok {
		return name
	}
	sc, _, _ := procMapVirtualKeyW.Call(vk, 0) // MAPVK_VK_TO_VSC
	if sc != 0 {
		var buf [64]uint16
		n, _, _ := procGetKeyNameTextW.Call(sc<<16, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n > 0 && int(n) <= len(buf) {
			return syscall.UTF16ToString(buf[:int(n)])
		}
	}
	return fmt.Sprintf("VK(0x%02X)", vk)
}

// mbShortcut 一条窗口级快捷键：mods 是要求的完整修饰键组合，vk 是触发键
type mbShortcut struct {
	name   string
	desc   string
	mods   mbMod
	vk     uintptr
	action func()
}

// mbShortcutRegistry 保存可动态增删的快捷键，供 monitorMbKeys 实时读取。
type mbShortcutRegistry struct {
	mu       sync.RWMutex
	items    map[uint64]mbShortcut
	nextID   uint64
	stopCh   chan struct{}
	stopOnce sync.Once
}

func newMbShortcutRegistry() *mbShortcutRegistry {
	return &mbShortcutRegistry{
		items:  make(map[uint64]mbShortcut),
		stopCh: make(chan struct{}),
	}
}

// add 注册快捷键并返回取消函数；调用该函数即可撤销这一条。
// 同一动作按不同 mods/vk 多次 add 即可支持更多快捷键。
func (r *mbShortcutRegistry) add(mods mbMod, vk uintptr, action func(), desc string) func() {
	if action == nil {
		return func() {}
	}
	name := mbKeyLabel(mods, vk)
	if desc == "" {
		desc = name
	}
	r.mu.Lock()
	r.nextID++
	id := r.nextID
	r.items[id] = mbShortcut{name: name, desc: desc, mods: mods, vk: vk, action: action}
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.items, id)
			r.mu.Unlock()
		})
	}
}

// match 要求修饰键组合完全一致，避免 Ctrl+Alt+Left 误触发 Alt+Left
func (r *mbShortcutRegistry) match(mods mbMod, vk uintptr) (mbShortcut, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.items {
		if s.vk == vk && s.mods == mods {
			return s, true
		}
	}
	return mbShortcut{}, false
}

// stop 停止按键监听并清空所有快捷键
func (r *mbShortcutRegistry) stop() {
	r.stopOnce.Do(func() { close(r.stopCh) })
	r.mu.Lock()
	r.items = make(map[uint64]mbShortcut)
	r.mu.Unlock()
}

// monitorMbKeys 在该窗口处于前台时提取按键（含 Ctrl/Shift/Alt/Win 组合）并输出到控制台，
// 命中注册表的按键执行对应动作。仅记录按下沿，不记录系统自动重复；窗口失焦时清空状态。
// 通过 reg.add 返回的取消函数可撤销单条快捷键，reg.stop() 可停止整个监听。
func monitorMbKeys(hwnd uintptr, reg *mbShortcutRegistry) {
	if reg == nil {
		return
	}
	t := time.NewTicker(30 * time.Millisecond)
	defer t.Stop()
	var prev [256]bool
	for {
		select {
		case <-reg.stopCh:
			return
		case <-t.C:
		}
		if alive, _, _ := procIsWindow.Call(hwnd); alive == 0 {
			return
		}
		fg, _, _ := procGetForegroundWindow.Call()
		if fg != hwnd {
			prev = [256]bool{}
			continue
		}
		mods := mbCurrentMods()
		for vk := uintptr(1); vk < 256; vk++ {
			down := mbKeyDown(vk)
			if down && !prev[vk] {
				if mbIsModifierKey(vk) {
					mbLogEvent("按键", mbKeyName(vk))
				} else {
					mbLogEvent("按键", mbKeyLabel(mods, vk))
					if s, ok := reg.match(mods, vk); ok {
						mbLogEvent("快捷键", s.name+" "+s.desc)
						s.action()
					}
				}
			}
			prev[vk] = down
		}
	}
}

// isLocalMbURL 判断地址是否指向本机主进程页面，这类页面保留网页自身标题
func isLocalMbURL(u string) bool {
	s := strings.ToLower(u)
	return strings.Contains(s, "localhost") || strings.Contains(s, "127.0.0.1")
}

// isAriaNgURL 判断加载地址是否为本机的 AriaNg 页面：localhost/127.0.0.1 且包含 AriaNg.html
func isAriaNgURL(u string) bool {
	return isLocalMbURL(u) && strings.Contains(strings.ToLower(u), "ariang.html")
}

// registerMbDownloads 注册下载回调：触发下载时弹出「另存为」对话框并由内核完成下载，
// 开始/进度/完成/保存路径输出到控制台。该回调在 Blink 线程执行，这里只调用下载相关 mb* API。
func registerMbDownloads(optional func(string, ...uintptr) uintptr, view uintptr) {
	recvCB := mbNewCallback(func(_ uintptr, job uintptr, _ unsafe.Pointer, length uintptr) uintptr {
		if v, ok := mbDownloads.Load(job); ok {
			info := v.(*mbDownloadInfo)
			if n := int64(int32(length)); n > 0 {
				total := atomic.AddInt64(&info.total, n)
				if total-atomic.LoadInt64(&info.lastLog) >= 1<<20 {
					atomic.StoreInt64(&info.lastLog, total)
					mbLogEvent("下载", fmt.Sprintf("进度 %s %s", info.url, mbSizeText(uintptr(total))))
				}
			}
		}
		return 0
	})
	finishCB := mbNewCallback(func(_ uintptr, job uintptr, result uintptr) uintptr {
		if v, ok := mbDownloads.Load(job); ok {
			info := v.(*mbDownloadInfo)
			state := "完成"
			switch result {
			case mbLoadingFailed:
				state = "失败"
			case mbLoadingCanceled:
				state = "取消"
			}
			mbLogEvent("下载", fmt.Sprintf("%s %s（共 %s）", state, info.url,
				mbSizeText(uintptr(atomic.LoadInt64(&info.total)))))
		}
		mbDownloads.Delete(job)
		mbDownloadBinds.Delete(job)
		return 0
	})
	saveNameCB := mbNewCallback(func(_ uintptr, path unsafe.Pointer) uintptr {
		mbLogEvent("下载", "保存位置 "+mbUTF16StringN(path, 4096))
		return 0
	})
	startCB := mbNewCallback(func(webView uintptr, _ unsafe.Pointer, expected uintptr,
		urlPtr, mimePtr, dispositionPtr unsafe.Pointer, job uintptr, dataBindPtr unsafe.Pointer) uintptr {
		url := mbUTF8String(urlPtr)
		mbDownloads.Store(job, &mbDownloadInfo{url: url, expected: expected})
		mbLogEvent("下载", fmt.Sprintf("开始 %s（大小 %s，类型 %s）", url, mbSizeText(expected), mbUTF8String(mimePtr)))

		dataBind := mbNetJobDataBind{recvCallback: recvCB, finishCallback: finishCB}
		bind := mbDownloadBind{recvCallback: recvCB, finishCallback: finishCB, saveNameCallback: saveNameCB}
		dialog := mbDialogOptions{
			magic:       mbDialogMagic,
			title:       mbUTF8Arg("保存文件"),
			buttonLabel: mbUTF8Arg("保存"),
		}
		if dir := mbDownloadDir(); dir != "" {
			dialog.defaultPath = mbUTF8Arg(dir)
		}
		mbDownloadBinds.Store(job, &mbDownloadBindsHold{dataBind: &dataBind, bind: &bind, dialog: &dialog})

		// 优先沿用内核传入的 dataBind（其中可能带有任务自身的回调）
		ptr := dataBindPtr
		if ptr == nil {
			ptr = unsafe.Pointer(&dataBind)
		}
		opt := optional("mbPopupDialogAndDownload", webView, uintptr(unsafe.Pointer(&dialog)),
			expected, uintptr(urlPtr), uintptr(mimePtr), uintptr(dispositionPtr), job,
			uintptr(ptr), uintptr(unsafe.Pointer(&bind)))
		if opt == mbDownloadOptCancel {
			mbDownloads.Delete(job)
			mbDownloadBinds.Delete(job)
			mbLogEvent("下载", "已取消 "+url)
		}
		return opt
	})
	optional("mbOnDownloadInBlinkThread", view, startCB, 0)
}

// registerMbEvents 注册浏览器事件回调；allowLinks=false 时拦截链接点击与表单提交。
// 窗口标题显示当前页面 URL，但本机页面（localhost / 127.0.0.1）保留网页标题。
func registerMbEvents(optional func(string, ...uintptr) uintptr, view uintptr, allowLinks bool, initialURL string) {
	var urlMu sync.Mutex
	currentURL := initialURL
	getURL := func() string {
		urlMu.Lock()
		defer urlMu.Unlock()
		return currentURL
	}
	setWindowTitle := func(u string) {
		if u == "" {
			return
		}
		if p := utf16Arg(u); p != 0 {
			optional("mbSetWindowTitleW", view, p)
		}
	}

	titleCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer, title unsafe.Pointer) uintptr {
		mbLogEvent("标题变化", mbUTF8String(title))
		// 本机页面保留网页标题；其他页面改回显示 URL
		if u := getURL(); !isLocalMbURL(u) {
			setWindowTitle(u)
		}
		return 0
	})
	optional("mbOnTitleChanged", view, titleCB, 0)

	urlCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer, u unsafe.Pointer, canBack, canForward uintptr) uintptr {
		addr := mbUTF8String(u)
		urlMu.Lock()
		currentURL = addr
		urlMu.Unlock()
		mbLogEvent("地址变化", fmt.Sprintf("%s [后退:%d 前进:%d]", addr, canBack, canForward))
		if isAriaNgURL(addr) {
			mbLogEvent("页面识别", "本机 AriaNg 页面已加载")
			go ensureAria2cFromURL(addr)
		}
		if !isLocalMbURL(addr) {
			setWindowTitle(addr)
		}
		return 0
	})
	optional("mbOnURLChanged", view, urlCB, 0)

	finishCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer, _ uintptr, u unsafe.Pointer, result uintptr, reason unsafe.Pointer) uintptr {
		detail := fmt.Sprintf("结果=%d %s", result, mbUTF8String(u))
		if reason != nil {
			detail += " 原因=" + mbUTF8String(reason)
		}
		mbLogEvent("加载完成", detail)
		return 0
	})
	optional("mbOnLoadingFinish", view, finishCB, 0)

	failCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer, u unsafe.Pointer, _ unsafe.Pointer) uintptr {
		mbLogEvent("加载失败", mbUTF8String(u))
		return 0
	})
	optional("mbOnLoadUrlFail", view, failCB, 0)

	consoleCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer, level uintptr, msg, source unsafe.Pointer, line uintptr, _ unsafe.Pointer) uintptr {
		mbLogEvent("页面控制台", fmt.Sprintf("级别=%d %s (行:%d)", level, mbUTF8String(msg), line))
		return 0
	})
	optional("mbOnConsole", view, consoleCB, 0)

	navCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer, navType uintptr, u unsafe.Pointer) uintptr {
		mbLogEvent("导航", mbNavTypeName(navType)+" "+mbUTF8String(u))
		if !allowLinks && (navType == mbNavLinkClick || navType == mbNavFormSubmit) {
			return 0
		}
		return 1 // 允许跳转
	})
	optional("mbOnNavigation", view, navCB, 0)

	// 关闭「链接点击弹新窗口」，让链接在当前窗口直接跳转
	optional("mbSetNavigationToNewWindowEnable", view, 0)

	// 文件下载：另存为对话框 + 进度日志
	registerMbDownloads(optional, view)
}

// setMbDllDirectory 让 mb132_x64.dll 的加载器能从同目录找到 mb132_x64.dll / mb132_x32.dll
func setMbDllDirectory(dllPath string) {
	if p := utf16Arg(filepath.Dir(dllPath)); p != 0 {
		procSetDllDirectoryW.Call(p)
	}
}

// mbDllUsable 判断 mb132_x64.dll 是否有效：能加载且必需导出齐全
func mbDllUsable(dllPath string) error {
	mb := syscall.NewLazyDLL(dllPath)
	if err := mb.Load(); err != nil {
		return fmt.Errorf("加载 %s 失败：%w（请确认 DLL 与 exe 位数一致、依赖齐全）", dllPath, err)
	}
	for _, name := range mbRequiredProcs {
		if err := mb.NewProc(name).Find(); err != nil {
			return fmt.Errorf("mb132_x64.dll 缺少导出 %s：%w", name, err)
		}
	}
	return nil
}

// setConsoleVisible 隐藏/恢复本进程的控制台窗口。
// 独占控制台时直接 SW_HIDE；若控制台被启动它的 cmd 等共用，则改为 FreeConsole
// 让本进程脱离控制台，避免把用户终端一起隐藏。
func setConsoleVisible(show bool) {
	if !show {
		hwnd, _, _ := procGetConsoleWindow.Call()
		if hwnd == 0 {
			return
		}
		shared := true
		if err := procGetConsoleProcessList.Find(); err == nil {
			var owners [2]uint32
			if n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&owners[0])), 2); n == 1 {
				shared = false
			}
		}
		if shared {
			if r, _, _ := procFreeConsole.Call(); r != 0 {
				mbConsoleDetached = true
			}
			return
		}
		procShowWindowW.Call(hwnd, swHide)
		return
	}
	// 窗口初始化失败时恢复控制台，便于看到错误信息
	if mbConsoleDetached {
		procAllocConsole.Call()
		mbConsoleDetached = false
		if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stdout, os.Stderr = f, f
		}
	}
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
		procShowWindowW.Call(hwnd, swShow)
	}
}

// prepareMbWindow 确保 exe 目录下 mb132_x64.dll 存在且哈希正确，再验证其可用性；
// 有效时返回 DLL 路径。文件缺失或哈希不符时，从内嵌 7z 资源解压覆盖。
// hideConsole 为 true 时立刻隐藏控制台（正常窗口模式）；守护/无窗口模式传 false。
// 无效时保留控制台、打印原因并返回空串（由调用方回退默认浏览器）。
func prepareMbWindow(hideConsole bool) string {
	p, err := ensureMbDll()
	if err != nil {
		fmt.Println("  mb132_x64.dll 准备失败：" + err.Error() + "，改用默认浏览器")
		return ""
	}
	setMbDllDirectory(p)
	if err := mbDllUsable(p); err != nil {
		fmt.Println("  mb132_x64.dll 不可用：" + err.Error() + "，改用默认浏览器")
		return ""
	}
	if hideConsole {
		setConsoleVisible(false)
	}
	return p
}

// runMbWindow 按 miniblink （mb.h 声明的纯 C 接口）的方式动态加载 mb132_x64.dll，
// 创建一个原生 Windows 窗口显示本服务页面。窗口关闭后返回 nil，
// 加载或初始化失败时返回 error，由调用方回退到系统默认浏览器。
// allowLinks 为 true 时允许点击页面链接在当前窗口跳转，false 时拦截链接点击。
// homeURL 为主进程 HTTP 服务地址，窗口内按 Ctrl+Home 可返回该页面；
// Alt+Left / Alt+Right 分别为后退 / 前进，F5 / Ctrl+R 为刷新。
// 快捷键由 mbShortcutRegistry 集中注册，可继续 add 扩展或用取消函数撤销。
// 窗口标题显示当前页面 URL，本机页面保留网页标题。
// 浏览器事件（标题、地址、加载结果、导航、页面控制台）与窗口按键会输出到主控制台。
func runMbWindow(dllPath, url, homeURL string, allowLinks bool) error {
	// miniblink 要求 mbInit 及之后所有 mb* 调用都在同一线程
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	setMbDllDirectory(dllPath)

	mb := syscall.NewLazyDLL(dllPath)
	if err := mb.Load(); err != nil {
		return fmt.Errorf("加载 %s 失败：%w（请确认 DLL 与 exe 位数一致、依赖齐全）", dllPath, err)
	}

	procs := make(map[string]*syscall.LazyProc)
	proc := func(name string) *syscall.LazyProc {
		if p := procs[name]; p != nil {
			return p
		}
		p := mb.NewProc(name)
		procs[name] = p
		return p
	}
	// 必需导出：缺一个就提前失败，避免 LazyProc.Call 运行期 panic
	for _, name := range mbRequiredProcs {
		if err := proc(name).Find(); err != nil {
			return fmt.Errorf("mb132_x64.dll 缺少导出 %s：%w", name, err)
		}
	}
	// 下载回调在 Blink 线程调用 mbPopupDialogAndDownload，提前解析避免并发写 procs map
	proc("mbPopupDialogAndDownload").Find()
	// 可选导出：不同 miniblink 版本并不一定都提供
	optional := func(name string, args ...uintptr) uintptr {
		p := proc(name)
		if err := p.Find(); err != nil {
			return 0
		}
		r, _, _ := p.Call(args...)
		return r
	}

	// miniblink132 SDK 通过 mbSetMbDllPath 指定 mb132_x64.dll 绝对路径；导出存在则按其方式设置
	if p := utf16Arg(dllPath); p != 0 {
		optional("mbSetMbDllPath", p)
	}

	proc("mbInit").Call(0) // settings = nullptr
	optional("mbEnableHighDPISupport")

	w, h := 1200, 800
	if v, _, _ := procGetSystemMetrics.Call(smCXScreen); v > 0 && int(v)*4/5 >= 960 {
		w = int(v) * 4 / 5
	}
	if v, _, _ := procGetSystemMetrics.Call(smCYScreen); v > 0 && int(v)*4/5 >= 640 {
		h = int(v) * 4 / 5
	}

	view, _, _ := proc("mbCreateWebWindow").Call(
		mbWindowTypePopup, 0, 0, 0, uintptr(w), uintptr(h))
	if view == 0 {
		return fmt.Errorf("mbCreateWebWindow 创建窗口失败")
	}
	optional("mbMoveToCenter", view)
	if p := utf16Arg(url); p != 0 {
		optional("mbSetWindowTitleW", view, p)
	}
	if homeURL == "" {
		homeURL = url
	}

	// 快捷键里的 mb* 调用必须在 UI 线程执行，统一通过投递回调完成
	postToUI := func(cb uintptr, name string) {
		if p := proc("mbPostToUiThread"); p.Find() == nil {
			p.Call(cb, 0)
			return
		}
		if p := proc("mbCallUiThreadAsync"); p.Find() == nil {
			p.Call(view, cb, 0, 0)
			return
		}
		mbLogEvent("快捷键", fmt.Sprintf("当前 mb132_x64.dll 不支持线程投递，%s 未生效", name))
	}
	goHomeCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer) uintptr {
		b := append([]byte(homeURL), 0)
		proc("mbLoadURL").Call(view, uintptr(unsafe.Pointer(&b[0])))
		runtime.KeepAlive(b)
		return 0
	})
	goBackCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer) uintptr {
		optional("mbGoBack", view)
		return 0
	})
	goForwardCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer) uintptr {
		optional("mbGoForward", view)
		return 0
	})
	goReloadCB := mbNewCallback(func(_ uintptr, _ unsafe.Pointer) uintptr {
		optional("mbReload", view)
		return 0
	})
	postGoHome := func() { postToUI(goHomeCB, "Ctrl+Home") }
	postGoBack := func() { postToUI(goBackCB, "Alt+Left") }
	postGoForward := func() { postToUI(goForwardCB, "Alt+Right") }
	postReload := func() { postToUI(goReloadCB, "F5/Ctrl+R") }

	// 快捷键集中注册：add 返回取消函数，可撤销单条；stop 停止全部监听
	shortcuts := newMbShortcutRegistry()
	shortcuts.add(mbModCtrl, vkHome, postGoHome, "返回主进程端口页面")
	shortcuts.add(mbModAlt, vkLeft, postGoBack, "后退")
	shortcuts.add(mbModAlt, vkRight, postGoForward, "前进")
	shortcuts.add(0, vkF5, postReload, "刷新当前页面")
	shortcuts.add(mbModCtrl, vkR, postReload, "刷新当前页面")

	// 注册事件回调与链接跳转参数（必须在加载 URL 之前）
	registerMbEvents(optional, view, allowLinks, url)
	if proc("mbOnDownloadInBlinkThread").Find() != nil {
		mbLogEvent("下载", "当前 mb132_x64.dll 不支持另存为下载回调，文件下载功能不可用")
	}
	mbLogEvent("窗口创建", fmt.Sprintf("句柄=%d 初始地址=%s 允许链接跳转=%v", view, url, allowLinks))

	urlBytes := append([]byte(url), 0)
	proc("mbLoadURL").Call(view, uintptr(unsafe.Pointer(&urlBytes[0])))
	runtime.KeepAlive(urlBytes)
	proc("mbShowWindow").Call(view, 1)

	// 窗口被关闭时向 UI 线程投递 WM_QUIT，让 mbRunMessageLoop 返回，
	// 主程序随窗口一起退出，避免服务残留在后台。
	if hwnd := optional("mbGetHostHWND", view); hwnd != 0 {
		mbLogEvent("按键监听", fmt.Sprintf("窗口句柄=%d，按键信息将输出到控制台（快捷键可增删/取消）", hwnd))
		go monitorMbKeys(hwnd, shortcuts)
		threadID, _, _ := procGetCurrentThreadId.Call()
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for range t.C {
				if alive, _, _ := procIsWindow.Call(hwnd); alive == 0 {
					shortcuts.stop()
					procPostThreadMessageW.Call(uintptr(uint32(threadID)), wmQuit, 0, 0)
					// 个别版本的 mbRunMessageLoop 不理会 WM_QUIT，兜底确保进程退出
					time.AfterFunc(1*time.Second, func() { exitMain(0) })
					return
				}
			}
		}()
	}

	proc("mbRunMessageLoop").Call()
	return nil
}
