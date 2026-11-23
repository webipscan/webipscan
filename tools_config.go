package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// windowSize 表示窗口初始尺寸；宽或高 <= 0 表示沿用主页的默认大窗口尺寸。
type windowSize struct {
	width  int
	height int
}

// defaultToolWindowSize 是除主页外新开窗口的默认尺寸。
var defaultToolWindowSize = windowSize{width: 1024, height: 576}

// toolOpenMode 是 tools.txt 中工具的打开方式。
type toolOpenMode string

const (
	toolModeInternal toolOpenMode = "internal" // 程序内嵌 miniblink 窗口
	toolModeSystem   toolOpenMode = "system"   // 系统默认浏览器
	toolModeChrome   toolOpenMode = "chrome"   // 外部 Chrome
)

// toolEntry 一条工具配置：名称、窗口尺寸、地址与打开方式。
type toolEntry struct {
	Name string
	URL  string
	Size windowSize
	Mode toolOpenMode
}

// builtinTools 是 tools.txt 不存在时使用的内置工具列表。
var builtinTools = []toolEntry{
	{Name: "必应翻译", URL: "https://cn.bing.com/translator?setmkt=zh-cn&setlang=zh-cn", Size: defaultToolWindowSize, Mode: toolModeInternal},
	{Name: "百度汉语", URL: "https://dict.baidu.com/", Size: defaultToolWindowSize, Mode: toolModeInternal},
	{Name: "百度地图", URL: "https://map.baidu.com/", Size: defaultToolWindowSize, Mode: toolModeInternal},
	{Name: "漢典古籍", URL: "https://gj.zdic.net/", Size: defaultToolWindowSize, Mode: toolModeInternal},
}

// loadTools 优先读取 exe 所在目录或当前目录的 tools.txt。
// 文件不存在时返回内置工具列表；文件存在时先保留文件中的配置，
// 再补充未重复的内置工具（按名称和地址去重）。
func loadTools() []toolEntry {
	for _, path := range toolConfigPaths() {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		fileTools := parseTools(f)
		_ = f.Close()
		return mergeTools(fileTools, builtinTools)
	}
	return append([]toolEntry(nil), builtinTools...)
}

func toolConfigPaths() []string {
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "tools.txt"))
	}
	return append(paths, "tools.txt")
}

// parseTools 解析每行「名称,尺寸,地址[,打开方式]」。
// 打开方式可省略，默认 internal；兼容旧的三列格式。
func parseTools(f *os.File) []toolEntry {
	var tools []toolEntry
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) != 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		size, ok := parseWindowSize(strings.TrimSpace(parts[1]))
		if !ok {
			fmt.Printf("  tools.txt 第 %d 行尺寸无效，使用默认 %dx%d\n",
				lineNo, defaultToolWindowSize.width, defaultToolWindowSize.height)
		}
		rest := strings.TrimSpace(parts[2])
		mode := toolModeInternal
		if i := strings.LastIndex(rest, ","); i >= 0 {
			rawMode := strings.TrimSpace(rest[i+1:])
			candidateURL := strings.TrimSpace(rest[:i])
			if m, ok := parseToolMode(rawMode); ok {
				mode = m
				rest = candidateURL
			} else if rawMode != "" && !strings.ContainsAny(rawMode, "/:") && isHTTPURL(candidateURL) {
				fmt.Printf("  tools.txt 第 %d 行打开方式无效：%s，使用默认内部\n", lineNo, rawMode)
				rest = candidateURL
			}
		}
		rawURL := strings.TrimSpace(rest)
		if name == "" || !isHTTPURL(rawURL) {
			continue
		}
		tools = append(tools, toolEntry{Name: name, URL: rawURL, Size: size, Mode: mode})
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("读取 tools.txt 失败：" + err.Error())
	}
	return tools
}

// parseWindowSize 解析 800x600 / 1024X768 / 640*480 等写法。
// 空白或无效值都回退到默认尺寸，ok 为 false 表示配置值无效。
func parseWindowSize(raw string) (windowSize, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultToolWindowSize, true
	}
	sep := strings.IndexAny(raw, "xX×*")
	if sep <= 0 || sep == len(raw)-1 {
		return defaultToolWindowSize, false
	}
	w, err := strconv.Atoi(strings.TrimSpace(raw[:sep]))
	if err != nil {
		return defaultToolWindowSize, false
	}
	h, err := strconv.Atoi(strings.TrimSpace(raw[sep+1:]))
	if err != nil {
		return defaultToolWindowSize, false
	}
	if w < 200 || h < 200 || w > 7680 || h > 4320 {
		return defaultToolWindowSize, false
	}
	return windowSize{width: w, height: h}, true
}

// parseToolMode 同时接受中文与英文写法，例如 内部/internal、系统/system、外部chrome/chrome。
func parseToolMode(raw string) (toolOpenMode, bool) {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), " ", ""))
	switch s {
	case "内部", "内嵌", "internal", "mb", "miniblink":
		return toolModeInternal, true
	case "系统", "默认", "system", "default", "browser":
		return toolModeSystem, true
	case "外部chrome", "chrome", "externalchrome", "chrome.exe":
		return toolModeChrome, true
	}
	return toolModeInternal, false
}

// mergeTools 按名称和规范化地址去重；primary 中的项优先，extra 仅补充缺少的项。
func mergeTools(primary, extra []toolEntry) []toolEntry {
	result := make([]toolEntry, 0, len(primary)+len(extra))
	seenName := make(map[string]bool)
	seenURL := make(map[string]bool)

	add := func(t toolEntry) {
		nameKey := strings.ToLower(t.Name)
		urlKey := normalizeToolURL(t.URL)
		if nameKey == "" || urlKey == "" || seenName[nameKey] || seenURL[urlKey] {
			return
		}
		if t.Size.width <= 0 || t.Size.height <= 0 {
			t.Size = defaultToolWindowSize
		}
		if t.Mode == "" {
			t.Mode = toolModeInternal
		}
		seenName[nameKey] = true
		seenURL[urlKey] = true
		result = append(result, t)
	}

	for _, t := range primary {
		add(t)
	}
	for _, t := range extra {
		add(t)
	}
	return result
}

func normalizeToolURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	key := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path
	if u.RawQuery != "" {
		key += "?" + u.RawQuery
	}
	return key
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}
