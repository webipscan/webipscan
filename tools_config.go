package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// toolEntry 一条工具配置：名称、初始尺寸（当前忽略）与地址。
type toolEntry struct {
	Name string
	URL  string
}

// builtinTools 是 tools.txt 不存在时使用的内置工具列表。
var builtinTools = []toolEntry{
	{Name: "必应翻译", URL: "https://cn.bing.com/translator?setmkt=zh-cn&setlang=zh-cn"},
	{Name: "百度汉语", URL: "https://dict.baidu.com/"},
	{Name: "百度地图", URL: "https://map.baidu.com/"},
	{Name: "漢典古籍", URL: "https://gj.zdic.net/"},
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

func parseTools(f *os.File) []toolEntry {
	var tools []toolEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) != 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		rawURL := strings.TrimSpace(parts[2])
		if name == "" || !isHTTPURL(rawURL) {
			continue
		}
		tools = append(tools, toolEntry{Name: name, URL: rawURL})
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("读取 tools.txt 失败：" + err.Error())
	}
	return tools
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
