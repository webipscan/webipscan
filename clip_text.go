package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// clipTextTTL 本地文本同步内容的保留时间；仅保存在内存中，不落盘。
const clipTextTTL = 2 * time.Hour

var clipTextMaxBytes = clipMaxSDP

type clipTextEntry struct {
	Text      string    `json:"text"`
	TS        int64     `json:"ts"`
	UpdatedAt time.Time `json:"-"`
}

var clipTextStore = struct {
	sync.Mutex
	items map[string]*clipTextEntry
}{items: make(map[string]*clipTextEntry)}

func init() { go clipTextCleanupLoop() }

func clipTextCleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		clipTextStore.Lock()
		for id, item := range clipTextStore.items {
			if time.Since(item.UpdatedAt) > clipTextTTL {
				delete(clipTextStore.items, id)
			}
		}
		clipTextStore.Unlock()
	}
}

// isClipLoopbackRequest 仅允许本机页面使用文本同步，避免局域网客户端误用服务端存储。
func isClipLoopbackRequest(r *http.Request) bool {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// handleClipText 为本机、无 WebRTC 的浏览器提供按房间号的文本读写，以时间戳后写胜。
func handleClipText(w http.ResponseWriter, r *http.Request) {
	if !isClipLoopbackRequest(r) {
		clipError(w, http.StatusForbidden, "文本同步仅限本机地址使用", nil)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if !clipIDRE.MatchString(id) {
		clipError(w, http.StatusBadRequest, "房间号无效", nil)
		return
	}

	switch r.Method {
	case http.MethodGet:
		clipTextStore.Lock()
		item := clipTextStore.items[id]
		var out clipTextEntry
		if item != nil {
			out = *item
		}
		clipTextStore.Unlock()
		clipJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var in clipTextEntry
		dec := json.NewDecoder(io.LimitReader(r.Body, int64(clipTextMaxBytes)+4096))
		if err := dec.Decode(&in); err != nil {
			clipError(w, http.StatusBadRequest, "请求内容无效", nil)
			return
		}
		if len([]byte(in.Text)) > clipTextMaxBytes {
			clipError(w, http.StatusRequestEntityTooLarge, "文本内容过长", nil)
			return
		}
		if in.TS <= 0 {
			in.TS = time.Now().UnixMilli()
		}
		clipTextStore.Lock()
		cur := clipTextStore.items[id]
		if cur == nil || in.TS >= cur.TS {
			in.UpdatedAt = time.Now()
			cur = &in
			clipTextStore.items[id] = cur
		}
		out := *cur
		clipTextStore.Unlock()
		clipJSON(w, http.StatusOK, out)

	case http.MethodDelete:
		clipTextStore.Lock()
		delete(clipTextStore.items, id)
		clipTextStore.Unlock()
		clipJSON(w, http.StatusOK, map[string]interface{}{"ok": true})

	default:
		clipError(w, http.StatusMethodNotAllowed, "不支持的请求方法", nil)
	}
}
