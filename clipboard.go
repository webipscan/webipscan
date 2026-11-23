package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	clipMaxSDP  = 512 << 10        // SDP 描述上限
	clipLinkTTL = 30 * time.Minute // 信令信息最长保留时间
)

var clipIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

// clipLink 只保存建立直连所需的 SDP 描述，不保存任何文本内容或文件。
// 两端完成 WebRTC 握手后会主动删除该记录，服务端随即彻底遗忘这条链接。
type clipLink struct {
	ID        string
	Offer     string
	Answer    string
	CreatedAt time.Time
}

type clipStore struct {
	mu    sync.Mutex
	links map[string]*clipLink
}

var clipStoreGlobal = newClipStore()

func newClipStore() *clipStore {
	s := &clipStore{links: make(map[string]*clipLink)}
	go s.cleanupLoop()
	return s
}

// clipShutdown 无需清理：服务端不落盘，也不保存任何用户数据。
func clipShutdown() {}

func clipRandom(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))
	}
	return hex.EncodeToString(b)
}

func (s *clipStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for id, link := range s.links {
			if time.Since(link.CreatedAt) > clipLinkTTL {
				delete(s.links, id)
			}
		}
		s.mu.Unlock()
	}
}

func clipJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clipError(w http.ResponseWriter, code int, msg string, extra map[string]interface{}) {
	v := map[string]interface{}{"error": msg}
	for k, val := range extra {
		v[k] = val
	}
	clipJSON(w, code, v)
}

func decodeClipBody(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, clipMaxSDP+4096))
	return dec.Decode(v)
}

// handleClipAPI 提供信令交换、二维码生成，以及本机无 WebRTC 时的文本同步。
func handleClipAPI(w http.ResponseWriter, r *http.Request) {
	s := clipStoreGlobal
	switch strings.TrimPrefix(r.URL.Path, "/api/clip/") {
	case "text":
		handleClipText(w, r)
	case "config":
		clipJSON(w, http.StatusOK, map[string]interface{}{
			"mode": "webrtc", "signalingOnly": true, "linkTTL": int(clipLinkTTL / time.Minute),
		})
	case "qr":
		handleClipQR(w, r)
	case "link":
		s.handleLink(w, r)
	case "link/answer":
		s.handleAnswer(w, r)
	case "link/delete":
		s.handleDelete(w, r)
	default:
		clipError(w, http.StatusNotFound, "接口不存在", nil)
	}
}

func handleClipQR(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" || len(text) > 512 {
		clipError(w, http.StatusBadRequest, "二维码内容为空或过长", nil)
		return
	}
	svg, err := qrSVG(text)
	if err != nil {
		clipError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.WriteString(w, svg)
}

func (s *clipStore) handleLink(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		id = r.Header.Get("X-Clip-Link")
	}
	if r.Method == http.MethodPost {
		// POST 的 id 允许只出现在 body 中，下面解析后统一校验
	} else if !clipIDRE.MatchString(id) {
		clipError(w, http.StatusBadRequest, "链接标识需为 3-32 位字母、数字、下划线或连字符", nil)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		link := s.links[id]
		var offer, answer string
		if link != nil {
			offer, answer = link.Offer, link.Answer
		}
		s.mu.Unlock()
		if link == nil || offer == "" {
			clipError(w, http.StatusNotFound, "尚未收到邀请信息", map[string]interface{}{"needOffer": true})
			return
		}
		clipJSON(w, http.StatusOK, map[string]interface{}{"offer": offer, "answer": answer, "hasAnswer": answer != ""})

	case http.MethodPost:
		var req struct {
			ID    string `json:"id"`
			Offer string `json:"offer"`
		}
		if err := decodeClipBody(r, &req); err != nil {
			clipError(w, http.StatusBadRequest, "请求格式错误", nil)
			return
		}
		linkID := id
		if linkID == "" || linkID == "undefined" {
			linkID = req.ID
		}
		if !clipIDRE.MatchString(linkID) {
			clipError(w, http.StatusBadRequest, "链接标识需为 3-32 位字母、数字、下划线或连字符", nil)
			return
		}
		if req.Offer == "" || len(req.Offer) > clipMaxSDP {
			clipError(w, http.StatusBadRequest, "邀请信息为空或过长", nil)
			return
		}
		s.mu.Lock()
		link := s.links[linkID]
		if link == nil {
			link = &clipLink{ID: linkID, CreatedAt: time.Now()}
			s.links[linkID] = link
		}
		link.Offer = req.Offer
		link.Answer = ""
		link.CreatedAt = time.Now()
		s.mu.Unlock()
		clipJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "id": linkID})

	case http.MethodDelete:
		s.mu.Lock()
		delete(s.links, id)
		s.mu.Unlock()
		clipJSON(w, http.StatusOK, map[string]interface{}{"ok": true})

	default:
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
	}
}

func (s *clipStore) handleAnswer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Answer string `json:"answer"`
	}
	if err := decodeClipBody(r, &req); err != nil {
		clipError(w, http.StatusBadRequest, "请求格式错误", nil)
		return
	}
	if !clipIDRE.MatchString(req.ID) || req.Answer == "" || len(req.Answer) > clipMaxSDP {
		clipError(w, http.StatusBadRequest, "应答信息为空或格式错误", nil)
		return
	}
	s.mu.Lock()
	link := s.links[req.ID]
	if link == nil {
		s.mu.Unlock()
		clipError(w, http.StatusNotFound, "邀请已过期，请重新生成", nil)
		return
	}
	link.Answer = req.Answer
	link.CreatedAt = time.Now()
	s.mu.Unlock()
	clipJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *clipStore) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	delete(s.links, id)
	s.mu.Unlock()
	clipJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
