package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- geoip.dat 远端版本检查与更新 ----------

var geoUpdateMu sync.Mutex

var geoHeadClient = &http.Client{Timeout: 20 * time.Second}
var geoDownloadClient = &http.Client{Timeout: 5 * time.Minute}

// remoteGeoIPSize 通过 HEAD（失败时用 Range GET）获取远端 geoip.dat 大小。
// 依次尝试 ghfast.top、gh-proxy.com、GitHub 官方地址。
func remoteGeoIPSize(ctx context.Context) (int64, string, error) {
	for _, mirror := range geoIPMirrors {
		if n, err := geoURLSize(ctx, mirror, false); err == nil && n > 0 {
			return n, mirror, nil
		}
		if n, err := geoURLSize(ctx, mirror, true); err == nil && n > 0 {
			return n, mirror, nil
		}
	}
	return 0, "", fmt.Errorf("无法从镜像或 GitHub 获取远端文件大小")
}

func geoURLSize(ctx context.Context, rawURL string, useRange bool) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", browserUA)
	if useRange {
		req.Method = http.MethodGet
		req.Header.Set("Range", "bytes=0-0")
	}
	resp, err := geoHeadClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if i := strings.LastIndex(cr, "/"); i >= 0 {
			if n, e := strconv.ParseInt(strings.TrimSpace(cr[i+1:]), 10, 64); e == nil && n > 0 {
				return n, nil
			}
		}
	}
	if resp.ContentLength > 0 {
		return resp.ContentLength, nil
	}
	return 0, fmt.Errorf("响应未返回文件大小")
}

// progressWriter 下载进度统计：按字节数节流回调
type progressWriter struct {
	w        io.Writer
	written  int64
	total    int64
	nextEmit int64
	emit     func(int64, int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.written += int64(n)
	if p.written >= p.nextEmit {
		p.emit(p.written, p.total)
		p.nextEmit = p.written + 512*1024
	}
	return n, err
}

// downloadGeoIPFile 下载到临时文件后原子替换，失败时保留原文件
func downloadGeoIPFile(ctx context.Context, rawURL string, size int64, emit func(int64, int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", browserUA)
	resp, err := geoDownloadClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		size = resp.ContentLength
	}

	tmp := geoIPFilePath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("创建临时文件失败：%w", err)
	}
	pw := &progressWriter{w: f, total: size, nextEmit: 512 * 1024, emit: emit}
	_, copyErr := io.Copy(pw, resp.Body)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmp)
		if copyErr != nil {
			return fmt.Errorf("下载失败：%w", copyErr)
		}
		return fmt.Errorf("写入文件失败：%w", closeErr)
	}
	if size > 0 && pw.written != size {
		os.Remove(tmp)
		return fmt.Errorf("文件大小不符：期望 %d 字节，实际 %d 字节", size, pw.written)
	}
	emit(pw.written, size)

	// Windows 不允许直接覆盖已存在的文件：先备份旧文件，失败时回滚
	backup := geoIPFilePath + ".bak"
	if _, err := os.Stat(geoIPFilePath); err == nil {
		os.Remove(backup)
		if err := os.Rename(geoIPFilePath, backup); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("备份旧文件失败：%w", err)
		}
	}
	if err := os.Rename(tmp, geoIPFilePath); err != nil {
		if _, e := os.Stat(backup); e == nil {
			os.Rename(backup, geoIPFilePath)
		}
		os.Remove(tmp)
		return fmt.Errorf("替换文件失败：%w", err)
	}
	os.Remove(backup)
	invalidateGeoIPCache()
	return nil
}

// handleGeoIPStatus 返回本地文件与远端版本对比
func handleGeoIPStatus(w http.ResponseWriter, r *http.Request) {
	s := geoIPReadStatus()
	size, mirror, err := remoteGeoIPSize(r.Context())
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		s.Note = "远端版本检查失败：" + err.Error()
	} else {
		s.RemoteSize = size
		s.Mirror = mirror
		s.Latest = s.Exists && s.Size == size
		switch {
		case !s.Exists:
			s.Note = "本地不存在 geoip.dat，点击下方按钮下载。"
		case s.Latest:
			s.Note = "本地文件大小与远端一致，已是最新版本。"
		default:
			s.Note = fmt.Sprintf("本地 %d 字节，远端 %d 字节，文件不是最新。", s.Size, size)
		}
	}
	json.NewEncoder(w).Encode(s)
}

// handleGeoIPUpdate SSE 检查并更新 geoip.dat
func handleGeoIPUpdate(w http.ResponseWriter, r *http.Request) {
	if !geoUpdateMu.TryLock() {
		http.Error(w, "已有更新任务正在运行", http.StatusConflict)
		return
	}
	defer geoUpdateMu.Unlock()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "当前连接不支持流式响应", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	emit := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(b))
		flusher.Flush()
	}

	st := geoIPReadStatus()
	emit("status", st)

	size, mirror, err := remoteGeoIPSize(r.Context())
	if err != nil {
		emit("error", map[string]string{"message": "远端版本检查失败：" + err.Error()})
		return
	}
	if st.Exists && st.Size == size {
		emit("done", map[string]interface{}{
			"updated": false, "latest": true, "size": size,
			"message": "文件大小与远端一致，已是最新版本。",
		})
		return
	}

	emit("status", map[string]interface{}{
		"mirror": mirror, "remoteSize": size, "message": "正在下载 geoip.dat…",
	})
	err = downloadGeoIPFile(r.Context(), mirror, size, func(done, total int64) {
		emit("progress", map[string]interface{}{"done": done, "total": total})
	})
	if err != nil {
		emit("error", map[string]string{"message": err.Error()})
		return
	}
	newStatus := geoIPReadStatus()
	emit("done", map[string]interface{}{
		"updated": true, "latest": true, "size": newStatus.Size,
		"mirror": mirror, "message": "geoip.dat 已更新完成。",
	})
}
