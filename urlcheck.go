package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// urlCheckClient 用于跳转前检测目标网址；内网设备常用自签名证书，因此跳过证书校验。
var urlCheckClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

var (
	urlSchemeWithSlashesRE = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)
	urlUnsafeSchemeRE      = regexp.MustCompile(`(?i)^(?:javascript|data|file|mailto|tel|ftp|about|blob):`)
)

type urlCheckResult struct {
	OK        bool   `json:"ok"`
	URL       string `json:"url,omitempty"`
	FinalURL  string `json:"finalURL,omitempty"`
	Status    int    `json:"status,omitempty"`
	Method    string `json:"method,omitempty"`
	ElapsedMS int64  `json:"elapsedMs,omitempty"`
	Error     string `json:"error,omitempty"`
}

// handleURLCheck 返回目标 http(s) 地址是否可正常访问，供前端决定是否跳转。
func handleURLCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(checkWebsiteURL(ctx, r.URL.Query().Get("url")))
}

// normalizeCheckURL 校验输入并补全协议，仅允许 http/https。
func normalizeCheckURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("请输入网址")
	}
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		if urlSchemeWithSlashesRE.MatchString(s) || urlUnsafeSchemeRE.MatchString(s) {
			return "", fmt.Errorf("仅支持 http/https 地址")
		}
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("网址格式无效：%v", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("网址格式无效，仅支持 http/https 地址")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("端口号无效：%s", p)
		}
	}
	return u.String(), nil
}

// checkWebsiteURL 先尝试 HEAD，服务器不支持时退回带 Range 的 GET，避免下载整个页面。
func checkWebsiteURL(ctx context.Context, raw string) (result urlCheckResult) {
	start := time.Now()
	defer func() { result.ElapsedMS = time.Since(start).Milliseconds() }()

	target, err := normalizeCheckURL(raw)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.URL = target

	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, target, nil)
		if err != nil {
			result.Error = "网址请求构造失败：" + err.Error()
			return
		}
		req.Header.Set("User-Agent", browserUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
		if method == http.MethodGet {
			req.Header.Set("Range", "bytes=0-0")
		}

		resp, err := urlCheckClient.Do(req)
		if err != nil {
			if method == http.MethodHead && ctx.Err() == nil {
				continue
			}
			result.Error = "无法访问该网址：" + err.Error()
			return
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()

		result.Status = resp.StatusCode
		result.Method = method
		if resp.Request != nil && resp.Request.URL != nil {
			result.FinalURL = resp.Request.URL.String()
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			result.OK = true
			return
		}
		if method == http.MethodHead && (resp.StatusCode == http.StatusMethodNotAllowed ||
			resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusForbidden) {
			continue
		}
		result.Error = fmt.Sprintf("目标返回 HTTP %d（%s）", resp.StatusCode, http.StatusText(resp.StatusCode))
		return
	}

	if result.Error == "" {
		result.Error = "无法访问该网址"
	}
	return
}
