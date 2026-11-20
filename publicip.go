package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------- 公网连接状态与出口 IP ----------

// PublicIPResult 公网连接状态
type PublicIPResult struct {
	Connected bool       `json:"connected"`
	IP        string     `json:"ip"`
	Info      *GeoIPInfo `json:"info,omitempty"`
	Note      string     `json:"note"`
	CheckedAt string     `json:"checkedAt"`
	Via       string     `json:"via"`
}

var (
	publicCacheMu sync.Mutex
	publicCache   *PublicIPResult
	publicCacheAt time.Time
)

// publicIPProvider 一个免费公网 IP 查询接口
type publicIPProvider struct {
	name string
	url  string
	key  string // 从 JSON 中取 IP 的字段名
}

// publicIPProviders 免费公网 IP 查询接口（无需 key）
var publicIPProviders = []publicIPProvider{
	{"ipinfo.io", "https://ipinfo.io/json", "ip"},
	{"ip-api.com", "http://ip-api.com/json/?fields=query", "query"},
	{"ipify", "https://api.ipify.org?format=json", "ip"},
	{"ipwho.is", "https://ipwho.is/", "ip"},
}

// fetchPublicIP 并发请求所有接口，采用最先返回有效结果的那台服务器；
// 拿到结果后立即取消其余请求，避免慢接口拖慢整个查询。
func fetchPublicIP(ctx context.Context) (string, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		ip, via string
		err     error
	}
	ch := make(chan result, len(publicIPProviders))
	for _, p := range publicIPProviders {
		go func(p publicIPProvider) {
			body, err := httpGet(ctx, p.url, nil)
			if err != nil {
				ch <- result{err: fmt.Errorf("%s：%w", p.name, err)}
				return
			}
			var obj map[string]interface{}
			if json.Unmarshal([]byte(body), &obj) != nil {
				ch <- result{err: fmt.Errorf("%s：返回非 JSON", p.name)}
				return
			}
			ipStr, _ := obj[p.key].(string)
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip == nil {
				ch <- result{err: fmt.Errorf("%s：未返回有效 IP", p.name)}
				return
			}
			if ip.To4() == nil {
				ch <- result{err: fmt.Errorf("%s：仅返回 IPv6", p.name)}
				return
			}
			ch <- result{ip: ip.String(), via: p.name}
		}(p)
	}

	var failures []string
	for i := 0; i < len(publicIPProviders); i++ {
		r := <-ch
		if r.ip != "" {
			return r.ip, r.via, nil
		}
		failures = append(failures, r.err.Error())
	}
	return "", "", fmt.Errorf("无法获取公网 IP（%s）", strings.Join(failures, "；"))
}

// QueryPublicIP 判断是否有公网连接，并附带出口 IP 的属地详情。
// 成功结果缓存 5 分钟，force=true 时强制刷新。
func QueryPublicIP(ctx context.Context, force bool) (*PublicIPResult, error) {
	publicCacheMu.Lock()
	if !force && publicCache != nil && time.Since(publicCacheAt) < 5*time.Minute {
		res := *publicCache
		publicCacheMu.Unlock()
		return &res, nil
	}
	publicCacheMu.Unlock()

	ip, via, err := fetchPublicIP(ctx)
	if err != nil {
		return &PublicIPResult{
			Connected: false,
			Note:      "未检测到公网连接：" + err.Error() + "。可能当前网络无公网出口，或相关查询服务被拦截。",
			CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
		}, nil
	}

	res := &PublicIPResult{
		Connected: true,
		IP:        ip,
		Via:       via,
		Note:      "公网出口 IP 来自 " + via + "，属地信息来自 geoip.dat 与在线查询。",
		CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	if info, e := QueryGeoIP(ctx, ip); e == nil {
		res.Info = info
	}

	publicCacheMu.Lock()
	publicCache = res
	publicCacheAt = time.Now()
	publicCacheMu.Unlock()
	return res, nil
}

func handlePublicIP(w http.ResponseWriter, r *http.Request) {
	res, err := QueryPublicIP(r.Context(), r.URL.Query().Get("force") == "1")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(res)
}
