package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- IP 反查域名 ----------

// DNSName 一条反查结果
type DNSName struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	Confirmed bool   `json:"confirmed"` // 正向解析是否回到该 IP（仅 PTR 结果有意义）
}

// ReverseSource 反查接口定义
type ReverseSource struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // ptr / same
	Description string `json:"description"`
	Default     bool   `json:"default"`
	External    bool   `json:"external,omitempty"`
	URL         string `json:"url,omitempty"`
}

// ReverseSourceStatus 单次查询中各接口的执行情况
type ReverseSourceStatus struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"`
	Note  string `json:"note,omitempty"`
}

// ReverseDNSResult IP 反查域名结果
type ReverseDNSResult struct {
	IP      string                `json:"ip"`
	PTR     []DNSName             `json:"ptr"`    // PTR（反向 DNS）结果
	SameIP  []DNSName             `json:"sameIp"` // 第三方「同 IP 站点」结果
	Sources []ReverseSourceStatus `json:"sources"`
	Note    string                `json:"note"`
	Elapsed int64                 `json:"elapsed"`
}

// reverseSources 可选反查接口；external 项不在服务端调用，仅提供页面跳转链接
var reverseSources = []ReverseSource{
	{ID: "ptr", Name: "系统 DNS PTR", Kind: "ptr", Description: "操作系统解析器查询 PTR 记录", Default: true},
	{ID: "doh", Name: "公共 DoH PTR", Kind: "ptr", Description: "阿里 DoH、Cloudflare DoH 查询 PTR 记录", Default: true},
	{ID: "hackertarget", Name: "HackerTarget", Kind: "ptr", Description: "api.hackertarget.com 反向 DNS 接口", Default: true},
	{ID: "nztool", Name: "NZTool", Kind: "ptr", Description: "nztool.com/tools/ip-reverse.html 的 PTR 查询接口", Default: true},
	{ID: "webscan", Name: "Webscan.cc", Kind: "same", Description: "同 IP 站点历史记录", Default: true},
	{ID: "yougetsignal", Name: "YouGetSignal", Kind: "same", Description: "同 IP 站点列表接口", Default: true},
	{ID: "tcping", Name: "TCPING.CN 被动 DNS", Kind: "ptr", Description: "历史绑定域名（需页面令牌与 PoW，仅提供跳转）", External: true, URL: "https://www.tcping.cn/ip-domains/{ip}"},
}

func reverseSourceByID(id string) (ReverseSource, bool) {
	for _, s := range reverseSources {
		if s.ID == id {
			return s, true
		}
	}
	return ReverseSource{}, false
}

// apiClient 访问第三方接口共用客户端：带浏览器 UA，避免被接口拒绝
var apiClient = &http.Client{Timeout: 9 * time.Second}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// httpGet 发起带 UA 的 GET 请求并返回响应体（限制 512KB）
func httpGet(ctx context.Context, rawURL string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", browserUA)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return string(b), fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(b), nil
}

// reverseAddrOf 生成 IPv4 的 in-addr.arpa 名称
func reverseAddrOf(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
}

// systemPTR 系统解析器查询 PTR（返回全部名称）
func systemPTR(ip string, timeout time.Duration) []string {
	ch := make(chan []string, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil {
			ch <- nil
			return
		}
		ch <- names
	}()
	select {
	case n := <-ch:
		return n
	case <-time.After(timeout):
		return nil
	}
}

// dohPTR 通过 DNS over HTTPS（阿里 / Cloudflare）查询 PTR 记录
func dohPTR(ctx context.Context, endpoint, ip string) []string {
	rev := reverseAddrOf(net.ParseIP(ip))
	if rev == "" {
		return nil
	}
	headers := map[string]string{"Accept": "application/dns-json"}
	body, err := httpGet(ctx, endpoint+"?name="+url.QueryEscape(rev)+"&type=PTR", headers)
	if err != nil {
		return nil
	}
	var resp struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.Unmarshal([]byte(body), &resp) != nil {
		return nil
	}
	var out []string
	for _, a := range resp.Answer {
		if a.Type != 12 { // 12 = PTR
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(a.Data), ".")
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// hackertargetPTR 第三方 reverse DNS 接口（纯文本：IP或域名）
func hackertargetPTR(ctx context.Context, ip string) []string {
	body, err := httpGet(ctx, "https://api.hackertarget.com/reversedns/?q="+url.QueryEscape(ip), nil)
	if err != nil {
		return nil
	}
	low := strings.ToLower(body)
	if strings.Contains(low, "error") || strings.Contains(low, "no dns") || strings.Contains(low, "api count") {
		return nil
	}
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 输出形如 "1.2.3.4: host.example.com"、"1.2.3.4 host.example.com" 或仅域名
		if i := strings.LastIndex(line, ":"); i >= 0 && net.ParseIP(strings.TrimSpace(line[:i])) != nil {
			line = strings.TrimSpace(line[i+1:])
		} else if strings.HasPrefix(line, ip+" ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, ip+" "))
		}
		line = strings.TrimSuffix(line, ".")
		if line == "" || line == ip {
			continue
		}
		out = append(out, line)
	}
	return out
}

// nztoolPTR 调用 nztool.com/tools/ip-reverse.html 页面使用的 PTR 查询接口
// 分析来源：页面 JS 中 CMS.api.post('/tools/ipReversePost.html', {ip})
func nztoolPTR(ctx context.Context, ip string) []string {
	form := url.Values{"ip": {ip}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://nztool.com/tools/ipReversePost.html", strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Origin", "https://nztool.com")
	req.Header.Set("Referer", "https://nztool.com/tools/ip-reverse.html")
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}
	var r struct {
		Code int `json:"code"`
		Data struct {
			Domains    []string `json:"domains"`
			PTRRecords []struct {
				PTR string `json:"ptr"`
			} `json:"ptr_records"`
			DataSource string `json:"data_source"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &r) != nil || r.Code != 200 {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	add := func(v string) {
		v = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
		if v == "" || seen[v] || v == ip {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, d := range r.Data.Domains {
		add(d)
	}
	for _, p := range r.Data.PTRRecords {
		add(p.PTR)
	}
	return out
}

// confirmForward 正向解析 name，判断是否包含 ip
func confirmForward(name, ip string) bool {
	ch := make(chan bool, 1)
	go func() {
		addrs, err := net.LookupHost(name)
		if err != nil {
			ch <- false
			return
		}
		for _, a := range addrs {
			if strings.TrimSpace(a) == ip {
				ch <- true
				return
			}
		}
		ch <- false
	}()
	select {
	case ok := <-ch:
		return ok
	case <-time.After(1500 * time.Millisecond):
		return false
	}
}

// confirmSites 并发校验候选域名是否真的解析到该 IP，只保留校验通过的
func confirmSites(candidates []DNSName, ip string) []DNSName {
	if len(candidates) == 0 {
		return nil
	}
	sem := make(chan struct{}, 16)
	keep := make([]bool, len(candidates))
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			keep[idx] = confirmForward(candidates[idx].Name, ip)
		}(i)
	}
	wg.Wait()

	out := make([]DNSName, 0, len(candidates))
	for i, c := range candidates {
		if keep[i] {
			c.Confirmed = true
			out = append(out, c)
		}
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// webscanSites webscan.cc 同 IP 站点接口：返回 JSON 数组 [{"domain":"a.com","ip":"1.2.3.4"}]
func webscanSites(ctx context.Context, ip string) []DNSName {
	body, err := httpGet(ctx, "https://api.webscan.cc/?action=query&ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return nil
	}
	var list []struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	if json.Unmarshal([]byte(body), &list) != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []DNSName
	for _, it := range list {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(it.Domain), "."))
		if name == "" || seen[name] || name == ip {
			continue
		}
		seen[name] = true
		out = append(out, DNSName{Name: name, Source: "webscan.cc"})
	}
	return out
}

// yougetsignalSites yougetsignal 同 IP 站点接口：返回 {"domainArray":[["a.com","1.2.3.4"]]}
func yougetsignalSites(ctx context.Context, ip string) []DNSName {
	form := url.Values{"remoteAddress": {ip}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://www.yougetsignal.com/tools/web-sites-on-web-server/php/get-web-sites-on-web-server-json.php",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var data struct {
		DomainArray [][]string `json:"domainArray"`
	}
	if json.Unmarshal(b, &data) != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []DNSName
	for _, pair := range data.DomainArray {
		if len(pair) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pair[0]), "."))
		if name == "" || seen[name] || name == ip {
			continue
		}
		seen[name] = true
		out = append(out, DNSName{Name: name, Source: "yougetsignal"})
	}
	return out
}

// ReverseDNS 使用默认接口汇总反查结果
func ReverseDNS(ctx context.Context, ipStr string) (*ReverseDNSResult, error) {
	return ReverseDNSWithSources(ctx, ipStr, nil)
}

// ReverseDNSWithSources 按选择的接口并发反查域名与同 IP 站点
func ReverseDNSWithSources(ctx context.Context, ipStr string, ids []string) (*ReverseDNSResult, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, fmt.Errorf("IP 格式不合法：%s", ipStr)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("暂不支持 IPv6：%s", ipStr)
	}
	ip = ip.To4()

	if len(ids) == 0 {
		for _, s := range reverseSources {
			if s.Default {
				ids = append(ids, s.ID)
			}
		}
	}
	// 外部跳转类接口与未知 ID 不参与服务端查询
	valid := make([]string, 0, len(ids))
	meta := make(map[string]ReverseSource, len(ids))
	seenID := make(map[string]bool, len(ids))
	for _, raw := range ids {
		s, ok := reverseSourceByID(strings.ToLower(strings.TrimSpace(raw)))
		if !ok || s.External || seenID[s.ID] {
			continue
		}
		seenID[s.ID] = true
		valid = append(valid, s.ID)
		meta[s.ID] = s
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("未选择有效的反查接口")
	}

	res := &ReverseDNSResult{IP: ip.String(), Sources: make([]ReverseSourceStatus, 0, len(valid))}
	start := time.Now()

	type outcome struct {
		ptr   []string
		sites []DNSName
		note  string
	}
	outcomes := make([]outcome, len(valid))
	var wg sync.WaitGroup
	for i, id := range valid {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			switch id {
			case "ptr":
				outcomes[i].ptr = systemPTR(res.IP, 2*time.Second)
			case "doh":
				outcomes[i].ptr = append(outcomes[i].ptr, dohPTR(ctx, "https://dns.alidns.com/resolve", res.IP)...)
				outcomes[i].ptr = append(outcomes[i].ptr, dohPTR(ctx, "https://cloudflare-dns.com/dns-query", res.IP)...)
			case "hackertarget":
				outcomes[i].ptr = hackertargetPTR(ctx, res.IP)
			case "nztool":
				outcomes[i].ptr = nztoolPTR(ctx, res.IP)
			case "webscan":
				outcomes[i].sites = webscanSites(ctx, res.IP)
			case "yougetsignal":
				outcomes[i].sites = yougetsignalSites(ctx, res.IP)
			}
		}(i, id)
	}
	wg.Wait()

	seenPTR := make(map[string]bool)
	addPTR := func(names []string, source string) int {
		added := 0
		for _, n := range names {
			n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
			if n == "" || seenPTR[n] {
				continue
			}
			seenPTR[n] = true
			res.PTR = append(res.PTR, DNSName{Name: n, Source: source})
			added++
		}
		return added
	}
	seenSite := make(map[string]bool)
	var candidates []DNSName
	for i, id := range valid {
		st := ReverseSourceStatus{ID: id, Name: meta[id].Name}
		st.Count += addPTR(outcomes[i].ptr, st.Name)
		if outcomes[i].note != "" {
			st.Note = outcomes[i].note
		}
		for _, site := range outcomes[i].sites {
			if seenSite[site.Name] {
				continue
			}
			seenSite[site.Name] = true
			candidates = append(candidates, site)
			st.Count++
		}
		res.Sources = append(res.Sources, st)
	}

	// 正向确认（最多 8 条，避免大量 DNS 查询拖慢响应）
	limit := len(res.PTR)
	if limit > 8 {
		limit = 8
	}
	wg = sync.WaitGroup{}
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res.PTR[idx].Confirmed = confirmForward(res.PTR[idx].Name, res.IP)
		}(i)
	}
	wg.Wait()

	// 第三方「同 IP 站点」数据噪声较大，逐个做正向解析校验，只保留解析到该 IP 的域名
	if len(candidates) > 150 {
		candidates = candidates[:150]
	}
	res.SameIP = confirmSites(candidates, res.IP)
	switch {
	case len(res.SameIP) == 0 && len(res.PTR) == 0:
		res.Note = "所选接口未查询到任何域名记录：目标可能没有配置 PTR，也可能没有已知网站在此 IP 上，或第三方接口暂不可用。"
	case len(res.SameIP) == 0 && len(candidates) > 0:
		res.Note = fmt.Sprintf("第三方接口返回了 %d 个候选域名，但经 DNS 正向校验后均未解析到该 IP（接口数据可能过期或不准确）；上方仅显示可信的 PTR 结果。", len(candidates))
	case len(res.SameIP) == 0:
		res.Note = "「同 IP 站点」未获取到数据（第三方接口可能限流，可稍后重试）。"
	default:
		res.Note = "「同 IP 站点」来自第三方接口，并已逐个做 DNS 正向校验（确认解析到该 IP）；PTR 结果来自反向 DNS，正向确认状态仅供参考。"
	}
	sort.SliceStable(res.SameIP, func(i, j int) bool { return res.SameIP[i].Name < res.SameIP[j].Name })
	res.Elapsed = time.Since(start).Milliseconds()
	return res, nil
}

// handleReverseDNSSources 返回可选的反查接口列表
func handleReverseDNSSources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(reverseSources)
}

// handleReverseDNS 返回 JSON 反查结果；sources 为逗号分隔的接口 ID，留空则用全部默认接口
func handleReverseDNS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var ids []string
	if raw := q.Get("sources"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				ids = append(ids, s)
			}
		}
	}
	res, err := ReverseDNSWithSources(r.Context(), q.Get("ip"), ids)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(res)
}
