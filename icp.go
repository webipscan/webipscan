package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------- 域名备案信息（ICP）查询 ----------

// ICPRecord 一条备案记录
type ICPRecord struct {
	Domain     string `json:"domain"`     // 网站域名
	SiteName   string `json:"siteName"`   // 网站名称
	UnitName   string `json:"unitName"`   // 主办单位名称
	Nature     string `json:"nature"`     // 主办单位性质
	ICPCode    string `json:"icpCode"`    // 备案号
	UpdateTime string `json:"updateTime"` // 审核/更新时间
}

// ICPResult 备案查询结果
type ICPResult struct {
	Domain      string      `json:"domain"`
	Source      string      `json:"source"`      // 命中的数据来源
	Records     []ICPRecord `json:"records"`     // 备案记录
	Note        string      `json:"note"`        // 补充说明 / 失败原因
	OfficialURL string      `json:"officialUrl"` // 工信部官方查询地址
	Elapsed     int64       `json:"elapsed"`
}

var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$`)

// NormalizeDomain 把用户输入（可能是 URL 或带路径）规范为裸域名
func NormalizeDomain(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", fmt.Errorf("请填写域名，如 example.com")
	}
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(s, "/"), "。"))
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("域名格式不合法：%s", input)
		}
		s = u.Host
	}
	// 去掉路径与端口
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	s = strings.TrimPrefix(s, "www.")
	if !domainRe.MatchString(s) {
		return "", fmt.Errorf("域名格式不合法：%s（示例：example.com）", input)
	}
	return s, nil
}

// icpProvider 一个第三方备案查询接口
type icpProvider struct {
	name string
	url  func(domain string) string
}

// icpProviders 依次尝试的公共免费接口（全部返回 JSON，字段名各异，用通用提取器解析）
// 前三个为 2026 年仍在维护、实测可用的服务；后面的旧接口留作兜底。
var icpProviders = []icpProvider{
	{"zxki", func(d string) string { return "https://api.zxki.cn/api/icp?url=" + url.QueryEscape(d) }},
	{"apihz", func(d string) string {
		return "https://cn.apihz.cn/api/wangzhan/icp.php?id=88888888&key=88888888&domain=" + url.QueryEscape(d)
	}},
	{"apizero", func(d string) string { return "https://v1.apizero.cn/api/icp?domain=" + url.QueryEscape(d) }},
	{"vvhan", func(d string) string { return "https://api.vvhan.com/api/icp?url=" + url.QueryEscape(d) }},
	{"pearktrue", func(d string) string { return "https://api.pearktrue.cn/api/icp/?domain=" + url.QueryEscape(d) }},
	{"mir6", func(d string) string { return "https://api.mir6.com/api/icp?domain=" + url.QueryEscape(d) }},
	{"66mz8", func(d string) string { return "https://api.66mz8.com/api/icp.php?domain=" + url.QueryEscape(d) }},
}

// 字段名候选（按优先级，忽略大小写与分隔符）
var (
	icpKeysDomain = []string{"domain", "domainname", "homeurl", "weburl", "website", "url"}
	icpKeysSite   = []string{"webname", "sitename", "websitename", "site", "title"}
	icpKeysUnit   = []string{"unitname", "unit", "companyname", "company", "organizername", "organizer", "orgname", "subject", "name"}
	icpKeysNature = []string{"naturename", "nature", "unitnature", "companytype", "sitetype", "servicetype", "type"}
	icpKeysCode   = []string{"mainlicence", "servicelicence", "icpcode", "icp", "licence", "license", "servicelicense", "beian", "number", "code"}
	icpKeysTime   = []string{"updatetime", "updatedate", "audittime", "auditdate", "time", "date"}
)

func normKey(s string) string {
	s = strings.ToLower(s)
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(s)
}

// pickString 在对象中按候选字段名取值（先后顺序即优先级）
func pickString(m map[string]interface{}, candidates ...string) string {
	norm := make(map[string]interface{}, len(m))
	for k, v := range m {
		norm[normKey(k)] = v
	}
	for _, c := range candidates {
		v, ok := norm[c]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" && s != "-" && !strings.EqualFold(s, "null") {
				return s
			}
		case float64:
			if t > 0 {
				return strconv.FormatFloat(t, 'f', -1, 64)
			}
		}
	}
	return ""
}

// collectMaps 递归收集 JSON 中的所有对象
func collectMaps(v interface{}, out *[]map[string]interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		*out = append(*out, t)
		for _, sub := range t {
			collectMaps(sub, out)
		}
	case []interface{}:
		for _, sub := range t {
			collectMaps(sub, out)
		}
	}
}

// extractICP 从任意结构的 JSON 响应中提取备案记录
func extractICP(body string) ([]ICPRecord, string) {
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return nil, "接口返回非 JSON 数据"
	}
	var objs []map[string]interface{}
	collectMaps(v, &objs)

	seen := make(map[string]bool)
	var out []ICPRecord
	for _, m := range objs {
		rec := ICPRecord{
			Domain:     pickString(m, icpKeysDomain...),
			SiteName:   pickString(m, icpKeysSite...),
			UnitName:   pickString(m, icpKeysUnit...),
			Nature:     pickString(m, icpKeysNature...),
			ICPCode:    pickString(m, icpKeysCode...),
			UpdateTime: pickString(m, icpKeysTime...),
		}
		// 纯数字的 "code" 通常是 HTTP 状态码，不是备案号
		if rec.ICPCode != "" && isDigits(rec.ICPCode) {
			rec.ICPCode = ""
		}
		// 有效性判定：有备案号，或有主办单位 + 至少一个网站字段，
		// 避免把 {"name":"接口名"} 之类的响应误判成备案记录
		if rec.ICPCode == "" && !(rec.UnitName != "" && (rec.Domain != "" || rec.Nature != "" || rec.SiteName != "")) {
			continue
		}
		key := rec.Domain + "|" + rec.ICPCode + "|" + rec.UnitName
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rec)
		if len(out) >= 20 {
			break
		}
	}
	if len(out) == 0 {
		msg := pickMessage(v)
		if msg == "" {
			msg = "接口未返回可识别的备案字段"
		}
		return nil, msg
	}
	return out, ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// pickMessage 从响应顶层提取 msg/message 之类的提示
func pickMessage(v interface{}) string {
	m, ok := v.(map[string]interface{})
	if !ok {
		return ""
	}
	for _, k := range []string{"msg", "message", "info", "error", "errmsg"} {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// icpNotFound 判断接口是否明确返回「域名未备案 / 没有备案记录」。
// 这种情况是有效查询结果，不需要继续尝试其他接口。
func icpNotFound(body string) bool {
	var v interface{}
	if json.Unmarshal([]byte(body), &v) != nil {
		return false
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	if msg := pickMessage(v); strings.Contains(msg, "未查询到") || strings.Contains(msg, "没有备案") ||
		strings.Contains(msg, "未备案") || strings.Contains(msg, "不存在备案") {
		return true
	}
	if data, ok := m["data"].(map[string]interface{}); ok {
		if filed, ok := data["is_filed"]; ok {
			switch b := filed.(type) {
			case bool:
				return !b
			case string:
				return b == "false" || b == "0" || b == "否"
			}
		}
		if filed, ok := data["is_icp"]; ok {
			switch b := filed.(type) {
			case bool:
				return !b
			case string:
				return b == "false" || b == "0" || b == "否"
			}
		}
		if len(data) == 0 {
			return true
		}
	}
	if arr, ok := m["data"].([]interface{}); ok && len(arr) == 0 {
		if code, ok := m["code"].(float64); ok && (code == 200 || code == 0) {
			return true
		}
	}
	return false
}

// icpFromMIIT 直接查询工信部备案系统（需要先获取 token，接口可能变动/风控）
func icpFromMIIT(ctx context.Context, domain string) ([]ICPRecord, error) {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sum := md5.Sum([]byte("testtest" + ts))
	authURL := "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth?timeStamp=" + ts +
		"&authKey=" + hex.EncodeToString(sum[:])
	body, err := httpGet(ctx, authURL, map[string]string{
		"Referer": "https://beian.miit.gov.cn/",
		"Origin":  "https://beian.miit.gov.cn",
	})
	if err != nil {
		return nil, err
	}
	var auth struct {
		Code   int    `json:"code"`
		Msg    string `json:"msg"`
		Params struct {
			Bussiness string `json:"bussiness"`
		} `json:"params"`
	}
	if json.Unmarshal([]byte(body), &auth) != nil || auth.Params.Bussiness == "" {
		return nil, fmt.Errorf("工信部接口鉴权失败")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"pageNum": "1", "pageSize": "10", "unitName": domain, "serviceType": 1,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition",
		strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("token", auth.Params.Bussiness)
	req.Header.Set("Referer", "https://beian.miit.gov.cn/")
	req.Header.Set("Origin", "https://beian.miit.gov.cn")
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, e := resp.Body.Read(buf)
		out.Write(buf[:n])
		if e != nil || out.Len() > 512*1024 {
			break
		}
	}
	raw := out.String()
	var probe struct {
		Code   int             `json:"code"`
		Msg    string          `json:"msg"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal([]byte(raw), &probe) != nil {
		return nil, fmt.Errorf("工信部接口返回非 JSON")
	}
	if probe.Code != 200 {
		if probe.Msg == "" {
			probe.Msg = "code=" + strconv.Itoa(probe.Code)
		}
		return nil, fmt.Errorf("工信部接口：%s", probe.Msg)
	}
	// 官方字段：list[] 内为 domain / unitName / mainLicence / serviceLicence / nature / updateTime
	records, msg := extractICP(raw)
	if len(records) == 0 {
		if msg == "" {
			msg = "工信部未查询到该域名的备案记录"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return records, nil
}

// buildCustomURL 拼装自定义接口地址：支持 {domain} 占位符，否则自动追加 ?domain=
func buildCustomURL(apiURL, domain string) (string, error) {
	u := strings.TrimSpace(apiURL)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "", fmt.Errorf("自定义接口需以 http:// 或 https:// 开头")
	}
	if strings.Contains(u, "{domain}") {
		return strings.ReplaceAll(u, "{domain}", url.QueryEscape(domain)), nil
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + "domain=" + url.QueryEscape(domain), nil
}

// QueryICP 依次尝试各个接口，返回第一份成功结果。
// customAPI 非空时优先使用用户自定义接口（响应需为 JSON）。
func QueryICP(ctx context.Context, domain, customAPI string) (*ICPResult, error) {
	start := time.Now()
	res := &ICPResult{
		Domain:      domain,
		OfficialURL: "https://beian.miit.gov.cn/#/Integrated/index",
	}
	var failures []string

	if strings.TrimSpace(customAPI) != "" {
		u, err := buildCustomURL(customAPI, domain)
		if err != nil {
			return nil, err
		}
		body, err := httpGet(ctx, u, map[string]string{"Referer": "https://beian.miit.gov.cn/"})
		if err != nil {
			failures = append(failures, "自定义接口："+err.Error())
		} else if icpNotFound(body) {
			res.Source = "自定义接口"
			res.Note = "自定义接口明确返回：该域名未查询到备案记录。"
			res.Elapsed = time.Since(start).Milliseconds()
			return res, nil
		} else if records, msg := extractICP(body); len(records) > 0 {
			res.Source = "自定义接口"
			res.Records = records
			res.Note = "数据来自你配置的自定义备案接口，字段与时效性请自行确认。"
			res.Elapsed = time.Since(start).Milliseconds()
			return res, nil
		} else {
			if msg == "" {
				msg = "未返回可识别的备案字段"
			}
			failures = append(failures, "自定义接口："+msg)
		}
	}

	var notFound []string
	for _, p := range icpProviders {
		body, err := httpGet(ctx, p.url(domain), map[string]string{"Referer": "https://beian.miit.gov.cn/"})
		if err != nil {
			failures = append(failures, p.name+"："+err.Error())
			continue
		}
		if icpNotFound(body) {
			notFound = append(notFound, p.name)
			continue
		}
		records, msg := extractICP(body)
		if len(records) == 0 {
			if msg == "" {
				msg = "未返回备案数据"
			}
			failures = append(failures, p.name+"："+msg)
			continue
		}
		res.Source = p.name
		res.Records = records
		res.Note = "数据来自第三方备案查询接口自动解析，字段与时效性请以工信部官方为准。"
		res.Elapsed = time.Since(start).Milliseconds()
		return res, nil
	}

	// 接口明确报告「未备案」是有效结果，无需再尝试官方接口
	if len(notFound) > 0 {
		res.Source = strings.Join(notFound, " / ")
		res.Note = fmt.Sprintf("该域名未查询到备案记录（明确返回此结果的接口：%s）。"+
			"备案状态以工信部为准，可点击下方官方入口核实。", strings.Join(notFound, "、"))
		res.Elapsed = time.Since(start).Milliseconds()
		return res, nil
	}

	if records, err := icpFromMIIT(ctx, domain); err == nil && len(records) > 0 {
		res.Source = "工信部官方接口"
		res.Records = records
		res.Note = "数据直接来自工信部备案查询系统。"
		res.Elapsed = time.Since(start).Milliseconds()
		return res, nil
	} else if err != nil {
		failures = append(failures, "工信部："+err.Error())
	}

	res.Elapsed = time.Since(start).Milliseconds()
	res.Note = "所有备案接口均未返回结果，可能原因：该域名未备案、接口限流/被拦截，或当前网络无法访问这些服务。" +
		"可点击下方「工信部官方查询」手动核实。\n尝试记录：" + strings.Join(failures, "；")
	if len(failures) == 0 {
		res.Note = "未查询到备案记录。"
	}
	return res, nil
}

// handleICP 返回 JSON 备案查询结果
func handleICP(w http.ResponseWriter, r *http.Request) {
	domain, err := NormalizeDomain(r.URL.Query().Get("domain"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	res, err := QueryICP(r.Context(), domain, r.URL.Query().Get("api"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(res)
}
