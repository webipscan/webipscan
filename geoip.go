package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- geoip.dat（v2fly / V2Ray GeoIPList）本地查询 ----------

const geoIPFileName = "geoip.dat"

// geoIPFilePath 允许测试时替换为临时路径
var geoIPFilePath = func() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), geoIPFileName)
	}
	return geoIPFileName
}()

// 用户给出的两个 GitHub 加速镜像 + 官方地址兜底
var geoIPMirrors = []string{
	"https://ghfast.top/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
	"https://gh-proxy.com/https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
	"https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
}

// GeoIPStatus geoip.dat 文件与远端版本对比状态
type GeoIPStatus struct {
	Exists     bool   `json:"exists"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	RemoteSize int64  `json:"remoteSize"`
	Latest     bool   `json:"latest"`
	Mirror     string `json:"mirror"`
	Updated    string `json:"updated"`
	EntryCount int    `json:"entryCount"`
	Note       string `json:"note"`
}

// ipRange geoip.dat 中的一条 CIDR（统一按 16 字节比较，IPv4 使用 ::ffff:a.b.c.d 映射）
type ipRange struct {
	start [16]byte
	end   [16]byte
	code  string
}

type geoIPEntry struct {
	code string
	ip   []byte
	pref uint32
}

type geoIPDB struct {
	ranges  []ipRange
	size    int64
	modTime time.Time
}

var (
	geoCacheMu sync.Mutex
	geoCache   *geoIPDB
)

// pbVarint 读取 protobuf varint
func pbVarint(data []byte, pos int) (uint64, int, error) {
	var val uint64
	var shift uint
	for pos < len(data) {
		b := data[pos]
		pos++
		val |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return val, pos, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, pos, fmt.Errorf("varint 溢出")
		}
	}
	return 0, pos, fmt.Errorf("protobuf 数据截断")
}

// pbSkip 跳过一个未知字段
func pbSkip(data []byte, pos int, wire uint64) (int, error) {
	switch wire {
	case 0: // varint
		_, p, err := pbVarint(data, pos)
		return p, err
	case 1: // 64bit
		if pos+8 > len(data) {
			return pos, fmt.Errorf("protobuf 数据截断")
		}
		return pos + 8, nil
	case 2: // length-delimited
		n, p, err := pbVarint(data, pos)
		if err != nil {
			return pos, err
		}
		if n > uint64(len(data)-p) {
			return pos, fmt.Errorf("protobuf 字段长度非法")
		}
		return p + int(n), nil
	case 5: // 32bit
		if pos+4 > len(data) {
			return pos, fmt.Errorf("protobuf 数据截断")
		}
		return pos + 4, nil
	default:
		return pos, fmt.Errorf("不支持的 protobuf wire type %d", wire)
	}
}

// parseGeoIPList 解析 GeoIPList。格式：
//
//	message CIDR      { bytes ip = 1; uint32 prefix = 2; }
//	message GeoIP     { string country_code = 1; repeated CIDR cidr = 2; }
//	message GeoIPList { repeated GeoIP entry = 1; }
func parseGeoIPList(data []byte) ([]geoIPEntry, error) {
	pos := 0
	var out []geoIPEntry
	for pos < len(data) {
		tag, p, err := pbVarint(data, pos)
		if err != nil {
			return nil, err
		}
		pos = p
		field, wire := tag>>3, tag&7
		if field != 1 || wire != 2 {
			pos, err = pbSkip(data, pos, wire)
			if err != nil {
				return nil, err
			}
			continue
		}
		n, p, err := pbVarint(data, pos)
		if err != nil {
			return nil, err
		}
		pos = p
		if n > uint64(len(data)-pos) {
			return nil, fmt.Errorf("GeoIP 条目长度非法")
		}
		entry, err := parseGeoIPEntry(data[pos : pos+int(n)])
		if err != nil {
			return nil, err
		}
		pos += int(n)
		out = append(out, entry...)
	}
	return out, nil
}

// parseGeoIPEntry 解析一个 GeoIP 消息，返回其中的全部 CIDR（附带 country_code）
func parseGeoIPEntry(data []byte) ([]geoIPEntry, error) {
	pos := 0
	code := ""
	var cidrs []geoIPEntry
	for pos < len(data) {
		tag, p, err := pbVarint(data, pos)
		if err != nil {
			return nil, err
		}
		pos = p
		field, wire := tag>>3, tag&7
		if wire == 2 {
			n, np, err := pbVarint(data, pos)
			if err != nil {
				return nil, err
			}
			pos = np
			if n > uint64(len(data)-pos) {
				return nil, fmt.Errorf("GeoIP 字段长度非法")
			}
			sub := data[pos : pos+int(n)]
			pos += int(n)
			switch field {
			case 1:
				code = string(sub)
			case 2:
				c, err := parseCIDR(sub)
				if err != nil {
					return nil, err
				}
				cidrs = append(cidrs, geoIPEntry{code: code, ip: c.ip, pref: c.pref})
			}
			continue
		}
		pos, err = pbSkip(data, pos, wire)
		if err != nil {
			return nil, err
		}
	}
	return cidrs, nil
}

type rawCIDR struct {
	ip   []byte
	pref uint32
}

func parseCIDR(data []byte) (rawCIDR, error) {
	pos := 0
	var out rawCIDR
	for pos < len(data) {
		tag, p, err := pbVarint(data, pos)
		if err != nil {
			return out, err
		}
		pos = p
		field, wire := tag>>3, tag&7
		switch {
		case field == 1 && wire == 2:
			n, np, err := pbVarint(data, pos)
			if err != nil {
				return out, err
			}
			pos = np
			if n > uint64(len(data)-pos) {
				return out, fmt.Errorf("CIDR ip 长度非法")
			}
			out.ip = append([]byte(nil), data[pos:pos+int(n)]...)
			pos += int(n)
		case field == 2 && wire == 0:
			v, np, err := pbVarint(data, pos)
			if err != nil {
				return out, err
			}
			out.pref = uint32(v)
			pos = np
		default:
			pos, err = pbSkip(data, pos, wire)
			if err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// loadGeoIPDB 读取并解析本地 geoip.dat；文件未变化时复用缓存
func loadGeoIPDB() (*geoIPDB, error) {
	st, err := os.Stat(geoIPFilePath)
	if err != nil {
		return nil, err
	}
	geoCacheMu.Lock()
	defer geoCacheMu.Unlock()
	if geoCache != nil && geoCache.size == st.Size() && geoCache.modTime.Equal(st.ModTime()) {
		return geoCache, nil
	}

	raw, err := os.ReadFile(geoIPFilePath)
	if err != nil {
		return nil, err
	}
	entries, err := parseGeoIPList(raw)
	if err != nil {
		return nil, fmt.Errorf("解析 geoip.dat 失败：%w", err)
	}
	db := &geoIPDB{size: st.Size(), modTime: st.ModTime(), ranges: make([]ipRange, 0, len(entries))}
	for _, e := range entries {
		if len(e.ip) != 4 && len(e.ip) != 16 {
			continue
		}
		prefix := int(e.pref)
		if len(e.ip) == 4 {
			if prefix > 32 {
				continue
			}
			prefix += 96 // IPv4 映射到 ::ffff:x.x.x.x
		} else if prefix > 128 {
			continue
		}
		mask := net.CIDRMask(prefix, 128)
		ip16 := net.IP(e.ip).To16()
		var r ipRange
		for i := 0; i < 16; i++ {
			r.start[i] = ip16[i] & mask[i]
			r.end[i] = r.start[i] | ^mask[i]
		}
		r.code = strings.ToUpper(strings.TrimSpace(e.code))
		db.ranges = append(db.ranges, r)
	}
	if len(db.ranges) == 0 {
		return nil, fmt.Errorf("geoip.dat 中没有可用的 IP 段")
	}
	sort.Slice(db.ranges, func(i, j int) bool {
		return bytes.Compare(db.ranges[i].start[:], db.ranges[j].start[:]) < 0
	})
	geoCache = db
	return db, nil
}

// invalidateGeoIPCache 文件更新后使缓存失效
func invalidateGeoIPCache() {
	geoCacheMu.Lock()
	geoCache = nil
	geoCacheMu.Unlock()
}

// geoIPLocalLookup 返回 IP 在 geoip.dat 中命中的全部标签（国家代码 / 分类）
func geoIPLocalLookup(ipStr string) ([]string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("IP 格式不合法：%s", ipStr)
	}
	db, err := loadGeoIPDB()
	if err != nil {
		return nil, err
	}
	target := ip.To16()
	var codes []string
	seen := make(map[string]bool)
	// geoip.dat 中国家段与分类段会重叠，因此倒序扫描全部区间；
	// 命中数通常很少，扫描在 start 远小于目标时可提前结束。
	for i := len(db.ranges) - 1; i >= 0; i-- {
		r := &db.ranges[i]
		if bytes.Compare(r.end[:], target) < 0 {
			continue
		}
		if bytes.Compare(r.start[:], target) > 0 {
			continue
		}
		if !seen[r.code] {
			seen[r.code] = true
			codes = append(codes, r.code)
			if len(codes) >= 64 {
				break
			}
		}
	}
	return codes, nil
}

// geoIPReadStatus 读取本地文件信息（不检查远端）
func geoIPReadStatus() GeoIPStatus {
	s := GeoIPStatus{Path: geoIPFilePath}
	if st, err := os.Stat(geoIPFilePath); err == nil {
		s.Exists = true
		s.Size = st.Size()
		s.Updated = st.ModTime().Format("2006-01-02 15:04:05")
	}
	geoCacheMu.Lock()
	if geoCache != nil {
		s.EntryCount = len(geoCache.ranges)
	}
	geoCacheMu.Unlock()
	return s
}

// ---------- 属地详情（本地 geoip.dat + 在线补充） ----------

// GeoDNSInfo 属地查询中域名解析所用的 DNS / DoH 信息
type GeoDNSInfo struct {
	Mode    string      `json:"mode"`
	Server  string      `json:"server"`
	Type    string      `json:"type"`
	RCode   string      `json:"rcode"`
	Records []DNSAnswer `json:"records"`
	Elapsed int64       `json:"elapsed"`
	Note    string      `json:"note,omitempty"`
}

// GeoIPInfo IP 属地查询结果
type GeoIPInfo struct {
	Query        string      `json:"query,omitempty"`
	IP           string      `json:"ip"`
	ResolvedIPs  []string    `json:"resolvedIps,omitempty"`
	DNS          *GeoDNSInfo `json:"dns,omitempty"`
	Country      string      `json:"country"`
	CountryCode  string      `json:"countryCode"`
	Region       string      `json:"region"`
	City         string      `json:"city"`
	ISP          string      `json:"isp"`
	Organization string      `json:"organization"`
	ASN          string      `json:"asn"`
	Type         string      `json:"type"`
	Tags         []string    `json:"tags"`
	Latitude     string      `json:"latitude"`
	Longitude    string      `json:"longitude"`
	Timezone     string      `json:"timezone"`
	Source       string      `json:"source"`
	Note         string      `json:"note"`

	proxy   bool
	hosting bool
	mobile  bool
}

// countryNames 常用国家/地区中文名（geoip.dat 只有两位代码，无省市信息）
var countryNames = map[string]string{
	"CN": "中国", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾", "JP": "日本",
	"KR": "韩国", "SG": "新加坡", "IN": "印度", "TH": "泰国", "VN": "越南", "MY": "马来西亚",
	"ID": "印度尼西亚", "PH": "菲律宾", "PK": "巴基斯坦", "BD": "孟加拉国", "KZ": "哈萨克斯坦",
	"US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西", "AR": "阿根廷", "CL": "智利",
	"GB": "英国", "FR": "法国", "DE": "德国", "IT": "意大利", "ES": "西班牙", "NL": "荷兰",
	"BE": "比利时", "CH": "瑞士", "AT": "奥地利", "SE": "瑞典", "NO": "挪威", "DK": "丹麦",
	"FI": "芬兰", "PL": "波兰", "CZ": "捷克", "HU": "匈牙利", "GR": "希腊", "PT": "葡萄牙",
	"IE": "爱尔兰", "RU": "俄罗斯", "UA": "乌克兰", "TR": "土耳其", "IL": "以色列",
	"AE": "阿联酋", "SA": "沙特阿拉伯", "EG": "埃及", "ZA": "南非", "NG": "尼日利亚",
	"AU": "澳大利亚", "NZ": "新西兰", "AP": "亚太地区", "EU": "欧洲地区", "UN": "未知",
}

// classifyGeoIP 根据本地标签和在线字段得出类型描述
func classifyGeoIP(info *GeoIPInfo, tags []string) {
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[strings.ToUpper(t)] = true
	}
	switch {
	case tagSet["PRIVATE"] || tagSet["PRIVATE-USE"] || tagSet["LOCAL"]:
		info.Type = "内网 / 私有地址"
	case tagSet["RESERVED"]:
		info.Type = "保留地址"
	case info.Organization != "" && (strings.Contains(strings.ToLower(info.Organization), "cloud") ||
		strings.Contains(strings.ToLower(info.Organization), "hosting") || tagSet["ORGANIZATION"]):
		info.Type = "数据中心 / 企业专线"
	case info.CountryCode == "CN":
		info.Type = "中国大陆"
	case info.CountryCode != "":
		info.Type = "境外"
	default:
		info.Type = "未知"
	}
	// 在线接口提供的更细粒度标记优先
	if info.proxy {
		info.Type = "代理 / VPN"
	} else if info.hosting {
		info.Type = "数据中心 / 机房"
	} else if info.mobile {
		info.Type = "移动网络"
	}
}

func enrichIPAPI(ctx context.Context, ip string, info *GeoIPInfo) bool {
	u := "http://ip-api.com/json/" + url.PathEscape(ip) +
		"?lang=zh-CN&fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,lat,lon,timezone,query"
	body, err := httpGet(ctx, u, nil)
	if err != nil {
		return false
	}
	var r struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		Mobile      bool    `json:"mobile"`
		Proxy       bool    `json:"proxy"`
		Hosting     bool    `json:"hosting"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
	}
	if json.Unmarshal([]byte(body), &r) != nil || r.Status != "success" {
		return false
	}
	info.Country = firstNonEmpty(info.Country, r.Country)
	info.CountryCode = firstNonEmpty(info.CountryCode, r.CountryCode)
	info.Region = r.RegionName
	info.City = r.City
	info.ISP = r.ISP
	info.Organization = r.Org
	info.ASN = r.AS
	info.Timezone = r.Timezone
	info.Latitude = fmtNum(r.Lat)
	info.Longitude = fmtNum(r.Lon)
	info.proxy, info.hosting, info.mobile = r.Proxy, r.Hosting, r.Mobile
	info.Source = "ip-api.com"
	return true
}

func enrichIPWhois(ctx context.Context, ip string, info *GeoIPInfo) bool {
	body, err := httpGet(ctx, "https://ipwho.is/"+url.PathEscape(ip)+"?lang=zh-CN", nil)
	if err != nil {
		return false
	}
	var r struct {
		Success     bool    `json:"success"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Timezone    struct {
			ID string `json:"id"`
		} `json:"timezone"`
		Connection struct {
			ISP string      `json:"isp"`
			Org string      `json:"org"`
			ASN json.Number `json:"asn"`
		} `json:"connection"`
	}
	if json.Unmarshal([]byte(body), &r) != nil || !r.Success {
		return false
	}
	asn := r.Connection.ASN.String()
	if asn != "" && asn != "0" {
		asn = "AS" + asn
	}
	info.Country = firstNonEmpty(info.Country, r.Country)
	info.CountryCode = firstNonEmpty(info.CountryCode, strings.ToUpper(r.CountryCode))
	info.Region = firstNonEmpty(info.Region, r.Region)
	info.City = firstNonEmpty(info.City, r.City)
	info.ISP = firstNonEmpty(info.ISP, r.Connection.ISP)
	info.Organization = firstNonEmpty(info.Organization, r.Connection.Org)
	info.ASN = firstNonEmpty(info.ASN, asn)
	info.Timezone = firstNonEmpty(info.Timezone, r.Timezone.ID)
	if info.Latitude == "" {
		info.Latitude = fmtNum(r.Latitude)
		info.Longitude = fmtNum(r.Longitude)
	}
	info.Source = "ipwho.is"
	return true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func fmtNum(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 4, 64)
}

// QueryGeoIP 查询 IP 属地：本地 geoip.dat 提供国家/分类，在线接口补充省市、运营商、公司
func QueryGeoIP(ctx context.Context, ipStr string) (*GeoIPInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// 允许输入域名，解析后查询
		addrs := lookupIPv4(ipStr, 3*time.Second)
		if len(addrs) == 0 {
			return nil, fmt.Errorf("IP 或域名无效：%s", ipStr)
		}
		ipStr = addrs[0]
		ip = net.ParseIP(ipStr)
	}
	ipStr = ip.String()

	info := &GeoIPInfo{IP: ipStr, Tags: []string{}, Source: "本地 geoip.dat"}
	tags, err := geoIPLocalLookup(ipStr)
	if err != nil {
		info.Note = "本地 geoip.dat 不可用：" + err.Error() + "。可在「程序信息」中检查/更新数据库。"
	} else {
		info.Tags = tags
		for _, t := range tags {
			if len(t) == 2 && t == strings.ToUpper(t) {
				if name, ok := countryNames[t]; ok {
					info.Country = name
					info.CountryCode = t
					break
				}
			}
			if strings.HasPrefix(t, "CN-") {
				info.Country = "中国"
				info.CountryCode = "CN"
			}
		}
	}

	onlineOK := enrichIPAPI(ctx, ipStr, info)
	if !onlineOK {
		onlineOK = enrichIPWhois(ctx, ipStr, info)
	}
	if !onlineOK {
		info.Note = strings.TrimSpace(info.Note + " 在线详情接口暂不可用，省市、公司/运营商与类型仅为本地数据推断。")
		info.Source = strings.TrimSpace(info.Source)
	} else {
		info.Source = "geoip.dat + " + info.Source
	}
	classifyGeoIP(info, tags)
	return info, nil
}

// GeoDNSOptions 属地查询时解析域名所用的 DNS / DoH 配置
type GeoDNSOptions struct {
	Mode   string // system / dns / doh
	Server string
	QType  string // A / AAAA
}

// QueryGeoIPWithDNS 支持通过指定 DNS / DoH 服务器解析域名后再查询属地；IP 输入时等同于 QueryGeoIP
func QueryGeoIPWithDNS(ctx context.Context, input string, opt GeoDNSOptions) (*GeoIPInfo, error) {
	input = strings.TrimSpace(input)
	if ip := net.ParseIP(input); ip != nil {
		info, err := QueryGeoIP(ctx, ip.String())
		if info != nil {
			info.Query = input
		}
		return info, err
	}
	mode := strings.ToLower(strings.TrimSpace(opt.Mode))
	if mode == "" {
		mode = "system"
	}
	qtype := strings.ToUpper(strings.TrimSpace(opt.QType))
	if qtype != "AAAA" {
		qtype = "A"
	}
	lookup, err := QueryDNS(ctx, DNSQueryRequest{
		Name: input, QType: qtype, Mode: mode, Server: opt.Server, Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("域名解析失败：%w", err)
	}
	var ips []string
	seen := make(map[string]bool)
	wantType := dnsNameTypes[qtype]
	for _, a := range lookup.Answers {
		if a.Type != wantType {
			continue
		}
		ip := net.ParseIP(a.Value)
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		ips = append(ips, ip.String())
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s 查询 %s 未返回 %s 记录（%s）", strings.ToUpper(mode), lookup.Server, qtype, lookup.RCode)
	}
	info, err := QueryGeoIP(ctx, ips[0])
	if err != nil {
		return nil, err
	}
	modeLabel := map[string]string{"system": "系统 DNS", "dns": "DNS 直连", "doh": "DoH"}[mode]
	if modeLabel == "" {
		modeLabel = mode
	}
	info.Query = input
	info.ResolvedIPs = ips
	info.DNS = &GeoDNSInfo{
		Mode: modeLabel, Server: lookup.Server, Type: lookup.Type, RCode: lookup.RCode,
		Records: lookup.Answers, Elapsed: lookup.Elapsed, Note: lookup.Note,
	}
	info.Note = strings.TrimSpace(fmt.Sprintf("域名 %s 经 %s（%s）解析为 %s。", input, modeLabel, lookup.Server, ips[0]) + " " + info.Note)
	return info, nil
}

func handleGeoIPQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	info, err := QueryGeoIPWithDNS(r.Context(), q.Get("ip"), GeoDNSOptions{
		Mode:   q.Get("dnsMode"),
		Server: q.Get("dnsServer"),
		QType:  q.Get("dnsType"),
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(info)
}
