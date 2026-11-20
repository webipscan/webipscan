package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---------- DNS / DoH 查询：仅使用 Go 标准库，手写 DNS wire format（RFC 1035 / RFC 8484） ----------

const (
	dnsClassIN   = 1
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypePTR   = 12
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33
	dnsTypeOPT   = 41
	dnsTypeANY   = 255
	dnsTypeCAA   = 257
)

var dnsTypeNames = map[uint16]string{
	dnsTypeA: "A", dnsTypeNS: "NS", dnsTypeCNAME: "CNAME", dnsTypeSOA: "SOA",
	dnsTypePTR: "PTR", dnsTypeMX: "MX", dnsTypeTXT: "TXT", dnsTypeAAAA: "AAAA",
	dnsTypeSRV: "SRV", dnsTypeOPT: "OPT", dnsTypeANY: "ANY", dnsTypeCAA: "CAA",
}

var dnsNameTypes = map[string]uint16{
	"A": dnsTypeA, "NS": dnsTypeNS, "CNAME": dnsTypeCNAME, "SOA": dnsTypeSOA,
	"PTR": dnsTypePTR, "MX": dnsTypeMX, "TXT": dnsTypeTXT, "AAAA": dnsTypeAAAA,
	"SRV": dnsTypeSRV, "ANY": dnsTypeANY, "CAA": dnsTypeCAA,
}

// DNSServerPreset 可选服务器预设
type DNSServerPreset struct {
	Label   string `json:"label"`
	Value   string `json:"value"`
	Default bool   `json:"default,omitempty"`
}

// DNSServerPresets 前端下拉框数据
type DNSServerPresets struct {
	DNS []DNSServerPreset `json:"dns"`
	DoH []DNSServerPreset `json:"doh"`
}

var dnsPresets = DNSServerPresets{
	DNS: []DNSServerPreset{
		{Label: "阿里 DNS（223.5.5.5）", Value: "223.5.5.5", Default: true},
		{Label: "阿里 DNS（223.6.6.6）", Value: "223.6.6.6"},
		{Label: "腾讯 DNSPod（119.29.29.29）", Value: "119.29.29.29"},
		{Label: "114DNS（114.114.114.114）", Value: "114.114.114.114"},
		{Label: "百度 DNS（180.76.76.76）", Value: "180.76.76.76"},
		{Label: "Google DNS（8.8.8.8）", Value: "8.8.8.8"},
		{Label: "Cloudflare（1.1.1.1）", Value: "1.1.1.1"},
	},
	DoH: []DNSServerPreset{
		{Label: "阿里 DoH", Value: "https://dns.alidns.com/dns-query", Default: true},
		{Label: "腾讯 DNSPod DoH", Value: "https://doh.pub/dns-query"},
		{Label: "360 DoH", Value: "https://doh.360.cn/dns-query"},
		{Label: "Cloudflare DoH", Value: "https://cloudflare-dns.com/dns-query"},
		{Label: "Google DoH", Value: "https://dns.google/dns-query"},
		{Label: "AdGuard DoH", Value: "https://dns.adguard-dns.com/dns-query"},
	},
}

// DNSAnswer 一条 DNS 资源记录
type DNSAnswer struct {
	Name     string `json:"name"`
	Type     uint16 `json:"type"`
	TypeName string `json:"typeName"`
	Class    uint16 `json:"class"`
	TTL      uint32 `json:"ttl"`
	Value    string `json:"value"`
}

// DNSQueryResult DNS / DoH 查询结果
type DNSQueryResult struct {
	Query      string      `json:"query"`
	Type       string      `json:"type"`
	Mode       string      `json:"mode"`
	Server     string      `json:"server"`
	RCode      string      `json:"rcode"`
	Flags      string      `json:"flags"`
	Truncated  bool        `json:"truncated"`
	Answers    []DNSAnswer `json:"answers"`
	Authority  []DNSAnswer `json:"authority"`
	Additional []DNSAnswer `json:"additional"`
	Elapsed    int64       `json:"elapsed"`
	Note       string      `json:"note,omitempty"`
}

// DNSQueryRequest DNS 查询参数
type DNSQueryRequest struct {
	Name    string
	QType   string
	Mode    string // system / dns / doh
	Server  string
	TCP     bool
	Timeout time.Duration
}

func handleDNSServers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(dnsPresets)
}

func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	timeout := 3 * time.Second
	if ms, err := strconv.Atoi(q.Get("timeout")); err == nil && ms > 0 && ms <= 30000 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	res, err := QueryDNS(r.Context(), DNSQueryRequest{
		Name:    strings.TrimSpace(q.Get("name")),
		QType:   strings.ToUpper(strings.TrimSpace(q.Get("type"))),
		Mode:    strings.ToLower(strings.TrimSpace(q.Get("mode"))),
		Server:  strings.TrimSpace(q.Get("server")),
		TCP:     q.Get("tcp") == "1" || q.Get("tcp") == "true",
		Timeout: timeout,
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(res)
}

// QueryDNS 按指定方式执行查询
func QueryDNS(ctx context.Context, req DNSQueryRequest) (*DNSQueryResult, error) {
	start := time.Now()
	name := strings.TrimSuffix(strings.TrimSpace(req.Name), ".")
	if name == "" {
		return nil, fmt.Errorf("域名或 IP 不能为空")
	}
	typ := strings.ToUpper(strings.TrimSpace(req.QType))
	if typ == "" {
		typ = "A"
	}
	typeID, ok := dnsNameTypes[typ]
	if !ok {
		return nil, fmt.Errorf("不支持的记录类型：%s", typ)
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "system"
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	res := &DNSQueryResult{Query: name, Type: typ, Mode: mode, Server: req.Server}

	switch mode {
	case "system":
		answers, note, err := systemDNSQuery(ctx, name, typ, timeout)
		if err != nil {
			return nil, err
		}
		res.Answers = answers
		res.RCode = "NOERROR"
		res.Note = note
	case "dns", "doh":
		server := req.Server
		if server == "" {
			if mode == "dns" {
				server = dnsPresets.DNS[0].Value
			} else {
				server = dnsPresets.DoH[0].Value
			}
		}
		res.Server = server
		queryName := name
		if typeID == dnsTypePTR {
			if rev := reverseDNSName(name); rev != "" {
				queryName = rev
			}
		}
		query, err := buildDNSQuery(queryName, typeID)
		if err != nil {
			return nil, err
		}
		var wire []byte
		if mode == "doh" {
			wire, err = dnsExchangeDoH(ctx, server, query, timeout)
		} else {
			wire, err = dnsExchangeDNS(ctx, server, query, timeout, req.TCP)
		}
		if err != nil {
			return nil, err
		}
		parsed, err := parseDNSResponse(wire)
		if err != nil {
			return nil, err
		}
		res.RCode = dnsRCODE(parsed.rcode)
		res.Flags = fmt.Sprintf("0x%04x", parsed.flags)
		res.Truncated = parsed.truncated
		res.Answers, res.Authority, res.Additional = parsed.answers, parsed.authority, parsed.additional
		if parsed.rcode != 0 {
			res.Note = "服务器返回非零响应码"
		}
	default:
		return nil, fmt.Errorf("不支持的查询方式：%s（可选 system / dns / doh）", mode)
	}
	res.Elapsed = time.Since(start).Milliseconds()
	return res, nil
}

// systemDNSQuery 使用 net.Resolver（系统解析器）查询常用记录类型
func systemDNSQuery(ctx context.Context, name, typ string, timeout time.Duration) ([]DNSAnswer, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resolver := net.DefaultResolver
	out := make([]DNSAnswer, 0, 4)
	add := func(typeName string, value string) {
		id := dnsNameTypes[typeName]
		out = append(out, DNSAnswer{Name: name, Type: id, TypeName: typeName, Class: dnsClassIN, Value: value})
	}
	var err error
	note := ""
	switch typ {
	case "A", "AAAA":
		var ips []net.IPAddr
		ips, err = resolver.LookupIPAddr(ctx, name)
		if err == nil {
			for _, ip := range ips {
				if typ == "A" && ip.IP.To4() != nil {
					add("A", ip.IP.To4().String())
				} else if typ == "AAAA" && ip.IP.To4() == nil && ip.IP.To16() != nil {
					add("AAAA", ip.IP.String())
				}
			}
		}
	case "CNAME":
		var v string
		v, err = resolver.LookupCNAME(ctx, name)
		if err == nil && v != "" {
			add("CNAME", strings.TrimSuffix(v, "."))
		}
	case "MX":
		var mxs []*net.MX
		mxs, err = resolver.LookupMX(ctx, name)
		if err == nil {
			for _, mx := range mxs {
				add("MX", fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
			}
		}
	case "TXT":
		var txts []string
		txts, err = resolver.LookupTXT(ctx, name)
		if err == nil {
			for _, t := range txts {
				add("TXT", t)
			}
		}
	case "NS":
		var nss []*net.NS
		nss, err = resolver.LookupNS(ctx, name)
		if err == nil {
			for _, ns := range nss {
				add("NS", strings.TrimSuffix(ns.Host, "."))
			}
		}
	case "PTR":
		if net.ParseIP(name) == nil {
			note = "PTR 查询需要在“域名/IP”框中填写 IP 地址"
			break
		}
		var names []string
		names, err = resolver.LookupAddr(ctx, name)
		if err == nil {
			for _, n := range names {
				add("PTR", strings.TrimSuffix(n, "."))
			}
		}
	default:
		note = "系统解析器仅支持 A / AAAA / CNAME / MX / TXT / NS / PTR，其他类型请选择 DNS 直连或 DoH"
	}
	if err != nil {
		return nil, note, fmt.Errorf("系统 DNS 查询失败：%w", err)
	}
	return out, note, nil
}

// buildDNSQuery 构造标准 DNS 查询报文
func buildDNSQuery(name string, qtype uint16) ([]byte, error) {
	qname, err := encodeDNSName(name)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 12+len(qname)+4)
	id := make([]byte, 2)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("生成 DNS 报文 ID 失败：%w", err)
	}
	buf = append(buf, id...)
	buf = append(buf, 0x01, 0x00) // RD=1：期望递归查询
	buf = append(buf, 0x00, 0x01) // QDCOUNT=1
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, qname...)
	buf = append(buf, byte(qtype>>8), byte(qtype), 0x00, byte(dnsClassIN))
	return buf, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("域名含空标签：%s", name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("域名标签超过 63 字节：%s", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// reverseDNSName 将 IP 转换为 PTR 反查名（IPv4 in-addr.arpa / IPv6 ip6.arpa）
func reverseDNSName(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	chars := strings.Split(hex.EncodeToString(v6), "")
	for i, j := 0, len(chars)-1; i < j; i, j = i+1, j-1 {
		chars[i], chars[j] = chars[j], chars[i]
	}
	return strings.Join(chars, ".") + ".ip6.arpa"
}

// normalizeDNSServer 规范化 DNS 服务器地址，缺省端口 53
func normalizeDNSServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("DNS 服务器不能为空")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(s[:i])
		if scheme != "udp" && scheme != "tcp" {
			return "", fmt.Errorf("DNS 直连请填写 IP 或域名（可带端口），DoH 才使用 http(s) 地址")
		}
		s = s[i+3:]
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			return "", fmt.Errorf("DNS 服务器地址不合法：%s", s)
		}
		if _, e := strconv.Atoi(port); e != nil || port == "" {
			port = "53"
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
			return net.JoinHostPort(ip.String(), "53"), nil
		}
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
		return net.JoinHostPort(s, "53"), nil
	}
	if _, err := strconv.Atoi(s); err == nil {
		return "", fmt.Errorf("DNS 服务器地址不合法：%s", s)
	}
	return net.JoinHostPort(s, "53"), nil
}

// dnsExchangeDNS 通过 UDP（截断时自动重试 TCP）或 TCP 发送查询
func dnsExchangeDNS(ctx context.Context, server string, query []byte, timeout time.Duration, tcp bool) ([]byte, error) {
	addr, err := normalizeDNSServer(server)
	if err != nil {
		return nil, err
	}
	network := "udp"
	if tcp {
		network = "tcp"
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("连接 DNS 服务器 %s 失败：%w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if network == "udp" {
		if len(query) > 512 {
			return nil, fmt.Errorf("UDP 查询报文过大，请勾选 TCP 或改用 DoH")
		}
		if _, err := conn.Write(query); err != nil {
			return nil, fmt.Errorf("发送 DNS 查询失败：%w", err)
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("读取 DNS 响应失败：%w", err)
		}
		wire := buf[:n]
		if len(wire) >= 4 && wire[2]&0x02 != 0 { // TC 位：响应被截断，改用 TCP 重试
			return dnsExchangeDNS(ctx, server, query, timeout, true)
		}
		return wire, nil
	}

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	for sent := 0; sent < len(framed); {
		n, err := conn.Write(framed[sent:])
		if err != nil || n == 0 {
			if err == nil {
				err = fmt.Errorf("连接已关闭")
			}
			return nil, fmt.Errorf("发送 TCP DNS 查询失败：%w", err)
		}
		sent += n
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("读取 TCP DNS 响应长度失败：%w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > 65535 {
		return nil, fmt.Errorf("TCP DNS 响应长度非法：%d", n)
	}
	wire := make([]byte, n)
	if _, err := io.ReadFull(conn, wire); err != nil {
		return nil, fmt.Errorf("读取 TCP DNS 响应失败：%w", err)
	}
	return wire, nil
}

// dnsExchangeDoH 按 RFC 8484 通过 HTTP(S) 发送 DNS wire format 报文
func dnsExchangeDoH(ctx context.Context, endpoint string, query []byte, timeout time.Duration) ([]byte, error) {
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("DoH 服务器需为 http(s) 地址：%s", endpoint)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("DoH 请求构造失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", browserUA)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH 请求失败：%w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 DoH 响应失败：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d：%s", resp.StatusCode, shortText(string(body), 160))
	}
	return body, nil
}

func shortText(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

type parsedDNS struct {
	rcode      int
	flags      uint16
	truncated  bool
	answers    []DNSAnswer
	authority  []DNSAnswer
	additional []DNSAnswer
}

// parseDNSResponse 解析 DNS 响应报文（支持名称压缩指针）
func parseDNSResponse(msg []byte) (*parsedDNS, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("DNS 响应过短（%d 字节）", len(msg))
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	counts := [4]int{
		int(binary.BigEndian.Uint16(msg[4:6])),
		int(binary.BigEndian.Uint16(msg[6:8])),
		int(binary.BigEndian.Uint16(msg[8:10])),
		int(binary.BigEndian.Uint16(msg[10:12])),
	}
	off := 12
	for i := 0; i < counts[0]; i++ { // Question 段
		_, next, err := decodeDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+4 > len(msg) {
			return nil, fmt.Errorf("DNS Question 段截断")
		}
		off += 4
	}
	readRR := func() (DNSAnswer, error) {
		name, next, err := decodeDNSName(msg, off)
		if err != nil {
			return DNSAnswer{}, err
		}
		off = next
		if off+10 > len(msg) {
			return DNSAnswer{}, fmt.Errorf("DNS 资源记录头部截断")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		class := binary.BigEndian.Uint16(msg[off+2 : off+4])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if rdlen < 0 || off+rdlen > len(msg) {
			return DNSAnswer{}, fmt.Errorf("DNS 资源记录数据截断")
		}
		value := dnsRDATAText(msg, off, rdlen, typ, class)
		off += rdlen
		typeName := dnsTypeNames[typ]
		if typeName == "" {
			typeName = "TYPE" + strconv.Itoa(int(typ))
		}
		return DNSAnswer{Name: name, Type: typ, TypeName: typeName, Class: class, TTL: ttl, Value: value}, nil
	}
	readGroup := func(n int) ([]DNSAnswer, error) {
		out := make([]DNSAnswer, 0, n)
		for i := 0; i < n; i++ {
			rr, err := readRR()
			if err != nil {
				return nil, err
			}
			out = append(out, rr)
		}
		return out, nil
	}
	answers, err := readGroup(counts[1])
	if err != nil {
		return nil, err
	}
	authority, err := readGroup(counts[2])
	if err != nil {
		return nil, err
	}
	additional, err := readGroup(counts[3])
	if err != nil {
		return nil, err
	}
	return &parsedDNS{
		rcode:      int(flags & 0x000f),
		flags:      flags,
		truncated:  flags&0x0200 != 0,
		answers:    answers,
		authority:  authority,
		additional: additional,
	}, nil
}

// decodeDNSName 解码域名，返回名称与报文中的下一个偏移位置
func decodeDNSName(msg []byte, off int) (string, int, error) {
	if off < 0 || off >= len(msg) {
		return "", 0, fmt.Errorf("DNS 名称偏移越界")
	}
	var labels []string
	pos, end, jumps := off, -1, 0
	for {
		if pos >= len(msg) {
			return "", 0, fmt.Errorf("DNS 名称截断")
		}
		l := int(msg[pos])
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(msg) {
				return "", 0, fmt.Errorf("DNS 压缩指针截断")
			}
			ptr := int(l&0x3f)<<8 | int(msg[pos+1])
			if ptr >= len(msg) {
				return "", 0, fmt.Errorf("DNS 压缩指针越界")
			}
			if end < 0 {
				end = pos + 2
			}
			pos = ptr
			jumps++
			if jumps > 64 {
				return "", 0, fmt.Errorf("DNS 压缩指针循环")
			}
			continue
		}
		if l&0xc0 != 0 {
			return "", 0, fmt.Errorf("DNS 名称标签类型非法")
		}
		pos++
		if l == 0 {
			if end < 0 {
				end = pos
			}
			break
		}
		if pos+l > len(msg) {
			return "", 0, fmt.Errorf("DNS 名称标签截断")
		}
		labels = append(labels, string(msg[pos:pos+l]))
		pos += l
	}
	name := strings.Join(labels, ".")
	if name == "" {
		name = "."
	}
	return name, end, nil
}

// dnsRDATAText 将常见记录类型的 RDATA 转成可读文本
func dnsRDATAText(msg []byte, off, rdlen int, typ, class uint16) string {
	end := off + rdlen
	if end > len(msg) {
		return ""
	}
	fallback := func() string { return "0x" + hex.EncodeToString(msg[off:end]) }
	if typ == dnsTypeOPT {
		return fmt.Sprintf("UDP payload=%d", class)
	}
	nameAt := func(p int) (string, int) {
		name, next, err := decodeDNSName(msg, p)
		if err != nil {
			return "?", p
		}
		return name, next
	}
	switch typ {
	case dnsTypeA:
		if rdlen == 4 {
			return net.IP(msg[off:end]).String()
		}
	case dnsTypeAAAA:
		if rdlen == 16 {
			return net.IP(msg[off:end]).String()
		}
	case dnsTypeCNAME, dnsTypePTR, dnsTypeNS, 39: // CNAME / PTR / NS / DNAME
		name, _ := nameAt(off)
		return name
	case dnsTypeMX:
		if rdlen >= 3 {
			pref := binary.BigEndian.Uint16(msg[off : off+2])
			host, _ := nameAt(off + 2)
			return fmt.Sprintf("%d %s", pref, host)
		}
	case dnsTypeTXT:
		var parts []string
		for p := off; p < end; {
			l := int(msg[p])
			p++
			if p+l > end {
				break
			}
			parts = append(parts, string(msg[p:p+l]))
			p += l
		}
		return strings.Join(parts, " ")
	case dnsTypeSOA:
		mname, p := nameAt(off)
		rname, p := nameAt(p)
		if p+20 <= end {
			return fmt.Sprintf("%s %s serial=%d refresh=%d retry=%d expire=%d minimum=%d",
				mname, rname,
				binary.BigEndian.Uint32(msg[p:p+4]),
				binary.BigEndian.Uint32(msg[p+4:p+8]),
				binary.BigEndian.Uint32(msg[p+8:p+12]),
				binary.BigEndian.Uint32(msg[p+12:p+16]),
				binary.BigEndian.Uint32(msg[p+16:p+20]))
		}
	case dnsTypeSRV:
		if rdlen >= 7 {
			target, _ := nameAt(off + 6)
			return fmt.Sprintf("priority=%d weight=%d port=%d target=%s",
				binary.BigEndian.Uint16(msg[off:off+2]),
				binary.BigEndian.Uint16(msg[off+2:off+4]),
				binary.BigEndian.Uint16(msg[off+4:off+6]), target)
		}
	case dnsTypeCAA:
		if rdlen >= 2 {
			tagLen := int(msg[off+1])
			if 2+tagLen <= rdlen {
				return fmt.Sprintf("flag=%d tag=%s value=%s", msg[off],
					string(msg[off+2:off+2+tagLen]), string(msg[off+2+tagLen:end]))
			}
		}
	}
	return fallback()
}

func dnsRCODE(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return "RCODE" + strconv.Itoa(code)
	}
}
