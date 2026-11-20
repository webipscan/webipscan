package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- 指定主机端口扫描 ----------

// PortScanConfig 端口扫描参数
type PortScanConfig struct {
	Hosts       []string // 目标（IP 或域名，已去重）
	Ports       []int    // 待扫描端口
	Timeout     time.Duration
	Concurrency int
}

// Target 解析后的目标：原始输入 + IPv4
type Target struct {
	Name string `json:"name"` // 用户输入（IP 或域名）
	IP   string `json:"ip"`   // 解析得到的 IPv4
}

// PortScanItem 一个开放端口
type PortScanItem struct {
	Host    string `json:"host"` // 目标原始输入
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	RTT     int64  `json:"rtt"`                // 毫秒
	Banner  string `json:"banner"`             // 服务横幅 / 页面标题
	MS17    string `json:"ms17_010,omitempty"` // 445 端口开放时的 MS17-010 检测结果
}

// portServiceNames 常见端口对应的服务名（未收录的显示为空）
var portServiceNames = map[int]string{
	7: "echo", 9: "discard", 13: "daytime", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 37: "time", 43: "whois", 53: "dns", 67: "dhcp", 69: "tftp", 79: "finger",
	80: "http", 81: "http-alt", 88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp",
	135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
	161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc", 389: "ldap", 443: "https",
	445: "smb", 465: "smtps", 500: "isakmp", 502: "modbus", 512: "exec", 513: "login",
	514: "syslog", 515: "lpd", 520: "rip", 548: "afp", 554: "rtsp", 587: "submission",
	593: "http-rpc", 623: "ipmi", 631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware",
	989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s", 1025: "nfs-or-msrpc",
	1080: "socks", 1099: "rmi", 1433: "mssql", 1434: "mssql-browser", 1521: "oracle",
	1701: "l2tp", 1723: "pptp", 1883: "mqtt", 1900: "upnp", 2049: "nfs", 2082: "cpanel",
	2083: "cpanel-https", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
	2376: "docker-tls", 2379: "etcd", 3000: "grafana/node", 3128: "squid", 3260: "iscsi",
	3306: "mysql", 3389: "rdp", 3690: "svn", 4444: "metasploit", 4505: "salt-master",
	4506: "salt-minion", 5000: "upnp/http", 5432: "postgresql", 5555: "adb",
	5601: "kibana", 5672: "rabbitmq", 5900: "vnc", 5901: "vnc-1", 5985: "winrm-http",
	5986: "winrm-https", 6000: "x11", 6379: "redis", 6443: "k8s-api", 7001: "weblogic",
	7002: "weblogic-ssl", 8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
	8081: "http-alt", 8088: "http-alt", 8161: "activemq", 8443: "https-alt",
	8888: "http-alt", 9000: "cslistener", 9001: "tor-or-http", 9042: "cassandra",
	9090: "http-alt", 9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
	9300: "elasticsearch", 10000: "webmin", 10250: "kubelet", 11211: "memcached",
	27017: "mongodb", 27018: "mongodb", 50000: "db2", 61616: "activemq",
}

func serviceOf(port int) string { return portServiceNames[port] }

// webScanPorts 端口扫描时额外抓取 HTTP 页面标题的端口
var webScanPorts = map[int]bool{
	80: true, 81: true, 443: true, 8080: true, 8081: true, 8088: true,
	8000: true, 8008: true, 8443: true, 8888: true, 9000: true, 9090: true,
	10000: true,
}

// top100Ports 常用端口集（"top100" / "common"）
var top100Ports = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
	139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
	554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
	1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
	4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
	6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9999,
	10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
}

// ParsePortSpec 解析端口表达式，支持：
//
//	1-65535 / full / all       完整 65535 个端口
//	top100 / common            常用端口集
//	22,80,443                  端口列表
//	1-1024,3306,8080           端口段 + 列表
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" || spec == "top100" || spec == "common" {
		out := append([]int(nil), top100Ports...)
		sort.Ints(out)
		return out, nil
	}
	if spec == "full" || spec == "all" || spec == "1-65535" {
		out := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			out = append(out, p)
		}
		return out, nil
	}

	seen := make(map[int]bool)
	var out []int
	add := func(p int) {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(strings.ReplaceAll(spec, " ", ","), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			a, err1 := strconv.Atoi(strings.TrimSpace(part[:i]))
			b, err2 := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("端口范围无效：%s（应为 1-65535，如 1-1024）", part)
			}
			for p := a; p <= b; p++ {
				add(p)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("端口无效：%s（应为 1-65535 的数字）", part)
		}
		add(p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有可扫描的端口")
	}
	sort.Ints(out)
	return out, nil
}

// ResolveTargets 把用户输入（IP 或域名，支持逗号/空格/分号分隔）解析为 IPv4 列表
func ResolveTargets(input string) ([]Target, error) {
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == '，' || r == ';' || r == '；' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	var out []Target
	seen := make(map[string]bool)
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !isValidHostInput(f) {
			return nil, fmt.Errorf("目标格式不合法：%s（仅支持 IP 或域名）", f)
		}
		if ip := net.ParseIP(f); ip != nil {
			v4 := ip.To4()
			if v4 == nil {
				return nil, fmt.Errorf("暂不支持 IPv6：%s", f)
			}
			if !seen[f] {
				seen[f] = true
				out = append(out, Target{Name: f, IP: v4.String()})
			}
			continue
		}
		ips := lookupIPv4(f, 3*time.Second)
		if len(ips) == 0 {
			return nil, fmt.Errorf("域名解析失败：%s", f)
		}
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, Target{Name: f, IP: ip})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("请填写目标 IP 或域名")
	}
	if len(out) > 16 {
		return nil, fmt.Errorf("目标过多（%d 个），一次最多 16 个地址", len(out))
	}
	return out, nil
}

// isValidHostInput 校验输入只含 IP / 域名允许的字符，避免命令或 URL 注入
func isValidHostInput(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == '.' || r == '-' || r == '_' || r == ':':
		default:
			return false
		}
	}
	return true
}

// lookupIPv4 域名解析（带超时），去重并保持顺序
func lookupIPv4(host string, timeout time.Duration) []string {
	type res struct{ ips []string }
	ch := make(chan res, 1)
	go func() {
		addrs, err := net.LookupIP(host)
		if err != nil {
			ch <- res{}
			return
		}
		var ips []string
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				ips = append(ips, v4.String())
			}
		}
		ch <- res{ips}
	}()
	select {
	case r := <-ch:
		return r.ips
	case <-time.After(timeout):
		return nil
	}
}

// probeOnePort 探测单个端口；返回 RTT、是否开放、横幅/标题
func probeOnePort(ip string, port int, timeout time.Duration) (int64, bool, string) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, false, ""
	}
	rtt := time.Since(start).Milliseconds()
	// 标准 Web 端口（含 TLS）：走 HTTP 客户端抓页面标题，更直观
	if titleWebPorts[port] {
		conn.Close()
		if t := fetchTitle(ip, port); t != "" {
			return rtt, true, "标题：" + t
		}
		return rtt, true, ""
	}
	// 其他 Web 端口：手工发一个 HTTP/1.0 请求取标题
	if webScanPorts[port] {
		_ = conn.SetDeadline(time.Now().Add(bannerTimeout(timeout)))
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n", ip, port, browserUA)
		data, _ := io.ReadAll(io.LimitReader(conn, 4096))
		conn.Close()
		if m := titleRe.FindStringSubmatch(string(data)); len(m) > 1 {
			if t := strings.TrimSpace(m[1]); t != "" {
				return rtt, true, "标题：" + t
			}
		}
		return rtt, true, ""
	}
	// 其他端口：短读一次服务横幅（SSH/SMTP/FTP/Redis 等会主动问候）
	_ = conn.SetReadDeadline(time.Now().Add(bannerTimeout(timeout)))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	if n <= 0 {
		return rtt, true, ""
	}
	return rtt, true, sanitizeBanner(buf[:n])
}

// titleRe 从 HTTP 响应中提取 <title>
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

// bannerTimeout 横幅读取超时：不超过用户设定超时，且最多 800ms
func bannerTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > 800*time.Millisecond {
		return 800 * time.Millisecond
	}
	return timeout
}

// sanitizeBanner 清理横幅中的不可打印字符，压缩空白并截断
func sanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			sb.WriteByte(' ')
		case c >= 32 && c < 127:
			sb.WriteByte(c)
		case c >= 0x80:
			sb.WriteByte(c) // 保留 UTF-8 字节
		}
	}
	s := strings.Join(strings.Fields(sb.String()), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// ScanPorts 对一组目标执行端口扫描。
// onOpen 每发现一个开放端口回调一次；onProgress 用于上报进度（done/total）。
func ScanPorts(ctx context.Context, cfg PortScanConfig, onOpen func(PortScanItem), onProgress func(done, total int)) error {
	total := len(cfg.Hosts) * len(cfg.Ports)
	if total == 0 {
		return fmt.Errorf("没有可扫描的目标端口")
	}

	jobs := make(chan PortScanItem, 1024)
	go func() {
		defer close(jobs)
		for _, h := range cfg.Hosts {
			for _, p := range cfg.Ports {
				select {
				case jobs <- PortScanItem{Host: h, Port: p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	workers := cfg.Concurrency
	if workers < 1 {
		workers = 200
	}
	if workers > 2000 {
		workers = 2000
	}
	if workers > total {
		workers = total
	}

	type found struct {
		item PortScanItem
		ok   bool
		done int // >0 表示这是一条进度事件
	}
	results := make(chan found, workers)
	var wg sync.WaitGroup
	var done int64
	reportStep := total / 100
	if reportStep < 20 {
		reportStep = 20
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				ip := job.IP
				if ip == "" {
					ip = job.Host
				}
				rtt, ok, banner := probeOnePort(ip, job.Port, cfg.Timeout)
				n := int(atomic.AddInt64(&done, 1))
				var ms17 string
				if ok && job.Port == ms17Port && ctx.Err() == nil {
					ms17 = checkMS17_010(ctx, ip, cfg.Timeout)
				}
				select {
				case results <- found{item: PortScanItem{
					Host: job.Host, IP: ip, Port: job.Port,
					Service: serviceOf(job.Port), RTT: rtt, Banner: banner, MS17: ms17,
				}, ok: ok}:
				case <-ctx.Done():
					return
				}
				// 进度采样：按比例上报，避免每完成一个端口就回调
				if n == total || n%reportStep == 0 {
					select {
					case results <- found{done: n}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	// 结果与进度在同一个协程内串行回调，保证 SSE 写入安全
	last := 0
	for f := range results {
		if f.done > 0 {
			if onProgress != nil && f.done != last {
				last = f.done
				onProgress(f.done, total)
			}
			continue
		}
		if f.ok && onOpen != nil {
			onOpen(f.item)
		}
	}
	if onProgress != nil && last < total {
		onProgress(total, total)
	}
	return nil
}

// handlePortScan SSE 实时推送指定主机的端口扫描结果
func handlePortScan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	ports, err := ParsePortSpec(q.Get("ports"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	targets, err := ResolveTargets(q.Get("host"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	timeout := 500 * time.Millisecond
	if t := q.Get("timeout"); t != "" {
		if ms, e := strconv.Atoi(t); e == nil && ms > 0 && ms <= 10000 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}
	concurrency := 500
	if c := q.Get("concurrency"); c != "" {
		if n, e := strconv.Atoi(c); e == nil && n > 0 && n <= 2000 {
			concurrency = n
		}
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "当前连接不支持流式响应", http.StatusInternalServerError)
		return
	}
	emit := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(b))
		flusher.Flush()
	}

	hosts := make([]string, 0, len(targets))
	for _, t := range targets {
		hosts = append(hosts, t.IP)
	}
	emit("start", map[string]interface{}{
		"targets":  targets,
		"ports":    len(ports),
		"total":    len(targets) * len(ports),
		"portSpec": q.Get("ports"),
	})

	cfg := PortScanConfig{Hosts: hosts, Ports: ports, Timeout: timeout, Concurrency: concurrency}
	open := 0
	start := time.Now()
	err = ScanPorts(r.Context(), cfg,
		func(item PortScanItem) {
			open++
			// 把 IP 映射回用户输入的原始目标，便于前端展示
			for _, t := range targets {
				if t.IP == item.IP {
					item.Host = t.Name
					break
				}
			}
			emit("port", item)
		},
		func(done, total int) {
			emit("progress", map[string]int{"done": done, "total": total})
		},
	)
	if err != nil {
		emit("error", map[string]string{"message": err.Error()})
		return
	}
	emit("done", map[string]interface{}{
		"open":    open,
		"total":   len(targets) * len(ports),
		"elapsed": time.Since(start).Milliseconds(),
	})
}
