package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostResult 单个 IP 的探测结果
type HostResult struct {
	IP       string `json:"ip"`
	Online   bool   `json:"online"`
	Hostname string `json:"hostname"`
	MAC      string `json:"mac"`
	Vendor   string `json:"vendor"`
	Ports    []int  `json:"ports"`
	RTT      int64  `json:"rtt"`                // 毫秒
	Title    string `json:"title"`              // 开放 Web 端口时抓取的页面标题
	MS17     string `json:"ms17_010,omitempty"` // 445 端口开放时的 MS17-010 检测结果
}

// titleWebPorts 需要抓取页面标题的 Web 端口（HTTP 与 HTTPS）
var titleWebPorts = map[int]bool{80: true, 443: true, 8000: true, 8080: true, 8443: true}

// titleSem 限制同时进行的网页抓取数量，避免扫描时瞬时大量 HTTP 请求
var titleSem = make(chan struct{}, 16)

// titleClient 抓取页面标题用的 HTTP 客户端：
//   - 自动跟随重定向（含 80→https 等跳转），因此 80 端口跳转后的页面标题也能读到
//   - 跳过 TLS 证书校验（内网设备常使用自签名证书）
//   - 整体超时 1.5s
var titleClient = &http.Client{
	Timeout: 1500 * time.Millisecond,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// fetchTitle 对开放了 Web 端口的主机抓取首页 <title>
func fetchTitle(ip string, port int) string {
	if !titleWebPorts[port] {
		return ""
	}
	titleSem <- struct{}{}
	defer func() { <-titleSem }()

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	resp, err := titleClient.Get(fmt.Sprintf("%s://%s:%d/", scheme, ip, port))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	// 只读取前 64KB，避免大页面占用过多内存
	buf := new(bytes.Buffer)
	io.Copy(buf, io.LimitReader(resp.Body, 64*1024))
	// 提取 <title>...</title>，忽略大小写与换行；自动覆盖重定向后的最终页面
	m := regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`).FindStringSubmatch(buf.String())
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// ScanConfig 扫描参数
type ScanConfig struct {
	CIDR        string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	UsePing     bool
	MaxHosts    int
}

// ScanSummary 扫描汇总
type ScanSummary struct {
	Total   int   `json:"total"`
	Online  int   `json:"online"`
	Offline int   `json:"offline"`
	Elapsed int64 `json:"elapsed"` // 毫秒
	// Updates 扫描结束后用最新 ARP 表补全 MAC/厂商的在线主机，前端据此刷新已推送的结果
	Updates []HostResult      `json:"updates"`
	ARP     map[string]string `json:"arp"` // ip -> mac（扫描后刷新的 ARP 表）
}

// DefaultPorts 默认探测端口（局域网常见服务）
var DefaultPorts = []int{22, 80, 135, 139, 443, 445, 502, 1433, 3306, 3389, 5900, 8000, 8080, 8443}

// DefaultConcurrency 默认并发主机数（可经 URL 参数 concurrency 覆盖）
const DefaultConcurrency = 20

// maxPortWorkers 单主机内并行探测端口的上限，避免一次打开过多 socket
const maxPortWorkers = 8

// ---------- CIDR 展开 ----------

// expandCIDR 把 CIDR 展开为 IP 列表；跳过网络地址与广播地址
func expandCIDR(cidr string, maxHosts int) ([]netip.Addr, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, fmt.Errorf("网段不能为空")
	}
	// 单个 IP 自动补 /32
	if !strings.Contains(cidr, "/") {
		cidr = cidr + "/32"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("网段格式错误（示例：192.168.1.0/24）：%v", err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("暂不支持 IPv6 网段")
	}

	// 计算主机数
	bits := 32 - prefix.Bits()
	var total uint64 = 1 << uint(bits)
	if prefix.Bits() >= 31 {
		total = uint64(1 << uint(bits))
	}
	if int(total) > maxHosts {
		return nil, fmt.Errorf("网段过大（%d 个地址），超过上限 %d，请缩小网段范围", total, maxHosts)
	}

	var addrs []netip.Addr
	addr := prefix.Addr()
	// 对于 /31 /32 不跳过首尾
	skipEdge := prefix.Bits() <= 30 && total > 2
	first := true
	for {
		if !prefix.Contains(addr) {
			break
		}
		isLast := addr.String() == lastAddrOf(prefix).String()
		if !(skipEdge && (first || isLast)) {
			addrs = append(addrs, addr)
		}
		first = false
		next := addr.Next()
		if !next.IsValid() || next == addr {
			break
		}
		addr = next
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("网段内没有可扫描的地址")
	}
	return addrs, nil
}

// lastAddrOf 计算广播地址（网段最后一个地址）
func lastAddrOf(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	mask := net.CIDRMask(p.Bits(), 32)
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = a[i] | ^mask[i]
	}
	return netip.AddrFrom4(b)
}

// ---------- 探测 ----------

// probeTCP 尝试 TCP 连接，返回是否开放与耗时(ms)
func probeTCP(ip string, port int, timeout time.Duration) (bool, int64) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false, 0
	}
	conn.Close()
	return true, time.Since(start).Milliseconds()
}

// pingOnce 调用系统 ping 命令（跨平台），返回是否通
func pingOnce(ip string, timeoutMs int) bool {
	if timeoutMs < 200 {
		timeoutMs = 200
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), ip)
	case "darwin":
		cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutMs), ip)
	default: // linux：-W 单位为秒
		sec := timeoutMs / 1000
		if sec < 1 {
			sec = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(sec), ip)
	}
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	// 各语言环境下 "TTL=" 均不翻译，据此判断
	return strings.Contains(strings.ToUpper(string(out)), "TTL=")
}

// getHostname 反向 DNS 查询，带超时保护
func getHostname(ip string, timeout time.Duration) string {
	ch := make(chan string, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			ch <- strings.TrimSuffix(names[0], ".")
		} else {
			ch <- ""
		}
	}()
	select {
	case n := <-ch:
		return n
	case <-time.After(timeout):
		return ""
	}
}

// ---------- ARP ----------

var (
	ipRe  = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	macRe = regexp.MustCompile(`(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`)
)

// getARPTable 读取系统 ARP 缓存表 ip -> mac
func getARPTable() map[string]string {
	table := make(map[string]string)
	cmd := exec.Command("arp", "-a")
	if runtime.GOOS != "windows" {
		cmd = exec.Command("arp", "-n")
	}
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return table
	}
	for _, line := range strings.Split(string(out), "\n") {
		ip := ipRe.FindString(line)
		mac := macRe.FindString(line)
		if ip == "" || mac == "" {
			continue
		}
		// 排除广播/组播
		if mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		table[ip] = normalizeMAC(mac)
	}
	return table
}

func normalizeMAC(m string) string {
	return strings.ToLower(strings.ReplaceAll(m, "-", ":"))
}

// ---------- OUI 厂商库（常见设备，前 3 字节）----------

var ouiDB = map[string]string{
	// 虚拟化
	"00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
	"00:1c:42": "Parallels", "08:00:27": "Oracle VirtualBox", "00:15:5d": "Microsoft Hyper-V",
	// 树莓派 / 单板
	"b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
	// 网络厂商
	"00:e0:fc": "Huawei 华为", "4c:1f:cc": "Huawei 华为", "ac:4e:91": "Huawei 华为",
	"00:9a:cd": "Huawei 华为", "70:7b:e8": "Huawei 华为",
	"00:0f:e2": "H3C 华三", "3c:8c:40": "H3C 华三", "70:ba:ef": "H3C 华三", "80:f6:2e": "H3C 华三",
	"50:c7:bf": "TP-Link", "98:da:c4": "TP-Link", "b0:4e:26": "TP-Link", "14:cc:20": "TP-Link",
	"c0:25:e9": "TP-Link", "ec:08:6b": "TP-Link", "a4:2b:b0": "TP-Link", "30:b5:c2": "TP-Link",
	"00:1c:f0": "D-Link", "1c:7e:e5": "D-Link", "b8:a3:86": "D-Link",
	"00:1e:2a": "NETGEAR", "20:4e:7f": "NETGEAR", "a0:40:a0": "NETGEAR",
	"00:12:17": "ASUS 华硕", "04:92:26": "ASUS 华硕", "2c:fd:a1": "ASUS 华硕", "ac:9e:17": "ASUS 华硕",
	// 小米 / 国产手机 IoT
	"8c:be:be": "Xiaomi 小米", "64:b4:73": "Xiaomi 小米", "28:6c:07": "Xiaomi 小米",
	"78:11:dc": "Xiaomi 小米", "0c:1d:af": "Xiaomi 小米", "34:ce:00": "Xiaomi 小米",
	"98:fa:9b": "Xiaomi 小米", "d4:97:0b": "Xiaomi 小米", "50:8f:4c": "Xiaomi 小米",
	// 苹果
	"00:1e:c2": "Apple", "3c:15:c2": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
	"00:23:12": "Apple", "14:10:9f": "Apple", "ac:bc:32": "Apple", "8c:85:90": "Apple",
	// Intel / 网卡
	"00:1b:77": "Intel", "3c:a9:f4": "Intel", "a4:34:d9": "Intel", "00:24:d7": "Intel",
	"8c:16:45": "Intel", "68:5b:35": "Intel",
	"00:e0:4c": "Realtek", "52:54:00": "Realtek/QEMU", "00:d8:61": "Realtek",
	// 安防监控
	"44:19:b6": "Hikvision 海康威视", "4c:bd:8f": "Hikvision 海康威视",
	"c0:56:27": "Hikvision 海康威视", "54:c4:15": "Hikvision 海康威视", "b4:a3:82": "Hikvision 海康威视",
	"3c:ef:8c": "Dahua 大华", "40:3f:8c": "Dahua 大华", "e0:50:8b": "Dahua 大华", "a0:bd:1d": "Dahua 大华",
	// 服务器/PC 厂商
	"00:14:22": "Dell 戴尔", "18:03:73": "Dell 戴尔", "f4:8e:38": "Dell 戴尔",
	"00:1e:0b": "HP 惠普", "3c:d9:2b": "HP 惠普", "94:57:a5": "HP 惠普",
	"00:1b:fc": "Lenovo 联想", "54:ee:75": "Lenovo 联想", "8c:16:45:00": "Lenovo 联想",
	"00:19:c6": "ZTE 中兴", "4c:54:99": "ZTE 中兴",
	"00:12:47": "Samsung 三星", "5c:0a:5b": "Samsung 三星", "8c:77:12": "Samsung 三星",
	// 工业/物联网
	"00:0e:cf": "Siemens 西门子", "00:1b:1b": "Siemens 西门子",
	"00:80:f4": "Beckhoff 倍福", "00:30:de": "Beckhoff 倍福",
	"00:0e:8f": "Moxa 摩莎", "00:0f:8f": "Moxa 摩莎",
}

// vendorOf 根据 MAC 前 3 字节识别厂商
func vendorOf(mac string) string {
	if mac == "" {
		return ""
	}
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	if v, ok := ouiDB[strings.Join(parts[:3], ":")]; ok {
		return v
	}
	return ""
}

// ---------- 本机网卡 / IP 枚举 ----------

// IfaceInfo 一张网卡上的一个 IPv4 地址
type IfaceInfo struct {
	Name string `json:"name"` // 网卡名
	IP   string `json:"ip"`   // IPv4 地址
	Mask string `json:"mask"` // 点分掩码，如 255.255.255.0
	Bits int    `json:"bits"` // 掩码位数，如 24
	CIDR string `json:"cidr"` // 该地址所属网段，如 192.168.1.0/24
	MAC  string `json:"mac"`
	Kind string `json:"kind"` // 有线 / 无线 / 虚拟 / 回环 / 其他
}

// ListLocalIfaces 列出本机全部处于 UP 状态的 IPv4 地址（回环排在最后）
func ListLocalIfaces() []IfaceInfo {
	var out []IfaceInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue // 暂不支持 IPv6
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 || ones > 32 {
				continue
			}
			netIP := ip4.Mask(ipnet.Mask)
			out = append(out, IfaceInfo{
				Name: ifc.Name,
				IP:   ip4.String(),
				Mask: net.IP(ipnet.Mask).String(),
				Bits: ones,
				CIDR: fmt.Sprintf("%s/%d", netIP.String(), ones),
				MAC:  normalizeMAC(ifc.HardwareAddr.String()),
				Kind: classifyIface(ifc, ip4),
			})
		}
	}

	// 排序：真实网络在前（有线→无线→虚拟→其他），回环最后
	rank := map[string]int{"有线": 0, "无线": 1, "虚拟": 2, "其他": 3, "回环": 9}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank[out[i].Kind], rank[out[j].Kind]
		if ri != rj {
			return ri < rj
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// classifyIface 依据网卡名与地址特征判断类型
func classifyIface(ifc net.Interface, ip net.IP) string {
	switch {
	case ifc.Flags&net.FlagLoopback != 0 || ip.IsLoopback():
		return "回环"
	}
	n := strings.ToLower(ifc.Name)
	virtualKeys := []string{
		"vmware", "virtualbox", "vbox", "vmnet", "hyper-v", "vethernet", "virtual",
		"tap-", "tap_", "tun", "wsl", "docker", "loopback", "pseudo", "npcap",
		"sangfor", "easyconnect", "vpn", "fortinet", "anyconnect", "zerotier",
		"hamachi", "tailscale", "et_",
	}
	for _, k := range virtualKeys {
		if strings.Contains(n, k) {
			return "虚拟"
		}
	}
	wirelessKeys := []string{"wlan", "wi-fi", "wifi", "wireless", "无线", "wlp", "ath"}
	for _, k := range wirelessKeys {
		if strings.Contains(n, k) {
			return "无线"
		}
	}
	if strings.HasPrefix(n, "eth") || strings.HasPrefix(n, "en") ||
		strings.HasPrefix(n, "以太网") || strings.HasPrefix(n, " ethernet") {
		return "有线"
	}
	return "其他"
}

// guessLocalCIDR 推测最适合扫描的本机网段
// 优先 192.168 → 10.x → 172.16-31.x；掩码长于 /24 时统一按 /24 返回，便于整段扫描
func guessLocalCIDR() string {
	candidates := map[int]string{} // 优先级 -> cidr
	for _, it := range ListLocalIfaces() {
		if it.Kind == "回环" {
			continue
		}
		ip := net.ParseIP(it.IP).To4()
		if ip == nil {
			continue
		}
		prefix := it.CIDR
		if it.Bits > 24 { // /25~/32 太窄，统一放大到 /24 便于整段扫描
			prefix = fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
		}
		switch {
		case ip[0] == 192 && ip[1] == 168:
			if _, ok := candidates[1]; !ok {
				candidates[1] = prefix
			}
		case ip[0] == 10:
			if _, ok := candidates[2]; !ok {
				candidates[2] = prefix
			}
		case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
			if _, ok := candidates[3]; !ok {
				candidates[3] = prefix
			}
		}
	}
	for _, pri := range []int{1, 2, 3} {
		if c, ok := candidates[pri]; ok {
			return c
		}
	}
	// 没有私有地址时退回第一个非回环网段
	for _, it := range ListLocalIfaces() {
		if it.Kind != "回环" {
			return it.CIDR
		}
	}
	return "192.168.1.0/24"
}

// ---------- 扫描主体 ----------

// probeHost 探测单个主机
// 说明：cfg.Concurrency 表示"同时探测的主机数"；同一主机的多个端口内部再并行，
// 这样并发 20 时不会因为串行探测 10 个端口而把单主机耗时放大 10 倍。
func probeHost(ip string, cfg ScanConfig, arpCache map[string]string) HostResult {
	res := HostResult{IP: ip, Ports: []int{}}

	type portResult struct {
		port int
		ok   bool
		rtt  int64
	}

	has445 := false
	if len(cfg.Ports) > 0 {
		ch := make(chan portResult, len(cfg.Ports))
		sem := make(chan struct{}, maxPortWorkers)
		for _, p := range cfg.Ports {
			go func(port int) {
				sem <- struct{}{}
				defer func() { <-sem }()
				ok, rtt := probeTCP(ip, port, cfg.Timeout)
				ch <- portResult{port, ok, rtt}
			}(p)
		}
		for i := 0; i < len(cfg.Ports); i++ {
			pr := <-ch
			if pr.ok {
				res.Online = true
				res.Ports = append(res.Ports, pr.port)
				if pr.port == ms17Port {
					has445 = true
				}
				if res.RTT == 0 || pr.rtt < res.RTT {
					res.RTT = pr.rtt
				}
				// 开放了 Web 端口则抓取页面标题
				if titleWebPorts[pr.port] {
					if t := fetchTitle(ip, pr.port); t != "" {
						res.Title = t
					}
				}
			}
		}
		sort.Ints(res.Ports)
	}

	// 1.1 445 开放时检测 MS17-010（永恒之蓝）
	if has445 {
		res.MS17 = checkMS17_010(context.Background(), ip, cfg.Timeout)
	}

	// 2. ICMP ping（未在 TCP 上发现时补充）
	if cfg.UsePing && !res.Online {
		t0 := time.Now()
		if pingOnce(ip, int(cfg.Timeout.Milliseconds())) {
			res.Online = true
			if res.RTT == 0 {
				res.RTT = time.Since(t0).Milliseconds()
			}
		}
	}

	// 3. 在线主机补充主机名与 MAC
	if res.Online {
		res.Hostname = getHostname(ip, 700*time.Millisecond)
		if m, ok := arpCache[ip]; ok {
			res.MAC = m
			res.Vendor = vendorOf(m)
		}
	}
	return res
}

// Scan 执行扫描；每完成一个主机就通过 emit 串行回调
func Scan(cfg ScanConfig, emit func(HostResult)) (*ScanSummary, error) {
	addrs, err := expandCIDR(cfg.CIDR, cfg.MaxHosts)
	if err != nil {
		return nil, err
	}

	arpCache := getARPTable() // 预热：已有的 ARP 记录

	jobs := make(chan netip.Addr, len(addrs))
	for _, a := range addrs {
		jobs <- a
	}
	close(jobs)

	results := make(chan HostResult, len(addrs))
	var wg sync.WaitGroup
	workers := cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(addrs) {
		workers = len(addrs)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				results <- probeHost(addr.String(), cfg, arpCache)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	start := time.Now()
	online := 0
	var onlineHosts []HostResult
	// 主协程串行推送，保证 SSE 写入安全
	for r := range results {
		if r.Online {
			online++
			onlineHosts = append(onlineHosts, r)
		}
		emit(r)
	}
	elapsed := time.Since(start).Milliseconds()

	// 探测完成后 ARP 表已更新，据此补全 MAC 与厂商（探测当时表里可能还没有）
	finalARP := getARPTable()
	for i := range onlineHosts {
		if onlineHosts[i].MAC == "" {
			if m, ok := finalARP[onlineHosts[i].IP]; ok {
				onlineHosts[i].MAC = m
				onlineHosts[i].Vendor = vendorOf(m)
			}
		}
	}

	return &ScanSummary{
		Total:   len(addrs),
		Online:  online,
		Offline: len(addrs) - online,
		Elapsed: elapsed,
		Updates: onlineHosts,
		ARP:     finalARP,
	}, nil
}
