package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// TraceHop 路由追踪的单个跃点
type TraceHop struct {
	TTL  int    `json:"ttl"`  // 第几跳
	Host string `json:"host"` // 节点 IP 或主机名；超时显示为 "请求超时"
	RTT  int64  `json:"rtt"`  // 往返耗时（毫秒），0 表示无响应
	Lost bool   `json:"lost"` // 该跃点是否无响应
}

// 允许的目标字符：仅 IP 或域名（禁止空格、引号、管道等注入字符）
var traceTargetRe = regexp.MustCompile(`^[a-zA-Z0-9.\-]{1,253}$`)

func isValidTraceTarget(s string) bool {
	if s == "" {
		return false
	}
	return traceTargetRe.MatchString(s)
}

// traceCommand 按平台选择路由追踪命令
func traceCommand(target string) *exec.Cmd {
	switch runtime.GOOS {
	case "windows":
		// -d 不做反向 DNS（更快更稳）；-w 超时 1000ms；-h 最多 30 跳
		return exec.Command("tracert", "-d", "-w", "1000", "-h", "30", target)
	case "darwin":
		return exec.Command("traceroute", "-n", "-w", "1", "-m", "30", target)
	default: // linux 等
		return exec.Command("traceroute", "-n", "-w", "1", "-m", "30", target)
	}
}

var (
	hopRe     = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	timeColRe = regexp.MustCompile(`^(?i)(\*|<1|\d+)\s*(?:ms)?\s+`)
)

// parseTraceLine 解析一行 traceroute 输出；不是跃点行则返回 ok=false
func parseTraceLine(line string) (TraceHop, bool) {
	m := hopRe.FindStringSubmatch(line)
	if m == nil {
		return TraceHop{}, false
	}
	ttl, err := strconv.Atoi(m[1])
	if err != nil {
		return TraceHop{}, false
	}
	rest := m[2]
	times := []int64{}
	for i := 0; i < 3; i++ { // 每跳通常 3 个探测列
		tm := timeColRe.FindStringSubmatch(rest)
		if tm == nil {
			break
		}
		rest = rest[len(tm[0]):]
		switch tm[1] {
		case "*":
			times = append(times, -1)
		case "<1":
			times = append(times, 1)
		default:
			if v, e := strconv.ParseInt(tm[1], 10, 64); e == nil {
				times = append(times, v)
			} else {
				times = append(times, -1)
			}
		}
	}

	host := strings.TrimSpace(rest)
	lost := len(times) > 0 && allNeg(times)
	if host == "" || strings.HasPrefix(host, "请求超时") || strings.Contains(host, "timed out") {
		host = "请求超时"
		lost = true
	}
	if lost {
		host = "请求超时"
	}

	var rtt int64
	for _, t := range times {
		if t > 0 && (rtt == 0 || t < rtt) {
			rtt = t
		}
	}
	return TraceHop{TTL: ttl, Host: host, RTT: rtt, Lost: lost}, true
}

func allNeg(t []int64) bool {
	for _, v := range t {
		if v > 0 {
			return false
		}
	}
	return true
}

// handleTrace SSE 实时推送路由追踪结果
func handleTrace(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if !isValidTraceTarget(target) {
		http.Error(w, "目标格式不合法（仅支持 IP 或域名，且不含空格及特殊符号）", http.StatusBadRequest)
		return
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

	cmd := traceCommand(target)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		emit("error", map[string]string{"message": "无法启动路由追踪：" + err.Error()})
		return
	}
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		emit("error", map[string]string{"message": "无法启动路由追踪：" + err.Error()})
		return
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	hops := 0
	for scanner.Scan() {
		hop, ok := parseTraceLine(scanner.Text())
		if !ok {
			continue
		}
		emit("hop", hop)
		hops++
	}
	cmd.Wait()

	if hops == 0 {
		emit("error", map[string]string{"message": "未解析到任何跃点，请确认目标可达（" + target + "）"})
		return
	}
	emit("done", map[string]int{"hops": hops})
}
