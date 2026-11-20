package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NatResult NAT 类型检测结果
type NatResult struct {
	Server     string `json:"server"`
	Peer       string `json:"peer"`       // 辅助 STUN 服务器（不同 IP）
	NatType    string `json:"natType"`
	LocalAddr  string `json:"localAddr"`
	Mapped1    string `json:"mapped1"`    // Test I：主端口映射
	Mapped2    string `json:"mapped2"`    // Test II：请求换 IP/端口后
	Mapped3    string `json:"mapped3"`    // Test III：备用端口映射
	MappedPeer string `json:"mappedPeer"` // Test IV：另一台不同 IP 服务器的映射
	TestI      bool   `json:"testI"`
	TestII     bool   `json:"testII"`
	TestIII    bool   `json:"testIII"`
	TestPeer   bool   `json:"testPeer"`
	Note       string `json:"note"`
}

// STUN 常量
const (
	stunMagic     = 0x2112A442
	stunBindReq   = 0x0001
	stunBindResp  = 0x0101
	attrXorMapped = 0x0020
	attrMapped    = 0x0001
	attrChangeReq = 0x0003

	stunTimeout = 3500 * time.Millisecond
)

var stunServerRe = regexp.MustCompile(`^[a-zA-Z0-9.\-]+:\d{1,5}$`)

// handleNat SSE 推送 NAT 类型检测结果
func handleNat(w http.ResponseWriter, r *http.Request) {
	server := strings.TrimSpace(r.URL.Query().Get("server"))
	if !stunServerRe.MatchString(server) {
		http.Error(w, "STUN 服务格式不合法（应为 host:port）", http.StatusBadRequest)
		return
	}
	peer := strings.TrimSpace(r.URL.Query().Get("peer"))
	if peer != "" && !stunServerRe.MatchString(peer) {
		http.Error(w, "辅助 STUN 服务格式不合法（应为 host:port）", http.StatusBadRequest)
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

	res, err := detectNAT(r.Context(), server, peer)
	if err != nil {
		emit("error", map[string]string{"message": err.Error()})
		return
	}
	emit("result", res)
	emit("done", map[string]int{})
}

// detectNAT 依据 RFC 5780 行为测试判定 NAT 类型。
// peer 为可选的另一台不同 IP 的 STUN 服务器：多数国内公共 STUN 不提供
// CHANGE-REQUEST / 备用端口，借助第二台服务器对比映射端口才能可靠识别对称型 NAT。
func detectNAT(ctx context.Context, server, peer string) (*NatResult, error) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("STUN 服务地址解析失败")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("STUN 端口不合法")
	}
	// RFC 5780 备用端口通常为 3479；其余按 +1 试探
	altPort := 3479
	if port != 3478 {
		altPort = port + 1
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("无法创建 UDP 套接字：%v", err)
	}
	defer conn.Close()

	primAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, fmt.Errorf("无法解析 STUN 服务：%v", err)
	}
	var altAddr *net.UDPAddr
	if a, e := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, altPort)); e == nil {
		altAddr = a
	}
	// 辅助服务器：与主服务器不同 IP，用于对称型判定
	var peerAddr *net.UDPAddr
	if peer != "" && peer != server {
		if a, e := net.ResolveUDPAddr("udp", peer); e == nil {
			peerAddr = a
		}
	}

	res := &NatResult{Server: server, Peer: peer, LocalAddr: conn.LocalAddr().String()}

	// Test I：主端口基础映射
	m1, ok := stunProbe(ctx, conn, primAddr, false, false)
	res.Mapped1, res.TestI = addrStr(m1), ok
	if !ok {
		res.NatType = "UDP 被阻断 / 无响应"
		res.Note = "未收到 STUN 服务器任何响应，可能 UDP 出站被防火墙拦截。"
		return res, nil
	}

	// 本地地址与映射地址一致 → 不在 NAT 之后
	if sameIP(conn.LocalAddr(), m1) {
		res.NatType = "开放互联网（无 NAT）"
		res.Note = "本地地址与映射地址一致，未在 NAT 之后。"
		return res, nil
	}

	// Test IV：向另一台不同 IP 的 STUN 服务器发送请求（复用同一本地端口）。
	// 对称型 NAT 会为目的地址分配新的映射端口，这是最可靠的对称型判据，
	// 且不依赖服务器支持 CHANGE-REQUEST / 备用端口，适合国内公共 STUN。
	var mp *net.UDPAddr
	okPeer := false
	if peerAddr != nil {
		mp, okPeer = stunProbe(ctx, conn, peerAddr, false, false)
	}
	res.MappedPeer, res.TestPeer = addrStr(mp), okPeer
	if okPeer && !sameMapped(m1, mp) {
		res.NatType = "对称型 NAT (Symmetric)"
		res.Note = "访问不同目的 IP 时映射端口发生变化。"
		return res, nil
	}

	// Test II：请求服务器从另一 IP/端口回复（CHANGE-REQUEST）
	m2, ok2 := stunProbe(ctx, conn, primAddr, true, true)
	res.Mapped2, res.TestII = addrStr(m2), ok2

	// Test III：发送到备用端口
	var m3 *net.UDPAddr
	ok3 := false
	if altAddr != nil {
		m3, ok3 = stunProbe(ctx, conn, altAddr, false, false)
	}
	res.Mapped3, res.TestIII = addrStr(m3), ok3

	switch {
	case ok3 && !sameMapped(m1, m3):
		res.NatType = "对称型 NAT (Symmetric)"
		res.Note = "不同服务器端口得到不同映射地址。"
	case ok2:
		res.NatType = "全锥型 NAT (Full Cone)"
		res.Note = "改变服务器地址/端口仍可收到响应。"
	case ok3:
		res.NatType = "限制锥型 NAT (Restricted Cone)"
		res.Note = "改变服务器端口仍可收到响应，但改变地址不可。"
	case okPeer:
		res.NatType = "锥型 NAT (Cone)"
		res.Note = "不同目的 IP 下映射端口保持一致；该服务不支持 CHANGE-REQUEST，无法进一步区分全锥/限制锥/端口限制锥。"
	default:
		res.NatType = "端口限制锥型 NAT (Port Restricted Cone)"
		res.Note = "改变服务器端口/地址均收不到响应。"
	}
	if !ok3 && !okPeer {
		res.Note += "（该 STUN 服务可能不支持 RFC5780 备用端口，且未配置辅助服务器，结论仅供参考）"
	}
	return res, nil
}

// stunProbe 发送一次 STUN 请求并等待首个绑定响应，返回映射地址
func stunProbe(ctx context.Context, conn *net.UDPConn, dst *net.UDPAddr, changeIP, changePort bool) (*net.UDPAddr, bool) {
	msg := buildStunRequest(changeIP, changePort)
	tid := msg[8:20]
	_ = conn.SetWriteDeadline(time.Now().Add(stunTimeout))
	if _, err := conn.WriteToUDP(msg, dst); err != nil {
		return nil, false
	}
	buf := make([]byte, 1500)
	_ = conn.SetReadDeadline(time.Now().Add(stunTimeout))
	for {
		select {
		case <-ctx.Done():
			return nil, false
		default:
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, false
		}
		// parseStunMapped 会校验事务 ID，自动忽略前一次测试迟到的响应
		if a, ok := parseStunMapped(buf[:n], tid); ok {
			return a, true
		}
	}
}

// buildStunRequest 构造 STUN Binding 请求；可选附加 CHANGE-REQUEST 属性
func buildStunRequest(changeIP, changePort bool) []byte {
	tid := make([]byte, 12)
	rand.Read(tid)
	var attr []byte
	if changeIP || changePort {
		val := uint32(0)
		if changeIP {
			val |= 0x00000001
		}
		if changePort {
			val |= 0x00000002
		}
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, val)
		attr = append(attr, 0x00, 0x03, 0x00, 0x04)
		attr = append(attr, v...)
	}
	msg := make([]byte, 20+len(attr))
	binary.BigEndian.PutUint16(msg[0:2], stunBindReq)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagic)
	copy(msg[8:20], tid)
	copy(msg[20:], attr)
	return msg
}

// parseStunMapped 解析 STUN 响应中的（XOR-）MAPPED-ADDRESS，仅支持 IPv4。
// tid 为本次请求的事务 ID；不匹配则忽略，避免复用同一 socket 时串包。
func parseStunMapped(b []byte, tid []byte) (*net.UDPAddr, bool) {
	if len(b) < 20 {
		return nil, false
	}
	if binary.BigEndian.Uint16(b[0:2]) != stunBindResp {
		return nil, false
	}
	if !bytes.Equal(b[8:20], tid) {
		return nil, false
	}
	off := 20
	for off+4 <= len(b) {
		attrType := binary.BigEndian.Uint16(b[off : off+2])
		attrLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+attrLen > len(b) {
			break
		}
		val := b[off+4 : off+4+attrLen]
		if (attrType == attrXorMapped || attrType == attrMapped) && attrLen >= 8 && val[1] == 0x01 {
			var ip net.IP
			var port uint16
			if attrType == attrXorMapped {
				port = binary.BigEndian.Uint16(val[2:4]) ^ uint16(stunMagic>>16)
				mc := uint32(stunMagic)
				xip := make([]byte, 4)
				for i := 0; i < 4; i++ {
					xip[i] = val[4+i] ^ byte(mc>>(uint(24-i*8)))
				}
				ip = net.IPv4(xip[0], xip[1], xip[2], xip[3])
			} else {
				port = binary.BigEndian.Uint16(val[2:4])
				ip = net.IPv4(val[4], val[5], val[6], val[7])
			}
			return &net.UDPAddr{IP: ip, Port: int(port)}, true
		}
		off = off + 4 + attrLen
		if rem := attrLen % 4; rem != 0 {
			off += 4 - rem
		}
	}
	return nil, false
}

func addrStr(a *net.UDPAddr) string {
	if a == nil {
		return "-"
	}
	return a.IP.String() + ":" + strconv.Itoa(a.Port)
}

func sameIP(local net.Addr, a *net.UDPAddr) bool {
	if a == nil || local == nil {
		return false
	}
	ip, _, err := net.SplitHostPort(local.String())
	if err != nil {
		return false
	}
	lip := net.ParseIP(ip)
	return lip != nil && lip.Equal(a.IP)
}

// sameMapped 比较两个映射地址是否完全一致（IP + 端口）。
// 对称型 NAT 的特征正是「IP 相同但端口不同」，因此不能只比较 IP。
func sameMapped(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
