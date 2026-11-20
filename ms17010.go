package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// MS17-010（永恒之蓝）非利用式检测：
// 445 端口开放时，用 SMBv1 匿名访问 IPC$，对 FID 0 发起 PeekNamedPipe 事务。
// 未打补丁的主机会返回 STATUS_INSUFF_SERVER_RESOURCES。

const (
	ms17Port = 445

	smb1Proto           = "\xffSMB"
	smbCmdNegotiate     = 0x72
	smbCmdSessionSetup  = 0x73
	smbCmdTreeConnect   = 0x75
	smbCmdTransaction   = 0x25
	smbTransPeekPipe    = 0x0023
	smbFIDZero          = 0x0000
	smbStatusInsuffRes  = 0xc0000205 // STATUS_INSUFF_SERVER_RESOURCES => 存在漏洞
	smbStatusInvalidHnd = 0xc0000008 // STATUS_INVALID_HANDLE => 已修补
	smbStatusAccessDen  = 0xc0000022 // STATUS_ACCESS_DENIED => 已修补
	smbStatusNameNotFnd = 0xc0000034 // STATUS_OBJECT_NAME_NOT_FOUND => 已修补

	MS17Vulnerable    = "存在漏洞"
	MS17NotVulnerable = "未发现漏洞"
	MS17Unknown       = "无法确认"
)

type smbRequestHeader struct {
	command             byte
	flags               byte
	flags2              uint16
	treeID, processID   uint16
	userID, multiplexID uint16
}

type smbResponseHeader struct {
	command             byte
	status              uint32
	treeID, processID   uint16
	userID, multiplexID uint16
}

func appendU16(b []byte, values ...uint16) []byte {
	for _, v := range values {
		b = append(b, byte(v), byte(v>>8))
	}
	return b
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// buildSMBPacket 组装 NetBIOS 会话报文 + SMBv1 头 + 命令参数
func buildSMBPacket(h smbRequestHeader, body []byte) []byte {
	smb := make([]byte, 32)
	copy(smb, smb1Proto)
	smb[4] = h.command
	smb[9] = h.flags
	binary.LittleEndian.PutUint16(smb[10:12], h.flags2)
	binary.LittleEndian.PutUint16(smb[24:26], h.treeID)
	binary.LittleEndian.PutUint16(smb[26:28], h.processID)
	binary.LittleEndian.PutUint16(smb[28:30], h.userID)
	binary.LittleEndian.PutUint16(smb[30:32], h.multiplexID)

	packet := append(smb, body...)
	out := make([]byte, 4, 4+len(packet))
	n := len(packet)
	out[1] = byte(n >> 16)
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	return append(out, packet...)
}

func parseSMBResponseHeader(payload []byte) (smbResponseHeader, error) {
	var h smbResponseHeader
	if len(payload) < 32 || string(payload[:4]) != smb1Proto {
		return h, fmt.Errorf("无效 SMBv1 响应")
	}
	h.command = payload[4]
	h.status = binary.LittleEndian.Uint32(payload[5:9])
	h.treeID = binary.LittleEndian.Uint16(payload[24:26])
	h.processID = binary.LittleEndian.Uint16(payload[26:28])
	h.userID = binary.LittleEndian.Uint16(payload[28:30])
	h.multiplexID = binary.LittleEndian.Uint16(payload[30:32])
	return h, nil
}

func smbNegotiatePacket() []byte {
	dialects := []byte(
		"\x02LANMAN1.0\x00" +
			"\x02LM1.2X002\x00" +
			"\x02NT LANMAN 1.0\x00" +
			"\x02NT LM 0.12\x00")
	body := []byte{0x00, byte(len(dialects)), byte(len(dialects) >> 8)}
	body = append(body, dialects...)
	return buildSMBPacket(smbRequestHeader{
		command: smbCmdNegotiate, flags: 0x18, flags2: 0x0128,
		processID: 0x2f4b, multiplexID: 0xc55e,
	}, body)
}

func smbSessionSetupPacket() []byte {
	// WordCount=13；之后 26 字节参数：AndX + 缓冲区上限 + 空凭据 + 能力。
	body := []byte{
		0x0d,
		0xff, 0x00, 0x00, 0x00, // AndXCommand/Reserved/Offset
		0xff, 0xff, 0x02, 0x00, 0x01, 0x00, // MaxBuffer/MaxMpx/VCNumber
		0x00, 0x00, 0x00, 0x00, // SessionKey
		0x00, 0x00, 0x00, 0x00, // ANSI/Unicode 密码长度
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x40, 0x00, 0x00, 0x00, // Capabilities
		0x26, 0x00, // ByteCount
	}
	body = append(body, 0x00, '.', 0x00)
	body = append(body, []byte("Windows 2000 2195\x00")...)
	body = append(body, []byte("Windows 2000 5.0\x00")...)
	return buildSMBPacket(smbRequestHeader{
		command: smbCmdSessionSetup, flags: 0x18, flags2: 0x0120,
		processID: 0x2f4b, multiplexID: 0xc55e,
	}, body)
}

func smbTreeConnectPacket(ip string, userID uint16) []byte {
	path := append([]byte("\\\\"), ip...)
	path = append(path, []byte("\\IPC$\x00")...)
	service := []byte("?????\x00")
	byteCount := 1 + len(path) + len(service) // 1 字节空密码

	body := []byte{
		0x04,
		0xff, 0x00, // AndXCommand / Reserved
		0x00, 0x00, // AndXOffset
		0x00, 0x00, // Flags
		0x01, 0x00, // PasswordLength
	}
	body = appendU16(body, uint16(byteCount))
	body = append(body, 0x00)
	body = append(body, path...)
	body = append(body, service...)
	return buildSMBPacket(smbRequestHeader{
		command: smbCmdTreeConnect, flags: 0x18, flags2: 0x0120,
		processID: 0x2f4b, userID: userID, multiplexID: 0xc55e,
	}, body)
}

func smbPeekNamedPipePacket(treeID, processID, userID, multiplexID uint16) []byte {
	const bcc = "\\PIPE\x00"
	const paramOffset = 0x004a

	body := []byte{0x10}                   // WordCount=16
	body = appendU16(body, 0, 0)           // TotalParameterCount, TotalDataCount
	body = appendU16(body, 0xffff, 0xffff) // MaxParameterCount, MaxDataCount
	body = append(body, 0x00, 0x00)        // MaxSetupCount, Reserved
	body = appendU16(body, 0)              // Flags
	body = appendU32(body, 0)              // Timeout
	body = appendU16(body, 0)              // Reserved
	body = appendU16(body, 0)              // ParameterCount
	body = appendU16(body, paramOffset)
	body = appendU16(body, 0) // DataCount
	body = appendU16(body, paramOffset)
	body = append(body, 0x02, 0x00) // SetupCount, Reserved
	body = appendU16(body, smbTransPeekPipe, smbFIDZero)
	body = appendU16(body, uint16(len(bcc)))
	body = append(body, []byte(bcc)...)

	return buildSMBPacket(smbRequestHeader{
		command: smbCmdTransaction, flags: 0x18, flags2: 0x0128,
		treeID: treeID, processID: processID,
		userID: userID, multiplexID: multiplexID,
	}, body)
}

func ms17Timeout(base time.Duration) time.Duration {
	t := base * 3
	if t < 1500*time.Millisecond {
		t = 1500 * time.Millisecond
	}
	if t > 3*time.Second {
		t = 3 * time.Second
	}
	return t
}

func smbExchange(ctx context.Context, conn net.Conn, req []byte, timeout time.Duration) (smbResponseHeader, error) {
	if err := ctx.Err(); err != nil {
		return smbResponseHeader{}, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return smbResponseHeader{}, err
	}
	if _, err := conn.Write(req); err != nil {
		return smbResponseHeader{}, err
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	var nb [4]byte
	if _, err := io.ReadFull(conn, nb[:]); err != nil {
		return smbResponseHeader{}, err
	}
	if nb[0] != 0 {
		return smbResponseHeader{}, fmt.Errorf("非 NetBIOS 会话报文")
	}
	n := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if n < 32 || n > 65535 {
		return smbResponseHeader{}, fmt.Errorf("SMB 响应长度异常：%d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return smbResponseHeader{}, err
	}
	return parseSMBResponseHeader(payload)
}

// checkMS17_010 返回 "存在漏洞" / "未发现漏洞" / "无法确认"。
// 只在调用方已确认 445 端口开放时调用。
func checkMS17_010(ctx context.Context, ip string, baseTimeout time.Duration) string {
	return checkMS17_010Addr(ctx, net.JoinHostPort(ip, "445"), ip, baseTimeout)
}

func checkMS17_010Addr(ctx context.Context, addr, ip string, baseTimeout time.Duration) string {
	timeout := ms17Timeout(baseTimeout)
	if deadline, ok := ctx.Deadline(); ok {
		if remain := time.Until(deadline); remain > 0 && remain < timeout {
			timeout = remain
		}
	}
	if timeout <= 0 {
		return MS17Unknown
	}

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return MS17Unknown
	}
	defer conn.Close()

	h, err := smbExchange(ctx, conn, smbNegotiatePacket(), timeout)
	if err != nil || h.command != smbCmdNegotiate || h.status != 0 {
		return MS17Unknown
	}
	h, err = smbExchange(ctx, conn, smbSessionSetupPacket(), timeout)
	if err != nil || h.status != 0 {
		return MS17Unknown
	}
	userID := h.userID

	h, err = smbExchange(ctx, conn, smbTreeConnectPacket(ip, userID), timeout)
	if err != nil || h.status != 0 {
		return MS17Unknown
	}

	h, err = smbExchange(ctx, conn,
		smbPeekNamedPipePacket(h.treeID, h.processID, userID, h.multiplexID), timeout)
	if err != nil || h.command != smbCmdTransaction {
		return MS17Unknown
	}
	switch h.status {
	case smbStatusInsuffRes:
		return MS17Vulnerable
	case smbStatusInvalidHnd, smbStatusAccessDen, smbStatusNameNotFnd:
		return MS17NotVulnerable
	default:
		return MS17Unknown
	}
}
