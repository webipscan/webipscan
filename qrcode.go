package main

import (
	"fmt"
	"strings"
)

// 本文件实现一个精简的 QR Code 编码器：仅支持 Byte 模式、纠错级别 L、版本 1-6。
// 局域网剪贴板的访问地址一般不超过 120 字节，版本 6(L) 可容纳 134 字节，
// 因此无需实现版本 7+ 的 version information，也不需要任何第三方依赖。

type qrECCapacity struct {
	dataCodewords int
	ecPerBlock    int
	blocks        int
}

var qrCap = [...]qrECCapacity{
	{}, // 版本 0 不使用
	{19, 7, 1},
	{34, 10, 1},
	{55, 15, 1},
	{80, 20, 1},
	{108, 26, 1},
	{136, 18, 2},
}

var qrAlignPos = [][]int{
	{}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34},
}

func gfMul(a, b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			r ^= a
		}
		hi := a&0x80 != 0
		a <<= 1
		if hi {
			a ^= 0x1d
		}
		b >>= 1
	}
	return r
}

func gfPow(n int) byte {
	x := byte(1)
	for i := 0; i < n; i++ {
		x = gfMul(x, 2)
	}
	return x
}

func rsGenerator(n int) []byte {
	g := []byte{1}
	for i := 0; i < n; i++ {
		next := make([]byte, len(g)+1)
		root := gfPow(i)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, root)
		}
		g = next
	}
	return g
}

func rsEncode(data []byte, n int) []byte {
	gen := rsGenerator(n)
	rem := make([]byte, n)
	for _, b := range data {
		factor := b ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for i := 0; i < n; i++ {
			rem[i] ^= gfMul(gen[i+1], factor)
		}
	}
	return rem
}

func qrFormatBits(mask int) uint16 {
	data := uint32(1<<3 | mask) // 纠错级别 L = 01
	rem := data
	for i := 0; i < 10; i++ {
		bit := (rem >> 9) & 1
		rem = (rem << 1) ^ (bit * 0x537)
	}
	rem &= 0x3ff
	return uint16(((data << 10) | rem) ^ 0x5412)
}

func qrMask(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return (r*c)%2+(r*c)%3 == 0
	case 6:
		return ((r*c)%2+(r*c)%3)%2 == 0
	default:
		return ((r*c)%3+(r+c)%2)%2 == 0
	}
}

func qrPenalty(m [][]bool) int {
	n := len(m)
	score := 0
	addRun := func(run int) {
		if run >= 5 {
			score += 3 + run - 5
		}
	}
	for i := 0; i < n; i++ {
		run := 1
		for j := 1; j < n; j++ {
			if m[i][j] == m[i][j-1] {
				run++
			} else {
				addRun(run)
				run = 1
			}
		}
		addRun(run)
		run = 1
		for j := 1; j < n; j++ {
			if m[j][i] == m[j-1][i] {
				run++
			} else {
				addRun(run)
				run = 1
			}
		}
		addRun(run)
	}
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-1; j++ {
			if m[i][j] == m[i+1][j] && m[i][j] == m[i][j+1] && m[i][j] == m[i+1][j+1] {
				score += 3
			}
		}
	}
	pattern := []bool{true, false, true, true, true, false, true}
	checkLine := func(line []bool) {
		for k := 0; k+7 <= len(line); k++ {
			ok := true
			for t := 0; t < 7; t++ {
				if line[k+t] != pattern[t] {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			lightBefore := k >= 4 && !line[k-1] && !line[k-2] && !line[k-3] && !line[k-4]
			lightAfter := k+11 <= len(line) && !line[k+7] && !line[k+8] && !line[k+9] && !line[k+10]
			if lightBefore || lightAfter {
				score += 40
			}
		}
	}
	for i := 0; i < n; i++ {
		row := make([]bool, n)
		col := make([]bool, n)
		for j := 0; j < n; j++ {
			row[j] = m[i][j]
			col[j] = m[j][i]
		}
		checkLine(row)
		checkLine(col)
	}
	dark := 0
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if m[i][j] {
				dark++
			}
		}
	}
	dev := float64(dark)*100/float64(n*n) - 50
	if dev < 0 {
		dev = -dev
	}
	score += int(dev/5) * 10
	return score
}

// qrEncode 把文本编码成 QR 矩阵（true 表示黑块）
func qrEncode(text string) ([][]bool, bool) {
	data := []byte(text)
	version := 0
	for v := 1; v <= 6; v++ {
		if len(data) <= qrCap[v].dataCodewords-2 {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, false
	}
	cap := qrCap[version]

	bits := make([]int, 0, cap.dataCodewords*8)
	addBits := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (val>>i)&1)
		}
	}
	addBits(0x4, 4) // Byte 模式
	addBits(len(data), 8)
	for _, b := range data {
		addBits(int(b), 8)
	}
	for len(bits) < cap.dataCodewords*8 && len(bits)%8 != 0 {
		bits = append(bits, 0)
	}
	pad := 0xec
	for len(bits) < cap.dataCodewords*8 {
		addBits(pad, 8)
		if pad == 0xec {
			pad = 0x11
		} else {
			pad = 0xec
		}
	}
	bytes := make([]byte, 0, len(bits)/8)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b = b<<1 | byte(bits[i+j])
		}
		bytes = append(bytes, b)
	}

	dataPer := cap.dataCodewords / cap.blocks
	dataBlocks := make([][]byte, cap.blocks)
	ecBlocks := make([][]byte, cap.blocks)
	for i := 0; i < cap.blocks; i++ {
		dataBlocks[i] = bytes[i*dataPer : (i+1)*dataPer]
		ecBlocks[i] = rsEncode(dataBlocks[i], cap.ecPerBlock)
	}
	stream := make([]byte, 0, len(bytes)+cap.blocks*cap.ecPerBlock)
	for i := 0; i < dataPer; i++ {
		for b := 0; b < cap.blocks; b++ {
			stream = append(stream, dataBlocks[b][i])
		}
	}
	for i := 0; i < cap.ecPerBlock; i++ {
		for b := 0; b < cap.blocks; b++ {
			stream = append(stream, ecBlocks[b][i])
		}
	}

	size := version*4 + 17
	matrix := make([][]bool, size)
	reserved := make([][]bool, size)
	for i := range matrix {
		matrix[i] = make([]bool, size)
		reserved[i] = make([]bool, size)
	}

	finder := func(r, c int) {
		for dr := -1; dr <= 7; dr++ {
			for dc := -1; dc <= 7; dc++ {
				rr, cc := r+dr, c+dc
				if rr < 0 || rr >= size || cc < 0 || cc >= size {
					continue
				}
				outer := (dr == 0 || dr == 6) && dc >= 0 && dc <= 6 ||
					(dc == 0 || dc == 6) && dr >= 0 && dr <= 6
				inner := dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4
				matrix[rr][cc] = outer || inner
				reserved[rr][cc] = true
			}
		}
	}
	finder(0, 0)
	finder(0, size-7)
	finder(size-7, 0)

	for i := 8; i < size-8; i++ {
		matrix[6][i] = i%2 == 0
		matrix[i][6] = i%2 == 0
		reserved[6][i] = true
		reserved[i][6] = true
	}

	for _, r := range qrAlignPos[version] {
		for _, c := range qrAlignPos[version] {
			if reserved[r][c] {
				continue
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					dark := (dr == -2 || dr == 2 || dc == -2 || dc == 2) || (dr == 0 && dc == 0)
					matrix[r+dr][c+dc] = dark
					reserved[r+dr][c+dc] = true
				}
			}
		}
	}

	matrix[size-8][8] = true
	reserved[size-8][8] = true
	writeFormat := func(mask int) {
		bits := qrFormatBits(mask)
		for i := 0; i < 15; i++ {
			v := (bits>>uint(i))&1 == 1
			switch {
			case i < 6:
				matrix[i][8] = v
			case i < 8:
				matrix[i+1][8] = v
			default:
				matrix[size-15+i][8] = v
			}
			switch {
			case i < 8:
				matrix[8][size-1-i] = v
			case i < 9:
				matrix[8][7] = v
			default:
				matrix[8][15-i-1] = v
			}
		}
	}
	writeFormat(0) // 占位，数据放置时这些格子会被跳过
	// 格式信息所在格子同样是功能图形，必须排除在数据放置和掩膜之外
	markFormat := func() {
		for i := 0; i < 15; i++ {
			var r, c int
			if i < 6 {
				r, c = i, 8
			} else if i < 8 {
				r, c = i+1, 8
			} else {
				r, c = size-15+i, 8
			}
			reserved[r][c] = true
			if i < 8 {
				r, c = 8, size-1-i
			} else if i < 9 {
				r, c = 8, 7
			} else {
				r, c = 8, 15-i-1
			}
			reserved[r][c] = true
		}
	}
	markFormat()

	bitIdx := 0
	right := size - 1
	up := true
	for right >= 1 {
		if right == 6 {
			right = 5
		}
		for i := 0; i < size; i++ {
			row := i
			if up {
				row = size - 1 - i
			}
			for c := right; c >= right-1; c-- {
				if reserved[row][c] {
					continue
				}
				dark := false
				if bitIdx < len(stream)*8 {
					dark = (stream[bitIdx/8]>>(7-uint(bitIdx%8)))&1 == 1
					bitIdx++
				}
				matrix[row][c] = dark
			}
		}
		up = !up
		right -= 2
	}

	bestMask, bestPenalty := 0, 1<<30
	for mask := 0; mask < 8; mask++ {
		for r := 0; r < size; r++ {
			for c := 0; c < size; c++ {
				if !reserved[r][c] && qrMask(mask, r, c) {
					matrix[r][c] = !matrix[r][c]
				}
			}
		}
		writeFormat(mask)
		if p := qrPenalty(matrix); p < bestPenalty {
			bestPenalty, bestMask = p, mask
		}
		for r := 0; r < size; r++ {
			for c := 0; c < size; c++ {
				if !reserved[r][c] && qrMask(mask, r, c) {
					matrix[r][c] = !matrix[r][c]
				}
			}
		}
	}
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if !reserved[r][c] && qrMask(bestMask, r, c) {
				matrix[r][c] = !matrix[r][c]
			}
		}
	}
	writeFormat(bestMask)
	return matrix, true
}

// qrSVG 返回可直接在 <img> 中使用的 SVG，quiet zone 为 4 个模块
func qrSVG(text string) (string, error) {
	matrix, ok := qrEncode(text)
	if !ok {
		return "", fmt.Errorf("二维码内容过长（最多 134 字节）")
	}
	border := 4
	n := len(matrix) + border*2
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges">`, n, n, n*5, n*5)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	for r, row := range matrix {
		for c, dark := range row {
			if dark {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", c+border, r+border)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
