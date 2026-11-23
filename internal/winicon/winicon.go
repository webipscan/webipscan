// Package winicon converts an embedded ICO (whose entries may be
// PNG-compressed, which LoadImageW cannot read) into a classic BMP/DIB ICO
// with several standard sizes, and exposes the raw entries for building
// Windows RT_ICON / RT_GROUP_ICON resources.
package winicon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
)

// Entry is one image stored in a ICO file. Width or Height of 0 means 256.
type Entry struct {
	Width    byte
	Height   byte
	Planes   uint16
	BitCount uint16
	Data     []byte
}

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// Convert reads a ICO file and returns a Windows-friendly ICO containing
// uncompressed 32-bit DIB images at common tray/explorer sizes.
func Convert(ico []byte) ([]byte, error) {
	src, err := largest(ico)
	if err != nil {
		return nil, err
	}
	img, err := decode(src.Data)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	limit := bounds.Dx()
	if bounds.Dy() < limit {
		limit = bounds.Dy()
	}
	sizes := make([]int, 0, 7)
	for _, s := range []int{16, 24, 32, 48, 64, 128, 256} {
		if s <= limit {
			sizes = append(sizes, s)
		}
	}
	if len(sizes) == 0 {
		sizes = append(sizes, limit)
	}

	images := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		images = append(images, dib(resizeBox(img, size), size))
	}

	var out bytes.Buffer
	le := binary.LittleEndian
	var header [6]byte
	le.PutUint16(header[0:2], 0)
	le.PutUint16(header[2:4], 1)
	le.PutUint16(header[4:6], uint16(len(sizes)))
	out.Write(header[:])

	offset := 6 + 16*len(sizes)
	for i, size := range sizes {
		var e [16]byte
		b := byte(size)
		if size == 256 {
			b = 0
		}
		e[0], e[1] = b, b
		le.PutUint16(e[4:6], 1)
		le.PutUint16(e[6:8], 32)
		le.PutUint32(e[8:12], uint32(len(images[i])))
		le.PutUint32(e[12:16], uint32(offset))
		out.Write(e[:])
		offset += len(images[i])
	}
	for _, data := range images {
		out.Write(data)
	}
	return out.Bytes(), nil
}

// Entries parses a ICO file and returns its raw image entries.
func Entries(ico []byte) ([]Entry, error) {
	if len(ico) < 6 {
		return nil, errors.New("ICO 文件过短")
	}
	le := binary.LittleEndian
	n := int(le.Uint16(ico[4:6]))
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		off := 6 + i*16
		if off+16 > len(ico) {
			return nil, errors.New("ICO 目录损坏")
		}
		size := int(le.Uint32(ico[off+8 : off+12]))
		dataOff := int(le.Uint32(ico[off+12 : off+16]))
		if dataOff < 0 || size < 0 || dataOff+size > len(ico) {
			return nil, errors.New("ICO 图像数据越界")
		}
		entries = append(entries, Entry{
			Width:    ico[off],
			Height:   ico[off+1],
			Planes:   le.Uint16(ico[off+4 : off+6]),
			BitCount: le.Uint16(ico[off+6 : off+8]),
			Data:     ico[dataOff : dataOff+size],
		})
	}
	return entries, nil
}

func largest(ico []byte) (Entry, error) {
	entries, err := Entries(ico)
	if err != nil {
		return Entry{}, err
	}
	best := Entry{}
	maxArea := 0
	for _, e := range entries {
		w, h := int(e.Width), int(e.Height)
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		if w*h > maxArea {
			best, maxArea = e, w*h
		}
	}
	if best.Data == nil {
		return Entry{}, errors.New("ICO 中没有可用图像")
	}
	return best, nil
}

func decode(data []byte) (image.Image, error) {
	if bytes.HasPrefix(data, pngSignature) {
		return png.Decode(bytes.NewReader(data))
	}
	if len(data) >= 40 {
		le := binary.LittleEndian
		w, h := int(le.Uint32(data[4:8])), int(le.Uint32(data[8:12]))/2
		bits, compression := le.Uint16(data[14:16]), le.Uint32(data[16:20])
		if bits == 32 && compression == 0 && w > 0 && h > 0 {
			stride := w * 4
			if len(data) >= 40+stride*h {
				img := image.NewRGBA(image.Rect(0, 0, w, h))
				for y := 0; y < h; y++ {
					row := 40 + (h-1-y)*stride // DIB 自下而上存储
					for x := 0; x < w; x++ {
						p := row + x*4
						img.SetRGBA(x, y, color.RGBA{B: data[p], G: data[p+1], R: data[p+2], A: data[p+3]})
					}
				}
				return img, nil
			}
		}
	}
	return nil, errors.New("不支持的图标图像格式（需要 PNG 或 32 位 DIB）")
}

// resizeBox 用盒式滤波缩放，按预乘 alpha 求均值以避免半透明边缘发黑。
func resizeBox(src image.Image, size int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	for y := 0; y < size; y++ {
		y0, y1 := y*sh/size, (y+1)*sh/size
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < size; x++ {
			x0, x1 := x*sw/size, (x+1)*sw/size
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, a, count uint32
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					c := color.NRGBAModel.Convert(src.At(b.Min.X+sx, b.Min.Y+sy)).(color.NRGBA)
					alpha := uint32(c.A)
					r += uint32(c.R) * alpha
					g += uint32(c.G) * alpha
					bl += uint32(c.B) * alpha
					a += alpha
					count++
				}
			}
			if a == 0 || count == 0 {
				continue
			}
			dst.SetRGBA(x, y, color.RGBA{
				R: uint8(r / a),
				G: uint8(g / a),
				B: uint8(bl / a),
				A: uint8(a / count),
			})
		}
	}
	return dst
}

// dib 生成 32 位 BGRA 位图：XOR 位图自下而上，AND 掩码置 0（透明度由 alpha 决定）。
func dib(img *image.RGBA, size int) []byte {
	stride := ((size + 31) / 32) * 4
	xorSize := size * size * 4
	andSize := stride * size
	out := make([]byte, 40+xorSize+andSize)
	le := binary.LittleEndian
	le.PutUint32(out[0:4], 40)
	le.PutUint32(out[4:8], uint32(size))
	le.PutUint32(out[8:12], uint32(size*2))
	le.PutUint16(out[12:14], 1)
	le.PutUint16(out[14:16], 32)
	le.PutUint32(out[20:24], uint32(xorSize+andSize))
	p := 40
	for y := size - 1; y >= 0; y-- {
		for x := 0; x < size; x++ {
			c := img.RGBAAt(x, y)
			out[p], out[p+1], out[p+2], out[p+3] = c.B, c.G, c.R, c.A
			p += 4
		}
	}
	return out
}
