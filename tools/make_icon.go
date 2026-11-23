//go:build ignore

// Command make_icon generates Windows .syso files containing RT_ICON and
// RT_GROUP_ICON resources built from static/icon.ico.
//
//	go run tools/make_icon.go
//
// The generated icon_*.syso files are picked up automatically by go build.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"webipscan/internal/winicon"
)

type dirEntry struct {
	id     uint32
	offset uint32
}

func main() {
	raw, err := os.ReadFile("static/icon.ico")
	if err != nil {
		log.Fatal(err)
	}
	converted, err := winicon.Convert(raw)
	if err != nil {
		log.Fatal(err)
	}
	entries, err := winicon.Entries(converted)
	if err != nil {
		log.Fatal(err)
	}
	rsrc, relocs := resources(entries)

	for name, target := range map[string]struct {
		machine, relType uint16
	}{
		"icon_windows_amd64.syso": {0x8664, 0x0002}, // IMAGE_REL_AMD64_ADDR32
		"icon_windows_386.syso":   {0x014c, 0x0006}, // IMAGE_REL_I386_DIR32
		"icon_windows_arm64.syso": {0xaa64, 0x0001}, // IMAGE_REL_ARM64_ADDR32
	} {
		if err := os.WriteFile(name, syso(target.machine, target.relType, rsrc, relocs), 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("generated", name)
	}
}

func resources(entries []winicon.Entry) ([]byte, []uint32) {
	n := len(entries)
	const langID = 0x0409
	var relocs []uint32

	// 资源目录固定为三层：Type -> ID -> Language -> DataEntry。
	iconIDDir := uint32(32)
	iconLangDir := iconIDDir + uint32(16+8*n)
	iconDataOff := iconLangDir + uint32(24*n)
	groupIDDir := iconDataOff + uint32(16*n)
	groupLangDir := groupIDDir + 24
	groupDataOff := groupLangDir + 24
	payloadBase := groupDataOff + 16

	var section bytes.Buffer
	section.Grow(int(payloadBase))
	section.Write(make([]byte, payloadBase))
	b := section.Bytes()

	copyAt := func(off uint32, data []byte) { copy(b[off:], data) }
	copyAt(0, directory([]dirEntry{
		{3, 0x80000000 | iconIDDir},
		{14, 0x80000000 | groupIDDir},
	}))
	copyAt(groupIDDir, directory([]dirEntry{{1, 0x80000000 | groupLangDir}}))
	copyAt(groupLangDir, directory([]dirEntry{{langID, groupDataOff}}))

	ids := make([]dirEntry, 0, n)
	for i := range entries {
		langOff := iconLangDir + uint32(24*i)
		ids = append(ids, dirEntry{uint32(i + 1), 0x80000000 | langOff})
		copyAt(langOff, directory([]dirEntry{{langID, iconDataOff + uint32(i*16)}}))
	}
	copyAt(iconIDDir, directory(ids))

	payloadOff := payloadBase
	for i, e := range entries {
		entryOff := iconDataOff + uint32(i*16)
		copyAt(entryOff, dataEntry(payloadOff, uint32(len(e.Data))))
		relocs = append(relocs, entryOff) // OffsetToData 稍后由链接器改成 RVA
		payloadOff += uint32(len(e.Data))
		payloadOff = (payloadOff + 3) &^ 3
	}

	group := groupIconDir(entries)
	copyAt(groupDataOff, dataEntry(payloadOff, uint32(len(group))))
	relocs = append(relocs, groupDataOff)

	for _, e := range entries {
		section.Write(e.Data)
		for section.Len()%4 != 0 {
			section.WriteByte(0)
		}
	}
	section.Write(group)
	return section.Bytes(), relocs
}

func directory(entries []dirEntry) []byte {
	out := make([]byte, 16+len(entries)*8)
	le := binary.LittleEndian
	le.PutUint16(out[14:16], uint16(len(entries))) // NumberOfIdEntries
	for i, e := range entries {
		off := 16 + i*8
		le.PutUint32(out[off:off+4], e.id)
		le.PutUint32(out[off+4:off+8], e.offset)
	}
	return out
}

func dataEntry(offset, size uint32) []byte {
	out := make([]byte, 16)
	le := binary.LittleEndian
	le.PutUint32(out[0:4], offset)
	le.PutUint32(out[4:8], size)
	return out
}

func groupIconDir(entries []winicon.Entry) []byte {
	out := make([]byte, 6+14*len(entries))
	le := binary.LittleEndian
	le.PutUint16(out[2:4], 1)
	le.PutUint16(out[4:6], uint16(len(entries)))
	for i, e := range entries {
		off := 6 + i*14
		out[off] = e.Width
		out[off+1] = e.Height
		le.PutUint16(out[off+4:off+6], e.Planes)
		le.PutUint16(out[off+6:off+8], e.BitCount)
		le.PutUint32(out[off+8:off+12], uint32(len(e.Data)))
		le.PutUint16(out[off+12:off+14], uint16(i+1))
	}
	return out
}

// syso 生成一个只含 .rsrc 段的 COFF 对象；Go 链接器会把它合并进 exe 的 .rsrc 节，
// 并用重定位把各 IMAGE_RESOURCE_DATA_ENTRY.OffsetToData 修正为真实的 RVA。
func syso(machine, relType uint16, rsrc []byte, relocs []uint32) []byte {
	const (
		headerSize = 20 + 40
		symSize    = 18
		relSize    = 10
	)
	out := make([]byte, headerSize)
	le := binary.LittleEndian
	le.PutUint16(out[0:2], machine)
	le.PutUint16(out[2:4], 1)

	// COFF 排列顺序：节数据 -> 重定位表 -> 符号表 -> 字符串表（仅长度 4）。
	relOff := uint32(headerSize + len(rsrc))
	symOff := relOff + uint32(relSize*len(relocs))
	le.PutUint32(out[8:12], symOff)
	le.PutUint16(out[12:14], 1)

	sec := out[20:]
	copy(sec[0:8], ".rsrc\x00\x00\x00")
	le.PutUint32(sec[8:12], uint32(len(rsrc)))
	le.PutUint32(sec[16:20], uint32(len(rsrc)))
	le.PutUint32(sec[20:24], headerSize)
	le.PutUint32(sec[24:28], relOff)
	le.PutUint16(sec[32:34], uint16(len(relocs)))
	le.PutUint32(sec[36:40], 0x40000040) // CNT_INITIALIZED_DATA | MEM_READ

	out = append(out, rsrc...)

	for _, off := range relocs {
		rel := make([]byte, relSize)
		le.PutUint32(rel[0:4], off)
		le.PutUint32(rel[4:8], 0) // 段符号索引
		le.PutUint16(rel[8:10], relType)
		out = append(out, rel...)
	}

	sym := make([]byte, symSize)
	copy(sym[0:8], ".rsrc\x00\x00\x00")
	le.PutUint16(sym[12:14], 1) // 所属段号
	sym[16] = 3                 // IMAGE_SYM_CLASS_STATIC
	out = append(out, sym...)

	out = append(out, 4, 0, 0, 0) // 空字符串表
	return out
}
