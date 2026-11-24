package main

import "encoding/binary"

// sniNameOffset 返回 SNI 主机名字符串在记录内的绝对偏移。
// 找不到返回 0（调用方据此退化为不分片）。
func sniNameOffset(rec []byte) int {
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x01 {
		return 0
	}
	p := 5 + 4 + 2 + 32
	if len(rec) < p+1 {
		return 0
	}
	p += 1 + int(rec[p])
	if len(rec) < p+2 {
		return 0
	}
	p += 2 + int(binary.BigEndian.Uint16(rec[p:]))
	if len(rec) < p+1 {
		return 0
	}
	p += 1 + int(rec[p])
	if len(rec) < p+2 {
		return 0
	}
	extTotal := int(binary.BigEndian.Uint16(rec[p:]))
	p += 2
	extEnd := p + extTotal
	if len(rec) < extEnd {
		return 0
	}
	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(rec[p:])
		elen := int(binary.BigEndian.Uint16(rec[p+2:]))
		body := p + 4
		if etype == 0x0000 && elen >= 5 {
			return body + 5
		}
		p = body + elen
	}
	return 0
}

// ParseClientHelloSNI 只读解析 SNI，用于日志。
func ParseClientHelloSNI(rec []byte) (string, bool) {
	off := sniNameOffset(rec)
	if off == 0 || off+2 > len(rec) {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(rec[off-2:]))
	if off+n > len(rec) {
		return "", false
	}
	return string(rec[off : off+n]), true
}

// fragmentHello 把单 record 的 ClientHello 在第 cut 字节处拆成两个 record。
//
// cut 是相对 handshake body 的偏移（即不含 5 字节 record 头）。
// 传 sniNameOffset 的返回值减去 5 即得到「名字起点」处的切点。
func fragmentHello(rec []byte, cut int) []byte {
	if len(rec) < 6 || cut <= 0 {
		return rec
	}
	body := rec[5:]
	if cut >= len(body) {
		return rec
	}
	mk := func(b []byte) []byte {
		out := make([]byte, 0, 5+len(b))
		out = append(out, 0x16, rec[1], rec[2],
			byte(len(b)>>8), byte(len(b)))
		return append(out, b...)
	}
	return append(mk(body[:cut]), mk(body[cut:])...)
}

func countRecords(b []byte) int {
	n, i := 0, 0
	for i+5 <= len(b) {
		ln := int(b[i+3])<<8 | int(b[i+4])
		i += 5 + ln
		n++
	}
	return n
}
