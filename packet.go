package main

import "encoding/binary"

// 自实现用户态 TCP/IP 栈的最小包操作层。
// 只处理 IPv4 + TCP + UDP，不做分片重组（TUN 的 MTU 我们设 1400，客户端不会发超 MTU 的包）。

const (
	ipProtoTCP = 6
	ipProtoUDP = 17

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

type ip4 struct {
	Src, Dst [4]byte
	Proto    byte
	Frag     bool
	Payload  []byte
}

func parseIP4(b []byte) (ip4, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return ip4{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return ip4{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		total = len(b)
	}
	p := ip4{Proto: b[9]}
	copy(p.Src[:], b[12:16])
	copy(p.Dst[:], b[16:20])
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		p.Frag = true
	}
	p.Payload = b[ihl:total]
	return p, true
}

type tcpSeg struct {
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            byte
	Window           uint16
	Payload          []byte
}

func parseTCP(b []byte) (tcpSeg, bool) {
	if len(b) < 20 {
		return tcpSeg{}, false
	}
	off := int(b[12]>>4) * 4
	if off < 20 || len(b) < off {
		return tcpSeg{}, false
	}
	return tcpSeg{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Seq:     binary.BigEndian.Uint32(b[4:8]),
		Ack:     binary.BigEndian.Uint32(b[8:12]),
		Flags:   b[13],
		Window:  binary.BigEndian.Uint16(b[14:16]),
		Payload: b[off:],
	}, true
}

func parseUDPPorts(b []byte) (sport, dport uint16, payload []byte, ok bool) {
	if len(b) < 8 {
		return 0, 0, nil, false
	}
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if n < 8 || n > len(b) {
		n = len(b)
	}
	return binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4]), b[8:n], true
}

func csum(b []byte, init uint32) uint16 {
	s := init
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func pseudo(src, dst [4]byte, proto byte, n int) uint32 {
	var s uint32
	s += uint32(binary.BigEndian.Uint16(src[0:2])) + uint32(binary.BigEndian.Uint16(src[2:4]))
	s += uint32(binary.BigEndian.Uint16(dst[0:2])) + uint32(binary.BigEndian.Uint16(dst[2:4]))
	s += uint32(proto) + uint32(n)
	return s
}

func putIP4(src, dst [4]byte, proto byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(payload)))
	b[8] = 64
	b[9] = proto
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:12], csum(b[:20], 0))
	copy(b[20:], payload)
	return b
}


func buildTCP(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = 0x50
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], window)
	copy(seg[20:], payload)
	binary.BigEndian.PutUint16(seg[16:18], csum(seg, pseudo(src, dst, ipProtoTCP, len(seg))))
	return putIP4(src, dst, ipProtoTCP, seg)
}

func buildUDP(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	seg := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint16(seg[4:6], uint16(8+len(payload)))
	copy(seg[8:], payload)
	binary.BigEndian.PutUint16(seg[6:8], csum(seg, pseudo(src, dst, ipProtoUDP, len(seg))))
	return putIP4(src, dst, ipProtoUDP, seg)
}
