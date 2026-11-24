package main

import (
	"net"
	"testing"
	"time"
)

// TUN 栈跑不到真网卡也能验证的一半：SYN 进、SYN-ACK 出、校验和正确。
func TestStackHandshake(t *testing.T) {
	var out [][]byte
	route := func(sip [4]byte, sport int, sni string, hello []byte) (net.Conn, bool, error) {
		return nil, false, errCutSkipped
	}
	st := NewStack(func(p []byte) { out = append(out, p) }, route, nil)

	cli := [4]byte{10, 7, 0, 2}
	srv := [4]byte{1, 2, 3, 4}
	st.Handle(buildTCP(cli, srv, 50000, 443, 1000, 0, tcpSYN, 65535, nil))
	if len(out) != 1 {
		t.Fatalf("SYN 应回 1 个包，实际 %d", len(out))
	}
	ip, ok := parseIP4(out[0])
	if !ok || ip.Proto != ipProtoTCP {
		t.Fatalf("回包不是 TCP/IPv4")
	}
	seg, ok := parseTCP(ip.Payload)
	if !ok {
		t.Fatalf("回包 TCP 头解析失败")
	}
	if seg.Flags&tcpSYN == 0 || seg.Flags&tcpACK == 0 {
		t.Fatalf("回包应是 SYN-ACK，实际 flags=%#02x", seg.Flags)
	}
	if seg.Ack != 1001 {
		t.Fatalf("ACK 应为 1001，实际 %d", seg.Ack)
	}
	// 校验和自校验：全包累加结果为 0
	if csum(ip.Payload, pseudo(ip.Src, ip.Dst, ipProtoTCP, len(ip.Payload))) != 0 {
		t.Fatalf("TCP 校验和错误")
	}
	raw := out[0]
	if got := csum(raw[:20], 0); got != 0 {
		t.Fatalf("IP 头校验和错误: %#x", got)
	}
}

// 重复 SYN（客户端重传）不应再建一条连接。
func TestStackRetransmitSYN(t *testing.T) {
	route := func(sip [4]byte, sport int, sni string, hello []byte) (net.Conn, bool, error) {
		return nil, false, errCutSkipped
	}
	var n int
	st := NewStack(func(p []byte) { n++ }, route, nil)
	cli := [4]byte{10, 7, 0, 2}
	srv := [4]byte{1, 2, 3, 4}
	st.Handle(buildTCP(cli, srv, 50000, 443, 1000, 0, tcpSYN, 65535, nil))
	first := n
	st.Handle(buildTCP(cli, srv, 50000, 443, 1000, 0, tcpSYN, 65535, nil))
	if n-first > 1 {
		t.Fatalf("重复 SYN 回了 %d 个包", n-first)
	}
	time.Sleep(10 * time.Millisecond)
}
