package main

import (
	"encoding/binary"
	"fmt"
)

// sniNameLen 返回 SNI 域名字符串长度。
func sniNameLen(rec []byte) int {
	off := sniNameOffset(rec)
	if off < 2 || off+1 > len(rec) {
		return 0
	}
	return int(rec[off-2])<<8 | int(rec[off-1])
}

// cutCandidates 给出该 hello 的候选分片点（记录内绝对偏移）。
//
// 实测规律：切点必须落在 SNI 域名字符串「内部」（不是起点、不是终点），
// 让第一段带上域名前半、第二段带上域名后半，检测器两边都拼不出完整域名。
//
// 早期版本用百分比取点（25/40/55/70/85%），对短域名会整段跳过有效区间：
// `www.bilibili.com` 名字只有 14 字节、偏移 117，有效切点是 121..132，
// 而 25% 取整落在 120（死区），于是全部候选失败。
//
// 现在按名字内部每个字节都作候选，保证不漏。代价是候选最多 nlen-1 个，
// 但实际第一个或第二个就命中（检测器只要求「不完整」），开销可接受。
func cutCandidates(rec []byte) []int {
	off := sniNameOffset(rec)
	if off <= 0 {
		return nil
	}
	nlen := sniNameLen(rec)
	if nlen <= 1 {
		return nil
	}
	// 优先从名字中部向两侧展开：命中一次就够，中段最稳。
	var out []int
	mid := off + nlen/2
	for d := 0; d < nlen; d++ {
		for _, c := range []int{mid + d, mid - d} {
			if c <= off || c >= off+nlen {
				continue
			}
			if c <= 5 || c >= len(rec)-5 {
				continue
			}
			dup := false
			for _, e := range out {
				if e == c {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, c)
			}
		}
	}
	return out
}

// describeCuts 打印候选切点，调试用。
func describeCuts(host string, rec []byte) {
	off := sniNameOffset(rec)
	cands := cutCandidates(rec)
	fmt.Printf("%-40s hello=%-5d SNI@%-4d len=%-3d cuts=%v\n",
		host, len(rec), off, sniNameLen(rec), cands)
}

var _ = binary.BigEndian
