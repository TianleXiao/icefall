package main

// strategy.go —— 每个域名的绕过策略表。
//
// 为什么需要：分片只对「SNI 检测型」封锁有效。
// 实测过的三种情况：
//   1. 分片可通      —— 学校只认 TLS ClientHello 的明文 SNI，切碎就看不到
//   2. 分片上上游    —— 分片后在本地仍不通（IP 被封/服务器拒非白名单 SNI），交给上游代理
//   3. 直连就好      —— 没被封，别多此一举（分片反而增加握手开销）
//
// 策略由启动时的自动探测决定，也可用 strategy.json 手工覆盖。

import (
	"sync"
	"encoding/json"
	"os"
)

// Mode 是一个域名的绕过方式。
type Mode string

const (
	ModeDirect   Mode = "direct"   // 完全直连，不碰代理
	ModeFragment Mode = "fragment" // 本地 TLS record 分片
	ModeUpstream Mode = "upstream" // 整条隧道转上游代理（Clash）
)

// Strategy 表：域名后缀 -> 模式。按后缀匹配（长后缀优先）。
type Strategy struct {
	entries map[string]Mode
	mu      sync.RWMutex
}

func newStrategy() *Strategy {
	return &Strategy{entries: map[string]Mode{}}
}

// Set 设置一个后缀的策略。
func (s *Strategy) Set(suffix string, m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[suffix] = m
}

// snapshot 返回策略表的副本，用于生成 PAC。
func (s *Strategy) snapshot() map[string]Mode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Mode, len(s.entries))
	for k, v := range s.entries {
		out[k] = v
	}
	return out
}

// Get 查一个 host 的策略，长后缀优先，找不到返回 ModeDirect。
func (s *Strategy) Get(host string) Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	best := ""
	for k := range s.entries {
		if host == k {
			return s.entries[k]
		}
		if len(host) > len(k)+1 && host[len(host)-len(k)-1] == '.' &&
			host[len(host)-len(k):] == k {
			if len(k) > len(best) {
				best = k
			}
		}
	}
	if best != "" {
		return s.entries[best]
	}
	return ModeDirect
}

// Save 写入 JSON，便于用户编辑。格式与 discover 写出的保持一致。
func (s *Strategy) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make(map[string]string, len(s.entries))
	for k, v := range s.entries {
		entries[k] = string(v)
	}
	b, _ := json.MarshalIndent(map[string]any{"entries": entries}, "", "  ")
	return os.WriteFile(path, b, 0o644)
}

// Load 从 JSON 读策略；文件不存在返回错误，调用方自己决定用内置表。
func (s *Strategy) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw struct {
		Entries map[string]string `json:"entries"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k, v := range raw.Entries {
		s.Set(k, Mode(v))
	}
	return nil
}

// builtinStrategy 是实测得出的内置表。数据来自本机对每个域名的 cut 扫描。
func builtinStrategy() *Strategy {
	s := newStrategy()

	// 分片可通（学校按明文 SNI 精确 RST）
	for _, d := range []string{
		"bilibili.com", "hdslb.com", "bilivideo.com", "bilivideo.cn", "bilibili.tv",
		"xiaohongshu.com", "xhscdn.com",
		"douyin.com", "douyinpic.com", "douyinvod.com",
		"mihoyo.com", "hoyoverse.com", "hypergryph.com",
		"qq.com", "wegame.com.cn",
		"haimacloud.com", "haima.com",
		"channels.weixin.qq.com", "finder.video.qq.com", "dldir1.qq.com",
	} {
		s.Set(d, ModeFragment)
	}

	// 分片无效，交给上游（微信长连接服务器只认白名单 SNI，学校又 RST 真 SNI）
	for _, d := range []string{
		"short.weixin.qq.com", "long.weixin.qq.com",
	} {
		s.Set(d, ModeUpstream)
	}

	// 明确直连：国内没被封的、以及本地网络设备
	for _, d := range []string{
		"baidu.com", "zhihu.com", "taobao.com", "jd.com", "weibo.com",
		"163.com", "aliyun.com", "aliyuncs.com", "tencent.com",
	} {
		s.Set(d, ModeDirect)
	}

	return s
}
