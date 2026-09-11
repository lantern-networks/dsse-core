package main

import (
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// dnsCache is a small, TTL-respecting response cache for the DNS-over-tunnel proxy. Without it EVERY hostname a
// page touches is a fresh round-trip to the Edge over the (T) tunnel — on a real page (dozens of distinct hosts,
// re-resolved by the browser) that is a DNS storm that stalls the page and, under the 8s timeout, fails as
// ERR_NAME_NOT_RESOLVED → broken images. This is the biggest Windows-vs-macOS asymmetry: on Windows ALL DNS
// rides the tunnel, so caching the answer (keyed by the question, expiring on the record TTL) removes the
// repeat round-trips. Cache hits rewrite only the 2-byte transaction id to match the new query; TTLs are left
// as-is (the OS resolver caches per-TTL anyway, so staleness is bounded exactly as normal DNS).
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsCacheEntry
	maxTTL  time.Duration // cap so even high-TTL records re-validate through the Edge periodically
	maxSize int
	now     func() time.Time
}

type dnsCacheEntry struct {
	response []byte
	expires  time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: map[string]dnsCacheEntry{}, maxTTL: 60 * time.Second, maxSize: 4096, now: time.Now}
}

// get returns a cached response for query (transaction id rewritten to match) when present and unexpired.
func (c *dnsCache) get(query []byte) ([]byte, bool) {
	key, ok := dnsQuestionKey(query)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	e, found := c.entries[key]
	if found && c.now().After(e.expires) {
		delete(c.entries, key)
		found = false
	}
	c.mu.Unlock()
	if !found {
		return nil, false
	}
	out := make([]byte, len(e.response))
	copy(out, e.response)
	if len(out) >= 2 && len(query) >= 2 {
		out[0], out[1] = query[0], query[1] // transaction id of the asking query
	}
	return out, true
}

// put stores response under the query's question key, expiring on the answer's minimum TTL (capped). A zero/low
// TTL or an unparseable message is simply not cached (fail-open: correctness over a marginal hit).
func (c *dnsCache) put(query, response []byte) {
	key, ok := dnsQuestionKey(query)
	if !ok {
		return
	}
	ttl, ok := dnsMinTTL(response)
	if !ok || ttl == 0 {
		return
	}
	d := time.Duration(ttl) * time.Second
	if d > c.maxTTL {
		d = c.maxTTL
	}
	stored := make([]byte, len(response))
	copy(stored, response)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		// Cheap bound: drop one arbitrary (oldest-ish) entry. The cache is short-lived churn, not an LRU.
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = dnsCacheEntry{response: stored, expires: c.now().Add(d)}
}

// dnsQuestionKey derives a cache key from the first question (lowercased qname + qtype + qclass). Returns false
// for anything not a single standard query, so we only cache the common case.
func dnsQuestionKey(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount != 1 {
		return "", false
	}
	name, off, ok := dnsReadName(msg, 12)
	if !ok || off+4 > len(msg) {
		return "", false
	}
	qtypeClass := msg[off : off+4]
	return strings.ToLower(name) + "|" + string(qtypeClass), true
}

// dnsReadName reads a (possibly compressed) domain name starting at off, returning the name text and the offset
// of the byte AFTER the name in the message (for the question this is qname's terminator + 1; pointers are not
// followed for the "after" offset since questions don't use them, but we tolerate them defensively).
func dnsReadName(msg []byte, off int) (string, int, bool) {
	var sb strings.Builder
	cur := off
	for {
		if cur >= len(msg) {
			return "", 0, false
		}
		n := int(msg[cur])
		if n == 0 {
			return sb.String(), cur + 1, true
		}
		if n&0xC0 == 0xC0 { // compression pointer ends the name (2 bytes)
			if cur+2 > len(msg) {
				return "", 0, false
			}
			return sb.String(), cur + 2, true
		}
		cur++
		if cur+n > len(msg) {
			return "", 0, false
		}
		sb.Write(msg[cur : cur+n])
		sb.WriteByte('.')
		cur += n
	}
}

// dnsMinTTL walks the answer records and returns the minimum TTL. Returns false on any parse trouble.
func dnsMinTTL(msg []byte) (uint32, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	if an == 0 {
		return 0, false
	}
	off := 12
	for i := 0; i < qd; i++ { // skip questions
		_, n, ok := dnsReadName(msg, off)
		if !ok {
			return 0, false
		}
		off = n + 4 // qtype + qclass
	}
	var min uint32 = 0xFFFFFFFF
	for i := 0; i < an; i++ {
		n, ok := dnsRecordNameEnd(msg, off)
		if !ok {
			return 0, false
		}
		off = n
		if off+10 > len(msg) {
			return 0, false
		}
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10 + rdlen
		if off > len(msg) {
			return 0, false
		}
		if ttl < min {
			min = ttl
		}
	}
	if min == 0xFFFFFFFF {
		return 0, false
	}
	return min, true
}

// dnsRecordNameEnd returns the offset just AFTER a record's NAME field (which may be a compression pointer).
func dnsRecordNameEnd(msg []byte, off int) (int, bool) {
	for {
		if off >= len(msg) {
			return 0, false
		}
		n := int(msg[off])
		if n == 0 {
			return off + 1, true
		}
		if n&0xC0 == 0xC0 {
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		}
		off += 1 + n
	}
}
