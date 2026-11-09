package frontdoor

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limit.go — bounding how fast one address may try a door.

// TokenBucket is a small per-key token-bucket limiter with no dependency outside the standard library.
type TokenBucket struct {
	mu        sync.Mutex
	nextSweep time.Time
	buckets   map[string]*bucketState
	rps       float64
	burst     float64
	Now       func() time.Time
}

type bucketState struct {
	tokens   float64
	lastSeen time.Time
}

// NewTokenBucket makes a limiter that refills rps tokens per second up to burst. A non-positive rps means
// "unlimited"; a non-positive burst takes the rate as its burst.
func NewTokenBucket(rps, burst float64) *TokenBucket {
	if burst <= 0 {
		burst = rps
	}
	return &TokenBucket{buckets: map[string]*bucketState{}, rps: rps, burst: burst, Now: time.Now}
}

// Allow reports whether a request from key may proceed, consuming one token.
func (l *TokenBucket) Allow(key string) bool {
	if l == nil || l.rps <= 0 {
		return true
	}
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.nextSweep) {
		// A fully replenished idle bucket is the same as a new one: reclaim those and only those.
		for oldKey, old := range l.buckets {
			if now.Sub(old.lastSeen).Seconds()*l.rps >= l.burst {
				delete(l.buckets, oldKey)
			}
		}
		l.nextSweep = now.Add(time.Minute)
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucketState{tokens: l.burst, lastSeen: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.lastSeen).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rps
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ClientIP is the address a request's limits are keyed on: the connection's own address, or, when the
// connection comes FROM one of the trusted proxies, the rightmost X-Forwarded-For entry that is not itself a
// trusted proxy. With no trusted proxies the header is never read: it is written by whoever sends the
// request, and a limiter that believed it would be keyed on a value the client chose.
func ClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}
	if len(trustedProxies) > 0 && Contains(trustedProxies, host) {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if cand := strings.TrimSpace(parts[i]); cand != "" && !Contains(trustedProxies, cand) {
				return cand
			}
		}
	}
	return host
}

// Contains reports whether host (an address) lies in one of the networks.
func Contains(nets []*net.IPNet, host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
