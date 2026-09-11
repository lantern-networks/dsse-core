package main

import (
	"container/heap"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// mesh_anti_replay.go adds REPLAY PROTECTION to the inter-region mesh ingress (the data mesh upgrade and the
// cross-region revocation push). The bare shared-secret header authenticates the SENDER but a captured request
// can be replayed verbatim: re-establishing a tunnel, or (worse) re-applying a stale revocation that can DENY
// any identity. Each outbound mesh request is now stamped with a timestamp + a single-use random nonce and an
// HMAC-SHA256 over (timestamp, nonce, sha256(body)) keyed by the shared mesh secret. The receiver rejects a
// request whose timestamp is outside the freshness window, whose signature does not verify (constant-time), or
// whose nonce was already seen within the window. The HMAC also gives integrity (the body cannot be tampered)
// without putting the secret on the wire in a forgeable position.
//
// This layers ON TOP of meshIngressAuth (mTLS allowlist / secret) — it does not replace authorization. It is
// active only when a shared secret is configured (the HMAC needs a key); a pure mTLS-allowlist link with no
// secret relies on the per-connection mTLS handshake, which is not itself replayable.

const (
	meshAntiReplayWindow  = 5 * time.Minute
	meshTimestampHeader   = "x-mesh-ts"
	meshNonceHeader       = "x-mesh-nonce"
	meshSignatureHeader   = "x-mesh-sig"
	meshNonceLengthBytes  = 16
	meshReplayGuardMaxLen = 100_000 // safety cap on the nonce cache (each entry expires after the window)
)

// Process-level nonce caches: one per mesh ingress (the data-plane tunnel upgrade and the revocation push).
var (
	revocationMeshReplayGuard = newMeshReplayGuard(meshAntiReplayWindow)
	dataMeshReplayGuard       = newMeshReplayGuard(meshAntiReplayWindow)
)

// meshRequestSignature is the HMAC-SHA256 over the canonical (ts \n nonce \n sha256(body)) keyed by secret.
func meshRequestSignature(secret, ts, nonce string, body []byte) string {
	bodySum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write(bodySum[:])
	return hex.EncodeToString(mac.Sum(nil))
}

// signMeshRequest stamps anti-replay headers (ts, nonce, signature) on an outbound mesh request. No-op when no
// secret is configured (the link relies on mTLS, which is not replayable).
func signMeshRequest(h http.Header, secret string, body []byte, now time.Time) {
	if secret == "" {
		return
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	nonceRaw := make([]byte, meshNonceLengthBytes)
	if _, err := rand.Read(nonceRaw); err != nil {
		// Fail-safe: without a fresh nonce we omit the headers; the receiver still has the secret/mTLS auth.
		return
	}
	nonce := hex.EncodeToString(nonceRaw)
	h.Set(meshTimestampHeader, ts)
	h.Set(meshNonceHeader, nonce)
	h.Set(meshSignatureHeader, meshRequestSignature(secret, ts, nonce, body))
}

// verifyMeshAntiReplay validates the anti-replay headers on an inbound mesh request: presence, freshness,
// HMAC signature, and nonce uniqueness. Returns nil when the request is fresh and authentic. When secret is
// empty it is a no-op (mTLS-only link). guard may be nil only when secret is empty.
func verifyMeshAntiReplay(h http.Header, secret string, body []byte, guard *meshReplayGuard, now time.Time) error {
	if secret == "" {
		return nil
	}
	ts := h.Get(meshTimestampHeader)
	nonce := h.Get(meshNonceHeader)
	sig := h.Get(meshSignatureHeader)
	if ts == "" || nonce == "" || sig == "" {
		return fmt.Errorf("missing mesh anti-replay headers (ts/nonce/sig)")
	}
	tsec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid mesh timestamp")
	}
	reqTime := time.Unix(tsec, 0)
	age := now.Sub(reqTime)
	if age < -meshAntiReplayWindow || age > meshAntiReplayWindow {
		return fmt.Errorf("mesh request timestamp outside freshness window")
	}
	want := meshRequestSignature(secret, ts, nonce, body)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return fmt.Errorf("mesh request signature mismatch")
	}
	if guard != nil && !guard.checkAndRecord(nonce, reqTime, now) {
		return fmt.Errorf("mesh request nonce replay")
	}
	return nil
}

// meshReplayGuard remembers recently-seen nonces until they can no longer be replayed within the freshness
// window, rejecting duplicates. Eviction is O(log n) per expired entry via a min-heap ordered by expiry —
// the old code re-scanned the ENTIRE nonce map on every request (O(N) per request, O(N^2) under load, a
// CPU-amplification lever, review #31). A hard cap bounds memory if eviction can't keep up.
type meshReplayGuard struct {
	mu     sync.Mutex
	seen   map[string]time.Time // nonce -> expiry (for the replay lookup)
	exp    meshExpiryHeap       // min-heap of (expiry, nonce) for ordered eviction
	window time.Duration
}

func newMeshReplayGuard(window time.Duration) *meshReplayGuard {
	return &meshReplayGuard{seen: make(map[string]time.Time), window: window}
}

// checkAndRecord returns true if the nonce is fresh (unseen and still replayable within the window) and
// records it; false if it was already seen (a replay) or the cache is full. reqTime is the request's OWN
// timestamp: the nonce is retained until reqTime+window, i.e. exactly the end of that request's freshness
// window. Retaining only until now+window (the old behavior) forgot a nonce before the freshness window
// closed when the sender clock was AHEAD, re-opening a replay window (review #31).
func (g *meshReplayGuard) checkAndRecord(nonce string, reqTime, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	// Evict only the entries that have actually expired, cheapest-first off the heap top.
	for len(g.exp) > 0 && !g.exp[0].expiry.After(now) {
		ev := heap.Pop(&g.exp).(meshExpiryEntry)
		// Only drop from the map if the map still points at THIS entry's expiry (defends against a
		// re-inserted nonce, though single-use random nonces make that vanishingly unlikely).
		if e, ok := g.seen[ev.nonce]; ok && e.Equal(ev.expiry) {
			delete(g.seen, ev.nonce)
		}
	}
	if exp, ok := g.seen[nonce]; ok && !now.After(exp) {
		return false // replay
	}
	if len(g.seen) >= meshReplayGuardMaxLen {
		// Cache is full of still-fresh nonces (extreme load / attack). Fail closed: reject rather than forget a
		// nonce and admit a replay.
		return false
	}
	expiry := reqTime.Add(g.window)
	g.seen[nonce] = expiry
	heap.Push(&g.exp, meshExpiryEntry{nonce: nonce, expiry: expiry})
	return true
}

// meshExpiryEntry is a (nonce, expiry) pair on the eviction heap.
type meshExpiryEntry struct {
	nonce  string
	expiry time.Time
}

// meshExpiryHeap is a min-heap of meshExpiryEntry ordered by expiry (earliest at the top), implementing
// container/heap.Interface so expired nonces are evicted in O(log n) instead of an O(n) full scan.
type meshExpiryHeap []meshExpiryEntry

func (h meshExpiryHeap) Len() int           { return len(h) }
func (h meshExpiryHeap) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }
func (h meshExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *meshExpiryHeap) Push(x any)        { *h = append(*h, x.(meshExpiryEntry)) }
func (h *meshExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	*h = old[:n-1]
	return entry
}
