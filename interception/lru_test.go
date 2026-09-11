package interception

import (
	"crypto/tls"
	"strconv"
	"testing"
)

func TestLRUEvictsLeastRecentlyUsed(t *testing.T) {
	c := newLRU[int](2)
	c.put("a", 1)
	c.put("b", 2)
	// Touch "a" so "b" becomes least-recently-used.
	if v, ok := c.get("a"); !ok || v != 1 {
		t.Fatalf("get(a) = %d,%v", v, ok)
	}
	c.put("c", 3) // over cap → evict LRU ("b")
	if _, ok := c.peek("b"); ok {
		t.Fatal("b should have been evicted as least-recently-used")
	}
	if _, ok := c.peek("a"); !ok {
		t.Fatal("a should survive (recently used)")
	}
	if _, ok := c.peek("c"); !ok {
		t.Fatal("c should be present")
	}
	if c.len() != 2 {
		t.Fatalf("len = %d, want 2 (capped)", c.len())
	}
}

func TestLRUPeekDoesNotReorder(t *testing.T) {
	c := newLRU[int](2)
	c.put("a", 1)
	c.put("b", 2)
	c.peek("a")   // peek must NOT mark "a" as recently used
	c.put("c", 3) // "a" is still LRU → evicted
	if _, ok := c.peek("a"); ok {
		t.Fatal("peek must not protect an entry from eviction")
	}
}

// Review #22: under decrypt-all the leaf cache is keyed by the client-controlled SNI. A flood of distinct
// SNIs must not grow the cache without bound — it is LRU-capped, so its size stays <= the cap.
func TestLeafCacheIsBounded(t *testing.T) {
	e, err := NewEngine([]string{"*"}, nil, CAOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	// Shrink the cap for the test so we don't mint 16k+ certs.
	e.leafCache = newLRU[*tls.Certificate](64)
	for i := 0; i < 500; i++ {
		if _, err := e.leafFor("host-" + strconv.Itoa(i) + ".example.com"); err != nil {
			t.Fatalf("leafFor: %v", err)
		}
	}
	e.mu.Lock()
	n := e.leafCache.len()
	e.mu.Unlock()
	if n > 64 {
		t.Fatalf("leaf cache grew to %d entries, want <= 64 (LRU cap)", n)
	}
}
