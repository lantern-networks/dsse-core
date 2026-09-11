package interception

import "container/list"

// lru is a bounded, least-recently-used map keyed by string. Under decrypt-all the interception engine keys
// per-SNI state (leaf certs, handshake-failure counts, ever-succeeded marks) by the CLIENT-CONTROLLED SNI,
// so a plain map grows one entry per distinct SNI forever — a memory-exhaustion lever (review #22). The LRU
// caps the working set and evicts the least-recently-used entry on overflow. It is NOT safe for concurrent
// use; every caller holds the Engine mutex.
type lru[V any] struct {
	cap int
	ll  *list.List // front = most recently used
	m   map[string]*list.Element
}

type lruEntry[V any] struct {
	key string
	val V
}

// newLRU builds a bounded LRU. A cap <= 0 is treated as 1 (a cache must hold at least one entry).
func newLRU[V any](capacity int) *lru[V] {
	if capacity <= 0 {
		capacity = 1
	}
	return &lru[V]{cap: capacity, ll: list.New(), m: map[string]*list.Element{}}
}

// get returns the value for key and marks it most-recently-used.
func (c *lru[V]) get(key string) (V, bool) {
	if el, ok := c.m[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruEntry[V]).val, true
	}
	var zero V
	return zero, false
}

// peek returns the value for key WITHOUT changing its recency (for read-only guards).
func (c *lru[V]) peek(key string) (V, bool) {
	if el, ok := c.m[key]; ok {
		return el.Value.(*lruEntry[V]).val, true
	}
	var zero V
	return zero, false
}

// put inserts or updates key, marks it most-recently-used, and evicts the least-recently-used entry when
// the cache exceeds its cap.
func (c *lru[V]) put(key string, val V) {
	if el, ok := c.m[key]; ok {
		el.Value.(*lruEntry[V]).val = val
		c.ll.MoveToFront(el)
		return
	}
	c.m[key] = c.ll.PushFront(&lruEntry[V]{key: key, val: val})
	if c.ll.Len() > c.cap {
		if back := c.ll.Back(); back != nil {
			c.ll.Remove(back)
			delete(c.m, back.Value.(*lruEntry[V]).key)
		}
	}
}

// delete removes key if present.
func (c *lru[V]) delete(key string) {
	if el, ok := c.m[key]; ok {
		c.ll.Remove(el)
		delete(c.m, key)
	}
}

// len reports the number of cached entries.
func (c *lru[V]) len() int { return c.ll.Len() }
