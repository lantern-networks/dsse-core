package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// dnsQuery builds a minimal single-question DNS query (qtype A / qclass IN) for name with transaction id txid.
func dnsQuery(txid uint16, name string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], txid)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	msg = append(msg, encodeName(name)...)
	msg = append(msg, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	return msg
}

// dnsResponse builds a reply to dnsQuery(name) with one A answer carrying ttl.
func dnsResponse(txid uint16, name string, ttl uint32) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], txid)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180) // QR + RD + RA
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(msg[6:8], 1)      // ANCOUNT
	q := encodeName(name)
	msg = append(msg, q...)
	msg = append(msg, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	// Answer: name = compression pointer to the question at offset 12.
	msg = append(msg, 0xC0, 0x0C)
	msg = append(msg, 0, 1, 0, 1) // TYPE A, CLASS IN
	ttlb := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlb, ttl)
	msg = append(msg, ttlb...)
	msg = append(msg, 0, 4)             // RDLENGTH
	msg = append(msg, 93, 184, 216, 34) // RDATA (an IPv4)
	return msg
}

func encodeName(name string) []byte {
	var out []byte
	for len(name) > 0 {
		dot := len(name)
		for i := 0; i < len(name); i++ {
			if name[i] == '.' {
				dot = i
				break
			}
		}
		label := name[:dot]
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
		if dot == len(name) {
			break
		}
		name = name[dot+1:]
	}
	out = append(out, 0)
	return out
}

func TestDNSCacheHitMissExpiryAndTxidRewrite(t *testing.T) {
	c := newDNSCache()
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }

	q1 := dnsQuery(0x1111, "example.com")
	resp := dnsResponse(0x1111, "example.com", 30)

	// Miss before put.
	if _, ok := c.get(q1); ok {
		t.Fatalf("expected miss before put")
	}
	c.put(q1, resp)

	// Hit for a DIFFERENT transaction id; the returned response carries the asking txid.
	q2 := dnsQuery(0x2222, "EXAMPLE.com") // different case + txid: same question key
	got, ok := c.get(q2)
	if !ok {
		t.Fatalf("expected cache hit for same question (case-insensitive)")
	}
	if binary.BigEndian.Uint16(got[0:2]) != 0x2222 {
		t.Fatalf("response txid = %04x, want 2222 (rewritten to the asking query)", binary.BigEndian.Uint16(got[0:2]))
	}

	// Still a hit just before expiry; a miss after the 30s TTL.
	now = now.Add(29 * time.Second)
	if _, ok := c.get(q1); !ok {
		t.Fatalf("expected hit before TTL expiry")
	}
	now = now.Add(2 * time.Second) // now 31s > 30s TTL
	if _, ok := c.get(q1); ok {
		t.Fatalf("expected miss after TTL expiry")
	}
}

func TestDNSCacheRespectsTTLCapAndSkipsZeroTTL(t *testing.T) {
	c := newDNSCache()
	now := time.Unix(2_000_000, 0)
	c.now = func() time.Time { return now }

	// High TTL is capped at maxTTL (60s): a hit at 59s, miss at 61s.
	q := dnsQuery(1, "long.example")
	c.put(q, dnsResponse(1, "long.example", 86400))
	now = now.Add(59 * time.Second)
	if _, ok := c.get(q); !ok {
		t.Fatalf("expected hit within the 60s cap")
	}
	now = now.Add(2 * time.Second)
	if _, ok := c.get(q); ok {
		t.Fatalf("expected miss past the 60s cap")
	}

	// TTL 0 is never cached.
	qz := dnsQuery(2, "zero.example")
	c.put(qz, dnsResponse(2, "zero.example", 0))
	if _, ok := c.get(qz); ok {
		t.Fatalf("ttl=0 must not be cached")
	}
}

func TestDNSMinTTLParsesAnswer(t *testing.T) {
	ttl, ok := dnsMinTTL(dnsResponse(1, "a.example", 42))
	if !ok || ttl != 42 {
		t.Fatalf("dnsMinTTL = %d,%v want 42,true", ttl, ok)
	}
	if _, ok := dnsMinTTL(dnsQuery(1, "a.example")); ok {
		t.Fatalf("a query with no answers must not yield a TTL")
	}
}
