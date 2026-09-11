package dnsech

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// buildHTTPSRdata: SvcPriority(1) + root target + alpn(key1, "h2") + ech(key5, 4 bytes).
func buildHTTPSRdata(withECH bool) []byte {
	d := []byte{0x00, 0x01, 0x00} // priority=1, target=root(0x00)
	// alpn: key=1, len=3, value=[0x02 'h' '2']
	d = append(d, 0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2')
	if withECH {
		// ech: key=5, len=4, value=DEADBEEF
		d = append(d, 0x00, 0x05, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF)
	}
	return d
}

func httpsRdataParams(t *testing.T, raw []byte) map[uint16]bool {
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	keys := map[uint16]bool{}
	for _, rr := range m.Answers {
		if uint16(rr.Header.Type) != dnsTypeHTTPS {
			continue
		}
		// x/net dnsmessage parses HTTPS records into a typed *HTTPSResource with structured SvcParams.
		h, ok := rr.Body.(*dnsmessage.HTTPSResource)
		if !ok {
			t.Fatalf("expected *dnsmessage.HTTPSResource, got %T", rr.Body)
		}
		for _, p := range h.Params {
			keys[uint16(p.Key)] = true
		}
	}
	return keys
}

func TestStripECHFromDNSResponse(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	mk := func(withECH bool) []byte {
		m := dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true},
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.Type(dnsTypeHTTPS), Class: dnsmessage.ClassINET}},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.Type(dnsTypeHTTPS), Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.UnknownResource{Type: dnsmessage.Type(dnsTypeHTTPS), Data: buildHTTPSRdata(withECH)},
			}},
		}
		raw, err := m.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		return raw
	}

	// With ECH -> stripped, ech gone, alpn kept.
	out, n, err := StripECHFromDNSResponse(mk(true))
	if err != nil || n != 1 {
		t.Fatalf("strip with ech: n=%d err=%v", n, err)
	}
	keys := httpsRdataParams(t, out)
	if keys[svcParamKeyECH] {
		t.Fatalf("ech (key 5) should be removed")
	}
	if !keys[1] {
		t.Fatalf("alpn (key 1) should be preserved")
	}

	// Without ECH -> no change, n=0.
	raw := mk(false)
	out2, n2, err2 := StripECHFromDNSResponse(raw)
	if err2 != nil || n2 != 0 {
		t.Fatalf("strip without ech: n=%d err=%v", n2, err2)
	}
	if len(out2) != len(raw) {
		t.Fatalf("no-ech message should be unchanged length")
	}

	// Garbage -> fail-open (returns input, err set, never panics/corrupts).
	if out3, n3, err3 := StripECHFromDNSResponse([]byte{0x01, 0x02}); err3 == nil || n3 != 0 || len(out3) != 2 {
		t.Fatalf("garbage should fail-open: n=%d err=%v", n3, err3)
	}
}

// TestStripECHFromRealCloudflareRecord runs the strip against a REAL HTTPS RR captured from
// crypto.cloudflare.com (dig -t HTTPS crypto.cloudflare.com @1.1.1.1). Unlike the synthetic case, ech
// (key 5) sits in the MIDDLE of the SvcParams (order: alpn, ipv4hint, ech, ipv6hint), so a correct strip
// must drop ech AND preserve every param after it — the exact wire shape clients actually receive. Proves
// the function works on real-world data.
func TestStripECHFromRealCloudflareRecord(t *testing.T) {
	// crypto.cloudflare.com. IN HTTPS — RDATA (133 bytes): pri=1 target=. alpn=h2 ipv4hint ech ipv6hint.
	const realRDATAHex = "0001000001000302683200040008A29F874FA29F884F000500470045FE0D00412A00200020C88D967C7399450D4E48CCCA34B9FE71324A488EDB21AC44C68B1647352A14680004000100010012636C6F7564666C6172652D6563682E636F6D000000060020260647000007000000000000A29F874F260647000007000000000000A29F884F"
	rdata, err := hex.DecodeString(realRDATAHex)
	if err != nil {
		t.Fatalf("decode real rdata: %v", err)
	}
	name := dnsmessage.MustNewName("crypto.cloudflare.com.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.Type(dnsTypeHTTPS), Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.Type(dnsTypeHTTPS), Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.UnknownResource{Type: dnsmessage.Type(dnsTypeHTTPS), Data: rdata},
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	// sanity: the real record really does carry ech before we strip it.
	if !httpsRdataParams(t, raw)[svcParamKeyECH] {
		t.Fatalf("test fixture should contain ech (key 5)")
	}

	out, n, err := StripECHFromDNSResponse(raw)
	if err != nil || n != 1 {
		t.Fatalf("strip real record: n=%d err=%v", n, err)
	}
	keys := httpsRdataParams(t, out)
	if keys[svcParamKeyECH] {
		t.Fatalf("ech (key 5) must be removed from the real record")
	}
	// every other param survives — alpn(1), ipv4hint(4), ipv6hint(6) — including the one AFTER ech.
	for _, k := range []uint16{1, 4, 6} {
		if !keys[k] {
			t.Fatalf("svcparam key %d must be preserved after stripping a middle ech", k)
		}
	}
	// the cleartext public_name no longer appears with its ECHConfig framing (defense-in-depth: the ECH
	// blob bytes are gone from the wire, not just the param header).
	if strings.Contains(hex.EncodeToString(out), strings.ToLower("FE0D0041")) {
		t.Fatalf("the ECHConfig body should be gone from the wire after strip")
	}
}
