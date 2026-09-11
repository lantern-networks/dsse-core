package dnsresolver

import (
	"bytes"
	"github.com/lantern-networks/dsse-core/dns"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeUpstreamDNS returns a canned response for any query (so the over-tunnel path is testable offline).
type fakeUpstreamDNS struct{ reply []byte }

func (f fakeUpstreamDNS) Resolve(_ []byte) ([]byte, error) { return f.reply, nil }

func TestDNSOverTunnelHandlerResolvesAndDenies(t *testing.T) {
	// Build an A-record response the fake upstream will return for forwarded queries.
	upResp := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("app.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("app.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
		}},
	}
	upRaw, err := upResp.Pack()
	if err != nil {
		t.Fatalf("pack upstream: %v", err)
	}

	resolver := NewWithUpstream("t1", fakeUpstreamDNS{reply: upRaw}, dns.NewConntrackStore())
	echOff := false
	denyPol, _ := PolicyFromDTO(PolicyDTO{Deny: []string{"blocked.example.com"}, ECHStrip: &echOff})
	resolver.SetPolicy(denyPol)
	handler := OverTunnelHandler(resolver)

	query := func(name string) []byte {
		q := dnsmessage.Message{
			Header:    dnsmessage.Header{RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		}
		raw, perr := q.Pack()
		if perr != nil {
			t.Fatalf("pack query: %v", perr)
		}
		return raw
	}

	// Allowed name -> forwarded, returns the A record over the tunnel (application/dns-message).
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/steer/dns-query", bytes.NewReader(query("app.example.com."))))
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed query: status=%d", rec.Code)
	}
	if ct := rec.Header().Get("content-type"); ct != dnsMessageContentType {
		t.Fatalf("content-type=%q want %q", ct, dnsMessageContentType)
	}
	if ips := ExtractResolvedIPs(rec.Body.Bytes()); len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("expected the upstream A record back, got %v", ips)
	}

	// Denied name -> NXDOMAIN response (still 200 at HTTP; the DNS rcode carries the deny).
	rec2 := httptest.NewRecorder()
	handler(rec2, httptest.NewRequest(http.MethodPost, "/steer/dns-query", bytes.NewReader(query("blocked.example.com."))))
	if rec2.Code != http.StatusOK {
		t.Fatalf("denied query http status=%d", rec2.Code)
	}
	var dr dnsmessage.Message
	if err := dr.Unpack(rec2.Body.Bytes()); err != nil {
		t.Fatalf("unpack deny response: %v", err)
	}
	if dr.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("denied name should be NXDOMAIN, got rcode=%v", dr.Header.RCode)
	}
}

func TestDNSOverTunnelHandlerRejectsEmptyBody(t *testing.T) {
	resolver := NewWithUpstream("t1", fakeUpstreamDNS{}, dns.NewConntrackStore())
	rec := httptest.NewRecorder()
	OverTunnelHandler(resolver)(rec, httptest.NewRequest(http.MethodPost, "/steer/dns-query", bytes.NewReader(nil)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body should be 400, got %d", rec.Code)
	}
}
