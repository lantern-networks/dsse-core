package policycandidate

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestManualCertPinRegistrationRequiresAnExactName(t *testing.T) {
	invalid := []string{"", "*", "*.example.com", ".example.com", "example..com", "https://example.com/path", "example.com/path", "user@example.com", "example.com:443", "example.com?x", "example.com#x", "example%2ecom", "a\\b.example", "a_b.example", "-a.example", "a-.example", "198.51.100.10", "[2001:db8::1]", "2001:db8::1", "198.51.100.0/24", "127.1", "2130706433", "0x7f000001", "127.0.0.0x1", strings.Repeat("9", 50), strings.Repeat("a", 64) + ".example"}
	for _, host := range invalid {
		s := NewStore()
		p := &candidateTestPersister{}
		s.SetPersister(p)
		if _, e := s.AddManualCertPinBypass(context.Background(), "own", host, time.Now()); e == nil || len(p.data) != 0 || len(s.candidates) != 0 {
			t.Fatalf("accepted %q or changed state", host)
		}
	}
	for _, tc := range []struct{ input, want string }{{" API.Example.COM. ", "api.example.com"}, {"localhost", "localhost"}, {"\u4f8b\u3048.\u30c6\u30b9\u30c8", "xn--r8jz45g.xn--zckzah"}} {
		s := NewStore()
		c, e := s.AddManualCertPinBypass(context.Background(), "own", tc.input, time.Now())
		if e != nil || c.Host != tc.want {
			t.Fatalf("%q: %+v %v", tc.input, c, e)
		}
	}
	t.Logf("rejected %d unsafe manual inputs", len(invalid))
}
func TestCertPinTargetUsesNamedSNIInsteadOfSharedIP(t *testing.T) {
	for _, tc := range []struct {
		host, sni, want string
		risk            bool
		bad             bool
	}{
		{"named.example", "different.example", "named.example", false, false},
		{"203.0.113.7", "SNI.Example.", "sni.example", false, false},
		{"2001:db8::1", "sni.example", "sni.example", false, false},
		{"", "sni.example", "sni.example", false, false},
		{"203.0.113.7", "", "203.0.113.7", true, false},
		{"2001:0db8::1", "", "", false, true},
		{"", "2001:db8::1", "", false, true},
		{"::ffff:192.0.2.1", "", "", false, true},
		{"", "203.0.113.7", "203.0.113.7", true, false},
		{"*", "sni.example", "", false, true},
		{"*.example", "", "", false, true},
		{"203.0.113.7", "*.example", "", false, true},
		{"198.51.100.0/24", "", "", false, true},
	} {
		got, risk, e := CertPinBypassTarget(Candidate{Host: tc.host, SNI: tc.sni})
		if got != tc.want || risk != tc.risk || (e != nil) != tc.bad {
			t.Fatalf("%+v => %q %v %v", tc, got, risk, e)
		}
	}
}
func TestCertPinMaterializeRecomputesRiskBeforeSaving(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	for _, host := range []string{"198.51.100.10", "*", "*.example", "198.51.100.0/24", "2001:0db8::1", "::ffff:192.0.2.1"} {
		s := NewStore()
		p := &candidateTestPersister{}
		s.SetPersister(p)
		c, e := s.ObserveCertPinFailure(ctx, "own", host, "", 443, "pin", now)
		if e != nil {
			t.Fatal(e)
		}
		c.Status = "approved"
		c.SuggestedAction = "review"
		c.Confidence = "high"
		c.AttributionSource = attributionSourceDNSTunnel
		if _, e = s.Upsert(ctx, c, "own", now); e != nil {
			t.Fatal(e)
		}
		before := bytes.Clone(p.data)
		live, _, _ := s.Get(ctx, "own", c.CandidateID)
		if _, _, e = s.Materialize(ctx, "own", c.CandidateID, false, now); e == nil || !bytes.Equal(before, p.data) {
			t.Fatal("advisory metadata bypassed scope gate")
		}
		after, _, _ := s.Get(ctx, "own", c.CandidateID)
		if !reflect.DeepEqual(after, live) {
			t.Fatal("rejected adoption changed live evidence")
		}
		result, _, e := s.Materialize(ctx, "own", c.CandidateID, true, now)
		if host == "198.51.100.10" {
			if e != nil || result.Confidence != "low" || result.SuggestedAction != "investigate_only" {
				t.Fatal("exact IP override", e, result)
			}
		} else if e == nil || !bytes.Equal(before, p.data) {
			t.Fatal("override permitted broad target")
		}
	}
	// Stale risk labels do not prevent adopting an independently identifiable name.
	s := NewStore()
	c, _ := s.ObserveCertPinFailure(ctx, "own", "203.0.113.7", "sni.example", 443, "pin", now)
	c.Status = "approved"
	c.SuggestedAction = "investigate_only"
	s.Upsert(ctx, c, "own", now)
	if _, _, e := s.Materialize(ctx, "own", c.CandidateID, false, now); e != nil {
		t.Fatal(e)
	}
}
