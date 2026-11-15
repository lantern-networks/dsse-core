package dnsresolver

import (
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lantern-networks/dsse-core/dns"
)

func answerWithLifetime(t *testing.T, name string, ttl uint32) []byte {
	t.Helper()
	n := dnsmessage.MustNewName(name)
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
			Body:   &dnsmessage.AResource{A: [4]byte{10, 55, 1, 30}},
		}},
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Found on a Windows walk (2026-11-14): a private application reached by name was refused about five minutes
// after the device last asked for the name. The answer the device held was good for an hour; this resolver
// remembered which name the address belonged to for five minutes.
func TestTheNameForAnAddressIsKeptForAsLongAsTheDeviceMayUseTheAddress(t *testing.T) {
	ct := dns.NewConntrackStore()
	r := NewWithUpstream("tenant", fakeUpstream{resp: answerWithLifetime(t, "wiki.corp.example.", 3600)}, ct)
	now := time.Now()
	out, err := r.HandleQuery(dnsQuery(t, "wiki.corp.example.", dnsmessage.TypeA), now)
	if err != nil {
		t.Fatal(err)
	}
	given := longestAddressLifetime(out)
	if given == 0 || given > uint32(dns.ConntrackDefaultTTLSeconds) {
		t.Fatalf("the device was given the address for %d seconds; it will not ask again for that long, and an Edge that restarts in between has no name for it", given)
	}
	// Every moment at which the device may still be using the address, the name is known.
	for _, after := range []time.Duration{time.Second, time.Duration(given) * time.Second, time.Duration(given)*time.Second + 30*time.Second} {
		if _, _, ok := ct.LookupFQDN("tenant", "10.55.1.30", now.Add(after)); !ok {
			t.Fatalf("%s after the answer the device still holds the address and the name is gone", after)
		}
	}
	// And it is not kept for ever.
	if _, _, ok := ct.LookupFQDN("tenant", "10.55.1.30", now.Add(time.Duration(given)*time.Second+10*time.Minute)); ok {
		t.Fatal("the name outlived the device's cache by ten minutes")
	}
}

func TestAShortLivedAnswerIsHandedOverUnchanged(t *testing.T) {
	raw := answerWithLifetime(t, "cdn.example.", 20)
	ct := dns.NewConntrackStore()
	r := NewWithUpstream("tenant", fakeUpstream{resp: raw}, ct)
	now := time.Now()
	out, err := r.HandleQuery(dnsQuery(t, "cdn.example.", dnsmessage.TypeA), now)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Fatal("an answer already shorter than the limit was rewritten")
	}
	// The name is still kept for the ordinary five minutes, as before.
	if _, _, ok := ct.LookupFQDN("tenant", "10.55.1.30", now.Add(4*time.Minute)); !ok {
		t.Fatal("a short-lived answer's name was forgotten sooner than it used to be")
	}
}

func TestAnAnswerThatCannotBeReadIsNotRewritten(t *testing.T) {
	junk := []byte{0x01, 0x02, 0x03}
	if out, ok := withAddressLifetimeAtMost(junk, 300); ok || string(out) != string(junk) {
		t.Fatal("an unreadable answer was reported as shortened, or changed")
	}
}

// Review finding (2026-11-14): shortening a lifetime inside a TSIG-signed answer, and keeping the signature,
// makes a correct answer fail its check at the client. Such an answer is handed over byte for byte, and the
// name is remembered for the lifetime it really carries.
func TestASignedAnswerIsHandedOverUntouchedAndItsNameKeptForItsWholeLifetime(t *testing.T) {
	n := dnsmessage.MustNewName("wiki.corp.example.")
	key := dnsmessage.MustNewName("device-key.")
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 3600},
			Body:   &dnsmessage.AResource{A: [4]byte{10, 55, 1, 30}},
		}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: key, Type: dnsTypeTSIG, Class: dnsmessage.ClassANY, TTL: 0},
			Body:   &dnsmessage.UnknownResource{Type: dnsTypeTSIG, Data: []byte("a signature over every byte of this message")},
		}},
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if out, ok := withAddressLifetimeAtMost(raw, 300); ok || string(out) != string(raw) {
		t.Fatal("a signed answer was rewritten, or reported as shortened")
	}
	ct := dns.NewConntrackStore()
	r := NewWithUpstream("tenant", fakeUpstream{resp: raw}, ct)
	now := time.Now()
	out, err := r.HandleQuery(dnsQuery(t, "wiki.corp.example.", dnsmessage.TypeA), now)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Fatal("the device was handed a signed answer that is not the one the upstream signed")
	}
	// The device may use the address for the full hour; the name is there for all of it.
	if _, _, ok := ct.LookupFQDN("tenant", "10.55.1.30", now.Add(59*time.Minute)); !ok {
		t.Fatal("the name was forgotten while the device's signed answer was still good")
	}
}
