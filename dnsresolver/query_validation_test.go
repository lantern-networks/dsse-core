package dnsresolver

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type countedUpstream struct{ calls int }

func (u *countedUpstream) Resolve(raw []byte) ([]byte, error) {
	u.calls++
	return raw, nil
}

func TestResolverRefusesUninspectableQueriesBeforeForwarding(t *testing.T) {
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("allowed.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	blocked := question
	blocked.Name = dnsmessage.MustNewName("blocked.example.")
	cases := map[string]dnsmessage.Message{
		"no question":              {},
		"second blocked question":  {Questions: []dnsmessage.Question{question, blocked}},
		"response passed as query": {Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{question}},
		"non-query opcode":         {Header: dnsmessage.Header{OpCode: 5}, Questions: []dnsmessage.Question{question}},
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := msg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			u := &countedUpstream{}
			r := NewWithUpstream("tenant", u, dns.NewConntrackStore())
			p, err := PolicyFromDTO(PolicyDTO{Deny: []string{"blocked.example"}})
			if err != nil {
				t.Fatal(err)
			}
			r.SetPolicy(p)
			out, err := r.HandleQuery(raw, time.Now())
			if u.calls != 0 {
				t.Fatal("uninspectable query reached the upstream")
			}
			var reply dnsmessage.Message
			if err == nil && (reply.Unpack(out) != nil || !reply.Response || reply.RCode == dnsmessage.RCodeSuccess) {
				t.Fatal("uninspectable query was not refused")
			}
		})
	}
	t.Run("malformed wire", func(t *testing.T) {
		u := &countedUpstream{}
		r := NewWithUpstream("tenant", u, dns.NewConntrackStore())
		if _, err := r.HandleQuery([]byte{1, 2}, time.Now()); err == nil || u.calls != 0 {
			t.Fatal("malformed query was forwarded")
		}
	})
}

func TestResolverSupportsOmittedOptionalConntrack(t *testing.T) {
	r := NewWithUpstream("tenant", fakeUpstream{resp: dnsAplusHTTPSEch(t, "app.example.", [4]byte{203, 0, 113, 5})}, nil)
	if _, err := r.HandleQuery(dnsQuery(t, "app.example.", dnsmessage.TypeA), time.Now()); err != nil {
		t.Fatal(err)
	}
	p, err := PolicyFromDTO(PolicyDTO{Sinkhole: map[string]string{"app.example": "192.0.2.5"}})
	if err != nil {
		t.Fatal(err)
	}
	r.SetPolicy(p)
	if _, err := r.HandleQuery(dnsQuery(t, "app.example.", dnsmessage.TypeA), time.Now()); err != nil {
		t.Fatal(err)
	}
}
