package dnsresolver

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func TestResolverRejectsUnrelatedUpstreamResponse(t *testing.T) {
	for _, name := range []string{"id", "name", "type", "class", "query", "opcode", "missing question", "extra question"} {
		t.Run(name, func(t *testing.T) {
			var response dnsmessage.Message
			if err := response.Unpack(dnsAplusHTTPSEch(t, "app.example.", [4]byte{192, 0, 2, 5})); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "id":
				response.ID++
			case "name":
				response.Questions[0].Name = dnsmessage.MustNewName("other.example.")
			case "type":
				response.Questions[0].Type = dnsmessage.TypeAAAA
			case "class":
				response.Questions[0].Class = dnsmessage.ClassCHAOS
			case "query":
				response.Response = false
			case "opcode":
				response.OpCode = 5
			case "missing question":
				response.Questions = nil
			case "extra question":
				response.Questions = append(response.Questions, response.Questions[0])
			}
			raw, err := response.Pack()
			if err != nil {
				t.Fatal(err)
			}
			ct := dns.NewConntrackStore()
			r := NewWithUpstream("tenant", fakeUpstream{resp: raw}, ct)
			now := time.Now()
			if _, err := r.HandleQuery(dnsQuery(t, "app.example.", dnsmessage.TypeA), now); err == nil {
				t.Fatal("unrelated upstream reply was accepted")
			}
			if _, _, ok := ct.LookupFQDN("tenant", "192.0.2.5", now); ok {
				t.Fatal("unrelated reply populated conntrack")
			}
		})
	}
}
