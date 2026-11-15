package dnsresolver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type reviewPolicyOnlyUpstream struct{ calls int }

func (u *reviewPolicyOnlyUpstream) Resolve([]byte) ([]byte, error) {
	u.calls++
	return nil, fmt.Errorf("this policy answer must not need an upstream")
}

func TestPolicyAnswersRemainAvailableByName(t *testing.T) {
	for _, action := range []string{"stub", "sinkhole"} {
		t.Run(action, func(t *testing.T) {
			const name = "application.internal.example"
			const answer = "10.55.1.31"
			now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
			ct := dns.NewConntrackStore()
			upstream := &reviewPolicyOnlyUpstream{}
			r := NewWithUpstream("tenant-a", upstream, ct)
			dto := PolicyDTO{}
			if action == "stub" {
				dto.StubIPv4 = map[string]string{name: answer}
			} else {
				dto.Sinkhole = map[string]string{name: answer}
			}
			pol, err := PolicyFromDTO(dto)
			if err != nil {
				t.Fatal(err)
			}
			r.SetPolicy(pol)
			raw, err := r.HandleQueryForTenant(context.Background(), "tenant-a", dnsQuery(t, name+".", dnsmessage.TypeA), now)
			if err != nil {
				t.Fatal(err)
			}
			returned := ExtractResolvedIPs(raw)
			if len(returned) != 1 || returned[0] != answer || upstream.calls != 0 {
				t.Fatalf("invalid fixture response=%v calls=%d", returned, upstream.calls)
			}
			named := ct.LookupAddresses("tenant-a", name, now)
			t.Logf("policy=%s returned=%v named=%v upstream_calls=%d", action, returned, named, upstream.calls)
			if len(named) != 1 || named[0] != answer {
				t.Error("the Edge's own policy answer is missing from the trusted named-flow address index")
			}
			if got := ct.LookupAddresses("tenant-b", name, now); len(got) != 0 {
				t.Errorf("other tenant has answers: %v", got)
			}
		})
	}
}
