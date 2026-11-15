package dns

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestNameIndexCountersAndProvenance(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, capacity := range []int{1, 3, 17} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			s := NewConntrackStore()
			s.capacity = capacity
			rng := rand.New(rand.NewSource(42))
			for i := 0; i < 10000; i++ {
				at := now.Add(time.Duration(i) * time.Second)
				tenant := fmt.Sprintf("tenant-%d", rng.Intn(2))
				name := fmt.Sprintf("app-%d.internal.example", rng.Intn(10))
				ip := fmt.Sprintf("192.0.2.%d", 1+rng.Intn(16))
				req := ObservationRequest{TenantID: tenant, FQDN: name, ResolvedIPs: []string{ip}, TTLSeconds: 1 + rng.Intn(5)}
				switch rng.Intn(3) {
				case 0:
					s.RecordEdgeAnswer(req, at)
				case 1:
					s.LookupAddresses(tenant, name, at)
				case 2:
					s.Record(req, at)
				}
				sum := 0
				seen := map[string]bool{}
				for _, set := range s.byName {
					sum += len(set)
				}
				for _, key := range s.nameOrder {
					if seen[key] {
						t.Fatalf("duplicate FIFO at %d", i)
					}
					seen[key] = true
					if _, ok := s.byName[key]; !ok {
						t.Fatalf("stale FIFO at %d", i)
					}
				}
				if sum != s.nameAddresses || sum > capacity || len(s.nameOrder) != len(s.byName) {
					t.Fatalf("step=%d entries=%d counted=%d capacity=%d names=%d FIFO=%d", i, sum, s.nameAddresses, capacity, len(s.byName), len(s.nameOrder))
				}
			}
		})
	}
	s := NewConntrackStore()
	s.RecordEdgeAnswer(ObservationRequest{TenantID: "t", FQDN: "app.internal.example", ResolvedIPs: []string{"192.0.2.1"}, TTLSeconds: 2}, now)
	s.Record(ObservationRequest{TenantID: "t", FQDN: "app.internal.example", ResolvedIPs: []string{"192.0.2.2"}, TTLSeconds: 300}, now.Add(time.Second))
	got := s.LookupAddresses("t", "app.internal.example", now.Add(time.Second))
	if len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("observation modified trusted answer: %v", got)
	}
	if got := s.LookupAddresses("t", "app.internal.example", now.Add(3*time.Second)); len(got) != 0 {
		t.Fatalf("observation extended trusted lifetime: %v", got)
	}
}
