package dns

import (
	"sort"
	"testing"
	"time"
)

func TestTheAnswersForANameCanBeAskedForByName(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	s := NewConntrackStore()
	s.RecordEdgeAnswer(ObservationRequest{TenantID: "t1", FQDN: "Wiki.Corp.", ResolvedIPs: []string{"10.0.0.2", "10.0.0.1"}, TTLSeconds: 60}, now)
	s.RecordEdgeAnswer(ObservationRequest{TenantID: "t2", FQDN: "wiki.corp", ResolvedIPs: []string{"10.9.9.9"}, TTLSeconds: 60}, now)

	got := s.LookupAddresses("t1", "wiki.corp", now)
	sort.Strings(got)
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("t1 wiki.corp = %v", got)
	}
	if got := s.LookupAddresses("t2", "WIKI.corp.", now); len(got) != 1 || got[0] != "10.9.9.9" {
		t.Fatalf("t2 = %v, want only its own answer", got)
	}

	// Several names commonly share an address. A later name resolved to it does not take it from the earlier
	// one: the address-to-name side keeps only the latest name, the name-to-address side keeps both.
	s.RecordEdgeAnswer(ObservationRequest{TenantID: "t1", FQDN: "files.corp", ResolvedIPs: []string{"10.0.0.2"}, TTLSeconds: 60}, now)
	got = s.LookupAddresses("t1", "wiki.corp", now)
	sort.Strings(got)
	if len(got) != 2 || got[1] != "10.0.0.2" {
		t.Fatalf("after files.corp also resolved to 10.0.0.2, wiki.corp = %v", got)
	}
	if got := s.LookupAddresses("t1", "files.corp", now); len(got) != 1 || got[0] != "10.0.0.2" {
		t.Fatalf("files.corp = %v", got)
	}
	if name, _, _ := s.LookupFQDN("t1", "10.0.0.2", now); name != "files.corp" {
		t.Fatalf("the address-to-name side names the latest, got %q", name)
	}
	// A lapsed answer is not returned.
	if got := s.LookupAddresses("t1", "wiki.corp", now.Add(61*time.Second)); len(got) != 0 {
		t.Fatalf("lapsed = %v", got)
	}
}

func TestTheNameIndexIsBoundedLikeTheAddresses(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	s := NewConntrackStore()
	s.capacity = 2
	s.RecordEdgeAnswer(ObservationRequest{TenantID: "t", FQDN: "a.corp", ResolvedIPs: []string{"10.0.0.1"}}, now)
	s.RecordEdgeAnswer(ObservationRequest{TenantID: "t", FQDN: "b.corp", ResolvedIPs: []string{"10.0.0.2"}}, now)
	s.RecordEdgeAnswer(ObservationRequest{TenantID: "t", FQDN: "c.corp", ResolvedIPs: []string{"10.0.0.3"}}, now)
	if got := s.LookupAddresses("t", "a.corp", now); len(got) != 0 {
		t.Fatalf("evicted a.corp still answers %v", got)
	}
	if _, ok := s.byName[nameKey("t", "a.corp")]; ok {
		t.Fatal("the name index kept a name beyond its capacity")
	}
	if got := s.LookupAddresses("t", "c.corp", now); len(got) != 1 {
		t.Fatalf("c.corp = %v", got)
	}
}
