package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/dns"
	"github.com/lantern-networks/dsse-core/model"
)

func TestANameWhoseAddressIsRegisteredIsThatAddressesFlow(t *testing.T) {
	reg := connector.NewRegistry()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, c := range []model.ConnectorRegistration{
		{ID: "conn-hq", TenantID: "tenant-a", Status: "active",
			ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.55.1.16/28"}, FQDNDomains: []string{"wiki.hq.example"}}},
		{ID: "conn-b", TenantID: "tenant-b", Status: "active",
			ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"only-names.example"}}},
	} {
		c.PrivateBaseURL = "https://internal.invalid"
		if _, err := reg.Register(c, now); err != nil {
			t.Fatalf("register %s: %v", c.ID, err)
		}
	}
	answers := map[string][]net.IP{
		"files.hq.example":  {net.ParseIP("10.55.1.31")},
		"mixed.hq.example":  {net.ParseIP("203.0.113.9"), net.ParseIP("10.55.1.20")},
		"public.example":    {net.ParseIP("203.0.113.10")},
		"wiki.hq.example":   {net.ParseIP("10.55.1.31")},
		"mapped.hq.example": {net.ParseIP("::ffff:10.55.1.30")},
	}
	lookups := 0
	prev := observeResolver
	observeResolver = func(_ context.Context, host string) ([]net.IP, error) {
		lookups++
		return answers[host], nil
	}
	t.Cleanup(func() { observeResolver = prev; observeLocality = newObserveLocalityCache() })
	observeLocality = newObserveLocalityCache()
	ctx := context.Background()

	cases := []struct {
		tenant, host, want string
		ok                 bool
	}{
		{"tenant-a", "files.hq.example", "10.55.1.31", true},  // not declared by name, address registered
		{"tenant-a", "FILES.hq.example.", "10.55.1.31", true}, // one spelling
		{"tenant-a", "mixed.hq.example", "10.55.1.20", true},  // the registered answer among several
		{"tenant-a", "mapped.hq.example", "10.55.1.30", true}, // an IPv4-mapped answer is the IPv4 address
		{"tenant-a", "wiki.hq.example", "", false},            // declared by name, and no device was answered for it
		{"tenant-a", "public.example", "", false},             // outside every registered network
		{"tenant-a", "10.55.1.31", "", false},                 // already an address
		{"tenant-b", "files.hq.example", "", false},           // another tenant's networks are not this one's
	}
	for _, c := range cases {
		got, ok := registeredAddressBehindName(ctx, reg, nil, c.tenant, c.host, now)
		if got != c.want || ok != c.ok {
			t.Errorf("%s %q: got (%q, %v), want (%q, %v)", c.tenant, c.host, got, ok, c.want, c.ok)
		}
	}

	// A tenant with no address routes has nothing a name could resolve into: no lookup is made for it.
	before := lookups
	if _, ok := registeredAddressBehindName(ctx, reg, nil, "tenant-b", "anything.example", now); ok {
		t.Fatal("tenant-b has no address routes")
	}
	if lookups != before {
		t.Fatalf("a tenant without address routes caused %d lookups", lookups-before)
	}
}

// The resolver answers once per name within the cache's lifetime: the flow-open path does not resolve again for
// every connection to the same name.
func TestANameIsResolvedOnceForManyFlows(t *testing.T) {
	reg := connector.NewRegistry()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	c := model.ConnectorRegistration{ID: "conn-hq", TenantID: "tenant-a", Status: "active", PrivateBaseURL: "https://internal.invalid",
		ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.55.1.16/28"}}}
	if _, err := reg.Register(c, now); err != nil {
		t.Fatal(err)
	}
	lookups := 0
	prev := observeResolver
	observeResolver = func(_ context.Context, host string) ([]net.IP, error) {
		lookups++
		return []net.IP{net.ParseIP("10.55.1.31")}, nil
	}
	t.Cleanup(func() { observeResolver = prev; observeLocality = newObserveLocalityCache() })
	observeLocality = newObserveLocalityCache()
	for i := 0; i < 5; i++ {
		if addr, ok := registeredAddressBehindName(context.Background(), reg, nil, "tenant-a", "files.hq.example", now.Add(time.Duration(i)*time.Second)); !ok || addr != "10.55.1.31" {
			t.Fatalf("flow %d: got (%q, %v)", i, addr, ok)
		}
	}
	if lookups != 1 {
		t.Fatalf("lookups = %d, want 1", lookups)
	}
}

// A name in a zone the organization forwards to its internal DNS resolves only through the connector, never
// through the Edge's own resolver. The address this Edge answered the tenant's devices with is the one the flow
// goes to; the Edge's own lookup is not consulted when that answer exists.
func TestANameAnsweredByTheInternalDNSIsRoutedByThatAnswer(t *testing.T) {
	reg := connector.NewRegistry()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	c := model.ConnectorRegistration{ID: "conn-hq", TenantID: "tenant-a", Status: "active", PrivateBaseURL: "https://internal.invalid",
		ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.55.1.16/28"}}}
	if _, err := reg.Register(c, now); err != nil {
		t.Fatal(err)
	}
	memory := dns.NewConntrackStore()
	memory.RecordEdgeAnswer(dns.ObservationRequest{TenantID: "tenant-a", FQDN: "intranet.hq.internal", ResolvedIPs: []string{"10.55.1.31"}, TTLSeconds: 360}, now)
	memory.RecordEdgeAnswer(dns.ObservationRequest{TenantID: "tenant-b", FQDN: "other.hq.internal", ResolvedIPs: []string{"10.55.1.30"}, TTLSeconds: 360}, now)
	lookups := 0
	prev := observeResolver
	observeResolver = func(_ context.Context, host string) ([]net.IP, error) {
		lookups++
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	t.Cleanup(func() { observeResolver = prev; observeLocality = newObserveLocalityCache() })
	observeLocality = newObserveLocalityCache()
	ctx := context.Background()

	if addr, ok := registeredAddressBehindName(ctx, reg, memory.LookupAddresses, "tenant-a", "Intranet.hq.internal.", now.Add(time.Minute)); !ok || addr != "10.55.1.31" {
		t.Fatalf("got (%q, %v), want the internal DNS's answer 10.55.1.31", addr, ok)
	}
	if lookups != 0 {
		t.Fatalf("the Edge's own resolver was asked %d times although it had answered the device", lookups)
	}
	// Another tenant's answer is not this tenant's.
	if _, ok := registeredAddressBehindName(ctx, reg, memory.LookupAddresses, "tenant-a", "other.hq.internal", now.Add(time.Minute)); ok {
		t.Fatal("tenant-b's answer must not route tenant-a's flow")
	}
	// An answer that has lapsed is not used.
	if _, ok := registeredAddressBehindName(ctx, reg, memory.LookupAddresses, "tenant-a", "intranet.hq.internal", now.Add(10*time.Minute)); ok {
		t.Fatal("a lapsed answer must not route a flow")
	}
}

// A name a Site declares becomes an address flow only when this Edge answered the tenant's devices with an
// address that the SAME Site carries. Then a rule written for the application's address applies, as it does to
// a device that sends the address.
func TestADeclaredNameIsItsAnsweredAddressOnlyOnItsOwnSite(t *testing.T) {
	reg := connector.NewRegistry()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, c := range []model.ConnectorRegistration{
		{ID: "conn-hq-1", TenantID: "tenant-a", ConnectorGroupID: "hq", Status: "active",
			ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.55.1.16/28"}, FQDNDomains: []string{"intranet.hq.internal"}}},
		{ID: "conn-hq-2", TenantID: "tenant-a", ConnectorGroupID: "hq", Status: "active",
			ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.55.1.16/28"}}},
		{ID: "conn-branch", TenantID: "tenant-a", ConnectorGroupID: "branch", Status: "active",
			ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.66.0.0/24"}, FQDNDomains: []string{"files.branch.internal"}}},
	} {
		c.PrivateBaseURL = "https://internal.invalid"
		if _, err := reg.Register(c, now); err != nil {
			t.Fatal(err)
		}
	}
	memory := dns.NewConntrackStore()
	memory.RecordEdgeAnswer(dns.ObservationRequest{TenantID: "tenant-a", FQDN: "intranet.hq.internal", ResolvedIPs: []string{"10.55.1.31"}, TTLSeconds: 360}, now)
	// A branch name whose answer lies in the HQ Site's range: the branch Site resolves it, not HQ's connector.
	memory.RecordEdgeAnswer(dns.ObservationRequest{TenantID: "tenant-a", FQDN: "files.branch.internal", ResolvedIPs: []string{"10.55.1.20"}, TTLSeconds: 360}, now)
	prev := observeResolver
	observeResolver = func(_ context.Context, host string) ([]net.IP, error) {
		t.Errorf("a declared name must not be looked up by the Edge's own resolver (%s)", host)
		return nil, nil
	}
	t.Cleanup(func() { observeResolver = prev; observeLocality = newObserveLocalityCache() })
	observeLocality = newObserveLocalityCache()
	ctx := context.Background()
	at := now.Add(time.Minute)

	if addr, ok := registeredAddressBehindName(ctx, reg, memory.LookupAddresses, "tenant-a", "intranet.hq.internal", at); !ok || addr != "10.55.1.31" {
		t.Fatalf("intranet: got (%q, %v), want 10.55.1.31 on its own Site", addr, ok)
	}
	if addr, ok := registeredAddressBehindName(ctx, reg, memory.LookupAddresses, "tenant-a", "files.branch.internal", at); ok {
		t.Fatalf("a branch name answered inside HQ's range must stay a name, got %q", addr)
	}
	if _, ok := registeredAddressBehindName(ctx, reg, nil, "tenant-a", "intranet.hq.internal", at); ok {
		t.Fatal("without this Edge's answer a declared name stays a name")
	}
}
