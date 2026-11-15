package assetcatalog

import (
	"context"
	"testing"
)

// Found on a Windows walk: "not an address" was saved as a destination, and came back selected in a rule.
func TestANetworkEndpointsAddressMustBeSomethingARuleCanMatch(t *testing.T) {
	for _, ok := range []string{"10.0.0.10", "10.0.0.0/24", "2001:db8::1", "2001:db8::/48", "db.example.com", "*.example.com", "intranet", "wiki.org-01.fleet.internal", "_sip.example.com", "example.com."} {
		if err := ValidateNetworkAddress(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"not an address", " 10.0.0.10", "10.0.0.10 ", "http://db.example.com", "db.example.com:5432", "10.0.0.0/33", "*.*.example.com", "a..b", "-bad.example.com", "exa mple.com", "*"} {
		if err := ValidateNetworkAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTheCatalogRefusesAnAddressThatIsNotOneAndKeepsWhatItHad(t *testing.T) {
	s := NewStore()
	if _, err := s.UpsertEndpointContext(context.Background(), Endpoint{TenantID: "t1", Alias: "Bad test", Kind: KindNetwork, Source: SourceManual, Address: "not an address"}); err == nil {
		t.Fatal("the catalog stored a destination no flow can be")
	}
	if got := s.ListEndpoints("t1"); len(got) != 0 {
		t.Fatalf("a refused endpoint was stored anyway: %+v", got)
	}
	saved, err := s.UpsertEndpointContext(context.Background(), Endpoint{TenantID: "t1", Alias: "prod database", Kind: KindNetwork, Source: SourceManual, Address: "10.0.0.10"})
	if err != nil {
		t.Fatal(err)
	}
	// Renaming does not re-judge an address that is not being changed.
	saved.Alias = "production database"
	if _, err := s.UpsertEndpointContext(context.Background(), saved); err != nil {
		t.Fatalf("rename refused: %v", err)
	}
}
