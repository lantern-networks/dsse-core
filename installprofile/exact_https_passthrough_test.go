package installprofile

import (
	"reflect"
	"testing"
	"time"
)

func TestExactHTTPSPassthroughIsExplicitAndSignedInNewProfiles(t *testing.T) {
	issued := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	without := Build(Options{Tenant: "tenant-a"}, issued)
	if without.Deployment.ExactHTTPSPassthroughEndpoints == nil {
		t.Fatal("new profiles must carry an explicit empty exception list")
	}
	with := Build(Options{Tenant: "tenant-a", Deployment: DeploymentSpec{
		ExactHTTPSPassthroughEndpoints: []ExactHTTPSPassthroughEndpoint{{
			Hostname: "idp.example.test", Addresses: []string{"203.0.113.10", "2001:db8::10"},
		}},
	}}, issued)
	if !reflect.DeepEqual(with.Deployment.ExactHTTPSPassthroughEndpoints,
		[]ExactHTTPSPassthroughEndpoint{{Hostname: "idp.example.test", Addresses: []string{"203.0.113.10", "2001:db8::10"}}}) {
		t.Fatalf("signed profile lost exact IdP endpoints: %+v", with.Deployment.ExactHTTPSPassthroughEndpoints)
	}
	envelope, pin := signProfile(t, with)
	verified, trusted, err := Load(envelope, pin)
	if err != nil || !trusted || !reflect.DeepEqual(verified.Deployment.ExactHTTPSPassthroughEndpoints,
		with.Deployment.ExactHTTPSPassthroughEndpoints) {
		t.Fatalf("verified profile lost exact IdP endpoints: trusted=%t err=%v", trusted, err)
	}
}

func TestParseExactHTTPSPassthroughRejectsBroadOrAmbiguousEntries(t *testing.T) {
	good := `[{"hostname":"idp.example.test","addresses":["203.0.113.10","2001:db8::10"]}]`
	parsed, err := ParseExactHTTPSPassthroughEndpoints(good)
	if err != nil || len(parsed) != 1 || parsed[0].Hostname != "idp.example.test" {
		t.Fatalf("valid dedicated IdP: parsed=%+v err=%v", parsed, err)
	}
	for _, bad := range []string{
		`null`, `{}`, `[] true`, `[{"hostname":"idp.example.test","addresses":["203.0.113.10"],"port":8443}]`,
		`[{"hostname":"*.example.test","addresses":["203.0.113.10"]}]`,
		`[{"hostname":"Idp.example.test","addresses":["203.0.113.10"]}]`,
		`[{"hostname":"203.0.113.10","addresses":["203.0.113.10"]}]`,
		`[{"hostname":"idp.example.test","addresses":["idp.example.test"]}]`,
		`[{"hostname":"idp.example.test","addresses":["127.0.0.1"]}]`,
		`[{"hostname":"idp.example.test","addresses":["203.0.113.10","203.0.113.10"]}]`,
		`[{"hostname":"idp.example.test","addresses":[]}]`,
		`[{"hostname":"idp.example.test","addresses":["203.0.113.10"]},{"hostname":"idp.example.test","addresses":["203.0.113.11"]}]`,
	} {
		if got, err := ParseExactHTTPSPassthroughEndpoints(bad); err == nil {
			t.Errorf("accepted unsafe endpoint %q: %+v", bad, got)
		}
	}
}

func TestExactHTTPSPassthroughRejectsOverlappingBroadDomainRule(t *testing.T) {
	endpoint := []ExactHTTPSPassthroughEndpoint{{Hostname: "idp.example.test", Addresses: []string{"203.0.113.10"}}}
	if err := ValidateExactHTTPSPassthroughAgainstBroadDomains(endpoint, []string{"*.example.test"}); err == nil {
		t.Fatal("a domain-wide rule would bypass the exact HTTPS rule on every port and address")
	}
	if err := ValidateExactHTTPSPassthroughAgainstBroadDomains(endpoint, []string{"console.example.test"}); err != nil {
		t.Fatalf("unrelated Console exception rejected: %v", err)
	}
}
