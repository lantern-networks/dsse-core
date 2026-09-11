package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// A policy whose sni/fqdn condition is a "*." wildcard (e.g. an endpoint authored as *.google.com) matches
// every sub-domain of the suffix, on both the SNI key (steered/decrypted browser flow) and the FQDN key
// (plain SWG/HTTP egress), but NOT the apex — and an unrelated host still fails.
func TestHostnameWildcardCondition(t *testing.T) {
	for _, key := range []string{"sni", "fqdn"} {
		policy := model.Policy{
			ID:         "p-wild",
			Status:     "active",
			Conditions: map[string]any{key: "*.google.com"},
			Action:     model.PolicyAction{Decision: "deny"},
		}
		reqFor := func(host string) model.DecisionRequest {
			if key == "sni" {
				return model.DecisionRequest{SNI: host}
			}
			return model.DecisionRequest{FQDN: host}
		}
		if ok, _ := matchPolicy(policy, reqFor("accounts.google.com"), "human"); !ok {
			t.Fatalf("%s=*.google.com should match sub-domain accounts.google.com", key)
		}
		if ok, _ := matchPolicy(policy, reqFor("mail.google.com"), "human"); !ok {
			t.Fatalf("%s=*.google.com should match sub-domain mail.google.com", key)
		}
		if ok, _ := matchPolicy(policy, reqFor("google.com"), "human"); ok {
			t.Fatalf("%s=*.google.com must NOT match the apex google.com (author an exact endpoint for that)", key)
		}
		if ok, _ := matchPolicy(policy, reqFor("notgoogle.com"), "human"); ok {
			t.Fatalf("%s=*.google.com must NOT match an unrelated host", key)
		}
		if ok, _ := matchPolicy(policy, reqFor("evil-google.com.attacker.net"), "human"); ok {
			t.Fatalf("%s=*.google.com must NOT match a look-alike suffix without a dot boundary", key)
		}
	}
}

// An exact (non-wildcard) hostname condition still matches exactly and rejects sub-domains — backward
// compatibility with the existing per-site rules.
func TestHostnameExactStillExact(t *testing.T) {
	policy := model.Policy{
		ID:         "p-exact",
		Status:     "active",
		Conditions: map[string]any{"sni": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "deny"},
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{SNI: "accounts.google.com"}, "human"); !ok {
		t.Fatalf("exact sni should match itself")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{SNI: "mail.google.com"}, "human"); ok {
		t.Fatalf("exact sni must NOT match a different sub-domain")
	}
}

// The wildcard is honoured whether the expected value is a plain string or a list (op:in shape the compiler
// could emit), case-insensitively.
func TestHostnameWildcardListAndCase(t *testing.T) {
	policy := model.Policy{
		ID:         "p-list",
		Status:     "active",
		Conditions: map[string]any{"sni": []any{"*.example.org", "*.GOOGLE.com"}},
		Action:     model.PolicyAction{Decision: "deny"},
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{SNI: "Accounts.Google.Com"}, "human"); !ok {
		t.Fatalf("wildcard list should match case-insensitively")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{SNI: "a.example.org"}, "human"); !ok {
		t.Fatalf("wildcard list should match the other pattern")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{SNI: "a.example.net"}, "human"); ok {
		t.Fatalf("wildcard list must NOT match a host outside every pattern")
	}
}
