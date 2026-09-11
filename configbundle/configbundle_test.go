package configbundle_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/configbundle"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func seedStore(t *testing.T) *policy.Store {
	t.Helper()
	s := policy.NewStore([]model.Policy{{
		ID: "p1", TenantID: "acme", Name: "allow", Priority: 100, Status: "active",
		Conditions: map[string]any{"actor_type": "user"},
		Action:     model.PolicyAction{Decision: "allow"},
	}})
	return s
}

func TestFromStoreCarriesPolicies(t *testing.T) {
	b := configbundle.FromStore(seedStore(t), "acme")
	if len(b.Policies) != 1 || b.Policies[0].ID != "p1" {
		t.Fatalf("bundle should carry the tenant's policy: %+v", b.Policies)
	}
	if b.TenantConfig == nil {
		t.Fatal("bundle should carry tenant config")
	}
}

// Review #6: the CP->Edge config bundle wire format carried no signature at all — transport auth alone let
// a compromised path feed an edge arbitrary policy. Sign/Verify pin the snapshot to the CP signing key.
func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := configbundle.KeyIDFor(pub)
	ring := map[string]ed25519.PublicKey{keyID: pub}

	b := configbundle.Bundle{Generation: 7, Policies: []model.Policy{{ID: "p9", Action: model.PolicyAction{Decision: "deny"}}}}
	signed, err := configbundle.Sign(b, keyID, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := configbundle.Verify(signed, ring); err != nil {
		t.Fatalf("signed bundle must verify: %v", err)
	}

	// A JSON round-trip (the wire) must still verify — canonicalization must be stable.
	wire, _ := json.Marshal(signed)
	var decoded configbundle.Bundle
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := configbundle.Verify(decoded, ring); err != nil {
		t.Fatalf("bundle must verify after a wire round-trip: %v", err)
	}

	// Tamper: any covered field change (a policy flip, the generation/anti-rollback epoch) must fail.
	tampered := decoded
	tampered.Policies = []model.Policy{{ID: "p9", Action: model.PolicyAction{Decision: "allow"}}}
	if err := configbundle.Verify(tampered, ring); err == nil {
		t.Fatal("tampered policies must not verify")
	}
	replayed := decoded
	replayed.Generation = 99
	if err := configbundle.Verify(replayed, ring); err == nil {
		t.Fatal("tampered generation must not verify")
	}

	// Unsigned bundle with a configured keyring must be rejected (no signature-optional downgrade).
	if err := configbundle.Verify(b, ring); err == nil {
		t.Fatal("unsigned bundle must be rejected when trusted keys are configured")
	}

	// A signer outside the keyring must be rejected even with a valid self-signature.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	rogue, _ := configbundle.Sign(b, "rogue-key", otherPriv)
	if err := configbundle.Verify(rogue, ring); err == nil {
		t.Fatal("signature by an untrusted key must be rejected")
	}

	// Verify with an empty ring is an error, not a pass.
	if err := configbundle.Verify(signed, nil); err == nil {
		t.Fatal("empty keyring must be an error")
	}
}

func TestParseTrustedKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base64.RawURLEncoding.EncodeToString(pub)
	keys, err := configbundle.ParseTrustedKeys("cp-config-abc=" + encoded)
	if err != nil || len(keys) != 1 || !keys["cp-config-abc"].Equal(pub) {
		t.Fatalf("parse = %v, err=%v", keys, err)
	}
	if _, err := configbundle.ParseTrustedKeys("missing-separator"); err == nil {
		t.Fatal("malformed entry must be rejected")
	}
	if keys, err := configbundle.ParseTrustedKeys("  "); err != nil || keys != nil {
		t.Fatalf("blank list should parse to nil ring, got %v err=%v", keys, err)
	}
}

func TestFetch(t *testing.T) {
	want := configbundle.Bundle{Generation: 7, Policies: []model.Policy{{ID: "p9"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := configbundle.Fetch(ctx, srv.Client(), srv.URL, "tok")
	if err != nil || got.Generation != 7 || len(got.Policies) != 1 || got.Policies[0].ID != "p9" {
		t.Fatalf("fetch = %+v, err=%v", got, err)
	}
	if _, err := configbundle.Fetch(ctx, srv.Client(), srv.URL, ""); err == nil {
		t.Fatal("fetch without the bearer token should fail (401)")
	}
}
