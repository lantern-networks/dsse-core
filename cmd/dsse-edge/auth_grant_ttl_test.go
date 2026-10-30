package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestNativeFederatedGrantTTLUsesCurrentRuleAndTenant(t *testing.T) {
	store := policy.NewStore(nil)
	for tenant, cap := range map[string]int{"node": 90, "customer": 300} {
		store.SetEastWestEnabled(tenant, true)
		store.SetEastWestMaxGrantTTL(tenant, cap)
		store.SetCompiledEastWestRules(tenant, []decision.EastWestRule{{ID: "private", Destinations: []string{"10.200.0.10"}, Mode: "authenticate", MaxTTLSeconds: 600}})
	}
	base := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "node"}}
	for tenant, want := range map[string]int64{"node": 90, "customer": 300} {
		req := model.DecisionRequest{TenantID: tenant, Destination: "10.200.0.10", DestinationPort: 18081, Protocol: "tcp", ConnectorRouteVerified: true, ActorType: "human"}
		dec := runtimeEvaluatorForTenant(base, store, tenant).Evaluate(req)
		requirements := authFlowRequirements(dec, "10.200.0.10:18081")
		if requirements.Invalid || requirements.GrantTTLSeconds == nil || *requirements.GrantTTLSeconds != want {
			t.Fatalf("%s TTL requirement = %+v, want %d", tenant, requirements, want)
		}
	}
	invalid := model.DecisionRequest{TenantID: "customer", Destination: "10.200.0.10", DestinationPort: 18081, Protocol: "tcp", ConnectorRouteVerified: true, ActorType: "human"}
	invalidEvaluator := runtimeEvaluatorForTenant(base, store, "customer")
	invalidEvaluator.EastWestMaxGrantTTLSeconds = -1 // malformed evaluator input must not become an unlimited grant
	if !authFlowRequirements(invalidEvaluator.Evaluate(invalid), "10.200.0.10:18081").Invalid {
		t.Fatal("invalid tenant ceiling was silently dropped")
	}
	store.SetEastWestMaxGrantTTL("customer", 0)
	req := model.DecisionRequest{TenantID: "customer", Destination: "10.200.0.10", DestinationPort: 18081, Protocol: "tcp", ConnectorRouteVerified: true, ActorType: "human"}
	cap := authFlowRequirements(runtimeEvaluatorForTenant(base, store, "customer").Evaluate(req), "10.200.0.10:18081").GrantTTLSeconds
	if cap == nil || *cap != 600 {
		t.Fatal("an unset tenant cap must preserve the rule cap, not the node tenant's cap")
	}
}

func TestFederatedGrantTTLCannotReuseOldLongLivedGrant(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := grantstore.NewStore()
	gate := &federatedAuthGate{grants: store}
	grant := authTestBindGrant(t, gate, grantstore.Grant{GrantID: "old", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app:22", AuthTime: now.Add(-11 * time.Minute).Format(time.RFC3339)})
	if _, err := store.Mint(grant, 8*time.Hour, now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	cap := int64(300)
	req := federatedRequirements{IdP: "corp", Scope: "app:22", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, GrantTTLSeconds: &cap}
	if gate.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("old eight-hour evidence bypassed the current five-minute policy")
	}
	cap = 900
	if !gate.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("evidence within the current cap should remain usable")
	}
	for _, bad := range []int64{0, -1, 1<<63 - 1} {
		req.GrantTTLSeconds = &bad
		if gate.hasLiveGrantWithRequirements("tenant", "device", req) {
			t.Fatal("invalid cap must deny")
		}
	}
}

func TestFederatedGrantTTLBoundaryAndMalformedPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		issued string
		cap    int64
		want   bool
	}{
		{now.Add(-299 * time.Second).Format(time.RFC3339), 300, true},
		{now.Add(-300 * time.Second).Format(time.RFC3339), 300, false},
		{now.Add(time.Second).Format(time.RFC3339), 300, false},
		{"", 300, false}, {"bad", 300, false}, {now.Format(time.RFC3339), 1<<63 - 1, false},
	} {
		if got := authGrantWithinTTL(tc.issued, tc.cap, now); got != tc.want {
			t.Fatalf("grant cap %d boundary got %v, want %v", tc.cap, got, tc.want)
		}
	}
	for _, bad := range []any{0, -1, 1.5, "300", int64(1<<63 - 1), nil} {
		req := authFlowRequirements(model.AccessDecision{Actions: []model.DecisionAction{{Type: "prompt_reauthentication", Metadata: map[string]any{"grant_ttl_seconds": bad}}}}, "app:22")
		if !req.Invalid {
			t.Fatalf("invalid policy cap %T was accepted", bad)
		}
	}
}

func TestCappedSealedStateUsesVersionRejectedByLegacyPortals(t *testing.T) {
	signer := newDeviceBindingSignerFromSecret("test-shared-key")
	b := newClientlessBroker(idpregistry.NewStore(), grantstore.NewStore(), nil, "https://portal.example", "tenant", time.Hour, signer)
	b.recoverySharedKey = true
	now := time.Now().UTC()
	cap := int64(15)
	p := pendingAuth{requestID: strings.Repeat("a", 32), boundDevice: "device", tenantID: "tenant", idpID: "corp", nonce: "nonce", codeVerifier: "verifier", redirectURI: b.selfBaseURL + "/clientless/auth/callback", browserHash: sha256.Sum256([]byte(strings.Repeat("b", 32))), providerDigest: sha256.Sum256([]byte("provider")), createdAt: now, deadline: now.Add(time.Minute), grantTTLSeconds: &cap}
	state, err := b.sealAuthState(p)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(state, sealedAuthStatePrefix))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := b.ceremonyStateAEAD()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := aead.Open(nil, encoded[:aead.NonceSize()], encoded[aead.NonceSize():], []byte(b.selfBaseURL))
	if err != nil {
		t.Fatal(err)
	}
	var payload sealedAuthPayload
	if json.Unmarshal(raw, &payload) != nil {
		t.Fatal("cannot decode own sealed state")
	}
	if payload.Version != 2 || payload.GrantTTLSeconds == nil || *payload.GrantTTLSeconds != 15 {
		t.Fatal("old version-1-only Portal could silently drop the capped lifetime")
	}
	request := httptest.NewRequest("GET", b.selfBaseURL+"/clientless/auth/callback", nil)
	request.AddCookie(&http.Cookie{Name: authSessionCookie, Value: strings.Repeat("b", 32)})
	recovered, ok := b.recoverAuthState(request, state, now)
	if !ok || recovered.grantTTLSeconds == nil || *recovered.grantTTLSeconds != 15 {
		t.Fatal("new Portal lost the sealed cap")
	}
	for _, tc := range []struct {
		version int
		ttl     *int64
		want    bool
	}{
		{1, nil, true}, {1, &cap, false}, {2, nil, false}, {2, new(int64), false}, {3, &cap, false},
	} {
		changed := payload
		changed.Version = tc.version
		changed.GrantTTLSeconds = tc.ttl
		body, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		token := sealedAuthStatePrefix + base64.RawURLEncoding.EncodeToString(append(nonce, aead.Seal(nil, nonce, body, []byte(b.selfBaseURL))...))
		_, ok := b.recoverAuthState(request, token, now)
		if ok != tc.want {
			t.Fatalf("sealed version/cap combination %d: accepted=%v want=%v", tc.version, ok, tc.want)
		}
	}

}
