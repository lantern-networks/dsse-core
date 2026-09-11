package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEntitlementStore(t *testing.T) {
	s := newEntitlementStore(map[string]bool{featureDLP: true})
	// Default applies when no explicit entry.
	if !s.Entitled("acme", featureDLP) {
		t.Fatal("default-true feature should be entitled")
	}
	// Explicit revoke overrides the default.
	s.SetFeature("acme", featureDLP, false)
	if s.Entitled("acme", featureDLP) {
		t.Fatal("explicit revoke should win over the default")
	}
	// Other tenants still get the default.
	if !s.Entitled("other", featureDLP) {
		t.Fatal("other tenant should get the default")
	}
	// Default-off deployment: unlicensed by default.
	off := newEntitlementStore(map[string]bool{featureDLP: false})
	if off.Entitled("acme", featureDLP) {
		t.Fatal("default-off feature should not be entitled")
	}
	// nil store = everything entitled (backward compatible).
	var nilStore *entitlementStore
	if !nilStore.Entitled("acme", featureDLP) {
		t.Fatal("nil store should entitle everything")
	}
}

// A tenant NOT entitled to DLP is never inspected, even with a dlp_inspect directive present.
func TestDLPGatedByEntitlement(t *testing.T) {
	config, store := newDLPTestConfig(t)
	config.Entitlements = newEntitlementStore(map[string]bool{featureDLP: false}) // DLP not licensed
	dec := dlpDecWithInspect("dec-ent", "tenant-a", "app-1", "block", "my_number")
	body := `{"my_number":"123456789018"}`
	req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	// Not entitled → inert: the guard is never installed, the body reads clean (no ErrBlocked), nothing recorded.
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("unentitled tenant should not have a guard (err=%v)", err)
	}
	if string(forwarded) != body {
		t.Fatalf("body altered for unentitled tenant")
	}
	if hook.blocked() {
		t.Fatal("unentitled tenant must not be blocked by DLP")
	}
	hook.finalizeObserve(context.Background())
	if store.Count() != 0 {
		t.Fatalf("unentitled tenant produced %d inspection events, want 0", store.Count())
	}

	// Flip entitlement on → the same flow is now inspected + blocked.
	config.Entitlements = newEntitlementStore(map[string]bool{featureDLP: true})
	req2 := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	hook2 := installEdgeSWGHTTPEgressDLP(req2, config, dec)
	if _, err := io.ReadAll(req2.Body); err == nil {
		t.Fatal("entitled tenant should have the guard trip (ErrBlocked)")
	}
	if !hook2.blocked() {
		t.Fatal("entitled tenant should be blocked")
	}
}
