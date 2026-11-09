package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

// Found 2026-11-08 on acceptance C: an administrator pressed "Revoke" on an access approval and every attempt
// failed, on every node, before and after leadership moved. The Console sent the revocation to an Edge; an Edge
// that pulls its configuration from a control plane refuses it, which is right, but it answered 503 and said
// "control-plane authority", and the Console asks the control plane again only for a 409 or 501 whose error
// names "control plane". So the refusal was a dead end rather than a redirection.
func TestAnEdgeThatPullsItsConfigurationRefersARevocationToTheControlPlane(t *testing.T) {
	store := grantstore.NewStore()
	if _, err := store.Mint(grantstore.Grant{GrantID: "g1", TenantID: "tenant"}, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	r, _ := rolloutFixture(t)
	mux := http.NewServeMux()
	registerGrantsAdmin(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			h(w, requestWithAdminIdentity(req, adminIdentity{TenantID: "tenant"}))
		}
	}, store, testEvaluator(), nil, nil, r, "https://admin.example.test")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/admin/grants/g1/revoke", nil))
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	// The two things the Console's retry reads (app.js, apiFetch): the status, and the words.
	if w.Code != http.StatusConflict && w.Code != http.StatusNotImplemented {
		t.Fatalf("refusal status = %d, want 409 or 501 so the Console asks the control plane", w.Code)
	}
	if !regexp.MustCompile(`(?i)control plane`).MatchString(body.Error) {
		t.Fatalf("refusal %q does not name the control plane in the words the Console looks for", body.Error)
	}
	if g, ok := store.Get("g1"); !ok || g.Revoked {
		t.Fatal("the Edge changed the approval while refusing to revoke it")
	}
}
