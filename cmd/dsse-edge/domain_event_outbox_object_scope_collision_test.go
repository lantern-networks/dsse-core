package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/objectstore"
)

func TestDomainEventObjectPathKeepsCaseDistinctTenantScopes(t *testing.T) {
	store, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	delivery := objectStoreDomainEventOutboxDelivery{ObjectStore: store}
	foreign := mustDomainEventOutboxEnvelope(t)
	foreign.TenantID, foreign.ID = "A_B", "foreign_event"
	if err := delivery.DeliverDomainEvent(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	foreignManifest := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(foreign))
	foreignBytes, err := store.ReadGeneratedFile(domainEventOutboxObjectFilename(foreign))
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerOutboxAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		serverConfig{}, decision.Evaluator{}, writer, nil, nil, nil, nil, store)
	call := func(tenant, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = requestWithAdminIdentity(req, adminIdentity{
			PrincipalID: "customer-admin", TenantID: tenant, Roles: []string{"admin"}, AuthMethod: "admin_session",
		})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	// Dot and underscore are both valid opaque tenant ID characters. The
	// customer A.B must not list or verify A_B's object through a shared prefix.
	listPath := "/admin/domain-event-outbox/object-manifests"
	if rec := call("A.B", listPath); rec.Code != http.StatusOK {
		t.Fatalf("A.B list status=%d", rec.Code)
	} else {
		var result domainEventOutboxObjectManifestListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Returned != 0 || len(result.Rows) != 0 {
			t.Fatalf("A.B listed A_B's foreign manifest: %+v", result)
		}
	}
	verifyPath := "/admin/domain-event-outbox/object-manifests/verify?" + url.Values{"manifest_ref": {foreignManifest}}.Encode()
	if rec := call("A.B", verifyPath); rec.Code != http.StatusBadRequest {
		t.Fatalf("A.B verified A_B's foreign manifest: status=%d", rec.Code)
	}
	if rec := call("A_B", verifyPath); rec.Code != http.StatusOK {
		t.Fatalf("A_B cannot verify its own manifest: status=%d", rec.Code)
	}
	foreignPrefixPath := listPath + "?" + url.Values{"prefix": {domainEventOutboxTenantObjectPrefix("A_B")}}.Encode()
	if rec := call("A.B", foreignPrefixPath); rec.Code != http.StatusBadRequest {
		t.Fatalf("A.B selected A_B's foreign prefix: status=%d", rec.Code)
	}
	own := mustDomainEventOutboxEnvelope(t)
	own.TenantID, own.ID = "A.B", foreign.ID
	if err := delivery.DeliverDomainEvent(context.Background(), own); err != nil {
		t.Fatal(err)
	}
	if domainEventOutboxObjectFilename(own) == domainEventOutboxObjectFilename(foreign) {
		t.Fatal("distinct tenant object paths collide")
	}
	if got, err := store.ReadGeneratedFile(domainEventOutboxObjectFilename(foreign)); err != nil || !bytes.Equal(got, foreignBytes) {
		t.Fatalf("A.B delivery overwrote A_B's object: %v", err)
	}
	if rec := call("A.B", listPath); rec.Code != http.StatusOK {
		t.Fatalf("A.B own list status=%d", rec.Code)
	} else {
		var result domainEventOutboxObjectManifestListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(own))
		if result.Returned != 1 || len(result.Rows) != 1 || result.Rows[0].ManifestRef != want {
			t.Fatalf("A.B list was not restricted to its own manifest: %+v", result)
		}
	}
	ownManifest := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(own))
	ownVerifyPath := "/admin/domain-event-outbox/object-manifests/verify?" + url.Values{"manifest_ref": {ownManifest}}.Encode()
	if rec := call("A.B", ownVerifyPath); rec.Code != http.StatusOK {
		t.Fatalf("A.B cannot verify its own manifest: status=%d", rec.Code)
	}
	if rec := call("A_B", ownVerifyPath); rec.Code != http.StatusBadRequest {
		t.Fatalf("A_B verified A.B's foreign manifest: status=%d", rec.Code)
	}
}

func TestDomainEventObjectPathNeverOverwritesDistinctEventIDs(t *testing.T) {
	store, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	delivery := objectStoreDomainEventOutboxDelivery{ObjectStore: store}
	first := mustDomainEventOutboxEnvelope(t)
	first.ID = "domain_outbox_test_x:y"
	second := first
	second.ID = "domain_outbox_test_x_y"
	firstRef := domainEventOutboxObjectFilename(first)
	if err := delivery.DeliverDomainEvent(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	firstBytes, err := store.ReadGeneratedFile(firstRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := delivery.DeliverDomainEvent(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	secondRef := domainEventOutboxObjectFilename(second)
	if firstRef == secondRef {
		t.Fatalf("distinct outbox event IDs share object ref %q", firstRef)
	}
	got, err := store.ReadGeneratedFile(firstRef)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, firstBytes) {
		t.Fatal("the second published event overwrote the first object")
	}
	for _, event := range []domainEventOutboxEnvelope{first, second} {
		ref := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(event))
		if _, err := verifyDomainEventOutboxObjectManifest(store, ref); err != nil {
			t.Fatalf("verify %q: %v", event.ID, err)
		}
	}
	// Normal alphanumeric, hyphen and underscore IDs retain their existing path.
	if got := safeDomainEventOutboxObjectSegment("tenant_lab-001"); got != "tenant_lab-001" {
		t.Fatalf("safe key changed: %q", got)
	}
}
