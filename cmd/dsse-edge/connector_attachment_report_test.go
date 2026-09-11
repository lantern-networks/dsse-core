package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

func connectorReportServer(t *testing.T, registry connectorRegistryStore) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerConnectorReportRoute(mux, registry, nil, "", true)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func postConnectorReport(t *testing.T, server *httptest.Server, body any) int {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(server.URL+"/connector-report", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// ★★★ AN ATTACHMENT REPORT MUST NOT BE ABLE TO UNDO AN OPERATOR'S DECISION. The reporting node's copy of a
// registration comes from the authority and can be a generation behind, so writing the whole record back on
// every tunnel attach would let a stale node erase a rename or the routes somebody authored.
func TestAnAttachmentReportTouchesOnlyTheRegionItReports(t *testing.T) {
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn-1", TenantID: "t1", Status: "registered", EdgeRegionID: "region-b",
		PrivateBaseURL:  "https://internal.invalid",
		Name:            "Tokyo DC connector",
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	server := connectorReportServer(t, registry)

	// A node reports the attachment carrying a STALE copy: no name, no routes, the wrong region.
	stale := model.ConnectorRegistration{ID: "conn-1", TenantID: "t1", PrivateBaseURL: "https://internal.invalid"}
	if code := postConnectorReport(t, server, map[string]any{
		"registration": stale, "tenant_id": "t1", "attached_region_id": "region-a",
	}); code != http.StatusNoContent {
		t.Fatalf("status: got %d", code)
	}

	got, ok := registry.Get("conn-1")
	if !ok {
		t.Fatal("the connector disappeared")
	}
	if got.AttachedRegionID != "region-a" {
		t.Fatalf("attached region: got %q", got.AttachedRegionID)
	}
	if got.Name != "Tokyo DC connector" {
		t.Fatalf("the operator's name was overwritten by a stale report: %q", got.Name)
	}
	if len(got.ReachableRoutes.FQDNDomains) != 1 {
		t.Fatalf("the authored routes were overwritten by a stale report: %v", got.ReachableRoutes)
	}
	if got.EdgeRegionID != "region-b" {
		t.Fatalf("where it enrolled is a separate fact and must survive: %q", got.EdgeRegionID)
	}
}

// A report for a connector the authority does not have yet must not be lost: it is recorded, carrying the
// region it came with, so an attachment that beats the registration report still lands.
func TestAnAttachmentReportForAnUnknownConnectorIsStillRecorded(t *testing.T) {
	registry := connector.NewRegistry()
	server := connectorReportServer(t, registry)

	reg := model.ConnectorRegistration{ID: "conn-2", TenantID: "t1", PrivateBaseURL: "https://internal.invalid", EdgeRegionID: "region-b"}
	if code := postConnectorReport(t, server, map[string]any{
		"registration": reg, "tenant_id": "t1", "attached_region_id": "region-a",
	}); code != http.StatusNoContent {
		t.Fatalf("status: got %d", code)
	}
	got, ok := registry.Get("conn-2")
	if !ok {
		t.Fatal("a report for an unknown connector must record it rather than drop it")
	}
	if got.AttachedRegionID != "region-a" || got.EdgeRegionID != "region-b" {
		t.Fatalf("both facts must land: attached=%q registered=%q", got.AttachedRegionID, got.EdgeRegionID)
	}
}

// The ordinary registration report is unchanged: no attached region, the whole record recorded.
func TestARegistrationReportWithNoAttachedRegionIsUnchanged(t *testing.T) {
	registry := connector.NewRegistry()
	server := connectorReportServer(t, registry)

	reg := model.ConnectorRegistration{ID: "conn-3", TenantID: "t1", PrivateBaseURL: "https://internal.invalid", EdgeRegionID: "region-b", Name: "named at registration"}
	if code := postConnectorReport(t, server, map[string]any{"registration": reg, "tenant_id": "t1"}); code != http.StatusNoContent {
		t.Fatalf("status: got %d", code)
	}
	got, ok := registry.Get("conn-3")
	if !ok {
		t.Fatal("the registration was not recorded")
	}
	if got.Name != "named at registration" || got.EdgeRegionID != "region-b" {
		t.Fatalf("registration report changed shape: %+v", got)
	}
	if got.AttachedRegionID != "" {
		t.Fatalf("nothing was reported about where it is attached: %q", got.AttachedRegionID)
	}
}

// ★★★ AND THE LIVENESS IN THAT SAME REPORT IS NOT THROWN AWAY (2026-09-01, found on the Console: a site with
// two live connectors read "Down — 0 of 2 connectors online").
//
// The attachment path returned as soon as it had recorded the region, so once the Edge began carrying a
// connector's heartbeat, every one of those reports updated the region and dropped the rest. The authority's
// last_heartbeat stayed frozen at registration, and adminConnectorOnline reads exactly that.
//
// Two facts arrive in one message. The reporter owns one of them.
func TestAnAttachmentReportAlsoCarriesTheLivenessItObserved(t *testing.T) {
	reg := connector.NewRegistry()
	const id = "conn_live_001"
	if _, err := reg.Register(model.ConnectorRegistration{
		ID: id, TenantID: "tenant_x", Name: "the operator's own name", Status: "registered",
		PrivateBaseURL:  "https://private.example.test",
		LastHeartbeatAt: "2026-09-01T01:00:00Z",
	}, time.Now()); err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := reg.RecordLiveness(id, "online", "2026-09-01T02:45:00Z"); err != nil {
		t.Fatalf("RecordLiveness: %v", err)
	}
	got, ok := reg.Get(id)
	if !ok {
		t.Fatal("the connector vanished")
	}
	if got.LastHeartbeatAt != "2026-09-01T02:45:00Z" || got.Status != "online" {
		t.Errorf("liveness did not land: heartbeat=%q status=%q", got.LastHeartbeatAt, got.Status)
	}
	// ★ AND NOTHING THE OPERATOR AUTHORED MOVED. That is the whole reason the report cannot simply re-register:
	// a reporting Edge's copy is stale about the things it does not own.
	if got.Name != "the operator's own name" {
		t.Errorf("the operator's name was overwritten by a liveness report: %q", got.Name)
	}
}
