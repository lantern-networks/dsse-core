package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

type refusingDiscoveryPersister struct{}

func (refusingDiscoveryPersister) Load() ([]byte, error) { return nil, nil }
func (refusingDiscoveryPersister) Save([]byte) error     { return errors.New("disk refused") }

// The registration takes effect in the registry before route discovery is
// saved. When only discovery failed, the handler answered 503 and skipped the
// connector_registered record, the report to the authority and the boundary
// refresh, so a connector that exists had no record of registering.
func TestConnectorRegistrationIsRecordedWhenOnlyDiscoveryFails(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	old := connectorRouteGov
	connectorRouteGov = newConnectorRouteGovernanceWithPersister("", false, refusingDiscoveryPersister{})
	defer func() { connectorRouteGov = old }()
	registry := connector.NewRegistry()
	handler := newServerWithClient(testEvaluatorWithPolicies(nil), writer, registry, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{}`))}, nil
	})})
	req := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_disc_fail","tenant_id":"tenant_lab_001","connector_group_id":"cgrp_lab_001","name":"Lab",
		"edge_region_id":"local","edge_cluster_id":"local-edge-001","private_base_url":"http://connector.local",
		"status":"registered","reachable_routes":{"cidrs":["10.8.0.0/24"]},"metadata":{}}`))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("discovery failure not reported: %d %s", rec.Code, rec.Body)
	}
	if _, ok := registry.Get("conn_disc_fail"); !ok {
		t.Fatal("precondition: the registration took effect")
	}
	writer.Close()
	found := false
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(path); strings.Contains(string(b), "connector_registered") {
				found = true
			}
		}
		return nil
	})
	if !found {
		t.Fatal("a registration that took effect left no connector_registered record")
	}
}
