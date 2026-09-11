package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A connector used to take the deployment's name and the deployment's root whatever its organization had
// (2026-09-07, measured on twenty organizations that each had a door answering in all three regions). The
// region list beside it was already per-organization; the name and the anchor were not.
//
// ★ THE TWO HALVES MOVE TOGETHER OR NEITHER MOVES. Pinning an organization's CA while asking for the
// deployment's name is served the deployment's certificate and fails verification; the reverse fails from the
// other side. So the tests below assert the PAIR, not either field alone.

func writeToken(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestAConnectorPinsItsOwnOrganizationsAuthorityAndAsksForItsName(t *testing.T) {
	dir := t.TempDir()
	tok := writeToken(t, map[string]any{
		"v": 1, "edge_url": "https://agents.example", "tenant_id": "tenant_x", "site": "hq",
		"bootstrap":             "s3cret",
		"edge_ca":               "-----BEGIN CERTIFICATE-----\nDEPLOYMENT\n-----END CERTIFICATE-----",
		"org_server_name":       "abc.example",
		"org_enrol_server_name": "enrol.abc.example",
		"org_anchors":           "-----BEGIN CERTIFICATE-----\nORGANIZATION\n-----END CERTIFICATE-----",
	})

	var edgeURL, tenantID, site, connectorID, connectorSecret, bootstrap, region, cluster, ca, endpoints, serverName string
	firstRun, err := resolveConnectorEnrollment(dir, tok, connectorEnrollmentFlags{
		EdgeURL: &edgeURL, TenantID: &tenantID, Site: &site, ConnectorID: &connectorID,
		ConnectorSecret: &connectorSecret, BootstrapSecret: &bootstrap, Region: &region, Cluster: &cluster,
		EdgeTransportCA: &ca, EdgeEndpoints: &endpoints, EdgeServerName: &serverName,
	})
	if err != nil || !firstRun {
		t.Fatalf("first run: firstRun=%v err=%v", firstRun, err)
	}
	if serverName != "abc.example" {
		t.Fatalf("the connector must ask for its organization's own name, got %q", serverName)
	}
	pinned, rerr := os.ReadFile(ca)
	if rerr != nil {
		t.Fatalf("read pinned anchors: %v", rerr)
	}
	if !strings.Contains(string(pinned), "ORGANIZATION") {
		t.Fatalf("the connector must pin its organization's authority, pinned:\n%s", pinned)
	}
	if strings.Contains(string(pinned), "DEPLOYMENT") {
		t.Fatalf("pinning the deployment root beside the organization's would accept the shared certificate "+
			"for the organization's name, pinned:\n%s", pinned)
	}

	// And the state carries both names, so every later start — which has no token — asks for the same thing.
	st, ok, lerr := loadConnectorState(filepath.Join(dir, "connector-state.json"))
	if lerr != nil || !ok {
		t.Fatalf("load state: ok=%v err=%v", ok, lerr)
	}
	if st.EdgeServerName != "abc.example" || st.EdgeEnrolmentServerName != "enrol.abc.example" {
		t.Fatalf("state must persist both names, got transport=%q enrolment=%q",
			st.EdgeServerName, st.EdgeEnrolmentServerName)
	}
}

// An organization with no door of its own — and every token issued before these fields existed — keeps the
// behaviour it had: the deployment's shared certificate, and the dialled host as the name.
func TestAConnectorWithoutAnOrganizationDoorIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	tok := writeToken(t, map[string]any{
		"v": 1, "edge_url": "https://agents.example", "tenant_id": "tenant_x", "site": "hq",
		"bootstrap": "s3cret",
		"edge_ca":   "-----BEGIN CERTIFICATE-----\nDEPLOYMENT\n-----END CERTIFICATE-----",
	})
	var edgeURL, tenantID, site, connectorID, connectorSecret, bootstrap, region, cluster, ca, endpoints, serverName string
	if _, err := resolveConnectorEnrollment(dir, tok, connectorEnrollmentFlags{
		EdgeURL: &edgeURL, TenantID: &tenantID, Site: &site, ConnectorID: &connectorID,
		ConnectorSecret: &connectorSecret, BootstrapSecret: &bootstrap, Region: &region, Cluster: &cluster,
		EdgeTransportCA: &ca, EdgeEndpoints: &endpoints, EdgeServerName: &serverName,
	}); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if serverName != "" {
		t.Fatalf("with no organization door the connector must send the dialled host, got %q", serverName)
	}
	pinned, _ := os.ReadFile(ca)
	if !strings.Contains(string(pinned), "DEPLOYMENT") {
		t.Fatalf("the deployment root must still be pinned, pinned:\n%s", pinned)
	}
}

// A name with no anchors, or anchors with no name, is half a change: it would ask for a certificate it cannot
// verify, or verify against an authority that will never sign what it is served. Neither half is taken alone.
func TestHalfAnOrganizationDoorIsNotTaken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload map[string]any
	}{
		{"name without anchors", map[string]any{"org_server_name": "abc.example"}},
		{"anchors without a name", map[string]any{"org_anchors": "-----BEGIN CERTIFICATE-----\nORGANIZATION\n-----END CERTIFICATE-----"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			payload := map[string]any{
				"v": 1, "edge_url": "https://agents.example", "tenant_id": "tenant_x", "site": "hq",
				"bootstrap": "s3cret",
				"edge_ca":   "-----BEGIN CERTIFICATE-----\nDEPLOYMENT\n-----END CERTIFICATE-----",
			}
			for k, v := range tc.payload {
				payload[k] = v
			}
			var edgeURL, tenantID, site, connectorID, connectorSecret, bootstrap, region, cluster, ca, endpoints, serverName string
			if _, err := resolveConnectorEnrollment(dir, writeToken(t, payload), connectorEnrollmentFlags{
				EdgeURL: &edgeURL, TenantID: &tenantID, Site: &site, ConnectorID: &connectorID,
				ConnectorSecret: &connectorSecret, BootstrapSecret: &bootstrap, Region: &region, Cluster: &cluster,
				EdgeTransportCA: &ca, EdgeEndpoints: &endpoints, EdgeServerName: &serverName,
			}); err != nil {
				t.Fatalf("first run: %v", err)
			}
			if serverName != "" {
				t.Fatalf("half a door must not change the name, got %q", serverName)
			}
			pinned, _ := os.ReadFile(ca)
			if !strings.Contains(string(pinned), "DEPLOYMENT") {
				t.Fatalf("half a door must not change what is pinned, pinned:\n%s", pinned)
			}
		})
	}
}

// The name reaches the *tls.Config the connector actually dials with. A field that is stored and never sent
// is the same defect in a different place.
func TestTheNameReachesTheDialledTLSConfig(t *testing.T) {
	dir := t.TempDir()
	caPath, _ := writeSelfSigned(t, dir, "abc.example")
	cfg, err := buildConnectorTLSConfig(connectorTransportConfig{
		EdgeCAFile: caPath, DevMode: true, ServerName: "abc.example",
	})
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	if cfg == nil || cfg.ServerName != "abc.example" {
		t.Fatalf("the organization's name must be what the ClientHello asks for, got %+v", cfg)
	}
}
