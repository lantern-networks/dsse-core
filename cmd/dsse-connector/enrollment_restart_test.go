package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func tokenFor(t *testing.T, tok connectorEnrollmentToken) string {
	t.Helper()
	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func flagsFor() (connectorEnrollmentFlags, *string, *string, *string, *string, *string, *string, *string, *string) {
	edge, tenant, site, id := new(string), new(string), new(string), new(string)
	secret, bootstrap, region, cluster, ca := new(string), new(string), new(string), new(string), new(string)
	return connectorEnrollmentFlags{
		EdgeURL: edge, TenantID: tenant, Site: site, ConnectorID: id,
		ConnectorSecret: secret, BootstrapSecret: bootstrap,
		Region: region, Cluster: cluster, EdgeTransportCA: ca,
	}, edge, tenant, site, id, secret, bootstrap, region, cluster
}

// ★★★ EVERY RESTART MINTED A NEW CONNECTOR (2026-08-25, measured: one site held seven connectors for one
// running process, six of them dead, and a route bound to the connector an operator could see stopped applying
// the moment it restarted). The Console hands over ONE self-contained command; that command becomes a systemd
// unit or a container's arguments, and every start passes the same argv — token included. The flag said "first
// run only" and nothing an operator actually runs works that way.
func TestARestartWithTheSameTokenKeepsTheIdentity(t *testing.T) {
	dir := t.TempDir()
	tok := connectorEnrollmentToken{V: 1, EdgeURL: "https://agents.example:443", TenantID: "tenant_a",
		Site: "site-b", Bootstrap: "one-time-1"}

	f, _, _, _, id, _, _, _, _ := flagsFor()
	first, err := resolveConnectorEnrollment(dir, tokenFor(t, tok), f)
	if err != nil || !first {
		t.Fatalf("first run: firstRun=%v err=%v", first, err)
	}
	firstID := *id
	if firstID == "" {
		t.Fatal("the first run produced no connector id")
	}

	// The same command line again — a restart. A NEW bootstrap secret is what a re-issued command carries, and
	// it must not change the answer: the token is single-use, so its secret says nothing about identity.
	tok.Bootstrap = "one-time-2"
	f2, _, _, _, id2, _, _, _, _ := flagsFor()
	again, err := resolveConnectorEnrollment(dir, tokenFor(t, tok), f2)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if again {
		t.Fatalf("a restart with the same token re-enrolled — it must reconnect from the state")
	}
	if *id2 != firstID {
		t.Fatalf("the connector changed identity across a restart: %q -> %q", firstID, *id2)
	}
}

// ★ AND A TOKEN THAT NAMES SOMEWHERE ELSE IS A DELIBERATE MOVE. Refusing that would strand a connector an
// operator is re-homing, so it enrols again — the one case where the state is replaced.
func TestATokenForAnotherSiteStillEnrols(t *testing.T) {
	dir := t.TempDir()
	tok := connectorEnrollmentToken{V: 1, EdgeURL: "https://agents.example:443", TenantID: "tenant_a",
		Site: "site-b", Bootstrap: "one-time-1"}
	f, _, _, _, id, _, _, _, _ := flagsFor()
	if _, err := resolveConnectorEnrollment(dir, tokenFor(t, tok), f); err != nil {
		t.Fatal(err)
	}
	firstID := *id

	moved := tok
	moved.Site = "site-c"
	f2, _, _, _, id2, _, _, _, _ := flagsFor()
	again, err := resolveConnectorEnrollment(dir, tokenFor(t, moved), f2)
	if err != nil {
		t.Fatal(err)
	}
	if !again || *id2 == firstID {
		t.Fatalf("a token naming another site did not re-enrol: firstRun=%v id=%q", again, *id2)
	}
	// And the state now describes where it moved to, or the next restart would go back.
	st, ok, _ := loadConnectorState(filepath.Join(dir, "connector-state.json"))
	if !ok || st.Site != "site-c" {
		t.Fatalf("the state did not follow the move: %+v", st)
	}
}

// The guard: with no state at all a token still enrols, so the checks above are about a RESTART and not about
// the token being ignored.
func TestAFirstRunStillEnrols(t *testing.T) {
	dir := t.TempDir()
	if _, err := os.Stat(filepath.Join(dir, "connector-state.json")); err == nil {
		t.Fatal("the harness started with state")
	}
	f, _, _, _, id, _, _, _, _ := flagsFor()
	first, err := resolveConnectorEnrollment(dir, tokenFor(t, connectorEnrollmentToken{
		V: 1, EdgeURL: "https://agents.example:443", TenantID: "tenant_a", Site: "site-b", Bootstrap: "b"}), f)
	if err != nil || !first || *id == "" {
		t.Fatalf("a first run did not enrol: firstRun=%v id=%q err=%v", first, *id, err)
	}
}
