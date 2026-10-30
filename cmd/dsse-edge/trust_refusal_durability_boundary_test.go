package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRefusalReportDoesNotAcknowledgeAnUndurableJournal(t *testing.T) {
	oldTrust, oldInterception := trustRefusals, interceptionRefusals
	t.Cleanup(func() { trustRefusals, interceptionRefusals = oldTrust, oldInterception })
	root := t.TempDir()
	blocked := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	trustRefusals = newTrustRefusalStore(filepath.Join(blocked, "trust.json"))
	interceptionRefusals = newTrustRefusalStore(filepath.Join(root, "interception.json"))
	handler := observedTestServer(t, nil, newObservedExclusionStore(0))
	entry := observedTrustRefusal{Reason: "unknown authority", FirstAt: time.Now(), LastAt: time.Now(), Count: 1}
	body, err := json.Marshal(map[string]any{"trust_refusals": []observedTrustRefusal{entry}})
	if err != nil {
		t.Fatal(err)
	}
	cert := leafWithCN(t, "mac-dev-1")
	send := func() int {
		req := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	if status := send(); status != http.StatusServiceUnavailable {
		t.Fatalf("undurable refusal report status = %d, want retryable 503", status)
	}
	if len(trustRefusals.ForTenant("t1")) != 0 {
		t.Fatal("failed persistence changed the in-memory committed view")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	trustRefusals = newTrustRefusalStore(filepath.Join(blocked, "trust.json"))
	if status := send(); status != http.StatusNoContent {
		t.Fatalf("replayed refusal report status = %d, want 204", status)
	}
	if got := newTrustRefusalStore(filepath.Join(blocked, "trust.json")).ForTenant("t1"); len(got["mac-dev-1"]) != 1 {
		t.Fatal("retry did not durably preserve the refusal")
	}
}

func TestCorruptRefusalJournalIsNotOverwrittenByNextReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	original := []byte("{broken journal")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store := newTrustRefusalStore(path)
	if _, err := store.Merge("t1", "mac-dev-1", []observedTrustRefusal{{Reason: "unknown authority", Count: 1}}); err == nil {
		t.Fatal("corrupt durable evidence was acknowledged")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("corrupt original evidence was overwritten")
	}
}

func TestTrustRefusalsKeepCaseDistinctOrganizationsSeparate(t *testing.T) {
	store := newTrustRefusalStore(filepath.Join(t.TempDir(), "trust.json"))
	if _, err := store.Merge("TenantA", "device-one", []observedTrustRefusal{{Reason: "unknown authority", Count: 1}}); err != nil {
		t.Fatal(err)
	}
	if got := store.ForTenant("tenanta"); len(got) != 0 {
		t.Fatalf("case-distinct organization read another tenant's refusals: %+v", got)
	}
}

func TestTrustRefusalJournalWithoutDurablePathRefusesNewEvidence(t *testing.T) {
	store := newTrustRefusalStore("")
	if _, err := store.Merge("tenant", "device", []observedTrustRefusal{{Reason: "unknown authority"}}); err == nil {
		t.Fatal("volatile journal acknowledged the device's only copy")
	}
	if got := store.ForTenant("tenant"); len(got) != 0 {
		t.Fatal("rejected evidence became visible as committed")
	}
}
