package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
)

// The directory relay uses the verified Edge machine door. A bearer on the
// admin door must not be required for a connector's own directory import.
func TestDirectoryMachineReportBindsEdgeTenantConnectorAndSourceOverTLS(t *testing.T) {
	oldSelector := controlChannelSelector.Load()
	controlChannelSelector.Store(nil)
	t.Cleanup(func() { controlChannelSelector.Store(oldSelector) })
	oldAuthority := auditIngestAuthorityMap
	auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"Acme"}}}
	t.Cleanup(func() { auditIngestAuthorityMap = oldAuthority })
	store := humanidentity.NewHumanIdentityDirectoryStore()
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-a", TenantID: "Acme", PrivateBaseURL: "https://internal.example.test"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "Acme", humanidentity.HumanIdentitySourcePolicy{
		Source: "scim", ConnectorType: "scim", Enabled: true, Metadata: map[string]any{"connector_id": "conn-a"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerHumanIdentityRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, testEvaluator(), nil,
		store, nil, registry, "", false, true, "", nil, nil)

	ca, caKey, caPEM := testAdmissionCA(t)
	oldOperatorRoots := auditIngestOperatorRoots.Load()
	if !setAuditIngestOperatorCAPEM([]byte(caPEM)) {
		t.Fatal("operator Edge authority was not loaded")
	}
	t.Cleanup(func() { auditIngestOperatorRoots.Store(oldOperatorRoots) })
	foreignCA, foreignKey, _ := testAdmissionCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pool.AddCert(foreignCA)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	clientForIssuer := func(cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) *http.Client {
		cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		if cn != "" {
			key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
				NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			der, e := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, issuerKey)
			if e != nil {
				t.Fatal(e)
			}
			cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{der, issuer.Raw}, PrivateKey: key}}
		}
		return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	}
	clientFor := func(cn string) *http.Client { return clientForIssuer(cn, ca, caKey) }
	postUsing := func(client *http.Client, tenant, connectorID, source string) int {
		t.Helper()
		report := directoryImportReport{TenantID: tenant, ConnectorID: connectorID,
			Request: humanidentity.HumanIdentityDirectoryImportRequest{Source: source,
				Identities: []model.HumanIdentity{{ID: "person-a", Subject: "person-a", Status: "active", Source: source}}}}
		body, e := json.Marshal(report)
		if e != nil {
			t.Fatal(e)
		}
		response, e := client.Post(server.URL+"/directory-import-report", "application/json", bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	post := func(cn, tenant, connectorID, source string) int {
		return postUsing(clientFor(cn), tenant, connectorID, source)
	}
	for _, tc := range []struct {
		name, cn, tenant, connectorID, source string
		status                                int
	}{
		{"no machine certificate", "", "Acme", "conn-a", "scim", http.StatusForbidden},
		{"untrusted Edge authority", "edge-b", "Acme", "conn-a", "scim", http.StatusForbidden},
		{"case-distinct tenant", "edge-a", "acme", "conn-a", "scim", http.StatusForbidden},
		{"unregistered connector", "edge-a", "Acme", "conn-other", "scim", http.StatusForbidden},
		{"unassigned source", "edge-a", "Acme", "conn-a", "other", http.StatusForbidden},
		{"authorized machine import", "edge-a", "Acme", "conn-a", "scim", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := post(tc.cn, tc.tenant, tc.connectorID, tc.source); got != tc.status {
				t.Fatalf("machine directory report status = %d, want %d", got, tc.status)
			}
		})
	}
	// The listener may trust tenant device CAs as well as the deployment's
	// operator CA. A tenant-issued certificate with an Edge's CN is still a
	// connector/device, even when that CN is present in the authority map.
	if got := postUsing(clientForIssuer("edge-a", foreignCA, foreignKey), "Acme", "conn-a", "scim"); got != http.StatusForbidden {
		t.Fatalf("tenant-issued client impersonated Edge machine: %d", got)
	}
	auditIngestAuthorityMap = nil
	if got := post("edge-a", "Acme", "conn-a", "scim"); got != http.StatusForbidden {
		t.Fatalf("tenant certificate fallback admitted an unmapped machine: %d", got)
	}
	auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"Acme"}}}
	// Use the reporter itself over a real verified client-cert TLS connection,
	// with no administrator bearer or cross-tenant elevation.
	reporter := &directoryCPReporter{url: server.URL, client: clientFor("edge-a"), outboxPath: t.TempDir() + "/outbox.jsonl"}
	if err := reporter.Report(directoryImportReport{TenantID: "Acme", ConnectorID: "conn-a",
		Request: humanidentity.HumanIdentityDirectoryImportRequest{Source: "scim",
			Identities: []model.HumanIdentity{{ID: "person-b", Subject: "person-b", Status: "active", Source: "scim"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(reporter.outboxPath); !os.IsNotExist(err) {
		t.Fatalf("verified machine report was queued instead of delivered: %v", err)
	}
	owned, err := humanidentity.HumanIdentityDirectoryList(context.Background(), store, "Acme", time.Now(), humanidentity.HumanIdentityDirectoryListOptions{})
	if err != nil || owned.Count != 2 {
		t.Fatalf("authorized tenant identities count = %d, err=%v", owned.Count, err)
	}
	foreign, err := humanidentity.HumanIdentityDirectoryList(context.Background(), store, "acme", time.Now(), humanidentity.HumanIdentityDirectoryListOptions{})
	if err != nil || foreign.Count != 0 {
		t.Fatalf("case-distinct tenant identities count = %d, err=%v", foreign.Count, err)
	}
}
