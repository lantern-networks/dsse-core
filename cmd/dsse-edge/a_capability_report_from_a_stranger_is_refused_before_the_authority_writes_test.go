package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/authrollout"
)

// Security review S7 (2026-11-07). The capability report accepted any VERIFIED client certificate at the door
// and only the store, inside its transaction, noticed the certificate was nobody in the census. On the agent
// plane every enrolled device presents a verified certificate, so every device could make the authority open a
// transaction. A stranger is now turned away with 403 before the write lease and the store.
func TestACapabilityReportFromAStrangerIsRefusedBeforeTheAuthorityWrites(t *testing.T) {
	runtime, m := rolloutFixture(t)
	member := &x509.Certificate{Raw: []byte("member-leaf")}
	sum := sha256.Sum256(member.Raw)
	m.Members[1].CertificateSHA256 = hex.EncodeToString(sum[:])
	if e := runtime.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	registerAuthRolloutRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, runtime)
	report := authrollout.Report{Generation: 1, NodeID: "edge", Version: "next", Features: []string{authrollout.EvidenceFeature}}
	raw, _ := json.Marshal(report)

	stranger := &x509.Certificate{Raw: []byte("an-enrolled-laptop")}
	r := httptest.NewRequest("POST", "/fleet-capabilities/report", bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{stranger}, VerifiedChains: [][]*x509.Certificate{{stranger}}}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a verified certificate the census does not name answered %d, want 403: %s", w.Code, w.Body.String())
	}
	state, err := runtime.authority.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Observed) != 0 {
		t.Fatalf("the stranger's report was recorded: %+v", state.Observed)
	}

	// The member it impersonated still reports normally.
	r = httptest.NewRequest("POST", "/fleet-capabilities/report", bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{member}, VerifiedChains: [][]*x509.Certificate{{member}}}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("the census member answered %d: %s", w.Code, w.Body.String())
	}
}
