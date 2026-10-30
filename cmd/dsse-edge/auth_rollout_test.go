package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

type countingRolloutPersister struct {
	inner    blobstore.Persister
	loads    int
	failLoad bool
}

func (p *countingRolloutPersister) Load() ([]byte, error) {
	p.loads++
	if p.failLoad {
		return nil, errors.New("rollout read unavailable")
	}
	return p.inner.Load()
}
func (p *countingRolloutPersister) Save(b []byte) error { return p.inner.Save(b) }

func TestAuthDecisionSnapshotBoundsReadsAndKeepsCompletedCapability(t *testing.T) {
	p := &countingRolloutPersister{inner: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "rollout.json")}}
	s := authrollout.NewStore(p)
	m := authrollout.Manifest{Deployment: "test", Generation: 1, Members: []authrollout.Member{
		{ID: "cp", Role: "cp", Version: "next", CertificateSHA256: fmt.Sprintf("%064x", 1)},
		{ID: "edge", Role: "edge", Version: "next", CertificateSHA256: fmt.Sprintf("%064x", 2)},
	}}
	r := &authRolloutRuntime{authority: s, expected: &m.Members[1], deployment: m.Deployment}
	if err := s.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	if r.featureEnabled(authrollout.DeviceUserFeature) {
		t.Fatal("mixed rollout activated identity")
	}
	reads := p.loads
	for i := 0; i < 100; i++ {
		r.deviceUserBindingMode()
		r.featureEnabled(authrollout.SingleRequestFeature)
	}
	if p.loads != reads {
		t.Fatalf("authorization reread store %d times", p.loads-reads)
	}
	p.failLoad = true
	r.decisionMu.Lock()
	r.decisionNextRead = time.Time{}
	r.decisionMu.Unlock()
	if _, known := r.deviceUserBindingMode(); known {
		t.Fatal("mixed rollout used stale authorization state after a read failure")
	}
	p.failLoad = false
	// A write by this process bypasses the polling delay and is observed at once.
	features := []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.DeviceUserFeature}
	for _, n := range m.Members {
		if err := s.Record(context.Background(), n.CertificateSHA256, authrollout.Report{NodeID: n.ID, Generation: m.Generation, Version: "next", Features: features}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Activate(context.Background(), m.Generation, features, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !r.featureEnabled(authrollout.DeviceUserFeature) {
		t.Fatal("local activation remained cached")
	}
	p.failLoad = true
	r.decisionMu.Lock()
	r.decisionNextRead = time.Time{}
	r.decisionMu.Unlock()
	if !r.featureEnabled(authrollout.DeviceUserFeature) {
		t.Fatal("completed capability lost on read outage")
	}
}

func TestAuthEdgeDecisionSnapshotTracksSignedAdoption(t *testing.T) {
	authority, m := rolloutFixture(t)
	if err := authority.authority.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	p := &countingRolloutPersister{inner: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "edge-cache.json")}}
	edge := &authRolloutRuntime{cache: authrollout.NewCache(authrollout.NewStore(p)), expected: &m.Members[1], deployment: m.Deployment}
	mixed, err := authority.distribution(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.adopt(mixed, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if enabled, known := edge.deviceUserBindingMode(); enabled || !known {
		t.Fatal("signed mixed state unavailable")
	}
	reads := p.loads
	for i := 0; i < 100; i++ {
		edge.deviceUserBindingMode()
	}
	if p.loads != reads {
		t.Fatalf("Edge reread cache %d times", p.loads-reads)
	}
	completeRollout(t, authority, m)
	complete, err := authority.distribution(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.adopt(complete, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !edge.featureEnabled(authrollout.SingleRequestFeature) {
		t.Fatal("signed completion was not seen immediately")
	}
}

func rolloutFixture(t *testing.T) (*authRolloutRuntime, authrollout.Manifest) {
	t.Helper()
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "rollout.json")}
	s := authrollout.NewStore(p)
	m := authrollout.Manifest{Deployment: "test", Generation: 1, Members: []authrollout.Member{{ID: "cp", Role: "cp", Version: "0.3.1", CertificateSHA256: fmt.Sprintf("%064x", 1)}, {ID: "edge", Role: "edge", Version: "0.3.1", CertificateSHA256: fmt.Sprintf("%064x", 2)}}}
	return &authRolloutRuntime{authority: s, expected: &m.Members[1], deployment: m.Deployment}, m
}
func completeRollout(t *testing.T, r *authRolloutRuntime, m authrollout.Manifest) {
	t.Helper()
	for _, n := range m.Members {
		if e := r.authority.Record(context.Background(), n.CertificateSHA256, authrollout.Report{NodeID: n.ID, Generation: m.Generation, Version: "next", Features: []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature}}, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	if e := r.authority.Activate(context.Background(), m.Generation, []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature}, time.Now()); e != nil {
		t.Fatal(e)
	}
}
func TestAuthRolloutGateAcceptsLegacyOnlyDuringConfirmedMixedPhase(t *testing.T) {
	b, g := ceremonyFixture(t)
	r, m := rolloutFixture(t)
	provider := idpregistry.Connection{IdPID: "corp", TenantID: "tenant", Type: "oidc", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: "https://idp.example/token", JWKSURI: "https://idp.example/keys", ClientID: "client"}
	// Use the same registration seam as the production gate.
	registry := idpregistry.NewStore()
	if _, e := registry.Upsert(provider); e != nil {
		t.Fatal(e)
	}
	g.registry = registry
	g.rollout = r
	provider, _ = registry.Get("tenant", "corp")
	m.Providers = map[string]string{authrollout.ProviderKey("tenant", "corp"): authEvidenceProviderDigest(provider)}
	now := time.Now().UTC().Truncate(time.Second)
	legacy := grantstore.Grant{GrantID: "legacy", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app:22"}
	if _, e := b.grants.Mint(legacy, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	req := federatedRequirements{IdP: "corp", Scope: "app:22"}
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("legacy allowed without census")
	}
	if e := r.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	if !g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("issued legacy grant lost during mixed phase")
	}
	if g.hasLiveGrantWithRequirements("tenant", "other", req) {
		t.Fatal("legacy crossed device boundary")
	}
	zero := int64(0)
	single := req
	single.MaxAgeSeconds = &zero
	single.RequestID = "new-request"
	if g.hasLiveGrantWithRequirements("tenant", "device", single) {
		t.Fatal("legacy satisfied a single-request rule")
	}
	changed := provider
	changed.ClientID = "new-client"
	if _, e := registry.Upsert(changed); e != nil {
		t.Fatal(e)
	}
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("legacy survived IdP replacement")
	}
	if _, e := registry.Upsert(provider); e != nil {
		t.Fatal(e)
	}
	completeRollout(t, r, m)
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("legacy allowed after completion")
	}
}
func TestAuthRolloutRoutesRequireOperatorAndMemberCertificate(t *testing.T) {
	runtime, m := rolloutFixture(t)
	cert := &x509.Certificate{Raw: []byte("verified-test-leaf")}
	sum := sha256.Sum256(cert.Raw)
	m.Members[1].CertificateSHA256 = hex.EncodeToString(sum[:])
	if e := runtime.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	permissions := []string{}
	registerAuthRolloutRoutes(mux, func(p string, h http.HandlerFunc) http.HandlerFunc { permissions = append(permissions, p); return h }, runtime)
	if len(permissions) != 3 {
		t.Fatal("admin routes missing")
	}
	for _, p := range permissions {
		if p != "admin.platform.write" {
			t.Fatal("not deployment-operator protected")
		}
	}
	report := authrollout.Report{Generation: 1, NodeID: "edge", Version: "next", Features: []string{authrollout.EvidenceFeature}}
	raw, _ := json.Marshal(report)
	for _, verified := range []bool{false, true} {
		r := httptest.NewRequest("POST", "/fleet-capabilities/report", bytes.NewReader(raw))
		if verified {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		want := 403
		if verified {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("verified=%t status=%d body=%s", verified, w.Code, w.Body.String())
		}
	}
	report.NodeID = "cp"
	raw, _ = json.Marshal(report)
	r := httptest.NewRequest("POST", "/fleet-capabilities/report", bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatal("member impersonated CP")
	}
}
func TestAuthRolloutBundleMustBeSignedAndCannotDowngradeAfterRestart(t *testing.T) {
	r, m := rolloutFixture(t)
	if e := r.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "cache.json")}
	edge := &authRolloutRuntime{cache: authrollout.NewCache(authrollout.NewStore(p))}
	now := time.Now()
	d, _ := r.distribution(now)
	if edge.adopt(d, false, now) == nil {
		t.Fatal("unsigned authorization state accepted")
	}
	if e := edge.adopt(d, true, now); e != nil {
		t.Fatal(e)
	}
	completeRollout(t, r, m)
	done, _ := r.distribution(now.Add(time.Second))
	if e := edge.adopt(done, true, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	edge = &authRolloutRuntime{cache: authrollout.NewCache(authrollout.NewStore(p))}
	if edge.adopt(d, true, now.Add(time.Second)) == nil {
		t.Fatal("restart erased completion latch")
	}
	if e := edge.adopt(nil, false, now); e != nil {
		t.Fatal(e)
	}
	current, _ := edge.distribution(now)
	if !current.State.Complete {
		t.Fatal("old CP omission undid latch")
	}
}
