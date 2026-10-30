package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/tenantca"
)

type authResultTestStorage struct {
	mu  sync.Mutex
	raw []byte
}

func (s *authResultTestStorage) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.raw...), nil
}
func (s *authResultTestStorage) Update(edit func([]byte) ([]byte, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := edit(s.raw)
	if err == nil {
		s.raw = append([]byte(nil), next...)
	}
	return err
}

func authResultFixture(now time.Time) authFlowResult {
	return authFlowResult{RequestID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TenantID: "tenant", DeviceID: "device",
		Principal: testAuthPrincipal, Session: testAuthSession, Result: "resumed", FinalAt: now.Unix(),
		ExpiresAt: now.Unix() + int64(authFlowResultTTL/time.Second)}
}

func TestAuthResultLedgerSharedImmutableAndBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	shared := &authResultTestStorage{}
	a, b := newAuthResultLedger(shared), newAuthResultLedger(shared)
	a.clock = func() time.Time { return now }
	b.clock = a.clock
	r := authResultFixture(now)
	if err := a.Record(r); err != nil {
		t.Fatal(err)
	}
	if err := b.Record(r); err != nil {
		t.Fatal("idempotent record:", err)
	}
	if got, err := b.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "resumed" {
		t.Fatalf("other CP lookup = %q, %v", got, err)
	}
	for _, change := range []func(*authFlowResult){
		func(v *authFlowResult) { v.TenantID = "other" },
		func(v *authFlowResult) { v.DeviceID = "other" },
		func(v *authFlowResult) { v.Principal = "windows:S-1-5-21-100-200-300-1002" },
		func(v *authFlowResult) {
			v.Session = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
	} {
		wrong := r
		change(&wrong)
		if got, err := b.Lookup(wrong.RequestID, wrong.TenantID, wrong.DeviceID, wrong.Principal, wrong.Session); err != nil || got != "" {
			t.Fatalf("wrong owner revealed result %q, %v", got, err)
		}
	}
	changed := r
	changed.Result = "not_resumed"
	if err := b.Record(changed); !errors.Is(err, errAuthFlowResultConflict) {
		t.Fatalf("conflict = %v", err)
	}
	b.clock = func() time.Time { return now.Add(authFlowResultTTL) }
	if got, err := b.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "" {
		t.Fatalf("expired result = %q, %v", got, err)
	}
}

func TestAuthResultAuthorityRequiresEdgeIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := newAuthResultLedger(nil)
	store.clock = func() time.Time { return now }
	mux := http.NewServeMux()
	registerAuthResultAuthorityRoutes(mux, store, "", func(r *http.Request, tenant string) bool {
		return r.Header.Get("X-Test-Edge") == "verified" && tenant == "tenant"
	})
	r := authResultFixture(now)
	body, _ := json.Marshal(r)
	req := httptest.NewRequest(http.MethodPost, "/auth-flow-results", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unverified POST = %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/auth-flow-results", bytes.NewReader(body))
	req.Header.Set("X-Test-Edge", "verified")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("verified POST = %d", w.Code)
	}
	for _, verified := range []bool{false, true} {
		query, _ := json.Marshal(map[string]string{"request_id": r.RequestID, "tenant_id": r.TenantID, "device_id": r.DeviceID, "os_principal": r.Principal, "os_session": r.Session})
		get := httptest.NewRequest(http.MethodPost, "/auth-flow-results/query", bytes.NewReader(query))
		if verified {
			get.Header.Set("X-Test-Edge", "verified")
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, get)
		if verified && w.Code != http.StatusOK || !verified && w.Code != http.StatusNoContent {
			t.Fatalf("GET verified=%v status=%d", verified, w.Code)
		}
	}
}

func TestAuthResultAuthorityRejectsTenantEndpointAndUsesManagementDoor(t *testing.T) {
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "auth-result-ca", 82)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{"tenant": ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	edgeChains := leafSignedBy(t, ca, "edge-a", reg.Pool)
	endpointChains := leafSignedBy(t, ca, "endpoint-a", reg.Pool)
	if len(edgeChains) == 0 || len(endpointChains) == 0 {
		t.Fatal("unverified client certificate fixture")
	}
	previous := auditIngestAuthorityMap
	t.Cleanup(func() { auditIngestAuthorityMap = previous })
	now := time.Now().UTC().Truncate(time.Second)
	result := authResultFixture(now)
	body, _ := json.Marshal(result)
	store := newAuthResultLedger(nil)
	mux := http.NewServeMux()
	registerAuthResultAuthorityRoutes(mux, store, "", func(r *http.Request, tenant string) bool {
		return authResultEdgeAuthorized(r, reg, tenant)
	})
	post := func(handler http.Handler, chains [][]*x509.Certificate) int {
		req := httptest.NewRequest(http.MethodPost, "/auth-flow-results", bytes.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: chains[0][:1], VerifiedChains: chains}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	get := func(handler http.Handler, chains [][]*x509.Certificate) int {
		query, _ := json.Marshal(map[string]string{"request_id": result.RequestID, "tenant_id": result.TenantID, "device_id": result.DeviceID, "os_principal": result.Principal, "os_session": result.Session})
		req := httptest.NewRequest(http.MethodPost, "/auth-flow-results/query", bytes.NewReader(query))
		req.TLS = &tls.ConnectionState{PeerCertificates: chains[0][:1], VerifiedChains: chains}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	admin := adminSurfaceOnlyMiddleware(mux)
	data := dataPlaneOnlyMiddleware(mux)
	for _, tc := range []struct {
		name     string
		mapEdges map[string][]string
		chains   [][]*x509.Certificate
		want     int
	}{
		{"no explicit Edge map", nil, edgeChains, http.StatusForbidden},
		{"endpoint from same tenant", map[string][]string{"edge-a": {"tenant"}}, endpointChains, http.StatusForbidden},
		{"Edge not mapped to tenant", map[string][]string{"edge-a": {"other"}}, edgeChains, http.StatusForbidden},
		{"mapped Edge", map[string][]string{"edge-a": {"tenant"}}, edgeChains, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mapEdges == nil {
				auditIngestAuthorityMap = nil
			} else {
				auditIngestAuthorityMap = &auditIngestAuthority{byEdge: tc.mapEdges}
			}
			if got := post(admin, tc.chains); got != tc.want {
				t.Fatalf("admin route = %d, want %d", got, tc.want)
			}
		})
	}
	if got := post(data, edgeChains); got != http.StatusNotFound {
		t.Fatalf("result API exposed on data plane: %d", got)
	}
	auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"tenant"}}}
	if got := get(admin, edgeChains); got != http.StatusOK {
		t.Fatalf("mapped Edge could not read result: %d", got)
	}
	if got := get(admin, endpointChains); got != http.StatusNoContent {
		t.Fatalf("tenant endpoint learned final result: %d", got)
	}
	if got := get(data, edgeChains); got != http.StatusNotFound {
		t.Fatalf("result lookup exposed on data plane: %d", got)
	}
}

func TestAuthResultNotifierNeverReversesOutcome(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := newAuthResultLedger(nil)
	base := authResultFixture(now)
	base.Result = ""
	base.FinalAt, base.ExpiresAt = 0, 0
	n := &authResultNotifier{store: store, base: base}
	n.Final("resumed")
	n.Final("not_resumed") // later bridge failure cannot change the final result
	got, err := store.Lookup(base.RequestID, base.TenantID, base.DeviceID, base.Principal, base.Session)
	if err != nil || got != "resumed" {
		t.Fatalf("final result = %q, %v", got, err)
	}
}

type blockingAuthResultStore struct {
	ledger  *authResultLedger
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
}

func (s *blockingAuthResultStore) Record(r authFlowResult) error {
	close(s.entered)
	<-s.release
	err := s.ledger.Record(r)
	close(s.done)
	return err
}

func (s *blockingAuthResultStore) Lookup(id, tenant, device, principal, session string) (string, error) {
	return s.ledger.Lookup(id, tenant, device, principal, session)
}

func TestAuthResultNotifierDoesNotBlockResumedFlowOnAuthority(t *testing.T) {
	store := &blockingAuthResultStore{ledger: newAuthResultLedger(nil), entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	r := authResultFixture(time.Now().UTC().Truncate(time.Second))
	r.Result, r.FinalAt, r.ExpiresAt = "", 0, 0
	n := &authResultNotifier{store: store, base: r}
	returned := make(chan struct{})
	go func() { n.FinalAsync("resumed"); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("resumed flow waited for the CP result write")
	}
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("asynchronous result write did not start")
	}
	n.Final("not_resumed") // a later bridge failure cannot reverse the resumed result
	close(store.release)
	select {
	case <-store.done:
	case <-time.After(time.Second):
		t.Fatal("result write did not finish")
	}
	if got, err := store.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "resumed" {
		t.Fatalf("final result = %q, %v", got, err)
	}
}

func TestAuthResultRemoteRoundTripAcrossEdges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	shared := &authResultTestStorage{}
	authority := newAuthResultLedger(shared)
	authority.clock = func() time.Time { return now }
	mux := http.NewServeMux()
	registerAuthResultAuthorityRoutes(mux, authority, "", func(*http.Request, string) bool { return true })
	server := httptest.NewServer(mux)
	defer server.Close()
	a := remoteAuthResultStore{url: server.URL + "/auth-flow-results", client: server.Client()}
	b := remoteAuthResultStore{url: server.URL + "/auth-flow-results", client: server.Client()}
	r := authResultFixture(now)
	if err := a.Record(r); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != r.Result {
		t.Fatalf("other Edge lookup = %q, %v", got, err)
	}
	if got, err := b.Lookup(r.RequestID, r.TenantID, "other", r.Principal, r.Session); err != nil || got != "" {
		t.Fatalf("other device result = %q, %v", got, err)
	}
}

func TestAuthResultRemoteRealMTLSAndPrivateQuery(t *testing.T) {
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "auth-result-wire-ca", 83)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{"tenant": ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	pair := func(name string) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, &key.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
	}
	previous := auditIngestAuthorityMap
	auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"tenant"}}}
	t.Cleanup(func() { auditIngestAuthorityMap = previous })
	ledger := newAuthResultLedger(&authResultTestStorage{})
	mux := http.NewServeMux()
	registerAuthResultAuthorityRoutes(mux, ledger, "", func(r *http.Request, tenant string) bool {
		return authResultEdgeAuthorized(r, reg, tenant)
	})
	registerAuthenticationGrantAuthority(mux, grantstore.NewStore(), "", func(r *http.Request, tenant string) bool { return authResultEdgeAuthorized(r, reg, tenant) })
	server := httptest.NewUnstartedServer(adminSurfaceOnlyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth-flow-results/query" && (r.URL.RawQuery != "" || r.Method != http.MethodPost) {
			t.Errorf("result lookup leaked into request URL or used wrong method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: reg.Pool}
	server.StartTLS()
	defer server.Close()
	newClient := func(cert tls.Certificate) *http.Client {
		cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		cfg.Certificates = []tls.Certificate{cert}
		return &http.Client{Timeout: time.Second * 2, Transport: &http.Transport{TLSClientConfig: cfg}}
	}

	// The mint and boundary APIs require a mapped machine identity for the exact
	// tenant; a valid endpoint certificate is insufficient even for its own tenant.
	for _, operation := range []string{"reauthentication", "mint"} {
		for _, tc := range []struct {
			identity, tenant string
			status           int
		}{{"edge-a", "tenant", 0}, {"edge-a", "other", http.StatusForbidden}, {"endpoint-a", "tenant", http.StatusForbidden}} {
			client := newClient(pair(tc.identity))
			body, _ := json.Marshal(map[string]any{"grant": map[string]string{"tenant_id": tc.tenant}})
			response, e := client.Post(server.URL+"/authentication-grants/"+operation, "application/json", bytes.NewReader(body))
			if e != nil {
				t.Fatal(e)
			}
			response.Body.Close()
			expected := tc.status
			if expected == 0 {
				expected = http.StatusOK
				if operation == "mint" {
					expected = http.StatusBadRequest
				}
			}
			if response.StatusCode != expected {
				t.Fatalf("authority %s %s %s: got %d want %d", operation, tc.identity, tc.tenant, response.StatusCode, expected)
			}
			client.CloseIdleConnections()
		}
	}
	edge := remoteAuthResultStore{url: server.URL + "/auth-flow-results", client: newClient(pair("edge-a"))}
	endpoint := remoteAuthResultStore{url: server.URL + "/auth-flow-results", client: newClient(pair("endpoint-a"))}
	r := authResultFixture(time.Now().UTC().Truncate(time.Second))
	if err := edge.Record(r); err != nil {
		t.Fatal(err)
	}
	if got, err := edge.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "resumed" {
		t.Fatalf("verified Edge lookup = %q, %v", got, err)
	}
	if got, err := endpoint.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "" {
		t.Fatalf("endpoint learned a result: %q, %v", got, err)
	}
	forged := r
	forged.RequestID = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if err := endpoint.Record(forged); err == nil {
		t.Fatal("tenant endpoint wrote an authentication result")
	}
	if got, err := edge.Lookup(forged.RequestID, forged.TenantID, forged.DeviceID, forged.Principal, forged.Session); err != nil || got != "" {
		t.Fatalf("unverified result entered ledger: %q, %v", got, err)
	}
	legacy, err := edge.client.Get(server.URL + "/auth-flow-results?request_id=" + r.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, legacy.Body)
	legacy.Body.Close()
	if legacy.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("legacy URL lookup remains enabled: %d", legacy.StatusCode)
	}
}

func TestAuthResultMuxQueryRequiresVerifiedAdmittedDeviceAndOriginalSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := newAuthResultLedger(nil)
	store.clock = func() time.Time { return now }
	r := authResultFixture(now)
	if err := store.Record(r); err != nil {
		t.Fatal(err)
	}
	query, _ := json.Marshal(map[string]string{"request_id": r.RequestID, "os_principal": r.Principal, "os_session": r.Session})
	for _, input := range []struct {
		verified, admitted bool
		tenant, device     string
		payload            []byte
	}{
		{false, true, r.TenantID, r.DeviceID, query},
		{true, false, r.TenantID, r.DeviceID, query},
		{true, true, "other", r.DeviceID, query},
		{true, true, r.TenantID, "other", query},
		{true, true, r.TenantID, r.DeviceID, []byte(`{"request_id":"` + r.RequestID + `","os_principal":"` + r.Principal + `","os_session":"wrong"}`)},
		{true, true, r.TenantID, r.DeviceID, append(append([]byte(nil), query[:len(query)-1]...), []byte(`,"extra":"x"}`)...)},
	} {
		if got := handleAuthResultQuery(store, input.verified, input.tenant, input.device, input.admitted, input.payload); got != nil {
			t.Fatalf("unauthorized query returned %s", got)
		}
	}
	if got := handleAuthResultQuery(store, true, r.TenantID, r.DeviceID, true, query); !bytes.Contains(got, []byte(`"resumed"`)) {
		t.Fatalf("authorized query = %s", got)
	}
}

func TestAuthResultRemoteFollowsManagementDoor(t *testing.T) {
	previous := controlChannelSelector.Load()
	t.Cleanup(func() { controlChannelSelector.Store(previous) })
	data := httptest.NewServer(dataPlaneOnlyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("result reached data door") })))
	defer data.Close()
	mux := http.NewServeMux()
	ledger := newAuthResultLedger(&authResultTestStorage{})
	registerAuthResultAuthorityRoutes(mux, ledger, "", func(_ *http.Request, tenant string) bool { return tenant == "tenant" })
	management := httptest.NewServer(adminSurfaceOnlyMiddleware(mux))
	defer management.Close()
	controlChannelSelector.Store(&cpEndpointSelector{current: management.URL, currentRegion: "region-a"})
	s := remoteAuthResultStore{url: data.URL + "/auth-flow-results", client: management.Client()}
	r := authResultFixture(time.Now().UTC().Truncate(time.Second))
	r.Result = "not_resumed"
	if err := s.Record(r); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "not_resumed" {
		t.Fatalf("denial result not shared through management door: %q %v", got, err)
	}
}
