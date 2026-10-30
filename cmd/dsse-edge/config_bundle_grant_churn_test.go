package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/migrations"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestGrantStreamConfigurationConvergesDuringLoginChurn(t *testing.T) {
	p := &grantPageSharedAuthority{}
	a, w := grantstore.NewStore(), grantstore.NewStore()
	for _, s := range []*grantstore.Store{a, w} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	exerciseGrantStreamConfigurationChurn(t, a, w)
}

// This test owns a disposable database's production keys and revision trigger.
func TestPostgresGrantStreamConfigurationConvergesDuringLoginChurn(t *testing.T) {
	dsn := os.Getenv("DSSE_GRANT_PAGES_TEST_DSN")
	if dsn == "" {
		t.Skip("DSSE_GRANT_PAGES_TEST_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE cp_state_blobs (store_key text PRIMARY KEY, payload bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal("fresh database required: ", err)
	}
	defer func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS cp_state_blobs`)
		_, _ = db.Exec(`DROP FUNCTION IF EXISTS dsse_stamp_grant_blob_revision()`)
		_, _ = db.Exec(`DROP SEQUENCE IF EXISTS dsse_grant_blob_revision_seq`)
	}()
	ddl, err := os.ReadFile("../../migrations/056_grant_blob_revision.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range migrations.SplitSQLStatements(string(ddl)) {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	a, w := grantstore.NewStore(), grantstore.NewStore()
	for _, s := range []*grantstore.Store{a, w} {
		if err := s.SetPersister(grantstore.NewCachedRollingPersister(postgresGrantPair{db: db})); err != nil {
			t.Fatal(err)
		}
	}
	exerciseGrantStreamConfigurationChurn(t, a, w)
}

type grantChurnEdgeInstance struct {
	token    string
	status   *configBundleSyncStatus
	attempts atomic.Uint64
}

func exerciseGrantStreamConfigurationChurn(t *testing.T, a, w *grantstore.Store) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rows := make([]grantstore.Grant, 30000)
	for i := range rows {
		rows[i] = grantstore.Grant{GrantID: fmt.Sprintf("churn-%06d", i), TenantID: "tenant", UserID: fmt.Sprintf("user-%d", i), DeviceID: "device", IdPID: "idp", Scope: "app:22", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	}
	if _, _, err := w.MergeAuthorityEvidence(rows, now); err != nil {
		t.Fatal(err)
	}
	if err := a.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	// Instrumented race runs decode several 30,000-row snapshots considerably
	// slower than normal builds. This is a test watchdog, not a product deadline
	// or a relaxation of the one-attempt assertions below.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	started := time.Now()
	var writes atomic.Uint64
	writerReady := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		tick := time.NewTicker(125 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				writerDone <- nil
				return
			case <-tick.C:
				_, err := a.Mint(grantstore.Grant{GrantID: fmt.Sprintf("login-%06d", writes.Load()), TenantID: "tenant", UserID: "new-user", DeviceID: "device", IdPID: "idp", Scope: "app:22"}, time.Hour, time.Now())
				if err != nil {
					writerDone <- err
					return
				}
				if writes.Add(1) == 1 {
					close(writerReady)
				}
			}
		}
	}()
	defer func() {
		cancel()
		if err := <-writerDone; err != nil {
			t.Error(err)
		}
	}()
	signer := testAgentPolicySigner(t)
	select {
	case <-writerReady:
	case <-ctx.Done():
		t.Fatal("local login writer never committed")
	}
	// Exercise the real CP route, including all its refresh/generation checks,
	// while the same authority Store handles local login writes. The later sync
	// phases use an explicit epoch fixture to isolate a CP incarnation change
	// without launching another process or sharing the Edge's global store.
	exerciseProductionGrantSnapshotUnderChurn(t, ctx, a, signer, &writes)
	var stateMu sync.Mutex
	epoch, generation, decision := "epoch-one", uint64(1), "deny"
	instances := map[string]*grantChurnEdgeInstance{}
	var totalRequests, pages atomic.Uint64
	delayedEntered, delayedRelease, delayedDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseDelayed := func() { releaseOnce.Do(func() { close(delayedRelease) }) }
	handlers := map[string]http.Handler{}
	for _, e := range []string{"epoch-one", "epoch-two"} {
		m := http.NewServeMux()
		registerGrantBundlePages(m, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, func() *grantstore.Store { return a }, signer, e, "", true)
		handlers[e] = m
	}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// A canceled client can finish before its server handler does. Hold an
		// old instance's request across replacement to exercise that ordering.
		delayed := r.Header.Get("X-Test-Delay-Old-Edge") == "1"
		if delayed {
			close(delayedEntered)
			<-delayedRelease
			defer close(delayedDone)
		}
		stateMu.Lock()
		e, g, d := epoch, generation, decision
		instance := instances[r.Header.Get("Authorization")]
		stateMu.Unlock()
		if instance == nil {
			http.Error(rw, "unknown test Edge instance", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/admin/grant-bundle-page" {
			handlers[e].ServeHTTP(&grantPageFlushWriter{ResponseWriter: rw, after: func() { pages.Add(1) }}, r)
			return
		}
		if r.URL.Path != "/admin/config-bundle" {
			http.NotFound(rw, r)
			return
		}
		observed := instance.status.snapshot()
		if observed["have_applied"] != true || observed["last_applied_epoch"] != e || observed["last_applied_generation"] != g {
			instance.attempts.Add(1)
			totalRequests.Add(1)
		}
		if delayed {
			// Only the old request's attribution is under test here; the real
			// configuration/stream requests below retain the full workload.
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		grantGeneration, err := a.SnapshotGenerationChecked()
		if err != nil {
			http.Error(rw, "authority unavailable", 503)
			return
		}
		payload := configBundlePayload{Epoch: e, Generation: g, Policies: []model.Policy{{ID: "live-policy", TenantID: "tenant", Status: "active", Conditions: map[string]any{"service_family": "ssh"}, Action: model.PolicyAction{Decision: d}}}, GrantPages: &grantBundleReference{Protocol: grantPageProtocol, Epoch: e, Generation: grantGeneration}}
		env, err := signer.Sign(payload, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(rw).Encode(env)
	}))
	defer server.Close()
	defer releaseDelayed()
	prior := theGrantStore.Load()
	defer theGrantStore.Store(prior)
	start := func(startGate <-chan struct{}) (*grantChurnEdgeInstance, *policy.Store, context.CancelFunc, <-chan struct{}) {
		theGrantStore.Store(grantstore.NewStore())
		instance := &grantChurnEdgeInstance{status: &configBundleSyncStatus{}}
		stateMu.Lock()
		instance.token = fmt.Sprintf("fixture-edge-%d", len(instances)+1)
		instances["Bearer "+instance.token] = instance
		stateMu.Unlock()
		policies := policy.NewStore(nil)
		child, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		source := configBundleSource{url: server.URL, tenantID: "tenant", token: instance.token, client: server.Client(), interval: time.Second, verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true, status: instance.status}
		go func() {
			defer close(done)
			if startGate != nil {
				select {
				case <-startGate:
				case <-child.Done():
					return
				}
			}
			source.run(child, configApplyTargets{policyStore: policies})
		}()
		return instance, policies, stop, done
	}
	wait := func(status *configBundleSyncStatus, e string, g uint64) {
		t.Helper()
		for {
			s := status.snapshot()
			if s["have_applied"] == true && s["last_applied_epoch"] == e && s["last_applied_generation"] == g {
				return
			}
			if ctx.Err() != nil {
				t.Fatalf("configuration failed to converge: %v", s)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	instance, policies, stop, done := start(nil)
	defer func() { stop(); <-done }()
	wait(instance.status, "epoch-one", 1)
	if got := instance.attempts.Load(); got != 1 {
		t.Fatalf("initial baseline took %d polls, want 1", got)
	}
	if len(theGrantStore.Load().ListAll()) < len(rows) {
		t.Fatal("snapshot omitted grants")
	}
	stateMu.Lock()
	generation, decision = 2, "allow"
	before := instance.attempts.Load()
	stateMu.Unlock()
	wait(instance.status, "epoch-one", 2)
	if got := instance.attempts.Load() - before; got != 1 {
		t.Fatalf("policy update took %d polls under grant churn, want 1", got)
	}
	if p, ok, err := policies.Get(ctx, "tenant", "live-policy"); err != nil || !ok || p.Action.Decision != "allow" {
		t.Fatal("updated policy not applied")
	}
	if _, _, err := w.RequireReauthenticationForTenantContext(ctx, "tenant", rows[0].GrantID, time.Now()); err != nil {
		t.Fatal(err)
	}
	for theGrantStore.Load().Valid(rows[0].GrantID, time.Now()) {
		if ctx.Err() != nil {
			t.Fatal("grant-only revocation never arrived")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if instance.status.snapshot()["last_applied_generation"] != uint64(2) {
		t.Fatal("grant-only update changed configuration generation")
	}
	stateMu.Lock()
	epoch, generation = "epoch-two", 1
	before = instance.attempts.Load()
	stateMu.Unlock()
	wait(instance.status, "epoch-two", 1)
	if got := instance.attempts.Load() - before; got != 1 {
		t.Fatalf("CP restart took %d polls, want 1", got)
	}
	// Reproduce the old fixture race deterministically: a request from the
	// retiring Edge remains in the server after its client has canceled. Its
	// delayed accounting must stay bound to that Edge, never the new one.
	retired := instance
	retiredAttempts := retired.attempts.Load()
	oldContext, cancelOld := context.WithCancel(ctx)
	defer cancelOld()
	oldRequest, err := http.NewRequestWithContext(oldContext, http.MethodGet, server.URL+"/admin/config-bundle", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldRequest.Header.Set("Authorization", "Bearer "+retired.token)
	oldRequest.Header.Set("X-Test-Delay-Old-Edge", "1")
	oldClientDone := make(chan struct{})
	go func() {
		defer close(oldClientDone)
		response, _ := server.Client().Do(oldRequest)
		if response != nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-delayedEntered:
	case <-ctx.Done():
		t.Fatal("old request did not enter barrier")
	}
	cancelOld()
	<-oldClientDone
	stop()
	<-done
	newStartGate := make(chan struct{})
	instance, _, stop, done = start(newStartGate)
	releaseDelayed()
	<-delayedDone
	if got := instance.attempts.Load(); got != 0 {
		t.Fatalf("old canceled request counted against new Edge before its first poll: %d", got)
	}
	if got := retired.attempts.Load(); got != retiredAttempts {
		t.Fatalf("canceled old Edge request used new status: old attempts=%d, want %d", got, retiredAttempts)
	}
	close(newStartGate)
	wait(instance.status, "epoch-two", 1)
	if got := instance.attempts.Load(); got != 1 {
		t.Fatalf("new Edge took %d polls, want 1", got)
	}
	if theGrantStore.Load().Valid(rows[0].GrantID, time.Now()) {
		t.Fatal("new Edge missed stored revocation")
	}
	if writes.Load() < 3 || pages.Load() < 50 {
		t.Fatalf("insufficient workload: writes=%d pages=%d", writes.Load(), pages.Load())
	}
	elapsed := time.Since(started)
	t.Logf("initial grants=30000 writes=%d measured_writes_per_second=%.2f pages=%d configuration_attempts=%d elapsed=%s applied_grant_generation=%v", writes.Load(), float64(writes.Load())/elapsed.Seconds(), pages.Load(), totalRequests.Load(), elapsed, instance.status.snapshot()["last_grant_generation"])
}

func exerciseProductionGrantSnapshotUnderChurn(t *testing.T, ctx context.Context, authority *grantstore.Store, signer *agentpolicy.Signer, writes *atomic.Uint64) {
	t.Helper()
	wasCP, priorOperator, priorGrant := edgeIsControlPlane, operatorTenantConfigured(), theGrantStore.Load()
	edgeIsControlPlane = true
	defer func() {
		edgeIsControlPlane = wasCP
		declareOperatorTenant(priorOperator, false)
		theGrantStore.Store(priorGrant)
	}()
	auth := newAdminAuthStore()
	now := time.Now()
	auth.UpsertPrincipal(adminPrincipal{ID: "reader", TenantID: "operator", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "reader", TenantID: "operator", TokenHash: adminTokenHash("fixture-reader"), Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: "reader", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", PolicyStore: policy.NewStore(nil), AgentPolicySigner: signer, FleetConfigStatus: newFleetConfigStatusStore(time.Second)})
	theGrantStore.Store(authority)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/grant-bundle-page" {
			// A slow receiver makes writes overlap the actual production stream,
			// rather than merely starting a writer beside a sub-millisecond read.
			h.ServeHTTP(&grantPageFlushWriter{ResponseWriter: w, after: func() {
				select {
				case <-time.After(100 * time.Millisecond):
				case <-r.Context().Done():
				}
			}}, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	source := configBundleSource{url: server.URL, client: server.Client(), token: "fixture-reader", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	before := writes.Load()
	payload, err := source.fetch(ctx)
	if err != nil || payload.GrantPages == nil {
		t.Fatalf("production config-bundle failed during local login writes: %v", err)
	}
	rows, err := source.fetchGrantPages(ctx, *payload.GrantPages)
	if err != nil || rows == nil || len(rows.Grants)+len(rows.ProtectedGrants) < 30000 {
		t.Fatalf("production grant stream failed during local login writes: %v", err)
	}
	if writes.Load() <= before {
		t.Fatal("no local login committed during production snapshot transfer")
	}
	t.Logf("production config-bundle and grant stream completed with same-Store login writer; overlapping_writes=%d snapshot_generation=%d", writes.Load()-before, rows.generation)
}

func TestIncompleteGrantStreamDoesNotPartiallyApplyConfiguration(t *testing.T) {
	signer := testAgentPolicySigner(t)
	policyRow := model.Policy{ID: "existing-policy", TenantID: "tenant", Status: "active", Conditions: map[string]any{"service_family": "ssh"}, Action: model.PolicyAction{Decision: "allow"}}
	policies := policy.NewStore([]model.Policy{policyRow})
	if seeded, ok, err := policies.Get(t.Context(), "tenant", policyRow.ID); err != nil || !ok || seeded.Action.Decision != "allow" {
		t.Fatal("test baseline policy was not installed")
	}
	policyRow.Action.Decision = "deny"
	ref := grantBundleReference{Protocol: grantPageProtocol, Epoch: "epoch", Generation: 2}
	payload := configBundlePayload{Epoch: ref.Epoch, Generation: 2, Policies: []model.Policy{policyRow}, GrantPages: &ref}
	page := grantBundlePage{Protocol: grantPageProtocol, Epoch: ref.Epoch, Generation: ref.Generation, Offset: 0, NextOffset: 1, Total: 2, Grants: &grantBundle{Complete: true, Grants: []grantstore.Grant{{GrantID: "first"}}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body any = payload
		if r.URL.Path == "/admin/grant-bundle-page" {
			body = page
		}
		envelope, err := signer.Sign(body, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	status := &configBundleSyncStatus{}
	source := configBundleSource{url: server.URL, client: server.Client(), interval: time.Hour, verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true, status: status}
	done := make(chan struct{})
	go func() { defer close(done); source.run(ctx, configApplyTargets{policyStore: policies}) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for status.snapshot()["last_error"] == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	observed := status.snapshot()
	if observed["have_applied"] == true || observed["last_error"] == nil {
		t.Fatal("truncated grant stream was acknowledged")
	}
	stored, found, err := policies.Get(ctx, "tenant", policyRow.ID)
	if err != nil || !found || stored.Action.Decision != "allow" {
		t.Fatal("configuration changed before grant stream completed")
	}
}
