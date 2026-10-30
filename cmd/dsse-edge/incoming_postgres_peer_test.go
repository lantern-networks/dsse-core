package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
)

// Opt-in real PostgreSQL check. A private schema keeps this test away from a
// caller's existing admin_runtime_state row even when a test DB is reused.
func TestIncomingPostgresPeerBundleLifecycle(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for a real PostgreSQL check")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		t.Skip("this isolated-schema test requires a PostgreSQL URL DSN")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("incoming_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(`DROP SCHEMA "` + schema + `" CASCADE`); err != nil {
			t.Errorf("cleanup test schema: %v", err)
		}
	}()
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := newCPStateBlobDB(u.String(), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "admin_runtime_state"}
	one, two := policy.NewStore(nil), policy.NewStore(nil)
	for _, store := range []*policy.Store{one, two} {
		if err := store.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
	}
	tenant := testEvaluator().PolicyBundle.TenantID
	// Start a separate CP process before either incoming write. Its Store has
	// already loaded the old row when the parent CP changes the shared policy.
	childContext, stopChild := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopChild()
	child := exec.CommandContext(childContext, os.Args[0], "-test.run=^TestIncomingPostgresPeerChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_INCOMING_PEER_CHILD_DSN="+u.String())
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	lines := bufio.NewScanner(stdout)
	peerURL, peerKey := "", ""
	for lines.Scan() {
		if strings.HasPrefix(lines.Text(), "DSSE_INCOMING_PEER_READY ") {
			fields := strings.Fields(lines.Text())
			if len(fields) == 3 {
				peerURL, peerKey = fields[1], fields[2]
			}
			break
		}
	}
	if peerURL == "" || peerKey == "" {
		t.Fatalf("peer CP did not load before writes: %v %s", lines.Err(), stderr.String())
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: one, AdminAuth: newAdminAuthStore(), Writer: writer})
	restoredIncomingPost(t, first, `{"id":"rule","business_owner":"owner","expires_at":"2030-01-01T00:00:00Z","service_family":"tcp","protocol":"tcp","port":8443,"status":"active"}`, 200)
	post := httptest.NewRecorder()
	first.ServeHTTP(post, httptest.NewRequest("POST", "/admin/server-initiated", strings.NewReader(`{"enabled":true}`)))
	if post.Code != 200 {
		t.Fatalf("confirmed default write status %d", post.Code)
	}
	// The second CP loaded before either incoming write. This ordinary, unrelated
	// setting change must not write its stale empty incoming maps over the first CP.
	two.SetEastWestEnabled(tenant, true)
	source := configBundleSource{url: peerURL, client: &http.Client{Timeout: 5 * time.Second}, tenantID: tenant, verifyPubKeyHex: peerKey, requireSigned: true, interval: 25 * time.Millisecond}
	peerBundle, err := source.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !peerBundle.signatureVerified || peerBundle.TenantConfig == nil || !peerBundle.TenantConfig.ServerInitiatedEnabled || len(peerBundle.TenantConfig.LegacyExceptions) != 1 || peerBundle.TenantConfig.LegacyExceptions[0].ID != "rule" {
		t.Fatal("independent peer CP served stale incoming bundle")
	}
	edge := policy.NewStore(nil)
	edgeHTTP := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: edge, AdminAuth: newAdminAuthStore(), ConfigSourceURL: peerURL})
	readEdge := func(wantEnabled bool, wantRows int) {
		t.Helper()
		defaultResponse := httptest.NewRecorder()
		edgeHTTP.ServeHTTP(defaultResponse, httptest.NewRequest("GET", "/admin/server-initiated", nil))
		var current struct {
			Enabled bool `json:"server_initiated_enabled"`
		}
		if defaultResponse.Code != 200 || json.Unmarshal(defaultResponse.Body.Bytes(), &current) != nil || current.Enabled != wantEnabled {
			t.Fatalf("Edge default readback status=%d enabled=%t want=%t", defaultResponse.Code, current.Enabled, wantEnabled)
		}
		listResponse := httptest.NewRecorder()
		edgeHTTP.ServeHTTP(listResponse, httptest.NewRequest("GET", "/admin/legacy-exceptions", nil))
		var listed adminLegacyExceptionListResponse
		if listResponse.Code != 200 || json.Unmarshal(listResponse.Body.Bytes(), &listed) != nil || len(listed.Exceptions) != wantRows {
			t.Fatalf("Edge exception readback status=%d rows=%d want=%d", listResponse.Code, len(listed.Exceptions), wantRows)
		}
		if wantRows == 1 && listed.Exceptions[0].ID != "rule" {
			t.Fatal("Edge exception readback changed the confirmed rule")
		}
	}
	pollContext, stopPoll := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopPoll()
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		source.run(pollContext, configApplyTargets{policyStore: edge, applications: appcatalog.NewStore(), dlp: dlpStoresForTest("incoming-postgres")})
	}()
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if edge.ServerInitiatedEnabledFor(tenant) && len(edge.LegacyExceptionsFor(tenant)) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !edge.ServerInitiatedEnabledFor(tenant) || len(edge.LegacyExceptionsFor(tenant)) != 1 || edge.LegacyExceptionsFor(tenant)[0].ID != "rule" {
		t.Fatal("Edge poller did not apply the peer CP's confirmed incoming policy")
	}
	readEdge(true, 1)
	deleted := httptest.NewRecorder()
	first.ServeHTTP(deleted, httptest.NewRequest("DELETE", "/admin/legacy-exceptions/rule", nil))
	if deleted.Code != 200 {
		t.Fatalf("confirmed exception deletion status %d", deleted.Code)
	}
	post = httptest.NewRecorder()
	first.ServeHTTP(post, httptest.NewRequest("POST", "/admin/server-initiated", strings.NewReader(`{"enabled":false}`)))
	if post.Code != 200 {
		t.Fatalf("confirmed default disable status %d", post.Code)
	}
	until = time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if !edge.ServerInitiatedEnabledFor(tenant) && len(edge.LegacyExceptionsFor(tenant)) == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopPoll()
	<-pollDone
	if edge.ServerInitiatedEnabledFor(tenant) || len(edge.LegacyExceptionsFor(tenant)) != 0 {
		t.Fatal("Edge poller did not apply the peer CP's confirmed deletion and disable")
	}
	readEdge(false, 0)
	audits, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, audit := range audits {
		if audit["event_type"] == "admin_incoming_changed" && audit["tenant_id"] == tenant && audit["result"] == "success" {
			actions[fmt.Sprint(audit["action"])]++
		}
	}
	if actions["upsert_exception"] != 1 || actions["block_default"] != 1 || actions["remove_exception"] != 1 || actions["allow_default"] != 1 || len(actions) != 4 {
		t.Fatalf("expected four distinct confirmed incoming audits, got %v", actions)
	}
	if _, err := stdin.Write([]byte("done\n")); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	for lines.Scan() {
	}
	if err := child.Wait(); err != nil || lines.Err() != nil {
		t.Fatalf("independent peer CP failed: %v; scan=%v; stderr=%s", err, lines.Err(), stderr.String())
	}
	// The second CP's product handler must reload the PostgreSQL authority
	// before serving an Edge-facing bundle, even after its unrelated save.
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: two, AdminAuth: newAdminAuthStore()})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest("GET", "/admin/config-bundle", nil))
	if response.Code != 200 {
		t.Fatalf("second CP bundle status %d: %s", response.Code, response.Body)
	}
	var bundle configBundlePayload
	if err := json.Unmarshal(response.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.TenantConfig == nil || bundle.TenantConfig.ServerInitiatedEnabled || len(bundle.TenantConfig.LegacyExceptions) != 0 {
		t.Fatalf("second CP served stale incoming policy: %+v", bundle.TenantConfig)
	}
	if err := two.RefreshSharedRuntime(); err != nil || two.ServerInitiatedEnabledFor(tenant) || len(two.LegacyExceptionsFor(tenant)) != 0 {
		t.Fatalf("unrelated CP save erased incoming policy: %v", err)
	}
	fresh := policy.NewStore(nil)
	if err := fresh.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if fresh.ServerInitiatedEnabledFor(tenant) || len(fresh.LegacyExceptionsFor(tenant)) != 0 {
		t.Fatal("PostgreSQL reload lost incoming policy")
	}
	raw, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		EastWest map[string]bool `json:"east_west_enabled"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || !document.EastWest[tenant] {
		t.Fatalf("unrelated CP write did not persist: %v", err)
	}
}

func TestIncomingPostgresPeerChild(t *testing.T) {
	dsn := os.Getenv("DSSE_INCOMING_PEER_CHILD_DSN")
	if dsn == "" {
		t.Skip("only run as the PostgreSQL peer subprocess")
	}
	db, err := newCPStateBlobDB(dsn, "../../migrations", false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := policy.NewStore(nil)
	if err := store.SetRuntimeStatePersister(postgresBlobPersister{db: db, key: "admin_runtime_state"}); err != nil {
		t.Fatal(err)
	}
	signer := testAgentPolicySigner(t)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: store, AdminAuth: newAdminAuthStore(), AgentPolicySigner: signer})
	server := httptest.NewServer(h)
	defer server.Close()
	fmt.Fprintln(os.Stdout, "DSSE_INCOMING_PEER_READY", server.URL, signer.PublicKeyHex())
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
}

// The original candidate used a helper from its separate API test file.
func restoredIncomingPost(t *testing.T, h http.Handler, body string, want int) {
	t.Helper()
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/admin/legacy-exceptions", strings.NewReader(body)))
	if r.Code != want {
		t.Fatalf("incoming write status=%d want=%d", r.Code, want)
	}
}
