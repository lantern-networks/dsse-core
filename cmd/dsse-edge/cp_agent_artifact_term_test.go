package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestArtifactUploadCannotShelfBytesAfterLeadershipChanges(t *testing.T) {
	p, first, second := blobWriterPostgresFixture(t)
	const tenant = "tenant_lab_001"
	const bearer = "artifact-term-test-token"
	signer := updateSigner(t)
	manifest, envelope := signedUpdate(t, signer, "0.3.2", time.Now())
	store := newPublishedAgentUpdateStore().WithArtifactShelf(sharedAgentUpdateArtifactShelf(p.db))
	if err := store.LoadFromPersister(p, tenant); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.PublishContext(captureCPWriteLease(context.Background()), tenant, envelope,
		[]string{signer.PublicKeyHex()}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writer, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: tenant, TokenHash: adminTokenHash(bearer),
		CreatedByAdminPrincipalID: "operator", Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"},
		Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth,
		OperatorTenantID: tenant, PublishedAgentUpdateStore: store, AgentUpdatePins: []string{signer.PublicKeyHex()},
		AgentUpdateArtifactDir: filepath.Join(root, "artifacts")})
	path := "/admin/agent-update-artifact?platform=" + manifest.Platform + "&arch=" + manifest.Arch
	request := func(body *pausedSeatBody) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, path, body)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Operate-Tenant", tenant)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	body := &pausedSeatBody{Reader: bytes.NewReader(artifactBytesFor("0.3.2")),
		entered: make(chan struct{}), resume: make(chan struct{})}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(body) }()
	select {
	case <-body.entered:
	case rec := <-done:
		t.Fatalf("upload did not reach body: status %d", rec.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("upload body was not reached")
	}
	first.release()
	second.tick()
	if !second.IsLeader() {
		close(body.resume)
		<-done
		t.Fatal("peer did not acquire leadership")
	}
	close(body.resume)
	select {
	case rec := <-done:
		if rec.Code == http.StatusOK {
			t.Fatal("old term upload reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale upload did not finish")
	}
	blob := store.shelfFor(tenant, manifest.Platform, manifest.Arch, manifest.Version)
	raw, err := blob.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Fatal("old leader wrote shared artifact bytes after peer takeover")
	}
	// The same signed pending release remains retryable by the new leader.
	cpLeaderElectorInstance = second
	freshBody := &pausedSeatBody{Reader: bytes.NewReader(artifactBytesFor("0.3.2")),
		entered: make(chan struct{}), resume: make(chan struct{})}
	close(freshBody.resume)
	if rec := request(freshBody); rec.Code != http.StatusOK {
		t.Fatalf("current leader could not retry upload: %d", rec.Code)
	}
	if raw, err := blob.Load(); err != nil || !bytes.Equal(raw, artifactBytesFor("0.3.2")) {
		t.Fatal("new leader did not shelve verified artifact", err)
	}
	if _, err := os.Stat(artifactStorePath(filepath.Join(root, "artifacts"), tenant, manifest.Platform, manifest.Arch, manifest.Version)); err != nil {
		t.Fatal(err)
	}
}
