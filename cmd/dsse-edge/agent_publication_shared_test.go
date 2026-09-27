package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSharedPublicationKeepsPeerAndLatestPending(t *testing.T) {
	p := &transactionalCAFixture{}
	a, b := newPublishedAgentUpdateStore(), newPublishedAgentUpdateStore()
	for _, s := range []*publishedAgentUpdateStore{a, b} {
		if err := s.LoadFromPersister(p, "a"); err != nil {
			t.Fatal(err)
		}
	}
	signer := updateSigner(t)
	keys := []string{signer.PublicKeyHex()}
	now := time.Now()
	_, ea := signedUpdate(t, signer, "0.3.1", now)
	_, eb := signedUpdate(t, signer, "0.3.2", now)
	ready := func(agentupdate.Manifest) bool { return true }
	if _, _, _, err := a.Publish("a", ea, keys, now, ready); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := b.Publish("b", eb, keys, now, ready); err != nil {
		t.Fatal(err)
	}
	fresh := newPublishedAgentUpdateStore()
	if err := fresh.LoadFromPersister(p, "a"); err != nil {
		t.Fatal(err)
	}
	if len(fresh.ForTenant("a")) != 1 || len(fresh.ForTenant("b")) != 1 {
		t.Fatal("stale publication removed peer release")
	}
	if _, _, _, err := a.Publish("a", ea, keys, now, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := b.Publish("a", eb, keys, now, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.Activate("a", agentupdate.PlatformWindows, agentupdate.ArchAMD64, ea.PayloadSHA256); err == nil || ok {
		t.Fatal("stale upload activated replaced pending manifest")
	}
}

func TestSharedPublicationFailurePreservesLiveAndErasure(t *testing.T) {
	p := &transactionalCAFixture{}
	s := newPublishedAgentUpdateStore()
	if err := s.LoadFromPersister(p, "a"); err != nil {
		t.Fatal(err)
	}
	signer := updateSigner(t)
	keys := []string{signer.PublicKeyHex()}
	now := time.Now()
	_, env := signedUpdate(t, signer, "0.3.1", now)
	if _, _, _, err := s.Publish("a", env, keys, now, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := p.Load()
	p.failCommit = true
	if ok, err := s.Activate("a", agentupdate.PlatformWindows, agentupdate.ArchAMD64, env.PayloadSHA256); err == nil || ok {
		t.Fatal("unconfirmed activation")
	}
	if len(s.ForTenant("a")) != 0 || len(s.PendingFor("a")) != 1 {
		t.Fatal("failed commit changed local state")
	}
	if n, err := s.RemoveTenantChecked("a"); err == nil || n != 0 {
		t.Fatal("unconfirmed erasure")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("failed commit changed durable state")
	}
	p.failCommit = false
	if n, err := s.RemoveTenantChecked("a"); err != nil || n != 1 {
		t.Fatal("retry failed", n, err)
	}
	if _, _, _, err := s.Publish("b", env, keys, now, nil); err != nil {
		t.Fatal(err)
	}
	fresh := newPublishedAgentUpdateStore()
	fresh.LoadFromPersister(p, "b")
	if len(fresh.PendingFor("a")) != 0 || len(fresh.PendingFor("b")) != 1 {
		t.Fatal("peer erasure resurrected")
	}
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`{"schema":"published_agent_updates.v2"}`), []byte(`broken`)} {
		p.mu.Lock()
		p.raw = bad
		p.mu.Unlock()
		if _, _, err := s.PublicationFor(context.Background(), "b"); err == nil {
			t.Fatal("unavailable row accepted", string(bad))
		}
	}
}

func TestPostgresPublicationRequestTermAndPeer(t *testing.T) {
	d, _, a, b := trustDistributionPostgresFixture(t)
	blob := d.store.(postgresBlobPersister)
	blob.key = "agent_updates"
	s, peer := newPublishedAgentUpdateStore(), newPublishedAgentUpdateStore()
	for _, store := range []*publishedAgentUpdateStore{s, peer} {
		if err := store.LoadFromPersister(blob, "a"); err != nil {
			t.Fatal(err)
		}
	}
	signer := updateSigner(t)
	keys := []string{signer.PublicKeyHex()}
	now := time.Now()
	_, env := signedUpdate(t, signer, "0.3.1", now)
	if _, _, _, err := s.Publish("a", env, keys, now, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := peer.Publish("b", env, keys, now, nil); err != nil {
		t.Fatal(err)
	}
	_, pending, err := s.PublicationFor(context.Background(), "b")
	if err != nil || len(pending) != 1 {
		t.Fatal("peer not refreshed", err)
	}
	old := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	b.release()
	a.tick()
	before, _ := blob.Load()
	if _, _, _, err := s.PublishContext(old, "c", env, keys, now, nil); err == nil {
		t.Fatal("old request published")
	}
	if ok, err := s.ActivateContext(old, "a", agentupdate.PlatformWindows, agentupdate.ArchAMD64, env.PayloadSHA256); err == nil || ok {
		t.Fatal("old request activated")
	}
	if n, _, err := s.removeTenantWithCleanupContext(old, "a"); err == nil || n != 0 {
		t.Fatal("old request erased")
	}
	after, _ := blob.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("old term changed state")
	}
	if ok, err := s.Activate("a", agentupdate.PlatformWindows, agentupdate.ArchAMD64, env.PayloadSHA256); err != nil || !ok {
		t.Fatal("current activation failed", err)
	}
	if n, err := peer.RemoveTenantChecked("b"); err != nil || n != 1 {
		t.Fatal("current erasure failed", err)
	}
	fresh := newPublishedAgentUpdateStore()
	if err := fresh.LoadFromPersister(blob, "a"); err != nil {
		t.Fatal(err)
	}
	if len(fresh.ForTenant("a")) != 1 || len(fresh.PendingFor("b")) != 0 {
		t.Fatal("peer activation/erasure lost")
	}
	// Actual HTTP handler must preserve the term accepted before body decoding.
	h := newSignRouteHarness(t, signer)
	h.store.LoadFromPersister(blob, "a")
	body, _ := json.Marshal(env)
	req := httptest.NewRequest("PUT", "/admin/agent-updates", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, adminIdentity{PrincipalID: "test", TenantID: "a", AuthMethod: "admin_session"}))
	req.Body = &enrolmentTermBody{Reader: strings.NewReader(string(body)), before: func() { a.release(); b.tick(); b.release(); a.tick() }}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("old HTTP term response: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPublicationFailureAuditHasIndependentIdentity(t *testing.T) {
	signer := updateSigner(t)
	h := newSignRouteHarness(t, signer)
	p := &transactionalCAFixture{failCommit: true}
	h.store.LoadFromPersister(p, "a")
	m := publishableManifest(time.Now())
	status, _ := h.post(t, "a", m)
	if status != 503 {
		t.Fatal(status)
	}
	var rows []map[string]any
	filepath.Walk(filepath.Join(h.dir, "logs"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".jsonl") {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
				var row map[string]any
				if json.Unmarshal(line, &row) == nil {
					rows = append(rows, row)
				}
			}
		}
		return nil
	})
	if len(rows) != 2 {
		t.Fatalf("attempt/refusal missing: %d", len(rows))
	}
	if rows[0]["id"] == rows[1]["id"] {
		t.Fatal("failure reuses attempt identity")
	}
	if rows[1]["event_type"] != "agent_update_publish_failed" || rows[1]["result"] != "error" {
		t.Fatal(rows[1])
	}
	metadata := rows[1]["metadata"].(map[string]any)
	if metadata["agent_version"] != m.Version {
		t.Fatal("verified manifest attribution missing")
	}
}
