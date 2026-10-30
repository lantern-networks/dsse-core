package grantstore

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSnapshotVersionFencesLegacySharedWriter(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := grantFixture("bound", now)
	g.Issuer = "https://idp.example"
	g.UserID = "user"
	g.IdPID = "corp"
	g.ProviderConfigSHA256 = strings.Repeat("a", 64)
	g.Scope = "app:22"
	g.AuthTime = now.Format(time.RFC3339)
	g.ReauthenticationStartedAt = now.Add(-time.Second).Format(time.RFC3339)
	legacy, _ := json.Marshal(map[string]Grant{g.GrantID: g})
	p := &grantSharedFixture{raw: legacy}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	// First successful updated writer moves the old snapshot to the fenced form.
	if _, err := s.Mint(Grant{GrantID: "second", TenantID: g.TenantID}, time.Minute, now); err != nil {
		t.Fatal(err)
	}
	before, _ := p.Load()
	// Same old JSON map codec and transactional writer shape. It cannot reach the
	// marshal step that would erase issuer/freshness fields from unrelated rows.
	err := p.UpdateContext(context.Background(), func(raw []byte) ([]byte, error) {
		type oldGrant struct {
			GrantID  string `json:"grant_id"`
			TenantID string `json:"tenant_id"`
		}
		var old map[string]oldGrant
		if err := json.Unmarshal(raw, &old); err != nil {
			return nil, err
		}
		return json.Marshal(old)
	})
	if err == nil {
		t.Fatal("old writer silently accepted new schema")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("old writer changed evidence")
	}
	peer := NewStore()
	if err := peer.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, ok := peer.Get(g.GrantID)
	if !ok || got.ProviderConfigSHA256 != g.ProviderConfigSHA256 || got.ReauthenticationStartedAt != g.ReauthenticationStartedAt {
		t.Fatal("evidence lost during migration")
	}
	if _, err := decodeShared([]byte(`{"schema_version":4,"grants":{}}`)); err == nil {
		t.Fatal("unknown future schema accepted")
	}
}
