package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestRuntimeEditsPreservePeerControls(t *testing.T) {
	p := &trSharedPersister{}
	a, b := NewStore(nil), NewStore(nil)
	for _, s := range []*Store{a, b} {
		if err := s.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
	}
	yes := true
	ttl := 120
	if err := a.ApplyEastWestUpdateConfirmed("peer", nil, &ttl, &yes, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.SetServerInitiatedEnabledConfirmed("local", true); err != nil {
		t.Fatal(err)
	}
	restored := NewStore(nil)
	if err := restored.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if !restored.EastWestIsEnabled("peer") || restored.EastWestMaxGrantTTL("peer") != 120 {
		t.Fatal("incoming edit erased peer East-West controls")
	}
	if err := a.UpsertLegacyExceptionConfirmed("local", model.LegacyException{ID: "one", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpsertLegacyExceptionConfirmed("local", model.LegacyException{ID: "two", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.MutateLegacyExceptionConfirmed("local", "two", func(ex model.LegacyException) (model.LegacyException, error) {
		ex.BusinessOwner = "edited"
		return ex, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restored.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	rows := restored.LegacyExceptionsFor("local")
	if len(rows) != 2 || rows[1].Port != 22 || !restored.ServerInitiatedEnabledFor("local") {
		t.Fatal("exception partial edit erased latest row")
	}
}

func TestPolicyDeleteAndStatusWaitForConfirmedSave(t *testing.T) {
	p := &incomingFaultStore{}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	item := model.Policy{ID: "authored", Name: "authored", Conditions: map[string]any{"sni": "example.invalid"}, Status: "active", Action: model.PolicyAction{Decision: "allow"}}
	if _, err := s.Upsert(context.Background(), item, "tenant", time.Now()); err != nil {
		t.Fatal(err)
	}
	p.failure = errors.New("disk unavailable")
	if _, removed, err := s.Delete(context.Background(), "tenant", "authored"); err == nil || removed {
		t.Fatal("delete reported success before confirmed save")
	}
	if s.SetPolicyStatus("tenant", "authored", "disabled") {
		t.Fatal("status reported success before confirmed save")
	}
	got, ok, _ := s.Get(context.Background(), "tenant", "authored")
	if !ok || got.Status != "active" {
		t.Fatal("failed save changed effective policy")
	}
}

func TestRuntimeRefreshRemovesOverlayAndRetainsDerivedRules(t *testing.T) {
	p := &trSharedPersister{}
	seed := model.Policy{ID: "base", TenantID: "tenant", Name: "base", Conditions: map[string]any{"sni": "base.invalid"}, Status: "active", Action: model.PolicyAction{Decision: "allow"}}
	a, b := NewStore([]model.Policy{seed}), NewStore([]model.Policy{seed})
	for _, s := range []*Store{a, b} {
		if err := s.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
	}
	b.SetCompiledPolicies("tenant", []model.Policy{{ID: "derived", TenantID: "tenant", Status: "active"}})
	item := seed
	item.ID = "authored"
	if _, err := a.Upsert(context.Background(), item, "tenant", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !a.SetPolicyStatus("tenant", "base", "disabled") {
		t.Fatal("status")
	}
	if err := b.RefreshSharedRuntime(); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := b.Get(context.Background(), "tenant", "base"); got.Status != "disabled" {
		t.Fatal("override not refreshed")
	}
	if _, _, err := a.Delete(context.Background(), "tenant", "authored"); err != nil {
		t.Fatal(err)
	}
	// Simulate removal of an override by another authoritative writer.
	if err := p.Update(func(raw []byte) ([]byte, error) {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		delete(doc, "policy_status_override")
		doc["future_field"] = map[string]bool{"kept": true}
		return json.Marshal(doc)
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshSharedRuntime(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Get(context.Background(), "tenant", "authored"); ok {
		t.Fatal("deleted authored policy resurrected")
	}
	if got, _, _ := b.Get(context.Background(), "tenant", "base"); got.Status != "active" {
		t.Fatal("removed override did not restore bundle policy")
	}
	if len(b.compiledPolicies["tenant"]) != 1 {
		t.Fatal("refresh erased independently compiled policy")
	}
	if err := b.SetServerInitiatedEnabledConfirmed("other", true); err != nil {
		t.Fatal(err)
	}
	raw, _ := p.Load()
	if !bytes.Contains(raw, []byte(`"future_field"`)) {
		t.Fatal("unknown field lost")
	}
	generation := b.ConfigGeneration()
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(`{"east_west_enabled":null}`), []byte(`{"schema_version":"unsupported"}`)} {
		p.Save(bad)
		if err := b.RefreshSharedRuntime(); err == nil {
			t.Fatalf("bad authority read accepted: %s", bad)
		}
		if err := b.SetServerInitiatedEnabledConfirmed("other", false); !errors.Is(err, ErrPolicyPersistence) {
			t.Fatalf("bad authority write accepted: %v", err)
		}
		if !b.ServerInitiatedEnabledFor("other") || b.ConfigGeneration() != generation {
			t.Fatal("authority failure changed live/generation")
		}
	}
}
