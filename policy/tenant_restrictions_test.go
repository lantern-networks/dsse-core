package policy

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func trptr[T any](v T) *T { return &v }

type trFailPersister struct{}

func (trFailPersister) Load() ([]byte, error) { return nil, nil }
func (trFailPersister) Save([]byte) error     { return errors.New("disk unavailable") }
func TestManagedTenantRestrictionPersistenceDistributionAndIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	cp := NewStore(nil)
	if err := cp.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"one", "two"} {
		if err := cp.SaveTenantRestriction(tenant, "google_workspace", TenantRestrictionPatch{AllowedValue: trptr(tenant + ".example"), Enabled: trptr(true)}); err != nil {
			t.Fatal(err)
		}
	}
	cp = NewStore(nil)
	if err := cp.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	edge := NewStore(nil)
	for _, tenant := range cp.Tenants() {
		cfg := cp.SnapshotTenantConfig(tenant)
		raw, _ := json.Marshal(cfg)
		var restored TenantConfigBundle
		if err := json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		edge.ApplyBundle(tenant, nil, restored, time.Now())
	}
	old := edge.RuntimeEvaluator(decision.Evaluator{})
	if old.TenantRestrictionHeaderValues[tenantrestriction.Ref("one", "google_workspace")] != "one.example" || old.TenantRestrictionHeaderValues[tenantrestriction.Ref("two", "google_workspace")] != "two.example" {
		t.Fatal("tenant values lost during restart/distribution")
	}
	if err := cp.SaveTenantRestriction("one", "google_workspace", TenantRestrictionPatch{Enabled: trptr(false), AllowedValue: trptr("")}); err != nil {
		t.Fatal(err)
	}
	edge.ApplyBundle("one", nil, cp.SnapshotTenantConfig("one"), time.Now())
	fresh := edge.RuntimeEvaluator(decision.Evaluator{})
	if len(fresh.TenantRestrictionHeaderValues) != 1 || len(old.TenantRestrictionHeaderValues) != 2 {
		t.Fatal("snapshot changed or clear failed")
	}
	if fresh.PolicyBundle.SWGTenantRestrictionRules[0].Status != "inactive" {
		t.Fatal("disable not distributed")
	}
}
func TestManagedTenantRestrictionFailureIsAtomic(t *testing.T) {
	s := NewStore(nil)
	_ = s.SetRuntimeStatePersister(trFailPersister{})
	before := s.ConfigGeneration()
	if err := s.SaveTenantRestriction("one", "google_workspace", TenantRestrictionPatch{AllowedValue: trptr("example.com"), Enabled: trptr(true)}); err == nil {
		t.Fatal("reported save success")
	}
	if len(s.SnapshotTenantConfig("one").SaaSTenantRestrictions) != 0 || s.ConfigGeneration() != before {
		t.Fatal("failed save published")
	}
	s = NewStore(nil)
	_ = s.SetRuntimeStatePath(filepath.Join(t.TempDir(), "admin.json"))
	for _, patch := range []TenantRestrictionPatch{{Enabled: trptr(true)}, {AllowedValue: trptr("a.example\r\nInjected: bad")}, {AllowedValue: trptr("example.com"), Enabled: trptr(true)}} {
		if err := s.SaveTenantRestriction("one", "microsoft_365", patch); err == nil {
			t.Fatal("invalid M365 accepted")
		}
	}
	if len(s.Tenants()) != 0 {
		t.Fatal("invalid input created configuration")
	}
}

func TestManagedTenantRestrictionErasureSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	s := NewStore(nil)
	_ = s.SetRuntimeStatePath(path)
	for _, tenant := range []string{"one", "two"} {
		if err := s.SaveTenantRestriction(tenant, "google_workspace", TenantRestrictionPatch{AllowedValue: trptr(tenant + ".example"), Enabled: trptr(true)}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.RemoveTenantRestrictions("one"); err != nil || n != 1 {
		t.Fatalf("erase: %d %v", n, err)
	}
	restored := NewStore(nil)
	if err := restored.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	if restored.CountTenantRestrictions("one") != 0 || restored.CountTenantRestrictions("two") != 1 {
		t.Fatal("erasure lost or crossed tenant boundary")
	}
	if cfg := restored.SnapshotTenantConfig("one").SaaSTenantRestrictions; cfg == nil || len(cfg) != 0 {
		t.Fatal("clear instruction not distributed")
	}
}

// Two independently started control planes sharing a transactional blob.
type trSharedPersister struct {
	mu   sync.Mutex
	raw  []byte
	fail bool
}

func (p *trSharedPersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return nil, errors.New("database unavailable")
	}
	return append([]byte(nil), p.raw...), nil
}
func (p *trSharedPersister) Save(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = append([]byte(nil), raw...)
	return nil
}
func (p *trSharedPersister) Update(edit func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("database unavailable")
	}
	next, err := edit(p.raw)
	if err == nil {
		p.raw = append([]byte(nil), next...)
	}
	return err
}
func TestManagedTenantRestrictionSharedAuthorityRefreshAndMerge(t *testing.T) {
	shared := &trSharedPersister{}
	one, two := NewStore(nil), NewStore(nil)
	_ = one.SetRuntimeStatePersister(shared)
	_ = two.SetRuntimeStatePersister(shared)
	if err := one.SaveTenantRestriction("one", "google_workspace", TenantRestrictionPatch{AllowedValue: trptr("one.example"), Enabled: trptr(true)}); err != nil {
		t.Fatal(err)
	}
	before := two.ConfigGeneration()
	if err := two.RefreshTenantRestrictions(); err != nil {
		t.Fatal(err)
	}
	if !two.SnapshotTenantConfig("one").SaaSTenantRestrictions["google_workspace"].Enabled || two.ConfigGeneration() <= before {
		t.Fatal("standby didn't refresh before publishing")
	}
	// A process that never refreshed must still merge against committed state.
	three := NewStore(nil)
	_ = three.SetRuntimeStatePersister(shared)
	if err := one.SaveTenantRestriction("two", "openai_chatgpt", TenantRestrictionPatch{AllowedValue: trptr("wsp_123"), Enabled: trptr(true)}); err != nil {
		t.Fatal(err)
	}
	if err := three.SaveTenantRestriction("one", "google_workspace", TenantRestrictionPatch{Enabled: trptr(false)}); err != nil {
		t.Fatal(err)
	}
	_ = two.RefreshTenantRestrictions()
	if two.SnapshotTenantConfig("one").SaaSTenantRestrictions["google_workspace"].Enabled || !two.SnapshotTenantConfig("two").SaaSTenantRestrictions["openai_chatgpt"].Enabled {
		t.Fatal("stale writer lost another tenant's setting")
	}
	shared.fail = true
	if err := two.RefreshTenantRestrictions(); err == nil {
		t.Fatal("unavailable DB accepted as fresh")
	}
	if err := two.SaveTenantRestriction("two", "openai_chatgpt", TenantRestrictionPatch{Enabled: trptr(false)}); !errors.Is(err, ErrPolicyPersistence) {
		t.Fatal("failed commit reported success")
	}
	if !two.SnapshotTenantConfig("two").SaaSTenantRestrictions["openai_chatgpt"].Enabled {
		t.Fatal("failed commit changed local settings")
	}
}

func TestManagedTenantRestrictionSharedValidationIsNotPersistenceFailure(t *testing.T) {
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(&trSharedPersister{}); err != nil {
		t.Fatal(err)
	}
	err := s.SaveTenantRestriction("one", "google_workspace", TenantRestrictionPatch{AllowedValue: trptr("bad domain"), Enabled: trptr(true)})
	if err == nil || errors.Is(err, ErrPolicyPersistence) {
		t.Fatalf("validation classification: %v", err)
	}
}
