package humanapproval

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type toggledApprovalPersister struct {
	base  blobstore.FilePersister
	fail  bool
	saves int
}

func (p *toggledApprovalPersister) Load() ([]byte, error) { return p.base.Load() }
func (p *toggledApprovalPersister) Save(b []byte) error {
	p.saves++
	if p.fail {
		return fmt.Errorf("private-approval-store-path")
	}
	return p.base.Save(b)
}
func approvalFixture(t *testing.T, capacity int) (*Store, *toggledApprovalPersister) {
	t.Helper()
	s := NewStore(capacity)
	p := &toggledApprovalPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "approvals.json")}}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	return s, p
}
func putApproval(t *testing.T, s *Store, tenant, id string) {
	t.Helper()
	if _, e := s.Upsert(model.HumanApprovalEvent{ID: id, TenantID: tenant, ApprovalResult: "approved"}); e != nil {
		t.Fatal(e)
	}
}

func TestApprovalSameIDTenantsAndAmbiguousCompatibility(t *testing.T) {
	s, p := approvalFixture(t, 0)
	putApproval(t, s, "a", "same")
	putApproval(t, s, "b", "same")
	for _, store := range []*Store{s, NewStore(0)} {
		if store != s {
			if e := store.SetPersister(p); e != nil {
				t.Fatal(e)
			}
		}
		for _, tenant := range []string{"a", "b"} {
			if e, ok := store.GetForTenant(tenant, "same"); !ok || e.TenantID != tenant {
				t.Fatalf("tenant lost: %s %+v %v", tenant, e, ok)
			}
		}
		if _, ok := store.Get("same"); ok {
			t.Fatal("ambiguous lookup must refuse")
		}
		if _, _, err := store.Revoke("same", "test"); err == nil {
			t.Fatal("ambiguous revoke must refuse")
		}
	}
}
func TestApprovalRejectedUpsertDoesNotPublishOrEvict(t *testing.T) {
	for _, capacity := range []int{0, 1} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			s, p := approvalFixture(t, capacity)
			putApproval(t, s, "a", "existing")
			before, _ := p.Load()
			p.fail = true
			for _, id := range []string{"new", "existing"} {
				_, err := s.Upsert(model.HumanApprovalEvent{ID: id, TenantID: "a", ApprovalResult: "approved", ExpiresAt: stringPtr(time.Now().Add(time.Hour).Format(time.RFC3339))})
				if err == nil {
					t.Fatal("missing failure")
				}
				if _, ok := s.GetForTenant("a", "new"); ok {
					t.Fatal("rejected approval became active")
				}
				existing, ok := s.GetForTenant("a", "existing")
				if !ok || existing.ExpiresAt != nil {
					t.Fatal("existing approval changed or evicted")
				}
				after, _ := p.Load()
				if string(after) != string(before) {
					t.Fatal("rejected save changed disk")
				}
			}
			p.fail = false
			putApproval(t, s, "a", "other")
			reloaded := NewStore(0)
			if e := reloaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if _, ok := reloaded.GetForTenant("a", "new"); ok {
				t.Fatal("rejected approval leaked through later save")
			}
		})
	}
}
func TestApprovalRevokeRetriesPersistenceWithoutRestoringAccess(t *testing.T) {
	s, p := approvalFixture(t, 0)
	putApproval(t, s, "a", "retry")
	p.fail = true
	for attempt := 0; attempt < 2; attempt++ {
		prev := p.saves
		event, found, err := s.Revoke("retry", "private-reason")
		if !found || err == nil || event.ApprovalResult != "revoked" {
			t.Fatalf("attempt %d: %+v %v %v", attempt, event, found, err)
		}
		if p.saves != prev+1 {
			t.Fatal("retry did not save")
		}
		if _, ok := s.GetActive("retry", time.Now()); ok {
			t.Fatal("failed save restored access")
		}
	}
	if _, err := s.Upsert(model.HumanApprovalEvent{ID: "retry", TenantID: "a", ApprovalResult: "approved"}); err == nil {
		t.Fatal("pending revocation reactivated")
	}
	p.fail = false
	if _, ok, e := s.Revoke("retry", "again"); !ok || e != nil {
		t.Fatal(e)
	}
	reloaded := NewStore(0)
	if e := reloaded.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	e, ok := reloaded.GetForTenant("a", "retry")
	if !ok || e.ApprovalResult != "revoked" || *e.Reason != "private-reason" {
		t.Fatalf("revocation did not survive retry/restart: %+v", e)
	}
}

type loadedApprovalPersister struct {
	data      []byte
	loadError error
}

func (p loadedApprovalPersister) Load() ([]byte, error) { return p.data, p.loadError }
func (p loadedApprovalPersister) Save([]byte) error     { return fmt.Errorf("wrong persister") }
func TestApprovalLoadValidationDoesNotReplaceLiveStateOrWriter(t *testing.T) {
	for _, fixture := range []loadedApprovalPersister{
		{loadError: fmt.Errorf("load failed")}, {data: []byte(`{bad`)},
		{data: []byte(`{"same":{"id":"same","tenant_id":"a"},"a\u0000same":{"id":"same","tenant_id":"a"}}`)},
		{data: []byte(`{"x":{"id":"same","tenant_id":" a "}}`)},
	} {
		s, p := approvalFixture(t, 0)
		putApproval(t, s, "a", "kept")
		if e := s.SetPersister(fixture); e == nil {
			t.Fatal("invalid load accepted")
		}
		putApproval(t, s, "a", "later")
		raw, _ := p.Load()
		var snap map[string]model.HumanApprovalEvent
		if e := json.Unmarshal(raw, &snap); e != nil || len(snap) != 2 {
			t.Fatalf("original writer/state lost: %s", raw)
		}
	}
}
func TestApprovalRejectsInvalidCompositeKeyParts(t *testing.T) {
	for _, event := range []model.HumanApprovalEvent{{ID: "x"}, {TenantID: "a"}, {TenantID: "a\x00b", ID: "x"}, {TenantID: "a", ID: "b\x00x"}, {TenantID: " a", ID: "x"}, {TenantID: "a", ID: "x "}} {
		s := NewStore(0)
		if _, e := s.Upsert(event); e == nil || s.Count() != 0 {
			t.Fatal("invalid key accepted")
		}
	}
}

func TestApprovalLegacySnapshotReindexAndScopedRevocation(t *testing.T) {
	s, p := approvalFixture(t, 0)
	if err := p.base.Save([]byte(`{"same":{"id":"same","tenant_id":"a","approval_result":"approved"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	putApproval(t, s, "b", "same")
	if _, ok, err := s.RevokeForTenant("a", "same", "test"); !ok || err != nil {
		t.Fatal(err)
	}
	own, _ := s.GetForTenant("a", "same")
	foreign, _ := s.GetForTenant("b", "same")
	if own.ApprovalResult != "revoked" || foreign.ApprovalResult != "approved" {
		t.Fatal("scoped revoke crossed tenant")
	}
	if _, ok, err := s.RevokeForTenant("missing", "same", "test"); ok || err != nil {
		t.Fatal("foreign-only revoke was not absent")
	}
	reloaded := NewStore(0)
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if reloaded.CountForTenant("a") != 1 || reloaded.CountForTenant("b") != 1 {
		t.Fatal("legacy upgrade lost tenant")
	}
	raw, _ := p.Load()
	var snap map[string]model.HumanApprovalEvent
	json.Unmarshal(raw, &snap)
	if len(snap) != 2 || snap["a\x00same"].TenantID != "a" || snap["b\x00same"].TenantID != "b" {
		t.Fatal("snapshot not scoped")
	}
}
func TestApprovalTenantErasureUsesExactAttribution(t *testing.T) {
	s, _ := approvalFixture(t, 0)
	putApproval(t, s, "a", "same")
	putApproval(t, s, "A", "same")
	if s.CountForTenant("a") != 1 || s.RemoveTenant("a") != 1 {
		t.Fatal("tenant attribution was case-folded")
	}
	if _, ok := s.GetForTenant("A", "same"); !ok {
		t.Fatal("another tenant was erased")
	}
}
