package steerexclusion

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func restorePolicy(id, tenant string) Policy {
	return Policy{ID: id, TenantID: tenant, ScopeType: "tenant", Status: "active", ExcludedAppSigningIDs: []string{"com.example.tool"}}
}
func restoreBytes(policies ...Policy) []byte {
	b, err := json.Marshal(struct {
		Policies []Policy `json:"policies"`
	}{policies})
	if err != nil {
		panic(err)
	}
	return b
}
func invalidRestoreSnapshots() map[string][]byte {
	good := string(restoreBytes(restorePolicy("owned", "tenant_a")))
	row := strings.TrimSuffix(strings.TrimPrefix(good, `{"policies":[`), `]}`)
	return map[string][]byte{
		"empty": {}, "null": []byte(`null`), "empty-object": []byte(`{}`), "null-array": []byte(`{"policies":null}`), "object-array": []byte(`{"policies":{}}`),
		"nil-row": []byte(`{"policies":[null]}`), "empty-row": []byte(`{"policies":[{}]}`), "duplicate-id": []byte(`{"policies":[` + row + `,` + row + `]}`),
		"duplicate-field": []byte(`{"policies":[` + row + `],"policies":[]}`), "alias-field": []byte(strings.Replace(good, `"policies"`, `"Policies"`, 1)),
		"duplicate-row-field": []byte(strings.Replace(good, `"tenant_id":"tenant_a"`, `"tenant_id":"tenant_bad","tenant_id":"tenant_a"`, 1)),
		"alias-row-field":     []byte(strings.Replace(good, `"tenant_id"`, `"Tenant_ID"`, 1)), "missing-status": []byte(strings.Replace(good, `,"status":"active"`, "", 1)),
		"unknown-status": []byte(strings.Replace(good, `"status":"active"`, `"status":"disabled"`, 1)), "blank-tenant": []byte(strings.Replace(good, `"tenant_a"`, `" "`, 1)),
		"empty-apps": []byte(strings.Replace(good, `["com.example.tool"]`, `[]`, 1)), "null-note": []byte(strings.Replace(good, `"note":""`, `"note":null`, 1)),
		"mixed": []byte(`{"policies":[` + row + `,null]}`), "invalid-json": []byte(`{`), "invalid-utf8": append([]byte(`{"policies":[],"`), 0xff),
	}
}
func TestSteerExclusionRestoreRejectsCompleteInvalidSnapshot(t *testing.T) {
	for name, data := range invalidRestoreSnapshots() {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policies.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewStoreWithPersistence(NewFilePersistence(path)); err == nil {
				t.Fatal("invalid snapshot accepted at startup")
			}
		})
	}
}
func TestSteerExclusionRestoreKeepsHeldAndBackendOnFailure(t *testing.T) {
	for name, data := range invalidRestoreSnapshots() {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policies.json")
			good := restoreBytes(restorePolicy("owned", "tenant_a"), restorePolicy("foreign", "tenant_b"))
			if err := os.WriteFile(path, good, 0600); err != nil {
				t.Fatal(err)
			}
			f := NewFilePersistence(path)
			s, err := NewStoreWithPersistence(f)
			if err != nil {
				t.Fatal(err)
			}
			before := s.List("tenant_a")
			backend := f.candidateLocked()
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			s.refreshedAt = time.Time{}
			if got := s.List("tenant_a"); !reflect.DeepEqual(got, before) {
				t.Fatal("failed refresh replaced held policies", got)
			}
			if !reflect.DeepEqual(f.byID, backend) {
				t.Fatal("failed load replaced backend cache")
			}
			if got := s.ResolveForDevice("tenant_a", "device", ""); len(got) != 1 || got[0] != "com.example.tool" {
				t.Fatal("failed load changed resolution", got)
			}
			if err = os.WriteFile(path, good, 0600); err != nil {
				t.Fatal(err)
			}
			s.refreshedAt = time.Time{}
			if _, err = f.LoadAll(context.Background()); err != nil {
				t.Fatal("valid recovery", err)
			}
			if !reflect.DeepEqual(s.List("tenant_a"), before) {
				t.Fatal("recovery changed policy")
			}
		})
	}
}
func TestSteerExclusionKnownSnapshotCannotDisappear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.json")
	f := NewFilePersistence(path)
	s, err := NewStoreWithPersistence(f)
	if err != nil {
		t.Fatal("first boot", err)
	}
	if _, err = s.Upsert(restorePolicy("owned", "tenant_a"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s.refreshedAt = time.Time{}
	if len(s.List("tenant_a")) != 1 {
		t.Fatal("missing known file erased the held set")
	}
	if _, err = f.LoadAll(context.Background()); err == nil {
		t.Fatal("missing known file accepted as first boot")
	}
}

func TestSteerExclusionTypedRestoreCopiesAndRejectsInvalidRows(t *testing.T) {
	good := restorePolicy("owned", "tenant_a")
	for name, rows := range map[string][]*Policy{
		"null-row": {nil}, "duplicate": {&good, &good}, "bad-status": {{ID: "bad", TenantID: "tenant_a", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"app"}}},
	} {
		t.Run(name, func(t *testing.T) {
			backend := &countingPersistence{policies: rows}
			if _, err := NewStoreWithPersistence(backend); err == nil {
				t.Fatal("invalid typed startup accepted")
			}
			backend.policies = []*Policy{&good}
			s, err := NewStoreWithPersistence(backend)
			if err != nil {
				t.Fatal(err)
			}
			backend.policies = rows
			s.refreshedAt = time.Time{}
			if len(s.List("tenant_a")) != 1 {
				t.Fatal("bad typed refresh changed held set")
			}
			if _, err = s.ListChecked("tenant_a"); err == nil {
				t.Fatal("bad refresh advertised as healthy")
			}
		})
	}
	backend := &countingPersistence{policies: []*Policy{&good}}
	s, err := NewStoreWithPersistence(backend)
	if err != nil {
		t.Fatal(err)
	}
	good.ExcludedAppSigningIDs[0] = "changed-backend"
	good.Note = "changed-backend"
	if got := s.List("tenant_a")[0]; got.ExcludedAppSigningIDs[0] != "com.example.tool" || got.Note != "" {
		t.Fatal("startup aliases backend pointer")
	}
	s.refreshedAt = time.Time{}
	s.List("tenant_a")
	good.ExcludedAppSigningIDs[0] = "changed-again"
	if got := s.List("tenant_a")[0]; got.ExcludedAppSigningIDs[0] != "changed-backend" {
		t.Fatal("refresh aliases backend pointer")
	}
	backend.policies = nil
	s.refreshedAt = time.Time{}
	if rows, err := s.ListChecked("tenant_a"); err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("valid typed empty result", rows, err)
	}
}

func TestSteerExclusionReadHealthBlocksWritesUntilRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.json")
	good := restoreBytes(restorePolicy("owned", "tenant_a"), restorePolicy("foreign", "tenant_b"))
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStoreWithPersistence(NewFilePersistence(path))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.refreshedAt = time.Time{}
	for i := 0; i < 2; i++ {
		if rows, err := s.ListChecked("tenant_a"); err == nil || rows != nil {
			t.Fatal("unhealthy authority read", rows, err)
		}
	}
	if _, err = s.Upsert(restorePolicy("new", "tenant_a"), time.Now()); !errors.Is(err, ErrPersistence) {
		t.Fatal("write accepted while load unverified", err)
	}
	if deleted, err := s.DeleteChecked("owned", "tenant_a", time.Now()); deleted || !errors.Is(err, ErrPersistence) {
		t.Fatal("delete accepted while load unverified", err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != `{}` {
		t.Fatal("refused mutations rewrote the damaged source")
	}
	if err = os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	s.refreshedAt = time.Time{}
	if rows, err := s.ListChecked("tenant_a"); err != nil || len(rows) != 1 {
		t.Fatal("health did not recover", rows, err)
	}
	if _, err = s.Upsert(restorePolicy("new", "tenant_a"), time.Now()); err != nil {
		t.Fatal("recovered mutation refused", err)
	}
	if err = os.WriteFile(path, []byte(`{"policies":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.refreshedAt = time.Time{}
	if rows, err := s.ListChecked("tenant_a"); err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("explicit stored empty refused", rows, err)
	}
	restarted, err := NewStoreWithPersistence(NewFilePersistence(path))
	if err != nil || len(restarted.List("tenant_b")) != 0 {
		t.Fatal("empty restart failed", err)
	}
}
