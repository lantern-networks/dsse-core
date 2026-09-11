package enrolledinventory

import (
	"encoding/json"
	"errors"
	"testing"
)

type pkiSharedTestStore struct {
	raw []byte
	err error
}

func (p *pkiSharedTestStore) Shared() bool          { return true }
func (p *pkiSharedTestStore) Load() ([]byte, error) { return p.raw, p.err }
func (p *pkiSharedTestStore) Save(b []byte) error   { p.raw = b; return nil }
func TestPKIPopulationReadsDurableStateAndReturnsFailures(t *testing.T) {
	ledger := NewLedger()
	store := &pkiSharedTestStore{}
	ledger.persister = store
	if _, err := ledger.ListForPKI(); err == nil {
		t.Fatal("absent store passed")
	}
	store.raw = []byte(`{"entries":{"mac":{"identity":"mac","tenant_id":"tenant_a","enabled":true}}}`)
	entries, err := ledger.ListForPKI()
	if err != nil || len(entries) != 1 || entries[0].Identity != "mac" {
		t.Fatalf("%v %v", entries, err)
	}
	// A later shared enrolment must be seen even when it was never loaded into this process.
	state := stateFile{Entries: map[string]Entry{"windows": {Identity: "windows", TenantID: "tenant_a", Enabled: true}}}
	store.raw, _ = json.Marshal(state)
	entries, err = ledger.ListForPKI()
	if err != nil || len(entries) != 1 || entries[0].Identity != "windows" {
		t.Fatalf("stale population: %v %v", entries, err)
	}
	store.err = errors.New("database unavailable")
	if _, err := ledger.ListForPKI(); err == nil {
		t.Fatal("read failure became a population")
	}
	store.err = nil
	for _, raw := range []string{`null`, `{}`, `{"entries":null}`, `broken`} {
		store.raw = []byte(raw)
		if _, err := ledger.ListForPKI(); err == nil {
			t.Fatalf("corrupt snapshot %s passed", raw)
		}
	}
	if _, err := NewLedger().ListForPKI(); err == nil {
		t.Fatal("node-local population passed")
	}
}
