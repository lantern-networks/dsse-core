package nhi

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type snapshotStore struct{ raw []byte }

func (p *snapshotStore) Load() ([]byte, error) { return bytes.Clone(p.raw), nil }
func (p *snapshotStore) Save(b []byte) error   { p.raw = bytes.Clone(b); return nil }

func TestInvalidNHISnapshotCannotEmptyRegistryOrReplaceWriter(t *testing.T) {
	entry, _ := json.Marshal(testIdentity("registered"))
	for name, raw := range map[string][]byte{
		"zero-byte": {}, "null": []byte(`null`), "missing": []byte(`{}`),
		"null-identities":  []byte(`{"identities":null}`),
		"case-field":       []byte(`{"Identities":{}}`),
		"duplicate-field":  []byte(`{"identities":{"one":` + string(entry) + `},"identities":{}}`),
		"duplicate-record": []byte(`{"identities":{"one":` + string(entry) + `,"one":` + string(entry) + `}}`),
	} {
		t.Run(name, func(t *testing.T) {
			original := &snapshotStore{}
			s := NewStore()
			if err := s.SetPersister(original); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Upsert(context.Background(), testIdentity("registered"), "tenant_a", time.Now()); err != nil {
				t.Fatal(err)
			}
			bad := &snapshotStore{raw: raw}
			if err := s.SetPersister(bad); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			if _, _, ok := ValidateRuntimeEvidence(context.Background(), s, model.DecisionRequest{}, "tenant_a", "unknown", time.Now()); ok {
				t.Fatal("failed reload bypassed registry validation")
			}
			if _, err := s.Upsert(context.Background(), testIdentity("second"), "tenant_a", time.Now()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bad.raw, raw) {
				t.Fatal("failed replacement became the active writer")
			}
			loaded := NewStore()
			if err := loaded.SetPersister(original); err != nil {
				t.Fatal(err)
			}
			rows, _ := loaded.List(context.Background(), "tenant_a")
			if len(rows) != 2 {
				t.Fatal("original registry writer was lost")
			}
		})
	}
}

func TestExplicitEmptyNHISnapshotRemainsSupported(t *testing.T) {
	if err := NewStore().SetPersister(&snapshotStore{raw: []byte(`{"identities":{}}`)}); err != nil {
		t.Fatal(err)
	}
	if err := NewStore().SetPersister(&snapshotStore{}); err != nil {
		t.Fatal(err)
	}
}
