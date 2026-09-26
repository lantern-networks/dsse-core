package enrolledinventory

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type erasureContextStore struct {
	data                []byte
	reject, unconfirmed bool
}

func (p *erasureContextStore) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *erasureContextStore) Save(b []byte) error   { p.data = bytes.Clone(b); return nil }
func (p *erasureContextStore) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.reject {
		return errors.New("not authorized")
	}
	raw, err := edit(bytes.Clone(p.data))
	if err != nil {
		return err
	}
	if p.unconfirmed {
		return errors.New("unconfirmed commit")
	}
	p.data = raw
	return nil
}
func TestSharedTenantRetirementAndClaimRelease(t *testing.T) {
	p := &erasureContextStore{}
	l := NewLedger()
	l.SetPersisterChecked(p)
	l.Enroll("owned", "tenant", "", "now")
	e := l.entries["owned"]
	e.ReenrolmentNonce = 7
	l.entries["owned"] = e
	l.persistCheckedLocked()
	claim := newStubClaimer()
	claim.ClaimIdentity(context.Background(), "tenant", "owned", 7)
	l.SetIdentityClaimer(claim)
	stamp := "2026-09-20T00:00:00Z"
	p.reject = true
	gen := l.ConfigGeneration()
	if _, err := l.RetireTenantContext(context.Background(), "tenant", stamp); !errors.Is(err, ErrInventorySave) {
		t.Fatal(err)
	}
	if e, _ := l.EntryFor("owned"); !e.Enabled || l.ConfigGeneration() != gen {
		t.Fatal("unauthorized retirement applied")
	}
	p.reject = false
	p.unconfirmed = true
	if _, err := l.RetireTenantContext(context.Background(), "tenant", stamp); !errors.Is(err, ErrInventorySave) {
		t.Fatal(err)
	}
	if e := l.Authoritative()[0]; e.Enabled || e.RemovedAt == "" {
		t.Fatal("unconfirmed retirement did not retain local denial")
	}
	if !claim.held["tenant\x00owned"] {
		t.Fatal("claim released before erasure")
	}
	p.unconfirmed = false
	if _, err := l.RetireTenantContext(context.Background(), "tenant", stamp); err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(p.data)
	gen = l.ConfigGeneration()
	p.unconfirmed = true
	if ids, err := l.RemoveTenantContext(context.Background(), "tenant"); !errors.Is(err, ErrInventorySave) || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	if !bytes.Equal(before, p.data) || l.ConfigGeneration() != gen || !claim.held["tenant\x00owned"] {
		t.Fatal("unconfirmed erasure changed state or released claim")
	}
	p.unconfirmed = false
	if ids, err := l.RemoveTenantContext(context.Background(), "tenant"); err != nil || len(ids) != 1 {
		t.Fatal(ids, err)
	}
	if claim.held["tenant\x00owned"] {
		t.Fatal("tombstone's actual grant was not released after commit")
	}
}
