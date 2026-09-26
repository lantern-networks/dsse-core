package revocation

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type automaticSharedStore struct {
	raw                   []byte
	failBefore, failAfter bool
}

func (p *automaticSharedStore) Load() ([]byte, error) { return bytes.Clone(p.raw), nil }
func (p *automaticSharedStore) Save(b []byte) error   { p.raw = bytes.Clone(b); return nil }
func (p *automaticSharedStore) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.failBefore {
		return errors.New("before callback")
	}
	next, err := edit(bytes.Clone(p.raw))
	if err != nil {
		return err
	}
	if p.failAfter {
		return errors.New("unconfirmed commit")
	}
	p.raw = next
	return nil
}
func TestAutomaticSharedFailureRetry(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconfirmed", true: "refused"}[before], func(t *testing.T) {
			p := &automaticSharedStore{}
			o := NewHighRiskOverlay()
			if err := o.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			peer := NewHighRiskOverlay()
			peer.SetPersister(p)
			peer.SetDeviceRiskContext(context.Background(), "foreign", "critical")
			peer.SetUserRiskContext(context.Background(), UserRisk{TenantID: "other", ID: "person", Severity: "high"})
			raw := bytes.Clone(p.raw)
			p.failBefore, p.failAfter = before, !before
			result, err := o.RaiseDeviceRisk("target", "critical")
			if err != ErrRiskSave || !result.Applied || result.Persistence != "unconfirmed" || o.Snapshot()["target"] != "critical" || !bytes.Equal(raw, p.raw) {
				t.Fatal(result, err)
			}
			p.failBefore, p.failAfter = false, false
			result, err = o.RaiseDeviceRisk("target", "medium")
			if err != nil || result.Severity != "critical" || result.Changed || result.Persistence != "saved" || o.Snapshot()["foreign"] != "critical" || len(o.UserSnapshot()) != 1 {
				t.Fatal(result, err)
			}
			reload := NewHighRiskOverlay()
			if err := reload.SetPersister(p); err != nil || reload.Snapshot()["target"] != "critical" {
				t.Fatal(err)
			}
		})
	}
}
func TestSharedMeshFailureRetryAndCallback(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconfirmed", true: "authority-refused"}[before], func(t *testing.T) {
			p := &automaticSharedStore{}
			a := NewAdmissionRevocations()
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			peer := NewAdmissionRevocations()
			peer.SetPersister(p)
			peer.RevokeCheckedContext(context.Background(), "foreign", "origin")
			raw := bytes.Clone(p.raw)
			p.failBefore, p.failAfter = before, !before
			calls := 0
			a.SetOnRevoked(func(string, string) { calls++; a.FeedSnapshot() })
			a.SetMeshReporter(func(string, string) { t.Error("mesh loop") })
			changed, err := a.RevokeFromMeshCheckedContext(context.Background(), "target", "received")
			_, applied := a.IsRevoked("target")
			if err != ErrAdmissionSave || changed == before || applied == before || !bytes.Equal(raw, p.raw) {
				t.Fatal(changed, applied, err)
			}
			p.failBefore, p.failAfter = false, false
			changed, err = a.RevokeFromMeshChecked("target", "received")
			if err != nil || changed != before || calls != 1 || a.Snapshot()["foreign"] != "origin" {
				t.Fatal(changed, calls, err)
			}
			gen := a.ConfigGeneration()
			changed, err = a.RevokeFromMeshChecked("target", "received")
			if err != nil || changed || calls != 1 || a.ConfigGeneration() != gen {
				t.Fatal("duplicate callback/generation", err)
			}
			reload := NewAdmissionRevocations()
			if err := reload.SetPersister(p); err != nil || reload.FeedSnapshot()["target"] != "received" {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedMeshFirstSaveCanRetry(t *testing.T) {
	p := &automaticSharedStore{failAfter: true}
	a := NewAdmissionRevocations()
	a.SetPersister(p)
	if _, err := a.RevokeFromMeshChecked("first", "block"); err != ErrAdmissionSave {
		t.Fatal(err)
	}
	p.failAfter = false
	if changed, err := a.RevokeFromMeshChecked("first", "block"); err != nil || changed {
		t.Fatal(changed, err)
	}
	restored := NewAdmissionRevocations()
	if err := restored.SetPersister(p); err != nil || restored.FeedSnapshot()["first"] != "block" {
		t.Fatal(err)
	}
}

func TestSharedAutomaticPendingSurvivesOtherTargetAndAdminOverride(t *testing.T) {
	p := &automaticSharedStore{failAfter: true}
	o := NewHighRiskOverlay()
	o.SetPersister(p)
	if _, err := o.RaiseDeviceRisk("first", "critical"); err != ErrRiskSave {
		t.Fatal(err)
	}
	p.failAfter = false
	if _, err := o.RaiseDeviceRisk("second", "high"); err != nil {
		t.Fatal(err)
	}
	restored := NewHighRiskOverlay()
	restored.SetPersister(p)
	if restored.Snapshot()["first"] != "critical" || restored.Snapshot()["second"] != "high" {
		t.Fatal("pending mark lost")
	}
	p.failAfter = true
	o.RaiseDeviceRisk("third", "critical")
	p.failAfter = false
	if _, err := o.SetDeviceRiskContext(context.Background(), "third", "none"); err != nil {
		t.Fatal(err)
	}
	o.RaiseDeviceRisk("second", "high")
	restored.SetPersister(p)
	if _, ok := restored.Snapshot()["third"]; ok {
		t.Fatal("explicit admin clear resurrected")
	}
}
func TestSharedMeshPendingSurvivesAnotherDelivery(t *testing.T) {
	p := &automaticSharedStore{failAfter: true}
	a := NewAdmissionRevocations()
	a.SetPersister(p)
	a.RevokeFromMeshChecked("first", "one")
	p.failAfter = false
	if _, err := a.RevokeFromMeshChecked("second", "two"); err != nil {
		t.Fatal(err)
	}
	restored := NewAdmissionRevocations()
	restored.SetPersister(p)
	if restored.FeedSnapshot()["first"] != "one" || restored.FeedSnapshot()["second"] != "two" {
		t.Fatal("pending mesh block lost")
	}
}
