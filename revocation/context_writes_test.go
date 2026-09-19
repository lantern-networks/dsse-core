package revocation

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type failingContextPersister struct {
	raw           []byte
	afterCallback bool
}

func (p *failingContextPersister) Load() ([]byte, error) { return bytes.Clone(p.raw), nil }
func (p *failingContextPersister) Save(raw []byte) error { p.raw = bytes.Clone(raw); return nil }
func (p *failingContextPersister) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.afterCallback {
		if _, err := edit(bytes.Clone(p.raw)); err != nil {
			return err
		}
	}
	return errors.New("shared transaction refused")
}
func TestContextAdmissionRefusalAndUnconfirmedSaveDiffer(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-authorized-edit", true: "after-authorized-edit"}[after], func(t *testing.T) {
			p := &failingContextPersister{afterCallback: after}
			a := NewAdmissionRevocations()
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if err := a.RevokeChecked("foreign", "keep"); err != nil {
				t.Fatal(err)
			}
			before, _ := p.Load()
			gen := a.ConfigGeneration()
			calls := 0
			a.SetOnRevoked(func(string, string) { calls++ })
			applied, err := a.RevokeCheckedContext(context.Background(), "target", "block")
			if !errors.Is(err, ErrAdmissionSave) || applied != after {
				t.Fatal("wrong outcome", applied, err)
			}
			_, blocked := a.IsRevoked("target")
			if blocked != after || calls != map[bool]int{false: 0, true: 1}[after] {
				t.Fatal("incorrect local effect", blocked, calls)
			}
			if !after && a.ConfigGeneration() != gen {
				t.Fatal("refused request advanced generation")
			}
			if raw, _ := p.Load(); !bytes.Equal(before, raw) {
				t.Fatal("failed transaction stored bytes")
			}
			if err := a.RestoreCheckedContext(context.Background(), "foreign"); !errors.Is(err, ErrAdmissionSave) {
				t.Fatal(err)
			}
			if _, ok := a.IsRevoked("foreign"); !ok {
				t.Fatal("failed restore lifted block")
			}
		})
	}
}
func TestContextRiskFailureDoesNotPublishEitherNamespace(t *testing.T) {
	p := &failingContextPersister{afterCallback: true}
	o := NewHighRiskOverlay()
	if err := o.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SetDeviceRisk("target", "critical"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SetUserRisk(UserRisk{TenantID: "tenant", ID: "person", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	gen := o.ConfigGeneration()
	before, _ := p.Load()
	if _, err := o.SetDeviceRiskContext(context.Background(), "target", "none"); !errors.Is(err, ErrRiskSave) {
		t.Fatal(err)
	}
	if _, err := o.SetUserRiskContext(context.Background(), UserRisk{TenantID: "tenant", ID: "person", Severity: "none"}); !errors.Is(err, ErrRiskSave) {
		t.Fatal(err)
	}
	if o.ConfigGeneration() != gen || o.Snapshot()["target"] != "critical" {
		t.Fatal("failed save published device state")
	}
	if sev, _ := o.UserSeverity("tenant", "person"); sev != "high" {
		t.Fatal("failed save published user state")
	}
	if raw, _ := p.Load(); !bytes.Equal(before, raw) {
		t.Fatal("failed transaction stored bytes")
	}
}
