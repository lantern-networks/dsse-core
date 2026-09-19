package revocation

import (
	"bytes"
	"context"
	"testing"
)

func TestSharedErasureUnconfirmedDoesNotPublish(t *testing.T) {
	for _, after := range []bool{false, true} {
		p := &failingContextPersister{afterCallback: after}
		a := NewAdmissionRevocations()
		a.SetPersister(p)
		a.RevokeChecked("owned", "blocked")
		a.RevokeFromMeshChecked("received", "mesh")
		before := bytes.Clone(p.raw)
		gen := a.ConfigGeneration()
		n, err := a.RemoveDevicesContext(context.Background(), []string{"owned"})
		if n != 0 || err == nil || !bytes.Equal(before, p.raw) || gen != a.ConfigGeneration() {
			t.Fatal("unconfirmed admission erasure published")
		}
		if _, ok := a.IsRevoked("owned"); !ok {
			t.Fatal("block lifted")
		}
		p = &failingContextPersister{afterCallback: after}
		o := NewHighRiskOverlay()
		o.SetPersister(p)
		o.SetDeviceRisk("owned", "high")
		o.SetUserRisk(UserRisk{TenantID: "tenant", ID: "user", Severity: "critical"})
		before = bytes.Clone(p.raw)
		gen = o.ConfigGeneration()
		n, err = o.RemoveTenantRisksContext(context.Background(), "tenant", []string{"owned"})
		if n != 0 || err == nil || !bytes.Equal(before, p.raw) || gen != o.ConfigGeneration() || o.Snapshot()["owned"] != "high" || len(o.UserSnapshot()) != 1 {
			t.Fatal("unconfirmed risk erasure published")
		}
	}
}
