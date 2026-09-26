package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestLegacyUnattributedSurvivesSharedRiskEdits(t *testing.T) {
	ctx := context.Background()
	raw, err := json.Marshal(highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: map[string]string{}, Users: map[string]UserRisk{}, LegacyUnattributed: map[string]string{"old-person": "high", "keep": "critical"}})
	if err != nil {
		t.Fatal(err)
	}
	p := &automaticSharedStore{raw: raw}
	first, second := NewHighRiskOverlay(), NewHighRiskOverlay()
	for _, o := range []*HighRiskOverlay{first, second} {
		if err := o.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := first.SetUserRiskContext(ctx, UserRisk{TenantID: "tenant", ID: "person", Severity: "medium"}); err != nil {
		t.Fatal(err)
	}
	if _, err := second.SetDeviceRiskContext(ctx, "device", "high"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.RaiseDeviceRisk("automatic", "critical"); err != nil {
		t.Fatal(err)
	}
	if _, err := second.DiscardLegacyUnattributedContext(ctx, "old-person", "medium"); !errors.Is(err, ErrLegacyRiskChanged) {
		t.Fatalf("stale resolution accepted: %v", err)
	}
	p.failAfter = true
	if _, err := second.DiscardLegacyUnattributedContext(ctx, "old-person", "high"); !errors.Is(err, ErrRiskSave) {
		t.Fatal(err)
	}
	if second.LegacySeverity("old-person") != "high" {
		t.Fatal("failed resolution removed live mark")
	}
	p.failAfter = false
	if _, err := second.DiscardLegacyUnattributedContext(ctx, "old-person", "high"); err != nil {
		t.Fatal(err)
	}
	reloaded := NewHighRiskOverlay()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if reloaded.LegacySeverity("old-person") != "" || reloaded.LegacySeverity("keep") != "critical" {
		t.Fatal("resolution changed unrelated legacy marks")
	}
	if sev, ok := reloaded.UserSeverity("tenant", "person"); !ok || sev != "medium" {
		t.Fatal("concurrent user edit lost")
	}
	if reloaded.Snapshot()["device"] != "high" || reloaded.Snapshot()["automatic"] != "critical" {
		t.Fatal("concurrent device edit lost")
	}
}

type legacyMarkSharedStore struct {
	automaticSharedStore
	failSave bool
}

func (p *legacyMarkSharedStore) Save(raw []byte) error {
	if p.failSave {
		return errors.New("save failed")
	}
	return p.automaticSharedStore.Save(raw)
}
func TestUnconfirmedLegacyMarkCannotBeClearedBySharedUserEdit(t *testing.T) {
	p := &legacyMarkSharedStore{}
	o := NewHighRiskOverlay()
	if err := o.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	o.Mark("existing", "medium")
	p.failSave = true
	o.Mark("device", "critical")
	p.failSave = false
	if _, err := o.SetUserRiskContext(context.Background(), UserRisk{TenantID: "tenant", ID: "person", Severity: "high"}); !errors.Is(err, ErrRiskUnavailable) {
		t.Fatalf("user edit must wait for explicit device retry: %v", err)
	}
	if o.Snapshot()["device"] != "critical" {
		t.Fatal("unconfirmed protective mark was cleared")
	}
	o.Mark("device", "critical")
	if _, err := o.SetUserRiskContext(context.Background(), UserRisk{TenantID: "tenant", ID: "person", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	reloaded := NewHighRiskOverlay()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if reloaded.Snapshot()["device"] != "critical" {
		t.Fatal("retried mark not preserved")
	}
}
