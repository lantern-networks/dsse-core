package revocation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestRiskReloadReplacesBothNamespacesAndIndexes(t *testing.T) {
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}
	a, b := NewHighRiskOverlay(), NewHighRiskOverlay()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	a.SetDeviceRisk("old", "critical")
	a.SetUserRisk(UserRisk{TenantID: "tenant-a", ID: "same-id", Subjects: []string{"old-subject"}, Severity: "high"})
	a.SetUserRisk(UserRisk{TenantID: "tenant-b", ID: "same-id", Subjects: []string{"other-subject"}, Severity: "medium"})
	if err := b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	a.SetDeviceRisk("old", "none")
	a.SetDeviceRisk("NewCase", "high")
	a.SetUserRisk(UserRisk{TenantID: "tenant-a", ID: "same-id", Subjects: []string{"new-subject"}, Severity: "critical"})
	before, _ := os.ReadFile(p.Path)
	if err := b.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.IsHighRisk("old"); ok {
		t.Fatal("removed risk retained")
	}
	if sev, ok := b.IsHighRisk("NewCase"); !ok || sev != "high" {
		t.Fatal("device identity/severity changed")
	}
	if _, ok := b.UserSeverity("tenant-a", "old-subject"); ok {
		t.Fatal("obsolete subject index retained")
	}
	if sev, ok := b.UserSeverity("tenant-a", "new-subject"); !ok || sev != "critical" {
		t.Fatal("new subject not indexed")
	}
	if sev, ok := b.UserSeverity("tenant-b", "same-id"); !ok || sev != "medium" {
		t.Fatal("cross-tenant collision")
	}
	generation := b.ConfigGeneration()
	if err := b.ReloadFromStore(); err != nil || b.ConfigGeneration() != generation {
		t.Fatal("same state changed generation")
	}
	after, _ := os.ReadFile(p.Path)
	if string(before) != string(after) {
		t.Fatal("reload wrote storage")
	}
	os.Remove(p.Path)
	if err := b.ReloadFromStore(); err == nil || b.Health() == nil {
		t.Fatal("missing prior state accepted")
	}
	if sev, _ := b.IsHighRisk("NewCase"); sev != "high" {
		t.Fatal("failure lost old map")
	}
	os.WriteFile(p.Path, []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{},"users":{}}`), 0600)
	if err := b.ReloadFromStore(); err != nil || b.Health() != nil {
		t.Fatal("valid repair did not recover")
	}
	if len(b.Snapshot()) != 0 || len(b.UserSnapshot()) != 0 {
		t.Fatal("explicit empty replacement not applied")
	}
}

func TestRiskReloadFirstBootAndLegacyBoundary(t *testing.T) {
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}
	o := NewHighRiskOverlay()
	if err := o.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := o.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.Path, []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{}}`), 0600)
	if err := o.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p.Path, []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"unattributed":"high"}}`), 0600)
	if err := o.ReloadFromStore(); err == nil || o.Health() == nil {
		t.Fatal("promotion guessed legacy attribution")
	}
	if len(o.Snapshot()) != 0 {
		t.Fatal("unattributed entry was published")
	}
	// Explicit startup recovery still adopts legacy state for the existing
	// inventory/directory migration, rather than changing the old upgrade path.
	if err := o.SetPersister(p); err != nil || !o.NeedsMigration() {
		t.Fatal("startup migration path changed")
	}
}
