package revocation

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type userRiskPersisterPublicBaseline struct {
	base       blobstore.Persister
	fail, weak bool
}

func (p *userRiskPersisterPublicBaseline) Load() ([]byte, error) { return p.base.Load() }
func (p *userRiskPersisterPublicBaseline) Save(b []byte) error {
	if p.fail {
		return errors.New("internal-path")
	}
	if err := p.base.Save(b); err != nil {
		return err
	}
	if p.weak {
		return blobstore.ErrSavedWithoutAtomicity
	}
	return nil
}

func TestLegacyRiskDiscardRequiresConfirmedSavePublicBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"orphan":"critical"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := &userRiskPersisterPublicBaseline{base: blobstore.FilePersister{Path: path}}
	o := NewHighRiskOverlay()
	if err := o.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := o.MigrateLegacy(func(string) (*UserRisk, error) { return nil, ErrLegacyUnattributed }); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	if _, err := o.DiscardLegacyUnattributed("orphan", "critical"); !errors.Is(err, ErrRiskSave) || o.LegacySeverity("orphan") != "critical" {
		t.Fatalf("failed save published a discard: %v", err)
	}
	reloaded := NewHighRiskOverlay()
	if err := reloaded.SetStatePath(path); err != nil || reloaded.LegacySeverity("orphan") != "critical" {
		t.Fatalf("failed save erased disk risk: %v", err)
	}
	p.fail = false
	if _, err := o.DiscardLegacyUnattributed("orphan", "high"); !errors.Is(err, ErrLegacyRiskChanged) {
		t.Fatalf("stale expected severity accepted: %v", err)
	}
	if _, err := o.DiscardLegacyUnattributed("orphan", "critical"); err != nil {
		t.Fatal(err)
	}
	if o.LegacyUnattributedCount() != 0 {
		t.Fatal("resolved mark remained in memory")
	}
}
func TestUserRiskSeparatesTenantsDevicesAndSubjectsPublicBaseline(t *testing.T) {
	o := NewHighRiskOverlay()
	o.Mark("shared", "medium")
	mark := UserRisk{TenantID: "one", ID: "shared", Subjects: []string{"subject", "email@example.test"}, Severity: "critical"}
	if _, err := o.SetUserRisk(mark); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"shared", "subject", "email@example.test"} {
		if sev, ok := o.UserSeverity("one", id); !ok || sev != "critical" {
			t.Fatalf("missing subject %s", id)
		}
		if _, ok := o.UserSeverity("two", id); ok {
			t.Fatal("cross-tenant risk")
		}
	}
	if _, ok := o.UserSeverity("one", "SUBJECT"); ok {
		t.Fatal("opaque subject was case folded")
	}
	if sev, _ := o.IsHighRisk("shared"); sev != "medium" {
		t.Fatal("user risk modified device")
	}
	mark.TenantID = "two"
	mark.Severity = "high"
	o.SetUserRisk(mark)
	mark.TenantID = "one"
	mark.Severity = "none"
	o.SetUserRisk(mark)
	if _, ok := o.UserSeverity("one", "subject"); ok {
		t.Fatal("clear failed")
	}
	if sev, _ := o.UserSeverity("two", "subject"); sev != "high" {
		t.Fatal("clear changed other tenant")
	}
	if sev, _ := o.IsHighRisk("shared"); sev != "medium" {
		t.Fatal("clear changed device")
	}
}

func TestFailedDeviceSaveCannotBePersistedByUserWritePublicBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.json")
	p := &userRiskPersisterPublicBaseline{base: blobstore.FilePersister{Path: path}}
	o := NewHighRiskOverlay()
	if err := o.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	o.Mark("device", "high") // conservative live escalation, but the save failed
	if sev, _ := o.IsHighRisk("device"); sev != "high" {
		t.Fatal("failed device save removed the live escalation")
	}
	p.fail = false
	if _, err := o.SetUserRisk(UserRisk{TenantID: "one", ID: "alice", Severity: "high"}); !errors.Is(err, ErrRiskUnavailable) {
		t.Fatalf("unconfirmed device mark leaked into user save: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected user save wrote a snapshot: %v", err)
	}
	o.Mark("device", "high") // same-value retry must confirm the pending save
	if _, err := o.SetUserRisk(UserRisk{TenantID: "one", ID: "alice", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	again := NewHighRiskOverlay()
	if err := again.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if sev, _ := again.IsHighRisk("device"); sev != "high" {
		t.Fatal("device retry did not persist")
	}
	if sev, _ := again.UserSeverity("one", "alice"); sev != "high" {
		t.Fatal("user write did not persist")
	}
}
func TestUserRiskRejectsSaveBeforePublishingAndSurvivesRestartPublicBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.json")
	p := &userRiskPersisterPublicBaseline{base: blobstore.FilePersister{Path: path}}
	o := NewHighRiskOverlay()
	o.SetPersister(p)
	mark := UserRisk{TenantID: "one", ID: "alice", Subjects: []string{"subject"}, Severity: "high"}
	if warning, err := o.SetUserRisk(mark); err != nil || warning {
		t.Fatal(warning, err)
	}
	before, _ := os.ReadFile(path)
	generation := o.ConfigGeneration()
	for _, sev := range []string{"none", "critical"} {
		p.fail = true
		mark.Severity = sev
		if _, err := o.SetUserRisk(mark); !errors.Is(err, ErrRiskSave) {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) || o.ConfigGeneration() != generation {
			t.Fatal("rejected save became visible")
		}
		if sev, _ := o.UserSeverity("one", "subject"); sev != "high" {
			t.Fatal("rejected save changed risk")
		}
	}
	p.fail = false
	mark.Severity = "medium"
	o.SetUserRisk(mark)
	again := NewHighRiskOverlay()
	again.SetStatePath(path)
	if err := again.Health(); err != nil {
		t.Fatal(err)
	}
	if sev, _ := again.UserSeverity("one", "subject"); sev != "medium" {
		t.Fatal("restart lost risk")
	}
	p.weak = true
	mark.Severity = "critical"
	if warning, err := o.SetUserRisk(mark); err != nil || !warning {
		t.Fatal(warning, err)
	}
	again = NewHighRiskOverlay()
	again.SetStatePath(path)
	if sev, _ := again.UserSeverity("one", "subject"); sev != "critical" {
		t.Fatal("committed warning diverged")
	}
	p.weak = false
	p.fail = true
	if n, err := o.RemoveUsers("one"); n != 0 || err == nil {
		t.Fatal(n, err)
	}
	p.fail = false
	if n, err := o.RemoveUsers("one"); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	again = NewHighRiskOverlay()
	again.SetStatePath(path)
	if again.CountUsers("one") != 0 {
		t.Fatal("erased risk restored")
	}
}
func TestUserRiskFeedRejectsMalformedAndCopiesSubjectsPublicBaseline(t *testing.T) {
	o := NewHighRiskOverlay()
	mark := UserRisk{TenantID: "one", ID: "alice", Subjects: []string{"subject"}, Severity: "high"}
	o.SetUserRisk(mark)
	snapshot := o.UserSnapshot()
	snapshot[0].Subjects[0] = "mutated"
	if _, ok := o.UserSeverity("one", "mutated"); ok {
		t.Fatal("snapshot aliases storage")
	}
	for _, rows := range [][]UserRisk{{{TenantID: "", ID: "alice", Severity: "high"}}, {{TenantID: "one", ID: "alice", Severity: "none"}}, {mark, mark}} {
		if err := o.ReplaceSyncedUsers(rows); err == nil {
			t.Fatal("invalid feed accepted")
		}
		if sev, _ := o.UserSeverity("one", "subject"); sev != "high" {
			t.Fatal("invalid feed changed risk")
		}
	}
	peer := NewHighRiskOverlay()
	if err := peer.ReplaceSyncedUsers(o.UserSnapshot()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(o.UserSnapshot(), peer.UserSnapshot()) {
		t.Fatal("feed mismatch")
	}
	peer.ReplaceSyncedUsers(nil)
	if peer.CountUsers("one") != 0 {
		t.Fatal("explicit empty feed failed")
	}
}
func TestRiskStateUnreadableAndUnknownSchemaRemainUnavailablePublicBaseline(t *testing.T) {
	for _, raw := range []string{"{", `{"schema_version":"future","devices":{}}`, `{"schema_version":"high_risk_overlay_state.v2","users":{"invalid":{"id":"alice","severity":"high"}}}`, `{"schema_version":"high_risk_overlay_state.v2","devices":{},"legacy_unattributed":null}`, `{"schema_version":"high_risk_overlay_state.v2","devices":{},"legacy_unattributed":{"id":"none"}}`, `{"schema_version":"high_risk_overlay_state.v1","devices":{},"legacy_unattributed":{"id":"high"}}`, `{"schema_version":"high_risk_overlay_state.v2","devices":{},"legacy_unattributed":{"id":"high","id":"critical"}}`} {
		path := filepath.Join(t.TempDir(), "risk.json")
		os.WriteFile(path, []byte(raw), 0600)
		o := NewHighRiskOverlay()
		o.SetStatePath(path)
		if o.Health() == nil {
			t.Fatal("bad store reads healthy")
		}
		if _, err := o.SetUserRisk(UserRisk{TenantID: "one", ID: "alice", Severity: "high"}); err == nil {
			t.Fatal("bad store overwritten")
		}
		after, _ := os.ReadFile(path)
		if string(after) != raw {
			t.Fatal("bad store destroyed")
		}
	}
}
