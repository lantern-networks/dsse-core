package revocation

import (
	"bytes"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const riskValidSnapshot = `{"schema_version":"high_risk_overlay_state.v2","devices":{"Owned":"high","owned":"medium"},"users":{"one\u0000alice":{"tenant_id":"one","id":"alice","severity":"critical","subjects":["alice","alias"]}}}`

func TestRiskSnapshotInvalidReplacementRetainsStateAndWriter(t *testing.T) {
	cases := map[string][]byte{
		"zero": {}, "whitespace": []byte(" \n"), "null": []byte(`null`), "array": []byte(`[]`), "truncated": []byte(`{"devices":`), "trailing": []byte(riskValidSnapshot + `{}`),
		"missing-schema": []byte(`{"devices":{}}`), "null-schema": []byte(`{"schema_version":null,"devices":{}}`),
		"missing-devices": []byte(`{"schema_version":"high_risk_overlay_state.v2"}`), "null-devices": []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":null}`),
		"array-devices":     []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":[]}`),
		"duplicate-schema":  []byte(`{"schema_version":"unknown","schema_version":"high_risk_overlay_state.v2","devices":{}}`),
		"duplicate-devices": []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{"Owned":"high"},"devices":{}}`),
		"duplicate-device":  []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{"Owned":"high","\u004fwned":"medium"}}`),
		"null-users":        []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{},"users":null}`),
		"duplicate-users":   []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{},"users":{},"users":{}}`),
		"read-error":        nil,
	}
	mutations := map[string][2]string{
		"unknown-schema": {"high_risk_overlay_state.v2", "PRIVATE_CONTENT"}, "legacy-typed-users": {"high_risk_overlay_state.v2", "high_risk_overlay_state.v1"},
		"schema-alias": {"schema_version", "Schema_version"}, "devices-alias": {"devices", "Devices"}, "users-alias": {"users", "Users"}, "unknown-field": {"\"devices\"", "\"PRIVATE_CONTENT\""},
		"empty-device": {`"Owned":`, `"":`}, "padded-device": {`"Owned":`, `" Owned ":`}, "null-device-risk": {`"high"`, `null`}, "number-device-risk": {`"high"`, `42`}, "clear-device-risk": {`"high"`, `"none"`}, "padded-device-risk": {`"high"`, `" high "`},
		"wrong-user-key": {`one\u0000alice`, `one\u0000other`}, "duplicate-user": {`"users":{`, `"users":{"one\u0000alice":{},`},
		"null-user":            {`{"tenant_id":"one","id":"alice","severity":"critical","subjects":["alice","alias"]}`, `null`},
		"duplicate-user-field": {`"severity":"critical"`, `"severity":"high","severity":"critical"`},
		"user-field-alias":     {`"tenant_id"`, `"Tenant_id"`}, "null-user-id": {`"id":"alice"`, `"id":null`}, "missing-user-tenant": {`"tenant_id":"one",`, ``},
		"unknown-user-field": {`"subjects"`, `"unknown"`}, "padded-user-id": {`"id":"alice"`, `"id":" alice "`},
		"clear-user-risk": {`"critical"`, `"none"`}, "null-user-risk": {`"critical"`, `null`}, "uppercase-user-risk": {`"critical"`, `"CRITICAL"`},
		"null-subjects": {`["alice","alias"]`, `null`}, "null-subject": {`"alias"`, `null`}, "number-subject": {`"alias"`, `123`}, "empty-subject": {`"alias"`, `""`}, "padded-subject": {`"alias"`, `" alias "`}, "nul-subject": {`"alias"`, `"a\u0000b"`},
	}
	for name, pair := range mutations {
		cases[name] = []byte(strings.Replace(riskValidSnapshot, pair[0], pair[1], 1))
	}
	cases["invalid-utf8"] = bytes.Replace([]byte(riskValidSnapshot), []byte("alias"), []byte{0xff}, 1)
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			old := &admissionRestorePersister{data: []byte(riskValidSnapshot)}
			o := NewHighRiskOverlay()
			if err := o.SetPersister(old); err != nil {
				t.Fatal(err)
			}
			devices, users, gen := o.Snapshot(), o.UserSnapshot(), o.ConfigGeneration()
			saved := bytes.Clone(old.data)
			candidate := &admissionRestorePersister{data: data}
			want := ErrInvalidRiskSnapshot
			if name == "read-error" {
				candidate.loadErr = errors.New("PRIVATE_CONTENT")
				want = ErrRiskLoad
			}
			if err := o.SetPersister(candidate); err != want {
				t.Fatalf("wrong error: %v", err)
			}
			if !reflect.DeepEqual(devices, o.Snapshot()) || !reflect.DeepEqual(users, o.UserSnapshot()) || o.ConfigGeneration() != gen || o.persister != old || !bytes.Equal(saved, old.data) || candidate.writes != 0 {
				t.Fatal("failed restoration mutated state/writer")
			}
			if o.Health() != want {
				t.Fatal("unavailable state not retained")
			}
			if d, u, e := o.CheckedSnapshot(); e != ErrRiskUnavailable || d != nil || u != nil {
				t.Fatal("checked read exposed stale state")
			}
			if sev, ok := o.UserSeverity("one", "alias"); !ok || sev != "critical" {
				t.Fatal("enforcement alias was cleared")
			}
			if _, err := o.SetDeviceRisk("Owned", "none"); err != ErrRiskUnavailable {
				t.Fatal("write on unavailable snapshot")
			}
			if _, err := o.SetUserRisk(UserRisk{TenantID: "other", ID: "bob", Severity: "high"}); err != ErrRiskUnavailable {
				t.Fatal("shared write on unavailable snapshot")
			}
			if err := o.SetPersister(nil); err != want {
				t.Fatal("nil writer masked load failure")
			}
			if err := o.SetPersister(&admissionRestorePersister{}); err != want {
				t.Fatal("missing snapshot masked failure")
			}
			if err := o.SetPersister(old); err != nil || o.Health() != nil || o.ConfigGeneration() != gen {
				t.Fatal("explicit good restoration failed or churned generation")
			}
			if _, err := o.SetDeviceRisk("Owned", "none"); err != nil {
				t.Fatal(err)
			}
			if candidate.writes != 0 || old.writes != 1 {
				t.Fatal("rejected writer adopted")
			}
			if o.Snapshot()["owned"] != "medium" {
				t.Fatal("case-sensitive device was removed")
			}
		})
	}
	t.Logf("%d invalid/read-failed snapshots", len(cases))
}

func TestRiskSnapshotValidReplacementMigrationAndFiles(t *testing.T) {
	o := NewHighRiskOverlay()
	o.Mark("old", "high")
	gen := o.ConfigGeneration()
	p := &admissionRestorePersister{data: []byte(riskValidSnapshot)}
	if err := o.SetPersister(p); err != nil || o.ConfigGeneration() != gen+1 {
		t.Fatal("replacement failed", err)
	}
	d, u, err := o.CheckedSnapshot()
	if err != nil || len(d) != 2 || len(u) != 1 {
		t.Fatal("valid read", err)
	}
	d["Owned"] = "none"
	u[0].Subjects[0] = "changed"
	if sev, _ := o.UserSeverity("one", "alias"); sev != "critical" || o.Snapshot()["Owned"] != "high" {
		t.Fatal("snapshot aliases live state")
	}
	if err := o.SetPersister(p); err != nil || o.ConfigGeneration() != gen+1 || p.writes != 0 {
		t.Fatal("same snapshot churn/rewrite")
	}
	for _, raw := range []string{`{"schema_version":"high_risk_overlay_state.v2","devices":{}}`, `{"schema_version":"high_risk_overlay_state.v1","devices":{}}`, `{"schema_version":"high_risk_overlay_state.v1","devices":{},"users":{}}`} {
		if err := o.SetPersister(&admissionRestorePersister{data: []byte(raw)}); err != nil || o.Health() != nil || len(o.UserSnapshot()) != 0 || len(o.Snapshot()) != 0 {
			t.Fatal("valid empty/legacy", err)
		}
	}
	legacy := &admissionRestorePersister{data: []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"legacy":"high"}}`)}
	if err := o.SetPersister(legacy); err != nil || !o.NeedsMigration() || o.Health() == nil {
		t.Fatal("legacy attribution bypassed")
	}
	if _, _, err := o.CheckedSnapshot(); err != ErrRiskUnavailable {
		t.Fatal("legacy read accepted")
	}
	if err := o.MigrateLegacy(func(string) (*UserRisk, error) {
		return &UserRisk{TenantID: "one", ID: "legacy", Severity: "high"}, nil
	}); err != nil || o.Health() != nil {
		t.Fatal("migration failed", err)
	}
	restored := NewHighRiskOverlay()
	if err := restored.SetPersister(legacy); err != nil || len(restored.UserSnapshot()) != 1 || len(restored.Snapshot()) != 0 {
		t.Fatal("migrated namespace", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "risk.json")
	fresh := NewHighRiskOverlay()
	if err := fresh.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("first boot created file")
	}
	if _, err := fresh.SetDeviceRisk("first", "high"); err != nil {
		t.Fatal(err)
	}
	if err := restored.SetStatePath(path); err != nil || restored.Snapshot()["first"] != "high" || len(restored.UserSnapshot()) != 0 {
		t.Fatal("file restoration", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restored.SetStatePath(filepath.Join(dir, "empty")); err != ErrInvalidRiskSnapshot {
		t.Fatal("zero file accepted")
	}
	if err := restored.SetPersister(blobstore.FilePersister{Path: dir}); err != ErrRiskLoad {
		t.Fatal("directory accepted")
	}
	if err := restored.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if err := restored.SetPersister(nil); err != nil || restored.Snapshot()["first"] != "high" {
		t.Fatal("volatile recovery")
	}
	if warning, err := restored.SetDeviceRisk("first", "none"); err != nil || !warning {
		t.Fatal("volatile contract", err)
	}
}
