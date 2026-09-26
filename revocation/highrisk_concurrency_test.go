package revocation

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type riskReadState struct {
	Devices                map[string]string
	Users                  []UserRisk
	Index                  string
	Listed                 []string
	DeviceCount, UserCount int
	Generation             uint64
	Healthy, Legacy        bool
}

func readRiskState(o *HighRiskOverlay) riskReadState {
	devices, users := o.Snapshot(), o.UserSnapshot()
	index, _ := o.UserSeverity("one", "alias")
	_, _ = o.IsHighRisk("target")
	_, _, _ = o.CheckedSnapshot()
	return riskReadState{devices, users, index, o.List(), o.CountDevices([]string{"target", "foreign"}), o.CountUsers("one"), o.ConfigGeneration(), o.Health() == nil, o.NeedsMigration()}
}
func seededRiskForConcurrency(t *testing.T) *HighRiskOverlay {
	t.Helper()
	o := NewHighRiskOverlay()
	o.Mark("target", "high")
	o.Mark("foreign", "critical")
	for _, mark := range []UserRisk{{TenantID: "one", ID: "alice", Subjects: []string{"alias"}, Severity: "high"}, {TenantID: "other", ID: "bob", Severity: "critical"}} {
		if _, err := o.SetUserRisk(mark); err != nil {
			t.Fatal(err)
		}
	}
	return o
}
func TestRiskReadsContinueDuringStorage(t *testing.T) {
	for _, action := range []string{"device_raise", "device_lower", "device_clear", "legacy_raise", "legacy_lower", "legacy_clear", "user_raise", "user_clear", "erase_both", "migrate", "load"} {
		for _, failed := range []bool{false, true} {
			name := action + "/ok"
			if failed {
				name = action + "/failed"
			}
			t.Run(name, func(t *testing.T) {
				o := seededRiskForConcurrency(t)
				if action == "migrate" {
					if err := o.SetPersister(&admissionRestorePersister{data: []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"target":"high","foreign":"critical"}}`)}); err != nil {
						t.Fatal(err)
					}
				}
				initial := readRiskState(o)
				p := newAdmissionGatedStore(t)
				if failed {
					p.err = errors.New("delayed storage failure")
				}
				if action == "load" {
					p.gateLoad = true
					devices := o.Snapshot()
					devices["target"] = "medium"
					users := cloneUserRisks(o.users)
					var err error
					p.data, err = json.Marshal(highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: devices, Users: users})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					if err := o.SetPersister(p); err != nil {
						t.Fatal(err)
					}
				}
				done := admissionAsync(func() error {
					var err error
					switch action {
					case "device_raise":
						_, err = o.SetDeviceRisk("target", "critical")
					case "device_lower":
						_, err = o.SetDeviceRisk("target", "medium")
					case "device_clear":
						_, err = o.SetDeviceRisk("target", "none")
					case "legacy_raise":
						o.Mark("target", "critical")
					case "legacy_lower":
						o.Mark("target", "medium")
					case "legacy_clear":
						o.Clear("target")
					case "user_raise":
						_, err = o.SetUserRisk(UserRisk{TenantID: "one", ID: "alice", Subjects: []string{"alias"}, Severity: "critical"})
					case "user_clear":
						_, err = o.SetUserRisk(UserRisk{TenantID: "one", ID: "alice", Severity: "none"})
					case "erase_both":
						_, err = o.RemoveTenantRisksChecked("one", []string{"target"})
					case "migrate":
						err = o.MigrateLegacy(func(id string) (*UserRisk, error) {
							if id == "target" {
								return &UserRisk{TenantID: "one", ID: "alice", Subjects: []string{"alias"}}, nil
							}
							return nil, nil
						})
					case "load":
						err = o.SetPersister(p)
					}
					return err
				})
				admissionWithin(t, p.entered)
				during := admissionWithin(t, admissionAsync(func() riskReadState { return readRiskState(o) }))
				want := initial
				if action == "legacy_raise" {
					want.Devices = map[string]string{"target": "critical", "foreign": "critical"}
					want.Generation++
				}
				if !reflect.DeepEqual(during, want) {
					t.Fatalf("pending state differs: got %+v want %+v", during, want)
				}
				select {
				case <-done:
					t.Fatal("acknowledged while I/O pending")
				default:
				}
				p.release()
				err := admissionWithin(t, done)
				checked := !strings.HasPrefix(action, "legacy_")
				if (err != nil) != (failed && checked) {
					t.Fatalf("wrong acknowledgement: %v", err)
				}
				after := readRiskState(o)
				if after.Devices["foreign"] != "critical" {
					t.Fatal("foreign device lost")
				}
				if action != "migrate" {
					if len(after.Users) == 0 || after.Users[len(after.Users)-1].TenantID != "other" {
						t.Fatal("foreign user lost")
					}
				}
				if failed && action != "legacy_raise" {
					want = initial
					if action == "load" {
						want.Healthy = false
					}
					if !reflect.DeepEqual(after, want) {
						t.Fatalf("failed operation changed published state: %+v", after)
					}
				} else {
					if after.Generation != initial.Generation+1 {
						t.Fatal("wrong generation", after.Generation, initial.Generation)
					}
					switch action {
					case "device_raise", "legacy_raise":
						if after.Devices["target"] != "critical" {
							t.Fatal("raise missing")
						}
					case "device_lower", "legacy_lower", "load":
						if after.Devices["target"] != "medium" {
							t.Fatal("lower missing")
						}
					case "device_clear", "legacy_clear", "erase_both", "migrate":
						if _, ok := after.Devices["target"]; ok {
							t.Fatal("clear missing")
						}
					case "user_raise":
						if after.Index != "critical" {
							t.Fatal("user raise missing")
						}
					case "user_clear":
						if after.Index != "" {
							t.Fatal("user clear missing")
						}
					}
					if action == "erase_both" && after.UserCount != 0 {
						t.Fatal("user erase missing")
					}
					if action == "migrate" && (!after.Healthy || after.Legacy || after.Index != "high") {
						t.Fatal("migration incomplete")
					}
				}
			})
		}
	}
}

func TestRiskQueuedWritersRetainBothNamespaces(t *testing.T) {
	for _, next := range []string{"user", "device", "erase", "synced_device", "synced_user", "replace_writer"} {
		t.Run(next, func(t *testing.T) {
			o := seededRiskForConcurrency(t)
			p := newAdmissionGatedStore(t)
			if err := o.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			first := admissionAsync(func() error { _, err := o.SetDeviceRisk("target", "medium"); return err })
			admissionWithin(t, p.entered)
			replacement := &admissionRestorePersister{}
			started := make(chan struct{})
			second := admissionAsync(func() error {
				close(started)
				var err error
				switch next {
				case "user":
					_, err = o.SetUserRisk(UserRisk{TenantID: "one", ID: "new", Severity: "high"})
				case "device":
					_, err = o.SetDeviceRisk("new-device", "high")
				case "erase":
					_, err = o.RemoveTenantRisksChecked("one", []string{"target"})
				case "synced_device":
					o.ReplaceSynced(map[string]string{"from-feed": "high", "foreign": "critical"})
				case "synced_user":
					err = o.ReplaceSyncedUsers([]UserRisk{{TenantID: "synced", ID: "remote", Severity: "critical"}})
				case "replace_writer":
					err = o.SetPersister(replacement)
				}
				return err
			})
			<-started
			admissionWithin(t, admissionAsync(func() riskReadState { return readRiskState(o) }))
			select {
			case <-second:
				t.Fatal("writer overtook pending save")
			case <-time.After(20 * time.Millisecond):
			}
			p.release()
			if err := admissionWithin(t, first); err != nil {
				t.Fatal(err)
			}
			if err := admissionWithin(t, second); err != nil {
				t.Fatal(err)
			}
			state := readRiskState(o)
			switch next {
			case "user":
				if _, ok := o.UserSeverity("one", "new"); !ok || state.Devices["target"] != "medium" {
					t.Fatal("lost prior/current write")
				}
			case "device":
				if state.Devices["new-device"] != "high" || state.Devices["target"] != "medium" {
					t.Fatal("lost devices")
				}
			case "erase":
				if state.DeviceCount != 1 || state.UserCount != 0 {
					t.Fatal("erase did not follow write")
				}
			case "synced_device":
				if len(state.Devices) != 2 || state.Devices["from-feed"] != "high" {
					t.Fatal("sync overwritten")
				}
			case "synced_user":
				if len(state.Users) != 1 || state.Users[0].TenantID != "synced" || state.Devices["target"] != "medium" {
					t.Fatal("user sync overwritten")
				}
			case "replace_writer":
				if state.Devices["target"] != "medium" || o.persister != replacement {
					t.Fatal("writer replacement ordering")
				}
			}
			// A following checked write must save the latest combined snapshot, including
			// pulled changes (which retain their existing non-persisting setter contract).
			if _, err := o.SetDeviceRisk("last", "high"); err != nil {
				t.Fatal(err)
			}
			reopened := NewHighRiskOverlay()
			target := o.persister
			if err := reopened.SetPersister(target); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reopened.Snapshot(), o.Snapshot()) || !reflect.DeepEqual(reopened.UserSnapshot(), o.UserSnapshot()) {
				t.Fatal("later save lost a namespace")
			}
			if len(p.saves) < 1 {
				t.Fatal("no saves")
			}
			var firstSaved highRiskOverlayStateFile
			if err := json.Unmarshal(p.saves[0], &firstSaved); err != nil {
				t.Fatal(err)
			}
			if firstSaved.Devices["target"] != "medium" || len(firstSaved.Users) != 2 {
				t.Fatal("pending save contained queued work")
			}
		})
	}
}

func TestRiskMigrationResolverCanReadPublishedState(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "ok", true: "failed"}[failed], func(t *testing.T) {
			p := &admissionRestorePersister{data: []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"target":"high"}}`)}
			o := NewHighRiskOverlay()
			if err := o.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			done := admissionAsync(func() error {
				return o.MigrateLegacy(func(string) (*UserRisk, error) {
					state := readRiskState(o)
					if !state.Legacy || state.Devices["target"] != "high" {
						return nil, errors.New("wrong pending legacy state")
					}
					if failed {
						return nil, errors.New("resolver failed")
					}
					return nil, nil
				})
			})
			err := admissionWithin(t, done)
			if (err != nil) != failed || o.NeedsMigration() != failed {
				t.Fatal("resolver result", err)
			}
			if failed && p.writes != 0 {
				t.Fatal("resolver failure wrote state")
			}
		})
	}
}
