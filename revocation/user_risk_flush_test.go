package revocation

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// This models the two possible durable outcomes after an unconfirmed flush,
// rather than causing a real power loss. Load returns only retained bytes.
type riskFlushPersister struct {
	data   []byte
	err    error
	retain bool
}

func (p *riskFlushPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *riskFlushPersister) Save(b []byte) error {
	if p.err == nil || p.retain {
		p.data = bytes.Clone(b)
	}
	return p.err
}

func TestCheckedUserRiskRejectsUnconfirmedFlush(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, outcome := range []struct {
		name                      string
		err                       error
		retain, accepted, warning bool
	}{
		{"atomic", nil, true, true, false},
		{"synced_in_place", blobstore.ErrSavedWithoutAtomicity, true, true, true},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false, false},
		{"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false, false},
		{"bridge_lost", bridge, false, false, false},
		{"bridge_retained", bridge, true, false, false},
		{"wrapped_bridge_lost", fmt.Errorf("save: %w", bridge), false, false, false},
		{"wrapped_bridge_retained", fmt.Errorf("save: %w", bridge), true, false, false},
	} {
		for _, op := range []string{"mark", "clear", "remove", "migrate"} {
			t.Run(outcome.name+"/"+op, func(t *testing.T) {
				p := &riskFlushPersister{}
				s := NewHighRiskOverlay()
				if op == "migrate" {
					p.data = []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"alice":"high","control-device":"medium"}}`)
				}
				s.SetPersister(p)
				if op != "migrate" {
					s.Mark("control-device", "medium")
					for _, tenant := range []string{"own", "foreign"} {
						if _, err := s.SetUserRisk(UserRisk{TenantID: tenant, ID: "alice", Subjects: []string{"subject"}, Severity: "high"}); err != nil {
							t.Fatal(err)
						}
					}
				}
				users, devices, generation := s.UserSnapshot(), s.Snapshot(), s.ConfigGeneration()
				p.err, p.retain = outcome.err, outcome.retain
				mutate := func() (bool, error) {
					switch op {
					case "mark", "clear":
						severity := "critical"
						if op == "clear" {
							severity = "none"
						}
						return s.SetUserRisk(UserRisk{TenantID: "own", ID: "alice", Subjects: []string{"subject"}, Severity: severity})
					case "remove":
						n, err := s.RemoveUsers("own")
						if (err == nil && n != 1) || (err != nil && n != 0) {
							t.Fatal("wrong removal count")
						}
						return false, err
					default:
						return false, s.MigrateLegacy(func(id string) (*UserRisk, error) {
							if id == "control-device" {
								return nil, nil
							}
							return &UserRisk{TenantID: "own", ID: id, Subjects: []string{"subject"}}, nil
						})
					}
				}
				warning, err := mutate()
				if (err == nil) != outcome.accepted {
					t.Fatalf("save accepted=%v, want %v", err == nil, outcome.accepted)
				}
				if !outcome.accepted && !errors.Is(err, ErrRiskSave) {
					t.Fatal("wrong failure classification")
				}
				if (op == "mark" || op == "clear") && warning != outcome.warning {
					t.Fatal("wrong completed-save warning")
				}
				if outcome.accepted {
					if s.ConfigGeneration() != generation+1 {
						t.Fatal("completed mutation not published")
					}
				} else if s.ConfigGeneration() != generation || !reflect.DeepEqual(users, s.UserSnapshot()) || !reflect.DeepEqual(devices, s.Snapshot()) {
					t.Fatal("unconfirmed mutation changed live state or generation")
				}
				reopened := NewHighRiskOverlay()
				reopened.SetPersister(p)
				if !outcome.retain {
					if !reflect.DeepEqual(users, reopened.UserSnapshot()) || !reflect.DeepEqual(devices, reopened.Snapshot()) {
						t.Fatal("unretained mutation appeared on restart")
					}
				} else {
					want := ""
					if op == "mark" {
						want = "critical"
					}
					if op == "migrate" {
						want = "high"
					}
					if got, _ := reopened.UserSeverity("own", "subject"); got != want {
						t.Fatalf("retained state=%q, want %q", got, want)
					}
				}
				if severity, _ := reopened.IsHighRisk("control-device"); severity != "medium" {
					t.Fatal("unrelated device changed")
				}
				if op != "migrate" {
					if severity, _ := reopened.UserSeverity("foreign", "subject"); severity != "high" {
						t.Fatal("foreign user changed")
					}
				}
				if !outcome.accepted {
					// Explicitly reapply the intended change after restoring storage.
					p.err = nil
					if _, err := mutate(); err != nil {
						t.Fatal(err)
					}
					if s.ConfigGeneration() != generation+1 {
						t.Fatal("retry not published once")
					}
					again := NewHighRiskOverlay()
					again.SetPersister(p)
					if !reflect.DeepEqual(s.UserSnapshot(), again.UserSnapshot()) || !reflect.DeepEqual(s.Snapshot(), again.Snapshot()) {
						t.Fatal("retry state differs on restart")
					}
				}
			})
		}
	}
}
