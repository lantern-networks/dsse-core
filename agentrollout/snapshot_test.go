package agentrollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

type rolloutSnapshotBlob struct {
	data  []byte
	err   error
	saves int
}

func (b *rolloutSnapshotBlob) Load() ([]byte, error) { return b.data, b.err }
func (b *rolloutSnapshotBlob) Save(data []byte) error {
	b.data = append([]byte{}, data...)
	b.saves++
	return nil
}

func savedRolloutFixture() AgentRolloutPlan {
	n := 11
	return AgentRolloutPlan{Frozen: true, DesiredVersion: "0.3.1", ReleaseChannel: "stable", Intent: "rollout", Reason: "PRIVATE_SAVED_REASON", UpdatedAt: "2026-09-18T00:00:00Z", Waves: &WaveSchedule{Waves: []RolloutWave{{Group: "Pilot", DelayDays: 0, Priority: 9}, {Group: "General", DelayDays: 4}}, DefaultDelayDays: &n}, Window: &agentupdate.PlanWindow{LocalStart: "01:00", LocalEnd: "05:00", RequireIdleMinutes: 15, RequireACPower: true, RequireUnattended: true, DeadlineDays: 7}}
}

func TestRolloutSnapshotRejectsUnknownHaltWithoutReplacingState(t *testing.T) {
	p := savedRolloutFixture()
	valid, _ := json.Marshal(map[string]AgentRolloutPlan{"own": p})
	replace := func(old, next string) []byte { return bytes.Replace(valid, []byte(old), []byte(next), 1) }
	bad := map[string][]byte{
		"zero-bytes": {}, "whitespace": []byte(" \n"), "null": []byte("null"), "array": []byte("[]"),
		"null-plan": []byte(`{"own":null}`), "empty-plan": []byte(`{"own":{}}`),
		"missing-halt": replace(`"frozen":true,`, ""), "null-halt": replace(`"frozen":true`, `"frozen":null`),
		"alias-halt": replace(`"frozen":true`, `"Frozen":true`), "duplicate-halt": replace(`"frozen":true`, `"frozen":true,"frozen":false`),
		"duplicate-tenant": []byte(`{"own":{"frozen":true},"own":{"frozen":false}}`),
		"padded-tenant":    replace(`"own":`, `" own ":`),
		"unknown-field":    replace(`"frozen":true`, `"frozen":true,"PRIVATE_UNKNOWN_FIELD":true`),
		"unknown-intent":   replace(`"intent":"rollout"`, `"intent":"PRIVATE_UNKNOWN_INTENT"`),
		"null-reason":      replace(`"reason":"PRIVATE_SAVED_REASON"`, `"reason":null`),
		"invalid-time":     replace(`2026-09-18T00:00:00Z`, `PRIVATE_INVALID_TIME`),
		"negative-idle":    replace(`"require_idle_minutes":15`, `"require_idle_minutes":-1`),
		"null-unattended":  replace(`"require_unattended":true`, `"require_unattended":null`),
		"missing-ac":       replace(`"require_ac_power":true,`, ""),
		"duplicate-ac":     replace(`"require_ac_power":true`, `"require_ac_power":true,"require_ac_power":false`),
		"bad-clock":        replace(`"01:00"`, `"PRIVATE_BAD_CLOCK"`),
		"long-deadline":    replace(`"deadline_days":7`, `"deadline_days":366`),
		"empty-schedule":   replace(`"waves":[{"group":"Pilot","delay_days":0,"priority":9},{"group":"General","delay_days":4}]`, `"unexpected":[]`),
		"null-wave":        replace(`{"group":"Pilot","delay_days":0,"priority":9}`, `null`),
		"missing-delay":    replace(`"delay_days":4`, `"priority":0`),
		"null-priority":    replace(`"priority":9`, `"priority":null`),
		"duplicate-delay":  replace(`"delay_days":4`, `"delay_days":4,"delay_days":0`),
		"negative-default": replace(`"default_delay_days":11`, `"default_delay_days":-1`),
		"duplicate-group":  replace(`"General"`, `"pilot"`),
		"trailing-value":   append(append([]byte{}, valid...), []byte(`{}`)...),
		"truncated":        valid[:len(valid)-1],
		"invalid-utf8":     bytes.Replace(valid, []byte("PRIVATE_SAVED_REASON"), []byte{0xff}, 1),
	}
	for name, data := range bad {
		for _, shared := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/file", true: "/shared"}[shared], func(t *testing.T) {
				old := &rolloutSnapshotBlob{}
				s := NewAgentRolloutStore()
				if err := s.LoadFromPersister(old); err != nil {
					t.Fatal(err)
				}
				if err := s.Set("own", p); err != nil {
					t.Fatal(err)
				}
				if err := s.Set("foreign", p); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "plans.json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				other := &rolloutSnapshotBlob{data: data}
				var err error
				if shared {
					err = s.LoadFromPersister(other)
				} else {
					err = s.LoadFrom(path)
				}
				if err == nil {
					t.Fatal("invalid snapshot accepted; halt state is unknown")
				}
				if strings.Contains(err.Error(), "PRIVATE_") {
					t.Fatal("saved content disclosed in error", err)
				}
				if !reflect.DeepEqual(s.Get("own"), p) || !reflect.DeepEqual(s.Get("foreign"), p) {
					t.Fatal("rejected load replaced held plans")
				}
				if err := s.Set("later", p); err != nil {
					t.Fatal(err)
				}
				if old.saves != 3 || other.saves != 0 {
					t.Fatal("rejected load retargeted persistence")
				}
				after, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(after, data) {
					t.Fatal("rejected snapshot overwritten")
				}
				fresh := NewAgentRolloutStore()
				if shared {
					err = fresh.LoadFromPersister(other)
				} else {
					err = fresh.LoadFrom(path)
				}
				if err == nil {
					t.Fatal("fresh startup accepted corrupt state")
				}
			})
		}
	}
	t.Logf("%d invalid snapshots, file and shared, held and fresh stores", len(bad))
}

func TestRolloutSnapshotRoundTripAndFirstBoot(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "shared"}[shared], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plans.json")
			blob := &rolloutSnapshotBlob{}
			load := func(s *AgentRolloutStore) error {
				if shared {
					return s.LoadFromPersister(blob)
				}
				return s.LoadFrom(path)
			}
			s := NewAgentRolloutStore()
			if err := load(s); err != nil {
				t.Fatal(err)
			}
			if blob.saves != 0 {
				t.Fatal("first boot wrote state")
			}
			p := savedRolloutFixture()
			if err := s.Set("own", p); err != nil {
				t.Fatal(err)
			}
			legacy := AgentRolloutPlan{Frozen: true, Reason: "legacy halt"}
			if err := s.Set("legacy", legacy); err != nil {
				t.Fatal(err)
			}
			if err := s.Set("", legacy); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				restored := NewAgentRolloutStore()
				if err := load(restored); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(restored.Get("own"), p) || !reflect.DeepEqual(restored.Get("legacy"), legacy) || !reflect.DeepEqual(restored.Get(""), legacy) {
					t.Fatal("round trip lost intent")
				}
				if _, _, update := AgentRolloutDecision(restored.Get("own"), "0.3.0", "0.3.1", "stable"); update {
					t.Fatal("restart released held fleet")
				}
			}
		})
	}
	for _, raw := range []string{`{}`, `{"own":{"frozen":false}}`, `{"own":{"frozen":true,"waves":null,"window":null}}`, `{"own":{"frozen":true,"waves":{"waves":null}}}`, `{"own":{"frozen":true,"waves":{"waves":[],"default_delay_days":0}}}`} {
		s := NewAgentRolloutStore()
		if err := s.LoadFromPersister(&rolloutSnapshotBlob{data: []byte(raw)}); err != nil {
			t.Fatalf("valid legacy/empty snapshot rejected: %s: %v", raw, err)
		}
	}
}

func TestRolloutSnapshotReadFailureKeepsBinding(t *testing.T) {
	s := NewAgentRolloutStore()
	old := &rolloutSnapshotBlob{}
	if err := s.LoadFromPersister(old); err != nil {
		t.Fatal(err)
	}
	p := savedRolloutFixture()
	if err := s.Set("own", p); err != nil {
		t.Fatal(err)
	}
	bad := &rolloutSnapshotBlob{err: errors.New("read unavailable")}
	if err := s.LoadFromPersister(bad); err == nil {
		t.Fatal("read failure accepted")
	}
	if err := s.LoadFrom(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	if !reflect.DeepEqual(s.Get("own"), p) {
		t.Fatal("read failure changed halt")
	}
	if err := s.Set("later", p); err != nil {
		t.Fatal(err)
	}
	if old.saves != 2 || bad.saves != 0 {
		t.Fatal("read failure changed persistence")
	}
}
