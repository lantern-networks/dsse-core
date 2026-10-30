package eastwestobserve

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type restoreBoundaryPersister struct {
	raw     []byte
	loadErr error
	saves   int
}

func (p *restoreBoundaryPersister) Load() ([]byte, error) { return p.raw, p.loadErr }
func (p *restoreBoundaryPersister) Save([]byte) error {
	p.saves++
	return nil
}

func TestUnreadableLocalInventoryCannotBeOverwrittenByObservationOrReport(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	foreign := FlowObservation{
		ObservationID: ObservationKey("device", "db.example", "ssh", 22),
		TenantID:      "other", Source: "device", Destination: "db.example", ServiceFamily: "ssh", Port: 22,
		Count: 1, FirstSeen: now.Format(time.RFC3339), LastSeen: now.Format(time.RFC3339),
	}
	crossTenant, err := json.Marshal(map[string]map[string]FlowObservation{"own": {foreign.ObservationID: foreign}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		err  error
	}{
		{name: "read error", err: errors.New("unreadable")},
		{name: "invalid JSON", raw: []byte(`{"own":`)},
		{name: "foreign tenant row", raw: crossTenant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &restoreBoundaryPersister{raw: tc.raw, loadErr: tc.err}
			s := NewStore()
			if err := s.SetPersister(p, 0); err == nil {
				t.Fatal("restore should fail")
			}
			if err := s.RefreshShared(); err == nil {
				t.Fatal("inventory read must not report an empty, healthy inventory")
			}
			s.Observe("own", "device", "", "db.example", "ssh", 22, now)
			if err := s.PersistIfDirty(); err == nil {
				t.Fatal("flush overwrote an unreadable inventory")
			}
			report := []FlowObservation{{Source: "device", Destination: "db.example", ServiceFamily: "ssh", Port: 22,
				Count: 1, FirstSeen: now.Format(time.RFC3339), LastSeen: now.Format(time.RFC3339)}}
			if _, err := s.ApplyReport(context.Background(), "own", "reporter", 1, report, now); err == nil {
				t.Fatal("report overwrote an unreadable inventory")
			}
			if p.saves != 0 {
				t.Fatalf("unreadable original was overwritten %d times", p.saves)
			}
		})
	}
}
