package enrolledinventory

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

type unconfirmedInventoryContextStore struct {
	data      []byte
	candidate []byte
}

func (p *unconfirmedInventoryContextStore) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *unconfirmedInventoryContextStore) Save(b []byte) error   { p.data = bytes.Clone(b); return nil }
func (p *unconfirmedInventoryContextStore) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	var err error
	p.candidate, err = edit(bytes.Clone(p.data))
	if err != nil {
		return err
	}
	return errors.New("private backend write failure")
}
func TestSharedInventoryUnconfirmedLifecycleDoesNotPublish(t *testing.T) {
	for _, operation := range []string{"enroll", "rearm", "assign", "kind", "remove", "machine", "report", "create", "rename", "delete"} {
		t.Run(operation, func(t *testing.T) {
			p := &unconfirmedInventoryContextStore{}
			l := NewLedger()
			if err := l.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			if _, err := l.Enroll("device", "tenant", "", "now"); err != nil {
				t.Fatal(err)
			}
			g, err := l.CreateGroup("Pilot", "tenant", "", "high", "now")
			if err != nil {
				t.Fatal(err)
			}
			before, _ := decodeInventorySnapshot(p.data)
			generation := l.ConfigGeneration()
			ctx := context.Background()
			name := "Renamed"
			switch operation {
			case "enroll":
				_, err = l.EnrollGroupForTenantContext(ctx, "new", "tenant", "tenant", "", "", "now", false)
			case "rearm":
				_, _, err = l.AllowReenrolmentContext(ctx, "device", "tenant", "now")
			case "assign":
				_, _, err = l.SetGroupContext(ctx, "device", "tenant", "Pilot", "now")
			case "kind":
				_, _, err = l.SetKindContext(ctx, "device", "tenant", KindService, "now")
			case "remove":
				_, err = l.RemoveCheckedContext(ctx, "device", "tenant", "now")
			case "machine":
				err = l.RecordReportedMachineContext(ctx, "device", "tenant", "machine", "now")
			case "report":
				_, err = l.RecordEnrolmentReportContext(ctx, "new", "tenant", "Pilot", "", "machine-new", "now")
			case "create":
				_, err = l.CreateGroupContext(ctx, "New", "tenant", "", "", "now")
			case "rename":
				_, _, err = l.UpdateGroupContext(ctx, g.ID, "tenant", &name, nil, nil, "now")
			case "delete":
				_, _, err = l.DeleteGroupContext(ctx, g.ID, "tenant", false)
			}
			if !errors.Is(err, ErrInventorySave) || len(p.candidate) == 0 {
				t.Fatalf("save refusal not exercised: %v", err)
			}
			if !reflect.DeepEqual(l.entries, before.Entries) || !reflect.DeepEqual(l.groups, before.Groups) || l.ConfigGeneration() != generation {
				t.Fatal("unconfirmed candidate published")
			}
		})
	}
}

type reportFileStore struct {
	data  []byte
	fail  bool
	saves int
}

func (p *reportFileStore) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *reportFileStore) Save(b []byte) error {
	p.saves++
	if p.fail {
		return errors.New("disk failure")
	}
	p.data = bytes.Clone(b)
	return nil
}
func TestEnrolmentReportCommitsMarkerAndMachineTogether(t *testing.T) {
	p := &reportFileStore{}
	l := NewLedger()
	if err := l.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	if _, err := l.RecordEnrolmentReportContext(context.Background(), "device", "tenant", "Pilot", "note", "machine-1", "now"); !errors.Is(err, ErrInventorySave) {
		t.Fatalf("storage refusal %v", err)
	}
	if _, ok := l.EntryFor("device"); ok {
		t.Fatal("failed file update published")
	}
	p.fail = false
	before := p.saves
	if _, err := l.RecordEnrolmentReportContext(context.Background(), "device", "tenant", "Pilot", "note", "machine-1", "now"); err != nil {
		t.Fatal(err)
	}
	if p.saves != before+1 {
		t.Fatal("report split into multiple saves")
	}
	restored := NewLedger()
	if err := restored.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	e, ok := restored.EntryFor("device")
	if !ok || e.MachineRef != "machine-1" || e.DeviceEnrolledAt != "now" {
		t.Fatalf("incomplete report %+v", e)
	}
	if _, err := restored.RecordEnrolmentReportContext(context.Background(), "device", "tenant", "Pilot", "note", "machine-2", "later"); err != nil {
		t.Fatal(err)
	}
	if e, _ := restored.EntryFor("device"); e.MachineRef != "machine-1" {
		t.Fatal("first machine binding replaced")
	}
}
