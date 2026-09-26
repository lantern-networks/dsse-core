package eastwestobserve

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
	"time"
)

type reportSaveFixture struct {
	raw []byte
	err error
}

func (p *reportSaveFixture) Load() ([]byte, error) { return p.raw, nil }
func (p *reportSaveFixture) Save(b []byte) error {
	if p.err == nil || errors.Is(p.err, blobstore.ErrDurabilityUnconfirmed) {
		p.raw = append([]byte(nil), b...)
	}
	return p.err
}
func TestReportRequiresConfirmedFileSaveBeforeAcknowledgement(t *testing.T) {
	for _, failure := range []error{errors.New("disk unavailable"), blobstore.ErrDurabilityUnconfirmed} {
		p := &reportSaveFixture{err: failure}
		s := NewStore()
		if err := s.SetPersister(p, 0); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		flows := []FlowObservation{reportedFlow("db", 2, now, now)}
		for i := 0; i < 2; i++ {
			if _, err := s.ApplyReport(context.Background(), "a", "edge", 1, flows, now); err == nil {
				t.Fatal("unconfirmed report acknowledged")
			}
		}
		p.err = nil
		if _, err := s.ApplyReport(context.Background(), "a", "edge", 1, flows, now); err != nil {
			t.Fatal(err)
		}
		fresh := NewStore()
		if err := fresh.SetPersister(p, 0); err != nil {
			t.Fatal(err)
		}
		if countOf(t, fresh, "a", "db") != 2 {
			t.Fatal("saved report lost or counted twice")
		}
		if applied, err := fresh.ApplyReport(context.Background(), "a", "edge", 1, flows, now); err != nil || applied {
			t.Fatal("receipt not saved", applied, err)
		}
	}
}
