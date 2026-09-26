package policycandidate

import (
	"context"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
	"time"
)

type reportSaveFixture struct {
	raw  []byte
	fail bool
}

func (p *reportSaveFixture) Load() ([]byte, error) { return p.raw, nil }
func (p *reportSaveFixture) Save(b []byte) error {
	p.raw = append([]byte(nil), b...)
	if p.fail {
		return blobstore.ErrDurabilityUnconfirmed
	}
	return nil
}
func TestReportRetryMustConfirmPreviouslyUnflushedReceipt(t *testing.T) {
	p := &reportSaveFixture{fail: true}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	obs := []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "db.example", Port: 443, Count: 2, LastObserved: now.Format(time.RFC3339)}}
	for i := 0; i < 2; i++ {
		if _, err := s.ApplyReport(context.Background(), "a", "edge", 1, obs, now); err == nil {
			t.Fatal("unconfirmed receipt acknowledged")
		}
	}
	p.fail = false
	if _, err := s.ApplyReport(context.Background(), "a", "edge", 1, obs, now); err != nil {
		t.Fatal(err)
	}
	fresh := NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	c, ok, err := fresh.Get(context.Background(), "a", LearningCandidateID("db.example", "", 443))
	if err != nil || !ok || c.FailureCount != 2 {
		t.Fatal("saved count", c, err)
	}
}
