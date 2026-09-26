package delegatedgrant

import (
	"testing"
	"time"
)

func TestTerminalAndExpiredGrantsDoNotExhaustActiveCapacity(t *testing.T) {
	for _, terminal := range []string{"revoked", "expired", "elapsed"} {
		t.Run(terminal, func(t *testing.T) {
			now := time.Now()
			s := NewStore(1)
			old := capacityRecord("a", "old", now)
			if terminal == "elapsed" {
				old.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339)
			} else {
				old.Status = terminal
			}
			if _, err := s.Upsert(old); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Upsert(capacityRecord("a", "new", now)); err != nil {
				t.Fatalf("inactive history blocks new grant: %v", err)
			}
			if got, ok := s.GetForTenant("a", "old"); !ok || got.Status != old.Status {
				t.Fatal("terminal history was lost")
			}
		})
	}
}
