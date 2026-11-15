package dns

import (
	"fmt"
	"testing"
	"time"
)

func TestReviewNameIndexStillHonorsTheStoreResourceBound(t *testing.T) {
	t.Run("one_name_many_addresses", func(t *testing.T) {
		s := NewConntrackStore()
		s.capacity = 2
		now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 8; i++ {
			s.RecordEdgeAnswer(ObservationRequest{TenantID: "test-tenant", FQDN: "rotating.example.test", ResolvedIPs: []string{fmt.Sprintf("192.0.2.%d", i)}, TTLSeconds: 60}, now.Add(time.Duration(i)*time.Second))
		}
		got := len(s.byName[nameKey("test-tenant", "rotating.example.test")])
		t.Logf("address records=%d capacity=%d named address records=%d names=%d", len(s.entries), s.capacity, got, len(s.byName))
		if got > s.capacity {
			t.Error("the new name index retains address entries beyond the store's resource bound")
		}
	})
	t.Run("expiry_reinsert_keeps_stale_fifo_keys", func(t *testing.T) {
		s := NewConntrackStore()
		s.capacity = 2
		now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 8; i++ {
			at := now.Add(time.Duration(2*i) * time.Second)
			s.RecordEdgeAnswer(ObservationRequest{TenantID: "test-tenant", FQDN: "repeat.example.test", ResolvedIPs: []string{"192.0.2.1"}, TTLSeconds: 1}, at)
			if got := s.LookupAddresses("test-tenant", "repeat.example.test", at.Add(time.Second)); len(got) != 0 {
				t.Fatal("expiry fixture did not expire")
			}
		}
		t.Logf("names=%d FIFO keys=%d capacity=%d", len(s.byName), len(s.nameOrder), s.capacity)
		if len(s.nameOrder) > 2*s.capacity {
			t.Error("expired and reinserted names leave the FIFO growing indefinitely")
		}
	})
}
