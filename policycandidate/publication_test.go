package policycandidate

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicationApprovalChecksSavedTarget(t *testing.T) {
	for _, kind := range []string{"suppressed", "target_changed", "erased", "observed"} {
		t.Run(kind, func(t *testing.T) {
			ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
			s := NewStore()
			path := filepath.Join(t.TempDir(), "candidates.json")
			if e := s.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			c, e := s.ObserveConnectorDiscovered(ctx, "own", "original.example", 443, "web", "conn", "site", "ns", nil, now)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "suppressed":
				_, _, e = s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "suppressed"}, now)
			case "target_changed":
				n := c
				n.Host = "changed.example"
				_, e = s.Upsert(ctx, n, "own", now)
			case "erased":
				_, e = s.RemoveTenantContext(ctx, "own")
			case "observed":
				_, e = s.ObserveConnectorDiscovered(ctx, "own", "original.example", 443, "web", "conn", "site", "ns", nil, now.Add(time.Second))
			}
			if e != nil {
				t.Fatal(e)
			}
			got, found, e := s.ApprovePublication(ctx, c, "published", now)
			switch kind {
			case "suppressed", "target_changed":
				if !errors.Is(e, ErrPublicationChanged) {
					t.Fatal("changed candidate approved", got, e)
				}
			case "erased":
				if e != nil || found {
					t.Fatal(got, found, e)
				}
			case "observed":
				if e != nil || !found || got.Status != "approved" || *got.LastObserved == *c.LastObserved {
					t.Fatal(got, e)
				}
			}
			fresh := NewStore()
			if e = fresh.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			saved, exists, e := fresh.Get(ctx, "own", c.CandidateID)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "erased" {
				if exists {
					t.Fatal("erased candidate restored")
				}
			} else if kind == "suppressed" && saved.Status != "suppressed" || kind == "target_changed" && saved.Host != "changed.example" || kind == "observed" && saved.Status != "approved" {
				t.Fatal(saved)
			}
		})
	}
}
