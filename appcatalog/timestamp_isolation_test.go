package appcatalog

import (
	"context"
	"testing"
	"time"
)

func TestCatalogReturnedTimestampsCannotMutateStoredState(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	cases := map[string]func(*Store, Entry) *string{
		"upsert": func(_ *Store, saved Entry) *string { return saved.UpdatedAt },
		"get": func(s *Store, _ Entry) *string {
			entry, _, _ := s.Get(ctx, "tenant", "app")
			return entry.UpdatedAt
		},
		"list": func(s *Store, _ Entry) *string {
			rows, _ := s.List(ctx, "tenant", ListOptions{})
			return rows.Applications[0].UpdatedAt
		},
		"list_all": func(s *Store, _ Entry) *string {
			rows, _ := s.ListAll(ctx, "tenant", ListAllOptions{})
			return rows[0].UpdatedAt
		},
		"snapshot": func(s *Store, _ Entry) *string { return s.Snapshot()["tenant"]["app"].UpdatedAt },
		"export": func(s *Store, _ Entry) *string {
			rows, _ := s.ExportSnapshot(ctx)
			return rows["tenant"]["app"].UpdatedAt
		},
	}
	for name, view := range cases {
		t.Run(name, func(t *testing.T) {
			s := NewStore()
			saved, err := s.Upsert(ctx, Entry{ApplicationID: "app", Status: "active"}, "tenant", now)
			if err != nil {
				t.Fatal(err)
			}
			*view(s, saved) = "changed outside the store"
			got, found, err := s.Get(ctx, "tenant", "app")
			if err != nil || !found || got.UpdatedAt == nil || *got.UpdatedAt != now.Format(time.RFC3339) {
				t.Fatalf("returned timestamp changed stored state: %+v, found=%v, err=%v", got, found, err)
			}
		})
	}
}

func TestCatalogAuthoritySnapshotDoesNotRetainTimestampPointer(t *testing.T) {
	s := NewStore()
	updated := "2026-10-23T00:00:00Z"
	want := updated
	snapshot := map[string]map[string]Entry{
		"tenant": {"app": {TenantID: "tenant", ApplicationID: "app", Status: "active", UpdatedAt: &updated}},
	}
	if err := s.ReplaceFromAuthority(snapshot); err != nil {
		t.Fatal(err)
	}
	updated = "changed after authority import"
	got, found, err := s.Get(context.Background(), "tenant", "app")
	if err != nil || !found || got.UpdatedAt == nil || *got.UpdatedAt != want {
		t.Fatalf("authority input changed stored state: %+v, found=%v, err=%v", got, found, err)
	}
}
