package appcatalog

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRejectedApplicationWritesKeepConfirmedState(t *testing.T) {
	for _, operation := range []string{"create", "edit", "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "apps.json")
			s := NewStore()
			if err := s.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			old := Entry{ApplicationID: "wiki", Name: "Original", Published: true, Destination: "wiki.example.test", DestinationPort: 443, PublishProtocol: "web"}
			if _, err := s.Upsert(ctx, old, "tenant-a", time.Now()); err != nil {
				t.Fatal(err)
			}
			before, err := s.ExportSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path+".tmp", 0700); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "create":
				_, err = s.Upsert(ctx, Entry{ApplicationID: "new", Name: "New"}, "tenant-a", time.Now())
			case "edit":
				old.Name = "Changed"
				_, err = s.Upsert(ctx, old, "tenant-a", time.Now())
			case "delete":
				err = s.Delete(ctx, "tenant-a", "wiki")
			}
			if err == nil {
				t.Fatal("write unexpectedly succeeded")
			}
			after, err := s.ExportSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("failed %s changed live catalog", operation)
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != string(saved) {
				t.Fatal("failed write changed saved catalog")
			}
			if err := os.Remove(path + ".tmp"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Upsert(ctx, Entry{ApplicationID: "unrelated"}, "tenant-b", time.Now()); err != nil {
				t.Fatal(err)
			}
			fresh := NewStore()
			if err := fresh.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			snapshot, err := fresh.ExportSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before["tenant-a"], snapshot["tenant-a"]) {
				t.Fatal("later unrelated save persisted a rejected mutation")
			}
		})
	}
}
