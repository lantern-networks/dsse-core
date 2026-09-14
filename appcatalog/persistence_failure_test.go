package appcatalog

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestFailedMutationPreservesCommittedCatalog(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "apps.json")
			store := NewStore()
			if err := store.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			saved, err := store.Upsert(ctx, Entry{ApplicationID: "existing", Name: "Saved", ApplicationType: "private_app"}, "tenant", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			disk, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+".backup"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "create":
				_, err = store.Upsert(ctx, Entry{ApplicationID: "new", Name: "Unsaved", ApplicationType: "saas"}, "tenant", time.Now())
			case "update":
				changed := saved
				changed.Name = "Unsaved"
				_, err = store.Upsert(ctx, changed, "tenant", time.Now())
			case "delete":
				err = store.Delete(ctx, "tenant", "existing")
			}
			if err == nil {
				t.Fatal("write unexpectedly succeeded")
			}
			current, found, err := store.Get(ctx, "tenant", "existing")
			if err != nil || !found || !reflect.DeepEqual(current, saved) {
				t.Fatalf("committed entry changed: %#v %v", current, err)
			}
			if _, found, _ := store.Get(ctx, "tenant", "new"); found {
				t.Fatal("failed create became live")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".backup", path); err != nil {
				t.Fatal(err)
			}
			restored, _ := os.ReadFile(path)
			if string(restored) != string(disk) {
				t.Fatal("committed bytes changed")
			}
			// A later successful snapshot must not carry the failed mutation to disk.
			if _, err := store.Upsert(ctx, Entry{ApplicationID: "later", ApplicationType: "private_app"}, "tenant", time.Now()); err != nil {
				t.Fatal(err)
			}
			reloaded := NewStore()
			if err := reloaded.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			current, found, err = reloaded.Get(ctx, "tenant", "existing")
			if err != nil || !found || !reflect.DeepEqual(current, saved) {
				t.Fatal("failed mutation leaked through later save")
			}
			if _, found, _ := reloaded.Get(ctx, "tenant", "new"); found {
				t.Fatal("failed create survived restart")
			}
		})
	}
}
