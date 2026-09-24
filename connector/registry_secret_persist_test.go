package connector

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSecretSaveFailureDoesNotPublishOrAlias(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-write", true: "after-write"}[uncertain], func(t *testing.T) {
			p := &managementPersister{}
			r := NewRegistry()
			if err := r.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if _, err := r.Register(testRegistration("target"), now); err != nil {
				t.Fatal(err)
			}
			oldHash := "sha256:" + strings.Repeat("a", 64)
			newHash := "sha256:" + strings.Repeat("b", 64)
			if _, _, err := r.RotateRuntimeSecretHashForTenantWithMetadata("tenant_a", "target", oldHash, now, "old-actor"); err != nil {
				t.Fatal(err)
			}
			before, _ := r.Get("target")
			generation := r.ConfigGeneration()
			disk := append([]byte(nil), p.data...)
			p.fail = true
			p.writeBeforeError = uncertain
			returned, found, err := r.RotateRuntimeSecretHashForTenantWithMetadata("tenant_a", "target", newHash, now.Add(time.Minute), "new-actor")
			if !errors.Is(err, ErrRegistryPersistence) || !found || returned.ID != "" {
				t.Fatal("unconfirmed rotation was accepted or returned candidate")
			}
			after, _ := r.Get("target")
			if !reflect.DeepEqual(before, after) || r.ConfigGeneration() != generation {
				t.Fatal("failed rotation changed resident metadata")
			}
			if !uncertain && !bytes.Equal(disk, p.data) {
				t.Fatal("pre-write error changed storage")
			}
			p.fail = false
			if _, err := r.Register(testRegistration("unrelated"), now); err != nil {
				t.Fatal(err)
			}
			restored := NewRegistry()
			if err := restored.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			got, _ := restored.Get("target")
			if !reflect.DeepEqual(got, before) {
				t.Fatal("unrelated save persisted rejected secret")
			}
			if _, ok, err := r.RotateRuntimeSecretHashForTenantWithMetadata("foreign", "target", newHash, now, "intruder"); err != nil || ok {
				t.Fatal("foreign rotation accepted")
			}
			if _, _, err := r.RotateRuntimeSecretHashForTenantWithMetadata("tenant_a", "target", newHash, now.Add(time.Minute), "new-actor"); err != nil {
				t.Fatal(err)
			}
			if before.Metadata[runtimeSecretHashMetadataKey] != oldHash {
				t.Fatal("successful rotation mutated an earlier snapshot")
			}
			restored = NewRegistry()
			if err := restored.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			got, _ = restored.Get("target")
			if got.Metadata[runtimeSecretHashMetadataKey] != newHash || got.Metadata[runtimeSecretRotatedByKey] != "new-actor" || r.ConfigGeneration() != generation+1 {
				t.Fatal("rotation retry not persisted or changed route generation")
			}
		})
	}
}
