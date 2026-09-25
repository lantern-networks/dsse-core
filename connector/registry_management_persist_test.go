package connector

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type managementPersister struct {
	data                   []byte
	fail, writeBeforeError bool
}

func (p *managementPersister) Load() ([]byte, error) { return append([]byte(nil), p.data...), nil }
func (p *managementPersister) Save(data []byte) error {
	if !p.fail || p.writeBeforeError {
		p.data = append([]byte(nil), data...)
	}
	if p.fail {
		return errors.New("private storage detail")
	}
	return nil
}

func TestManagementSaveFailureDoesNotPublishCandidate(t *testing.T) {
	for _, action := range []string{"rename", "clear", "remove"} {
		for _, uncertain := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "-before-write", true: "-after-write"}[uncertain], func(t *testing.T) {
				p := &managementPersister{}
				r := NewRegistry()
				if err := r.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Register(testRegistration("target"), time.Now()); err != nil {
					t.Fatal(err)
				}
				if _, _, err := r.SetDisplayNameForTenant("tenant_a", "target", "Before"); err != nil {
					t.Fatal(err)
				}
				before, _ := r.Get("target")
				generation := r.ConfigGeneration()
				disk := append([]byte(nil), p.data...)
				change := func() error {
					if action == "remove" {
						_, err := r.RemoveForTenant("tenant_a", "target")
						return err
					}
					name := "After"
					if action == "clear" {
						name = ""
					}
					_, _, err := r.SetDisplayNameForTenant("tenant_a", "target", name)
					return err
				}
				p.fail = true
				p.writeBeforeError = uncertain
				if err := change(); err == nil {
					t.Fatal("management accepted a failed save")
				}
				after, found := r.Get("target")
				if !found || !reflect.DeepEqual(before, after) || r.ConfigGeneration() != generation {
					t.Fatal("failed save published the candidate")
				}
				if !uncertain && !bytes.Equal(p.data, disk) {
					t.Fatal("pre-write failure changed bytes")
				}
				// An unrelated successful save must not carry the rejected candidate with it.
				p.fail = false
				if _, err := r.Register(testRegistration("unrelated"), time.Now()); err != nil {
					t.Fatal(err)
				}
				restored := NewRegistry()
				if err := restored.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				got, ok := restored.Get("target")
				if !ok || !reflect.DeepEqual(before, got) {
					t.Fatal("unrelated save carried rejected management state")
				}
				if err := change(); err != nil {
					t.Fatal(err)
				}
				restored = NewRegistry()
				if err := restored.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				got, ok = restored.Get("target")
				if action == "remove" {
					if ok {
						t.Fatal("removed record survived retry")
					}
				} else {
					want := "After"
					if action == "clear" {
						want = ""
					}
					if !ok || DisplayName(got) != want {
						t.Fatal("retry did not persist name")
					}
				}
			})
		}
	}
}

func TestSetDisplayNameDoesNotMutateInputMetadata(t *testing.T) {
	original := model.ConnectorRegistration{Metadata: map[string]any{connectorDisplayNameKey: "Before", "keep": "value"}}
	changed := SetDisplayName(original, "After")
	if DisplayName(original) != "Before" || DisplayName(changed) != "After" {
		t.Fatal("rename mutated the caller's snapshot")
	}
	cleared := SetDisplayName(original, "")
	if DisplayName(original) != "Before" || DisplayName(cleared) != "" || cleared.Metadata["keep"] != "value" {
		t.Fatal("clear mutated the caller's snapshot")
	}
}
