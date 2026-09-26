package inspectionposture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLegacyHostPatternsSurviveUpgrade(t *testing.T) {
	for _, host := range []string{"wiki.corp:8443", "https://wiki.corp/", "my_host.corp", "例え.jp", "::1", "*foo.com"} {
		t.Run(host, func(t *testing.T) {
			p := Posture{Mode: ModeBypassDefault, KnownBypassEnabled: true, DecryptAllowlistHosts: []string{host}}
			raw, _ := json.Marshal(p)
			path := filepath.Join(t.TempDir(), "posture.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			s := NewStore()
			if loaded, err := s.SetStatePath(path); err != nil || !loaded {
				t.Fatalf("legacy startup: %v", err)
			}
			if !reflect.DeepEqual(s.Get(), p.Normalized()) {
				t.Fatal("legacy inspection intent dropped")
			}
			if _, err := s.SetReceived(p); err != nil {
				t.Fatalf("signed legacy delivery: %v", err)
			}
			if _, err := s.Set(p); err == nil {
				t.Fatal("new invalid management input accepted")
			}
		})
	}
}

func TestLegacyHostAllowsUnrelatedModeEdit(t *testing.T) {
	s := NewStore()
	p := DefaultPosture()
	p.DecryptAllowlistHosts = []string{"legacy_host"}
	if _, err := s.SetReceived(p); err != nil {
		t.Fatal(err)
	}
	next := s.Get()
	next.Mode = ModeBypassDefault
	if _, _, err := s.UpdateContext(context.Background(), func(Posture) (Posture, error) { return next, nil }); err != nil {
		t.Fatal(err)
	}
	if s.Get().DecryptAllowlistHosts[0] != "legacy_host" {
		t.Fatal("legacy host was lost")
	}
	next.DecryptAllowlistHosts = append(next.DecryptAllowlistHosts, "new_invalid")
	if _, err := s.Set(next); err == nil {
		t.Fatal("new invalid host accepted")
	}
}
