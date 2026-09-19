package inspectionposture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
)

type faultPosturePersistence struct {
	data      []byte
	fail      atomic.Bool
	writes    int
	loadError error
}

func (p *faultPosturePersistence) Load() ([]byte, error) { return p.data, p.loadError }
func (p *faultPosturePersistence) Save(b []byte) error {
	p.writes++
	if p.fail.Load() {
		return fmt.Errorf("private storage failure")
	}
	p.data = append([]byte(nil), b...)
	return nil
}
func TestPostureFailedSavePreservesLiveGenerationAndRetry(t *testing.T) {
	s := NewStore()
	p := &faultPosturePersistence{}
	s.SetPersister(p)
	initial := Posture{Mode: ModeDecryptAll, KnownBypassEnabled: true, DecryptAllowlistHosts: []string{"wiki.example.invalid"}}
	s.Set(initial)
	before := s.Get()
	rev := s.ConfigGeneration()
	disk := string(p.data)
	candidate := before
	candidate.Mode = ModeBypassDefault
	p.fail.Store(true)
	if _, err := s.Set(candidate); !errors.Is(err, ErrPersistence) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, s.Get()) || s.ConfigGeneration() != rev || string(p.data) != disk {
		t.Fatal("failed save changed enforcement")
	}
	p.fail.Store(false)
	if _, err := s.Set(candidate); err != nil {
		t.Fatal(err)
	}
	restarted := NewStore()
	if ok, err := restarted.SetPersister(p); !ok || err != nil || !reflect.DeepEqual(restarted.Get(), s.Get()) {
		t.Fatal("retry not persisted", err)
	}
	rev = s.ConfigGeneration()
	if _, err := s.Set(s.Get()); err != nil || s.ConfigGeneration() != rev {
		t.Fatal("unchanged retry moved generation")
	}
}
func TestPostureSnapshotsDoNotAliasEnforcement(t *testing.T) {
	s := NewStore()
	p := Posture{Mode: ModeBypassDefault, DecryptAllowlistHosts: []string{"one.invalid"}, DecryptAllowlistGroups: []string{"m365_auth"}, BypassGroups: []string{"m365_optimize"}}
	returned, err := s.Set(p)
	if err != nil {
		t.Fatal(err)
	}
	p.DecryptAllowlistHosts[0] = "mutated.invalid"
	returned.BypassGroups[0] = "other"
	snapshot := s.Get()
	snapshot.DecryptAllowlistGroups[0] = "openai"
	want := s.Get()
	if want.DecryptAllowlistHosts[0] != "one.invalid" || want.DecryptAllowlistGroups[0] != "m365_auth" || want.BypassGroups[0] != "m365_optimize" {
		t.Fatal("snapshot alias modified enforcement")
	}
}
func TestPostureBadLoadPreservesStateAndOriginalWriter(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", `{"mode":"bogus","known_bypass_enabled":true}`, `{"mode":"decrypt_all","known_bypass_enabled":null}`, `{"mode":"decrypt_all","known_bypass_enabled":false,"decrypt_allowlist_groups":["missing"]}`, `{"mode":"bypass_default","known_bypass_enabled":true,"decrypt_allowlist_hosts":["https://wiki.invalid/a"]}`} {
		t.Run(fmt.Sprintf("length-%d", len(raw)), func(t *testing.T) {
			s := NewStore()
			original := &faultPosturePersistence{}
			s.SetPersister(original)
			s.Set(DefaultPosture())
			before := s.Get()
			rev := s.ConfigGeneration()
			bad := &faultPosturePersistence{data: []byte(raw)}
			if _, err := s.SetPersister(bad); err == nil {
				t.Fatal("bad snapshot accepted")
			}
			path := filepath.Join(t.TempDir(), "bad.json")
			os.WriteFile(path, []byte(raw), 0600)
			if _, err := s.SetStatePath(path); err == nil {
				t.Fatal("bad file accepted")
			}
			if !reflect.DeepEqual(before, s.Get()) || rev != s.ConfigGeneration() {
				t.Fatal("bad load changed live")
			}
			writes := original.writes
			s.Set(DefaultPosture())
			if original.writes != writes+1 || bad.writes != 0 {
				t.Fatal("failed load replaced writer")
			}
		})
	}
}
func TestPostureValidationDoesNotSilentlyDropChoices(t *testing.T) {
	for _, candidate := range []Posture{{Mode: ""}, {Mode: ModeBypassDefault, DecryptAllowlistHosts: []string{"2001:db8::1"}}, {Mode: ModeBypassDefault, DecryptAllowlistHosts: []string{"::ffff:192.0.2.1"}}, {Mode: ModeDecryptAll, DecryptAllowlistGroups: []string{"unknown"}}, {Mode: ModeDecryptAll, BypassGroups: []string{"openai"}}, {Mode: ModeBypassDefault, DecryptAllowlistHosts: []string{"host:443"}}, {Mode: ModeBypassDefault, DecryptAllowlistHosts: []string{"a..b"}}} {
		s := NewStore()
		if _, err := s.Set(candidate); err == nil || s.ConfigGeneration() != 0 {
			t.Fatal("invalid input adopted")
		}
	}
	if _, err := Validate(Posture{Mode: ModeBypassDefault, DecryptAllowlistHosts: []string{"*.example.com", "localhost", "127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPostureFileSaveFailureKeepsPreviousSnapshot(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "posture.json")
	s := NewStore()
	if _, err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(DefaultPosture()); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	generation := s.ConfigGeneration()
	if err := os.Rename(parent, parent+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	next := before
	next.Mode = ModeBypassDefault
	if _, err := s.Set(next); !errors.Is(err, ErrPersistence) {
		t.Fatal("failed file save was acknowledged", err)
	}
	saved, err := os.ReadFile(filepath.Join(parent+"-unavailable", "posture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != string(original) || !reflect.DeepEqual(s.Get(), before) || s.ConfigGeneration() != generation {
		t.Fatal("file failure changed committed posture")
	}
	if err := os.Rename(parent+"-unavailable", parent); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(next); err != nil {
		t.Fatal(err)
	}
	restart := NewStore()
	if loaded, err := restart.SetStatePath(path); err != nil || !loaded || !reflect.DeepEqual(restart.Get(), s.Get()) {
		t.Fatal("file retry not restored", err)
	}
}
