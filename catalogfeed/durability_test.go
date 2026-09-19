package catalogfeed

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

func durableFeedFixture(t *testing.T) (*Store, string, []byte, []byte, time.Time) {
	t.Helper()
	priv, id, keys := newTrust(t)
	now := time.Now().UTC()
	s := NewStore(keys)
	path := filepath.Join(t.TempDir(), "feed.json")
	if e := s.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	one := signFeed(t, priv, id, 101, entries("one"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	two := signFeed(t, priv, id, 102, entries("two"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	if _, e := s.Apply(one, now); e != nil {
		t.Fatal(e)
	}
	return s, path, one, two, now
}

func TestFeedRejectedSaveDoesNotPublish(t *testing.T) {
	for _, op := range []string{"apply", "rollback"} {
		t.Run(op, func(t *testing.T) {
			s, path, _, two, now := durableFeedFixture(t)
			if op == "rollback" {
				if _, e := s.Apply(two, now); e != nil {
					t.Fatal(e)
				}
			}
			old := s.Status(now)
			saved, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			mutate := func() (AppliedFeed, error) {
				if op == "apply" {
					return s.Apply(two, now)
				}
				return s.Rollback(101, now)
			}
			if e := os.Rename(path, path+".saved"); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			result, e := mutate()
			if !errors.Is(e, ErrPersistence) || result.CatalogVersion != 0 {
				t.Fatal("unconfirmed feed returned", result, e)
			}
			if !sameFeedStatus(s.Status(now), old) {
				t.Fatal("failed write changed live feed/history")
			}
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(path+".saved", path); e != nil {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(saved, after) {
				t.Fatal("rejected replacement changed file")
			}
			reopened := NewStore(s.trustedKeys)
			if e := reopened.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if !sameFeedStatus(reopened.Status(now), old) {
				t.Fatal("restart retained failed change")
			}
			if _, e := mutate(); e != nil {
				t.Fatal("retry", e)
			}
			reopened = NewStore(s.trustedKeys)
			if e := reopened.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if !sameFeedStatus(reopened.Status(now), s.Status(now)) {
				t.Fatal("successful retry lost on restart")
			}
			matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".feed.json.tmp*"))
			if len(matches) != 0 {
				t.Fatal("staging files leaked", matches)
			}
		})
	}
}

func TestFeedReadersKeepConfirmedStateDuringSave(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			s, _, _, two, now := durableFeedFixture(t)
			old := s.Status(now)
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			s.writeFile = func(path string, b []byte, mode os.FileMode) error {
				close(entered)
				<-release
				if fail {
					return errors.New("refused")
				}
				return durablefile.Write(path, b, mode)
			}
			go func() { _, e := s.Apply(two, now); done <- e }()
			<-entered
			read := make(chan Status, 1)
			go func() { read <- s.Status(now) }()
			select {
			case st := <-read:
				if !sameFeedStatus(st, old) {
					t.Error("unconfirmed state visible")
				}
			case <-time.After(time.Second):
				t.Error("read blocked on persistence")
			}
			close(release)
			e := <-done
			if (e != nil) != fail {
				t.Fatal(e)
			}
			want := 102
			if fail {
				want = 101
			}
			if s.EffectiveCatalog().Version != want {
				t.Fatal("commit outcome")
			}
		})
	}
}

func TestFeedUncertainCommitMustRetryBeforeChangingPath(t *testing.T) {
	for _, op := range []string{"apply", "rollback"} {
		t.Run(op, func(t *testing.T) {
			s, path, _, two, now := durableFeedFixture(t)
			if op == "rollback" {
				if _, e := s.Apply(two, now); e != nil {
					t.Fatal(e)
				}
			}
			old := s.Status(now)
			s.writeFile = func(path string, b []byte, mode os.FileMode) error {
				if e := durablefile.Write(path, b, mode); e != nil {
					return e
				}
				return durablefile.ErrReplacedNotFlushed
			}
			mutate := func() error {
				if op == "apply" {
					_, e := s.Apply(two, now)
					return e
				}
				_, e := s.Rollback(101, now)
				return e
			}
			if e := mutate(); !errors.Is(e, ErrPersistence) || !errors.Is(e, durablefile.ErrReplacedNotFlushed) {
				t.Fatal(e)
			}
			if !sameFeedStatus(s.Status(now), old) {
				t.Fatal("uncertain state published")
			}
			// Storage really changed: the test does not mistake an uncertain commit for rollback.
			saved := NewStore(s.trustedKeys)
			if e := saved.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if saved.Status(now).CatalogVersion == old.CatalogVersion {
				t.Fatal("fixture did not write before error")
			}
			for _, path := range []string{"", filepath.Join(t.TempDir(), "new.json")} {
				if e := s.SetStatePath(path); !errors.Is(e, ErrPersistence) {
					t.Fatal("dirty path replaced", e)
				}
			}
			s.writeFile = durablefile.Write
			if e := mutate(); e != nil {
				t.Fatal("retry", e)
			}
			if e := s.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if s.Status(now).CatalogVersion == old.CatalogVersion {
				t.Fatal("confirmed retry lost")
			}
		})
	}
}

func TestFeedOutputsAndTrustedKeysAreIsolated(t *testing.T) {
	priv, key, keys := newTrust(t)
	s := NewStore(keys)
	keys[key][0] ^= 0xff
	delete(keys, key)
	now := time.Now().UTC()
	raw := signFeed(t, priv, key, 101, entries("one"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	var env signedconfig.Envelope
	if e := json.Unmarshal(raw, &env); e != nil {
		t.Fatal(e)
	}
	env.Metadata = map[string]any{"nested": []any{map[string]any{"value": "original"}}}
	env, e := signedconfig.Sign(env, priv)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	applied, e := s.Apply(raw, now)
	if e != nil {
		t.Fatal("constructor trusted keys were aliased", e)
	}
	before := s.Status(now)
	damage := func(af *AppliedFeed) {
		af.Entries[0].ID = "changed"
		af.Entries[0].Patterns[0] = "*"
		af.Envelope.Payload[0] = '!'
		af.Envelope.Metadata["nested"].([]any)[0].(map[string]any)["value"] = "changed"
	}
	damage(&applied)
	status := s.Status(now)
	damage(status.Current)
	damage(&status.History[0])
	catalog := s.EffectiveCatalog()
	catalog.Entries[0].Patterns[0] = "*"
	if !sameFeedStatus(s.Status(now), before) {
		t.Fatal("returned state aliases live feed")
	}
	rolled, e := s.Rollback(101, now)
	if e != nil {
		t.Fatal(e)
	}
	before = s.Status(now)
	damage(&rolled)
	if !sameFeedStatus(s.Status(now), before) {
		t.Fatal("rollback output aliases live state")
	}
	builtin := NewStore(nil)
	cat := builtin.EffectiveCatalog()
	original := cat.Entries[0].Patterns[0]
	cat.Entries[0].Patterns[0] = "*"
	if builtin.EffectiveCatalog().Entries[0].Patterns[0] != original {
		t.Fatal("builtin output mutates global catalog")
	}
}

type pendingOverridePersister struct{ entered, release chan struct{} }

func (p pendingOverridePersister) Load() ([]byte, error) { return nil, nil }
func (p pendingOverridePersister) Save([]byte) error     { close(p.entered); <-p.release; return nil }
func TestFeedOverrideUsesCurrentCatalogAndSerializesChanges(t *testing.T) {
	s, _, _, two, now := durableFeedFixture(t)
	o := knownbypass.NewOverrideStore()
	p := pendingOverridePersister{make(chan struct{}), make(chan struct{})}
	if e := o.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := s.SetOverride(o, "own", knownbypass.Override{EntryID: "one", Mode: knownbypass.OverrideDisabled}, now)
		done <- e
	}()
	<-p.entered
	apply := make(chan error, 1)
	go func() { _, e := s.Apply(two, now); apply <- e }()
	select {
	case e := <-apply:
		t.Error("catalog advanced before pending override completed", e)
	case <-time.After(30 * time.Millisecond):
	}
	read := make(chan knownbypass.CatalogDocument, 1)
	go func() { read <- s.EffectiveCatalog() }()
	select {
	case cat := <-read:
		if cat.Version != 101 {
			t.Error("unexpected catalog")
		}
	case <-time.After(time.Second):
		t.Error("reader blocked on override storage")
	}
	close(p.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-apply:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("catalog change blocked")
	}
	for _, id := range []string{"one", "apple_time", "unknown"} {
		if _, e := s.SetOverride(o, "own", knownbypass.Override{EntryID: id, Mode: knownbypass.OverrideDisabled}, now); e == nil {
			t.Fatal("entry outside effective feed accepted", id)
		}
	}
	if len(o.List("own")) != 1 || len(o.List("other")) != 0 {
		t.Fatal("override scope")
	}
}

func TestFeedFailedLoadKeepsStateAndWriter(t *testing.T) {
	for _, kind := range []string{"read", "decode"} {
		t.Run(kind, func(t *testing.T) {
			s, path, _, two, now := durableFeedFixture(t)
			old := s.Status(now)
			bad := filepath.Join(t.TempDir(), "bad.json")
			if kind == "read" {
				if e := os.Mkdir(bad, 0700); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := os.WriteFile(bad, []byte(`{broken`), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := s.SetStatePath(bad); e == nil {
				t.Fatal("bad load accepted")
			}
			if !sameFeedStatus(s.Status(now), old) {
				t.Fatal("failed load changed live")
			}
			if _, e := s.Apply(two, now); e != nil {
				t.Fatal("failed load replaced writer", e)
			}
			reopened := NewStore(s.trustedKeys)
			if e := reopened.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if reopened.Status(now).CatalogVersion != 102 {
				t.Fatal("original path not updated")
			}
		})
	}
}

// RawMessage indentation can change when the containing snapshot is written.
func sameFeedStatus(a, b Status) bool {
	left, le := json.Marshal(a)
	right, re := json.Marshal(b)
	return le == nil && re == nil && bytes.Equal(left, right)
}
