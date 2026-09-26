package catalogfeed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/signedconfig"
)

func TestFeedSnapshotRejectsUnverifiedDerivedState(t *testing.T) {
	type badCase struct {
		name   string
		change func(map[string]any)
		raw    func([]byte) []byte
	}
	cases := []badCase{}
	add := func(name string, f func(map[string]any)) { cases = append(cases, badCase{name: name, change: f}) }
	current := func(x map[string]any) map[string]any { return x["current"].(map[string]any) }
	for _, field := range []string{"catalog_version", "envelope_version", "signing_key_id", "created_at", "expires_at", "applied_at"} {
		field := field
		add("derived-"+field, func(x map[string]any) {
			if field == "catalog_version" {
				current(x)[field] = 999
			} else {
				current(x)[field] = "PRIVATE_SNAPSHOT_VALUE"
			}
		})
	}
	add("entries", func(x map[string]any) { current(x)["entries"].([]any)[0].(map[string]any)["patterns"] = []any{"*"} })
	for _, field := range []string{"signature", "checksum", "signing_key_id", "type", "status", "created_at", "expires_at"} {
		field := field
		add("envelope-"+field, func(x map[string]any) { current(x)["envelope"].(map[string]any)[field] = "PRIVATE_SNAPSHOT_VALUE" })
	}
	add("payload", func(x map[string]any) {
		current(x)["envelope"].(map[string]any)["payload"].(map[string]any)["entries"].([]any)[0].(map[string]any)["patterns"] = []any{"*"}
	})
	add("history-signature", func(x map[string]any) {
		x["history"].([]any)[0].(map[string]any)["envelope"].(map[string]any)["signature"] = "ed25519:bad"
	})
	add("history-current-mismatch", func(x map[string]any) {
		x["history"].([]any)[0].(map[string]any)["applied_at"] = "2020-01-01T00:00:00Z"
	})
	add("history-absent", func(x map[string]any) { delete(x, "history") })
	add("history-without-current", func(x map[string]any) { x["current"] = nil })
	add("history-null-entry", func(x map[string]any) { x["history"] = []any{nil} })
	add("history-limit", func(x map[string]any) {
		for len(x["history"].([]any)) <= historyLimit {
			x["history"] = append(x["history"].([]any), x["current"])
		}
	})
	add("unknown-root", func(x map[string]any) { x["future"] = "PRIVATE_SNAPSHOT_VALUE" })
	add("unknown-current", func(x map[string]any) { current(x)["future"] = "PRIVATE_SNAPSHOT_VALUE" })
	add("unknown-envelope", func(x map[string]any) { current(x)["envelope"].(map[string]any)["future"] = "PRIVATE_SNAPSHOT_VALUE" })
	add("alternate-case", func(x map[string]any) { x["Current"] = x["current"]; delete(x, "current") })
	for _, raw := range []string{"", " ", "null", "[]", "{} {}", "{\"current\":null,\"current\":null}", "{\"history\":[null]}"} {
		raw := raw
		cases = append(cases, badCase{name: "shape-" + raw, raw: func([]byte) []byte { return []byte(raw) }})
	}
	cases = append(cases, badCase{name: "nested-duplicate", raw: func(b []byte) []byte {
		return bytes.Replace(b, []byte(`"catalog_version":101`), []byte(`"catalog_version":101,"catalog_version":101`), 1)
	}})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, path, _, two, now := durableFeedFixture(t)
			old := s.Status(now)
			before, _ := os.ReadFile(path)
			var x map[string]any
			json.Unmarshal(before, &x)
			if tc.change != nil {
				tc.change(x)
			}
			data, _ := json.Marshal(x)
			if tc.raw != nil {
				data = tc.raw(data)
			}
			bad := filepath.Join(t.TempDir(), "bad.json")
			os.WriteFile(bad, data, 0600)
			if e := s.SetStatePath(bad); !errors.Is(e, ErrInvalidSnapshot) || e.Error() != ErrInvalidSnapshot.Error() {
				t.Fatalf("invalid snapshot accepted or content disclosed: %v", e)
			}
			if !sameFeedStatus(s.Status(now), old) || s.statePath != path || s.dirty {
				t.Fatal("refusal changed state, writer or reconciliation state")
			}
			unchanged, _ := os.ReadFile(path)
			if !bytes.Equal(before, unchanged) {
				t.Fatal("refusal changed original")
			}
			if _, e := s.Apply(two, now); e != nil {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(bad)
			if !bytes.Equal(after, data) {
				t.Fatal("refused path became writer")
			}
			reopened := NewStore(s.trustedKeys)
			if e := reopened.SetStatePath(path); e != nil || reopened.Status(now).CatalogVersion != 102 {
				t.Fatal("original writer not preserved", e)
			}
		})
	}
	t.Logf("rejected %d complete snapshots without replacing state or writer", len(cases))
}

func TestFeedSnapshotRestoresTrustedStaleHistory(t *testing.T) {
	priv, key, trust := newTrust(t)
	now := time.Now().UTC()
	s := NewStore(trust)
	path := filepath.Join(t.TempDir(), "feed.json")
	s.SetStatePath(path)
	first := signFeed(t, priv, key, 101, entries("old"), now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339))
	if _, e := s.Apply(first, now.Add(-90*time.Minute)); e != nil {
		t.Fatal(e)
	}
	second := signFeed(t, priv, key, 102, entries("new"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	var env signedconfig.Envelope
	json.Unmarshal(second, &env)
	env.Metadata = map[string]any{"counter": json.Number("900719925474099312345"), "nested": map[string]any{"items": []any{json.Number("1.50"), "ok"}}}
	env, _ = signedconfig.Sign(env, priv)
	second, _ = json.Marshal(env)
	if _, e := s.Apply(second, now); e != nil {
		t.Fatal("signed metadata number changed", e)
	}
	if _, e := s.Rollback(101, now); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(path)
	restored := NewStore(trust)
	if e := restored.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	if !sameFeedStatus(s.Status(now), restored.Status(now)) || !restored.Status(now).Stale {
		t.Fatal("stale trusted history not preserved")
	}
	if _, e := restored.Rollback(102, now); e != nil {
		t.Fatal(e)
	}
	if restored.Status(now).Stale {
		t.Fatal("fresh rollback mislabeled stale")
	}
	if _, e := restored.Rollback(101, now); e != nil {
		t.Fatal(e)
	}
	if _, e := restored.Apply(first, now); e == nil {
		t.Fatal("expired new apply accepted")
	}
	// Removing trust from even a historical signer rejects the complete snapshot.
	for _, keys := range []map[string]ed25519.PublicKey{nil, {key: bytes.Repeat([]byte{1}, ed25519.PublicKeySize)}} {
		untrusted := NewStore(keys)
		if e := untrusted.SetStatePath(path); !errors.Is(e, ErrInvalidSnapshot) {
			t.Fatal("untrusted restore", e)
		}
		if untrusted.Status(now).Source != "builtin" || untrusted.statePath != "" {
			t.Fatal("untrusted data adopted")
		}
	}
	// The original formatted snapshot itself remains loadable, including signed numeric metadata.
	original := filepath.Join(t.TempDir(), "original.json")
	os.WriteFile(original, before, 0600)
	if e := NewStore(trust).SetStatePath(original); e != nil {
		t.Fatal("formatted signed payload was altered", e)
	}
}

func TestFeedAdmissionRejectsUnrestorableDocuments(t *testing.T) {
	priv, key, trust := newTrust(t)
	now := time.Now().UTC()
	valid := signFeed(t, priv, key, 1, entries("entry"), now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	payloads := []string{`null`, `{"version":0,"entries":[{"id":"entry"}]}`, `{"version":1,"entries":[]}`, `{"version":1,"entries":[{"id":"entry"},{"id":"entry"}]}`, `{"version":1,"entries":[{"id":" entry "}]}`, `{"Version":1,"entries":[{"id":"entry"}]}`, `{"version":1,"version":1,"entries":[{"id":"entry"}]}`, `{"version":1,"entries":[{"id":"entry","future":true}]}`, `{"version":1,"entries":[{"id":"entry","id":"entry"}]}`}
	for _, payload := range payloads {
		var env signedconfig.Envelope
		json.Unmarshal(valid, &env)
		env.Payload = json.RawMessage(payload)
		env.Checksum, _ = signedconfig.PayloadChecksum(env.Payload)
		env, _ = signedconfig.Sign(env, priv)
		raw, _ := json.Marshal(env)
		s := NewStore(trust)
		if _, e := s.Apply(raw, now); e == nil {
			t.Fatal("accepted unrestorable payload", payload)
		}
		if s.current != nil || len(s.history) != 0 || s.dirty {
			t.Fatal("rejected payload published")
		}
	}
	for _, alter := range []func([]byte) []byte{func(b []byte) []byte { return bytes.Replace(b, []byte(`"type":`), []byte(`"Type":`), 1) }, func(b []byte) []byte { return append(b, []byte(` {}`)...) }, func(b []byte) []byte {
		return bytes.Replace(b, []byte(`"type":`), []byte(`"type":"ignored","type":`), 1)
	}} {
		if _, e := NewStore(trust).Apply(alter(valid), now); e == nil {
			t.Fatal("ambiguous envelope accepted")
		}
	}
	var env signedconfig.Envelope
	json.Unmarshal(valid, &env)
	env.CreatedAt = "invalid"
	env, _ = signedconfig.Sign(env, priv)
	raw, _ := json.Marshal(env)
	if _, e := NewStore(trust).Apply(raw, now); e == nil {
		t.Fatal("unrestorable timestamp accepted")
	}
	t.Logf("refused %d signed payloads and 4 invalid envelope/timestamp cases", len(payloads))
}

func TestFeedSnapshotEmptyAndMissingContracts(t *testing.T) {
	s, original, _, two, now := durableFeedFixture(t)
	old := s.Status(now)
	missing := filepath.Join(t.TempDir(), "missing.json")
	if e := s.SetStatePath(missing); e != nil || !sameFeedStatus(s.Status(now), old) {
		t.Fatal("missing attach", e)
	}
	if _, e := os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("attach unexpectedly acknowledged a save")
	}
	if _, e := s.Apply(two, now); e != nil {
		t.Fatal(e)
	}
	other := NewStore(s.trustedKeys)
	if e := other.SetStatePath(original); e != nil || other.Status(now).CatalogVersion != 101 {
		t.Fatal("old path changed", e)
	}
	for _, empty := range []string{`{}`, `{"current":null,"history":null}`, `{"current":null,"history":[]}`} {
		p := filepath.Join(t.TempDir(), "empty.json")
		os.WriteFile(p, []byte(empty), 0600)
		if e := s.SetStatePath(p); e != nil || s.Status(now).Source != "builtin" || len(s.Status(now).History) != 0 {
			t.Fatal("explicit empty", e)
		}
	}
}
