package catalogfeed

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/signedconfig"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetiredFeedHistoryKeyDoesNotPreventStartup(t *testing.T) {
	oldPrivate, oldID, trust := newTrust(t)
	newPrivate, _, newTrustSet := newTrust(t)
	newID := oldID + "-rotated"
	for _, key := range newTrustSet {
		trust[newID] = key
	}
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "feed.json")
	s := NewStore(trust)
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(signFeed(t, oldPrivate, oldID, 101, entries("old"), now.Format(time.RFC3339), ""), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(signFeed(t, newPrivate, newID, 102, entries("new"), now.Format(time.RFC3339), ""), now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	reopened := NewStore(map[string]ed25519.PublicKey{newID: trust[newID]})
	if err := reopened.SetStatePath(path); err != nil {
		t.Fatalf("retired history signer prevented startup: %v", err)
	}
	if reopened.Status(now).CatalogVersion != 102 {
		t.Fatal("current trusted feed lost")
	}
	if _, err := reopened.Rollback(101, now); err == nil {
		t.Fatal("retired signer restored by rollback")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("loading changed original evidence")
	}
}

func TestLegacySignedFeedPayloadStillLoads(t *testing.T) {
	priv, key, trust := newTrust(t)
	now := time.Now().UTC()
	raw := signFeed(t, priv, key, 101, entries("legacy"), now.Format(time.RFC3339), "")
	var env signedconfig.Envelope
	json.Unmarshal(raw, &env)
	var payload map[string]any
	json.Unmarshal(env.Payload, &payload)
	payload["future_metadata"] = true
	values := payload["entries"].([]any)
	payload["entries"] = append(values, values[0])
	env.Payload, _ = json.Marshal(payload)
	env.Checksum, _ = signedconfig.PayloadChecksum(env.Payload)
	env, _ = signedconfig.Sign(env, priv)
	af := AppliedFeed{CatalogVersion: 101, Entries: append(entries("legacy"), entries("legacy")...), EnvelopeVersion: env.Version, SigningKeyID: env.SigningKeyID, CreatedAt: env.CreatedAt, ExpiresAt: env.ExpiresAt, AppliedAt: now.Format(time.RFC3339), Envelope: env}
	saved, _ := json.Marshal(snapshot{Current: &af, History: []AppliedFeed{af}})
	path := filepath.Join(t.TempDir(), "feed.json")
	os.WriteFile(path, saved, 0600)
	s := NewStore(trust)
	if err := s.SetStatePath(path); err != nil {
		t.Fatalf("valid legacy signed payload: %v", err)
	}
	if len(s.EffectiveCatalog().Entries) != 2 {
		t.Fatal("legacy signed entries changed")
	}
	raw, _ = json.Marshal(env)
	if _, err := NewStore(trust).Apply(raw, now); err == nil {
		t.Fatal("strict new input validation weakened")
	}
}
