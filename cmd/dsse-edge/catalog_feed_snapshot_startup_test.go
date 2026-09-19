package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/catalogfeed"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

func TestCatalogFeedSnapshotProductionStartup(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	key := "ed25519-public:startup"
	now := time.Now().UTC()
	payload, _ := json.Marshal(knownbypass.CatalogDocument{Version: 101, Entries: []knownbypass.Group{{ID: "trusted_entry", Name: "Trusted", Patterns: []string{"old.feed.example"}}}})
	checksum, _ := signedconfig.PayloadChecksum(payload)
	env, e := signedconfig.Sign(signedconfig.Envelope{Type: catalogfeed.FeedType, Version: "version-101", Payload: payload, Checksum: checksum, SigningKeyID: key, Status: "active", CreatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)}, priv)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(env)
	seed := t.TempDir()
	feedPath := filepath.Join(seed, "feed.json")
	store := catalogfeed.NewStore(map[string]ed25519.PublicKey{key: pub})
	store.SetStatePath(feedPath)
	if _, e := store.Apply(raw, now.Add(-90*time.Minute)); e != nil {
		t.Fatal(e)
	}
	valid, e := os.ReadFile(feedPath)
	if e != nil {
		t.Fatal(e)
	}
	prepare := func(data []byte, keys bool) (string, string) {
		t.Helper()
		dir := t.TempDir()
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "feed.json")
		os.WriteFile(path, data, 0600)
		k := map[string]string{}
		if keys {
			k[key] = base64.StdEncoding.EncodeToString(pub)
		}
		b, _ := json.Marshal(k)
		os.WriteFile(filepath.Join(dir, "keys.json"), b, 0600)
		return dir, path
	}
	argsFor := func(dir, path string) []string {
		return []string{"-predefined-catalog-feed-store", path, "-predefined-catalog-feed-trusted-keys-file", filepath.Join(dir, "keys.json")}
	}
	for _, data := range [][]byte{valid, []byte(`{}`)} {
		dir, path := prepare(data, true)
		base, stop := startCertPinMain(t, dir, false, argsFor(dir, path)...)
		var st catalogfeed.Status
		certPinStartupGet(t, base, "/admin/predefined-catalog/feed", &st)
		if bytes.Equal(data, valid) {
			if st.Source != "feed" || st.CatalogVersion != 101 || !st.Stale {
				t.Fatal("trusted stale feed not restored", st)
			}
			var decision effectivePolicyResponse
			certPinStartupGet(t, base, "/admin/effective-policy?destination=old.feed.example", &decision)
			if decision.Inspection.Decision != "bypass" {
				t.Fatal("trusted feed not applied at startup", decision.Inspection)
			}
		} else if st.Source != "builtin" {
			t.Fatal("empty feed did not retain builtin")
		}
		stop()
		after, _ := os.ReadFile(path)
		if !bytes.Equal(data, after) {
			t.Fatal("startup rewrote snapshot")
		}
	}
	cases := []struct {
		name string
		data []byte
		keys bool
	}{{"empty-file", nil, true}, {"null", []byte(`null`), true}, {"removed-trust", valid, false}, {"duplicate", []byte(`{"current":null,"current":null}`), true}}
	for _, field := range []string{"entries", "signature", "history", "unknown"} {
		var x map[string]any
		json.Unmarshal(valid, &x)
		cur := x["current"].(map[string]any)
		switch field {
		case "entries":
			cur["entries"].([]any)[0].(map[string]any)["patterns"] = []any{"PRIVATE_SNAPSHOT_VALUE"}
		case "signature":
			cur["envelope"].(map[string]any)["signature"] = "PRIVATE_SNAPSHOT_VALUE"
		case "history":
			x["history"].([]any)[0].(map[string]any)["signing_key_id"] = "PRIVATE_SNAPSHOT_VALUE"
		case "unknown":
			x["future"] = "PRIVATE_SNAPSHOT_VALUE"
		}
		b, _ := json.Marshal(x)
		cases = append(cases, struct {
			name string
			data []byte
			keys bool
		}{field, b, true})
	}
	module, _ := filepath.Abs("../..")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := prepare(tc.data, tc.keys)
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a"}
			args = append(args, argsFor(dir, path)...)
			b, _ := json.Marshal(args)
			argsPath := filepath.Join(dir, "args.json")
			os.WriteFile(argsPath, b, 0600)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argsPath)
			out, e := cmd.CombinedOutput()
			if e == nil || ctx.Err() != nil || !strings.Contains(string(out), "predefined-catalog feed store: invalid catalog feed snapshot") {
				t.Fatalf("invalid startup: err=%v deadline=%v out=%s", e, ctx.Err(), out)
			}
			if bytes.Contains(out, []byte("PRIVATE_SNAPSHOT_VALUE")) {
				t.Fatal("startup disclosed snapshot contents")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(tc.data, after) {
				t.Fatal("failed startup changed snapshot")
			}
		})
	}
	t.Logf("main: 2 accepted snapshots, %d rejected snapshots", len(cases))
}
