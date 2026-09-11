package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE FLEET'S DISTRIBUTION WENT BACKWARDS AND EMPTIED THE LAB (2026-08-20, measured).
//
// Two Edges share one trust store on purpose — one fleet, one distribution, one serial. Each read it at
// start-up, kept its own copy, and wrote the whole thing whenever it changed something. Last writer wins. So a
// node that had not yet noticed a promotion persisted its older announcement over the newer one: serial 127,
// naming the authority every device had adopted, became serial 126 naming the one the control plane had just
// retired.
//
// Nothing was visibly wrong until the next restart. Then both Edges read that file, found it announcing an
// authority neither of them holds, and refused to join — correctly, and the fleet was empty. Restoring it
// meant hand-repairing the file.
func TestTheSharedTrustStoreRefusesToGoBackwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport_trust.json")

	// Another Edge has already distributed serial 127.
	ahead, _ := json.Marshal(transportTrustStoreState{
		SchemaVersion: "transport_trust_store.v1", Serial: 127, AnchorsPEM: "newer",
		AnnouncedInterception: "tenant=the-authority-every-device-adopted",
	})
	if err := os.WriteFile(path, ahead, 0o600); err != nil {
		t.Fatal(err)
	}

	// This node still holds 126 and tries to persist its own view.
	behind := &transportTrustStore{path: path, serial: 126, pems: "older",
		announced: "tenant=the-authority-that-was-just-retired"}
	err := behind.persistLocked()
	if err == nil {
		t.Fatal("a node holding an older distribution wrote it over a newer one — the file then announces an " +
			"authority no device holds, and every Edge refuses to join after the next restart")
	}
	if !strings.Contains(err.Error(), "backwards") {
		t.Fatalf("the refusal does not say what it prevented: %v", err)
	}

	// The file is untouched: a refused write must not leave a half-written store either.
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var after transportTrustStoreState
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if after.Serial != 127 || after.AnchorsPEM != "newer" {
		t.Fatalf("the newer distribution was damaged by a refused write: %+v", after)
	}

	// Forwards is the ordinary case and must still work.
	forward := &transportTrustStore{path: path, serial: 128, pems: "newest", announced: "tenant=next"}
	if err := forward.persistLocked(); err != nil {
		t.Fatalf("a node advancing the distribution could not persist it: %v", err)
	}
}
