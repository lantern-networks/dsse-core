package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE CONSENSUS STORE KEEPS ITS DATA SOMEWHERE THAT SURVIVES THE CONTAINER (2026-09-03, measured on a
// running three-region deployment: recreating its containers left the cluster with ONE member and the other
// two refusing to start, "member count is unequal").
//
// Every other stateful service in a generated deployment has a named volume. This one had three read-only
// certificates and nothing else, so etcd's data directory lived inside the container — and recreating it,
// which this installer's own printed procedures ask for, destroyed the deployment's consensus state.
func TestTheConsensusStoreHasSomewhereDurableToKeepItsData(t *testing.T) {
	if !strings.Contains(composeConsensusStore, `"store-a-state:/data"`) {
		t.Error("the consensus store mounts no volume for its data directory, so recreating the container " +
			"destroys the deployment's consensus state")
	}
	if !strings.Contains(composeConsensusStore, "ETCD_DATA_DIR: /data") {
		t.Error("etcd is not told to use the volume, so it writes to its default inside the container")
	}
	// ★ AND THE FILE IS RENDERED, not asserted against a copy of the same string. A volume that is mounted
	// and never declared makes compose refuse the whole deployment, so the check has to be against what is
	// actually written.
	dir := t.TempDir()
	if err := composeFileFor(dir, machineShape{holds: regionShapeStateBearing, edges: true}, true); err != nil {
		t.Fatalf("render a state-bearing machine: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	file := string(body)
	if !strings.Contains(file, "store-a-state:/data") {
		t.Fatal("the rendered file does not mount the store's data volume")
	}
	if !strings.Contains(file, "\n  store-a-state:\n") {
		t.Error("store-a-state is mounted but never declared under volumes: — compose refuses a file that " +
			"names a volume it does not define, so this would not start at all")
	}
}
