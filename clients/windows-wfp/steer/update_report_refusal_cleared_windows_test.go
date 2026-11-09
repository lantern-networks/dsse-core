//go:build windows

package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// A cleared refusal goes out as "installed", which the Edge's schema accepts, and says why in the metadata.
func TestAClearedRefusalGoesOutAsInstalledAndSaysSo(t *testing.T) {
	body := agentUpdateEventBody(heartbeatConfig{deviceID: "dev-1", tenantID: "tenant-a"},
		agentupdate.Report{ID: "aue_1", Status: agentupdate.ReportInstalled, RefusalCleared: true, RunningVersion: "0.4.1"})
	if body["update_status"] != "installed" {
		t.Fatalf("update_status = %v", body["update_status"])
	}
	meta, _ := body["metadata"].(map[string]any)
	if meta["refusal_cleared"] != true || meta["refused"] != nil {
		t.Fatalf("metadata = %v", meta)
	}
}
