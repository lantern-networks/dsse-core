package main

import (
	"net/http"
	"testing"
	"time"
)

func TestRuntimeTenantReassignmentDoesNotCarryPreviousTenantState(t *testing.T) {
	for _, via := range []string{"connect", "report", "version", "flow"} {
		t.Run(via, func(t *testing.T) {
			s := newEndpointRuntimeStore()
			now := time.Now().UTC()
			h := http.Header{}
			h.Set(deviceHeaderOS, "private-os")
			h.Set(postureHeaderEncryption, "on")
			h.Set(postureHeaderFirewall, "on")
			s.ingestFromConnect("shared-device", "Acme", h, "192.0.2.33", now)
			s.ingestAgentVersion("shared-device", "Acme", "private-version", now)
			s.recordSteeredFlow("shared-device", "Acme", "private-user", now)
			s.m["shared-device"].edge = "private-edge"
			switch via {
			case "connect":
				s.ingestFromConnect("shared-device", "acme", http.Header{}, "", now.Add(time.Second))
			case "report":
				s.ingestFromReport("shared-device", "acme", "", nil, nil, "", "", now.Add(time.Second))
			case "version":
				s.ingestAgentVersion("shared-device", "acme", "new-version", now.Add(time.Second))
			case "flow":
				s.recordSteeredFlow("shared-device", "acme", "", now.Add(time.Second))
			}
			got := s.snapshot(now.Add(time.Second))["shared-device"]
			if got.OS != "" || got.SourceIP != "" || got.Edge != "" || len(got.LoggedInUsers) != 0 || got.Posture.DiskEncryptionEnabled != nil || got.Posture.FirewallEnabled != nil {
				t.Fatalf("previous tenant state survived via %s: %+v", via, got)
			}
			if (via == "report" || via == "version") && (got.SteerActive || got.LastSteered != "") {
				t.Fatal("new tenant inherited old steering activity")
			}
		})
	}
}
