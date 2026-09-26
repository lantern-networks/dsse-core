package assetcatalog

import (
	"encoding/json"
	"testing"
)

func TestLegacyServiceRemainsEditableWithoutBlockingStartup(t *testing.T) {
	for _, ports := range [][]PortProto{{{Protocol: "tcp", Port: 70000}}, {{Protocol: "sctp", Port: 443}}} {
		t.Run(ports[0].Protocol, func(t *testing.T) {
			p := &certPinSharedWriter{}
			seed := NewStore()
			if err := seed.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			svc := Service{ID: "old", TenantID: "tenant", Alias: "old-service", Ports: []PortProto{{Protocol: "tcp", Port: 443}}}
			if _, err := seed.UpsertService(svc); err != nil {
				t.Fatal(err)
			}
			raw, err := p.Load()
			if err != nil {
				t.Fatal(err)
			}
			var snap persistedCatalog
			if err := json.Unmarshal(raw, &snap); err != nil {
				t.Fatal(err)
			}
			old := snap.Services["tenant"]["old"]
			old.Ports = ports
			snap.Services["tenant"]["old"] = old
			raw, err = json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Save(raw); err != nil {
				t.Fatal(err)
			}
			restored := NewStore()
			if err := restored.SetPersister(p); err != nil {
				t.Fatalf("legacy record blocked startup: %v", err)
			}
			if got := restored.ServiceTransportPorts("tenant", "old"); len(got) != 0 {
				t.Fatal("invalid transport became executable")
			}
			if _, err := restored.UpsertGroup(Group{ID: "other", TenantID: "tenant", Alias: "other"}); err != nil {
				t.Fatalf("legacy record blocked unrelated edit: %v", err)
			}
			again := NewStore()
			if err := again.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			var kept bool
			for _, row := range again.ListServices("tenant") {
				if row.ID == "old" {
					kept = true
					if row.Ports[0] != ports[0] {
						t.Fatal("legacy data silently rewritten")
					}
				}
			}
			if !kept {
				t.Fatal("legacy record discarded")
			}
			if _, err := again.UpsertService(old); err == nil {
				t.Fatal("invalid new edit accepted")
			}
			if _, err := again.UpsertService(svc); err != nil {
				t.Fatalf("operator cannot repair old service: %v", err)
			}
			if got := again.ServiceTransportPorts("tenant", "old"); len(got["tcp"]) != 1 || got["tcp"][0] != 443 {
				t.Fatal("repaired service not effective")
			}
		})
	}
}
