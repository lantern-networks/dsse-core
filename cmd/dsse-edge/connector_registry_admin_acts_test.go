package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ MOVING THE REGISTRY TO THE DEPLOYMENT'S DATABASE TOOK RENAME AND REMOVE AWAY (2026-08-25, caught by the
// installer's own verification failing to clean up after itself: DELETE /admin/connectors/... -> 501).
//
// Both admin acts were reached by asserting the IN-MEMORY registry's concrete type. Removing a connector is
// how a customer takes its access away, so a durable store that cannot revoke is worse than the split it was
// brought in to fix. This pins the property that made it possible: the routes ask for what the ACT needs.
func TestBothRegistryStoresCanRenameAndRemove(t *testing.T) {
	stores := map[string]any{
		"the in-memory registry":    connector.NewRegistry(),
		"the deployment's database": postgresConnectorRegistryStore{},
	}
	for name, store := range stores {
		if _, ok := store.(connectorRegistryRenamer); !ok {
			t.Fatalf("%s cannot rename a connector — the Console's Rename answers 501 against it", name)
		}
		if _, ok := store.(connectorRegistryRemover); !ok {
			t.Fatalf("%s cannot remove a connector — a customer cannot take its access away", name)
		}
		if _, ok := store.(connectorRegistryStore); !ok {
			t.Fatalf("%s is not a connector registry at all", name)
		}
	}
}

// ★★★ AND THE BUNDLE'S VERSION HAS TO MOVE WHEN THE CATALOG DOES. The aggregate generation an Edge compares
// against is a sum, and its connector term was read from the in-memory registry BY CONCRETE TYPE — silently
// zero once the control plane's registry became the deployment's database. A catalog that travels and a
// version that does not move is the same as not carrying it at all: no Edge pulls.
func TestBothRegistryStoresReportAConfigGeneration(t *testing.T) {
	stores := map[string]any{
		"the in-memory registry":    connector.NewRegistry(),
		"the deployment's database": postgresConnectorRegistryStore{},
	}
	for name, store := range stores {
		if _, ok := store.(interface{ ConfigGeneration() uint64 }); !ok {
			t.Fatalf("%s reports no config generation — registering a connector would change the bundle's "+
				"contents and not its version, and no Edge would pull it", name)
		}
	}
}

// ★★★ THE GENERATION MUST BE MONOTONIC, AND A FINGERPRINT IS NOT (2026-08-26, measured being worse than the
// problem it replaced). The bundle's generation is a SUM of terms and an Edge applies a generation GREATER
// than the one it holds — so a term that can decrease does not slow the fleet, it stops it: one decrease and
// no Edge applies configuration again until the control plane restarts.
func TestTheConnectorGenerationNeverGoesBackwards(t *testing.T) {
	reg := connector.NewRegistry()
	gen := func() uint64 {
		c, ok := any(reg).(interface{ ConfigGeneration() uint64 })
		if !ok {
			t.Fatal("the registry reports no generation")
		}
		return c.ConfigGeneration()
	}
	last := gen()
	now := time.Now().UTC()
	for i := 0; i < 8; i++ {
		if _, err := reg.Register(model.ConnectorRegistration{
			ID: "conn-a", TenantID: "tenant_a", ConnectorGroupID: "site-1",
			EdgeRegionID: "region-a", Status: "registered", PrivateBaseURL: "https://app.internal:8443",
		}, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("register: %v", err)
		}
		got := gen()
		if got < last {
			t.Fatalf("the generation went backwards: %d -> %d. Every Edge stops applying configuration at that "+
				"moment, and says nothing", last, got)
		}
		last = got
	}
}
