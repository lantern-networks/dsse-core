package edgeplane

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
)

func TestPublishedCatalogAppliesDisabledAndPublishedRowsBeyondFirstThousand(t *testing.T) {
	const tenant = "tenant_a"
	ctx := context.Background()
	store := appcatalog.NewStore()
	now := time.Now()
	for i := 0; i < 1000; i++ {
		_, err := store.Upsert(ctx, appcatalog.Entry{
			ApplicationID: fmt.Sprintf("a%04d", i), ApplicationType: "private_app",
			Status: "active", Published: true, Destination: "ordinary.example.test",
			DestinationPort: 443, PublishProtocol: "web",
		}, tenant, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []appcatalog.Entry{
		{ApplicationID: "zzzy", ApplicationType: "private_app", Status: "active", Published: true,
			Destination: "late.example.test", DestinationPort: 443, PublishProtocol: "web"},
		{ApplicationID: "zzzz", ApplicationType: "private_app", Status: "disabled", Published: true,
			Destination: "disabled.example.test", DestinationPort: 443, PublishProtocol: "web"},
	} {
		if _, err := store.Upsert(ctx, row, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	base := map[string]ApplicationRouteProfile{"zzzz": {Destination: "old-enabled.example.test"}}
	routes, err := RouteProfilesWithPublishedCatalog(ctx, base, store, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := routes["zzzz"]; ok {
		t.Fatal("disabled row beyond first thousand left a base route enabled")
	}
	if got := routes["zzzy"].Destination; got != "late.example.test" {
		t.Fatalf("published row beyond first thousand missing: %q", got)
	}
}
