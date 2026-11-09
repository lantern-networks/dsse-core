package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// ★ THE LICENCE PAGE READ "IN USE 2" BESIDE A DEVICES SCREEN SAYING "1 DEVICE" (0.4.1 acceptance B rerun). Both
// were right: the licence counts agents and a connector is one, so it holds a seat, and the Devices screen leaves
// it out. Nothing on either page said so. The row now carries how many of the seats are connectors, counted by
// the same function the Devices screen uses to leave them out.
func TestTheLicenceRowSaysHowManySeatsAreConnectors(t *testing.T) {
	_, _, ledger, _, deps := licenceAdminFixture(t)
	for _, id := range []string{"skusanagi-win10", "conn-1899faeac85c"} {
		if _, err := ledger.Enroll(id, "tenant_b2", "", "2026-11-07T00:00:00Z"); err != nil {
			t.Fatalf("enrol %s: %v", id, err)
		}
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-1899faeac85c", TenantID: "tenant_b2",
		Status: "active", PrivateBaseURL: "https://internal.invalid"}, time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	deps.connectorsAdmitted = func(tenantID string) int {
		return admittedConnectorCount(ledger, tenantID, connectorIdentitiesFor(registry, tenantID))
	}

	rows := deps.tenantViews()
	if len(rows) != 1 {
		t.Fatalf("rows: %#v", rows)
	}
	if rows[0].Used != 2 {
		t.Fatalf("the seat count changed: %d in use, want 2 — the connector still holds a seat", rows[0].Used)
	}
	if rows[0].Connectors != 1 {
		t.Fatalf("the row says %d of its seats are connectors, want 1", rows[0].Connectors)
	}
	if devices := adminEnrolledEndpointCount(ledger, "tenant_b2", 0, connectorIdentitiesFor(registry, "tenant_b2")); devices != rows[0].Used-rows[0].Connectors {
		t.Fatalf("the licence page and the Devices screen disagree: %d devices there, %d here", devices, rows[0].Used-rows[0].Connectors)
	}
}
