package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
)

type riskProbeDirectory struct {
	people map[string][]model.HumanIdentity
}

func (d riskProbeDirectory) Upsert(context.Context, model.HumanIdentity, string, time.Time) (model.HumanIdentity, error) {
	return model.HumanIdentity{}, nil
}
func (d riskProbeDirectory) List(_ context.Context, tenant string, _ ...humanidentity.HumanIdentityDirectoryListOptions) ([]model.HumanIdentity, error) {
	return d.people[tenant], nil
}
func (d riskProbeDirectory) Stats(context.Context, string, time.Time) (humanidentity.HumanIdentityDirectoryStats, error) {
	return humanidentity.HumanIdentityDirectoryStats{}, nil
}

// ★★★ ONE CUSTOMER MARKED ANOTHER CUSTOMER'S LAPTOP CRITICAL (2026-08-22, measured live).
func TestARiskMarkMustNameAnEntityTheCallerOwns(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("risk-probe", "tenant_reference_lab", "probe", now); err != nil {
		t.Fatalf("seed the ledger: %v", err)
	}
	dir := riskProbeDirectory{people: map[string][]model.HumanIdentity{
		"tenant_reference_lab": {{ID: "u_lab_1", Subject: "alice", TenantID: "tenant_reference_lab"}},
	}}

	// The measured attack: Northwind names the lab's device.
	owned, why := riskEntityOwnedByCaller(context.Background(), "device", "risk-probe", "tenant_northwind", ledger, dir)
	if owned {
		t.Fatal("a customer was allowed to mark another organization's device")
	}
	if !strings.Contains(why, "your organization") {
		t.Fatalf("the refusal does not say why: %q", why)
	}

	// ★ THE CONTROL, and it is the whole test: the owner must still be able to mark their own device, or this
	// took the risk control away from everybody and would look identical from the attacker's side.
	if owned, why := riskEntityOwnedByCaller(context.Background(), "device", "risk-probe",
		"tenant_reference_lab", ledger, dir); !owned {
		t.Fatalf("an organization was refused a mark on its OWN device: %q", why)
	}

	// An entity nobody can place is nobody's — a mark on it is one nobody can lift.
	if owned, _ := riskEntityOwnedByCaller(context.Background(), "device", "never-enrolled",
		"tenant_reference_lab", ledger, dir); owned {
		t.Fatal("an unplaceable entity was treated as the caller's")
	}

	// People are resolved through the organization's own directory, both ways.
	if owned, why := riskEntityOwnedByCaller(context.Background(), "user", "alice",
		"tenant_reference_lab", ledger, dir); !owned {
		t.Fatalf("an organization was refused a mark on its own person: %q", why)
	}
	if owned, _ := riskEntityOwnedByCaller(context.Background(), "user", "alice",
		"tenant_northwind", ledger, dir); owned {
		t.Fatal("a customer marked somebody in another organization's directory")
	}
	// And a directory this node does not hold is a refusal, not a pass: the alternative is marking somebody
	// because the lookup was unavailable.
	if owned, why := riskEntityOwnedByCaller(context.Background(), "user", "alice",
		"tenant_reference_lab", ledger, nil); owned || !strings.Contains(why, "directory") {
		t.Fatalf("a missing directory did not fail safe: owned=%v why=%q", owned, why)
	}
}

// And the route calls it: a helper nothing calls is the shape this repo keeps finding.
func TestTheRiskSignalWriteAsksWhoOwnsTheEntity(t *testing.T) {
	raw, err := os.ReadFile("admin_risk_serverinit_routes.go")
	if err != nil {
		t.Fatalf("read the routes: %v", err)
	}
	src := string(raw)
	if !strings.Contains(src, "riskEntityOwnedByCaller(") {
		t.Fatal("POST /admin/risk-signals does not ask who owns the entity, so a customer can mark another " +
			"organization's device critical across the whole fleet")
	}
	// The operator answering for the whole deployment must still be able to mark, or this closed the control
	// rather than scoping it.
	if !strings.Contains(src, "adminAnswerScope(r)") {
		t.Fatal("the scope check has no whole-deployment escape, so the operator can no longer mark anything")
	}
}
