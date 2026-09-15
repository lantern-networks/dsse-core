package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// A tenant's logs sit on every node that served it, and only that node can erase them — so the erasure order
// has to travel. This is the whole claim: an order in a SIGNED bundle erases the tenant on the receiving node.
func TestACarriedErasureOrderErasesTheTenantOnThisNode(t *testing.T) {
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	payload := signedPayloadWithPurgeOrder("tenant_gone")

	applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())

	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); !os.IsNotExist(err) {
		t.Fatalf("the ordered tenant's logs are still on this node: %v", err)
	}
	if targets.enrolled.IsAdmitted("device-gone") {
		t.Fatal("the ordered tenant's device is still admitted")
	}
	if len(targets.localCredentials.List("tenant_gone")) != 0 {
		t.Fatal("the ordered tenant's administrator survived")
	}
	// And it stopped at the boundary.
	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_stays"))); err != nil {
		t.Fatalf("another tenant's logs were erased: %v", err)
	}
}

// ★ GATE 1: AN UNSIGNED BUNDLE MUST NOT ERASE ANYTHING. Unsigned bundles are accepted for policy — a lab, a
// bootstrap, an Edge with no pinned key — because bad policy can be re-pushed. Erased data cannot. Acting on
// an unsigned order means anything that can answer the config URL destroys a customer's data.
func TestAnUnsignedBundleNeverErasesATenant(t *testing.T) {
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	payload := signedPayloadWithPurgeOrder("tenant_gone")
	payload.signatureVerified = false // exactly what an unsigned pull produces

	applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())

	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
		t.Fatalf("an UNSIGNED bundle erased a tenant's logs: %v", err)
	}
	if !targets.enrolled.IsAdmitted("device-gone") {
		t.Fatal("an unsigned bundle removed a device from the ledger")
	}
}

// ★ GATE 2: the Edge checks the deletion itself. A payload that names a tenant as both existing and to-be-
// erased is a contradiction, and erasing a live customer is the worst outcome available here.
func TestAnOrderForATenantTheSameBundleStillListsIsRefused(t *testing.T) {
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	payload := signedPayloadWithPurgeOrder("tenant_gone")
	payload.Tenants.Tenants = append(payload.Tenants.Tenants, adminTenantModel{TenantID: "tenant_gone", Status: "active"})

	applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())

	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
		t.Fatalf("a tenant the bundle still lists as existing was erased: %v", err)
	}
}

// ★ GATE 3: a node does not destroy its own operation on the strength of a remote list.
func TestAnEdgeRefusesToEraseTheTenantItEnforcesFor(t *testing.T) {
	targets, dir := purgeTargetsForTest(t, "tenant_gone") // this Edge enforces for the tenant named in the order
	payload := signedPayloadWithPurgeOrder("tenant_gone")

	applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())

	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
		t.Fatalf("an Edge erased the tenant it is enforcing for: %v", err)
	}
}

// The order is carried forever, so applying it repeatedly must be harmless — that is what lets a node which
// was offline when the order was given still be told when it comes back.
func TestApplyingTheSameErasureOrderTwiceIsHarmless(t *testing.T) {
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	payload := signedPayloadWithPurgeOrder("tenant_gone")

	applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())
	applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())

	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_stays"))); err != nil {
		t.Fatalf("the second pass reached another tenant: %v", err)
	}
}

// The order must survive a restart of the authority, or a node that has not yet erased simply stops being
// told — which is the same silence the deletion tombstone exists to prevent, with worse consequences.
func TestPurgeOrdersSurviveARestartAndAreNeverCleared(t *testing.T) {
	path := t.TempDir() + "/tenant_models.json"
	now := time.Now()
	first := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, path)
	first.OrderPurge("tenant_gone", now)
	if got := first.PurgeOrders(); len(got) != 1 || got[0].TenantID != "tenant_gone" {
		t.Fatalf("the order was not recorded: %v", got)
	}
	before := first.ConfigGeneration()
	first.OrderPurge("tenant_gone", now.Add(time.Hour))
	if first.ConfigGeneration() != before {
		t.Fatal("re-ordering the same erasure is not a new fact and must not churn the generation")
	}

	restarted := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, path)
	if got := restarted.PurgeOrders(); len(got) != 1 || got[0].TenantID != "tenant_gone" {
		t.Fatalf("the order did not survive a restart: %v — a node that has not erased yet would never be told again", got)
	}
}

// purgeTargetsForTest builds an apply target holding two tenants' data, with this Edge enforcing for
// enforcementTenant.
func purgeTargetsForTest(t *testing.T, enforcementTenant string) (configApplyTargets, string) {
	t.Helper()
	now := time.Now()
	credentials := newLocalAdminCredentialStore("Lantern DSSE")
	if _, err := credentials.Invite("gone@corp.example", "tenant_gone", "adm_gone", []string{"admin"}, now); err != nil {
		t.Fatalf("invite: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	stamp := now.UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("device-gone", "tenant_gone", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	for _, tenant := range []string{"tenant_gone", "tenant_stays"} {
		partition := filepath.Join(dir, "tenants", logs.SafeTenantSegment(tenant))
		if err := os.MkdirAll(partition, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(partition, "access.log.jsonl"), []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return configApplyTargets{
		enrolled:            ledger,
		logWriter:           writer,
		localCredentials:    credentials,
		enforcementTenantID: enforcementTenant,
		nodeName:            "test-node",
	}, dir
}

// signedPayloadWithPurgeOrder is what a verified bundle carrying one erasure order looks like. The signature
// flag is unexported precisely so that only this side of the wire can set it.
func signedPayloadWithPurgeOrder(tenantID string) configBundlePayload {
	return configBundlePayload{
		signatureVerified: true,
		Tenants: &tenantModelBundle{
			Tenants:     []adminTenantModel{{TenantID: "tenant_stays", Status: "active"}},
			Deleted:     []tenantDeletion{{TenantID: tenantID}},
			PurgeOrders: []tenantPurgeOrder{{TenantID: tenantID, OrderedAt: time.Now().UTC().Format(time.RFC3339)}},
		},
	}
}

func TestCarriedErasurePreservesHeldOrUnknownDataUntilResolved(t *testing.T) {
	for _, state := range []string{"held", "unreadable", "malformed"} {
		t.Run(state, func(t *testing.T) {
			targets, dir := purgeTargetsForTest(t, "tenant_edge")
			p := &unreadableHoldPersister{data: []byte(`[]`)}
			if state == "unreadable" {
				p.err = fmt.Errorf("storage unavailable")
			}
			if state == "malformed" {
				p.data = []byte(`null`)
			}
			targets.legalHold = newLegalHoldStore(p)
			if state == "held" {
				if err := targets.legalHold.Set("tenant_gone", "review", "", true, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			payload := signedPayloadWithPurgeOrder("tenant_gone")
			for i := 0; i < 2; i++ {
				applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())
				if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
					t.Fatalf("protected logs erased: %v", err)
				}
				if !targets.enrolled.IsAdmitted("device-gone") || len(targets.localCredentials.List("tenant_gone")) == 0 {
					t.Fatal("protected identities erased")
				}
			}
			// The shared boundary reports an incomplete operation, never successful emptiness.
			result := purgeAdminTenantData(context.Background(), "node", "tenant_gone", nil, nil, nil, nil, nil, nil, "", nil, nil, adminTenantExtraStores{}, targets.legalHold, time.Now())
			if result.Complete || len(result.Failures) != 1 || len(result.Erased) != 0 {
				t.Fatalf("blocked result: %+v", result)
			}
			if state == "held" {
				if err := targets.legalHold.Set("tenant_gone", "review", "", false, time.Now()); err != nil {
					t.Fatal(err)
				}
			} else {
				// Loading a repaired snapshot represents a restart, not clearing the poisoned store.
				targets.legalHold = newLegalHoldStore(&unreadableHoldPersister{data: []byte(`[]`)})
			}
			applyCarriedTenantPurges(context.Background(), targets, payload, "node", time.Now())
			if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); !os.IsNotExist(err) {
				t.Fatalf("standing order not retried after release/repair: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_stays"))); err != nil {
				t.Fatalf("unrelated tenant erased: %v", err)
			}
		})
	}
}
