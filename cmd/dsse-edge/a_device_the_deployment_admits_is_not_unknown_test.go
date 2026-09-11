package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// The real in-memory runtime store — the one a generated deployment actually runs, since it passes no
// -device-store. Using it rather than a fake is the point: the behaviour under test is what happens when THAT
// store has been emptied by a restart.
func newTestDeviceRuntimeStore() deviceRuntimeStore { return device.NewStore() }

func aLedgerAdmitting(t *testing.T, id, tenant string) *enrolledinventory.Ledger {
	t.Helper()
	l := enrolledinventory.NewLedger()
	if _, err := l.Enroll(id, tenant, "enrolled for this test", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return l
}

// ★★★ AN EDGE THAT FORGOT IS NOT A DEPLOYMENT THAT REFUSED (2026-08-26, letter 113, measured on real
// hardware). The runtime store is memory by default, so an Edge restart empties it; the device stayed in the
// deployment's durable enrolled inventory and heartbeated into a 404 every fifteen seconds for two hours,
// while its traffic went on being carried and decrypted.
func TestADeviceTheDeploymentAdmitsIsRebuiltRatherThanRefused(t *testing.T) {
	const id, tenant = "skusanagi-win10", "tenant_default"
	ledger := aLedgerAdmitting(t, id, tenant)
	store := newTestDeviceRuntimeStore()
	bundle := model.PolicyBundle{TenantID: tenant}

	// The Edge has no record: this is the state after a restart.
	if _, ok := store.Get(id); ok {
		t.Fatal("the store started with a record, so this proves nothing")
	}
	dev, ok := rehydrateAdmittedDevice(ledger, store, id, id, bundle, time.Now())
	if !ok || dev.TenantID != tenant {
		t.Fatalf("an admitted device was not rebuilt: ok=%v dev=%+v", ok, dev)
	}
	if _, present := store.Get(id); !present {
		t.Fatal("the record was reported rebuilt and is not in the store")
	}
}

// ★★★ AND IT IS NOT SELF-REGISTRATION. Without the proven-identity gate anything that reached the endpoint
// could name a device into an organization — which is exactly what the agent refuses to do on its own, and
// for the same reason.
func TestRebuildingRequiresTheTransportToHaveProvenTheSameIdentity(t *testing.T) {
	const id, tenant = "skusanagi-win10", "tenant_default"
	bundle := model.PolicyBundle{TenantID: tenant}

	for _, tc := range []struct{ name, proven, reported string }{
		{"nothing was proven", "", id},
		{"a different device is named", "some-other-device", id},
		{"nothing is named", id, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := rehydrateAdmittedDevice(aLedgerAdmitting(t, id, tenant), newTestDeviceRuntimeStore(),
				tc.proven, tc.reported, bundle, time.Now()); ok {
				t.Fatal("a device was conjured into an organization without proving it was that device")
			}
		})
	}
	// Control: the same call with a proven, matching identity succeeds — so the refusals above are about the
	// gate and not about the fixture.
	if _, ok := rehydrateAdmittedDevice(aLedgerAdmitting(t, id, tenant), newTestDeviceRuntimeStore(),
		id, id, bundle, time.Now()); !ok {
		t.Fatal("the control must pass")
	}
}

// A device the deployment has REMOVED stays a 404, whatever certificate it still holds. Rebuilding it would
// undo the one act an operator performs to stop a machine.
func TestADeviceTheDeploymentDoesNotAdmitIsStillRefused(t *testing.T) {
	const tenant = "tenant_default"
	ledger := aLedgerAdmitting(t, "somebody-else", tenant)
	if _, ok := rehydrateAdmittedDevice(ledger, newTestDeviceRuntimeStore(), "removed-device", "removed-device",
		model.PolicyBundle{TenantID: tenant}, time.Now()); ok {
		t.Fatal("a device the deployment does not admit was rebuilt")
	}
}

// ★★★ THE WORD "devices" MEANS ENROLLED, AND THE LICENCE AGREES (2026-08-27). The operator-facing count read
// the RUNTIME store — memory on a generated deployment — so it returned to zero on every Edge restart while
// the roster still held every device. It is also not what money is counted against: the licence uses
// ledger.CountAdmitted. A screen showing a different number under the same word as the invoice is the kind of
// wrong that is discovered by an argument about a bill.
func TestTheOperatorsDeviceCountIsTheOneTheLicenceCounts(t *testing.T) {
	const tenant = "tenant_default"
	ledger := aLedgerAdmitting(t, "one", tenant)
	if _, err := ledger.Enroll("two", tenant, "second", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	// An Edge that has just restarted knows nobody: presence is 0, the roster is 2.
	if got := adminEnrolledDeviceCount(ledger, tenant, 0); got != ledger.CountAdmitted(tenant) {
		t.Fatalf("the operator is shown %d and billed for %d", got, ledger.CountAdmitted(tenant))
	}
	if got := adminEnrolledDeviceCount(ledger, tenant, 0); got != 2 {
		t.Fatalf("a restarted Edge reported %d devices for an organization that has 2", got)
	}

	// ★ AND ANOTHER ORGANIZATION'S DEVICES ARE NOT IN THIS ONE'S COUNT — the same boundary the licence draws.
	if got := adminEnrolledDeviceCount(ledger, "somebody-else", 0); got != 0 {
		t.Fatalf("another organization was shown %d of this one's devices", got)
	}

	// ★ WITH NO LEDGER IT FALLS BACK TO PRESENCE, NOT TO ZERO. A node that cannot answer the roster question
	// must not answer it with "this organization has no devices", which is the failure being replaced.
	if got := adminEnrolledDeviceCount(nil, tenant, 7); got != 7 {
		t.Fatalf("a node with no ledger answered %d instead of what it could actually see", got)
	}
}

// ★★★ A CUSTOMER'S DEVICE IS RECORDED INTO THE CUSTOMER'S ORGANIZATION, NOT THE NODE'S (2026-09-01,
// measured on a three-region deployment with a real Windows box).
//
// The runtime store refuses a device whose tenant differs from the policy bundle's, and the bundle handed to
// the rehydrate is the PULLER'S — this Edge's own, which on a deployment that serves customers is the
// operator's tenant. Every customer device was refused with "device tenant_id tenant_… does not match policy
// bundle tenant_id tenant_default" and went on heartbeating into a 404 while its traffic was carried and
// decrypted: the symptom the header of this file records from 2026-08-26, arriving through the next gate.
func TestARehydratedDeviceKeepsTheOrganizationTheLedgerNames(t *testing.T) {
	const id, customer = "skusanagi-win10", "tenant_eksuhxrdhdimxjq2mbgqhd6tha"
	ledger := aLedgerAdmitting(t, id, customer)
	store := newTestDeviceRuntimeStore()
	// The Edge's own bundle names the OPERATOR's tenant — what a node serving customers actually holds, since
	// the fleet credential is the operator's. The store compares the two, so this is the whole defect.
	operatorsBundle := model.PolicyBundle{TenantID: "tenant_default"}

	dev, ok := rehydrateAdmittedDevice(ledger, store, id, id, operatorsBundle, time.Now())
	if !ok {
		t.Fatal("a device the deployment admits was refused; on a deployment with customers that is every device")
	}
	if dev.TenantID != customer {
		t.Errorf("recorded into %q; the ledger — which is what decides admission — says %q", dev.TenantID, customer)
	}
	if got, present := store.Get(id); !present || got.TenantID != customer {
		t.Errorf("the store holds present=%v tenant=%q, want the customer's organization", present, got.TenantID)
	}
}
