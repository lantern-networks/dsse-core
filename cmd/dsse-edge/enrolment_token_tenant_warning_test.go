package main

import (
	"strings"
	"testing"
)

// ★★ A CREDENTIAL NOTHING CAN USE, ISSUED WITH NO HINT OF IT (2026-08-17, measured on the lab).
//
// A Northwind administrator minted an enrolment token through the Console: 200, a real secret, tenant_northwind
// on the record. POST /enroll then answered "invalid or missing eligibility token" for it — the endpoint
// verifies the token against the ONE organization this node enrols for, assigns that organization to the
// device, and signs with the node's single device-identity CA. The token belongs to an organization this node
// does not enrol for, so nothing can ever use it.
//
// The administrator's next move is to suspect the device, or the installer, or the network. It is none of
// those. Not refused — another Edge in the fleet may enrol for that organization and this node cannot know —
// but said, at the moment of issue and on the list.
func TestATokenForAnOrganizationThisNodeDoesNotEnrolForSaysSo(t *testing.T) {
	// ★ The operator's reading of it. On 2026-08-18 this message split in two: a customer is told what they
	// can act on, and only whoever answers for the deployment is told whose node this is — naming another
	// customer of the same provider on this customer's screen is a disclosure, and they may be competitors.
	// See TestTheEnrolmentWarningDoesNotNameAnotherTenantToACustomer.
	warning := enrolmentTokenTenantWarning("tenant_northwind", "tenant_reference_lab", true, false)
	if warning == "" {
		t.Fatal("a token this node's /enroll will refuse must say so at issue — silence sends the administrator " +
			"after the device")
	}
	// Both organizations named: which one is holding a useless token, and which one this node serves.
	if !strings.Contains(warning, "tenant_northwind") || !strings.Contains(warning, "tenant_reference_lab") {
		t.Fatalf("the warning must name both organizations, got %q", warning)
	}

	// The ordinary case stays quiet.
	if w := enrolmentTokenTenantWarning("tenant_reference_lab", "tenant_reference_lab", true, false); w != "" {
		t.Fatalf("a usable token must not be warned about: %q", w)
	}
	// Case-insensitively, like every other tenant comparison on this path.
	if w := enrolmentTokenTenantWarning("Tenant_Reference_Lab", "tenant_reference_lab", true, false); w != "" {
		t.Fatalf("tenant comparison must be case-insensitive here as it is in the token store: %q", w)
	}
	// And an unknown node tenant is not an excuse to invent a warning.
	if w := enrolmentTokenTenantWarning("tenant_northwind", "", true, false); w != "" {
		t.Fatalf("with no node tenant known, say nothing rather than guess: %q", w)
	}
}

// ★★★ AND THE SAME SCREEN TOLD A CUSTOMER WHOSE DEVICES DO ENROL THAT THEY COULD NOT (2026-08-28, measured by
// approving a Mac for Kaede Logistics on a two-region deployment and enrolling it with the token the Console
// had just warned about — HTTP 200, certificate signed by "Kaede Logistics Device Identity CA").
//
// /enroll stopped verifying against the node's own organization on 2026-08-21: it takes the organization from
// the token and refuses only when this node holds no device-identity authority for it. An organization whose
// device identities this deployment issues therefore has tokens that work — and this warning went on saying
// every one of them would be refused, then recommended registering an external device CA, which is the only
// thing that would have made the refusal real.
func TestNoWarningWhenThisNodeIssuesThatOrganizationsDeviceIdentities(t *testing.T) {
	if w := enrolmentTokenTenantWarning("tenant_kaede", "tenant_default", true, true); w != "" {
		t.Fatalf("this node signs device certificates for tenant_kaede, so its tokens enrol here; the screen "+
			"that issues them must not say they are refused: %q", w)
	}
	// And the customer's half of the message is silenced by the same fact, not only the operator's.
	if w := enrolmentTokenTenantWarning("tenant_kaede", "tenant_default", false, true); w != "" {
		t.Fatalf("a customer must not be sent after their device either: %q", w)
	}
	// Holding no authority for them is still worth saying.
	if w := enrolmentTokenTenantWarning("tenant_kaede", "tenant_default", false, false); w == "" {
		t.Fatal("a token this node cannot sign for must still be flagged at issue")
	}
}

// ★★★ AND THE ANSWER MUST COME FROM WHATEVER THIS NODE ROLE HAS (2026-08-28, measured on the lab AFTER the fix
// above shipped, which is the point: the helper's tests all passed and the screen was unchanged).
//
// The first version asked only the Edge's runtime signer map. The enrolment-token screen is served by the
// CONTROL PLANE, which does not hold that map — it holds the per-organization device authorities — so the
// warning stayed exactly where it was, on a deployment whose /enroll answers 200 for that organization. The
// same family as every "verify the call site, not the helper" finding in this tree: a correct function wired to
// the wrong source is indistinguishable from no fix at all, from the screen.
func TestTheDeploymentIsAskedWhereverThisNodeRoleKeepsTheAnswer(t *testing.T) {
	if nodeIssuesDeviceIdentitiesFor(nil, "tenant_kaede") {
		t.Fatal("a node holding neither an authority nor a signer must not claim it can issue")
	}
	if nodeIssuesDeviceIdentitiesFor(newTenantDeviceAuthority(nil, nil, nil), "") {
		t.Fatal("no organization named is not an organization this node issues for")
	}

	// A control plane: the row is what it has, and it is enough.
	seed := []byte(`[{"tenant_id":"tenant_kaede"}]`)
	cp := newTenantDeviceAuthority(seed, nil, nil)
	if !nodeIssuesDeviceIdentitiesFor(cp, "tenant_kaede") {
		t.Error("a control plane holding this organization's device authority answered that it cannot issue " +
			"for it — which is the screen telling a customer their working token is refused")
	}
	// Case-insensitively, like every other tenant comparison on this path.
	if !nodeIssuesDeviceIdentitiesFor(cp, "Tenant_Kaede") {
		t.Error("tenant comparison must be case-insensitive here as it is in the token store")
	}
	// And somebody else's organization is still somebody else's.
	if nodeIssuesDeviceIdentitiesFor(cp, "tenant_northwind") {
		t.Error("an organization this deployment holds no authority for must still be warned about")
	}
}
