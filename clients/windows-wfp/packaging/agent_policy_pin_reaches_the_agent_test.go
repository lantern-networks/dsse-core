package packaging

import (
	"os"
	"strings"
	"testing"
)

// agent_policy_pin_reaches_the_agent_test.go — the key that was validated, baked, and given to the wrong
// service.
//
// ★ MEASURED ON win-dev-1 (2026-08-12). DsseSteer's ServiceInstall carried the literal
// "--service-run --config-store", so every MSI-installed box started with no --agent-policy-pin. That flag is
// what gates trust-anchor recovery:
//
//	trust_anchor_recovery disabled (no --agent-policy-pin; the signed bundle could not be verified)
//
// which is what the box logs on every start. A device that cannot adopt a rotated transport CA loses the Edge
// on the day the fleet withdraws the old one, with no path back — and the recovery mechanism exists precisely
// for that day. The signed steer-exclusion policy is gated on the same flag and verified nothing either.
//
// -PlanPin IS the agent-policy key; build-msi.ps1 says so where it declares it. It was validated at build
// time, threaded into DsseUpdater's arguments, and withheld from the agent that needs it for everything except
// the rollout plan.

func wxs(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatalf("read DsseAgent.wxs: %v", err)
	}
	return string(b)
}

func TestTheSteerServiceIsGivenTheAgentPolicyPinWhenOneIsBaked(t *testing.T) {
	s := wxs(t)
	if !strings.Contains(s, `--agent-policy-pin $(var.PlanPin)`) {
		t.Fatal("DsseSteer's arguments never receive --agent-policy-pin. Without it the agent cannot adopt a " +
			"rotated transport CA (trust_anchor_recovery is disabled at startup) and cannot verify signed " +
			"steer-exclusion policy — on every device this package installs.")
	}
}

// And it must reach the STEER service specifically: the updater already had it, which is what made the gap
// hard to see — the key was present in the package and in one service's arguments.
func TestTheSteerServiceArgumentsAreBuiltRatherThanLiteral(t *testing.T) {
	s := wxs(t)
	if strings.Contains(s, `Arguments="--service-run --config-store"`) {
		t.Fatal("DsseSteer's Arguments are a literal again, so any pin the build validates cannot reach it")
	}
	if !strings.Contains(s, `Arguments="$(var.SteerArgs)"`) {
		t.Fatal("DsseSteer's Arguments do not come from SteerArgs; the conditional pin cannot be applied")
	}
	// The base must still be there — a device with no baked pin still needs the service to run at all.
	if !strings.Contains(s, `<?define SteerArgs = "--service-run --config-store" ?>`) {
		t.Fatal("the SteerArgs base no longer carries --service-run --config-store, so an unpinned build would " +
			"register a service that reads no configuration")
	}
}

// The two pins must not be confused. The update key signs CODE and an Edge must never hold it; the plan key is
// the agent-policy key an Edge does hold. Giving the agent the update key here would hand the code-signing
// authority to the policy path.
// ★ AND THE ANCHOR THE DEVICE IS BORN WITH HAS TO COME FROM SOMEWHERE (2026-08-12, traced on win-dev-1).
// Nothing provisioned it: the install profile carries `transport_anchor`, a FINGERPRINT, and the enrol
// response returns the DEVICE-ISSUING CA, which is a different PKI and cannot verify a server. A freshly
// installed device therefore had no transport anchor by any route — and once the agent correctly stopped
// persisting an identity it could not prove, that device stopped being able to ENROL at all: standing aside
// forever, waiting for a file the product never produced.
//
// The file name is the contract with the agent (provisionedTransportCAFile), so it is asserted rather than
// described.
func TestTheTransportAnchorCanBeProvisionedByThePackage(t *testing.T) {
	s := wxs(t)
	if !strings.Contains(s, `Source="transport_ca.pem"`) {
		t.Fatal("the package cannot install a transport anchor. A device with none cannot verify the Edge, and " +
			"since the enrolment probe refuses to persist an unproven identity, it cannot enrol either")
	}
	if !strings.Contains(s, `Id="DSSEDATADIR" Name="DSSE"`) ||
		!strings.Contains(s, `StandardDirectory Id="CommonAppDataFolder"`) {
		t.Fatal("the anchor is not installed under %ProgramData%\\DSSE, which is where the agent looks for it")
	}
	// It outlives the program: adopted anchors supersede it, and an uninstall must not take a device's trust
	// with it.
	if !strings.Contains(s, `Id="TransportCAFile" Guid="*" Bitness="always64" Permanent="yes"`) {
		t.Fatal("the transport anchor component is not Permanent; an uninstall would remove the device's trust")
	}
}

func TestTheAgentIsNotGivenTheUpdateSigningKey(t *testing.T) {
	s := wxs(t)
	if strings.Contains(s, `--agent-policy-pin $(var.UpdatePin)`) {
		t.Fatal("the agent is pinned to the UPDATE-signing key: that key is the authority to run code, and an " +
			"Edge holds the policy key — they must never be the same")
	}
}
