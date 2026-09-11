package main

import (
	"strings"
	"testing"
)

// keyC is a third distinct Ed25519 key; p256 is the other shape the updater accepts. The point of these tests
// is that five conditions on two services stay five, with their own shapes.
const (
	keyC = "3c3c9f1e2d4b5a60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
	p256 = "04" + "1111111111111111111111111111111111111111111111111111111111111111" +
		"2222222222222222222222222222222222222222222222222222222222222222"
	publisher = "subject:Aoba Networks"
)

func storedEverything() pinSet {
	return pinSet{
		"Steer_ConfigPin":      keyA,
		"Steer_AgentPolicyPin": keyB,
		"Updater_UpdatePin":    keyC + "," + p256,
		"Updater_PlanPin":      p256,
		"Updater_Publisher":    publisher,
	}
}

// TestTheUpdatePinIsNeverRestoredOntoTheSteerService checks that the
// code written to stop a service failing to start after an upgrade would itself have stopped it. DsseSteer has
// no --update-pin flag — that lives on DsseUpdater (DsseAgent.wxs UpdaterArgs, updater/main_windows.go).
func TestTheUpdatePinIsNeverRestoredOntoTheSteerService(t *testing.T) {
	r := fillMissingPins("DsseSteer", []string{"--service-run", "--config-store"}, storedEverything())

	joined := strings.Join(r.Args, " ")
	for _, flag := range []string{"--update-pin", "--plan-pin", "--update-publisher"} {
		if strings.Contains(joined, flag) {
			t.Fatalf("%s was put on DsseSteer, which does not accept it: %v", flag, r.Args)
		}
	}
	if len(r.Added) != 2 {
		t.Fatalf("DsseSteer carries exactly two conditions, got %v", r.Added)
	}
}

// TestEachServiceRestoresOnlyItsOwnConditions is the same rule from the other side.
func TestEachServiceRestoresOnlyItsOwnConditions(t *testing.T) {
	r := fillMissingPins("DsseUpdater", []string{"--service-run"}, storedEverything())

	got := pinsInArgs("DsseUpdater", r.Args)
	if got.get("Updater_UpdatePin") != keyC+","+p256 {
		t.Fatalf("the update key SET was not restored intact: %q", got.get("Updater_UpdatePin"))
	}
	if got.get("Updater_PlanPin") != p256 {
		t.Fatalf("the P-256 plan pin was not restored: %q", got.get("Updater_PlanPin"))
	}
	if got.get("Updater_Publisher") != publisher {
		t.Fatalf("the publisher requirement was not restored: %q", got.get("Updater_Publisher"))
	}
	if strings.Contains(strings.Join(r.Args, " "), "--config-pin") {
		t.Fatalf("a DsseSteer condition was put on DsseUpdater: %v", r.Args)
	}
}

// TestTheUpdaterShapesAreAccepted guards the validators. Applying the 64-hex profile-signing shape to all five
// would refuse a legal fleet its own update key: a PKCS#11 token holds a P-256 point, and pinning old AND new
// is how a rotation is carried out.
func TestTheUpdaterShapesAreAccepted(t *testing.T) {
	for _, c := range []struct {
		name  string
		check func(string) error
		value string
		ok    bool
	}{
		{"ed25519 update pin", validateKeySet, keyA, true},
		{"p256 update pin", validateKeySet, p256, true},
		{"rotation key set", validateKeySet, keyA + "," + p256, true},
		{"empty key set", validateKeySet, "", false},
		{"p256 plan pin", validateVerificationKey, p256, true},
		{"p256 as a config pin", validateEd25519Key, p256, false},
		{"subject publisher", validatePublisher, publisher, true},
		{"thumbprint publisher", validatePublisher, "thumbprint:" + keyA, true},
		{"bare publisher", validatePublisher, "Aoba Networks", false},
	} {
		err := c.check(c.value)
		if c.ok && err != nil {
			t.Fatalf("%s should be accepted: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("%s should be refused", c.name)
		}
	}
}

// TestOneConditionGoneIsRestoredAndTheOthersAreNotTouched is the case a single stored key got wrong: a box
// that still names a config pin used to take the "already in force" branch and never restore the POLICY pin
// the same upgrade had deleted.
func TestOneConditionGoneIsRestoredAndTheOthersAreNotTouched(t *testing.T) {
	args := []string{"--service-run", "--config-pin", keyA}

	r := fillMissingPins("DsseSteer", args, storedEverything())

	if len(r.Added) != 1 || r.Added[0] != "--agent-policy-pin" {
		t.Fatalf("only the missing policy pin should be restored, got %v", r.Added)
	}
	got := pinsInArgs("DsseSteer", r.Args)
	if got.get("Steer_ConfigPin") != keyA {
		t.Fatalf("an untouched pin changed: %+v", got)
	}
	if got.get("Steer_AgentPolicyPin") != keyB {
		t.Fatalf("the policy pin was restored to %s, want its OWN stored key %s", got.get("Steer_AgentPolicyPin"), keyB)
	}
}

// TestARestoredConditionIsNeverGuessedFromASibling is the defect a single adopted key produced: a box that
// held A/B/C came back A/A/A, every value individually plausible and the separation between authorities gone.
func TestARestoredConditionIsNeverGuessedFromASibling(t *testing.T) {
	stored := pinSet{"Steer_ConfigPin": keyA} // the store knows only the config key

	r := fillMissingPins("DsseSteer", []string{"--service-run"}, stored)

	if pinsInArgs("DsseSteer", r.Args).get("Steer_AgentPolicyPin") != "" {
		t.Fatalf("a purpose with nothing stored was filled from another purpose's key: %v", r.Args)
	}
	if len(r.Unheld) != 1 || r.Unheld[0] != "--agent-policy-pin" {
		t.Fatalf("the unheld purpose should be reported, got %v", r.Unheld)
	}
	if !strings.Contains(r.Note, "nothing was invented") {
		t.Fatalf("the note must say nothing was invented: %q", r.Note)
	}
}

// TestAConditionNamingADifferentValueIsNeverOverwritten keeps missing and mismatched as the different facts
// they are.
func TestAConditionNamingADifferentValueIsNeverOverwritten(t *testing.T) {
	args := []string{"--service-run", "--agent-policy-pin", keyC} // stored says B, service says C

	r := fillMissingPins("DsseSteer", args, storedEverything())

	if pinsInArgs("DsseSteer", r.Args).get("Steer_AgentPolicyPin") != keyC {
		t.Fatal("a condition already in force was overwritten")
	}
	if len(r.Differs) != 1 || r.Differs[0] != "--agent-policy-pin" {
		t.Fatalf("the mismatch should be reported, got %v", r.Differs)
	}
}

// TestAHealthyBoxIsNotRewritten guards the idempotence the MSI depends on: this runs on every install and
// upgrade, and a service whose command line is rewritten to the value it already had is a change in the audit
// record that changed nothing on the box.
func TestAHealthyBoxIsNotRewritten(t *testing.T) {
	args := []string{"--service-run", "--config-pin", keyA, "--agent-policy-pin", keyB}

	r := fillMissingPins("DsseSteer", args, storedEverything())

	if r.Changed() {
		t.Fatalf("nothing should be added to a box that already names every condition, got %v", r.Added)
	}
	if len(r.Args) != len(args) {
		t.Fatalf("the argument list grew: %v", r.Args)
	}
}

// TestConditionsAreReadInBothFlagForms mirrors pinFromArgs: an operator or an older package may have written
// either form, and reading only one would report a condition as absent and then "restore" a second copy.
func TestConditionsAreReadInBothFlagForms(t *testing.T) {
	for _, args := range [][]string{
		{"--config-pin=" + keyA, "--agent-policy-pin=" + keyB},
		{"-config-pin", keyA, "-agent-policy-pin", keyB},
	} {
		p := pinsInArgs("DsseSteer", args)
		if p.get("Steer_ConfigPin") != keyA || p.get("Steer_AgentPolicyPin") != keyB {
			t.Fatalf("args %v read as %+v", args, p)
		}
	}
}

// TestTheLastOccurrenceWins matches Go's flag package, which is what the agent will actually parse.
func TestTheLastOccurrenceWins(t *testing.T) {
	p := pinsInArgs("DsseSteer", []string{"--config-pin", keyA, "--config-pin", keyB})
	if p.get("Steer_ConfigPin") != keyB {
		t.Fatalf("want the last value %s, got %s", keyB, p.get("Steer_ConfigPin"))
	}
}
