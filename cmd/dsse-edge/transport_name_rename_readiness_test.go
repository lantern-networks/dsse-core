package main

import (
	"strings"
	"testing"
)

// ★★★ AN IDENTITY THAT NEVER SENDS EITHER NAME HELD THE ONLY RENAME IN THIS LAB SHUT (2026-08-22, measured).
//
// Both real devices reported sending the new name. The gate stayed closed on conn_lab_001 — a connector,
// which reaches this deployment on the agent plane by host (https://edge:8443) and presents no
// per-organization SNI at all. Retiring a transport NAME cannot fail a handshake that never carries it.
//
// It is EXCLUDED AND NAMED, never subtracted: a denominator that shrinks without saying so is a gate that has
// stopped measuring.
func TestARenameIsNotHeldShutBySomethingThatSendsNoName(t *testing.T) {
	enrolled := []string{"mac-dev-1", "win-dev-1", "conn_lab_001"}
	sending := map[string]string{"mac-dev-1": "new.invalid", "win-dev-1": "new.invalid"}

	held := measureTransportNameRename("t", "new.invalid", "old.invalid", enrolled, sending)
	if held.MayRetirePrevious {
		t.Fatal("without the exclusion the connector is silent and the gate must stay shut — otherwise this " +
			"test proves nothing about the exclusion below")
	}

	notAgents := map[string]bool{"conn_lab_001": true}
	open := measureTransportNameRenameExcluding("t", "new.invalid", "old.invalid", enrolled, sending, notAgents)
	if !open.MayRetirePrevious {
		t.Fatalf("every device that dials by name has moved; the rename must be finishable: %+v", open)
	}
	if len(open.NotAgents) != 1 || open.NotAgents[0] != "conn_lab_001" {
		t.Errorf("the excluded identity must be NAMED in the answer, got %v", open.NotAgents)
	}
	for _, id := range append(append([]string{}, open.NeverReported...), open.StillSendingPrevious...) {
		if id == "conn_lab_001" {
			t.Error("an excluded identity must not also be counted against the rename")
		}
	}

	// ★★★ AND IT CANCELS ITSELF. In production a connector reaches the Edge on 443, the same door as an
	// agent — the port was never the reason. The day one reports a transport name it is dialling by name, and
	// a rename can break it, so it must be counted again with no code change and nobody remembering.
	speaks := map[string]string{"mac-dev-1": "new.invalid", "win-dev-1": "new.invalid", "conn_lab_001": "old.invalid"}
	counted := measureTransportNameRenameExcluding("t", "new.invalid", "old.invalid", enrolled, speaks, notAgents)
	if counted.MayRetirePrevious {
		t.Error("a connector that reports sending the PREVIOUS name must hold the rename shut — the exclusion " +
			"is about sending no name, not about being a connector")
	}
	if len(counted.NotAgents) != 0 {
		t.Errorf("an identity that reported a name is no longer excluded, got %v", counted.NotAgents)
	}

	// ★ And excluding must not open a gate that a real device is holding shut.
	stillThere := map[string]string{"mac-dev-1": "new.invalid", "win-dev-1": "old.invalid"}
	shut := measureTransportNameRenameExcluding("t", "new.invalid", "old.invalid", enrolled, stillThere, notAgents)
	if shut.MayRetirePrevious {
		t.Error("a device still sending the previous name must keep the gate shut, exclusion or not")
	}
}

// ★★★ AN ORGANIZATION WITH NO DEVICES COULD NEVER FINISH A RENAME (2026-08-22, measured on tenant_northwind:
// nought devices, nought silent, may_retire_previous false, and nothing left to wait for).
//
// The gate wants a positive witness — at least one device saying it sends the new name — which is right when
// devices exist, because silence is the switched-off laptop it protects. With an empty denominator the
// witness cannot exist and the act it blocks cannot hurt anyone. "Nobody has reported" and "there is nobody"
// are different zeroes.
func TestARenameCanFinishForAnOrganizationThatHasNoDevices(t *testing.T) {
	empty := measureTransportNameRename("t", "new.invalid", "old.invalid", nil, nil)
	if !empty.MayRetirePrevious {
		t.Fatal("an organization with no devices can never finish a rename, for ever")
	}
	if !strings.Contains(empty.Note, "breaks nobody") {
		t.Errorf("the answer must say WHY it is allowed; \"nobody is affected\" is not \"everybody moved\": %q", empty.Note)
	}

	// ★ And only devices that could send a name count. An organization whose one identity is a connector has
	// nobody to break either — but a real device that has not spoken still holds it shut.
	onlyConnector := measureTransportNameRenameExcluding("t", "new.invalid", "old.invalid",
		[]string{"conn-1"}, nil, map[string]bool{"conn-1": true})
	if !onlyConnector.MayRetirePrevious {
		t.Error("an organization whose only enrolled identity sends no name has nobody to break")
	}
	silentDevice := measureTransportNameRename("t", "new.invalid", "old.invalid", []string{"laptop-1"}, nil)
	if silentDevice.MayRetirePrevious {
		t.Error("a device that exists and has not spoken must still hold the rename shut — that is the " +
			"switched-off laptop this gate is for")
	}
}
