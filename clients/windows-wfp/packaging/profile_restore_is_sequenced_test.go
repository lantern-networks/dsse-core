package packaging

import (
	"os"
	"strings"
	"testing"
)

// A device whose config store was scrubbed by an uninstall could not be made to steer again by reinstalling:
// the agent starts, finds no profile, and exits (measured on win-dev-1 2026-08-21 — `sc start DsseSteer`
// returned 1053 after an uninstall/reinstall pair that both reported success). The recovery is an escrowed copy
// of the last verified envelope plus an install action that reads it back. Both halves have to be present, and
// the action has to run at the right point, or the fix is only in the binary and never in the package.
func readWxs(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatalf("read DsseAgent.wxs: %v", err)
	}
	return string(b)
}

func TestTheInstallRestoresAProfileTheUninstallScrubbed(t *testing.T) {
	wxs := readWxs(t)
	if !strings.Contains(wxs, `Id="RestoreProfile"`) {
		t.Fatal("no RestoreProfile custom action: an uninstall/reinstall leaves a device that cannot steer, " +
			"and nothing in the package puts its profile back")
	}
	if !strings.Contains(wxs, `ExeCommand="--restore-profile"`) {
		t.Fatal("RestoreProfile does not pass --restore-profile; profileapply with no recognised flag prints " +
			"its usage and exits, which Return=ignore turns into a silently successful install")
	}
	if !strings.Contains(wxs, `<Custom Action="RestoreProfile"`) {
		t.Fatal("RestoreProfile is defined but never scheduled — a custom action that is not in a sequence " +
			"never runs, and reads in the source exactly like one that does")
	}
}

// The start type is DERIVED from the persisted profile. Restoring the profile after that action has already run
// leaves a box that holds a profile and is still on demand-start: it comes back only at the install after next.
func TestTheProfileIsRestoredBeforeTheStartTypeIsDerivedFromIt(t *testing.T) {
	wxs := readWxs(t)
	restore := strings.Index(wxs, `<Custom Action="RestoreProfile"`)
	reconcile := strings.Index(wxs, `<Custom Action="ReconcileSteerStartType"`)
	if restore < 0 || reconcile < 0 {
		t.Fatalf("both actions must be scheduled (restore=%d reconcile=%d)", restore, reconcile)
	}
	if restore > reconcile {
		t.Fatal("RestoreProfile is scheduled AFTER ReconcileSteerStartType. The start type is derived from the " +
			"persisted profile, so the reconcile would read an empty store and leave DsseSteer on demand-start")
	}
	// The verifier is restored between the profile and service start. Check both dependencies:
	// document order alone does not establish the MSI execution order.
	for _, dependency := range []string{
		`<Custom Action="ReconcileConfigPin" After="RestoreProfile"`,
		`<Custom Action="ReconcileSteerStartType" After="ReconcileConfigPin"`,
	} {
		if !strings.Contains(wxs, dependency) {
			t.Fatalf("missing install dependency %s; profile and verifier must be restored before service start", dependency)
		}
	}
}

// It must run on upgrades as well as fresh installs, and never on the uninstall that is deliberately scrubbing
// the store — restoring a profile during removal would put back exactly what ClearProfile just took out.
func TestTheRestoreRunsOnUpgradesAndNotOnUninstall(t *testing.T) {
	wxs := readWxs(t)
	i := strings.Index(wxs, `<Custom Action="RestoreProfile"`)
	if i < 0 {
		t.Fatal("RestoreProfile is not scheduled")
	}
	line := wxs[i:]
	if j := strings.Index(line, "/>"); j >= 0 {
		line = line[:j]
	}
	if !strings.Contains(line, `Condition="NOT REMOVE"`) {
		t.Fatalf("RestoreProfile must be conditioned NOT REMOVE — an upgrade is the case it exists for, and an "+
			"uninstall is the one case it must not touch. Got: %s", strings.TrimSpace(line))
	}
	if strings.Contains(line, "NOT Installed") {
		t.Fatal("RestoreProfile is conditioned NOT Installed, so it would skip every upgrade — including the " +
			"repair install an administrator runs precisely because the device stopped steering")
	}
}

// Return=check would let a refused escrow roll an install back. The escrow is a recovery convenience; a
// tampered or superseded copy is worth seeing in the log, never worth failing an install over.
func TestARefusedEscrowDoesNotRollTheInstallBack(t *testing.T) {
	wxs := readWxs(t)
	i := strings.Index(wxs, `<CustomAction Id="RestoreProfile"`)
	if i < 0 {
		t.Fatal("RestoreProfile custom action is not defined")
	}
	def := wxs[i:]
	if j := strings.Index(def, "/>"); j >= 0 {
		def = def[:j]
	}
	if !strings.Contains(def, `Return="ignore"`) {
		t.Fatalf("RestoreProfile must be Return=ignore. Got: %s", strings.TrimSpace(def))
	}
	if !strings.Contains(def, `Execute="deferred"`) || !strings.Contains(def, `Impersonate="no"`) {
		t.Fatalf("RestoreProfile writes HKLM and reads %%ProgramData%%, so it needs a deferred, "+
			"non-impersonated action. Got: %s", strings.TrimSpace(def))
	}
	if strings.Contains(def, "[CustomActionData]") {
		t.Fatal("an EXE custom action cannot read CustomActionData — its command line is formatted during the " +
			"immediate phase, so this resolves to the empty string and profileapply runs with no arguments")
	}
}
