package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// The updater reads this value to name the build a rollback is escaping, on a box whose agent cannot say what
// it is running. Nothing else compares the two spellings: the .wxs writes it, a .go file reads it, and a
// rename on either side produces a reader that finds nothing and a rollback that refuses nothing — silently,
// because "no installed version recorded" is a legitimate state.
func TestTheWxsStampsTheInstalledVersionValueTheUpdaterReads(t *testing.T) {
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatalf("read DsseAgent.wxs: %v", err)
	}
	want := `<RegistryValue Name="` + configstore.ValueInstalledVersion + `"`
	if !strings.Contains(string(b), want) {
		t.Fatalf("DsseAgent.wxs does not write a registry value named %q — the updater would find nothing there "+
			"and a rollback on a box with an unreadable running version would refuse nothing, leaving the build "+
			"it just escaped free to come back on the next tick", configstore.ValueInstalledVersion)
	}
}

// ★ The MSI property that admits a deliberate downgrade is named in TWO files that cannot import each other:
// the Go that passes it to msiexec, and the WiX launch condition that reads it. If they drift, the launch
// condition stops matching and every rollback is refused by the guard it was supposed to satisfy — with no
// error anywhere, because both halves are internally consistent and only disagree about a string.
//
// This is the same shape as the macOS executable-name drift (the builder defaulted to one name, the verifier to
// another, nothing compared them). One test comparing them is the whole fix.
func TestTheWxsLaunchConditionUsesTheRollbackPropertyTheUpdaterPasses(t *testing.T) {
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatalf("read DsseAgent.wxs: %v", err)
	}
	wxs := string(b)

	// The condition must name the property, spelled exactly as the Go side passes it.
	want := rollbackstore.RollbackIntentProperty + ` = &quot;1&quot;`
	if !strings.Contains(wxs, want) {
		t.Fatalf("DsseAgent.wxs has no launch condition admitting %q — a declared rollback would be refused by "+
			"the guard it is supposed to satisfy, silently, because both halves are individually correct",
			rollbackstore.RollbackIntentProperty)
	}

	// And it must still REFUSE an undeclared downgrade. An exception that swallowed the rule would be worse
	// than no exception: the guard exists to stop an accidental downgrade, and only the rollback path is
	// entitled to pass it.
	if !strings.Contains(wxs, "NOT WIX_DOWNGRADE_DETECTED OR "+rollbackstore.RollbackIntentProperty) {
		t.Fatal("the downgrade guard is no longer the first term of the launch condition — an operator running " +
			"msiexec by hand on an older package must still be refused")
	}

	// MajorUpgrade generates its own unconditional condition. If it came back, it would sit alongside this one
	// and refuse every rollback regardless — two conditions, one of which silently wins.
	if strings.Contains(wxs, "<MajorUpgrade") {
		t.Fatal("MajorUpgrade is back in DsseAgent.wxs: it generates an unconditional NOT WIX_DOWNGRADE_DETECTED " +
			"launch condition, which would refuse every declared rollback no matter what this one says")
	}

	// Hand-authored upgrade rows do NOT schedule RemoveExistingProducts; MajorUpgrade did. Losing it means an
	// upgrade installs alongside the old product instead of replacing it, which is invisible until a box is
	// running two agents.
	if !strings.Contains(wxs, `<RemoveExistingProducts After="InstallValidate" />`) {
		t.Fatal("RemoveExistingProducts is not scheduled after InstallValidate — with MajorUpgrade gone nothing " +
			"else schedules it, and every upgrade would install beside the old product")
	}
}

// ★ Satisfying the downgrade guard is not the same as being able to roll back, and both halves below were
// found by running one on hardware (win-dev-1, 2026-08-11) rather than by reading the file.
//
// The first: the OTHER launch condition refused. During a rollback the older package is not Installed (its
// ProductCode differs) and is not an upgrade, so the foreign-service guard was left deciding on the presence of
// a DsseSteer service that OUR OWN newer package had registered. msiexec returned 1603 and the journal was left
// saying rolling_back on a box nothing had changed — the false "check this box's network" alarm, recreated in
// the recovery path. It would have fired on every rollback on every box.
//
// The second: with that admitted, the rollback SUCCEEDED and left BOTH products registered, because the
// downgrade Upgrade row was detect-only and RemoveExistingProducts therefore removed nothing. Two products
// sharing one INSTALLDIR and one set of service names is the state that is invisible until something needs
// uninstalling.
func TestADeclaredRollbackIsNotRefusedBySomeOtherGuard(t *testing.T) {
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatalf("read DsseAgent.wxs: %v", err)
	}
	wxs := string(b)

	// Read the actual launch condition. Comparing one full spelling mistook the
	// added same-version exception for removal of the rollback exception.
	guard := regexp.MustCompile(`<Launch\s+Condition="([^"]*FOREIGNSTEERSERVICE[^"]*)"`).FindStringSubmatch(wxs)
	if len(guard) != 2 {
		t.Fatal("foreign-service launch condition missing")
	}
	terms := map[string]bool{}
	for _, term := range strings.Split(guard[1], " OR ") {
		terms[strings.TrimSpace(term)] = true
	}
	for _, term := range []string{"Installed", "WIX_UPGRADE_DETECTED", "WIX_DOWNGRADE_DETECTED", "DSSE_SAMEVERSION_DETECTED", "NOT FOREIGNSTEERSERVICE"} {
		if !terms[term] {
			t.Errorf("foreign-service guard is missing the %q case", term)
		}
		delete(terms, term)
	}
	if len(terms) != 0 {
		t.Errorf("unexpected foreign-service exception(s): %v", terms)
	}

	// The downgrade row must be one RemoveExistingProducts acts on. OnlyDetect is what MajorUpgrade generated,
	// and it is correct only for a product that can never go backwards.
	if regexp.MustCompile(`(?s)<UpgradeVersion[^>]*WIX_DOWNGRADE_DETECTED`).FindString(wxs) == "" {
		t.Fatal("no UpgradeVersion row sets WIX_DOWNGRADE_DETECTED — the downgrade guard has nothing to fire on")
	}
	row := regexp.MustCompile(`(?s)<UpgradeVersion[^>]*Property="WIX_DOWNGRADE_DETECTED"[^>]*/>`).FindString(wxs)
	if row == "" {
		row = regexp.MustCompile(`(?s)<UpgradeVersion[^>]*OnlyDetect[^>]*>\s*`).FindString(wxs)
	}
	if strings.Contains(row, `OnlyDetect="yes"`) {
		t.Errorf("the downgrade row is detect-only:\n%s\n\nRemoveExistingProducts does not remove a detect-only "+
			"match, so an authorised rollback installs the older product BESIDE the newer one — two products, "+
			"one INSTALLDIR, one set of service names", row)
	}
}

// stashFlag is the flag profileapply reads the package path from. Named here once and asserted against BOTH
// files below, because it is a string shared by a .wxs and a package main that cannot import each other.
const stashFlag = "--stash-rollback-msi"

// customActionRe matches one <CustomAction .../> element. The .wxs is small, hand-maintained and namespaced;
// a scan for the element beats pulling in an XML decode that would have to be taught the WiX schema.
var customActionRe = regexp.MustCompile(`(?s)<CustomAction\s.*?/>`)

// ★ The install stashes the package a later rollback needs, and it did so by passing the path on profileapply's
// command line. THE PATH NEVER ARRIVED, and the install still reported success.
//
// A deferred EXE custom action has no MsiGetProperty call to make: its command line is the Target column, which
// MSI formats while WRITING the execution script — in the immediate phase, where properties are still readable.
// So the CustomActionData indirection (correct for a deferred DLL or script action) resolved "[CustomActionData]"
// to the EMPTY STRING right there, and profileapply ran with no arguments, printed its usage, and exited 2.
// Return="ignore" then turned that into a clean install with no rollback material, on every box, forever — the
// exact state the action exists to prevent. Measured on win-dev-1 2026-08-11; see the comment above the action.
//
// Two assertions, because the wrong one alone would not have caught it: that this action still passes a path,
// and that NO exe custom action reverts to the indirection that silently yields nothing.
func TestTheStashCustomActionReceivesThePackagePath(t *testing.T) {
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatalf("read DsseAgent.wxs: %v", err)
	}
	wxs := string(b)

	var stash string
	for _, ca := range customActionRe.FindAllString(wxs, -1) {
		if strings.Contains(ca, `Id="StashRollbackMsi"`) {
			stash = ca
		}
		// The class rule, not just this one action: every custom action in this package launches an EXE
		// (FileRef or BinaryRef), so a command line naming CustomActionData is a command line that will be
		// empty at execute time — and Return="ignore" means nobody finds out.
		if strings.Contains(ca, "ExeCommand") && strings.Contains(ca, "[CustomActionData]") {
			t.Errorf("an EXE custom action passes [CustomActionData] on its command line:\n%s\n\n"+
				"MSI formats an exe action's Target when it writes the execution script, so this resolves to "+
				"the empty string and the program is launched with no arguments — a failure that Return=ignore "+
				"turns into a successful install. Write the property reference straight into ExeCommand.", ca)
		}
	}

	if stash == "" {
		t.Fatal("the StashRollbackMsi custom action is gone from DsseAgent.wxs — no install would keep the " +
			"package a later rollback needs, and agentupdate.Run refuses every update on a box with no " +
			"restore material")
	}
	if !strings.Contains(stash, stashFlag) || !strings.Contains(stash, "[OriginalDatabase]") {
		t.Fatalf("the StashRollbackMsi command line no longer passes the package path:\n%s\n\n"+
			"it must carry %s with [OriginalDatabase], which MSI expands while writing the execution script",
			stash, stashFlag)
	}

	// And the flag has to be one profileapply actually defines: Go's flag package exits 2 on an unknown flag,
	// which is indistinguishable from the no-arguments failure above and just as invisible behind Return=ignore.
	mainGo, err := os.ReadFile("cmd/profileapply/main.go")
	if err != nil {
		t.Fatalf("read cmd/profileapply/main.go: %v", err)
	}
	if !strings.Contains(string(mainGo), `flag.String("`+strings.TrimPrefix(stashFlag, "--")+`"`) {
		t.Fatalf("profileapply does not define %s — the installer would pass a flag the program rejects, "+
			"exiting 2 into a Return=ignore action that reports success", stashFlag)
	}
}

// ★★★ THE TWO ARTEFACTS A CUSTOMER RECEIVES HAVE TO REACH THE INSTALLER (2026-08-29, after walking the install
// on win-dev-1). Every organization-specific fact used to be a build-time input, so "a generic installer, a
// profile and a token" described a path that did not exist on Windows. CONFIG and TOKEN are that path.
func TestTheInstallerAcceptsAProfileAndATokenAtInstallTime(t *testing.T) {
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatalf("read DsseAgent.wxs: %v", err)
	}
	wxs := string(b)
	for _, prop := range []string{`<Property Id="CONFIG"`, `<Property Id="TOKEN"`, `<Property Id="PIN"`} {
		if !strings.Contains(wxs, prop) {
			t.Fatalf("the package declares no %s — a customer cannot hand it what the Console gave them", prop)
		}
	}
	if !strings.Contains(wxs, `Id="ProvisionFromConsole"`) {
		t.Fatal("nothing turns CONFIG/TOKEN into a provisioned device")
	}
	if !strings.Contains(wxs, `ExeCommand="--provision --config &quot;[CONFIG]&quot; --token &quot;[TOKEN]&quot; --pin-file &quot;[PIN]&quot;"`) {
		t.Fatal("the provision action does not pass all three artefacts on its command line")
	}
	// ★ Return=check, unlike the BUNDLED profile's ApplyProfile. A bundled profile that fails leaves a package
	// merely built without one; a profile the operator just typed failing is a mistake in what they are doing
	// now, and installing anyway hands them a device that looks installed and steers nothing.
	i := strings.Index(wxs, `Id="ProvisionFromConsole"`)
	end := i + 400
	if end > len(wxs) {
		end = len(wxs)
	}
	if seg := wxs[i:end]; !strings.Contains(seg, `Return="check"`) {
		t.Fatalf("the provision action does not fail the install when it fails:\n%s", seg)
	}
	// It must run only when the operator supplied a profile, or every ordinary install would fail on an
	// absent one.
	if !strings.Contains(wxs, `Action="ProvisionFromConsole" After="HardenConfigStore" Condition="CONFIG AND NOT REMOVE"`) {
		t.Fatal("the provision action is not conditioned on CONFIG being supplied, or is sequenced somewhere else")
	}
	// And before RestoreProfile, so a profile handed over now wins over an escrowed one from before.
	if strings.Index(wxs, `Action="ProvisionFromConsole"`) > strings.Index(wxs, `Action="RestoreProfile"`) {
		t.Fatal("the escrowed profile is restored before the one the operator just supplied")
	}
}
