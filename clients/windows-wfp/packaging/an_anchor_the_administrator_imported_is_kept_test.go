package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Found 2026-11-08 on acceptance C: after a clean uninstall, the check reported "FAIL still TRUSTED … Acceptance
// C Root CA" and exited 1. That root was the deployment anchor the administrator imported by hand to reach the
// Console, carried only by transport_ca.pem, which provisioning never puts in a trust store and the uninstall
// never takes back. The first fix read "any record on this machine" as "this package recorded everything", and
// review C2R1 showed that lets an interception root survive when an upgrade from 0.4.0 stops between files: the
// portal's record exists, the interception root has only the older package's note, the uninstall owns it, and the
// check called it kept. So the check decides each file the way the uninstall does.

// The files the uninstall takes trust back from, read from its source.
func uninstallTakesBackFrom(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("cmd/profileapply/everything_provisioning_trusted_comes_back_out.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func doRemoveEverythingProvisioningTrusted(")
	loop := strings.Index(src[start:], "for _, name := range []string{")
	end := strings.Index(src[start+loop:], "} {")
	if start < 0 || loop < 0 || end < 0 {
		t.Fatal("the uninstall's list of files is not where this test reads it")
	}
	var out []string
	for _, m := range regexp.MustCompile(`"([^"]+\.pem)"`).FindAllStringSubmatch(src[start+loop:start+loop+end], -1) {
		out = append(out, m[1])
	}
	return out
}

func TestTheCheckJudgesTheFilesTheUninstallTakesBackFrom(t *testing.T) {
	section := afterUninstallSection(t)
	m := regexp.MustCompile(`\$takenBack = @\(([^)]*)\)`).FindStringSubmatch(section)
	if m == nil {
		t.Fatal("the check no longer names the files the uninstall takes trust back from")
	}
	var named []string
	for _, q := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(m[1], -1) {
		named = append(named, q[1])
	}
	if want := uninstallTakesBackFrom(t); strings.Join(named, ",") != strings.Join(want, ",") {
		t.Fatalf("the check judges %v, the uninstall takes back from %v", named, want)
	}
}

func TestEachFileIsOwnedTheWayTheUninstallOwnsIt(t *testing.T) {
	section := afterUninstallSection(t)
	if strings.Contains(section, "$recording") || strings.Contains(section, "Filter '*.added-by-provisioning'") {
		t.Fatal("ownership is decided from a record anywhere on the machine again; a record of one file says nothing about another")
	}
	// Per file: the record, else the older package's note, else everything in it (onlyWhatProvisioningAdded).
	record := strings.Index(section, `if (Test-Path "$p.added-by-provisioning")`)
	note := strings.Index(section, `elseif (Test-Path "$p.trusted-by-older-package")`)
	all := strings.Index(section, `$ownsAll = $true`)
	if record < 0 || note < 0 || all < 0 || !(record < note && note < all) {
		t.Fatal("a file's owner is not decided record, then note, then everything")
	}
	if !strings.Contains(section, `if (($takenBack -contains $pem) -and ($ownsAll -or ($owned -contains $sha))) { $e.Owned = $true }`) {
		t.Fatal("a root is marked owned by something other than a file the uninstall takes back")
	}
	if !strings.Contains(section, `if ($e.Owned) { $left[$k] = $e } else { $kept[$k] = $e.Cert }`) {
		t.Fatal("what fails is no longer exactly what the uninstall owned and left")
	}
	// The file the administrator's anchor travels in is read, so it can be named as kept, but never owns.
	if !strings.Contains(section, `$takenBack + @('transport_ca.pem','trust_anchors_adopted.pem')`) {
		t.Fatal("transport_ca.pem is no longer read, so a kept anchor would go unreported")
	}
}
