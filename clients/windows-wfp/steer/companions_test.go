package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The miss this exists to stop: dsse-stepup-window.exe was implemented, wired into the step-up path, and never
// added to the installer. The runtime lookup falls back to the default browser when the file is absent, so the
// ceremony kept working and the feature simply never ran on an installed agent — for weeks, silently.
//
// A companion the code resolves at runtime but the MSI does not install is not a degraded feature, it is a
// feature that does not exist in the field. This turns that into a build failure at the moment the code is
// written, which is the only point where it is cheap to notice.
func TestEveryRuntimeCompanionIsInstalledByTheMSI(t *testing.T) {
	wxsPath := filepath.Join("..", "packaging", "DsseAgent.wxs")
	raw, err := os.ReadFile(wxsPath)
	if err != nil {
		t.Fatalf("read %s: %v — the packaging manifest is the authority on what reaches an installed agent", wxsPath, err)
	}
	// Substring match on the Source attribute, deliberately: the manifest is XML whose line endings depend on
	// the checkout (this repository has been bitten by whole-line comparison against CRLF more than once), and
	// what matters is that the file is named as an installed Source, not how the element is formatted.
	wxs := string(raw)

	if len(runtimeCompanions) == 0 {
		t.Fatal("runtimeCompanions is empty — if the agent no longer resolves sibling executables, delete this test with the table")
	}
	for _, c := range runtimeCompanions {
		if c.Exe == "" || c.Purpose == "" || c.IfMissing == "" {
			t.Errorf("companion %+v is incompletely declared: the startup warning needs a purpose AND the consequence of it being absent", c)
		}
		if !strings.Contains(wxs, `Source="`+c.Exe+`"`) {
			t.Errorf("the agent resolves %q at runtime but %s does not install it.\n"+
				"A companion that is not packaged never reaches a real deployment — the feature will silently "+
				"fall back forever (%s).\n"+
				"Fix: add a <File ... Source=%q/> to the manifest, not this test.",
				c.Exe, wxsPath, c.IfMissing, c.Exe)
			continue
		}
		// Declaring the File is not enough: a Component that no Feature references is compiled into the MSI and
		// installs nothing. Caught while adding the step-up window — the same silent-gap shape one level down,
		// and it would have produced an installer that still shipped no window.
		id := componentIDForFile(wxs, c.Exe)
		if id == "" {
			t.Errorf("%s installs %q but its <Component Id=...> could not be determined; the Feature wiring cannot be checked", wxsPath, c.Exe)
			continue
		}
		if !strings.Contains(wxs, `<ComponentRef Id="`+id+`"`) {
			t.Errorf("%s declares Component %q for %q but no <Feature> references it.\n"+
				"An unreferenced Component installs NOTHING — the MSI would build clean and still ship no %s.\n"+
				"Fix: add <ComponentRef Id=%q /> inside the Feature.",
				wxsPath, id, c.Exe, c.Exe, id)
		}
	}

	// Third link in the same chain, and the one that caught the author of this test out: the manifest names a
	// Source file, but something has to PRODUCE it into the staging directory. A companion that is declared and
	// referenced but never built fails the MSI build itself — later, and further from the change.
	buildPath := filepath.Join("..", "packaging", "build-msi.ps1")
	build, err := os.ReadFile(buildPath)
	if err != nil {
		t.Fatalf("read %s: %v", buildPath, err)
	}
	for _, c := range runtimeCompanions {
		if !strings.Contains(string(build), c.Exe) {
			t.Errorf("%s never builds %q, so the MSI has no file to package.\n"+
				"Declaring it in the manifest is not enough — add a `go build -o (Join-Path $stage %q) ...` line.",
				buildPath, c.Exe, c.Exe)
		}
	}
}

// componentIDForFile finds the Component Id that owns the <File Source="exe">, by scanning backwards from the
// File element to the nearest preceding Component Id. Deliberately simple: this checks wiring, and a manifest
// convoluted enough to defeat it is itself worth failing on.
func componentIDForFile(wxs, exe string) string {
	at := strings.Index(wxs, `Source="`+exe+`"`)
	if at < 0 {
		return ""
	}
	before := wxs[:at]
	open := strings.LastIndex(before, `<Component Id="`)
	if open < 0 {
		return ""
	}
	rest := before[open+len(`<Component Id="`):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// The lookup and the declaration must not drift: the step-up path resolves whatever the table says, so a
// rename in one place cannot leave the other pointing at a file that is no longer installed.
func TestStepUpWindowCompanionIsDeclared(t *testing.T) {
	var found bool
	for _, c := range runtimeCompanions {
		if c.Exe == "dsse-stepup-window.exe" {
			found = true
		}
	}
	if !found {
		t.Fatal("dsse-stepup-window.exe is not in runtimeCompanions — the step-up path resolves it, so it must be declared and packaged")
	}
}
