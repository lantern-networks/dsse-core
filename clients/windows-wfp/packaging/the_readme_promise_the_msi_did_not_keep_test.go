package packaging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE README PROMISED SOMETHING THE PACKAGE DID NOT DO (2026-09-07, measured on a Windows box by
// following the published instructions exactly).
//
// The Console writes one README into the device folder and sends it to every platform: "The installer takes
// install_profile.json, profile_signing_key.txt and enrolment_token.txt from the folder it is opened from."
// True on macOS. Here, provisioning was conditioned on the CONFIG property, which has no default, so
// `msiexec /i` from that folder never scheduled it. Exit 0, services running, nothing provisioned — and not
// even logged as skipped, because MSI does not mention an action whose condition is false.
//
// On a box that had been installed before, the agent then came up bound to a deployment destroyed the day
// before, because that deployment's profile was still in %ProgramData%\DSSE\ and nothing had replaced it.
//
// This reads the shipped WiX as text, which is what the Go tests in this package can do; the WiX build is
// what catches a malformed element.
func TestTheReadmePromiseIsKeptOnWindows(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("DsseAgent.wxs"))
	if err != nil {
		t.Fatalf("read the package definition: %v", err)
	}
	wxs := string(raw)

	if !strings.Contains(wxs, `Id="ProvisionFromInstallerFolder"`) {
		t.Fatal("nothing provisions from the folder the package was opened from, which is what the README the " +
			"Console writes into that folder says the installer does — so a plain msiexec /i installs a green, " +
			"unconfigured agent and says nothing")
	}
	if !strings.Contains(wxs, `--from-installer-folder &quot;[OriginalDatabase]&quot;`) {
		t.Error("the folder is not taken from the package's own path; OriginalDatabase is the one that needs " +
			"no ResolveSource")
	}
	if !strings.Contains(wxs,
		`<Custom Action="ProvisionFromInstallerFolder" After="ProvisionFromConsole" Condition="NOT CONFIG AND NOT REMOVE" />`) {
		t.Error("the folder action must run only when nobody passed CONFIG, and after the explicit one, so a " +
			"path an operator typed always wins over what happens to be lying beside the package")
	}
	// The explicit path keeps its strictness: a path somebody typed and got wrong is a mistake in the act
	// they are performing, and installing anyway hands them a device that looks installed and steers nothing.
	if !strings.Contains(wxs, `<Custom Action="ProvisionFromConsole" After="HardenConfigStore" Condition="CONFIG AND NOT REMOVE" />`) {
		t.Error("the explicit CONFIG action changed; it must still be conditioned on CONFIG alone")
	}
}
