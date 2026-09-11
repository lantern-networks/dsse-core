package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ ONE CONSTANT WAS MISSING AND THE DEVICE INTERCEPTED WITHOUT CARRYING ANYTHING (2026-08-29, measured).
//
// A Mac installed the documented way presented a real intercepted certificate — issued by its own
// organization's interception CA, for example.com, google and github — and then not one HTTP request
// completed. Chrome rendered nothing; curl was 0 of 15; the provider logged round_trip_timeout 82 times.
//
// The cause was `network_extension_runtime_copy_tunnel_enabled`. The control plane's snapshot publisher has
// written it since the tunnel existed, with the reason beside it: without it the extension falls back to the
// half-duplex session path, where every exchange is a separate request with a five-second deadline, and real
// sites break. The installer derives the same configuration from the deployment's profile — and its own
// comment says it states what the publisher states — but it did not state this one.
//
// So this test compares the two derivations rather than trusting either. It reads the KEYS the publisher
// writes unconditionally and requires the installer's derivation to write them too. A key the publisher only
// writes when something is configured is not required here; a constant is.
func TestTheInstallerStatesTheRuntimeCopyConstantsThePublisherStates(t *testing.T) {
	publisher := readFileForTest(t, "network_extension_snapshot_publisher.go")
	installer := readFileForTest(t, "../../clients/macos-network-extension/packaging/build_macos_ne_pkg.sh")

	// Unconditional assignments: `config["network_extension_..."] = <literal>` at one tab of indentation,
	// i.e. not inside an `if`. Those are the product's constants rather than the deployment's values.
	re := regexp.MustCompile(`(?m)^\tconfig\["(network_extension_runtime_copy_[a-z_]+)"\] = (true|false)$`)
	found := 0
	for _, m := range re.FindAllStringSubmatch(publisher, -1) {
		found++
		if !strings.Contains(installer, `"`+m[1]+`"`) {
			t.Errorf("the control plane publishes %s=%s to every device, and the installer's derivation does "+
				"not mention it — a device installed from a profile then runs on a different datapath from "+
				"one configured by the control plane, which is the shape that made a Mac intercept and carry "+
				"nothing", m[1], m[2])
		}
	}
	if found == 0 {
		t.Fatal("no unconditional runtime-copy constants found in the publisher — this test is measuring nothing")
	}
}

func readFileForTest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
