package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ AN UNINSTALL TAKES BACK WHAT PROVISIONING TRUSTED (2026-09-03, measured while tearing a lab down:
// msiexec removed the services, the driver and the binaries, and removed not one certificate).
func TestUninstallTakesBackWhatProvisioningTrusted(t *testing.T) {
	// The mode exists and is wired, so a package can call it.
	main, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), `flag.Bool("remove-what-provisioning-trusted"`) {
		t.Fatal("there is no uninstall mode for the anchors provisioning installs, so the lane this product " +
			"ships leaves an organization's interception root trusted on a machine that no longer runs the agent")
	}
	if !strings.Contains(string(main), "doRemoveEverythingProvisioningTrusted(") {
		t.Error("the flag exists but calls nothing")
	}

	// It names the two artefacts provisioning writes when it trusts something — and NOT transport_ca.pem,
	// which is written for the agent to verify the Edge with and never enters the machine's trust store.
	body, err := os.ReadFile("everything_provisioning_trusted_comes_back_out.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{`"interception-root.pem"`, `"step_up_portal_ca.pem"`} {
		if !strings.Contains(src, want) {
			t.Errorf("%s is installed into the trust store by provisioning and never taken back", want)
		}
	}
	if strings.Contains(src, `"transport_ca.pem"`) {
		t.Error("transport_ca.pem is not in the machine's trust store; removing it would be removing " +
			"something this never put there")
	}

	// The package schedules it on uninstall, and NOT gated on the build-time interception root — that gate is
	// what left the shipped lane with no removal at all.
	wxs, err := os.ReadFile(filepath.Join("..", "..", "DsseAgent.wxs"))
	if err != nil {
		t.Skip("the package file is not here")
	}
	w := string(wxs)
	if !strings.Contains(w, `Action="RemoveProvisionedAnchors"`) {
		t.Fatal("the package never runs the removal")
	}
	i := strings.Index(w, `<Custom Action="RemoveProvisionedAnchors"`)
	if j := strings.LastIndex(w[:i], "<?ifdef"); j >= 0 {
		if k := strings.LastIndex(w[:i], "<?endif?>"); k < j {
			t.Error("the removal is inside a build-time conditional again — that is exactly what left the " +
				"shipped lane without one")
		}
	}
	if !strings.Contains(w[i:i+220], `REMOVE~=&quot;ALL&quot;`) {
		t.Error("the removal is not conditioned on a full uninstall")
	}
	if !strings.Contains(w[i:i+220], `Before="RemoveFiles"`) {
		t.Error("the removal runs after the artefacts it reads have been deleted, so it can name nothing")
	}
}
