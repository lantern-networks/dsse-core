package main

import (
	"os"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/installprofile"
)

// ★★★ A MACHINE ADDS NOTHING TO ITS TRUST STORE WHEN THE PORTAL IS THE OPERATOR'S (2026-09-03, the
// operator's question settled the design).
//
// They asked: the authority expansion is for WebView's sake — but is that not because it is Keycloak? With
// Entra ID, would the device not display it perfectly well? Counting the hops answers it. The ceremony makes
// three navigations and only the middle one is the identity provider:
//
//  1. the DSSE portal        2. Entra ID / Okta / Keycloak        3. the DSSE portal again
//
// Moving to Entra ID fixes hop 2 and leaves 1 and 3 on a certificate this deployment issued itself. What
// fixes those is the operator's own certificate for the portal — which they had already decided to provide —
// and once they have, there is nothing for a device to add.
//
// So the anchor install is the LAB's answer, and this holds that it stays that way. A machine that quietly
// widened its trust store for a lab would carry that for the rest of its life.
func TestNothingIsTrustedWhenThePortalIsTheOperators(t *testing.T) {
	body, err := os.ReadFile("provision_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	install := strings.Index(src, "doInstallTrustAnchor(portalAnchorPath,")
	if install < 0 {
		t.Fatal("the portal's own authority is never installed — a lab could not complete a step-up at all")
	}
	guard := strings.LastIndex(src[:install], "if plan.StepUpPortalCertificateIsOperators {")
	if guard < 0 {
		t.Fatal("the anchor install is not gated on who the portal's certificate belongs to — every machine " +
			"would widen its trust store even where the portal is publicly trusted")
	}
	// The install must be in the ELSE arm, not the same arm as "nothing is added".
	arm := src[guard:install]
	if !strings.Contains(arm, "} else {") {
		t.Error("the anchor is installed in the same branch as the case that adds nothing")
	}
	// And the machine says which case it is in. Silence here is a trust decision nobody can audit later.
	if !strings.Contains(arm, "nothing is added") {
		t.Error("a machine that adds nothing does not say so")
	}

	// The fact travels: profile -> material -> plan.
	m, err := installprofile.DeriveDeployment(installprofile.DeploymentSpec{
		TransportAnchorsPEM:                []string{"-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----"},
		StepUpPortalCertificateIsOperators: true,
	})
	if err == nil && !m.StepUpPortalCertificateIsOperators {
		t.Error("the profile says the portal is the operator's and the material does not carry it")
	}
}

// ★ AN INSTALL SAYS WHAT IT IS INSTALLING (2026-09-03, reported from the Windows box).
//
// The transport anchor goes in through the same code path as the interception root, and that path announced
// BOTH as "interception root INSTALLED" — while the next line called the same act "this organization's
// transport anchor is trusted by this machine". One operation, two names, adjacent lines. An operator
// reading the log would take a transport anchor for an inspection authority.
func TestTheInstallNamesWhatItInstalls(t *testing.T) {
	body, err := os.ReadFile("interception_root_windows.go")
	if err != nil {
		t.Skip("windows-only source not present")
	}
	if strings.Contains(string(body), `"profileapply: interception root INSTALLED`) {
		t.Error("the trust-store install hard-codes \"interception root\", so installing anything else " +
			"through it announces the wrong thing")
	}
	caller, err := os.ReadFile("provision_windows.go")
	if err != nil {
		t.Skip()
	}
	if !strings.Contains(string(caller), `doInstallTrustAnchor(portalAnchorPath, "the step-up portal's authority")`) {
		t.Error("the portal's authority is installed without naming itself")
	}
}
