package main

import (
	"fmt"
	"strings"
	"testing"
)

const testRootPEM = `-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQGiE5gX0pz6b1SRCuTHmahjAKBggqhkjOPQQDAjA8MRgw
FgYDVQQKEw9IaWthcmkgTmV0d29ya3MxIDAeBgNVBAMTF0hpa2FyaSBOZXR3b3Jr
cyBSb290IENBMB4XDTI2MDgyODIzMzEwMFoXDTM2MDgyOTAwMzEwMFowPDEYMBYG
A1UEChMPSGlrYXJpIE5ldHdvcmtzMSAwHgYDVQQDExdIaWthcmkgTmV0d29ya3Mg
Um9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABORvwqUkl4CWnNd1VRiR
N+MhkR6IDRVeJ7axdHyLQCUnGfI6VvpQqlKeG0tlobzc5omSd+A9DF+9J/gGH+eb
fg6jQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSkcysvMNSON0nOOVnDl7b2c7u0bjAKBggqhkjOPQQDAgNIADBFAiEA1C6d+OeM
DlZFlPntK1ME6Qg/AEajymHlEKcTzVUsW+8CIDvS9NM6k8KC3EB/O74RmLtq/0l/
KfuwhmPl0V7gzIQp
-----END CERTIFICATE-----
`

// ★★★ "A TLS ERROR" NAMES THREE DIFFERENT FAULTS (2026-08-29, the Mac session lost a round trip to exactly
// this and recommended the fix; both clients now say the same thing). Wrong authority, no authority, and an
// unparseable one produce the same handshake failure and have three different fixes.
func TestTheEnrolmentBootstrapSaysWhichOfTheThreeItIs(t *testing.T) {
	pinned := describeBootstrapPinning(testRootPEM, "4c129d79", "sakura.example", nil)
	line := pinned.Line()
	if pinned.Unpinned != "" {
		t.Fatalf("a real CA was reported as unpinned: %q", line)
	}
	for _, want := range []string{"pinned to 1 authority", "Hikari Networks Root CA", "sakura.example", "4c129d79"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the line does not carry %q: %s", want, line)
		}
	}

	// Unparseable is NOT the same as absent, and the message must not merge them.
	broken := describeBootstrapPinning("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n", "", "", nil)
	if broken.Unpinned == "" || !strings.Contains(broken.Line(), "no usable certificate") {
		t.Fatalf("an unparseable CA was not reported as such: %s", broken.Line())
	}
	failed := describeBootstrapPinning(testRootPEM, "", "", fmt.Errorf("pool rejected it"))
	if !strings.Contains(failed.Line(), "pool rejected it") {
		t.Fatalf("the reason the CA could not be used was dropped: %s", failed.Line())
	}

	// Nothing at all.
	none := describeBootstrapPinning("", "", "", nil)
	if !strings.Contains(none.Line(), "UNPINNED") || !strings.Contains(none.Line(), "neither") {
		t.Fatalf("a wholly unpinned bootstrap did not say so: %s", none.Line())
	}
}

// ★ A DEVICE-CA FINGERPRINT ALONE IS NOT A PINNED CHANNEL, and the difference has to be readable. The endpoint
// is verified by the operating system's store; the only refusal left happens AFTER the one-time token is spent.
func TestADeviceCAFingerprintAloneIsReportedAsTheWeakerThingItIs(t *testing.T) {
	p := describeBootstrapPinning("", "4c129d79", "", nil)
	if p.Unpinned == "" {
		t.Fatal("a channel verified by the public trust store was reported as pinned")
	}
	line := p.Line()
	for _, want := range []string{"operating system", "token is spent", "4c129d79"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the line does not carry %q: %s", want, line)
		}
	}
}

// The line is printed on success too. One that appears only on failure cannot be compared against a machine
// that works, which is what makes a fleet debuggable at all.
func TestTheLineIsUnambiguousAboutWhatWasPresented(t *testing.T) {
	withName := describeBootstrapPinning(testRootPEM, "", "sakura.example", nil).Line()
	if !strings.Contains(withName, "name presented: sakura.example") {
		t.Fatalf("%s", withName)
	}
	withoutName := describeBootstrapPinning(testRootPEM, "", "", nil).Line()
	if !strings.Contains(withoutName, "no name presented") {
		t.Fatalf("%s", withoutName)
	}
	if !strings.Contains(withoutName, "issued device CA is NOT pinned") {
		t.Fatalf("an unpinned issued-CA was not stated: %s", withoutName)
	}
}
