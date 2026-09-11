// dsse-profileverify — verify a signed install profile against a pin the operator placed, and print what it says.
//
// ★★★ THE INSTALLER TOOK THE VERIFYING KEY OUT OF THE THING IT WAS VERIFYING (2026-08-29). The macOS package's
// postinstall decoded install_profile.json without checking its signature, read
// deployment.agent_policy_signing_public_key out of the decoded body, and wrote that as the device's pin — so
// the profile supplied the key that proves the profile. A substituted profile signed with its author's own key
// verified perfectly, and it decides where the device connects, which authorities it trusts on arrival, which
// keys may sign its updates, and which processes are exempt from steering. The signature was doing no work.
//
// The Windows session reached the same question from the other side, refused to take the shortcut, and asked
// for a decision. The decision (2026-08-29): the pin travels BESIDE the token — a fourth artefact the operator
// places, exactly like the one-time token, because placing it is an explicit act and one signed installer then
// serves every deployment.
//
// This tool exists because macOS cannot do the check itself: the postinstall's only crypto tool is
// /usr/bin/openssl, which is LibreSSL, and it will not even load an Ed25519 public key. So the verifier travels
// with the package, like the uninstaller and the install verifier do, for the same reason — the one moment it
// is needed is on a machine nobody can clone this repository onto.
//
// It prints the VERIFIED payload as JSON on stdout and nothing else, so a caller can pipe it straight into the
// derivation. Any failure is a non-zero exit and a sentence on stderr naming which failure it was.
//
// ★★★ AND IT SAYS WHAT THE PROFILE MEANS, ON STDERR. macos-agent.md tells the operator to run this before
// installing, and says it "prints what the device would join — which organization, which doors, whether an
// interception root is carried and whether it is the organization's own". It did not: it printed the payload,
// with two certificates and a base64 blob in it, and the reader had to know which keys to look for. The page
// was describing something that did not exist, on the one check it puts in front of every device install.
//
// The summary goes to STDERR because stdout is a contract: the macOS postinstall pipes it into the
// derivation. A person sees both; a pipeline sees what it always saw.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/installprofile"
)

func main() {
	profilePath := flag.String("profile", "", "path to the signed install profile (dsse_install_profile.v1 envelope)")
	pinPath := flag.String("pin", "", "path to the file holding the deployment's profile-signing public key (hex)")
	flag.Parse()

	if strings.TrimSpace(*profilePath) == "" || strings.TrimSpace(*pinPath) == "" {
		fmt.Fprintln(os.Stderr, "dsse-profileverify: -profile and -pin are both required. The pin is not read from "+
			"the profile: a document cannot carry the key that proves it.")
		os.Exit(2)
	}
	envelope, err := os.ReadFile(*profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-profileverify: cannot read the profile at %s: %v\n", *profilePath, err)
		os.Exit(2)
	}
	pinRaw, err := os.ReadFile(*pinPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-profileverify: cannot read the signing key at %s: %v\n"+
			"  This is the deployment's profile-signing key. The Console shows it beside the profile; the\n"+
			"  operator places it on the device, the same way the one-time enrolment token is placed.\n",
			*pinPath, err)
		os.Exit(2)
	}
	pin := strings.TrimSpace(string(pinRaw))
	if pin == "" {
		fmt.Fprintf(os.Stderr, "dsse-profileverify: %s is empty. An empty pin is not 'no pin' — it is a pin that "+
			"matches nothing, and refusing here is better than deriving a configuration nothing verified.\n", *pinPath)
		os.Exit(2)
	}

	profile, verified, err := installprofile.Load(envelope, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-profileverify: the profile does not load: %v\n", err)
		os.Exit(1)
	}
	if !verified {
		fmt.Fprintf(os.Stderr, "dsse-profileverify: the profile is NOT signed by the key in %s.\n"+
			"  Either this profile came from somewhere else, or this device was given the wrong deployment's\n"+
			"  key. Nothing is derived from it. The device keeps whatever configuration it already had.\n", *pinPath)
		os.Exit(1)
	}
	out, err := json.Marshal(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-profileverify: the profile verified but will not re-encode: %v\n", err)
		os.Exit(1)
	}
	summarise(os.Stderr, profile)
	fmt.Println(string(out))
}

// summarise says what the device would join, in the order a person checks it.
func summarise(w io.Writer, p installprofile.InstallProfile) {
	line := func(label, value string) { fmt.Fprintf(w, "  %-26s %s\n", label, value) }
	fmt.Fprintf(w, "dsse-profileverify: signed by the pinned key. This is what the device would join.\n")

	// ★ THE ORGANIZATION FIRST, because every device-side problem worth the name starts here: a profile
	// minted without naming a customer organization puts the device in the OPERATOR's, and from there every
	// screen reports success while nothing is per-tenant.
	org := strings.TrimSpace(p.Organization.TenantID)
	if org == "" {
		org = strings.TrimSpace(p.TenantID)
	}
	line("organization", org)
	line("posture", orNone(p.Posture))

	// The doors. The transport URL is the region's; the organization's own name is what makes the Edge serve
	// this organization's material rather than the deployment's.
	line("transport", orNone(p.TransportURL))
	if len(p.TransportEndpoints) > 0 {
		line("regions", strings.Join(p.TransportEndpoints, ", "))
	}
	line("this organization's door", orNone(p.Organization.TransportServerName))
	line("enrolment door", orNone(p.Organization.EnrolmentServerName))

	// ★★★ THE ANSWER THE PAGE SENDS PEOPLE HERE FOR. A profile carrying no interception root leaves every
	// link after it empty — no trusted CA bundle on the device, and every tool that reads one failing with
	// nothing able to explain why. One that carries the DEPLOYMENT's says the organization has no authority
	// of its own yet, which is a different thing and worth knowing before the install rather than after.
	switch {
	case strings.TrimSpace(p.Deployment.InterceptionRootPEM) == "":
		line("interception root", "NONE — a device installed from this profile has no CA to trust for "+
			"inspected traffic, and every tool that verifies TLS will fail on it")
	case p.Deployment.InterceptionRootIsOwn:
		line("interception root", "this organization's own")
	default:
		line("interception root", "the DEPLOYMENT's, shared — this organization has no authority of its own yet")
	}

	if strings.TrimSpace(p.Deployment.DeviceCAPinSHA256) == "" {
		line("device CA pin", "NONE — the device cannot pin the CA that issues its own identity")
	} else {
		line("device CA pin", p.Deployment.DeviceCAPinSHA256)
	}
	if strings.TrimSpace(p.Deployment.AnchorPEM) == "" {
		line("deployment anchor", "NONE")
	}
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "NONE"
	}
	return s
}
