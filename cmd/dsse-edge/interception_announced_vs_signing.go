package main

import (
	"fmt"
	"sort"
	"strings"
)

// interception_announced_vs_signing.go — does this node tell an organization's devices to look for the root its
// traffic is actually signed under?
//
// ★★★ NOTHING ASKED THAT, AND THE CHECK BUILT TO PREVENT THE OUTAGE WAS GREEN THROUGH IT (2026-08-19, reported
// from win-dev-1).
//
// Measured on that box with steering armed: github.com arrived as CN=github.com signed by "Lab Tenant
// Interception Issuing CA 2028" under a self-signed "Lab Tenant Interception Root 2028" — a root in no store on
// the machine, in neither LocalMachine nor CurrentUser. schannel refused it as well, so this was not a Node
// story: EVERY HTTPS request on the machine failed at once, which is precisely the failure the interception
// root switch design exists to make impossible.
//
// In the same window the device reported interception_root_trust wanted=1 found=1. Green — because the Edge had
// announced the deployment-wide root, the box does hold that one, and NOTHING COMPARED THE ANNOUNCED ROOT WITH
// THE SIGNING ONE. Two announcement paths had drifted apart: the trust bundle asked per organization
// (interceptionRootFingerprintsForTenant) while the policy document every agent fetches each minute asked about
// the node.
//
// The announcement is now derived from the same per-organization answer, so the two cannot drift by omission.
// This is the check that says so out loud, because "they cannot drift" is a claim about code and this is a
// claim about the running deployment — and the previous version of that claim was also true when it was
// written.
func interceptionAnnouncementMismatches(config serverConfig) []string {
	if config.NetworkExtensionLabTLS == nil {
		return nil
	}
	nodeTenant := strings.TrimSpace(config.TenantIDForTrust)
	pairs := []interceptionAnnouncement{}
	for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
		pairs = append(pairs, interceptionAnnouncement{
			Tenant:         issuer.Tenant,
			IntermediateCN: issuer.IntermediateCN,
			RootCommonName: issuer.RootCommonName,
			SigningSHA256:  issuer.RootSHA256,
			Announced:      interceptionRootFingerprintsForTenant(config, issuer.Tenant, nodeTenant),
		})
	}
	// ★★★ AND THE OTHER WAY AN ORGANIZATION HAS A ROOT (2026-08-30). This check exists to prove the announced
	// root and the signing one cannot drift, and it enumerated only offline intermediates — so an organization
	// signing under a root MINTED on this node was invisible to it. The deployment signed under 769131f4… and
	// announced 83fe37b9…, and this check reported nothing, exactly as the signal it replaced once did.
	//
	// A check that cannot see one of the two ways the thing it watches comes about is not a weaker check; it
	// is a green light with a hole in it.
	for _, root := range config.NetworkExtensionLabTLS.ListTenantInterceptionRoots() {
		signing := interceptionRootFingerprintsFromPEM(root.CertPEM)
		if len(signing) == 0 {
			continue
		}
		pairs = append(pairs, interceptionAnnouncement{
			Tenant:         root.Tenant,
			IntermediateCN: "(minted per-tenant root, no intermediate)",
			RootCommonName: interceptionRootCommonNameFromPEM(root.CertPEM),
			SigningSHA256:  signing[0],
			Announced:      interceptionRootFingerprintsForTenant(config, root.Tenant, nodeTenant),
		})
	}
	return interceptionAnnouncementMismatchLines(pairs)
}

// interceptionAnnouncement is one organization's signing root beside what its devices are told to look for.
// Separated from the config so the comparison can be tested in both directions — a check that cannot be shown
// to fail is not evidence of anything, and this one replaces a signal that was green through an outage.
type interceptionAnnouncement struct {
	Tenant         string
	IntermediateCN string
	RootCommonName string
	SigningSHA256  string
	Announced      []string
}

func interceptionAnnouncementMismatchLines(pairs []interceptionAnnouncement) []string {
	out := []string{}
	for _, issuer := range pairs {
		tenant := strings.TrimSpace(issuer.Tenant)
		signing := strings.TrimSpace(issuer.SigningSHA256)
		if tenant == "" {
			continue
		}
		if signing == "" {
			// The issuer exists and its root could not be read. That is not a match and must not be reported as
			// one: an organization whose signing root cannot be named is an organization nobody can tell its
			// devices what to trust.
			out = append(out, fmt.Sprintf("%s: its traffic is signed by %q whose root this node cannot read, so "+
				"its devices cannot be told what to look for", tenant, issuer.IntermediateCN))
			continue
		}
		announced := issuer.Announced
		found := false
		for _, fp := range announced {
			if strings.EqualFold(strings.TrimSpace(fp), signing) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: signed under %s (%s) and its devices are told to look for %s",
				tenant, issuer.RootCommonName, shortFingerprint(signing), announcedList(announced)))
		}
	}
	sort.Strings(out)
	return out
}

func shortFingerprint(hex string) string {
	h := strings.TrimSpace(hex)
	if len(h) <= 12 {
		return h
	}
	return h[:8] + "…"
}

// announcedList names what the devices were told, including the case where they were told nothing — which is
// the same outage wearing a quieter face.
func announcedList(fps []string) string {
	if len(fps) == 0 {
		return "nothing at all"
	}
	short := make([]string, 0, len(fps))
	for _, fp := range fps {
		short = append(short, shortFingerprint(fp))
	}
	return strings.Join(short, ", ")
}

// interceptionRootCommonNameFromPEM names a root for the mismatch line, so an operator reading it sees a
// certificate rather than a hash.
func interceptionRootCommonNameFromPEM(pem string) string {
	for _, cert := range parseAllCerts([]byte(pem)) {
		return cert.Subject.CommonName
	}
	return ""
}
