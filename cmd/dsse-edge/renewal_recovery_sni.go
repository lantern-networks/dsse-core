package main

import (
	"flag"
	"strings"
)

// renewal_recovery_sni.go — the name an agent will send to reach the expired-certificate renewal path once
// that path shares the main port.
//
// ★★★ STEP 1 OF the enrolment fold, AND ONLY STEP 1 (2026-08-19). An agent must reach an Edge on ONE port: this deployment
// publishes three (:8443 enrolment and the trust bundle, :18543 the transport, :18545 recovery), and on a real
// deployment all three would be 443 on one address and collide — so the recovery path AS BUILT cannot ship.
//
// The design (docs/pki_who_owns_which_certificate.ja.md the enrolment fold-1) selects that path by SNI on the same port,
// because it needs RequireAnyClientCert and the main transport must never be relaxed that way: a verification
// hole there is either "unverified certificates accepted" or "every device locked out".
//
// What lands here is the ANNOUNCEMENT, with the listeners untouched. That ordering is the whole point:
//
//  1. the Edge NAMES the SNI in the trust bundle          <- this
//  2. macOS and Windows learn to send it                  <- their planes, at their own pace
//  3. the Edge serves recovery for that SNI on the main port
//  4. every enrolled device is MEASURED onto a bundle carrying it, silence counted as "not yet"
//  5. :18545 closes and the port gate's expectation moves to 1
//
// Reversed, step 5 arrives before the devices that need recovery have heard of the replacement — and the
// devices that need it are, by definition, the ones that were switched off.
//
// Empty is the ordinary state and means what it has always meant: the recovery endpoint is a port, and an
// agent that never sees this field behaves exactly as before.
func registerRenewalRecoverySNIFlag() *string {
	return flag.String("renewal-recovery-sni", "", "the SNI an agent will send to reach the expired-certificate renewal path once it shares the main port (the enrolment fold). Announced in the trust bundle; it changes no listener on its own. Empty = agents keep using the separate recovery port")
}

// renewalRecoverySNIAnnouncement is what goes in the bundle: trimmed, lower-cased, and empty when unset — an
// SNI is compared case-insensitively and an agent must not be handed one that differs from what it will send.
func renewalRecoverySNIAnnouncement(configured string) string {
	return strings.ToLower(strings.TrimSpace(configured))
}

// ★★★ AND A NAME IS ONLY ANNOUNCED WHILE IT IS ACTUALLY BEING SERVED (2026-08-19).
//
// The announcement was the flag, lower-cased. It said nothing about whether the transport port answers that
// name with a certificate carrying it — and when it does not, the agent that believes the announcement dials
// the folded path, gets a certificate it must refuse, and stops. Announcing a name is telling every device
// where to go when it is already in trouble, so it has to be a statement about the running deployment, not
// about the command line.
//
// Read live, per bundle: the flag is parsed long before the path is wired, and the wiring is what knows
// whether the certificate carries the name.
func offeredRenewalRecoverySNI(configured string) string {
	name := renewalRecoverySNIAnnouncement(configured)
	if name == "" {
		return ""
	}
	r := renewalRecoveryMainPort.Load()
	if r == nil || !strings.EqualFold(strings.TrimSpace(r.sni), name) {
		return ""
	}
	return name
}
