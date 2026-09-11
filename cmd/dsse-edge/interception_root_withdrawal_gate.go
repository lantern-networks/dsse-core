package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Whether an organization may stop announcing the interception root its devices are moving off.
//
// ★ THE JUDGEMENT WAS A HUMAN'S, AND THE MISTAKE IT INVITES IS THE ONE JUST FIXED (2026-08-16). A replacement
// keeps the outgoing root announced so devices pinned to it keep working. Withdrawing it while devices are
// still pinned to it re-creates, by hand, exactly the flag day the overlap was built to remove: every one of
// them mismatches at once and, with the pin armed, stands aside together.
//
// So the withdrawal is decided the same way every other trust change in this tree is: on what devices have
// REPORTED, never on what was distributed. Three rules, each of which is a different failure if dropped:
//
//   - a device that has NOT SAID blocks. Silence is unknown, never "has moved" — the same rule the transport
//     anchor withdrawal and the interception root switch already follow, and for the same reason: the devices
//     that are broken are disproportionately the ones not reporting.
//   - an organization with NO enrolled devices is allowed. There is nobody to strand, and a gate that cannot
//     be satisfied on an empty fleet blocks the very first rotation of every new customer.
//   - an operator may account for a device BY NAME through the acknowledgement store. A Windows agent that
//     does not yet report its pin cannot satisfy this gate at all, and a safeguard that cannot be satisfied is
//     an instruction to work around it. Vouching is recorded with who and why.
type interceptionWithdrawalVerdict struct {
	Allowed bool
	// StillPinned are the devices that say they are pinned to the root being withdrawn. Named, because "some
	// devices are not ready" sends an operator hunting.
	StillPinned []string
	// Silent are the devices of this organization that have not reported a pin at all.
	Silent []string
	Text   string
}

func interceptionRootWithdrawalGate(config serverConfig, r *http.Request, tenant, sha256Hex string) interceptionWithdrawalVerdict {
	target := strings.ToLower(strings.TrimSpace(sha256Hex))
	tenant = strings.TrimSpace(tenant)
	if target == "" || tenant == "" {
		return interceptionWithdrawalVerdict{Text: "tenant and root fingerprint are both required"}
	}
	devices := enrolledIdentitiesForTenant(config, tenant)
	if len(devices) == 0 {
		return interceptionWithdrawalVerdict{Allowed: true,
			Text: "no enrolled device belongs to this organization, so there is nobody to strand"}
	}
	vouched := map[string]bool{}
	for _, ack := range transportAnchorAcks.For(target) {
		vouched[strings.ToLower(strings.TrimSpace(ack.Identity))] = true
	}
	var stillPinned, silent []string
	for _, identity := range devices {
		if vouched[strings.ToLower(strings.TrimSpace(identity))] {
			continue
		}
		pin, said := deviceReportedInterceptionRootPin(config, tenant, identity)
		switch {
		case !said:
			silent = append(silent, identity)
		case strings.EqualFold(pin, target):
			stillPinned = append(stillPinned, identity)
		}
	}
	sort.Strings(stillPinned)
	sort.Strings(silent)
	if len(stillPinned) == 0 && len(silent) == 0 {
		return interceptionWithdrawalVerdict{Allowed: true,
			Text: "every device of this organization reports a different pin, so none is left looking for this root"}
	}
	parts := []string{}
	if len(stillPinned) > 0 {
		parts = append(parts, "still pinned to it: "+strings.Join(stillPinned, ", "))
	}
	if len(silent) > 0 {
		parts = append(parts, "have not reported a pin: "+strings.Join(silent, ", "))
	}
	return interceptionWithdrawalVerdict{
		StillPinned: stillPinned,
		Silent:      silent,
		Text: fmt.Sprintf("withdrawing this root would leave devices of %q looking for a certificate this Edge "+
			"no longer names — %s. Re-install them with this organization's current configuration "+
			"(/admin/tenant-install-bundle/%s), or account for a device by name if it cannot report.",
			tenant, strings.Join(parts, "; "), tenant),
	}
}

// enrolledIdentitiesForTenant is this organization's enabled devices, from the admission authority rather than
// from telemetry — the denominator every trust measurement in this tree uses. Counting only devices that
// report would make a fleet look ready precisely because the machines in trouble are the quiet ones.
func enrolledIdentitiesForTenant(config serverConfig, tenant string) []string {
	if config.EnrolledLedger == nil {
		return nil
	}
	var out []string
	for _, entry := range config.EnrolledLedger.List() {
		if !entry.Enabled {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(entry.TenantID), strings.TrimSpace(tenant)) {
			continue
		}
		out = append(out, entry.Identity)
	}
	return out
}

// deviceReportedInterceptionRootPin answers two questions at once, because collapsing them is the mistake this
// gate exists to avoid: did this device SAY which root it is pinned to, and if so which one. A device that has
// not reported is unknown, never "pinned to nothing".
func deviceReportedInterceptionRootPin(config serverConfig, tenant, identity string) (pin string, said bool) {
	if config.ObservedExclusions == nil {
		return "", false
	}
	for _, e := range config.ObservedExclusions.Query(tenant,
		observedQueryFilter{Device: identity, Limit: 1}).Entries {
		if !strings.EqualFold(strings.TrimSpace(e.DeviceIdentity), strings.TrimSpace(identity)) {
			continue
		}
		if strings.TrimSpace(e.InterceptionRootPinSHA256) == "" {
			return "", false
		}
		return strings.ToLower(strings.TrimSpace(e.InterceptionRootPinSHA256)), true
	}
	return "", false
}

// deviceCAWithdrawalGate decides whether an organization may stop trusting one of its DEVICE CAs.
//
// Same shape as the interception one next to it, and a different fact underneath: a device moves to a
// replacement device CA when its certificate is REISSUED under it, which the Edge sees at the handshake as the
// anchor the verified chain ended at. Withdrawing while a device is still admitted under the outgoing CA does
// not degrade that device — it stops it connecting at all, at the next handshake, with no way back in, because
// the credential it would renew with is the one that just stopped being trusted.
//
// The refusals:
//
//   - the LAST CA of an organization is never withdrawn here. That is not the end of a rotation, it is the end
//     of that organization's ability to admit anything, and it has its own act (DELETE /admin/tenant-cas/{id}).
//   - a device still admitted under it blocks, by name.
//   - a device this node has NEVER SEEN present a certificate blocks. Unknown is not "has moved" — and a
//     device that has been switched off through the whole rotation is exactly the one that comes back to find
//     its certificate no longer trusted.
//   - an organization with no enrolled devices is allowed, and a device that cannot be measured is accounted
//     for by name, for the reasons given on the interception gate.
func deviceCAWithdrawalGate(config serverConfig, tenant, sha256Hex string, remaining int) interceptionWithdrawalVerdict {
	target := strings.ToLower(strings.TrimSpace(sha256Hex))
	tenant = strings.TrimSpace(tenant)
	if target == "" || tenant == "" {
		return interceptionWithdrawalVerdict{Text: "tenant and CA fingerprint are both required"}
	}
	// The registry contains imported CAs; a managed authority can also admit
	// this organization's devices. Count that retained path from a checked read,
	// and never claim that deleting a registration withdraws an active managed CA.
	if config.TenantDeviceAuthority != nil {
		snapshot, err := config.TenantDeviceAuthority.materialSnapshot()
		if err != nil {
			return interceptionWithdrawalVerdict{Text: "managed device authority could not be read: " + err.Error()}
		}
		managed := certificatesInPEM([]byte(deviceAnchorsOf(snapshot.cas[strings.ToLower(tenant)])))
		for _, cert := range managed {
			if strings.EqualFold(certFingerprint(cert), target) {
				return interceptionWithdrawalVerdict{Text: "this CA is still admitted by the managed device authority; finish its managed rotation before removing this registration"}
			}
			if remaining <= 0 && cert.IsCA && cert.NotAfter.After(time.Now()) {
				remaining = 1
			}
		}
	}
	if remaining <= 0 {
		return interceptionWithdrawalVerdict{Text: fmt.Sprintf(
			"this is the only CA registered to %q; withdrawing it would leave that organization unable to admit "+
				"any device at all. That is a different act — retire the organization's identity basis with "+
				"DELETE /admin/tenant-cas/%s — and it is not how a rotation ends.", tenant, tenant)}
	}
	// ★ A RE-PARENT IS NOT A ROTATION (2026-08-19). If another registered CA carries the SAME subject and the
	// SAME key, this certificate has been re-issued under a different parent — typically to move an
	// organization out of the provider's PKI tree and under its own root. Every device certificate that
	// verified under this one verifies under that one, because a leaf chains by issuer NAME and is checked
	// with the CA's KEY, and neither changed. Nothing this gate protects against can happen, so refusing here
	// would leave "re-issue every device certificate first" as the only way out of the provider's tree — which
	// is the one thing a re-parent exists to avoid. See device_ca_reparent.go for why both halves are required.
	if replacement, ok := deviceCAReparentedBy(deviceCACertificateByFingerprint(config, target),
		deviceCACertificatesForTenant(config, tenant)); ok {
		return interceptionWithdrawalVerdict{Allowed: true, Text: fmt.Sprintf(
			"this CA has been RE-PARENTED: %q carries the same subject and the same key under a different "+
				"root, so every device certificate that verified under this one verifies under that one",
			replacement.Subject.CommonName)}
	}
	devices := enrolledIdentitiesForTenant(config, tenant)
	if len(devices) == 0 {
		return interceptionWithdrawalVerdict{Allowed: true,
			Text: "no enrolled device belongs to this organization, so there is nobody to lock out"}
	}
	vouched := map[string]bool{}
	for _, ack := range transportAnchorAcks.For(target) {
		vouched[strings.ToLower(strings.TrimSpace(ack.Identity))] = true
	}
	seen := map[string]deviceCertificateFact{}
	for _, fact := range deviceCertificates.snapshot() {
		seen[strings.ToLower(strings.TrimSpace(fact.Identity))] = fact
	}
	var stillOn, unseen []string
	for _, identity := range devices {
		key := strings.ToLower(strings.TrimSpace(identity))
		if vouched[key] {
			continue
		}
		fact, ok := seen[key]
		switch {
		case !ok || strings.TrimSpace(fact.AnchorSHA256) == "":
			unseen = append(unseen, identity)
		case strings.EqualFold(fact.AnchorSHA256, target):
			stillOn = append(stillOn, identity)
		}
	}
	sort.Strings(stillOn)
	sort.Strings(unseen)
	if len(stillOn) == 0 && len(unseen) == 0 {
		return interceptionWithdrawalVerdict{Allowed: true,
			Text: "every device of this organization was last admitted under a different CA"}
	}
	parts := []string{}
	if len(stillOn) > 0 {
		parts = append(parts, "still admitted under it: "+strings.Join(stillOn, ", "))
	}
	if len(unseen) > 0 {
		// ★ "IN THIS DEPLOYMENT", NOT "ON THIS NODE" (2026-08-23). The facts this reads are observed at the (T)
		// handshake, which only an Edge terminates — so on a control plane the sentence used to be true of
		// every device and the withdrawal was refused forever, including for a CA the control plane had itself
		// just registered. Edges ship what they see (device_certificate_fact_ship.go), so the answer is now the
		// fleet's. The gate is unchanged: an unseen device still blocks a withdrawal.
		parts = append(parts, "no Edge in this deployment has seen these present a certificate: "+strings.Join(unseen, ", "))
	}
	return interceptionWithdrawalVerdict{
		StillPinned: stillOn,
		Silent:      unseen,
		Text: fmt.Sprintf("withdrawing this CA would stop devices of %q connecting at their next handshake, with "+
			"no way back in — %s. Re-issue their certificates under the replacement first, or account for a "+
			"device by name if it cannot be measured.", tenant, strings.Join(parts, "; ")),
	}
}
