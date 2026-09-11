package main

import (
	"fmt"
	"sort"
	"strings"
)

// fleet_promises_this_node_cannot_keep.go — a node that joins a shared fleet must be able to serve what that
// fleet has already told devices.
//
// ★★★ AUTOSCALING WOULD HAVE TAKEN DEVICES OFFLINE (2026-08-20, measured).
//
// The Edge fleet is shared across organizations and grows and shrinks with load — so an Edge can appear
// without anybody preparing it. Roadmap D gave each organization its own transport certificate, announced by
// name in the signed trust bundle, and devices now SEND that name and verify against that organization's own
// anchor. Measured on this repository's own scale-out definition: it carries none of the per-organization
// material — not the certificates, not the roots, not the admitted-CA registry.
//
// So a device that has adopted its organization's anchor, dialling the name it was told, reaches a new node
// that answers with the shared certificate, and REFUSES it. The refusal is correct; the node is the fault.
// The devices affected are exactly the ones the fleet grew to serve, and it would look like a capacity
// problem.
//
// A node that will refuse devices is worse than a node that is not there: a load balancer routes around one
// that never comes up, and a fleet that scales out into a hole is a fleet that empties. So this is checked
// before the transport plane is served, and it is fatal — with the missing names printed, because "it did not
// start" needs to be answerable in one line at three in the morning.
//
// Read from the SHARED trust store, not from this node's configuration: the promise was made by whoever
// signed the distribution devices are holding, and this node's own flags cannot tell it what that was.
// ★ EVERY PROMISE IN THE STRING, NOT JUST THE NAMES (2026-08-20, second measurement). The first version
// checked the per-organization names and let a scaled node through that had no renewal-recovery path — and
// that node then dropped "recovery-sni=..." from the shared announcement and advanced the serial, so every
// device adopting it lost the recovery name. The dedicated port it would have fallen back to was closed
// yesterday. Same defect, one token over: whatever the fleet has promised, a node that cannot keep it does
// not get to speak for the fleet.
func fleetPromisesThisNodeCannotKeep(announced string, canServeName, canOfferRecovery func(string) bool) []string {
	return fleetPromisesThisNodeCannotKeepWithAnchors(announced, canServeName, canOfferRecovery, nil)
}

// ★★★ AND THE CERTIFICATE MUST CHAIN TO THE ANCHOR THE FLEET ANNOUNCED, NOT MERELY CARRY THE NAME
// (2026-08-20, found by running it). A node that fetched its material from the control plane served
// lab.dsse.invalid from a NEW authority while the rest of the fleet was still announcing the old one — every
// device that reached it would have been refused, and the name check alone said the node was fine.
//
// The announcement carries "tenant=fingerprint" for each organization's anchor, so this compares them. A
// tenant this node holds no anchor for is not a mismatch: it is covered by the name check above.
func fleetPromisesThisNodeCannotKeepWithAnchors(announced string, canServeName, canOfferRecovery func(string) bool,
	anchorFingerprintsFor func(string) []string) []string {
	return fleetPromisesThisNodeCannotKeepWithServed(announced, canServeName, canOfferRecovery,
		anchorFingerprintsFor, nil, nil)
}

// ★★★ AND WHAT THIS NODE WOULD ACTUALLY PRESENT, NOT ONLY WHAT IT HOLDS (2026-08-20, reported from win-dev-1
// after 31 minutes with no steering and no interception).
//
// The anchor check above asks whether this node HOLDS at least one of the authorities the fleet announces for
// an organization. It passed for a node that held the announced one as incoming material and went on SERVING
// the previous one — which the fleet had already withdrawn, because every device had reported adopting the new
// one. So the certificate that box was handed on its next handshake was signed by an authority its own trust
// bundle no longer contained. It refused, correctly, and fell out of the fleet: steering disarmed, traffic on
// the native network, recovered by a person restarting a service.
//
// Holding an anchor and presenting a certificate under it are two different facts, and only the second one is
// what a device meets. A node that would present something the fleet does not announce is a node that refuses
// devices, which is the thing this file exists to prevent.
func fleetPromisesThisNodeCannotKeepWithServed(announced string, canServeName, canOfferRecovery func(string) bool,
	anchorFingerprintsFor func(string) []string, servedAnchorFor func(string) string,
	organizationIsGone func(string) bool) []string {
	missing := []string{}
	// Names the fleet still announces that no organization has any more. Not failures — said out loud, because
	// a node that silently declines to keep a promise is the shape this file exists to prevent.
	retracted := []string{}
	// ★★★ AT LEAST ONE, NOT ALL (2026-08-20, and getting this wrong took a healthy node down). During a
	// rotation the fleet announces BOTH of an organization's authorities and devices hold both; a node
	// serving either end is serving something they can verify. Requiring each announced fingerprint
	// individually refused region-b for holding the old anchor while the new one was being adopted — the
	// middle of the very overlap this mechanism exists to perform.
	announcedAnchors := map[string][]string{}
	tokens := strings.Split(announced, ",")
	// ★ ANCHORS FIRST, IN A PASS OF THEIR OWN (2026-08-22). The name judgement below asks whether this node's
	// material for an organization is CURRENT, which it answers from the anchors — so collecting them in the
	// same loop would make the verdict depend on the order tokens happen to appear in. This repository has
	// already been bitten once by an order-dependent comparison over this very string.
	rest := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if anchorFingerprintsFor != nil {
			if tenant, want, ok := strings.Cut(token, "="); ok {
				want = strings.ToLower(strings.TrimSpace(want))
				tenant = strings.TrimSpace(tenant)
				// Only the per-organization anchor tokens look like this; recovery-sni= and the rest are
				// handled below and never name a tenant with a fingerprint.
				if len(want) == 64 && tenant != "" && !strings.Contains(tenant, "@") {
					// Collected and judged per organization below: this node must hold AT LEAST ONE of the
					// anchors announced for it, because mid-rotation the fleet announces both ends.
					announcedAnchors[tenant] = append(announcedAnchors[tenant], want)
					continue
				}
			}
		}
		rest = append(rest, token)
	}
	// holdsAnAnnouncedAnchorFor is this node's evidence that its material for an organization is CURRENT: the
	// control plane handed it an authority the fleet is announcing right now. Used only to tell an announcement
	// that is BEHIND from a node that is behind — see the name check.
	holdsAnAnnouncedAnchorFor := func(tenant string) bool {
		if anchorFingerprintsFor == nil {
			return false
		}
		wanted := announcedAnchors[tenant]
		if len(wanted) == 0 {
			return false
		}
		for _, h := range anchorFingerprintsFor(tenant) {
			for _, w := range wanted {
				if strings.EqualFold(strings.TrimSpace(h), w) {
					return true
				}
			}
		}
		return false
	}
	for _, token := range rest {
		if name, ok := strings.CutPrefix(token, "recovery-sni="); ok {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || name == "withdrawn" || canOfferRecovery(name) {
				continue
			}
			missing = append(missing, "the fleet promised devices they can renew an expired certificate at the "+
				"name "+name+", and this node does not offer it (an Edge that cannot ISSUE cannot recover)")
			continue
		}
		// Names are announced as "tenant@name" (transportTenantCertificates.ServerNameAnnouncements). Anything
		// else in the string is a fingerprint or a flag and is not a promise about a name.
		at := strings.Index(token, "@")
		if at <= 0 || at == len(token)-1 {
			continue
		}
		tenant, name := token[:at], strings.ToLower(strings.TrimSpace(token[at+1:]))
		if name == "" || canServeName(name) {
			continue
		}
		// ★★★ A NAME THE ORGANIZATION NO LONGER HAS IS THE ANNOUNCEMENT BEING BEHIND, NOT THIS NODE
		// (2026-08-22, measured — it took BOTH lab Edges down and they stayed down until a name was put back).
		//
		// The announcement is durable and fleet-wide. Abandoning a transport rename, or retiring the previous
		// name, changes the CONTROL PLANE's material immediately and reaches the announcement only when a
		// running Edge next recomputes and publishes it. An Edge that restarts inside that window read a
		// promise naming a name its own fresh material does not carry, and exited — every Edge in the fleet,
		// at once, because they all read the same store. The only way back was to re-create the name.
		//
		// So: if this node holds an authority the fleet is announcing for that organization RIGHT NOW, its
		// material is current, the control plane no longer has that name, and nobody can serve it. That is a
		// retraction to publish, not a promise to fail. If it holds no announced anchor for the organization,
		// it cannot tell "the name is gone" from "I am behind", and it still refuses — which is the case this
		// file was written for.
		if holdsAnAnnouncedAnchorFor(tenant) {
			retracted = append(retracted, tenant+"@"+name)
			continue
		}
		// ★★★ AND THE ORGANIZATION BEING GONE ENTIRELY, WHICH THIS NODE HAD ALREADY BEEN TOLD (2026-09-07,
		// measured after every Edge in three regions exited over eighteen deleted organizations).
		//
		// The branch above needs an ANNOUNCED ANCHOR as its evidence that this node's material is current. An
		// organization that has been DELETED has no anchor here at all, so it can never take that branch, and
		// every deleted organization therefore lands on the refusal below — hours later, on whatever restart
		// comes first, on every node at once because they all read the same announcement.
		//
		// The evidence was in hand and unused. The control plane's last successful answer named twenty
		// organizations and none of them was this one; a successful answer that does not mention an
		// organization AT ALL is exactly the "the name is gone" this file could not previously distinguish
		// from "I am behind". Absence of an ANSWER still proves nothing and still refuses — see
		// OrganizationIsGone, which is false until one arrives.
		//
		// Retracting rather than refusing also makes the condition self-clearing: the announcement recompute
		// twelve lines after this guard publishes the set without the dead organization and advances the
		// serial. A deployment already carrying the promise disarms itself on its next start instead of
		// needing a file edited on every node.
		if organizationIsGone != nil && organizationIsGone(tenant) {
			retracted = append(retracted, tenant+"@"+name+" (the control plane no longer has this organization)")
			continue
		}
		missing = append(missing, tenant+" was promised the name "+name+" and this node has no certificate for it")
	}
	// The anchors, judged per organization: this node must hold AT LEAST ONE of the ones announced for it.
	for tenant, wanted := range announcedAnchors {
		have := anchorFingerprintsFor(tenant)
		if len(have) == 0 {
			continue // holds none of its own: covered by the NAME check above
		}
		matched := false
		for _, h := range have {
			for _, w := range wanted {
				if strings.EqualFold(h, w) {
					matched = true
				}
			}
		}
		if matched {
			// ★ Held is not served. The certificate a device meets is the one presented for that
			// organization's name, and if the fleet no longer announces the authority that signed it, the
			// device will refuse it — see the note on this function.
			if servedAnchorFor != nil {
				if served := strings.TrimSpace(servedAnchorFor(tenant)); served != "" {
					announcedServed := false
					for _, w := range wanted {
						if strings.EqualFold(served, w) {
							announcedServed = true
						}
					}
					if !announcedServed {
						announcedShort := make([]string, 0, len(wanted))
						for _, w := range wanted {
							announcedShort = append(announcedShort, shortFingerprint(w))
						}
						missing = append(missing, tenant+" would be served a certificate signed by "+
							shortFingerprint(served)+", and the fleet announces "+
							strings.Join(announcedShort, "/")+" — this node holds one of those but does not "+
							"present it, so that organization's devices would refuse the certificate they meet")
					}
				}
			}
			continue
		}
		short := make([]string, 0, len(have))
		for _, h := range have {
			short = append(short, shortFingerprint(h))
		}
		announcedShort := make([]string, 0, len(wanted))
		for _, w := range wanted {
			announcedShort = append(announcedShort, shortFingerprint(w))
		}
		missing = append(missing, tenant+" is announced with "+strings.Join(announcedShort, "/")+
			" and this node holds "+strings.Join(short, "/")+" — none of them match, so its devices would "+
			"refuse the certificate this node presents")
	}
	if len(retracted) > 0 {
		sort.Strings(retracted)
		logInfof("fleet_announcement_behind names=%s — the fleet still announces these and the organizations "+
			"they belong to no longer have them; this node holds their current authorities, so it is joining "+
			"and will publish the retraction rather than refusing devices", strings.Join(retracted, ","))
	}
	sort.Strings(missing)
	return missing
}

func refuseToJoinFleetIfPromisesCannotBeKept(announced string, canServeName, canOfferRecovery func(string) bool) error {
	missing := fleetPromisesThisNodeCannotKeep(announced, canServeName, canOfferRecovery)
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("this node cannot serve %d name(s) the fleet has already announced to devices, so devices "+
		"holding that distribution would reach it and be refused: %s. A node that refuses devices is worse than "+
		"one that is absent — give it what the fleet has promised (per-organization certificates via "+
		"-transport-tenant-cert-dir, and the ability to issue for the renewal-recovery name) before it joins, "+
		"or stop promising it",
		len(missing), strings.Join(missing, "; "))
}

func refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced string, canServeName, canOfferRecovery func(string) bool,
	anchorFingerprintsFor func(string) []string, servedAnchorFor func(string) string,
	organizationIsGone func(string) bool) error {
	missing := fleetPromisesThisNodeCannotKeepWithServed(announced, canServeName, canOfferRecovery,
		anchorFingerprintsFor, servedAnchorFor, organizationIsGone)
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("this node cannot keep %d promise(s) the fleet has already made to devices: %s. A node that "+
		"refuses devices is worse than one that is absent", len(missing), strings.Join(missing, "; "))
}

// organizationIsGoneAccordingToTheControlPlane answers whether the control plane's last successful answer did
// not mention an organization at all — the evidence the start-up promise guard needs to tell a stale promise
// from a node that is behind.
//
// A package-level function rather than a field, for the same reason connectorEnrollmentRegions is one: the
// guard runs during start-up, in a closure that is built before the material fetcher exists, and threading it
// through every constructor between the two would be a larger change than the question deserves. Nil until the
// fetcher is wired, and false until it has an answer — both of which mean "refuse", which is the safe end.
var organizationIsGoneAccordingToTheControlPlane func(string) bool
