package main

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The trust bundle is THE set of certificate authorities one organization's agents accept — the Edge they
// will talk to, and the interception roots they must find in their own trust store. It is signed, carries a
// monotonic serial, and holds LISTS rather than single values, because an overlap is the normal state while a
// CA is being replaced.
//
// ★ IT WAS ONE BUNDLE FOR THE WHOLE NODE (found 2026-08-16). The tenant on the payload was always
// evaluator.PolicyBundle.TenantID — the organization that happens to own the Edge — so every organization's
// devices were handed the same document, naming the same anchors. That is invisible on a single-tenant node
// and wrong on the multi-tenant one this product now ships: once each organization signs its intercepted
// traffic under its OWN root, a bundle that names somebody else's root tells a device to look for a
// certificate it will never have, and stays silent about the one it needs.
//
// The intended end state, which this is the first half of: each organization's bundle is FIXED AT AGENT
// INSTALL TIME, so a device's trust is decided before it ever reaches the network, and replacing a CA is a
// new bundle carrying old and new together rather than a flag day.
//
// restart-durability: ephemeral — this holds SIGNATURES, not facts. Every input is durable elsewhere (the
// transport trust store on disk, each organization's interception issuer on disk), and losing the cache costs
// one signing operation per organization on the next fetch. Nothing an operator reads lives only here.
// populated-by: assertion — the first fetch after a restart or a change rebuilds it, so it re-converges with
// no operator action; a bundle that is never fetched is one no device needed.
type perTenantTrustBundles struct {
	mu sync.Mutex
	// generation invalidates every cached signature at once. The alternative — recomputing which tenants a
	// change touched — is the kind of bookkeeping that is right until somebody adds a fourth input.
	generation int64
	cached     map[string]cachedTrustBundle
	config     serverConfig
	// nodeTenant is the organization that owns this Edge: the fallback for a device this node cannot place,
	// which is exactly what a single-tenant deployment is.
	nodeTenant string
	// The transport material every organization's bundle is built from, held HERE rather than in the handler's
	// closure: the trust store rewrites it from its own goroutine while requests are reading it, and a string
	// assigned in one goroutine and read in another is a race whatever it looks like at the call site.
	pems   string
	serial int64
}

type cachedTrustBundle struct {
	generation int64
	envelope   agentpolicy.Envelope
}

// perTenantTrustBundlesForAdmin is the node's one bundle builder, so the admin surface can ask what an
// organization is actually being told rather than reading the node's configured set beside it.
var perTenantTrustBundlesForAdmin *perTenantTrustBundles

func newPerTenantTrustBundles(config serverConfig, nodeTenant string) *perTenantTrustBundles {
	return &perTenantTrustBundles{cached: map[string]cachedTrustBundle{}, config: config, nodeTenant: nodeTenant}
}

// Invalidate is called whenever anything a bundle is built from changes that is NOT the transport set — an
// organization's interception issuer being loaded, for instance. Signatures are recomputed on the next fetch,
// once per organization, never per request: this endpoint is unauthenticated and signing per request would
// let anonymous traffic spend the signing key.
func (b *perTenantTrustBundles) Invalidate() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.generation++
	b.mu.Unlock()
}

// SetTransportMaterial records the anchors and serial every organization's bundle is built from, and
// invalidates in the same breath. A serial that moved without the signatures moving would serve devices an
// old anchor set under a new number, which is the one thing the monotonic serial exists to make impossible.
func (b *perTenantTrustBundles) SetTransportMaterial(pems string, serial int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.pems, b.serial = pems, serial
	b.generation++
	b.mu.Unlock()
}

// For returns the signed bundle for one organization, building and caching it if needed.
func (b *perTenantTrustBundles) For(tenantID string) (agentpolicy.Envelope, bool) {
	if b == nil || b.config.AgentPolicySigner == nil {
		return agentpolicy.Envelope{}, false
	}
	tenant := strings.TrimSpace(tenantID)
	if tenant == "" {
		tenant = b.nodeTenant
	}
	if b.config.DistributedTenantTrust != nil {
		return b.config.DistributedTenantTrust.For(tenant)
	}
	if b.config.TenantTrustDistributor != nil {
		return b.config.TenantTrustDistributor.For(tenant)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if hit, ok := b.cached[tenant]; ok && hit.generation == b.generation {
		return hit.envelope, true
	}
	if b.serial <= 0 {
		return agentpolicy.Envelope{}, false
	}
	// ★★★ ROADMAP D, S2 (2026-08-19): this organization's OWN transport anchor, ADDED to the shared ones.
	//
	// The shared anchor is what every organization's devices verify this Edge with, so whoever holds it can
	// impersonate the Edge to any of them. The way out is not to swap the anchor — that strands every device
	// that has not taken the new bundle — but to distribute both, let adoption be measured, and withdraw the
	// shared one from THIS organization's bundle afterwards.
	//
	// Derived from the certificate this node actually serves that organization (transport_tenant_certificates.go),
	// so the bundle cannot name an anchor the handshake does not chain to. That is the same rule the
	// interception announcement was corrected under on this same day, applied before the mistake rather than
	// after it.
	pems, ownCount, withdrew := b.announcedAnchorPEMs(tenant)
	// ★★★ SAID ON EVERY PATH, INCLUDING THE HEALTHY ONE (2026-08-29, after a Windows machine adopted a bundle
	// that named the DEPLOYMENT's transport authority for an organization that has its own). Which authorities
	// an organization's bundle names is the difference between its devices being able to reach their own door
	// and not; when it is wrong, everything downstream still reads green. A node that says nothing here leaves
	// an operator comparing a bundle against a certificate by hand, which is how this took a day to find.
	log.Printf("trust_bundle building tenant=%q own_transport_anchors=%d shared_withdrawn=%v — an organization "+
		"with a certificate of its own must see own_transport_anchors>=1, or its devices cannot verify the "+
		"door they are told to dial", tenant, ownCount, withdrew)
	// ★ ROADMAP D, S3 (Edge half): the name this organization's agents should send. Announced rather than
	// configured on the device, so it is derived from the certificate this node serves them and cannot drift
	// from it. Absent for an organization with no certificate of its own, which is every organization today
	// except where an operator has placed one — and an agent that never sees it dials exactly as before.
	serverName, _ := transportTenantCertificates.ServerNameFor(tenant)
	env, err := b.config.AgentPolicySigner.SignTrustBundlePayload(agentpolicy.TrustBundlePayload{
		TenantID:                tenant,
		Serial:                  b.serial,
		TransportCAPEM:          pems,
		RenewalRecoveryEndpoint: b.config.TrustBundleRecoveryEndpoint,
		InterceptionRootSHA256:  interceptionRootFingerprintsForTenant(b.config, tenant, b.nodeTenant),
		AgentPolicyPublicKeys:   b.config.AgentPolicyNextPublicKeys,
		TransportServerName:     serverName,
		RenewalRecoverySNI:      recoveryNameForTenant(b.config.RenewalRecoverySNI, serverName),
	}, time.Now())
	if err != nil {
		log.Printf("trust_bundle WARNING could not sign the bundle for %q (%v) — that organization's agents cannot "+
			"learn which anchors to trust or report on", tenant, err)
		return agentpolicy.Envelope{}, false
	}
	b.cached[tenant] = cachedTrustBundle{generation: b.generation, envelope: env}
	return env, true
}

// announcedAnchorPEMs is the anchor set THIS organization's devices are told to trust, and what it is made of:
// the concatenated PEMs, how many of them are the organization's own, and whether the shared anchor has left
// this organization's bundle.
//
// ★★★ EXTRACTED BECAUSE THE SCREEN WAS ANSWERING ABOUT A DIFFERENT SET (2026-08-20). /admin/transport-trust-anchors
// read the node's CONFIGURED bundle, so mid-overlap it showed one anchor — the shared one — while the lab
// organization's devices were being handed three, and its readiness and "safe to cut" were computed for the
// set nobody is verifying against. The decision that screen exists to support is the withdrawal of the shared
// anchor, which is precisely the decision it could not see.
//
// So both callers derive from here. Must be called with b.mu held.
func (b *perTenantTrustBundles) announcedAnchorPEMs(tenant string) (string, int, bool) {
	withdrewShared := false
	pems := b.pems
	// ★ EVERY authority this organization is being moved between, not just the one in use — see AnchorsFor.
	// An overlap that announces only the end in use is not an overlap.
	// Close a rotation that has been adopted BEFORE deciding what to announce, so the bundle this call
	// produces is the one that follows the promotion rather than the one before it.
	b.promotePendingIfAdopted(tenant)
	own := transportTenantCertificates.AnchorsFor(tenant)
	if len(own) > 0 {
		for _, anchor := range own {
			pems = strings.TrimRight(pems, "\n") + "\n" + strings.TrimSpace(anchor) + "\n"
		}
		// ★★★ ROADMAP D, S4: and once every one of this organization's devices HOLDS its own anchor, the shared
		// one leaves this organization's bundle. That is the whole point of D — while the shared anchor is in
		// an organization's bundle, whoever holds it can impersonate this Edge to that organization's devices.
		//
		// Measured, never assumed, and re-measured on every rebuild: if the answer stops being complete — a
		// device enrols and has not reported, a report goes stale, a machine comes back on an older
		// distribution — the shared anchor RETURNS to the bundle and the serial advances, so the fleet lands
		// back on the overlap rather than on a set some device cannot verify. A withdrawal that cannot undo
		// itself is a withdrawal nobody should make automatically.
		//
		// The device keeps the last refusal: it verifies the offered anchors against the chain this Edge is
		// actually serving it before adopting, and stays where it is if they do not validate.
		// ★ AND THE WITHDRAWAL IS ONLY OFFERED WHEN THERE IS ONE END TO WITHDRAW TO. Mid-overlap this
		// organization has two authorities of its own; dropping the shared anchor then would leave devices
		// choosing between two sets while they are still moving between them.
		if len(own) == 1 && b.sharedAnchorMayBeWithdrawn(tenant) {
			pems = strings.TrimSpace(own[0]) + "\n"
			withdrewShared = true
		}
	}
	// ★ REPORTED FROM THE BRANCH THAT MAKES IT, NOT RE-DERIVED FROM THE RESULT (2026-08-20). It was
	// re-derived, and the comparison was wrong in a way nothing could see: it trimmed one side and appended a
	// newline to the other, so it was ALWAYS false. The admin screen's "shared_anchor_withdrawn" therefore read
	// false while the shared anchor was gone from that organization's bundle, and the announcement token built
	// on it never appeared — so the withdrawal never advanced the serial. A fact deduced from an output is a
	// second implementation of the decision; this returns the decision itself.
	return pems, len(own), withdrewShared
}

// PromoteIfAdopted asks whether this organization's overlap can close, and closes it when it can.
//
// ★★★ SOMETHING HAS TO ASK (2026-08-20, measured). The promotion was evaluated only while BUILDING a bundle,
// and bundles are cached by generation — so once the evidence settled, nothing rebuilt and nothing re-asked.
// On the lab both devices reported holding the incoming authority at the current distribution and the overlap
// stayed open, because the evidence arrives asynchronously and no code path was going to look again. A gate
// that only runs when something else changes is not a gate on the thing it measures.
//
// Invalidating on a promotion is the other half: the bundles cached under the old set name an authority this
// node has just stopped serving.
func (b *perTenantTrustBundles) PromoteIfAdopted(tenant string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	promoted := b.promotePendingIfAdopted(strings.TrimSpace(tenant))
	if promoted {
		b.generation++
	}
	b.mu.Unlock()
}

// CatchUpWithTheFleet promotes an organization that the FLEET has already moved, without waiting to re-measure
// the devices.
//
// ★★★ THE PROMOTION WAS NOT DURABLE (2026-08-20, measured on the restart right after it first fired). Which
// authority a node serves for an organization lives in an in-memory index built at boot from the files on disk
// plus the material the control plane hands over — so every restart put the file-based authority back in front
// and RE-OPENED an overlap that had already closed on evidence. The periodic pass then closed it again a
// minute later: two serial advances per restart, and a fleet that flaps between two anchors and one.
//
// The durable record already exists and is already shared: the fleet's own announcement. If it names this
// organization's incoming authority and no longer names the one this node is serving, the fleet has moved, the
// devices were told, and this node is simply behind. Catching up is not a new decision — it is reading the
// decision that was made.
//
// It cannot widen anything: it only ever moves this node ONTO an authority the signed distribution already
// tells that organization's devices to trust.
func (b *perTenantTrustBundles) CatchUpWithTheFleet(tenant, announced string) {
	if b == nil || b.config.DistributedTenantTrust != nil || strings.TrimSpace(announced) == "" {
		return
	}
	tenant = strings.TrimSpace(tenant)
	pending := transportTenantCertificates.PendingFingerprintFor(tenant)
	if pending == "" {
		return
	}
	fleetNames := func(fingerprint string) bool {
		if strings.TrimSpace(fingerprint) == "" {
			return false
		}
		for _, token := range strings.Split(announced, ",") {
			name, fp, ok := strings.Cut(strings.TrimSpace(token), "=")
			if ok && strings.EqualFold(strings.TrimSpace(name), tenant) &&
				strings.EqualFold(strings.TrimSpace(fp), fingerprint) {
				return true
			}
		}
		return false
	}
	serving, _ := transportTenantCertificates.AnchorFingerprintFor(tenant)
	if !fleetNames(pending) || fleetNames(serving) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if transportTenantCertificates.PromotePending(tenant) {
		b.generation++
		log.Printf("transport tenant certificate: %q now SERVES %s because the FLEET already announces it and "+
			"no longer announces %s — this node was behind, not deciding", tenant, shortFingerprint(pending),
			shortFingerprint(serving))
	}
}

// AnnouncedAnchorsFor is announcedAnchorPEMs for a caller that does not hold the lock — the admin screen.
//
// ★ IT PROMOTES, LIKE THE BUILD DOES, AND THAT IS DELIBERATE. Promotion is driven by evidence already
// recorded, not by the call, and it is idempotent. Letting the screen skip it would reintroduce the exact
// drift this extraction removes: the page would show two of the organization's authorities while the next
// bundle the same devices fetch carries one.
func (b *perTenantTrustBundles) AnnouncedAnchorsFor(tenant string) (string, int, bool) {
	if b == nil {
		return "", 0, false
	}

	if b.config.DistributedTenantTrust != nil || b.config.TenantTrustDistributor != nil {
		env, ok := b.For(tenant)
		if !ok {
			return "", 0, false
		}
		payload, err := agentpolicy.VerifyTrustBundleWithKeys(env, append([]string{b.config.AgentPolicySigner.PublicKeyHex()}, b.config.AgentPolicyNextPublicKeys...), 0)
		if err != nil {
			return "", 0, false
		}
		own := transportTenantCertificates.AnchorsFor(payload.TenantID)
		if b.config.TenantTransportAuthority != nil {
			snapshot, err := b.config.TenantTransportAuthority.materialSnapshot()
			if err != nil {
				return "", 0, false
			}
			if row := snapshot.cas[payload.TenantID]; row != nil {
				own = []string{row.CACertPEM}
				if row.Incoming != nil {
					own = append(own, row.Incoming.CACertPEM)
				}
			}
		}
		announced, _ := payload.Fingerprints()
		ownSet := map[string]bool{}
		for _, pem := range own {
			ownSet[fingerprintOfFirstCert(pem)] = true
		}
		withdrew := len(announced) > 0 && len(ownSet) > 0
		for _, fp := range announced {
			if !ownSet[fp] {
				withdrew = false
			}
		}
		return payload.TransportCAPEM, len(ownSet), withdrew
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.TrimSpace(tenant) == "" {
		tenant = b.nodeTenant
	}
	return b.announcedAnchorPEMs(tenant)
}

// interceptionRootFingerprintsForTenant names the interception roots THIS organization's devices must find in
// their own trust store.
//
// An organization that signs under its own root is told about that root and nothing else: naming the
// deployment's other anchors to it would be both a membership disclosure and an instruction to look for
// certificates it should never hold. An organization with no issuer of its own is served by the node-wide
// intermediate, so it is told the node-wide answer — which is exactly what every organization was told
// before, and remains correct for a single-tenant deployment.
func interceptionRootFingerprintsForTenant(config serverConfig, tenant, nodeTenant string) []string {
	// ★★ THE NODE'S OWN TENANT WAS EXCLUDED FROM THIS ENTIRELY (2026-08-18). The guard read "any tenant that is
	// not the node's", so the moment the node's own tenant acquired an interception issuer of its own, its
	// devices would still be announced the node-wide root — the one thing this function exists to prevent. With
	// the interception-root pin armed, every one of that tenant's devices goes from satisfied to mismatch
	// together, which is the fleet-wide stand-aside the 2026-08-16 fix above was written about.
	//
	// It has never fired because the node's tenant has never had its own issuer; it is the precondition for
	// giving it one, which is the last step of making every tenant's PKI independent of the provider's.
	//
	// The question is not "is this the node's tenant" but "does this tenant have an issuer of its own". A
	// deployment where nobody does still falls through to the node-wide answer, unchanged.
	if config.NetworkExtensionLabTLS != nil && strings.TrimSpace(tenant) != "" &&
		(!strings.EqualFold(strings.TrimSpace(tenant), strings.TrimSpace(nodeTenant)) ||
			tenantHasItsOwnInterceptionIssuer(config, tenant)) {
		// EVERY root this organization should be looking for: the one signing now, plus any it is being moved
		// OFF and that has not been withdrawn yet.
		//
		// ★ THIS USED TO RETURN EXACTLY ONE (fixed 2026-08-16). A replacement therefore switched the announced
		// set the instant the new issuer loaded, and every device of that organization still pinned to the
		// previous root went from satisfied to mismatch together — with the pin armed, the whole fleet standing
		// aside at once. The agent's rule that an overlap is a match could never fire, because the Edge had no
		// way to name two.
		// ★ FINGERPRINTS, NOT CERTIFICATES (2026-08-21). A retirement this node knows about only from its
		// durable record — because it came up on material that had already been replaced — has no certificate
		// here, and a device needs only the fingerprint. Asking for certificates dropped exactly the overlap
		// that a file replacement plus a restart creates. See
		// interception_announced_roots_survive_a_restart.go.
		if announced := config.NetworkExtensionLabTLS.OfflineTenantAnnouncedRootFingerprints(tenant); len(announced) > 0 {
			return announced
		}
		// ★★★ AND THE ORDER BETWEEN THE TWO IS NOT ARBITRARY (2026-08-30, measured an hour after adding the
		// second one). An organization can have an authority the CONTROL PLANE holds — one for the whole
		// deployment, which every Edge takes — and a root minted on THIS node. When both exist the control
		// plane's is the answer: it is the one every other Edge will also serve, and a device is told one
		// fingerprint and may be served by any of them.
		//
		// Measured with the order the other way round, minutes after the control-plane authority was created:
		//
		//	osaka announced f1c7fdf6…   (the deployment's authority for Sakura Foods)
		//	tokyo announced efa1ac6d…   (a root left over on that node)
		//
		// — the same organization, two answers, one door apart. The node-local root is what a deployment has
		// before it has an authority, and it must stop being the answer the moment it does.
		for _, root := range config.NetworkExtensionLabTLS.ListTenantInterceptionRoots() {
			if !strings.EqualFold(strings.TrimSpace(root.Tenant), strings.TrimSpace(tenant)) {
				continue
			}
			if tenantHasCentralInterceptionAuthority(config, tenant) {
				break
			}
			if fps := interceptionRootFingerprintsFromPEM(root.CertPEM); len(fps) > 0 {
				return fps
			}
		}
		for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
			if !strings.EqualFold(strings.TrimSpace(issuer.Tenant), strings.TrimSpace(tenant)) {
				continue
			}
			// The issuer exists but its root could not be read. Returning the node-wide list here would tell
			// this organization to look for another organization's root, so it is told nothing rather than
			// something false — and the log says why, because an empty list is otherwise indistinguishable
			// from a deployment that does not intercept.
			log.Printf("trust_bundle WARNING %q has an interception issuer whose root could not be read; its agents "+
				"are told no interception root rather than another organization's", tenant)
			return nil
		}
	}
	return nodeWideInterceptionRootFingerprints(config)
}

// tenantHasItsOwnInterceptionIssuer reports whether this tenant signs under a root of its own on this node.
func tenantHasItsOwnInterceptionIssuer(config serverConfig, tenant string) bool {
	if config.NetworkExtensionLabTLS == nil {
		return false
	}
	for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
		if strings.EqualFold(strings.TrimSpace(issuer.Tenant), strings.TrimSpace(tenant)) {
			return true
		}
	}
	// ★★★ AND A ROOT MINTED ON THIS NODE IS ALSO AN ISSUER OF ITS OWN (2026-08-30, measured on a deployment
	// stood up from nothing, reported by win-dev-1 from the device side).
	//
	// There are TWO ways an organization comes to sign under its own root: an offline intermediate imported
	// from material it signed itself, and a root minted here through POST /admin/interception-roots/{tenant}.
	// This asked about the first only. So a deployment that had minted the second signed that organization's
	// traffic under the organization's root and told its devices to look for the DEPLOYMENT's:
	//
	//	signing   769131f4…  CN=Lantern DSSE Interception Root (tenant_zkn2u…)
	//	announced 83fe37b9…  O=Hikari Networks, CN=Hikari Networks Root CA
	//
	// A device then reports interception_root_trust wanted=1 found=0 and never looks for the certificate that
	// is actually signing its traffic. Every step that produced this answered 200.
	for _, root := range config.NetworkExtensionLabTLS.ListTenantInterceptionRoots() {
		if strings.EqualFold(strings.TrimSpace(root.Tenant), strings.TrimSpace(tenant)) {
			return true
		}
	}
	return false
}

// trustBundleInvalidate lets code that changes an organization's anchors say so without reaching through the
// route registration that owns the cache. It is a package-level seam rather than a parameter because the one
// caller — loading an organization's interception issuer — sits in a different file registered earlier, and
// threading the cache through every constructor between them would be worse than a named hook.
//
// nil until the trust bundle is being served at all (no -trust-bundle-ca / no signing key), which is why
// every caller goes through invalidateTrustBundles rather than calling it directly.
var trustBundleInvalidate func()

func invalidateTrustBundles() {
	if trustBundleInvalidate != nil {
		trustBundleInvalidate()
	}
}

// sharedAnchorMayBeWithdrawn answers roadmap D's last question for one organization: does every device of
// this organization that adopts trust bundles hold this organization's OWN transport anchor, at the
// distribution this Edge is currently handing out?
//
// Silence is never yes. A device that has not reported has not been shown to hold anything, and it is the one
// that will be verifying against whatever it kept.
func (b *perTenantTrustBundles) sharedAnchorMayBeWithdrawn(tenant string) bool {
	if b == nil || b.config.ObservedExclusions == nil || b.config.EnrolledLedger == nil {
		return false
	}
	fp, ok := transportTenantCertificates.AnchorFingerprintFor(tenant)
	if !ok || strings.TrimSpace(fp) == "" {
		return false
	}
	known := []string{}
	for _, e := range b.config.EnrolledLedger.List() {
		if !e.Enabled || !e.IsEndpoint() {
			continue
		}
		if t := strings.TrimSpace(e.TenantID); t != "" && !strings.EqualFold(t, tenant) {
			continue
		}
		known = append(known, e.Identity)
	}
	if len(known) == 0 {
		// No devices at all is not "everybody holds it". An organization with nothing enrolled would otherwise
		// have the shared anchor withdrawn from a bundle its first device will read.
		return false
	}
	// ★★★ FRESH IN TIME, NOT PINNED TO THE CURRENT SERIAL (2026-08-20, and getting this wrong made the lab
	// oscillate once a minute for as long as it took to read the log).
	//
	// This decision is REVERSIBLE and it is PUBLISHED: withdrawing the shared anchor changes what the
	// announcement says, which advances the serial, which — under a serial-pinned reading — instantly makes
	// every device's report stale, which un-withdraws it, which advances the serial again. The gate fed itself
	// its own output. Measured: 88, 89, 90, one per minute, with the shared anchor flapping in and out of two
	// devices' trust sets.
	//
	// The serial test belongs to the question "is this device on the CURRENT distribution", and that is the
	// right question for promotion — starting to SERVE something. It is the wrong question here. What this
	// gate needs to know is "does this device hold its organization's own authority", and a device can only
	// have got that from a distribution that carried it. Holding it is the evidence; which distribution it
	// last reported is not. Freshness still applies — a report older than the shelf life counts as silence —
	// so a machine that has been off does not open the gate.
	readiness := b.config.ObservedExclusions.TransportCAReadiness(tenant, fp, known)
	if !(len(readiness.Ready) == len(known) && len(readiness.NotReady) == 0 && len(readiness.Silent) == 0) {
		return false
	}
	// ★★★ AND EVERY DOOR THESE DEVICES DIAL, NOT ONLY THE ANCHOR THEY HOLD (2026-08-22, measured — it took the
	// whole lab fleet silent for two hours before anybody noticed, and it would have stayed silent for two
	// WEEKS).
	//
	// This gate asked one question: does every device hold its organization's own transport authority. Every
	// device did. So the shared anchor left the bundle — and the devices stopped reporting, because the
	// AGENT PLANE is a different listener from the transport plane and still presents the DEPLOYMENT's
	// certificate:
	//
	//	:18543 sni=lab.dsse.invalid   CN=lab.dsse.invalid       signed by the organization's own CA   ✓
	//	:8443  (the agent plane)      CN=dsse-edge              signed by Lantern DSSE Operator TLS CA ✗
	//
	// The device held exactly one anchor, refused the agent plane's certificate every sixty seconds, and said
	// so nowhere an operator would look: browsing kept working, because that is the transport plane. Every
	// readiness measurement in the product runs on those reports, so every rotation, every rename and every
	// retirement quietly froze.
	//
	// And the recovery the comment above promises — "if the answer stops being complete the shared anchor
	// RETURNS" — is fed by the reports that just stopped, and a report counts as silence only after
	// transportCAReportShelfLife. FOURTEEN DAYS. The gate had walked into the one state its own reversibility
	// could not reach.
	//
	// So the question is not "what does this device hold" but "is this device still using a door the
	// withdrawal would break". The device answers that itself, in transport_server_name_sent: a device that
	// reports sending this organization's own transport name is on the folded per-organization port and needs
	// nothing shared. A device that reports something else, or has not said, is not evidence — same rule as
	// everywhere else here, and it is the rule that keeps the enrolment fold honest, because the fold is exactly what makes
	// this withdrawal safe.
	own, ok := transportTenantCertificates.ServerNameFor(tenant)
	if !ok || strings.TrimSpace(own) == "" {
		return false
	}
	sending := map[string]string{}
	for _, e := range b.config.ObservedExclusions.Query(tenant, observedQueryFilter{}).Entries {
		if n := strings.TrimSpace(e.TransportServerNameSent); n != "" {
			sending[strings.ToLower(strings.TrimSpace(e.DeviceIdentity))] = strings.ToLower(n)
		}
	}
	for _, identity := range known {
		if !strings.EqualFold(sending[strings.ToLower(strings.TrimSpace(identity))], own) {
			return false
		}
	}
	return true
}

// promotePendingIfAdopted closes a rotation: this node starts SERVING the authority it has been announcing,
// once every device of that organization has been measured holding it.
//
// ★★★ THE MEASUREMENT IS THE WHOLE MECHANISM (2026-08-20). Promotion drops the old authority from this
// organization's bundle, so a device that has not adopted the new one is left verifying with something the
// fleet no longer announces and this node no longer presents. Silence is not adoption; a report from six
// months ago is not adoption; a device on an older distribution is not adoption. All three are already the
// rules transportCAReadiness applies, which is why the same measurement is used rather than a second one.
//
// Re-checked on every rebuild, like the withdrawal below it. Nothing here is irreversible in the dangerous
// direction: the pending anchor is announced for as long as it takes, and a rotation that never completes
// simply leaves the organization on two anchors, which is the safe end.
func (b *perTenantTrustBundles) promotePendingIfAdopted(tenant string) bool {
	if b != nil && b.config.DistributedTenantTrust != nil {
		return false
	}
	if b == nil || b.config.ObservedExclusions == nil || b.config.EnrolledLedger == nil {
		return false
	}
	pending := transportTenantCertificates.PendingFingerprintFor(tenant)
	if pending == "" {
		return false
	}
	// ★★★ NOT BEFORE THIS NODE KNOWS WHAT IT IS DISTRIBUTING (2026-08-20, seen in the log line that reported
	// its own weakness: "reported holding it at distribution 0"). The readiness question is "did every device
	// report at the CURRENT distribution", and a node that has not read the trust store yet has no current
	// distribution — so the comparison degrades to "at any distribution, ever", which is exactly the stale
	// evidence the serial exists to reject. Promotion starts SERVING an authority; accepting stale evidence
	// for it is how a fleet locks out the devices that have not moved.
	//
	// It fires a minute later instead, from the periodic pass, with a real serial. Waiting is free; this is
	// not.
	if b.serial <= 0 {
		return false
	}
	known := []string{}
	for _, e := range b.config.EnrolledLedger.List() {
		if !e.Enabled || !e.IsEndpoint() {
			continue
		}
		if t := strings.TrimSpace(e.TenantID); t != "" && !strings.EqualFold(t, tenant) {
			continue
		}
		known = append(known, e.Identity)
	}
	if len(known) == 0 {
		// ★★★ "NOBODY HAS REPORTED" AND "THERE IS NOBODY" ARE DIFFERENT ZEROES (2026-08-22, measured on
		// tenant_northwind — and this comment used to say the opposite).
		//
		// It read: "No devices to strand — but also nothing measured", and refused. Both halves are true and
		// the conclusion did not follow. Keeping an overlap costs nothing on its own, so refusing looked free
		// — but the overlap also freezes which certificate this node SERVES, and therefore which NAME it
		// answers to. Measured: northwind's rename completed on the control plane (server_name=st3zohor…,
		// renaming=false) and the wire went on answering northwind.dsse.invalid for ever, because the
		// promotion waited on evidence from devices that do not exist. An organization provisioned ahead of
		// its first device could never finish anything.
		//
		// There is nobody to strand. That is not evidence that anyone adopted; it is that adoption is not a
		// question here. Said in the log as its own sentence, because the two must never be confused on a
		// screen.
		if transportTenantCertificates.PromotePending(tenant) {
			log.Printf("transport tenant certificate: %q now SERVES the authority it has been announcing "+
				"(%s) — this organization has NO enrolled device, so there is nobody holding the previous "+
				"anchor to strand. This is not adoption; it is that there is nothing to adopt", tenant,
				shortFingerprint(pending))
			return true
		}
		return false
	}
	readiness := b.config.ObservedExclusions.TransportCAReadinessAtSerial(tenant, pending, known, b.serial)
	if len(readiness.Ready) != len(known) || len(readiness.NotReady) > 0 || len(readiness.Silent) > 0 {
		return false
	}
	if transportTenantCertificates.PromotePending(tenant) {
		log.Printf("transport tenant certificate: %q now SERVES the authority it has been announcing "+
			"(%s) — every one of its %d device(s) reported holding it at distribution %d, so the previous "+
			"authority leaves this organization's bundle", tenant, shortFingerprint(pending), len(known), b.serial)
		return true
	}
	return false
}

// recoveryNameForTenant is the recovery name THIS organization should be told, which has to be one its own
// devices can verify.
//
// ★★★ THE DEPLOYMENT-WIDE NAME BECOMES UNUSABLE THE MOMENT AN ORGANIZATION GETS ITS OWN AUTHORITY
// (2026-08-20, measured the night roadmap D first completed). That name is answered with the deployment-wide
// certificate — it must be, because the server picks its certificate from the name and every organization was
// sending the same one — and an organization that has moved onto its own authority no longer trusts it. On the
// lab: a device holding one anchor verifies lab.dsse.invalid and REFUSES recovery.dsse.invalid, while the
// dedicated recovery port had already been retired on the evidence that every device HELD the name. Nobody had
// asked whether they could verify what answers to it.
//
// So an organization with its own certificate is told recovery.<its name>, which that same certificate carries.
// An organization without one keeps the deployment's answer, which is what every organization had before.
func recoveryNameForTenant(configured, serverName string) string {
	offered := offeredRenewalRecoverySNI(configured)
	if offered == "" {
		return ""
	}
	own := organizationRecoveryName(serverName)
	if own == "" {
		return offered
	}
	// Only if this node actually serves it — the guard everywhere else in this file: never announce a name
	// nothing answers to.
	if _, _, ok := transportTenantCertificates.For(own); !ok {
		return offered
	}
	return own
}

// interceptionRootFingerprintsFromPEM is the fingerprint of every certificate in a PEM, which for a minted
// per-tenant root is one. Separate so the announcement and the mismatch check read a root the same way.
func interceptionRootFingerprintsFromPEM(pem string) []string {
	out := []string{}
	for _, cert := range parseAllCerts([]byte(pem)) {
		out = append(out, certFingerprint(cert))
	}
	return out
}

// tenantHasCentralInterceptionAuthority reports whether the deployment — not this node — holds this
// organization's interception authority. When it does, a root minted on this node is history: every Edge
// serves the deployment's, and announcing the local one would tell this organization's devices to look for a
// certificate only one node signs under.
func tenantHasCentralInterceptionAuthority(config serverConfig, tenant string) bool {
	if config.NetworkExtensionLabTLS == nil {
		return false
	}
	for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
		if strings.EqualFold(strings.TrimSpace(issuer.Tenant), strings.TrimSpace(tenant)) {
			return true
		}
	}
	return false
}
