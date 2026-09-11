package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// transport_tenant_certificates.go — the server certificate an organization's own devices see.
//
// ★★★ ROADMAP ITEM D, FIRST SLICE (2026-08-19, designed in the per-organization certificate design).
// The trust bundle's transport_ca_pem is one certificate for every organization, so whoever holds the
// provider's transport anchor can impersonate this Edge to ANY organization's devices. That is the last
// violation of the ownership line the rest of the PKI has already crossed.
//
// The selector is SNI, and deliberately not DNS. GetConfigForClient runs before the client certificate
// arrives, so the organization cannot be resolved from the credential — the ClientHello is all there is. And
// an agent does not need a resolvable name: it dials an address and SENDS a name. The Windows agent already
// carries a serverName it can vary per region; the same field carries this. the enrolment fold-1 chose the same mechanism
// for the recovery path, so both folds share one selector instead of inventing two.
//
// Indexed by the SANs of the certificate itself rather than by a naming convention: the certificate declares
// which names it answers for, and an SNI nobody's certificate names falls through to the shared one. This
// slice therefore changes NOTHING for any device — nobody sends these names yet. What it buys is that the
// steps that do change something (S2 distribute, S3 tell agents the name, S4 measure adoption and withdraw
// the shared anchor) each become small.
// restart-durability: edge_durable — persisted as files under -transport-tenant-cert-dir, which is where an
// organization's transport certificate is placed; this map is only the index, rebuilt from that directory at
// every start-up (loadTransportTenantCertificates, called before any listener). The control plane does not own
// it because it is material an Edge SERVES, keyed to a private key that must not travel: the CP holds who owns
// what, not the key that answers a handshake. Losing the map costs nothing — losing the directory means those
// organizations are served the shared certificate again, which is the state this exists to leave and is
// visible on the start-up line rather than silent.
//
// populated-by: assertion — loadTransportTenantCertificates re-reads the directory at every start-up and
// rebuilds the index from it, so the map cannot be persisted-but-empty: what is on disk is what is in force,
// and the start-up line names every organization and every name that was loaded. A certificate that could not
// be read, or that carries no name an SNI could select, is refused with a reason rather than counted — being
// in the directory is not the claim, being loaded is.
type transportTenantCerts struct {
	mu    sync.RWMutex
	bySNI map[string]*tls.Certificate
	// renamingTo / renamingFrom record that an organization is being moved onto a new transport name and is
	// still answering to the old one. Recorded from the MATERIAL rather than read off the certificate's SAN: a
	// certificate legitimately carries several names, and only the control plane knows which is being retired.
	renamingTo   map[string]string
	renamingFrom map[string]string
	// tenantOf records which organization each name belongs to, for the log and the admin surface. A name
	// without an organization would be a certificate this node serves on behalf of nobody.
	tenantOf map[string]string
	// anchorOf is the certificate an organization's devices must hold to verify the one above: the top of the
	// chain this Edge serves them, or the certificate itself when it is self-signed.
	//
	// ★ DERIVED FROM WHAT IS SERVED, NEVER CONFIGURED SEPARATELY (roadmap D, S2). A second place to record
	// "which anchor belongs to this organization" is a second place to drift from the certificate actually
	// presented — which is the defect this whole area keeps producing, most recently as an announcement naming
	// a root nothing signed under. There is one input: the certificate on disk. The anchor is read out of it.
	anchorOf map[string]string
	// refused names the organizations this node has taken out of service, with the reason. See Refuse.
	refused map[string]string
	// ★★★ WHEN THIS MATERIAL STOPS WORKING, KEPT WITH THE MATERIAL (2026-09-08, found by review).
	//
	// The effective deadline is not the leaf's NotAfter. It is the earliest end along the path that was
	// actually VERIFIED when the material was installed — leaf, whatever intermediates came with it, the
	// anchor its own devices are told to trust — and the lease the control plane stated beside it, whichever
	// comes first. Reading the leaf alone made an issuer that expired after installation invisible to the
	// selector, to the watcher and to the renewal schedule at once: a client refused the chain and nothing on
	// this node could see why.
	//
	// It lives HERE, beside the certificate, because it has to move when the certificate moves. Kept in the
	// fetcher it survived a promotion and was applied to the certificate that replaced it — so a node holding
	// twelve valid hours judged itself expired on the deadline of material it no longer serves.
	activeDeadlineOf  map[string]time.Time
	pendingDeadlineOf map[string]time.Time
	// ★★★ WHICH GENERATION OF MATERIAL A DECISION WAS TAKEN ABOUT (2026-09-08, found by review).
	//
	// The certificate and its deadline are written together now, but a JUDGEMENT still read them, then went
	// away to take locks of its own, and applied its conclusion afterwards. Measured: a judge that observed a
	// one-minute certificate, a promotion that replaced it with twelve valid hours, and then the judge waking
	// up and refusing the organization and killing the node on what it had seen before.
	//
	// A number that moves on every change is enough to catch it: a decision states which generation it was
	// taken about, and is thrown away rather than applied if the answer has moved on.
	generation uint64
	// retiring names the organizations whose material the control plane no longer has.
	//
	// ★★★ A NAME THIS FLEET HAS ANNOUNCED IS A PROMISE, AND DROPPING THE CERTIFICATE DOES NOT RETRACT IT
	// (2026-08-21, measured by doing it the other way round and taking the deployment down). An organization
	// was deleted and purged; every Edge stopped serving its name while the shared announcement went on
	// promising it, and the fleet-promise guard — correctly — refuses to let a node join when it cannot keep a
	// promise the fleet has made. region-b exited, region-a crash-looped, and nothing recovered until the
	// announcement was retracted by hand.
	//
	// So it is two phases, in the order every other withdrawal in this design uses:
	//
	//	1. RETRACT   the organization leaves the announcement; the serial advances; devices are told
	//	2. STOP      once the announcement no longer names it, the certificate is dropped
	//
	// Between the two the node still SERVES the name. That is the point: a promise is kept until it has been
	// withdrawn, not until somebody notices it should have been.
	retiring map[string]bool
	// pendingAnchorOf is an authority this node ANNOUNCES but does not yet serve from.
	//
	// ★★★ A ROTATION IS AN OVERLAP, NOT A SWITCH (2026-08-20). Moving an organization onto an authority the
	// control plane holds — so that Edges added under load can be handed material — means a NEW anchor, and
	// every device of that organization verifies with the old one until it has adopted the new. Serving the
	// new certificate the moment it arrives refuses every device that has not caught up, which is the same
	// mistake as swapping a transport CA without an overlap.
	//
	// So the new authority is announced first and served later: it rides in the trust bundle alongside the
	// one in use, adoption is measured, and only then does this node begin presenting it.
	pendingAnchorOf map[string]string
	// pendingCertOf is the certificate that will be served once the pending anchor has been adopted, kept so
	// the promotion is a decision rather than another fetch.
	pendingCertOf map[string]*tls.Certificate
	pendingNames  map[string][]string
}

// newTransportTenantCerts is the ONE place this index is constructed.
//
// ★ IT EXISTS BECAUSE THERE WERE TWO (2026-08-20). The global and the test helper each built the struct by
// hand, so adding a map to the type left the test's copy with a nil one and the first write panicked. A type
// with more than one construction site grows a field that only some of them know about.
func newTransportTenantCerts() *transportTenantCerts {
	return &transportTenantCerts{
		bySNI: map[string]*tls.Certificate{}, tenantOf: map[string]string{}, anchorOf: map[string]string{},
		retiring:        map[string]bool{},
		pendingAnchorOf: map[string]string{}, pendingCertOf: map[string]*tls.Certificate{},
		pendingNames: map[string][]string{},
	}
}

var transportTenantCertificates = newTransportTenantCerts()

// registerTransportTenantCertDirFlag is in a sibling file because the decomposition ratchet says new flags go
// in one, and because this setting has one reason for existing.
func registerTransportTenantCertDirFlag() *string {
	return flag.String("transport-tenant-cert-dir", "", "directory of per-organization transport server certificates, as <tenant>.crt + <tenant>.key. The Edge serves one of these when the ClientHello's SNI matches a name in that certificate, and the shared -transport-tls-cert otherwise. Empty = every organization is served the shared certificate, which is the state roadmap item D exists to end (the per-organization certificate design)")
}

// loadTransportTenantCertificates reads the directory and indexes each certificate by the names it carries.
//
// Not fatal when the directory is unreadable: an Edge that refuses to start because an OPTIONAL per-tenant
// certificate could not be read takes every organization down for one organization's material — the same
// trade the agent-configuration publisher was corrected under.
func loadTransportTenantCertificates(dir string) (int, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", dir, err)
	}
	loaded := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".crt") {
			continue
		}
		tenant := strings.TrimSuffix(name, ".crt")
		certPath := filepath.Join(dir, name)
		keyPath := filepath.Join(dir, tenant+".key")
		pair, perr := tls.LoadX509KeyPair(certPath, keyPath)
		if perr != nil {
			log.Printf("transport tenant certificate: WARNING %q could not be loaded (%v) — that organization's "+
				"devices are served the shared certificate, which is what they were served before", tenant, perr)
			continue
		}
		leaf, lerr := x509.ParseCertificate(pair.Certificate[0])
		if lerr != nil {
			log.Printf("transport tenant certificate: WARNING %q could not be parsed (%v)", tenant, lerr)
			continue
		}
		// ★ A CERTIFICATE WITH NO NAMES ANSWERS FOR NOTHING, and loading it would report a per-organization
		// certificate in force that no handshake can ever select. Refused loudly rather than counted.
		if len(leaf.DNSNames) == 0 {
			log.Printf("transport tenant certificate: WARNING %q carries no DNS names, so no SNI can select it — "+
				"it is NOT loaded. Issue it with the name that organization's agents will send", tenant)
			continue
		}
		pair.Leaf = leaf
		// The anchor devices must hold: the top of the chain as served, or the leaf itself when it is its own
		// issuer. Read here so it cannot disagree with what the handshake presents.
		anchorDER := pair.Certificate[len(pair.Certificate)-1]
		anchor := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchorDER}))
		// ★ MATERIAL READ FROM DISK CARRIES NO LEASE AND NO VERIFIED PATH — nobody handed it over, it was
		// already here. Its deadline is the earliest end in the chain on disk, which is the most this node can
		// say about it; the control plane's answer replaces it on the first fetch.
		fromDisk := time.Time{}
		for _, der := range pair.Certificate {
			if c, perr := x509.ParseCertificate(der); perr == nil {
				if fromDisk.IsZero() || c.NotAfter.Before(fromDisk) {
					fromDisk = c.NotAfter.UTC()
				}
			}
		}
		transportTenantCertificates.put(tenant, leaf.DNSNames, &pair, anchor, fromDisk)
		invalidateTrustBundlesAfterTransportMaterialChange(tenant, "loaded from disk")
		loaded++
		log.Printf("transport tenant certificate: %q answers for %v (subject %q)", tenant, leaf.DNSNames, leaf.Subject.CommonName)
	}
	return loaded, nil
}

// put installs one organization's certificate under every name it answers to. It is AUTHORITATIVE: a name
// this organization used to have and no longer does stops answering in the same step.
//
// ★★★ IT USED TO ONLY ADD, AND THAT MADE THE DESTRUCTIVE ACT SILENT (2026-08-22, measured on the lab). A name
// once served was served until the process restarted, so retire-previous-name returned 200, the readiness
// screen showed the rename finished — and every device still sending the old name kept connecting. The
// retirement took effect at the NEXT RESTART instead: hours or days later, all at once, with nothing linking
// the outage to the act that caused it. The same leak ran the other way for abandon-rename, where a device
// that had adopted the abandoned name was never pushed back off it.
//
// Scoped by organization. Another organization's names are not this organization's to drop.
// The trailing deadline is optional: a caller that verified a path and holds a lease passes the effective
// deadline; one that simply hands over a certificate says nothing, and the certificate's own end is then all
// that can be known about it.
func (t *transportTenantCerts) put(tenant string, names []string, cert *tls.Certificate, anchorPEM string, effectiveOpt ...time.Time) {
	effective := effectiveDeadlineOrCertificateEnd(cert, effectiveOpt)
	defer noteTransportDeadlinesChanged()
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.Lock()
	defer t.mu.Unlock()
	t.anchorOf[key] = anchorPEM
	if t.activeDeadlineOf == nil {
		t.activeDeadlineOf = map[string]time.Time{}
	}
	t.activeDeadlineOf[key] = effective
	t.generation++
	keep := make(map[string]bool, len(names))
	for _, n := range names {
		name := strings.ToLower(strings.TrimSpace(n))
		if name == "" {
			continue
		}
		keep[name] = true
		t.bySNI[name] = cert
		t.tenantOf[name] = tenant
	}
	// ★ Only names that are BOTH this organization's and absent from what it now has. A name whose tenantOf
	// entry names somebody else belongs to them, however it got there.
	for name, owner := range t.tenantOf {
		if keep[name] || !strings.EqualFold(strings.TrimSpace(owner), key) {
			continue
		}
		delete(t.bySNI, name)
		delete(t.tenantOf, name)
	}
}

// AnchorFor is the certificate this organization's devices must hold to verify the one this Edge serves them.
//
// ★ ADDED to the shared anchors in that organization's trust bundle, never substituted for them (roadmap D,
// S2). A device that has not yet taken the new bundle still verifies against the shared anchor, and a device
// that has takes either — which is what makes the switch survivable. Withdrawing the shared anchor is a
// separate, LATER act, gated on every device of that organization reporting that it holds this one.
func (t *transportTenantCerts) AnchorFor(tenant string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return "", false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	a, ok := t.anchorOf[key]
	return a, ok && strings.TrimSpace(a) != ""
}

// For returns the certificate to serve for this SNI, and whether one was found.
// transportSelectorClock is what the TLS selector judges validity against. A variable so a test can place a
// certificate on either side of its own dates without moving the host's clock.
var transportSelectorClock = time.Now

// Refuse and Allow record that an organization's material cannot be served right now, and that it can again.
//
// ★★★ A LOG LINE IS NOT A REFUSAL (2026-09-08, found by review). The expiry judge named the organizations
// whose material had run out and said the node "REFUSES" them — and nothing was wired to anything: the
// selector went on handing the expired certificate to every ClientHello that asked for that name. The client
// rejects it, which is true and is not the point; a client's refusal is not evidence that this node took the
// organization out of service, and "keep routing traffic into a door that cannot work" is the exact state
// the whole expiry design exists to prevent.
func (t *transportTenantCerts) Refuse(tenant, reason string) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.refused == nil {
		t.refused = map[string]string{}
	}
	t.refused[key] = reason
}

func (t *transportTenantCerts) Allow(tenant string) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.refused, key)
}

// refusalFor answers whether a name this node SERVES cannot be served right now, and why. The distinction
// from "not ours" matters: a name that is not ours falls through to the shared certificate, and a name that
// is ours but unusable must not — answering it with the deployment-wide certificate hands a device of that
// organization something its own anchor refuses, which reads as a broken device rather than a stopped door.
func (t *transportTenantCerts) refusalFor(sni string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(sni))
	if key == "" {
		return "", false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	cert, ok := t.bySNI[key]
	if !ok {
		return "", false
	}
	if reason, dead := t.refused[strings.ToLower(strings.TrimSpace(t.tenantOf[key]))]; dead {
		return reason, true
	}
	// ★ AND THE TIME IS CHECKED HERE TOO, not only by the watcher. Between an expiry and the watcher's next
	// tick there would otherwise be a window in which this node serves a certificate it already knows is
	// dead — and the window is exactly as long as whatever interval somebody chose for the watcher.
	if cert != nil && cert.Leaf != nil {
		// The effective deadline: the path verified at install and the lease, not the leaf alone.
		at := cert.Leaf.NotAfter.UTC()
		what := "its certificate expired at "
		if eff, has := t.activeDeadlineOf[strings.ToLower(strings.TrimSpace(t.tenantOf[key]))]; has &&
			!eff.IsZero() && eff.Before(at) {
			at, what = eff, "the chain it presents stopped being verifiable at "
		}
		if !transportSelectorClock().UTC().Before(at) {
			return what + at.Format(time.RFC3339), true
		}
	}
	return "", false
}

func (t *transportTenantCerts) For(sni string) (*tls.Certificate, string, bool) {
	key := strings.ToLower(strings.TrimSpace(sni))
	if key == "" {
		return nil, "", false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	c, ok := t.bySNI[key]
	return c, t.tenantOf[key], ok
}

// AnchorFingerprints names each organization's own transport anchor, as "tenant=sha256", sorted.
//
// ★ IT FEEDS THE SERIAL (roadmap D, S2). Devices adopt a trust bundle by serial, so content that changes
// without the serial moving never reaches them — measured on win-dev-1, which answered from a fifteen-day-old
// bundle because the interception roots changed and the serial did not. Adding an organization's anchor
// changes what its bundle says, so it belongs in the same announcement the serial follows.
func (t *transportTenantCerts) AnchorFingerprints() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.anchorOf)+len(t.pendingAnchorOf))
	// ★ PENDING ANCHORS COUNT HERE (2026-08-20). This feeds the announcement fingerprint that MOVES THE
	// SERIAL, and devices adopt by serial. Announcing a new authority in the bundle body while leaving this
	// list unchanged means no device ever fetches it — the overlap is published to nobody and can never
	// complete. Measured on the lab: three anchors in the bundle, serial unmoved at 58.
	for _, set := range []map[string]string{t.anchorOf, t.pendingAnchorOf} {
		for tenant, anchorPEM := range set {
			// ★★★ A RETIRING ORGANIZATION LEAVES THE ANNOUNCEMENT HERE TOO (2026-09-07, measured by deleting
			// one and watching, then by finding twenty Edges dead). Phase one of a retirement is "leave the
			// announcement, keep serving" — and it was implemented in the recovery-name loop alone, so a
			// deleted organization's recovery alias left and its ANCHOR and its NAME stayed. Phase two waits
			// for the announcement to stop naming the organization, so it never ran, so the certificate was
			// never dropped, so this line went on producing the token phase two was waiting to see gone. A
			// circular wait with no way out of it.
			//
			// What it cost: the promise outlives the organization, and the next Edge to START fails the
			// fleet-promise guard — "was promised the name … and this node has no certificate for it" — and
			// exits. Every node reads the same announcement, so it is every node, in every region, at once,
			// hours after the deletion that armed it, on whatever unrelated restart happens to come first.
			if t.retiring[strings.ToLower(strings.TrimSpace(tenant))] {
				continue
			}
			for _, c := range parseAllCerts([]byte(anchorPEM)) {
				out = append(out, tenant+"="+certFingerprint(c))
			}
		}
	}
	sort.Strings(out)
	return dedupeStrings(out)
}

func dedupeStrings(in []string) []string {
	out := in[:0]
	var last string
	for i, v := range in {
		if i > 0 && v == last {
			continue
		}
		out = append(out, v)
		last = v
	}
	return out
}

// AnchorFingerprintFor is this organization's own transport anchor, as the fingerprint the readiness
// measurement is keyed by. One anchor per organization: the roadmap D withdrawal asks "does every device hold
// THIS one", and an organization mid-rotation with two would need the question asked of both.
func (t *transportTenantCerts) AnchorFingerprintFor(tenant string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return "", false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	certs := parseAllCerts([]byte(t.anchorOf[key]))
	if len(certs) != 1 {
		// Zero: nothing of its own. More than one: an overlap, and withdrawing the shared anchor on a partial
		// answer is exactly what must not happen — so this says no rather than picking one.
		return "", false
	}
	return certFingerprint(certs[0]), true
}

// ServerNameFor is the name this organization's agents should send as the SNI, announced to them in their
// trust bundle so it is derived from the certificate this Edge serves rather than configured on the device.
//
// The FIRST name on the certificate, because a certificate may carry several and an agent must send one. An
// organization with no certificate of its own gets nothing, which is what an agent that has always dialled
// without a name keeps doing.
// RenameState is the name this organization is served under and the one it is moving OFF, or empty when no
// rename is in flight. Recorded from the MATERIAL rather than read off the certificate's SAN: a certificate
// legitimately carries several names, and only the control plane knows which is being retired.
func (t *transportTenantCerts) RenameState(tenant string) (current, previous string) {
	if t == nil {
		return "", ""
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.renamingTo[key], t.renamingFrom[key]
}

func (t *transportTenantCerts) noteRename(tenant, current, previous string) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.renamingTo == nil {
		t.renamingTo, t.renamingFrom = map[string]string{}, map[string]string{}
	}
	prev := strings.ToLower(strings.TrimSpace(previous))
	if prev == "" {
		delete(t.renamingTo, key)
		delete(t.renamingFrom, key)
		return
	}
	t.renamingTo[key] = strings.ToLower(strings.TrimSpace(current))
	t.renamingFrom[key] = prev
}

func (t *transportTenantCerts) ServerNameFor(tenant string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return "", false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for name, owner := range t.tenantOf {
		if strings.EqualFold(owner, key) {
			if cert, ok := t.bySNI[name]; ok && cert.Leaf != nil && len(cert.Leaf.DNSNames) > 0 {
				return cert.Leaf.DNSNames[0], true
			}
		}
	}
	return "", false
}

// anchorsByTenant is each organization's own anchor, for the code that measures who holds it.
// pendingAnchorsByTenant is each organization's anchor that is ANNOUNCED but not yet served — the far end of
// an overlap in flight.
//
// ★★★ THE CUSTOMER'S OWN CERTIFICATE MAP SHOWED ONE WHILE ITS DEVICES WERE TOLD TWO (2026-08-20). The map
// drew anchorOf only, so during the rotation this whole mechanism exists to perform, the organization could
// see the end it is moving OFF and not the end it is moving ONTO. That is the half a customer needs: the
// question they are being asked is "have your machines picked up the new one yet".
// TenantsWithPendingAuthority names the organizations that are mid-rotation: announcing one authority of
// their own while this node still serves another. They are the only ones a promotion pass has to ask about.
func (t *transportTenantCerts) TenantsWithPendingAuthority() []string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.pendingAnchorOf))
	for tenant := range t.pendingAnchorOf {
		if strings.TrimSpace(tenant) != "" {
			out = append(out, tenant)
		}
	}
	sort.Strings(out)
	return out
}

func (t *transportTenantCerts) pendingAnchorsByTenant() map[string]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]string, len(t.pendingAnchorOf))
	for tenant, pemText := range t.pendingAnchorOf {
		out[tenant] = pemText
	}
	return out
}

func (t *transportTenantCerts) anchorsByTenant() map[string]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]string, len(t.anchorOf))
	for tenant, pemText := range t.anchorOf {
		out[tenant] = pemText
	}
	return out
}

// ServerNameAnnouncements is each organization's announced name, as "tenant=name", sorted.
//
// ★★ IT BELONGS IN THE SERIAL'S ANNOUNCEMENT, AND LEAVING IT OUT COST A LIVE VERIFICATION (2026-08-19).
// The anchors were in it and the NAME was not, so adding a per-organization certificate advanced the serial
// while adding the name to an EXISTING one did not — and a device that had already adopted that serial has no
// reason to fetch again. Measured on mac-dev-1: it held two anchors, adopted_serial=30, and never learned the
// name, because the bundle it adopted was written before the field existed and nothing said the bundle had
// changed since.
//
// The rule is the one this same file's serial work states: the serial follows EVERYTHING the bundle says.
// A field added later is exactly the case that rule exists for.
// ★★★ AND IT PICKED ONE NAME OUT OF A GO MAP, SO THE FLEET NEVER SETTLED (2026-08-20, measured on a
// four-Edge lab). An organization now answers to two names — its own and its recovery alias — and both are in
// this index, because both are in the certificate. This loop kept the FIRST name the range happened to hand
// it, and Go randomises that per pass. So one recompute announced tenant_reference_lab@lab.dsse.invalid, the
// next announced tenant_reference_lab@recovery.lab.dsse.invalid, each node read the other's write as a change,
// and the serial climbed about once a minute with the two strings identical in every other respect.
//
// The consequence is not cosmetic. Devices adopt by serial and the withdrawal gate asks whether every device
// has confirmed the CURRENT distribution — so while the serial moves every minute, no device is ever current,
// and NO TRUST ANCHOR CAN BE WITHDRAWN AT ALL. Measured: fourteen withdrawal attempts over ten minutes, every
// one refused with "unconfirmed: mac-dev-1, win-dev-1", while both devices were healthy and reporting.
//
// Every non-recovery name is announced, sorted: deterministic, and it does not silently drop a name the fleet
// is expected to serve. The recovery alias is announced by recovery-name-for-<tenant>= and is skipped here, so
// it cannot take the primary name's place. An organization that somehow has only a recovery name keeps it —
// dropping the promise entirely would be a shrink, which is the failure the fleet guard exists to prevent.
func (t *transportTenantCerts) ServerNameAnnouncements() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	byTenant := map[string][]string{}
	recoveryOnly := map[string][]string{}
	for name, tenant := range t.tenantOf {
		key := strings.ToLower(strings.TrimSpace(tenant))
		n := strings.ToLower(strings.TrimSpace(name))
		if key == "" || n == "" {
			continue
		}
		// ★★★ AND THE NAME IS THE PROMISE THE GUARD READS. "tenant@name" is what a starting node checks it can
		// keep, so a retiring organization staying here is the token that kills the fleet — see the note in
		// AnchorFingerprints. Retracted while the node goes on SERVING the name, which is the whole point of
		// phase one: nothing stops being answered until every device has been told, by serial, to stop
		// expecting it.
		if t.retiring[key] {
			continue
		}
		// ★ AND THE ENROLMENT NAME TOO (2026-08-21). Every folded path adds a name to the certificate, and
		// every name in the certificate lands in this index. The recovery name taught this the hard way: an
		// announcement that picks one name out of a map flaps forever, the serial climbs every minute, and no
		// trust anchor can be withdrawn while it does. A second folded name is a second chance to repeat it.
		if strings.HasPrefix(n, recoveryNamePrefix) || strings.HasPrefix(n, enrolmentNamePrefix) {
			recoveryOnly[key] = append(recoveryOnly[key], n)
			continue
		}
		byTenant[key] = append(byTenant[key], n)
	}
	for key, names := range recoveryOnly {
		if len(byTenant[key]) == 0 {
			byTenant[key] = names
		}
	}
	out := []string{}
	for tenant, names := range byTenant {
		sort.Strings(names)
		last := ""
		for _, n := range names {
			if n == last {
				continue
			}
			last = n
			out = append(out, tenant+"@"+n)
		}
	}
	sort.Strings(out)
	return out
}

// Names lists what is loaded, for the start-up line and the admin surface — a deployment must be able to say
// which organizations are on their own certificate without reading a directory on the host.
func (t *transportTenantCerts) Names() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.bySNI))
	for name, tenant := range t.tenantOf {
		out = append(out, tenant+" ("+name+")")
	}
	sort.Strings(out)
	return out
}

// transportCertificateForClientHello is the seam: an organization's own certificate when its name is asked
// for, and the shared one otherwise. Wraps whatever the listener would have used, so a deployment with no
// per-organization certificates behaves exactly as before.
func transportCertificateForClientHello(shared func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello != nil {
			// ★ THE OPERATOR'S OWN CERTIFICATE FOR THE STEP-UP PORTAL WINS. It is browser-facing and its
			// name is one the operator holds — see the_step_up_portal_is_a_browser_facing_page.go.
			if cert := stepUpPortalCertificateFor(hello.ServerName); cert != nil {
				return cert, nil
			}
			// A name this node serves but cannot serve RIGHT NOW is refused outright — never answered with
			// the shared certificate. See refusalFor.
			if reason, refused := transportTenantCertificates.refusalFor(hello.ServerName); refused {
				return nil, fmt.Errorf("this node is not serving %q right now (%s), so the connection is "+
					"refused rather than answered with a certificate that organization's devices do not trust",
					hello.ServerName, reason)
			}
			if cert, _, ok := transportTenantCertificates.For(hello.ServerName); ok {
				return cert, nil
			}
			noteUnservedServerName(hello.ServerName)
		}
		return shared(hello)
	}
}

// noteUnservedServerName records that a device asked for a name this node does not serve.
//
// ★★★ THE SILENCE HERE COST AN INVESTIGATION (2026-08-20, reported from win-dev-1). That box asked for the
// name it had been provisioned with, because its agent restored the ANNOUNCED name a few hundred lines too
// late in its start-up. Every dial before that point went out under the old name, was answered with the
// deployment-wide certificate — correctly, that is what a server does with a name it does not recognise — and
// refused by a device that now holds only its own organization's anchor. The first casualty was its
// steering-posture fetch, so that boot ran on bootstrap flags with no control-plane posture at all.
//
// From this side the only trace was a SHA-256 in a refusal list, and finding it meant comparing fingerprints
// against every port. The Edge knew the answer at the moment of the handshake and said nothing.
//
// Rate-limited by NAME, because this is an unauthenticated path and an unbounded log is a way to fill a disk.
// One line per distinct name per hour, and a bounded set of names remembered.
var unservedServerNames = struct {
	mu   sync.Mutex
	seen map[string]time.Time
}{seen: map[string]time.Time{}}

func noteUnservedServerName(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	// No name at all is the ordinary case for probes and for deployments that serve one certificate to
	// everybody. Only a name that was ASKED FOR and is not served says something happened.
	if name == "" {
		return
	}
	now := time.Now()
	unservedServerNames.mu.Lock()
	last, known := unservedServerNames.seen[name]
	if known && now.Sub(last) < time.Hour {
		unservedServerNames.mu.Unlock()
		return
	}
	if len(unservedServerNames.seen) > 64 && !known {
		// Full: forget everything rather than grow. The next occurrence of any name logs again, which is the
		// safe direction for a diagnosis signal.
		unservedServerNames.seen = map[string]time.Time{}
	}
	unservedServerNames.seen[name] = now
	unservedServerNames.mu.Unlock()
	log.Printf("transport_server_name: a device asked for %q, which this node does not serve — it was answered "+
		"with the deployment-wide certificate, and a device holding only its own organization's anchor will "+
		"refuse that. Names this node serves: %v", name, transportTenantCertificates.Names())
}

// installTenantTransportMaterial puts material the CONTROL PLANE issued into the same index the file loader
// fills, so a handshake cannot tell where a certificate came from.
//
// ★★★ THE SAME INDEX ON PURPOSE (2026-08-20). An Edge that appears under load is given short-lived material
// by the control plane instead of having files placed on it; everything downstream — the SNI selector, the
// announced name, the anchor the trust bundle carries, the guard that refuses to join a fleet whose promises
// this node cannot keep — must read one answer. Two paths into "which certificate answers for this
// organization" is how a node ends up announcing one thing and serving another.
//
// The anchor is taken from what was handed over rather than derived again, so the bundle names the authority
// that actually signed the certificate this node will present.
func installTenantTransportMaterial(mat tenantTransportMaterial) error {
	tenant := strings.ToLower(strings.TrimSpace(mat.TenantID))
	if tenant == "" {
		return fmt.Errorf("material with no organization")
	}
	pair, err := tls.X509KeyPair([]byte(mat.CertPEM), []byte(mat.KeyPEM))
	if err != nil {
		return fmt.Errorf("certificate and key do not form a pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if len(leaf.DNSNames) == 0 {
		return fmt.Errorf("the certificate carries no DNS name, so no ClientHello could ever select it")
	}
	anchor := strings.TrimSpace(mat.AnchorPEM)
	if anchor == "" {
		return fmt.Errorf("no anchor was handed over, so this organization's devices could not be told what to trust")
	}
	// ★★★ THE THING BEING INSTALLED IS VERIFIED THE WAY A DEVICE WILL VERIFY IT (2026-09-08, found by
	// review).
	//
	// This checked that the certificate and key formed a pair, that a name was present and that an anchor came
	// with it — and never that the certificate was VALID. Reproduced: a leaf that expired an hour ago,
	// delivered with a not_after twelve hours in the future, installed successfully; the node then served it
	// and scheduled its renewal from the JSON.
	//
	// The install boundary is the right place for this. Every device that reaches this node builds exactly
	// this path — leaf, to the anchor it was told to trust, for server authentication, at the current moment —
	// so building it here is asking, before anything is served, the only question that decides whether serving
	// it works. It also catches a stale-but-genuine response, a delayed one, and an issuing bug, none of which
	// require anyone to have been compromised.
	verifiedUntil, err := transportMaterialPathDeadline(pair, anchor, transportInstallClock().UTC())
	if err != nil {
		return err
	}
	// ★ THE EFFECTIVE DEADLINE IS THE PATH'S END OR THE LEASE'S, WHICHEVER COMES FIRST, and it is computed
	// from the path this material ACTUALLY verified through — not from every certificate in the PEM and not
	// from the leaf alone.
	effective := verifiedUntil
	if lease, lerr := time.Parse(time.RFC3339, strings.TrimSpace(mat.NotAfter)); lerr == nil {
		if lease.UTC().Before(effective) {
			effective = lease.UTC()
		}
	}
	// ★★★ MATERIAL THAT IS ALREADY OVER IS NOT INSTALLED (2026-09-08, found by review). The chain verified,
	// so the certificate itself was fine — and the lease beside it had already run out, which under the
	// contract this node keeps makes the material unusable the moment it lands. It was published anyway,
	// replacing a working certificate, and the selector then refused the organization for a lease that
	// arrived dead. A material this node cannot serve is a failed refresh, not a new state: the previous
	// certificate stays, and the round is left unresolved so the next ask is a full fetch.
	//
	// An unparseable lease is not a deadline and is not read as one — the verified path decides alone.
	if !effective.IsZero() && !transportInstallClock().UTC().Before(effective) {
		return fmt.Errorf("this material is already past its effective end (%s) on arrival — the certificate "+
			"verifies but the lease the control plane put on it has run out, so installing it would replace a "+
			"working certificate with one this node must refuse", effective.Format(time.RFC3339))
	}
	pair.Leaf = leaf
	// Which name this organization is moving off, if any — see RenameState. Recorded before the
	// certificate is put in place, so a readiness read cannot see the new certificate beside a stale rename.
	transportTenantCertificates.noteRename(tenant, mat.ServerName, mat.PreviousServerName)
	// ★★★ IF THIS NODE ALREADY SERVES THAT ORGANIZATION UNDER A DIFFERENT AUTHORITY, THE NEW ONE IS ANNOUNCED
	// FIRST AND SERVED LATER. Presenting it immediately would refuse every device that has not yet adopted it
	// — which is every device, at the moment it arrives. The overlap is the mechanism roadmap D already uses:
	// publish both, measure adoption, then move.
	//
	// A node with nothing of its own for that organization — the autoscaled case this whole path exists for —
	// serves it at once, because there is no device holding an older anchor FROM THIS NODE to strand.
	if existing := strings.TrimSpace(anchorOfTenant(tenant)); existing != "" && existing != anchor {
		if !transportTenantCertificates.putPendingUnlessServingSuccessor(tenant, leaf.DNSNames, &pair, anchor, mat.SuccessorAnchorSHA256, effective) {
			return nil
		}
		// An announcement is a change to what the bundle says, exactly as a promotion is.
		invalidateTrustBundlesAfterTransportMaterialChange(tenant, "announced alongside the one in force")
		log.Printf("transport tenant certificate: %q was issued under a DIFFERENT authority than the one this "+
			"node serves — announcing it alongside rather than switching, so devices can adopt it first "+
			"(serving %s, announcing %s)", tenant, shortFingerprint(fingerprintOfFirstCert(existing)),
			shortFingerprint(fingerprintOfFirstCert(anchor)))
		return nil
	}
	transportTenantCertificates.put(tenant, leaf.DNSNames, &pair, anchor, effective)
	invalidateTrustBundlesAfterTransportMaterialChange(tenant, "installed")
	return nil
}

// invalidateTrustBundlesAfterTransportMaterialChange throws away the cached signatures, because what an
// organization's bundle SAYS has just changed.
//
// ★★★ Invalidate() HAD NO CALLER (2026-08-29, found by a Windows machine adopting a bundle that named the
// DEPLOYMENT's transport authority for an organization that has its own). The builder caches one signed
// bundle per organization and re-signs only when its generation moves; the generation moved when the SHARED
// anchor set changed and never when an organization's OWN certificate arrived. So an Edge that was handed an
// organization's material after it had already answered that organization once went on handing out the old
// bundle — naming only the shared anchor — until the process restarted.
//
// The device then cannot verify the door its own profile tells it to dial, every (T) call fails, and the
// ledger reads green throughout. Restarting the Edge "fixed" it, which is the worst kind of fix: it makes the
// defect look like a transient.
func invalidateTrustBundlesAfterTransportMaterialChange(tenant, what string) {
	if perTenantTrustBundlesForAdmin == nil {
		return
	}
	perTenantTrustBundlesForAdmin.Invalidate()
	log.Printf("trust_bundle invalidated: %q transport material %s, so every organization's bundle is re-signed "+
		"on next ask — a cached bundle would keep naming the anchors this node had BEFORE", tenant, what)
}

func anchorOfTenant(tenant string) string {
	a, ok := transportTenantCertificates.AnchorFor(tenant)
	if !ok {
		return ""
	}
	return a
}

func fingerprintOfFirstCert(pemText string) string {
	for _, c := range parseAllCerts([]byte(pemText)) {
		return certFingerprint(c)
	}
	return ""
}

// putPending records an authority this node will ANNOUNCE but not yet serve. See pendingAnchorOf.
func (t *transportTenantCerts) putPending(tenant string, names []string, cert *tls.Certificate, anchorPEM string, effectiveOpt ...time.Time) {
	t.putPendingUnlessServingSuccessor(tenant, names, cert, anchorPEM, "", effectiveDeadlineOrCertificateEnd(cert, effectiveOpt))
}

// Compare under the promotion lock: a full overlapping refresh must not reverse a
// completed promotion even if promotion happens while the refresh is being installed.
func (t *transportTenantCerts) putPendingUnlessServingSuccessor(tenant string, names []string, cert *tls.Certificate, anchorPEM, successor string, effective time.Time) bool {
	defer noteTransportDeadlinesChanged()
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.Lock()
	defer t.mu.Unlock()
	if successor != "" && fingerprintOfFirstCert(t.anchorOf[key]) == successor {
		return false
	}
	t.pendingAnchorOf[key] = anchorPEM
	t.pendingCertOf[key] = cert
	t.pendingNames[key] = append([]string{}, names...)
	if t.pendingDeadlineOf == nil {
		t.pendingDeadlineOf = map[string]time.Time{}
	}
	t.pendingDeadlineOf[key] = effective
	t.generation++
	return true
}

// AnchorsFor is every authority this organization's devices should be told to hold: the one in use, and any
// this node is preparing to move to. Both, because an overlap that announces only one end strands whichever
// half of the fleet has not moved.
func (t *transportTenantCerts) AnchorsFor(tenant string) []string {
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := []string{}
	if a := strings.TrimSpace(t.anchorOf[key]); a != "" {
		out = append(out, a)
	}
	if p := strings.TrimSpace(t.pendingAnchorOf[key]); p != "" && p != strings.TrimSpace(t.anchorOf[key]) {
		out = append(out, p)
	}
	return out
}

// AnchorFingerprintsFor is AnchorsFor as the fingerprints the readiness measurement and the fleet guard are
// keyed by — the whole set, so a node mid-rotation is judged against both ends of its own overlap.
func (t *transportTenantCerts) AnchorFingerprintsFor(tenant string) []string {
	out := []string{}
	for _, pemText := range t.AnchorsFor(tenant) {
		for _, c := range parseAllCerts([]byte(pemText)) {
			out = append(out, certFingerprint(c))
		}
	}
	return out
}

// PromotePending starts serving what was until now only announced. The caller decides WHEN — the measurement
// that says every device holds the new anchor is the whole point of the overlap.
func (t *transportTenantCerts) PromotePending(tenant string) bool {
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.Lock()
	defer t.mu.Unlock()
	defer noteTransportDeadlinesChanged()
	cert, ok := t.pendingCertOf[key]
	if !ok || cert == nil {
		return false
	}
	// ★★★ THE PROMOTION IS WHERE THE REFUSAL HAS TO LIVE, NOT IN A LOG BESIDE IT (2026-09-08, found by
	// review). The expiry judge said "this node will NOT promote" and changed nothing, and the fleet
	// catch-up path — which promotes on a fingerprint match alone — promoted it anyway, replacing a
	// certificate valid for twelve hours with one that had expired. A fingerprint says which authority the
	// fleet has moved to; it says nothing about whether the leaf THIS node holds under it is still usable.
	//
	// Refusing here covers every entrance, because they all end up in this function.
	deadline := time.Time{}
	if cert.Leaf != nil {
		deadline = cert.Leaf.NotAfter.UTC()
	}
	if eff, has := t.pendingDeadlineOf[key]; has && !eff.IsZero() && (deadline.IsZero() || eff.Before(deadline)) {
		deadline = eff
	}
	// A fixture that never parsed a leaf says nothing about when the material ends; that is not a reason to
	// refuse a promotion, only a reason not to claim one.
	if !deadline.IsZero() && !transportSelectorClock().UTC().Before(deadline) {
		log.Printf("★ transport tenant certificate: NOT promoting the authority %q is moving to — the material "+
			"this node holds under it stopped being usable at %s, so promoting would replace a working "+
			"certificate with one every device refuses. The authority in force is kept and fresh material "+
			"is requested.", tenant, deadline.Format(time.RFC3339))
		return false
	}
	t.anchorOf[key] = t.pendingAnchorOf[key]
	for _, n := range t.pendingNames[key] {
		nk := strings.ToLower(strings.TrimSpace(n))
		if nk == "" {
			continue
		}
		t.bySNI[nk] = cert
		t.tenantOf[nk] = key
	}
	// ★ AND THE DEADLINE MOVES WITH THE CERTIFICATE. Left behind, the deadline of the material that was just
	// replaced was applied to the material replacing it.
	if t.activeDeadlineOf == nil {
		t.activeDeadlineOf = map[string]time.Time{}
	}
	t.activeDeadlineOf[key] = deadline
	t.generation++
	delete(t.pendingCertOf, key)
	delete(t.pendingAnchorOf, key)
	delete(t.pendingNames, key)
	delete(t.pendingDeadlineOf, key)
	return true
}

// PendingFingerprintFor is the authority this node is announcing but not yet serving, as the fingerprint the
// readiness measurement is keyed by. Empty when there is no rotation in flight.
// ActiveDeadlines and PendingDeadlineFor read when the certificates this node is SERVING and ANNOUNCING run
// out, from the certificates themselves.
//
// ★★★ A SECOND RECORD OF THE SAME FACT IS A SECOND PLACE FOR IT TO BE WRONG (2026-09-08, found by review,
// three ways in one round).
//
// The fetcher kept its own book of deadlines beside this store, written when material was installed. Every
// transition that moved a certificate without going through an install moved one and not the other:
//
//   - a PROMOTION swapped the served certificate for the pending one and left the book on the old deadline,
//     so a node holding a certificate valid for twelve hours judged itself expired and left the fleet;
//   - a WITHDRAWN pending stayed in the book, so its dead deadline went on refusing an active door that had
//     been refreshed since;
//   - an expired PENDING was indistinguishable from an expired active, so it refused a door that was fine.
//
// The certificates are the fact. Availability is derived from them here, and the book keeps only what the
// certificates cannot say — the lease the control plane states beside them.
// Generation is how many times what this node serves or announces has changed. A decision that reads
// material and acts later states the generation it read, and drops its conclusion if this has moved.
func (t *transportTenantCerts) Generation() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.generation
}

// transportDeadlinesChanged is called whenever an effective deadline moves — an install, a promotion, a
// withdrawal, a name being dropped. The expiry watcher sets it, so that it re-derives its interval instead
// of finishing one chosen before the change.
//
// ★ IT IS NOT ONLY THE INSTALL. A promotion changes when this node stops working without any material
// arriving, and a watcher woken only by fetches would sleep through it.
var transportDeadlinesChanged func()

func noteTransportDeadlinesChanged() {
	if transportDeadlinesChanged != nil {
		transportDeadlinesChanged()
	}
}

func (t *transportTenantCerts) ActiveDeadlines() map[string]time.Time {
	out := map[string]time.Time{}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for name, cert := range t.bySNI {
		tenant := strings.ToLower(strings.TrimSpace(t.tenantOf[name]))
		if tenant == "" || cert == nil || cert.Leaf == nil {
			continue
		}
		// The effective deadline recorded when this material was verified and installed; the leaf's own end
		// only for a certificate that arrived some other way (loaded from disk at start-up).
		at := cert.Leaf.NotAfter.UTC()
		if eff, ok := t.activeDeadlineOf[tenant]; ok && !eff.IsZero() && eff.Before(at) {
			at = eff
		}
		if existing, ok := out[tenant]; !ok || at.Before(existing) {
			out[tenant] = at
		}
	}
	return out
}

func (t *transportTenantCerts) PendingDeadlineFor(tenant string) (time.Time, bool) {
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.RLock()
	defer t.mu.RUnlock()
	cert, ok := t.pendingCertOf[key]
	if !ok || cert == nil || cert.Leaf == nil {
		return time.Time{}, false
	}
	at := cert.Leaf.NotAfter.UTC()
	if eff, has := t.pendingDeadlineOf[key]; has && !eff.IsZero() && eff.Before(at) {
		at = eff
	}
	return at, true
}

// DropPending removes an announced-but-not-served authority: its certificate, its announcement and, because
// the deadline is derived from the certificate, its deadline. Used when the control plane's own snapshot no
// longer carries that authority — a rotation the operator abandoned.
func (t *transportTenantCerts) DropPending(tenant string) bool {
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.Lock()
	defer t.mu.Unlock()
	defer noteTransportDeadlinesChanged()
	if _, ok := t.pendingCertOf[key]; !ok {
		return false
	}
	delete(t.pendingCertOf, key)
	delete(t.pendingAnchorOf, key)
	delete(t.pendingNames, key)
	delete(t.pendingDeadlineOf, key)
	t.generation++
	return true
}

func (t *transportTenantCerts) PendingFingerprintFor(tenant string) string {
	key := strings.ToLower(strings.TrimSpace(tenant))
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, c := range parseAllCerts([]byte(t.pendingAnchorOf[key])) {
		return certFingerprint(c)
	}
	return ""
}

// StopServing removes every name this node presents on behalf of an organization, and its anchor with them.
//
// ★★★ THE CONTROL PLANE STOPPED ISSUING AND THIS NODE KEPT PRESENTING (2026-08-21, measured). An organization
// was deleted and then purged; the control plane no longer holds its transport authority and will mint nothing
// further for it. Every Edge went on serving its name anyway, because material already fetched is held until it
// expires — up to twelve hours during which an SNI probe for a customer that no longer exists still answers
// "yes, here", with a valid certificate.
//
// Returns how many names were dropped, so the caller can say what happened instead of doing it silently.
func (t *transportTenantCerts) StopServing(tenant string) int {
	if t == nil {
		return 0
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	dropped := 0
	for name, owner := range t.tenantOf {
		if !strings.EqualFold(strings.TrimSpace(owner), key) {
			continue
		}
		delete(t.tenantOf, name)
		delete(t.bySNI, name)
		dropped++
	}
	delete(t.anchorOf, key)
	delete(t.pendingAnchorOf, key)
	delete(t.retiring, key)
	return dropped
}

// ServedTenants names the organizations this node currently presents a certificate for.
func (t *transportTenantCerts) ServedTenants() []string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	seen := map[string]bool{}
	out := []string{}
	for _, owner := range t.tenantOf {
		owner = strings.ToLower(strings.TrimSpace(owner))
		if owner == "" || seen[owner] {
			continue
		}
		seen[owner] = true
		out = append(out, owner)
	}
	sort.Strings(out)
	return out
}

// BeginRetiring marks an organization as one this fleet should stop promising. It keeps SERVING until the
// announcement has moved — see the note on the retiring field. Returns true the first time.
func (t *transportTenantCerts) BeginRetiring(tenant string) bool {
	if t == nil {
		return false
	}
	key := strings.ToLower(strings.TrimSpace(tenant))
	if key == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.retiring[key] {
		return false
	}
	if _, served := t.anchorOf[key]; !served {
		return false
	}
	t.retiring[key] = true
	return true
}

// IsRetiring reports whether this organization has left the announcement and is waiting to be dropped.
func (t *transportTenantCerts) IsRetiring(tenant string) bool {
	if t == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.retiring[strings.ToLower(strings.TrimSpace(tenant))]
}

// Retiring names the organizations in that state, for the caller that finishes the job.
func (t *transportTenantCerts) Retiring() []string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.retiring))
	for tenant := range t.retiring {
		out = append(out, tenant)
	}
	sort.Strings(out)
	return out
}

// transportInstallClock is the clock the install boundary judges validity against. A variable so a test can
// place a certificate on either side of its own dates without moving the host's clock.
var transportInstallClock = time.Now

// transportMaterialVerifiesAsADeviceWould builds the path a device builds: the leaf, through whatever
// intermediates came with it, to the anchor this organization's devices are told to trust, for server
// authentication, at `at`.
//
// ★ THE ANCHOR IS THE POOL, NOT A HINT. Verifying against the system roots would pass on a certificate no
// device of this organization could check, and verifying against nothing would pass on anything.
// transportMaterialVerifiesAsADeviceWould answers whether this material can be served at `at`.
// transportMaterialPathDeadline answers the same question AND when that answer stops being true. Two names
// for one check because the first is what most callers want and reads as a question with a yes/no answer.
func transportMaterialVerifiesAsADeviceWould(pair tls.Certificate, anchorPEM string, at time.Time) error {
	_, err := transportMaterialPathDeadline(pair, anchorPEM, at)
	return err
}

func transportMaterialPathDeadline(pair tls.Certificate, anchorPEM string, at time.Time) (time.Time, error) {
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("parse the certificate being installed: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(anchorPEM)) {
		return time.Time{}, fmt.Errorf("the anchor handed over carries no usable certificate, so nothing could verify this material")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			return time.Time{}, fmt.Errorf("parse an intermediate delivered with the certificate: %w", perr)
		}
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("this material does not verify to the anchor its own organization's devices "+
			"are told to trust, so serving it would refuse every one of them (checked at %s): %w",
			at.Format(time.RFC3339), err)
	}
	// ★★★ AND WHEN THAT PATH STOPS WORKING IS THE ANSWER THIS FUNCTION IS ALREADY HOLDING. A path fails on
	// whichever certificate along it ends first, so the earliest end in the chain that actually verified is
	// when the door stops — not the leaf's own NotAfter, which is what every layer of this code used to read
	// and what made an issuer expiring after installation invisible to the selector, the watcher and the
	// renewal schedule at once.
	until := time.Time{}
	for _, chain := range chains {
		soonest := time.Time{}
		for _, c := range chain {
			if soonest.IsZero() || c.NotAfter.Before(soonest) {
				soonest = c.NotAfter.UTC()
			}
		}
		// Several paths may verify; the node can serve until the LONGEST-lived of them ends.
		if soonest.After(until) {
			until = soonest
		}
	}
	return until, nil
}

func effectiveDeadlineOrCertificateEnd(cert *tls.Certificate, given []time.Time) time.Time {
	if len(given) > 0 && !given[0].IsZero() {
		return given[0].UTC()
	}
	if cert != nil && cert.Leaf != nil {
		return cert.Leaf.NotAfter.UTC()
	}
	return time.Time{}
}
