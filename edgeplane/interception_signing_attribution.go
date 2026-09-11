package edgeplane

import (
	"log"
	"sort"
	"sync"
)

// ★★ WHICH AUTHORITY SIGNED WAS NEVER RECORDED (2026-08-18, measured).
//
// issuerFor already resolved, per flow, exactly which CA mints the certificate the user's browser is shown —
// their own organization's offline root, the node-wide intermediate that belongs to ONE named organization, or
// nothing at all. It returned that answer as `issuerScope`, and the only consumer was the leaf-cache key. So
// the deployment could sign an arbitrary amount of traffic under a customer's authority and no counter, log
// line or screen would differ from the case where it signed none.
//
// This is the thing the tenant-independence work is asserting about, so it has to be measurable before it can
// be enforced: "unattributed traffic is signed under a customer's CA" and "no such traffic exists" have to stop
// looking the same. Counting is deliberately the whole of it — no sampling of hosts, no per-flow log — because
// the question is how much, not which.
type interceptionSigningTally struct {
	mu     sync.Mutex
	counts map[string]uint64
	warned map[string]bool
}

var interceptionSigningCounts = &interceptionSigningTally{
	counts: map[string]uint64{},
	warned: map[string]bool{},
}

// countSigning records one leaf minted under the named authority class.
//
//	own_offline_root          the organization's own offline issuer signed for it — the intended state
//	primary_own               the node-wide intermediate signed for the organization it actually belongs to
//	direct_root               the deployment's own interception root signed the leaf directly — what
//	                          dsse-install generates, and the class that was NOT counted until 2026-08-26
//	offline_root              a single offline issuer signed, with no per-organization issuers loaded
//	node_intermediate         the node-wide intermediate signed, with no per-organization issuers loaded
//	refused_unattributed      ★ a flow whose organization did not resolve, REFUSED rather than signed under a
//	                          named organization's CA (this used to be unattributed_under_primary, which signed it)
//	refused_no_authority      per-tenant signing is in force, this organization has none, and this node holds no
//	                          authority of its own either, so nothing was signed
//	deployment_root_no_own_authority
//	                          ★ per-tenant signing is in force and this organization has not been given its own
//	                          authority, so it is inspected under THIS DEPLOYMENT's root — the posture
//	                          /admin/tenant-interception-authority describes. Counted separately from
//	                          direct_root so an operator can see how much traffic is inspected under the
//	                          deployment's own CA rather than an organization's, which is the number the
//	                          per-organization PKI work is trying to drive to zero
func (interception *NetworkExtensionLabTLSInterception) countSigning(class string) {
	interception.countSigningFor(class, "")
}

// ★★★ AND THE REFUSAL THAT STOPS EVERY FLOW FOR AN ORGANIZATION WAS SILENT (2026-08-28, measured on the
// two-region lab). Giving ONE organization its own interception authority puts this node into per-tenant
// signing for ALL of them — which is the separation working — and every other organization, including the
// deployment's own, stops being intercepted from that moment. issuerFor writes a careful sentence saying
// exactly that, and hands it to the TLS stack, which turns it into an `internal error` alert on the wire. So:
//
//	the client sees   remote error: tls: internal error
//	the Edge logs     nothing
//	the screen shows  a healthy deployment
//
// One organization was given a root at 01:02 and the deployment stopped decrypting anything else; the only
// trace was a counter nobody had reason to open. `refused_unattributed` already had this treatment — this is
// the same class of event and the more likely one, because it needs no misconfiguration at all, only a second
// customer.
//
// Once per organization, so a fleet-wide outage says so once and a busy node does not flood.
func (interception *NetworkExtensionLabTLSInterception) countSigningFor(class, tenantID string) {
	if interception == nil {
		return
	}
	tally := interceptionSigningCounts
	tally.mu.Lock()
	tally.counts[class]++
	n := tally.counts[class]
	// ★ The first occurrence says so out loud, once. A counter nobody reads is not a record; these classes are
	// the ones an operator would never think to go looking for, because nothing about them looks broken.
	key := class + "\x00" + tenantID
	first := false
	switch class {
	case "refused_unattributed", "refused_no_authority":
		if !tally.warned[key] {
			tally.warned[key] = true
			first = true
		}
	}
	tally.mu.Unlock()
	if !first {
		return
	}
	switch class {
	case "refused_unattributed":
		log.Printf("interception: a flow whose organization did not resolve was NOT intercepted — it is "+
			"deliberately not signed under the node-wide intermediate, which belongs to one named "+
			"organization whose devices would accept the certificate. count=%d (see /admin/interception-intermediate)", n)
	case "refused_no_authority":
		log.Printf("★ interception: organization %q is NOT being intercepted on this node and its flows are "+
			"failing at the TLS handshake. Another organization has its own interception authority here, which "+
			"puts this node into per-organization signing for EVERY organization — so this one needs its own "+
			"too (POST /admin/interception-intermediate/%s), or it is deliberately not signed at all rather "+
			"than under somebody else's CA. count=%d", tenantID, tenantID, n)
	}
}

// InterceptionSigningCounts reports, by authority class, how many leaves this node has minted since it started.
// Exposed so the answer is on a screen rather than in a developer's head.
func InterceptionSigningCounts() map[string]uint64 {
	tally := interceptionSigningCounts
	tally.mu.Lock()
	defer tally.mu.Unlock()
	out := make(map[string]uint64, len(tally.counts))
	for k, v := range tally.counts {
		out[k] = v
	}
	return out
}

// InterceptionSigningClasses returns the classes seen, sorted, so a caller can render them in a stable order.
func InterceptionSigningClasses() []string {
	counts := InterceptionSigningCounts()
	out := make([]string, 0, len(counts))
	for k := range counts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
