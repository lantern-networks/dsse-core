package main

import (
	"crypto/x509"
	tenantca "github.com/lantern-networks/dsse-core/tenantca"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// When each device's certificate expires, observed from the certificate it is actually using.
//
// Automatic renewal works and has been verified on both platforms. What did not exist was any way to SEE that
// it is still working. The failure mode is specific and nasty: renewal stops, nothing changes for weeks, and
// then every device issued a certificate on the same day fails authentication on the same day — together,
// with no warning, because certificates do not degrade before they expire. The readiness screen names that
// consequence and offered no way to check whether it was happening.
//
// Recorded at the (T) handshake rather than at issuance, for two reasons. It is the certificate the device is
// really presenting, so it cannot disagree with reality the way an issuance record can after a manual swap.
// And issuance facts written into the enrolled ledger would be destroyed on the next config bundle: the ledger
// is control-plane-authoritative configuration and a pull REPLACES it, so a per-device fact recorded at the
// Edge would survive exactly until the next poll. Observation belongs with the other observed state.
//
// In-memory on purpose. Every entry re-appears within seconds of a device reconnecting, so a restart costs a
// few seconds of a view rather than any fact worth keeping. Nothing here is enforcement — no decision reads it.
type deviceCertificateFacts struct {
	mu sync.Mutex
	by map[string]deviceCertificateFact
}

type deviceCertificateFact struct {
	Identity string `json:"identity"`
	// TenantID is the organization this device belongs to, taken from the CA that issued its certificate —
	// never from anything the device says, which is the rule the transport already follows.
	//
	// ★ WITHOUT IT THE FACT CANNOT BE SHIPPED (2026-08-23, measured). A shipment from an identified Edge must
	// name the organization it belongs to, or the control plane refuses it 403: "this record names no tenant,
	// and a shipment from an identified edge cannot be filed under none". Exactly right — a record filed under
	// nobody lands in the partition everybody reads. The fact simply had no tenant on it, because until it was
	// shipped it never left the node that observed it.
	TenantID string `json:"tenant_id,omitempty"`
	Subject  string `json:"subject"`
	IssuerCN string `json:"issuer_common_name"`
	// AnchorSHA256 is the CA this device's chain actually ENDED AT, by fingerprint.
	//
	// ★ THE ISSUER'S NAME IS NOT AN IDENTITY (2026-08-16). IssuerCN above is a display string, and two
	// certificate authorities can carry the same common name — this deployment already has that, with two
	// organizations' interception roots both called "Lantern DSSE Interception Root". Deciding whether a device
	// has moved to a REPLACEMENT authority by comparing names would answer "yes" for the one it is moving off.
	// Recorded from the verified chain, so it is the anchor the handshake itself used and not an inference.
	// Empty when the chain was not available (an unverified path), which is unknown rather than "none".
	AnchorSHA256 string `json:"anchor_sha256,omitempty"`
	Serial       string `json:"serial"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	DaysLeft     int    `json:"days_left"`
	Expired      bool   `json:"expired"`
	// LastSeenAt is when this certificate was last presented, which is what separates "expires in three days"
	// from "expired last month and nobody noticed because the device has not been on since".
	LastSeenAt string `json:"last_seen_at"`
	// RenewsAt is when the device will next ASK for a new certificate, which is not the same question as when
	// this one expires and is the more useful one. Renewal opens at two thirds of a certificate's life, so a
	// certificate with an unusually long life does not renew for a correspondingly long time — and a device
	// that never renews is a device whose issuing CA can never be retired, because something live still
	// depends on it.
	//
	// This lab has exactly that: a ten-year device certificate from a superseded CA, next renewing in 2033.
	// Nothing about "expires in 3636 days" says so; "renews in 2426 days" says it immediately.
	RenewsAt     string `json:"renews_at,omitempty"`
	RenewsInDays int    `json:"renews_in_days,omitempty"`
	RenewalDue   bool   `json:"renewal_due"`
}

var deviceCertificates = &deviceCertificateFacts{by: map[string]deviceCertificateFact{}}

// deviceCertificateTenantRegistry resolves a verified chain to the organization it belongs to, so an observed
// fact can name one. An atomic pointer because this is read on the handshake path and set once at start-up.
var deviceCertificateTenantRegistry atomic.Pointer[*tenantca.TenantCARegistry]

// setDeviceCertificateTenantRegistry arms tenant attribution for observed certificates. Without it a fact
// names no organization and cannot be shipped — the control plane refuses a record filed under nobody.
func setDeviceCertificateTenantRegistry(reg *tenantca.TenantCARegistry) {
	if reg != nil {
		deviceCertificateTenantRegistry.Store(&reg)
	}
}

// observe records the leaf a device just presented. Called on the admission path AFTER the connection has been
// accepted, so it can never influence whether it is: this function returns nothing and reports no errors,
// because a fact worth showing is not worth failing a handshake over.
func (f *deviceCertificateFacts) observe(identity string, leaf *x509.Certificate, now time.Time) {
	f.observeChain(identity, leaf, nil, now)
}

// observeChain records the same fact plus the ANCHOR the verified chain ended at. Callers that have the chain
// should use it: which authority admitted a device is the fact a replacement is measured by, and it cannot be
// recovered from the leaf alone.
func (f *deviceCertificateFacts) observeChain(identity string, leaf *x509.Certificate, chains [][]*x509.Certificate, now time.Time) {
	if f == nil || identity == "" || leaf == nil {
		return
	}
	fact := deviceCertificateFact{
		Identity:   identity,
		Subject:    leaf.Subject.CommonName,
		IssuerCN:   leaf.Issuer.CommonName,
		NotBefore:  leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:   int(leaf.NotAfter.Sub(now).Hours() / 24),
		Expired:    now.After(leaf.NotAfter),
		LastSeenAt: now.UTC().Format(time.RFC3339),
	}
	if leaf.SerialNumber != nil {
		fact.Serial = leaf.SerialNumber.String()
	}
	// Mirrors renewalDue — the same two-thirds rule the agent and the renew endpoint both apply. Computed
	// here rather than restated in a browser, so the three cannot drift into disagreeing about when a device
	// is going to act.
	if leaf.NotAfter.After(leaf.NotBefore) {
		renewsAt := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
		fact.RenewsAt = renewsAt.UTC().Format(time.RFC3339)
		fact.RenewsInDays = int(renewsAt.Sub(now).Hours() / 24)
		fact.RenewalDue = !now.Before(renewsAt)
	}
	// The last certificate of a verified chain is the anchor it was accepted under — and, through the registry,
	// the organization the device belongs to. Both come from the same place for the same reason: a device does
	// not get to say whose it is.
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		anchor := chain[len(chain)-1]
		if anchor != nil {
			fact.AnchorSHA256 = certFingerprint(anchor)
			if reg := deviceCertificateTenantRegistry.Load(); reg != nil {
				if tenant, ok := (*reg).TenantForVerifiedChains(chains); ok {
					fact.TenantID = tenant
				}
			}
			break
		}
	}
	f.mu.Lock()
	// A handshake that could not name the anchor must not ERASE one an earlier handshake did. The two arrive
	// on different paths, and a fact that flickers is worse for a gate than one that is simply absent.
	if fact.AnchorSHA256 == "" {
		if previous, ok := f.by[identity]; ok {
			fact.AnchorSHA256 = previous.AnchorSHA256
		}
	}
	previous, had := f.by[identity]
	f.by[identity] = fact
	f.mu.Unlock()

	// ★★★ AND THE FLEET HAS TO SEE IT, NOT JUST THIS NODE (2026-08-23, measured). The comment at the top of
	// this file says "nothing here is enforcement — no decision reads it". That stopped being true: the
	// device-CA withdrawal gate reads exactly this to answer "is anybody still admitted under the CA you are
	// about to retire", and a control plane — which never terminates a device handshake — sees none of it. So
	// the authority could not withdraw a CA it had itself registered: every enrolled device landed in "never
	// seen presenting a certificate on this node" and the withdrawal was refused, forever.
	//
	// ★ ON CHANGE ONLY. This runs on every (T) handshake, which is far too often to ship. What the gate needs
	// is which anchor and which certificate a device is presenting, and those change on a renewal or a
	// re-enrolment — not on a reconnect. Comparing them is what turns a per-handshake event into an
	// occasional one.
	if !had || previous.AnchorSHA256 != fact.AnchorSHA256 || previous.Serial != fact.Serial {
		shipDeviceCertificateFact(fact)
	}
}

// adopt records a fact OBSERVED SOMEWHERE ELSE — a shipped one, on the control plane.
//
// ★ NEWER WINS, AND ONLY NEWER. Two Edges may both have seen a device, and a batch replayed out of a spool
// after an outage can arrive after a fresher observation. Taking the later LastSeenAt is what stops a replay
// from reinstating a certificate the device has since replaced — which for the withdrawal gate would mean
// blocking a retirement on evidence that is no longer true.
//
// ★ AND IT NEVER ERASES AN ANCHOR, the same rule observeChain follows: a fact that flickers is worse for a
// gate than one that is simply absent.
func (f *deviceCertificateFacts) adopt(fact deviceCertificateFact) {
	if f == nil || fact.Identity == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.by[fact.Identity]; ok {
		if previous.LastSeenAt > fact.LastSeenAt {
			return // an older observation, arriving late
		}
		if fact.AnchorSHA256 == "" {
			fact.AnchorSHA256 = previous.AnchorSHA256
		}
	}
	f.by[fact.Identity] = fact
}

// snapshot returns the facts with the soonest expiry first, so the list opens on the devices that need
// attention rather than on whichever identity sorts alphabetically.
func (f *deviceCertificateFacts) snapshot() []deviceCertificateFact {
	if f == nil {
		return []deviceCertificateFact{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]deviceCertificateFact, 0, len(f.by))
	for _, v := range f.by {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NotAfter != out[j].NotAfter {
			return out[i].NotAfter < out[j].NotAfter
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}
