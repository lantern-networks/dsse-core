package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// interception_hsm_ha.go — node-level HSM redundancy: one Edge signing through TWO (or more) HSM sidecars,
// failing over when one dies WITHOUT draining the node.
//
// WHY THIS IS SEPARATE FROM THE FLEET-LEVEL DRAIN. interception_key_custody.go already gives fleet HA: a node
// whose key store is unhealthy fails readiness and the balancer routes around it. That protects AVAILABILITY
// across nodes, but it removes a whole node for one HSM's failure. Where a single Edge is paired with a
// replicated key across two HSMs (the standard HSM HA posture — key material mirrored between an active and a
// standby appliance), the node should keep signing on the survivor instead of dropping out. This is that layer.
//
// THE ONE INVARIANT THAT MAKES FAILOVER SAFE. Every member must hold the SAME key — same public key. Failing
// over to a DIFFERENT key would sign leaves that do not chain to the CA certificate this Edge presents, so
// every certificate minted during the failover would be rejected by clients: an outage that looks like a
// certificate bug, not an HSM one. The pool refuses to form if the members' public keys disagree. This is the
// check a physical two-appliance deployment cannot make for you — plugging in the wrong standby is a
// configuration error, and it should fail loudly at startup, not silently at the first failover.
//
// NO BACKGROUND GOROUTINE. Failure and recovery are driven by the sign path plus a cooldown clock: a member
// that fails is skipped for a cooldown, then retried on the next sign. Because members are tried in preference
// order, a recovered primary is preferred again automatically (fail-back) without anything having to poll it.
// The functional health monitor (interception_key_custody.go) still runs over the pool as a whole and will
// report the node degraded only if EVERY member is failing — which is exactly when the fleet-level drain should
// take over.

// splitCommaList splits a comma-separated flag value into trimmed, non-empty entries, preserving order. Used
// for the HSM sockets rather than splitPaths (which splits on the OS path separator ':', and a unix socket
// path may itself be absolute) — commas never appear in a socket path.
func splitCommaList(value string) []string {
	var out []string
	for _, p := range strings.Split(value, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// newHSMAgentPoolProvider builds an interception provider that signs through a POOL of sidecar sockets
// (primary first), failing over between them. It dials each socket, forms the pool (which refuses unless every
// sidecar reports the same replicated key), and pairs the pool with the CA certificate. A single-element list
// is accepted and behaves exactly like newHSMAgentProvider — so the caller can pass 1..N sockets uniformly.
func newHSMAgentPoolProvider(socketPaths []string, token, keyID, certPath, commonName string, cooldown time.Duration, now func() time.Time, logf func(string, ...any)) (*hsmAgentProvider, error) {
	if len(socketPaths) == 0 {
		return nil, fmt.Errorf("hsm pool: no sockets")
	}
	members := make([]namedSigner, 0, len(socketPaths))
	for _, sock := range socketPaths {
		signer, err := newHSMAgentSignerForSocket(sock, token, keyID)
		if err != nil {
			return nil, fmt.Errorf("hsm pool: dialing %s: %w", sock, err)
		}
		members = append(members, namedSigner{Name: sock, Signer: signer})
	}
	pool, err := newHSMSignerPool(members, cooldown, now, logf)
	if err != nil {
		return nil, err
	}
	return hsmProviderWithSigner(pool, certPath, commonName, now)
}

// namedSigner is one member of the pool: a crypto.Signer and a label for logs and errors. In production the
// signer is an *hsmAgentSigner over one sidecar socket; in tests it is a fake. The pool never assumes hardware.
type namedSigner struct {
	Name   string
	Signer crypto.Signer
}

// poolMember is the pool's mutable per-member state.
type poolMember struct {
	name        string
	signer      crypto.Signer
	failedUntil time.Time // in cooldown until this instant after a failure; retried once it passes
	lastErr     error
	failed      bool // last observed state, for logging the transition only once
}

// hsmSignerPool is a crypto.Signer that fans a Sign out across members in preference order, failing over on
// error and preferring the primary again once it recovers.
type hsmSignerPool struct {
	pub      crypto.PublicKey
	cooldown time.Duration
	now      func() time.Time
	logf     func(string, ...any)

	mu      sync.Mutex
	members []*poolMember
	active  string // name of the member that last signed successfully — observability only
}

// newHSMSignerPool builds a pool from members in PREFERENCE ORDER (primary first). It fails unless every
// member's public key matches the first member's — the invariant that makes failover safe.
func newHSMSignerPool(members []namedSigner, cooldown time.Duration, now func() time.Time, logf func(string, ...any)) (*hsmSignerPool, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("hsm pool: no members")
	}
	if now == nil {
		now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Second
	}
	pub := members[0].Signer.Public()
	if pub == nil {
		return nil, fmt.Errorf("hsm pool: member %q has no public key", members[0].Name)
	}
	pm := make([]*poolMember, 0, len(members))
	for i, m := range members {
		if m.Signer == nil {
			return nil, fmt.Errorf("hsm pool: member %q has no signer", m.Name)
		}
		if i > 0 && !publicKeysEqual(pub, m.Signer.Public()) {
			// The load-bearing safety check. A standby holding a different key is a misconfiguration that would
			// only surface as rejected certificates during a failover — so refuse to start instead.
			return nil, fmt.Errorf("hsm pool: member %q holds a DIFFERENT key than the primary %q — every member must hold the same replicated key, or failover would mint certificates that do not verify", m.Name, members[0].Name)
		}
		pm = append(pm, &poolMember{name: m.Name, signer: m.Signer})
	}
	return &hsmSignerPool{pub: pub, cooldown: cooldown, now: now, logf: logf, members: pm}, nil
}

// publicKeysEqual compares two public keys using the standard Equal method every stdlib key type implements.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	type equaler interface{ Equal(x crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}

func (p *hsmSignerPool) Public() crypto.PublicKey { return p.pub }

// candidates returns members to try, in order: those NOT in cooldown first (preference order preserved), then
// those in cooldown as a last resort. Trying a cooled-down member rather than refusing to sign is deliberate —
// a stale cooldown must never be the reason a leaf mint fails when the member might have recovered.
func (p *hsmSignerPool) candidates() []*poolMember {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.now()
	var ready, cooling []*poolMember
	for _, m := range p.members {
		if m.failedUntil.IsZero() || !t.Before(m.failedUntil) {
			ready = append(ready, m)
		} else {
			cooling = append(cooling, m)
		}
	}
	return append(ready, cooling...)
}

func (p *hsmSignerPool) markHealthy(m *poolMember) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m.failed {
		p.logf("interception_hsm_pool RECOVERED member=%s — back in the signing path", m.name)
	}
	m.failed = false
	m.failedUntil = time.Time{}
	m.lastErr = nil
	p.active = m.name
}

func (p *hsmSignerPool) markFailed(m *poolMember, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !m.failed {
		p.logf("interception_hsm_pool member FAILED member=%s error=%q — skipping it for %s and trying the next member",
			m.name, err.Error(), p.cooldown)
	}
	m.failed = true
	m.failedUntil = p.now().Add(p.cooldown)
	m.lastErr = err
}

// Sign tries members in preference order and returns the first success, failing over past any member that
// errors. It does NOT hold the pool lock across the (network) Sign, so concurrent leaf mints are not
// serialized on one another.
func (p *hsmSignerPool) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	cands := p.candidates()
	var errs []string
	for _, m := range cands {
		sig, err := m.signer.Sign(rand, digest, opts)
		if err == nil {
			p.markHealthy(m)
			return sig, nil
		}
		p.markFailed(m, err)
		errs = append(errs, m.name+": "+err.Error())
	}
	return nil, fmt.Errorf("hsm pool: all %d member(s) failed: %s", len(cands), strings.Join(errs, "; "))
}

// SignCert fans a purpose-bound /sign-cert mint across members exactly the way Sign fans a digest, so
// interception-leaf minting keeps the pool's HA + failover. A member whose signer does not implement /sign-cert
// is skipped with a recorded reason rather than silently dropped. This makes *hsmSignerPool satisfy
// edgeplane.InterceptionCertMinter, so the leaf path uses /sign-cert through the pool instead of the digest /sign.
func (p *hsmSignerPool) SignCert(template, issuer *x509.Certificate, leafPub crypto.PublicKey, purpose string) ([]byte, error) {
	cands := p.candidates()
	var errs []string
	for _, m := range cands {
		minter, ok := m.signer.(edgeplane.InterceptionCertMinter)
		if !ok {
			errs = append(errs, m.name+": signer has no /sign-cert")
			continue
		}
		der, err := minter.SignCert(template, issuer, leafPub, purpose)
		if err == nil {
			p.markHealthy(m)
			return der, nil
		}
		p.markFailed(m, err)
		errs = append(errs, m.name+": "+err.Error())
	}
	return nil, fmt.Errorf("hsm pool sign-cert: all %d member(s) failed: %s", len(cands), strings.Join(errs, "; "))
}

// ActiveMember reports which member last signed — for the admin/status surface, so an operator can see the
// node is running on the standby.
func (p *hsmSignerPool) ActiveMember() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

// MemberStatuses reports each member's current health for the status surface (name + healthy + last error),
// in preference order. Never includes key material.
func (p *hsmSignerPool) MemberStatuses() []map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.now()
	out := make([]map[string]any, 0, len(p.members))
	for i, m := range p.members {
		healthy := m.failedUntil.IsZero() || !t.Before(m.failedUntil)
		s := map[string]any{
			"name":    m.name,
			"role":    map[bool]string{true: "primary", false: "standby"}[i == 0],
			"healthy": healthy,
			"active":  m.name == p.active,
		}
		if m.lastErr != nil && !healthy {
			s["error"] = m.lastErr.Error()
		}
		out = append(out, s)
	}
	return out
}

// CertificateRequestDER fans a /sign-csr across members the way Sign and SignCert do, so re-issuing the
// intermediate keeps the pool's failover. A member whose signer cannot produce a request is skipped with a
// recorded reason rather than silently dropped — the same rule SignCert uses, for the same reason: a member
// quietly missing a capability turns a partial outage into a total one nobody can explain.
func (p *hsmSignerPool) CertificateRequestDER(commonName string, organization []string) ([]byte, error) {
	cands := p.candidates()
	var errs []string
	for _, m := range cands {
		maker, ok := m.signer.(interface {
			CertificateRequestDER(string, []string) ([]byte, error)
		})
		if !ok {
			errs = append(errs, m.name+": signer has no /sign-csr")
			continue
		}
		der, err := maker.CertificateRequestDER(commonName, organization)
		if err == nil {
			p.markHealthy(m)
			return der, nil
		}
		p.markFailed(m, err)
		errs = append(errs, m.name+": "+err.Error())
	}
	return nil, fmt.Errorf("hsm pool: all %d member(s) failed to produce a certificate request: %s",
		len(cands), strings.Join(errs, "; "))
}
