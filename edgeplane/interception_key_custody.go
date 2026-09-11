package edgeplane

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Key custody = WHERE the interception signing key actually lives, and whether it still works.
//
// The interception root/intermediate key is the crown jewel (docs/pki_trust_model.md): it is online because
// per-SNI leaves are signed on demand. The single most important control is that the key be non-exportable
// (HSM / PKCS#11) rather than bytes on the host. Today it is bytes on the host — and nothing in the product
// SAYS so. This makes custody visible, and checks that the key can actually sign.
//
// Design note (decision record: docs/2026-07-28_pki_key_custody_sidecar_decision.ja.md): PKCS#11 needs cgo,
// while the Edge builds CGO_ENABLED=0 onto `scratch`. Linking a vendor .so into the Edge would trade away the
// Tier-0 host hardening that the trust model counts as a control, and would split the release into two build
// variants. So the HSM lives in a separate signing sidecar, and it will report custody through this same seam.
// Nothing here assumes an HSM exists; with a file key it still does useful work.

// KeyCustodyFile is the custody value for a signing key held as bytes in this process.
const KeyCustodyFile = "file"

// KeyCustodyPKCS11 is the custody value for a key held in a PKCS#11 token (the signing sidecar / HSM).
const KeyCustodyPKCS11 = "pkcs11"

// keyCustodyReporter is OPTIONAL. A provider that knows its custody implements it; anything else is reported as
// KeyCustodyFile. Declared as a separate interface rather than a method on InterceptionRootProvider so adding
// custody does not break the existing implementations (file / static / per-tenant registry).
type keyCustodyReporter interface {
	KeyCustody() string
}

// KeyCustodyOf reports where a provider's signing key lives. Unknown providers are reported as "file" — the
// conservative answer, because claiming hardware custody that is not there would be worse than useless.
func KeyCustodyOf(provider InterceptionRootProvider) string {
	if provider == nil {
		return "none"
	}
	if r, ok := provider.(keyCustodyReporter); ok {
		if c := r.KeyCustody(); c != "" {
			return c
		}
	}
	return KeyCustodyFile
}

// KeyCustodyHealth is the result of a FUNCTIONAL check: it signs and verifies. Reachability is not enough —
// see CheckKeyCustodyHealth.
type KeyCustodyHealth struct {
	Custody   string        `json:"custody"`
	Healthy   bool          `json:"healthy"`
	LatencyMS float64       `json:"latency_ms"`
	CheckedAt time.Time     `json:"checked_at"`
	Error     string        `json:"error,omitempty"`
	latency   time.Duration `json:"-"`
}

// keyCustodySlowSignThreshold is the signing latency above which the key store is treated as failing, even
// though it still produces correct signatures.
//
// A SLOW HSM IS WORSE THAN A DEAD ONE. A dead one fails the functional check, the node reports unready and the
// balancer drains it. A slow one keeps passing, stays in rotation, and makes every leaf mint — that is, every
// NEW hostname a user visits — wait on it. The cached leaves that hide an outright failure hide this too, so
// the symptom reaching an operator is "some sites hang, most are fine", which does not look like the key
// store at all.
//
// Two seconds is far above anything healthy: a YubiHSM 2 signs P-256 in tens of milliseconds, and the lab's
// PKCS#11 sidecar over a container socket measured ~24ms steady, ~113ms on the first call. Set generously on
// purpose — this exists to catch a store that has become unusable, not to police normal variation.
const keyCustodySlowSignThreshold = 2 * time.Second

// keyCustodySlowChecksBeforeUnready is how many CONSECUTIVE slow checks it takes to pull a node out of
// rotation. One slow sample is a garbage-collection pause or a busy host, and reacting to it would flap the
// node in and out of the balancer — which costs more than the slowness it is reacting to.
const keyCustodySlowChecksBeforeUnready = 3

// CheckKeyCustodyHealth signs a fixed digest with the provider's key and verifies the signature against the
// certificate's public key.
//
// It is deliberately FUNCTIONAL rather than a liveness probe. "Can I reach the key store?" answers nothing
// about an expired session, a deleted key object, a token someone unplugged, or firmware that fails only on
// sign — all of which present as a healthy-looking system that cannot issue a certificate. Even with a file
// key it is worth doing: it detects a sealed key that can no longer be unsealed (a wrong or rotated KEK),
// which otherwise stays invisible until the first cache miss.
//
// Latency is reported because gradual slowdown precedes hardware failure, and because it is the number that
// decides whether an HSM can stay in the signing path at all.
func CheckKeyCustodyHealth(provider InterceptionRootProvider, now func() time.Time) KeyCustodyHealth {
	if now == nil {
		now = time.Now
	}
	h := KeyCustodyHealth{Custody: KeyCustodyOf(provider), CheckedAt: now().UTC()}
	if provider == nil {
		h.Error = "no interception root provider configured"
		return h
	}
	signer := provider.Signer()
	if signer == nil {
		h.Error = "provider has no signer"
		return h
	}
	cert := provider.Certificate()
	if cert == nil || cert.PublicKey == nil {
		h.Error = "provider has no certificate to verify against"
		return h
	}
	// Verify against the CERTIFICATE's public key, not the signer's own — this also catches a key that signs
	// correctly but has diverged from the certificate it is paired with (every leaf minted from here would then
	// be rejected by clients).
	return ProbeSigningKey(signer, cert.PublicKey, h.Custody, interceptionKeyCustodyHealthText, now)
}

// interceptionKeyCustodyHealthText is the fixed message whose SHA-256 the interception key signs as its liveness
// probe. It is the ONE digest the (purpose-bound) interception key is allowed to sign through the plain /sign in
// the signing sidecar (see the hsm-agent -sign-digest-allowlist / entrypoint.sh); keep the two in lockstep.
const interceptionKeyCustodyHealthText = "dsse interception key custody health check"

// Health-probe messages for the two secondary online-signing keys. The device-CA key is purpose-bound, so its
// message's SHA-256 must ALSO be in the hsm-agent -sign-digest-allowlist (entrypoint.sh builds it); the
// agent-policy key is not purpose-bound, so its plain /sign accepts any digest and needs no allowlist entry.
const DeviceCAKeyCustodyHealthText = "dsse device-ca key custody health check"
const AgentPolicyKeyCustodyHealthText = "dsse agent-policy key custody health check"

// ProbeSigningKey is the shared functional custody check behind every online signing key: sign healthText's
// SHA-256 with signer, verify the signature against verifyPub, and record the latency. Reachability is not
// enough — an expired session, a deleted key object, an unplugged token or firmware that fails only on sign all
// present as a healthy-looking store that cannot actually issue anything.
func ProbeSigningKey(signer crypto.Signer, verifyPub crypto.PublicKey, custody, healthText string, now func() time.Time) KeyCustodyHealth {
	if now == nil {
		now = time.Now
	}
	h := KeyCustodyHealth{Custody: custody, CheckedAt: now().UTC()}
	if signer == nil {
		h.Error = "no signer"
		return h
	}
	if verifyPub == nil {
		h.Error = "no public key to verify against"
		return h
	}
	digest := sha256.Sum256([]byte(healthText))
	start := time.Now()
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	h.latency = time.Since(start)
	h.LatencyMS = float64(h.latency.Microseconds()) / 1000.0
	if err != nil {
		h.Error = fmt.Sprintf("sign failed: %v", err)
		return h
	}
	if err := verifySignature(verifyPub, digest[:], sig); err != nil {
		h.Error = fmt.Sprintf("signature does not verify against the key's public half: %v", err)
		return h
	}
	h.Healthy = true
	return h
}

// verifySignature checks sig over digest with pub, for the key types an interception CA can plausibly use.
func verifySignature(pub any, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("ecdsa verification failed")
		}
		return nil
	case ed25519.PublicKey:
		// Ed25519 signs the message, not a pre-hash; the digest is what we passed to Sign, so verify that.
		if !ed25519.Verify(k, digest, sig) {
			return errors.New("ed25519 verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

// KeyCustodyChecker caches the health result so an admin polling the status API does not trigger a signing
// operation every time. Harmless with a file key; wasteful against an HSM, where every check is a real
// hardware operation and the throughput budget is the thing that decides whether the HSM can stay in the
// signing path at all (docs/pki_ideal_lifecycle_design.ja.md).
type KeyCustodyChecker struct {
	mu       sync.Mutex
	last     KeyCustodyHealth
	lastRun  time.Time
	interval time.Duration
}

// keyCustodyCheckInterval is the minimum gap between functional checks driven by a status read. A background
// checker on a shorter cadence belongs with the signing sidecar (stage 2 of the decision record), where the
// result also feeds the HA "unhealthy node removes itself from rotation" rule.
const keyCustodyCheckInterval = 30 * time.Second

func NewKeyCustodyChecker() *KeyCustodyChecker {
	return &KeyCustodyChecker{interval: keyCustodyCheckInterval}
}

// health returns a cached result, re-checking at most once per interval.
func (c *KeyCustodyChecker) health(provider InterceptionRootProvider, now func() time.Time) KeyCustodyHealth {
	if c == nil {
		return CheckKeyCustodyHealth(provider, now)
	}
	if now == nil {
		now = time.Now
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t := now()
	if !c.lastRun.IsZero() && t.Sub(c.lastRun) < c.interval {
		return c.last
	}
	c.last = CheckKeyCustodyHealth(provider, now)
	c.lastRun = t
	return c.last
}

// KeyCustodyStatus renders custody + health for the admin surface, in the shape the PKI Console view wants
// ("key custody = HSM vs file" — docs/admin_console_pki_management_design.md domain 3).
//
// It NEVER includes key material, only where the key lives and whether it works.
func KeyCustodyStatus(checker *KeyCustodyChecker, provider InterceptionRootProvider, now func() time.Time) map[string]any {
	h := checker.health(provider, now)
	out := map[string]any{
		"custody":    h.Custody,
		"healthy":    h.Healthy,
		"latency_ms": h.LatencyMS,
		"checked_at": h.CheckedAt.Format(time.RFC3339),
		// Honest self-report: a file key is NOT the production posture the trust model requires. Surfacing this
		// is the point — an operator should be able to see the gap without reading the design docs.
		"non_exportable": h.Custody != KeyCustodyFile && h.Custody != "none",
	}
	if h.Error != "" {
		out["error"] = h.Error
	}
	return out
}

// KeyCustodyMonitor runs the functional check on a timer, independent of anyone reading the admin API.
//
// A check that only runs when someone looks is not monitoring. The leaf cache means a dead signing key stays
// invisible until somebody visits a hostname nobody has visited yet, so the failure must be found by asking on
// a schedule rather than by waiting for a user to trip over it
// (docs/pki_ideal_lifecycle_design.ja.md).
type KeyCustodyMonitor struct {
	// consecutiveSlow counts back-to-back checks whose signing latency exceeded the threshold. Consecutive,
	// not cumulative: a node that was slow once an hour ago is not the problem being detected.
	consecutiveSlow int
	mu              sync.RWMutex
	last            KeyCustodyHealth
	provider        func() InterceptionRootProvider
	interval        time.Duration
	logf            func(string, ...any)
	started         bool
}

func NewKeyCustodyMonitor(provider func() InterceptionRootProvider, interval time.Duration, logf func(string, ...any)) *KeyCustodyMonitor {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &KeyCustodyMonitor{provider: provider, interval: interval, logf: logf}
}

// Start begins checking. Safe to call once; later calls are ignored.
func (m *KeyCustodyMonitor) Start() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	go func() {
		t := time.NewTicker(m.interval)
		defer t.Stop()
		m.Check() // once immediately, so a key that is broken at boot is reported at boot
		for range t.C {
			m.Check()
		}
	}()
}

func (m *KeyCustodyMonitor) Check() {
	h := CheckKeyCustodyHealth(m.provider(), time.Now)
	m.mu.Lock()
	prev := m.last
	prevSlow := m.consecutiveSlow
	if h.Healthy && h.latency > keyCustodySlowSignThreshold {
		m.consecutiveSlow++
	} else {
		m.consecutiveSlow = 0
	}
	slowNow := m.consecutiveSlow
	m.last = h
	m.mu.Unlock()

	// Log the TRANSITION, not every check. The moment degradation starts is the actionable event; repeating it
	// every interval turns the signal into noise the operator learns to ignore.
	switch {
	case !h.Healthy && (prev.Healthy || prev.CheckedAt.IsZero()):
		m.logf("interception_key_custody DEGRADED custody=%s error=%q — new hostnames cannot be intercepted until this is fixed; already-cached leaves keep working",
			h.Custody, h.Error)
	case h.Healthy && !prev.Healthy && !prev.CheckedAt.IsZero():
		m.logf("interception_key_custody RECOVERED custody=%s latency_ms=%.2f", h.Custody, h.LatencyMS)
	case slowNow == keyCustodySlowChecksBeforeUnready && prevSlow < keyCustodySlowChecksBeforeUnready:
		// Reported as its own state, not folded into DEGRADED: "signing takes seconds" and "signing fails"
		// call for different actions — investigate load or a failing device, versus replace it.
		m.logf("interception_key_custody SLOW custody=%s latency_ms=%.2f threshold_ms=%.0f consecutive=%d — "+
			"signatures still verify, but every new hostname waits on this; the node is reporting unready so "+
			"the balancer drains it",
			h.Custody, h.LatencyMS, float64(keyCustodySlowSignThreshold.Milliseconds()), slowNow)
	case prevSlow >= keyCustodySlowChecksBeforeUnready && slowNow == 0:
		m.logf("interception_key_custody SPEED RECOVERED custody=%s latency_ms=%.2f", h.Custody, h.LatencyMS)
	}
}

// SecondaryKeyCustodyMonitor runs the same functional sign+verify on an online signing key that is NOT on the
// traffic-serving path: the device-CA key (signs at every enrolment and renewal) and the agent-policy key (signs
// at every policy change). Both now live in the SAME token as the interception key, so a token-level fault
// (unplug, lost session) is already caught by KeyCustodyMonitor above. What this adds is per-KEY coverage — a
// deleted key object, a per-key permission change, a key that is slow while the token is fine — and, most
// importantly, VISIBILITY: these keys sign so rarely that a dead one would otherwise surface only when someone
// enrols a device or edits policy, which is the "the rare event hides the failure" trap of one level over.
//
// It deliberately does NOT gate /healthz. Draining the traffic node because an ENROLMENT key is slow would stop
// serving intercepted traffic for a fault on a path traffic never touches. The signal is the DEGRADED/SLOW log
// (queryable in the log subsystem) and the admin custody surface — not readiness.
type SecondaryKeyCustodyMonitor struct {
	Name            string
	probe           func(now func() time.Time) KeyCustodyHealth
	interval        time.Duration
	logf            func(string, ...any)
	mu              sync.RWMutex
	last            KeyCustodyHealth
	consecutiveSlow int
	started         bool
}

func NewSecondaryKeyCustodyMonitor(name string, probe func(now func() time.Time) KeyCustodyHealth, interval time.Duration, logf func(string, ...any)) *SecondaryKeyCustodyMonitor {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &SecondaryKeyCustodyMonitor{Name: name, probe: probe, interval: interval, logf: logf}
}

// Start begins checking on a timer. Safe to call once; later calls are ignored.
func (m *SecondaryKeyCustodyMonitor) Start() {
	if m == nil || m.probe == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go func() {
		t := time.NewTicker(m.interval)
		defer t.Stop()
		m.Check()
		for range t.C {
			m.Check()
		}
	}()
}

func (m *SecondaryKeyCustodyMonitor) Check() {
	h := m.probe(time.Now)
	m.mu.Lock()
	prev := m.last
	prevSlow := m.consecutiveSlow
	if h.Healthy && h.latency > keyCustodySlowSignThreshold {
		m.consecutiveSlow++
	} else {
		m.consecutiveSlow = 0
	}
	slowNow := m.consecutiveSlow
	m.last = h
	m.mu.Unlock()

	// Log the TRANSITION only — same discipline as the interception monitor, so the log is a signal not noise.
	switch {
	case !h.Healthy && (prev.Healthy || prev.CheckedAt.IsZero()):
		m.logf("%s_key_custody DEGRADED custody=%s error=%q — this key cannot sign; the function it backs (device enrolment/renewal, or policy signing) is stalled, though traffic is unaffected",
			m.Name, h.Custody, h.Error)
	case h.Healthy && !prev.Healthy && !prev.CheckedAt.IsZero():
		m.logf("%s_key_custody RECOVERED custody=%s latency_ms=%.2f", m.Name, h.Custody, h.LatencyMS)
	case slowNow == keyCustodySlowChecksBeforeUnready && prevSlow < keyCustodySlowChecksBeforeUnready:
		m.logf("%s_key_custody SLOW custody=%s latency_ms=%.2f threshold_ms=%.0f consecutive=%d — signatures still verify, but the key store is degrading",
			m.Name, h.Custody, h.LatencyMS, float64(keyCustodySlowSignThreshold.Milliseconds()), slowNow)
	case prevSlow >= keyCustodySlowChecksBeforeUnready && slowNow == 0:
		m.logf("%s_key_custody SPEED RECOVERED custody=%s latency_ms=%.2f", m.Name, h.Custody, h.LatencyMS)
	}
}

// Health returns the most recent result for the admin custody surface. Zero value = not yet checked.
func (m *SecondaryKeyCustodyMonitor) Health() KeyCustodyHealth {
	if m == nil {
		return KeyCustodyHealth{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}

// Health returns the most recent result. Zero value (CheckedAt zero) means the monitor has not run yet, which
// callers must treat as "unknown", not as "healthy".
func (m *KeyCustodyMonitor) Health() KeyCustodyHealth {
	if m == nil {
		return KeyCustodyHealth{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}

// Ready reports whether this node should receive NEW flows.
//
// Readiness is PULLED by the load balancer rather than the node pushing itself out of rotation. A node that is
// broken enough to matter may also be too broken to execute a removal; making the balancer ask means a hung
// node fails readiness simply by not answering. It also avoids the failure this session watched in the NE,
// where a component kept asserting "healthy (sticky)" while nothing worked.
//
// Unknown (not yet checked) counts as ready: refusing traffic before the first check has completed would make
// every start-up look like an outage.
func (m *KeyCustodyMonitor) Ready() (bool, string) {
	h := m.Health()
	if h.CheckedAt.IsZero() {
		return true, ""
	}
	if !h.Healthy {
		return false, h.Error
	}
	// Correct but unusably slow. Draining is the right answer: the flows this node would accept are the ones
	// that stall, and another node in the fleet may have a healthy store.
	m.mu.RLock()
	slow := m.consecutiveSlow
	m.mu.RUnlock()
	if slow >= keyCustodySlowChecksBeforeUnready {
		return false, fmt.Sprintf("key store signs correctly but takes %.0fms (threshold %.0fms) — every new hostname would wait on it",
			h.LatencyMS, float64(keyCustodySlowSignThreshold.Milliseconds()))
	}
	return true, ""
}
