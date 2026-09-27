package edgeplane

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

// testProvider is a minimal InterceptionRootProvider for custody tests.
type testProvider struct {
	cert    *x509.Certificate
	signer  crypto.Signer
	custody string
}

func (p *testProvider) Certificate() *x509.Certificate { return p.cert }
func (p *testProvider) CertPEM() []byte                { return nil }
func (p *testProvider) Signer() crypto.Signer          { return p.signer }

// custodyReportingProvider also declares where its key lives.
type custodyReportingProvider struct{ testProvider }

func (p *custodyReportingProvider) KeyCustody() string { return p.custody }

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "custody-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &testProvider{cert: cert, signer: key}
}

// A working key reports healthy, and an unknown provider is reported as "file" rather than claiming hardware
// custody it does not have — overstating custody would be worse than saying nothing.
func TestKeyCustodyHealthyFileKey(t *testing.T) {
	p := newTestProvider(t)
	h := CheckKeyCustodyHealth(p, time.Now)
	if !h.Healthy {
		t.Fatalf("expected healthy, got error %q", h.Error)
	}
	if h.Custody != KeyCustodyFile {
		t.Fatalf("custody = %q, want %q (an unknown provider must not claim hardware custody)", h.Custody, KeyCustodyFile)
	}
	if h.LatencyMS < 0 {
		t.Fatalf("latency must be recorded, got %v", h.LatencyMS)
	}
}

// A provider that knows its custody is reported verbatim — this is the seam the signing sidecar reports through.
func TestKeyCustodyReporterIsHonoured(t *testing.T) {
	base := newTestProvider(t)
	p := &custodyReportingProvider{testProvider: *base}
	p.custody = "pkcs11"
	if got := KeyCustodyOf(p); got != "pkcs11" {
		t.Fatalf("custody = %q, want pkcs11", got)
	}
	st := KeyCustodyStatus(NewKeyCustodyChecker(), p, time.Now)
	if st["non_exportable"] != true {
		t.Fatalf("pkcs11 custody must report non_exportable=true, got %v", st["non_exportable"])
	}
}

// ★ THE point of a FUNCTIONAL check: a signer that is present and returns no error, but whose signature does
// not verify against the certificate, must be reported UNHEALTHY. A liveness probe ("is the key store
// reachable?") passes here and would ship broken leaves — every certificate minted would be rejected by
// clients. This is the sealed-key-with-the-wrong-KEK / diverged-key case.
type wrongKeySigner struct{ other crypto.Signer }

func (s *wrongKeySigner) Public() crypto.PublicKey { return s.other.Public() }
func (s *wrongKeySigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	return s.other.Sign(r, d, o)
}

func TestKeyCustodyDetectsSignatureThatDoesNotVerify(t *testing.T) {
	p := newTestProvider(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	p.signer = &wrongKeySigner{other: other} // signs fine, but not with the cert's key

	h := CheckKeyCustodyHealth(p, time.Now)
	if h.Healthy {
		t.Fatal("a signature that does not verify against the certificate must be UNHEALTHY — " +
			"a reachability-only check would pass here and every minted leaf would be rejected by clients")
	}
	if h.Error == "" {
		t.Fatal("expected an error describing the mismatch")
	}
}

// A signer that fails outright is unhealthy — the plain hardware-is-gone case.
type failingSigner struct{ pub crypto.PublicKey }

func (s *failingSigner) Public() crypto.PublicKey { return s.pub }
func (s *failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("token not present")
}

func TestKeyCustodyDetectsSignFailure(t *testing.T) {
	p := newTestProvider(t)
	p.signer = &failingSigner{pub: p.cert.PublicKey}
	h := CheckKeyCustodyHealth(p, time.Now)
	if h.Healthy {
		t.Fatal("a signer that errors must be reported unhealthy")
	}
}

// The check is cached: an admin polling status must not drive one signing operation per request, because
// against an HSM every check costs real throughput.
type countingSigner struct {
	crypto.Signer
	n int
}

func (s *countingSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	s.n++
	return s.Signer.Sign(r, d, o)
}

func TestKeyCustodyCheckIsCached(t *testing.T) {
	p := newTestProvider(t)
	cs := &countingSigner{Signer: p.signer}
	p.signer = cs
	c := NewKeyCustodyChecker()

	base := time.Now()
	now := func() time.Time { return base }
	for i := 0; i < 5; i++ {
		if h := c.health(p, now); !h.Healthy {
			t.Fatalf("unexpected unhealthy: %v", h.Error)
		}
	}
	if cs.n != 1 {
		t.Fatalf("signed %d times for 5 status reads, want 1 (the result must be cached)", cs.n)
	}

	// After the interval it re-checks, so a key that breaks is not masked forever by the cache.
	now = func() time.Time { return base.Add(keyCustodyCheckInterval + time.Second) }
	_ = c.health(p, now)
	if cs.n != 2 {
		t.Fatalf("signed %d times after the interval elapsed, want 2 (a stale cache would hide a broken key)", cs.n)
	}
}

// The monitor must find a broken key by ASKING on a schedule. The leaf cache means nobody notices a dead
// signing key until they visit a hostname nobody has visited yet, so a check that only runs when someone
// reads the admin API is not monitoring.
func TestKeyCustodyMonitorReportsUnreadyWhenSigningBreaks(t *testing.T) {
	p := newTestProvider(t)
	good := p.signer
	var logs []string
	m := NewKeyCustodyMonitor(func() InterceptionRootProvider { return p }, time.Hour,
		func(f string, a ...any) { logs = append(logs, f) })

	m.Check()
	if ready, _ := m.Ready(); !ready {
		t.Fatal("a working key must be ready")
	}

	p.signer = &failingSigner{pub: p.cert.PublicKey}
	m.Check()
	ready, reason := m.Ready()
	if ready {
		t.Fatal("a key that cannot sign must make the node NOT ready — the balancer has to send new flows " +
			"to a node that can still mint leaves")
	}
	if reason == "" {
		t.Fatal("readiness must carry the reason so the operator is not left guessing")
	}

	p.signer = good
	m.Check()
	if ready, _ := m.Ready(); !ready {
		t.Fatal("recovery must restore readiness")
	}

	// Transitions are logged, not every check: repeating the same line every interval trains the operator to
	// ignore it.
	if len(logs) != 2 {
		t.Fatalf("expected 2 transition logs (degraded, recovered), got %d: %v", len(logs), logs)
	}
}

// Before the first check has run, readiness must NOT be false — otherwise every start-up would look like an
// outage to the balancer.
func TestKeyCustodyMonitorUnknownIsReady(t *testing.T) {
	m := NewKeyCustodyMonitor(func() InterceptionRootProvider { return nil }, time.Hour, nil)
	if ready, _ := m.Ready(); !ready {
		t.Fatal("an unchecked monitor must report ready; refusing traffic before the first check would make " +
			"every boot look like an outage")
	}
}

// slowProvider signs correctly but takes its time — a key store that has degraded rather than died.
type slowProvider struct {
	inner *testProvider
	delay time.Duration
}

func (p *slowProvider) Certificate() *x509.Certificate { return p.inner.Certificate() }
func (p *slowProvider) CertPEM() []byte                { return p.inner.CertPEM() }
func (p *slowProvider) Signer() crypto.Signer          { return slowSigner{p.inner.Signer(), p.delay} }

type slowSigner struct {
	inner crypto.Signer
	delay time.Duration
}

func (s slowSigner) Public() crypto.PublicKey { return s.inner.Public() }
func (s slowSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	time.Sleep(s.delay)
	return s.inner.Sign(rand, digest, opts)
}

// A key store that signs CORRECTLY but takes seconds must drain the node.
//
// It is worse than an outright failure: a dead store fails the functional check and the node is pulled out,
// while a slow one keeps passing and stays in rotation, so every new hostname a user visits waits on it. The
// leaf cache that hides an outright failure hides this too, so what reaches an operator is "some sites hang,
// most are fine" — which does not look like the key store at all.
func TestASlowKeyStoreDrainsTheNode(t *testing.T) {
	slow := &slowProvider{inner: newTestProvider(t), delay: keyCustodySlowSignThreshold + 250*time.Millisecond}
	monitor := NewKeyCustodyMonitor(func() InterceptionRootProvider { return slow }, time.Hour, func(string, ...any) {})

	// One slow sample must NOT drain: a garbage-collection pause or a busy host would otherwise flap the node
	// in and out of the balancer, which costs more than the slowness it reacts to.
	monitor.Check()
	if ready, _ := monitor.Ready(); !ready {
		t.Fatal("a single slow check pulled the node out of rotation — that flaps on ordinary jitter")
	}

	for i := 1; i < keyCustodySlowChecksBeforeUnready; i++ {
		monitor.Check()
	}
	ready, reason := monitor.Ready()
	if ready {
		t.Fatalf("after %d consecutive slow checks the node is still accepting flows — every new hostname would "+
			"stall on a key store that is technically healthy", keyCustodySlowChecksBeforeUnready)
	}
	if reason == "" {
		t.Fatal("drained without a reason; an operator cannot tell this from an outright failure")
	}

	// And the health itself stays HEALTHY: the signatures verify. Reporting it as failed would send an
	// operator to replace a device that is working, when the problem may be load.
	if h := monitor.Health(); !h.Healthy {
		t.Fatal("a slow-but-correct store was reported as unhealthy; the two need different operator actions")
	}
}

// Speed returning must put the node back. A drain that never lifts is an outage of its own.
func TestNodeReturnsWhenSigningSpeedRecovers(t *testing.T) {
	current := &slowProvider{inner: newTestProvider(t), delay: keyCustodySlowSignThreshold + 250*time.Millisecond}
	monitor := NewKeyCustodyMonitor(func() InterceptionRootProvider { return current }, time.Hour, func(string, ...any) {})
	for i := 0; i < keyCustodySlowChecksBeforeUnready; i++ {
		monitor.Check()
	}
	if ready, _ := monitor.Ready(); ready {
		t.Fatal("precondition: the node should be drained")
	}

	current.delay = 0
	monitor.Check()
	if ready, reason := monitor.Ready(); !ready {
		t.Fatalf("the node stayed drained after signing recovered (%s) — a drain that never lifts is its own outage", reason)
	}
}

// "Check signing now" is exposed to read-only administrators. Clicking it three times while one slow patch
// lasts must not do what three consecutive scheduled checks (a minute and a half of sustained slowness) do:
// pull the node out of rotation. A request still refreshes what the page shows, and an outright failure it
// finds still drains, exactly as a scheduled one would.
func TestRequestedChecksDoNotCountTowardsDraining(t *testing.T) {
	slow := &slowProvider{inner: newTestProvider(t), delay: keyCustodySlowSignThreshold + 250*time.Millisecond}
	monitor := NewKeyCustodyMonitor(func() InterceptionRootProvider { return slow }, time.Hour, func(string, ...any) {})
	monitor.Check() // one scheduled slow sample
	for i := 0; i < keyCustodySlowChecksBeforeUnready; i++ {
		monitor.CheckNow()
	}
	if ready, reason := monitor.Ready(); !ready {
		t.Fatalf("requested checks drained the node: %s", reason)
	}
	if h := monitor.Health(); !h.Healthy || h.CheckedAt.IsZero() {
		t.Fatalf("a requested check did not refresh the reported health: %+v", h)
	}
	for i := 1; i < keyCustodySlowChecksBeforeUnready; i++ {
		monitor.Check()
	}
	if ready, _ := monitor.Ready(); ready {
		t.Fatal("requested checks in between reset the scheduled count")
	}

	p := newTestProvider(t)
	broken := NewKeyCustodyMonitor(func() InterceptionRootProvider { return p }, time.Hour, func(string, ...any) {})
	p.signer = &failingSigner{pub: p.cert.PublicKey}
	broken.CheckNow()
	if ready, _ := broken.Ready(); ready {
		t.Fatal("a requested check that finds a key unable to sign must drain, as a scheduled one does")
	}
}
