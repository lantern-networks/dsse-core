package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// The withdrawal gate had no direct test (review V9) while being the one decision that can strand a
// fleet. These cover each way it must refuse, and the one way it may allow.

type fakeObserved struct{ ready map[string][]string }

func (f fakeObserved) Record(observedExclusionEntry) {}
func (f fakeObserved) Query(string, observedQueryFilter) observedQueryResult {
	return observedQueryResult{}
}
func (f fakeObserved) ByApp(string, int) observedByAppResult { return observedByAppResult{} }

// This double answers "nobody has said anything", which is the state that keeps the recovery port open —
// the safe direction for a test that is not about the fold.
func (f fakeObserved) RecoveryNameReadiness(_ string, name string, known []string) recoveryNameReadiness {
	return recoveryNameReadiness{Name: name, Silent: append([]string{}, known...)}
}

func (f fakeObserved) TransportCAReadinessAtSerial(t string, fp string, known []string, _ int64) transportCAReadiness {
	return f.TransportCAReadiness(t, fp, known)
}

func (f fakeObserved) TransportCAReadiness(_ string, fp string, known []string) transportCAReadiness {
	r := transportCAReadiness{Ready: []string{}, NotReady: []string{}, Silent: []string{}, NeverReportedAnything: []string{}}
	holders := map[string]bool{}
	for _, id := range f.ready[fp] {
		holders[id] = true
	}
	for _, id := range known {
		if holders[id] {
			r.Ready = append(r.Ready, id)
		} else {
			r.Silent = append(r.Silent, id)
			r.NeverReportedAnything = append(r.NeverReportedAnything, id)
		}
	}
	total := len(known)
	if total > 0 {
		r.ReadyPct = len(r.Ready) * 100 / total
	}
	r.SafeToCut = total > 0 && len(r.NotReady) == 0 && len(r.Silent) == 0
	return r
}

func gateFixture(t *testing.T) (a, b *x509.Certificate) {
	t.Helper()
	return parseAllCerts(testCertPEM(t, "anchor-a"))[0], parseAllCerts(testCertPEM(t, "anchor-b"))[0]
}

func TestWithdrawGateRefusesTheLastCertificate(t *testing.T) {
	a, _ := gateFixture(t)
	prev := transportTrust
	transportTrust = &transportTrustStore{}
	defer func() { transportTrust = prev }()
	ok, verdict := anchorWithdrawGate(serverConfig{}, "t", certFingerprint(a), []*x509.Certificate{a}, []string{"d1"}, 1)
	if ok || verdict.Code != "last_certificate" {
		t.Fatalf("the last certificate can never be withdrawn: ok=%v verdict=%+v", ok, verdict.Text)
	}
}

func TestWithdrawGateRefusesWhenTrustCannotBeMeasured(t *testing.T) {
	a, b := gateFixture(t)
	prev := transportTrust
	transportTrust = &transportTrustStore{}
	defer func() { transportTrust = prev }()
	ok, verdict := anchorWithdrawGate(serverConfig{}, "t", certFingerprint(a), []*x509.Certificate{a, b}, []string{"d1"}, 1)
	if ok || verdict.Code != "not_measurable" {
		t.Fatalf("no telemetry means no withdrawal: ok=%v verdict=%+v", ok, verdict.Text)
	}
}

// R6: an unreadable served certificate is not permission.
func TestWithdrawGateRefusesWhenTheServedCertificateCannotBeRead(t *testing.T) {
	a, b := gateFixture(t)
	prev, prevServed := transportTrust, transportServedCert
	transportTrust, transportServedCert = &transportTrustStore{}, nil
	defer func() { transportTrust, transportServedCert = prev, prevServed }()
	cfg := serverConfig{ObservedExclusions: fakeObserved{ready: map[string][]string{
		certFingerprint(b): {"d1"},
	}}, TransportCertFile: "/nonexistent/transport.pem"}
	ok, verdict := anchorWithdrawGate(cfg, "t", certFingerprint(a), []*x509.Certificate{a, b}, []string{"d1"}, 1)
	if ok || verdict.Code != "served_certificate_unreadable" {
		t.Fatalf("an unreadable served certificate must refuse, not pass: ok=%v verdict=%+v", ok, verdict.Text)
	}
}

// R5: coverage from one certificate and chain-verification from another is NOT the invariant. B is
// trusted by everyone but does not issue what the Edge serves; C issues it but nobody trusts C.
func TestWithdrawGateRequiresOneCertificateToSatisfyBoth(t *testing.T) {
	target, covering := gateFixture(t)
	issuing := parseAllCerts(testCertPEM(t, "anchor-c"))[0]
	prev, prevServed := transportTrust, transportServedCert
	transportTrust, transportServedCert = &transportTrustStore{}, nil
	defer func() { transportTrust, transportServedCert = prev, prevServed }()

	// The Edge presents `issuing` itself (self-signed), so only `issuing` verifies the chain — and only
	// `covering` is trusted by the fleet.
	dir := t.TempDir()
	path := dir + "/transport.pem"
	writePEM(t, path, issuing)
	cfg := serverConfig{
		ObservedExclusions: fakeObserved{ready: map[string][]string{certFingerprint(covering): {"d1"}}},
		TransportCertFile:  path,
	}
	ok, verdict := anchorWithdrawGate(cfg, "t", certFingerprint(target),
		[]*x509.Certificate{target, covering, issuing}, []string{"d1"}, 1)
	if ok {
		t.Fatal("coverage from one certificate and chain from another must not open the gate")
	}
	if verdict.Text == "" {
		t.Fatal("a refusal must say why")
	}

	// With ONE certificate doing both jobs, it opens.
	cfg.ObservedExclusions = fakeObserved{ready: map[string][]string{certFingerprint(issuing): {"d1"}}}
	ok, verdict = anchorWithdrawGate(cfg, "t", certFingerprint(target),
		[]*x509.Certificate{target, issuing}, []string{"d1"}, 1)
	if !ok {
		t.Fatalf("one certificate covering the fleet AND verifying the Edge must open it: %q", verdict.Text)
	}
}

func writePEM(t *testing.T, path string, c *x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
}
