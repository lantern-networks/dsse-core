package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestWatch(t *testing.T) (*interceptionWatch, *interceptionRefusalJournal, string) {
	t.Helper()
	dir := t.TempDir()
	j := newInterceptionRefusalJournal(dir)
	if j == nil {
		t.Fatal("a journal with a state dir must not be disabled")
	}
	w := newInterceptionWatch(j, nil)
	w.now = func() time.Time { return time.Date(2026, 8, 21, 15, 47, 0, 0, time.UTC) }
	return w, j, dir
}

// For eighteen minutes the only record of a total HTTPS outage was flows in a log nothing consumed, while the
// agent reported enforcement=healthy every fifteen seconds. This is that outage, with the device now asking.
func TestTheEighteenMinuteOutageIsNoLongerSilent(t *testing.T) {
	w, j, dir := newTestWatch(t)
	w.noteDestination("160.79.104.10:443")
	w.probe = func(dst string) (string, string) {
		if dst != "160.79.104.10:443" {
			t.Errorf("the probe was aimed at %q, not at somewhere this device actually talks to", dst)
		}
		return "abc123", "the intercepted chain is refused by BOTH verifiers on this device — go: x509: certificate " +
			"signed by unknown authority / platform: x509: certificate signed by unknown authority"
	}
	w.runOnce()

	got := j.pending()
	if len(got) != 1 {
		t.Fatalf("the device recorded %d entries for an interception it cannot verify; it has to record one", len(got))
	}
	if got[0].Destination != "160.79.104.10:443" || got[0].ServedSHA256 != "abc123" {
		t.Fatalf("the entry does not identify what was judged: %+v", got[0])
	}
	if !strings.Contains(got[0].Reason, "x509: certificate signed by unknown authority") {
		t.Fatalf("the verifier's own words were not carried: %q", got[0].Reason)
	}
	// It survives the restart of a box that is failing, which is the only reason it is on disk at all.
	raw, err := os.ReadFile(filepath.Join(dir, "interception_refusals.json"))
	if err != nil {
		t.Fatalf("the journal was not persisted: %v", err)
	}
	var onDisk []interceptionRefusal
	if err := json.Unmarshal(raw, &onDisk); err != nil || len(onDisk) != 1 {
		t.Fatalf("the persisted journal is not readable back: err=%v entries=%d", err, len(onDisk))
	}
}

// ★ A HEALTHY DEVICE MUST NOT FILL THE JOURNAL. The journal ships on every effective report; a row every quarter
// hour saying "fine" would bury the rows that are not. Health is reported by the interception-root field beside
// it, not by this.
func TestASuccessfulVerificationIsNotJournaled(t *testing.T) {
	w, j, _ := newTestWatch(t)
	w.noteDestination("160.79.104.10:443")
	w.probe = func(string) (string, string) { return "abc123", verificationSentence(nil, nil) }
	for i := 0; i < 20; i++ {
		w.runOnce()
	}
	if got := j.pending(); len(got) != 0 {
		t.Fatalf("a working device filled its own journal: %+v", got)
	}
}

// A probe that could not get an answer says nothing. "The Edge was unreachable" is not a fact about a
// certificate, and recording it as one is how an outage gets blamed on the wrong thing.
func TestAProbeThatCannotAnswerRecordsNothing(t *testing.T) {
	w, j, _ := newTestWatch(t)
	w.noteDestination("160.79.104.10:443")
	w.probe = func(string) (string, string) { return "", "" }
	if reason := w.runOnce(); reason != "" {
		t.Fatalf("a silent probe produced a verdict: %q", reason)
	}
	if got := j.pending(); len(got) != 0 {
		t.Fatalf("a silent probe wrote to the journal: %+v", got)
	}
}

// Before anything has been steered there is nowhere honest to probe, and a synthetic target would answer a
// question nobody asked.
func TestNothingIsProbedBeforeAnythingHasBeenSteered(t *testing.T) {
	w, j, _ := newTestWatch(t)
	called := false
	w.probe = func(string) (string, string) { called = true; return "x", "y" }
	w.runOnce()
	if called {
		t.Fatal("the watch invented a destination")
	}
	if got := j.pending(); len(got) != 0 {
		t.Fatalf("something was journaled with no traffic to judge: %+v", got)
	}
}

// A deployment that stays broken is probed every interval. That has to be one growing row, not a row per probe.
func TestARepeatedRefusalIsOneGrowingRow(t *testing.T) {
	w, j, _ := newTestWatch(t)
	w.noteDestination("160.79.104.10:443")
	w.probe = func(string) (string, string) {
		return "abc123", "the intercepted chain is refused by BOTH verifiers on this device — go: x509: bad"
	}
	for i := 0; i < 10; i++ {
		w.runOnce()
	}
	got := j.pending()
	if len(got) != 1 || got[0].Count != 10 {
		t.Fatalf("ten probes against one broken deployment produced entries=%d count=%d", len(got), got[0].Count)
	}
}

// A deployment that changes what it is serving produces a SECOND row, because it is a different certificate and
// possibly a different reason — merging them would hide a rotation happening mid-outage.
func TestADifferentCertificateIsADifferentRow(t *testing.T) {
	w, j, _ := newTestWatch(t)
	w.noteDestination("160.79.104.10:443")
	leaf := "aaa"
	w.probe = func(string) (string, string) { return leaf, "refused: go: x509: unknown authority" }
	w.runOnce()
	leaf = "bbb"
	w.runOnce()
	if got := j.pending(); len(got) != 2 {
		t.Fatalf("two different certificates were merged into %d row(s): %+v", len(got), got)
	}
}

// ★ THE SENTENCE IS NOT FLATTENED. On 2026-08-21 an intercepted chain was accepted by Chrome and refused by
// openssl, git and Node because of pathLenConstraint:0. "Certificate error" would have been true and useless;
// the constraint's name is the whole finding, and a disagreement between verifiers is a different fact from both
// of them refusing.
func TestTheVerifierSentenceIsNotFlattened(t *testing.T) {
	pathLen := errors.New(`x509: certificate signed by unknown authority (possibly because of "x509: path length constraint exceeded")`)
	unknown := errors.New("x509: certificate signed by unknown authority")

	both := verificationSentence(pathLen, unknown)
	if !strings.Contains(both, "path length constraint exceeded") {
		t.Fatalf("the constraint's name was dropped: %q", both)
	}
	if !strings.Contains(both, "BOTH verifiers") || interceptionVerified(both) {
		t.Fatalf("both verifiers refused and the entry does not read as a refusal: %q", both)
	}

	// The measured 2026-08-21 split: the platform's own chain validation allowed what Go refused.
	split := verificationSentence(pathLen, nil)
	if !strings.Contains(split, "DISAGREE") || !strings.Contains(split, "path length constraint exceeded") {
		t.Fatalf("the disagreement that hid the defect for a day is not reported as one: %q", split)
	}
	if interceptionVerified(split) {
		t.Fatalf("a disagreement is being treated as a healthy device: %q", split)
	}

	// And the reverse split is not silently the same sentence.
	reverse := verificationSentence(nil, unknown)
	if !strings.Contains(reverse, "DISAGREE") || !strings.Contains(reverse, "platform: ") {
		t.Fatalf("the reverse disagreement is not attributed to the right verifier: %q", reverse)
	}
	if interceptionVerified(reverse) {
		t.Fatalf("a platform refusal is being treated as a healthy device: %q", reverse)
	}
}

// ★ SUCCESS IS A STATEMENT TOO. This is the 2026-08-22 sentence: the material verifies on this device, so a tool
// that is still failing is not reading these stores. It is what separates a deployment problem from a machine's
// own configuration, and it took three hours to reach by hand without it.
func TestTheSuccessSentencePointsAtTheToolNotTheDeployment(t *testing.T) {
	s := verificationSentence(nil, nil)
	if !interceptionVerified(s) {
		t.Fatalf("a successful verification does not read as one: %q", s)
	}
	if !strings.Contains(s, "not the problem") || !strings.Contains(s, "not reading these stores") {
		t.Fatalf("the sentence does not point at the tool: %q", s)
	}
	if !strings.Contains(s, "NODE_EXTRA_CA_CERTS") {
		t.Fatalf("the sentence does not name the thing that was actually stale on 2026-08-22: %q", s)
	}
}

// Every sentence has to survive the journal's bound intact, or the tail — where the second verifier's
// disagreement lives — is exactly what gets cut.
func TestEverySentenceFitsInTheJournal(t *testing.T) {
	long := errors.New(strings.Repeat("x509: certificate signed by unknown authority; ", 20))
	for name, s := range map[string]string{
		"both":     verificationSentence(long, long),
		"go":       verificationSentence(long, nil),
		"platform": verificationSentence(nil, long),
		"neither":  verificationSentence(nil, nil),
	} {
		if len(s) > maxInterceptionReasonLen {
			t.Errorf("the %s sentence is %d chars and would be truncated at %d", name, len(s), maxInterceptionReasonLen)
		}
	}
}

// Mirrors the transport journal exactly: the report is the only copy, so entries go only when the Edge has taken
// them, and an entry that grew mid-flight is kept.
func TestTheJournalClearsOnlyWhatTheEdgeAccepted(t *testing.T) {
	dir := t.TempDir()
	j := newInterceptionRefusalJournal(dir)
	now := time.Date(2026, 8, 22, 3, 0, 0, 0, time.UTC)
	j.record(interceptionRefusal{ServedSHA256: "a", Reason: "r1"}, now)
	j.record(interceptionRefusal{ServedSHA256: "b", Reason: "r2"}, now)

	sent := j.pending()
	// While that report is in flight, the same refusal happens again.
	j.record(interceptionRefusal{ServedSHA256: "a", Reason: "r1"}, now.Add(time.Minute))
	j.clear(sent)

	left := j.pending()
	if len(left) != 1 || left[0].ServedSHA256 != "a" || left[0].Count != 2 {
		t.Fatalf("the entry that recurred while the report was in flight was lost: %+v", left)
	}
}

// A journal with nowhere to write is disabled, and every path has to tolerate that rather than being the reason
// a flow ends differently.
func TestAWatchWithNoJournalIsHarmless(t *testing.T) {
	var nilWatch *interceptionWatch
	nilWatch.noteDestination("1.2.3.4:443") // must not panic
	nilWatch.runOnce()

	w := newInterceptionWatch(newInterceptionRefusalJournal(""), nil)
	w.noteDestination("1.2.3.4:443")
	w.probe = func(string) (string, string) { return "x", "refused" }
	w.runOnce()
}

// End to end over a real handshake: the probe must COMPLETE the handshake, look at the chain, and come back with
// the verifier's own words rather than "handshake failed" — which is what verifying inside the handshake would
// have produced, collapsing every distinct reason into one.
func TestTheProbeReportsWhatTheVerifierSaidAboutARealChain(t *testing.T) {
	cert := selfSignedForTest(t)
	dial := func(string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			s := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})
			_ = s.Handshake()
			<-time.After(2 * time.Second)
			_ = s.Close()
		}()
		return client, nil
	}

	fp, reason := probeInterceptedChain(dial, "1.2.3.4:443", x509.NewCertPool())
	if fp == "" {
		t.Fatal("the probe did not identify the certificate it judged")
	}
	if reason == "" {
		t.Fatal("the probe completed a handshake against an untrusted chain and said nothing")
	}
	if !strings.Contains(reason, "x509:") {
		t.Fatalf("the verifier's own words are missing: %q", reason)
	}
	if interceptionVerified(reason) {
		t.Fatalf("an untrusted chain was reported as verified: %q", reason)
	}
	if !strings.Contains(reason, "issuers, not for its name") {
		t.Fatalf("the probe does not admit what it could not check: %q", reason)
	}
}

// A destination that cannot be reached says nothing about a certificate, so it must not become an entry.
func TestAnUnreachableDestinationIsNotAVerdict(t *testing.T) {
	dial := func(string) (net.Conn, error) { return nil, errors.New("mux unreachable") }
	if fp, reason := probeInterceptedChain(dial, "1.2.3.4:443", nil); fp != "" || reason != "" {
		t.Fatalf("an unreachable Edge produced a verdict about a certificate: fp=%q reason=%q", fp, reason)
	}
}

func selfSignedForTest(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Lab Tenant Interception Issuing CA test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"api.anthropic.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
