package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testTrustStore(t *testing.T, seed string, serial int64) (*transportTrustStore, *int) {
	t.Helper()
	resigns := 0
	s, err := openTransportTrustStore(filepath.Join(t.TempDir(), "trust.json"), seed, serial,
		func(pems string, serial int64) (func(), error) {
			return func() { resigns++ }, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return s, &resigns
}

// Add and withdraw advance the serial by one and re-sign exactly once each — the distribution devices
// refuse to roll back on can never be left behind by a change.
func TestTransportTrustStoreSerialAndResign(t *testing.T) {
	a := string(testCertPEM(t, "old"))
	b := string(testCertPEM(t, "new"))
	s, resigns := testTrustStore(t, a, 5)

	added, serial, err := s.Add(b)
	if err != nil || added.Subject.CommonName != "new" || serial != 6 {
		t.Fatalf("add: %v serial=%d", err, serial)
	}
	if _, _, err := s.Add(b); err == nil {
		t.Fatal("adding the same certificate twice must be refused")
	}

	anchors := s.Anchors()
	oldSHA := ""
	for _, c := range anchors {
		if c.Subject.CommonName == "old" {
			item := pkiItemFromCert(c)
			oldSHA = item.SHA256
		}
	}
	removed, serial, err := s.Withdraw(oldSHA)
	if err != nil || removed.Subject.CommonName != "old" || serial != 7 {
		t.Fatalf("withdraw: %v serial=%d", err, serial)
	}
	if *resigns != 2 {
		t.Fatalf("each change re-signs once, got %d", *resigns)
	}

	// The LAST certificate can never be withdrawn, whatever the caller decided.
	last := pkiItemFromCert(s.Anchors()[0])
	if _, _, err := s.Withdraw(last.SHA256); err == nil {
		t.Fatal("withdrawing the last certificate must be refused")
	}
}

// The store survives a restart with the set and serial it last committed, and the seed no longer applies.
func TestTransportTrustStoreDurability(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	a := string(testCertPEM(t, "old"))
	b := string(testCertPEM(t, "new"))
	s, err := openTransportTrustStore(path, a, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Add(b); err != nil {
		t.Fatal(err)
	}

	reopened, err := openTransportTrustStore(path, a, 1, nil) // same seed as day one
	if err != nil {
		t.Fatal(err)
	}
	pems, serial := reopened.Current()
	if serial != 2 || len(parseAllCerts([]byte(pems))) != 2 {
		t.Fatalf("the committed set must survive a restart, got serial=%d anchors=%d", serial, len(parseAllCerts([]byte(pems))))
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("the store holds public certificates only")
	}
}

// A set that cannot be re-signed is not adopted: the change is refused and the previous set keeps serving.
func TestTransportTrustStoreSignFailureAborts(t *testing.T) {
	a := string(testCertPEM(t, "old"))
	b := string(testCertPEM(t, "new"))
	s, err := openTransportTrustStore(filepath.Join(t.TempDir(), "trust.json"), a, 1,
		func(string, int64) (func(), error) { return nil, os.ErrPermission })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Add(b); err == nil {
		t.Fatal("a set that cannot be signed must not be adopted")
	}
	if _, serial := s.Current(); serial != 1 || len(s.Anchors()) != 1 {
		t.Fatal("the previous set must keep serving after a refused change")
	}
}

// R7: a serial may only go up. The reference lab really does run a store at serial 3 against a compose
// flag of 2, so a node rebuilt from the compose file without the state directory would have distributed a
// number the fleet had already passed — and every device would have refused it as a rollback while the
// Console reported success.
func TestTransportTrustSerialOnlyGoesUp(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/trust.json"
	a := string(testCertPEM(t, "anchor"))

	first, err := openTransportTrustStore(path, a, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.Add(string(testCertPEM(t, "second"))); err != nil {
		t.Fatal(err)
	}
	if _, serial := first.Current(); serial != 3 {
		t.Fatalf("a change advances the serial, got %d", serial)
	}

	// Reopened with the ORIGINAL flag value, as a rebuilt node would be.
	reopened, err := openTransportTrustStore(path, a, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, serial := reopened.Current(); serial != 3 {
		t.Fatalf("the store's higher serial must win over a stale flag, got %d", serial)
	}

	// And when the FLAG is ahead — an operator raised it, or the state is older than the deployment —
	// the higher one is adopted rather than silently handing the fleet a number it has passed.
	ahead, err := openTransportTrustStore(path, a, 9, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, serial := ahead.Current(); serial != 9 {
		t.Fatalf("a flag ahead of the store must be adopted, got %d", serial)
	}
	if _, _, err := ahead.Withdraw(certFingerprint(ahead.Anchors()[0])); err != nil {
		t.Fatal(err)
	}
	if _, serial := ahead.Current(); serial != 10 {
		t.Fatalf("changes continue from the adopted serial, got %d", serial)
	}
}

// A flag-floor bump must be DURABLE, not memory-only. Without persisting the adopted floor, the file stays at
// the old serial until some later mutation writes it; a restart where the flag no longer sits at/above the
// highest-served value then reloads the OLD serial and re-signs BELOW the fleet's high-water mark, stranding
// every device on a replay-refused distribution. This is the exact scenario the reference lab creates by
// running the flag below the store, so it must hold with NO Add/Withdraw between the bump and the restart.
func TestTransportTrustAdoptedFloorSurvivesRestartWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/trust.json"
	a := string(testCertPEM(t, "anchor"))

	// First run at serial 5, then a one-time floor bump to 7 (the operator pushes a keyring change).
	if _, err := openTransportTrustStore(path, a, 5, nil); err != nil {
		t.Fatal(err)
	}
	bumped, err := openTransportTrustStore(path, a, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, serial := bumped.Current(); serial != 7 {
		t.Fatalf("the flag floor must be adopted, got %d", serial)
	}

	// Restart with the flag back below the store (a steady-state compose, or the bump dropped) and NO mutation
	// in between. The persisted floor must win: serving anything below 7 hands the fleet a serial it has passed.
	restarted, err := openTransportTrustStore(path, a, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, serial := restarted.Current(); serial != 7 {
		t.Fatalf("the adopted floor must survive a restart with a lower flag and no mutation, got %d (want 7)", serial)
	}
}

// A distribution devices will refuse is not a distribution: a set with no serial, and a first run with no
// serial to give, are both refused at load rather than served.
func TestTransportTrustRefusesASerialDevicesWouldReject(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/trust.json"
	if err := os.WriteFile(path, []byte(`{"schema_version":"transport_trust_store.v1","serial":0,"anchors_pem":"`+
		strings.ReplaceAll(string(testCertPEM(t, "x")), "\n", "\\n")+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTransportTrustStore(path, "", 0, nil); err == nil {
		t.Fatal("a stored set with no serial must be refused, not distributed as serial 0")
	}
	if _, err := openTransportTrustStore(dir+"/fresh.json", string(testCertPEM(t, "y")), 0, nil); err == nil {
		t.Fatal("a first run with no serial must be refused")
	}
}

// R9: the caller's gate is re-judged inside the store lock, so a decision made on a stale snapshot cannot
// be acted on. Also proves the callback may read the store's own state without deadlocking.
func TestWithdrawReJudgesTheGateUnderTheLock(t *testing.T) {
	dir := t.TempDir()
	a := string(testCertPEM(t, "a"))
	s, err := openTransportTrustStore(dir+"/trust.json", a, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Add(string(testCertPEM(t, "b"))); err != nil {
		t.Fatal(err)
	}
	victim := certFingerprint(s.Anchors()[0])

	// A gate that refuses at the moment of removal must stop it, even though the caller decided to proceed.
	var sawRemaining int
	if _, _, err := s.WithdrawIf(victim, func(remaining []*x509.Certificate) (bool, string) {
		sawRemaining = len(remaining)
		return false, "conditions changed while waiting for the lock"
	}); err == nil {
		t.Fatal("a gate refusing under the lock must stop the withdrawal")
	}
	if sawRemaining != 1 {
		t.Fatalf("the gate sees what WOULD remain, got %d", sawRemaining)
	}
	if len(s.Anchors()) != 2 {
		t.Fatal("a refused withdrawal changes nothing")
	}

	// And an allowing gate proceeds.
	if _, _, err := s.WithdrawIf(victim, func([]*x509.Certificate) (bool, string) { return true, "" }); err != nil {
		t.Fatal(err)
	}
	if len(s.Anchors()) != 1 {
		t.Fatal("an allowed withdrawal removes exactly one")
	}
}
