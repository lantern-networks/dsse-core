package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

// The old read/check/Save path lets both authors pass the serial check, then
// overwrite each other. Transactional updates serialize without using this seam.
type overlappingTrustFixture struct {
	transactionalCAFixture
	barrier chan struct{}
	saves   sync.WaitGroup
}

func (p *overlappingTrustFixture) Save(raw []byte) error {
	if p.barrier != nil {
		p.saves.Done()
		<-p.barrier
	}
	return p.transactionalCAFixture.Save(raw)
}
func TestSharedTrustConcurrentAddsPreserveBothAuthors(t *testing.T) {
	p := &overlappingTrustFixture{}
	seed := string(testCertPEM(t, "seed"))
	a, err := openSharedTransportTrustStore(p, "", seed, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openSharedTransportTrustStore(p, "", seed, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.barrier = make(chan struct{})
	p.saves.Add(2)
	additions := []string{string(testCertPEM(t, "a")), string(testCertPEM(t, "b"))}
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	for i, s := range []*transportTrustStore{a, b} {
		go func(i int, s *transportTrustStore) { defer wg.Done(); _, _, err := s.Add(additions[i]); errs <- err }(i, s)
	}
	// Only the legacy path calls Save; don't wait on its barrier for the fixed path.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	legacy := make(chan struct{})
	go func() { p.saves.Wait(); close(legacy) }()
	select {
	case <-done:
		p.saves.Done()
		p.saves.Done()
	case <-legacy:
		close(p.barrier)
		<-done
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := p.Load()
	var st transportTrustStoreState
	json.Unmarshal(raw, &st)
	if st.Serial != 3 || len(parseAllCerts([]byte(st.AnchorsPEM))) != 3 {
		t.Fatalf("concurrent author lost: serial=%d anchors=%d", st.Serial, len(parseAllCerts([]byte(st.AnchorsPEM))))
	}
}

func TestSharedTrustCommitFailureAndLatestWithdrawalGate(t *testing.T) {
	p := &transactionalCAFixture{}
	seed := string(testCertPEM(t, "seed"))
	other := string(testCertPEM(t, "other"))
	published := 0
	a, err := openSharedTransportTrustStore(p, "", seed, 7, func(string, int64) (func(), error) { return func() { published++ }, nil })
	if err != nil {
		t.Fatal(err)
	}
	b, err := openSharedTransportTrustStore(p, "", seed, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = b.Add(other)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := p.Load()
	live, serial := a.Current()
	p.failCommit = true
	if c, n, err := a.Add(string(testCertPEM(t, "failed"))); err == nil || c != nil || n != 0 {
		t.Fatal("uncommitted result escaped")
	}
	after, _ := p.Load()
	now, n := a.Current()
	if !bytes.Equal(before, after) || live != now || serial != n || published != 0 {
		t.Fatal("failed commit published")
	}
	if _, m, err := a.AdvanceForAnnouncement([]string{"recovery-sni=edge.invalid"}, "test"); err == nil || m || a.RecoveryNameSince() != 0 {
		t.Fatal("failed announcement published")
	}
	p.failCommit = false
	fp := certFingerprint(parseAllCerts([]byte(seed))[0])
	called := false
	_, _, err = a.WithdrawIfContext(context.Background(), fp, func(remaining []*x509.Certificate, removed *x509.Certificate, serial int64) (bool, string) {
		called = true
		if certFingerprint(removed) != fp || serial != 8 || len(remaining) != 1 || remaining[0].Subject.CommonName != "other" {
			t.Fatal("gate used stale distribution", serial)
		}
		return false, "blocked"
	})
	if err == nil || !called {
		t.Fatal("gate bypassed")
	}
	_, n, err = a.Withdraw(fp)
	if err != nil || n != 9 || published != 1 {
		t.Fatal(n, err, published)
	}
	if err := b.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if len(b.Anchors()) != 1 || b.Anchors()[0].Subject.CommonName != "other" {
		t.Fatal("withdrawal resurrected")
	}
}

func TestSharedTrustReadSeedAndAnnouncementBoundaries(t *testing.T) {
	p := &transactionalCAFixture{}
	seed := string(testCertPEM(t, "seed"))
	a, err := openSharedTransportTrustStore(p, "", seed, 5, func(string, int64) (func(), error) { return func() {}, nil })
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := p.Load()
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	fields["future_field"] = "keep"
	raw, _ = json.Marshal(fields)
	p.Save(raw)
	if n, m, err := a.AdvanceForAnnouncement([]string{"recovery-sni=edge.invalid"}, "test"); err != nil || !m || n != 6 || a.RecoveryNameSince() != 6 {
		t.Fatal(n, m, err)
	}
	if n, m, err := a.AdvanceForAnnouncement([]string{"recovery-sni=edge.invalid"}, "test"); err != nil || m || n != 6 {
		t.Fatal(n, m, err)
	}
	saved, _ := p.Load()
	if !bytes.Contains(saved, []byte(`"future_field":"keep"`)) {
		t.Fatal("extension lost")
	}
	for _, bad := range [][]byte{nil, []byte(`{}`), []byte(`{"serial":8,"anchors_pem":"invalid"}`)} {
		p.Save(bad)
		if err := a.RefreshShared(); err == nil {
			t.Fatal("invalid read accepted")
		}
		if _, _, err := a.Add(string(testCertPEM(t, "rejected"))); err == nil {
			t.Fatal("invalid row overwritten")
		}
		got, _ := p.Load()
		if !bytes.Equal(got, bad) {
			t.Fatal("changed invalid row")
		}
	}
	p.Save(saved)
	restarted, err := openSharedTransportTrustStore(p, "", string(testCertPEM(t, "wrong-seed")), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pems, n := restarted.Current(); n != 6 || pems != seed {
		t.Fatal("restart changed authority")
	}
	// A candidate which cannot be signed must never commit.
	a.resign = func(string, int64) (func(), error) { return nil, fmt.Errorf("sign rejected") }
	if _, _, err := a.Add(string(testCertPEM(t, "unsigned"))); err == nil {
		t.Fatal("unsigned accepted")
	}
	after, _ := p.Load()
	if !bytes.Equal(saved, after) {
		t.Fatal("unsigned committed")
	}
}
