package authrollout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// A shared transactional backend; two Store objects represent independent CPs.
type memory struct {
	mu   sync.Mutex
	b    []byte
	fail bool
}

func (p *memory) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.b...), nil
}
func (p *memory) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return fmt.Errorf("disk unavailable")
	}
	p.b = append([]byte(nil), b...)
	return nil
}
func (p *memory) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := f(p.b)
	if e != nil {
		return e
	}
	if p.fail {
		return fmt.Errorf("commit failed")
	}
	p.b = b
	return nil
}
func fixture(t *testing.T) (*Store, *memory, Manifest, time.Time) {
	t.Helper()
	p := &memory{}
	s := NewStore(p)
	m := Manifest{Deployment: "fleet", Generation: 1, Providers: map[string]string{ProviderKey("tenant", "corp"): fmt.Sprintf("%064x", 99)}}
	for i, role := range []string{"cp", "cp", "cp", "edge", "edge", "edge"} {
		m.Members = append(m.Members, Member{ID: fmt.Sprint(i), Role: role, CertificateSHA256: fmt.Sprintf("%064x", i+1), Version: "0.3.1"})
	}
	if e := s.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	return s, p, m, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
}
func report(t *testing.T, s *Store, m Manifest, i int, now time.Time) {
	t.Helper()
	n := m.Members[i]
	e := s.Record(context.Background(), n.CertificateSHA256, Report{Generation: m.Generation, NodeID: n.ID, Version: "next", Features: []string{EvidenceFeature, SingleRequestFeature}}, now)
	if e != nil {
		t.Fatal(e)
	}
}
func TestMissingOfflineMemberNeverDisappears(t *testing.T) {
	s, p, m, now := fixture(t)
	for i := 0; i < 5; i++ {
		report(t, s, m, i, now)
	}
	s = NewStore(p)
	if e := s.Activate(context.Background(), 1, []string{EvidenceFeature}, now); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	v, _ := s.Read()
	if len(v.Manifest.Members) != 6 || v.Complete {
		t.Fatal("offline node vanished")
	}
	report(t, s, m, 5, now)
	if e := s.Activate(context.Background(), 1, []string{EvidenceFeature, SingleRequestFeature}, now); e != nil {
		t.Fatal(e)
	}
	v, _ = NewStore(p).Read()
	if !v.Complete {
		t.Fatal("CP restart forgot completion")
	}
}
func TestCeremonyRecoveryRequiresEveryCurrentMember(t *testing.T) {
	s, _, m, now := fixture(t)
	features := []string{EvidenceFeature, SingleRequestFeature, CeremonyRecoveryFeature}
	for i, n := range m.Members {
		advertised := features
		if i == len(m.Members)-1 {
			advertised = []string{EvidenceFeature, SingleRequestFeature}
		}
		if err := s.Record(context.Background(), n.CertificateSHA256, Report{
			Generation: m.Generation, NodeID: n.ID, Version: "next", Features: advertised,
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Activate(context.Background(), m.Generation, features, now); !errors.Is(err, ErrNotReady) {
		t.Fatalf("mixed fleet activated ceremony recovery: %v", err)
	}
	n := m.Members[len(m.Members)-1]
	if err := s.Record(context.Background(), n.CertificateSHA256, Report{
		Generation: m.Generation, NodeID: n.ID, Version: "next", Features: features,
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(context.Background(), m.Generation, features, now); err != nil {
		t.Fatal(err)
	}
	d, err := s.Distribute(now)
	if err != nil || !d.FeatureEnabled(CeremonyRecoveryFeature, now) {
		t.Fatal("fully upgraded fleet could not activate ceremony recovery")
	}
}
func TestCrossScopeIdentityEvidenceCannotBeActivated(t *testing.T) {
	s, _, m, now := fixture(t)
	features := []string{EvidenceFeature, DeviceUserFeature, "cross-scope-identity-evidence-v1"}
	for _, n := range m.Members {
		if err := s.Record(context.Background(), n.CertificateSHA256, Report{
			Generation: m.Generation, NodeID: n.ID, Version: "next", Features: features,
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Activate(context.Background(), m.Generation, features, now); err == nil {
		t.Fatal("removed cross-scope evidence was activated")
	}
}
func TestStaleWrongIdentityAndOldGenerationCannotComplete(t *testing.T) {
	s, _, m, now := fixture(t)
	for i := range m.Members {
		report(t, s, m, i, now)
	}
	if e := s.Activate(context.Background(), 1, []string{EvidenceFeature}, now.Add(FreshFor)); !errors.Is(e, ErrNotReady) {
		t.Fatal(e)
	}
	r := Report{Generation: 1, NodeID: "5", Version: "next", Features: []string{EvidenceFeature}}
	if s.Record(context.Background(), m.Members[0].CertificateSHA256, r, now) == nil {
		t.Fatal("forged member accepted")
	}
	r.Generation = 2
	if s.Record(context.Background(), m.Members[5].CertificateSHA256, r, now) == nil {
		t.Fatal("wrong generation accepted")
	}
}
func TestExplicitRetirementAndGenerationCAS(t *testing.T) {
	s, _, m, now := fixture(t)
	next := m
	next.Generation = 2
	next.Members = append([]Member(nil), m.Members[:5]...)
	if s.Configure(context.Background(), 1, next) == nil {
		t.Fatal("implicit removal accepted")
	}
	next.Members = append([]Member(nil), m.Members...)
	next.Members[5].Retired = true
	next.Members[5].RetirementReason = "machine decommissioned"
	if e := s.Configure(context.Background(), 1, next); e != nil {
		t.Fatal(e)
	}
	if s.Configure(context.Background(), 1, next) == nil {
		t.Fatal("stale operator overwrote census")
	}
	for i := 0; i < 5; i++ {
		report(t, s, next, i, now)
	}
	if e := s.Activate(context.Background(), 2, []string{EvidenceFeature}, now); e != nil {
		t.Fatal(e)
	}
}
func TestFailedCommitDoesNotActivate(t *testing.T) {
	s, p, m, now := fixture(t)
	for i := range m.Members {
		report(t, s, m, i, now)
	}
	p.fail = true
	if s.Activate(context.Background(), 1, []string{EvidenceFeature}, now) == nil {
		t.Fatal("commit failure hidden")
	}
	v, _ := s.Read()
	if v.Complete {
		t.Fatal("uncommitted activation published")
	}
}
func TestCompletionNeverDowngrades(t *testing.T) {
	s, _, m, now := fixture(t)
	for i := range m.Members {
		report(t, s, m, i, now)
	}
	if e := s.Activate(context.Background(), 1, []string{EvidenceFeature}, now); e != nil {
		t.Fatal(e)
	}
	if s.Record(context.Background(), m.Members[0].CertificateSHA256, Report{Generation: 1, NodeID: "0", Version: "0.3.1"}, now) == nil {
		t.Fatal("old binary accepted after activation")
	}
	m.Generation = 2
	if e := s.Configure(context.Background(), 1, m); e != nil {
		t.Fatal(e)
	}
	v, _ := s.Read()
	if !v.Complete {
		t.Fatal("membership edit reopened legacy acceptance")
	}
}
func TestDistributionMonotonicDurableAndBounded(t *testing.T) {
	s, _, m, now := fixture(t)
	cacheDB := &memory{}
	cache := NewCache(NewStore(cacheDB))
	mixed, e := s.Distribute(now)
	if e != nil {
		t.Fatal(e)
	}
	if e = cache.Adopt(context.Background(), *mixed, now); e != nil {
		t.Fatal(e)
	}
	d, _ := cache.Read()
	digest := m.Providers[ProviderKey("tenant", "corp")]
	if !d.AcceptLegacy("tenant", "corp", digest, now) || d.AcceptLegacy("other", "corp", digest, now) || d.AcceptLegacy("tenant", "corp", "changed", now) || d.AcceptLegacy("tenant", "corp", digest, now.Add(FreshFor)) {
		t.Fatal("legacy acceptance boundary")
	}
	for i := range m.Members {
		report(t, s, m, i, now)
	}
	if e = s.Activate(context.Background(), 1, []string{EvidenceFeature, SingleRequestFeature}, now); e != nil {
		t.Fatal(e)
	}
	done, _ := s.Distribute(now.Add(time.Second))
	if e = cache.Adopt(context.Background(), *done, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	cache = NewCache(NewStore(cacheDB))
	if e = cache.Adopt(context.Background(), *mixed, now.Add(time.Second)); e == nil {
		t.Fatal("stale bundle reopened acceptance")
	}
	d, _ = cache.Read()
	if d.AcceptLegacy("tenant", "corp", digest, now.Add(time.Second)) || !d.FeatureEnabled(SingleRequestFeature, now.Add(time.Second)) {
		t.Fatal("completion not enforced")
	}
	bad := *done
	bad.State.Complete = false
	bad.State.Enabled = nil
	bad.State.Revision++
	if cache.Adopt(context.Background(), bad, now.Add(time.Second)) == nil {
		t.Fatal("newer revision downgraded")
	}
}
func TestConcurrentCPReportersAndActivation(t *testing.T) {
	s, p, m, now := fixture(t)
	var wg sync.WaitGroup
	for i := range m.Members {
		wg.Add(1)
		go func(i int) { defer wg.Done(); report(t, NewStore(p), m, i, now) }(i)
	}
	wg.Wait()
	v, e := s.Read()
	if e != nil || len(v.Observed) != 6 {
		t.Fatalf("lost report: %v", e)
	}
	if e = s.Activate(context.Background(), 1, []string{EvidenceFeature}, now); e != nil {
		t.Fatal(e)
	}
}
func TestCorruptSnapshotIsNotAnEmptyFleet(t *testing.T) {
	_, p, _, _ := fixture(t)
	p.b = []byte(`{"schema":999}`)
	if _, e := NewStore(p).Read(); e == nil {
		t.Fatal("unknown schema accepted")
	}
	var v State
	_ = json.Unmarshal(p.b, &v)
}

func TestUnknownInstalledVersionDoesNotAuthorizeLegacy(t *testing.T) {
	s, _, m, now := fixture(t)
	m.Generation = 2
	m.Members[5].Version = "awaiting-first-report"
	if e := s.Configure(context.Background(), 1, m); e != nil {
		t.Fatal(e)
	}
	d, e := s.Distribute(now)
	if e != nil {
		t.Fatal(e)
	}
	if d.AcceptLegacy("tenant", "corp", m.Providers[ProviderKey("tenant", "corp")], now) {
		t.Fatal("unknown member version treated as confirmed mixed fleet")
	}
}
