package grantstore

import (
	"context"
	"encoding/json"
	"errors"
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type rollingMemory struct {
	mu               sync.Mutex
	legacy, evidence []byte
	fail             bool
}

func (m *rollingMemory) LoadGrantPair(context.Context) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.legacy...), append([]byte(nil), m.evidence...), nil
}
func (m *rollingMemory) UpdateGrantPair(ctx context.Context, f func([]byte, []byte) ([]byte, []byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	a, b, e := f(m.legacy, m.evidence)
	if e != nil {
		return e
	}
	if m.fail {
		return errors.New("commit refused")
	}
	m.legacy = a
	m.evidence = b
	return nil
}

type legacyMemory struct{ pair *rollingMemory }

func (p legacyMemory) Load() ([]byte, error) {
	a, _, e := p.pair.LoadGrantPair(context.Background())
	return a, e
}
func (p legacyMemory) Save(raw []byte) error {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	p.pair.legacy = append([]byte(nil), raw...)
	return nil
}
func (p legacyMemory) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	return p.pair.UpdateGrantPair(ctx, func(a, b []byte) ([]byte, []byte, error) { a, e := f(a); return a, b, e })
}
func rollingStores(t *testing.T) (*Store, *old.Store, *rollingMemory) {
	t.Helper()
	m := &rollingMemory{}
	n := NewStore()
	o := old.NewStore()
	if e := n.SetPersister(RollingPersister{m}); e != nil {
		t.Fatal(e)
	}
	if e := o.SetPersister(legacyMemory{m}); e != nil {
		t.Fatal(e)
	}
	return n, o, m
}
func rollingGrant(id string, now time.Time) Grant {
	return Grant{GrantID: id, TenantID: "tenant", UserID: "sub", DeviceID: "device", IdPID: "idp", Issuer: "https://idp.example", ProviderConfigSHA256: strings.Repeat("a", 64), AuthTime: now.Format(time.RFC3339), Scope: "host:22"}
}

func TestRollingReleasedStoreAlternatesWritesAndRevocations(t *testing.T) {
	n, o, m := rollingStores(t)
	now := time.Now().UTC().Truncate(time.Second)
	g, e := n.Mint(rollingGrant("new", now), time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	if !o.Valid(g.GrantID, now) || !old.GateAccepts(o, "tenant", "device", "") {
		t.Fatal("released store cannot read ordinary new grant")
	}
	if _, e = o.Mint(old.Grant{GrantID: "old", TenantID: "tenant", UserID: "sub", DeviceID: "device", IdPID: "idp"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	got, ok := n.Get(g.GrantID)
	if !ok || got.Issuer != g.Issuer || got.ProviderConfigSHA256 != g.ProviderConfigSHA256 || got.AuthTime != g.AuthTime || !n.Valid(g.GrantID, now) {
		t.Fatal("legacy rewrite erased evidence")
	}
	if _, ok = n.Get("old"); !ok {
		t.Fatal("new reader lost old grant")
	}
	if _, _, e = o.RevokeForTenant("tenant", "new"); e != nil {
		t.Fatal(e)
	}
	if n.Valid("new", now) {
		t.Fatal("legacy revocation not seen")
	}
	if _, _, e = n.RevokeForTenant("tenant", "old"); e != nil {
		t.Fatal(e)
	}
	if o.Valid("old", now) {
		t.Fatal("modern revocation not seen by released store")
	}
	var raw map[string]old.Grant
	if e = json.Unmarshal(m.legacy, &raw); e != nil {
		t.Fatal(e)
	}
	if len(raw) != 2 || !raw["new"].Revoked || !raw["old"].Revoked {
		t.Fatal("legacy map changed shape")
	}
	// A released writer overwrites all rows yet sidecar revocation remains monotonic.
	if _, e = o.Mint(old.Grant{GrantID: "third", TenantID: "tenant"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if n.Valid("new", now) || n.Valid("old", now) {
		t.Fatal("revocation resurrected")
	}
}
func TestRollingSingleRequestInvisibleToReleasedStore(t *testing.T) {
	n, o, m := rollingStores(t)
	now := time.Now().UTC().Truncate(time.Second)
	g := rollingGrant("single", now)
	g.AuthenticationRequestID = "req"
	g.ReauthenticationStartedAt = now.Format(time.RFC3339)
	g, e := n.Mint(g, time.Minute, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := o.Get(g.GrantID); ok || old.GateAccepts(o, "tenant", "device", "") {
		t.Fatal("old reader sees single request grant")
	}
	if _, e = o.Mint(old.Grant{GrantID: "peer", TenantID: "tenant"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	yes, e := n.ConsumeAuthenticationRequest(context.Background(), g, now)
	if e != nil || !yes {
		t.Fatalf("consume %v %v", yes, e)
	}
	restarted := NewStore()
	if e = restarted.SetPersister(RollingPersister{m}); e != nil {
		t.Fatal(e)
	}
	if yes, e = restarted.ConsumeAuthenticationRequest(context.Background(), g, now); e != nil || yes {
		t.Fatal("consumption did not survive restart")
	}
	if _, ok := o.Get(g.GrantID); ok {
		t.Fatal("consumption leaked into legacy key")
	}
}
func TestRollingFailedCommitPreservesBothKeys(t *testing.T) {
	n, o, m := rollingStores(t)
	now := time.Now().UTC()
	g, e := n.Mint(rollingGrant("g", now), time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	a, b, _ := m.LoadGrantPair(context.Background())
	m.fail = true
	if _, _, e = n.RevokeForTenant("tenant", g.GrantID); e == nil {
		t.Fatal("failure hidden")
	}
	x, y, _ := m.LoadGrantPair(context.Background())
	if string(a) != string(x) || string(b) != string(y) {
		t.Fatal("partial commit")
	}
	if n.Valid(g.GrantID, now) {
		t.Fatal("local denial lost")
	}
	if !o.Valid(g.GrantID, now) {
		t.Fatal("claimed uncommitted revocation")
	}
	m.fail = false
	if _, _, e = n.RevokeForTenant("tenant", g.GrantID); e != nil {
		t.Fatal(e)
	}
	if o.Valid(g.GrantID, now) {
		t.Fatal("retry failed")
	}
}
func TestRollingUnknownFeatureIsRowLocalAndPreserved(t *testing.T) {
	n, o, m := rollingStores(t)
	now := time.Now().UTC()
	g := rollingGrant("future", now)
	g.RequiredFeatures = []string{"future-feature-v99"}
	g.UnknownFields = map[string]json.RawMessage{"future_proof": json.RawMessage(`{"x":[1,2,3]}`)}
	if _, e := n.Mint(g, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if _, e := n.Mint(rollingGrant("ordinary", now), time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if n.Valid("future", now) || o.Valid("future", now) {
		t.Fatal("unknown feature authorized")
	}
	if !n.Valid("ordinary", now) || !o.Valid("ordinary", now) {
		t.Fatal("unknown row disabled document")
	}
	if _, e := o.Mint(old.Grant{GrantID: "old", TenantID: "tenant"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e := n.RevokeForTenant("tenant", "ordinary"); e != nil {
		t.Fatal(e)
	}
	re := NewStore()
	if e := re.SetPersister(RollingPersister{m}); e != nil {
		t.Fatal(e)
	}
	got, ok := re.Get("future")
	if !ok || string(got.UnknownFields["future_proof"]) != `{"x":[1,2,3]}` {
		t.Fatal("unknown data lost")
	}
}

func TestRollingLegacyReportCannotEraseEvidenceOrUndoRevocation(t *testing.T) {
	s, _, _ := rollingStores(t)
	now := time.Now().UTC().Truncate(time.Second)
	g, e := s.Mint(rollingGrant("g", now), time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := legacyProjection(g)
	if e != nil {
		t.Fatal(e)
	}
	var stripped Grant
	if e = json.Unmarshal(raw, &stripped); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.MergeChecked([]Grant{stripped}, now); e != nil {
		t.Fatal(e)
	}
	full, _ := s.Get("g")
	if full.Issuer != g.Issuer || full.ProviderConfigSHA256 != g.ProviderConfigSHA256 {
		t.Fatal("legacy report erased proof")
	}
	stripped.Revoked = true
	if _, _, e = s.MergeChecked([]Grant{stripped}, now); e != nil {
		t.Fatal(e)
	}
	stripped.Revoked = false
	if _, _, e = s.MergeChecked([]Grant{stripped}, now); e != nil {
		t.Fatal(e)
	}
	if s.Valid("g", now) {
		t.Fatal("stale report revived grant")
	}
}

func TestLegacyProjectionMatchesReleasedJSONFields(t *testing.T) {
	fields := map[string]bool{}
	typ := reflect.TypeOf(old.Grant{})
	for i := 0; i < typ.NumField(); i++ {
		fields[strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	if !reflect.DeepEqual(fields, legacyFields) {
		t.Fatalf("legacy projection differs from released JSON tags: want %v got %v", fields, legacyFields)
	}
}
func TestReleasedForwardedAuthTimeGrantRemainsValid(t *testing.T) {
	s, _, _ := rollingStores(t)
	now := time.Now().UTC().Truncate(time.Second)
	g, err := s.Mint(rollingGrant("with-auth-time", now), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(g)
	var released old.Grant
	if err = json.Unmarshal(raw, &released); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(released)
	var forwarded Grant
	if err = json.Unmarshal(raw, &forwarded); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.MergeChecked([]Grant{forwarded}, now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(g.GrantID)
	if !s.Valid(g.GrantID, now) || got.AuthTime != g.AuthTime {
		t.Fatal("released forwarding invalidated evidence")
	}
}
