package tenantca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// memPersister is the shared store two Edges write to.
type memPersister struct{ data []byte }

func (m *memPersister) Load() ([]byte, error)  { return m.data, nil }
func (m *memPersister) Save(data []byte) error { m.data = append([]byte(nil), data...); return nil }
func newRegistryForTest() *TenantCARegistry    { return NewTenantCARegistry() }
func shaOf(c *x509.Certificate) string         { s := sha256.Sum256(c.Raw); return hex.EncodeToString(s[:]) }

// ★★★ A DEVICE CA REGISTERED ON ONE EDGE MUST ADMIT THAT ORGANIZATION ON ALL OF THEM (2026-08-21).
//
// The registry was a file on the node that answered the registration — the control plane refuses to hold it
// (501) and the config bundle carries no CA — so a customer's registration reached exactly one Edge and every
// other node rejected that organization's devices at the handshake. The reference lab hid it because its
// Edges bind-mount one file.
func TestARegistrationOnOneEdgeReachesAnother(t *testing.T) {
	shared := &memPersister{}
	edgeA, edgeB := newRegistryForTest(), newRegistryForTest()
	cert, pemBytes := selfSignedCAForTest(t, "Acme Device CA")

	if _, err := edgeA.Register("tenant_acme", pemBytes); err != nil {
		t.Fatal(err)
	}
	if err := edgeA.SaveTo(shared); err != nil {
		t.Fatal(err)
	}
	added, err := edgeB.LoadFrom(shared)
	if err != nil || added != 1 {
		t.Fatalf("the other Edge adopted %d CA(s) (err=%v) — it would refuse this organization's devices", added, err)
	}
	if got := resolves(edgeB, cert); got != "tenant_acme" {
		t.Fatalf("the other Edge resolves this certificate to %q", got)
	}
}

// ★★★ AND A WITHDRAWAL MUST NOT BE RESURRECTED BY THE MERGE (2026-08-21, caught on the first live withdrawal).
//
// The merge is what makes two concurrent registrations safe, and it is exactly what undoes a removal: the
// shared view still holds the CA this node has just retired, so it is adopted back and written out again.
// Measured before this fix: a device CA withdrawn on region-a answered 200 and was still listed on BOTH Edges
// half a minute later. The guard here is the first half — without naming the removal, this test fails.
func TestAWithdrawalIsNotUndoneByTheSharedView(t *testing.T) {
	shared := &memPersister{}
	edgeA, edgeB := newRegistryForTest(), newRegistryForTest()
	cert, pemBytes := selfSignedCAForTest(t, "Acme Device CA")
	keep, keepPEM := selfSignedCAForTest(t, "Acme Second Device CA")

	for _, p := range [][]byte{pemBytes, keepPEM} {
		if _, err := edgeA.Register("tenant_acme", p); err != nil {
			t.Fatal(err)
		}
	}
	if err := edgeA.SaveTo(shared); err != nil {
		t.Fatal(err)
	}

	// The other Edge has the same view, so the shared store genuinely still names what is about to go.
	if added, err := edgeB.LoadFrom(shared); err != nil || added != 2 {
		t.Fatalf("setup: the other Edge adopted %d (err=%v)", added, err)
	}

	if removed, _ := edgeA.WithdrawAnchor("tenant_acme", shaOf(cert)); !removed {
		t.Fatal("the withdrawal did not happen at all")
	}
	if err := edgeA.SaveTo(shared, shaOf(cert)); err != nil {
		t.Fatal(err)
	}

	if got := resolves(edgeA, cert); got != "" {
		t.Fatalf("the withdrawn CA came back on the node that withdrew it (resolves to %q)", got)
	}
	fresh := newRegistryForTest()
	if _, err := fresh.LoadFrom(shared); err != nil {
		t.Fatal(err)
	}
	if got := resolves(fresh, cert); got != "" {
		t.Fatalf("the shared view still admits the withdrawn CA (resolves to %q) — every other Edge would too", got)
	}
	if got := resolves(fresh, keep); got != "tenant_acme" {
		t.Fatalf("the withdrawal took the wrong certificate with it: the remaining CA resolves to %q", got)
	}
	_ = time.Now
}

// resolves answers the question a handshake asks: which organization does a certificate issued by this CA
// belong to. Expressed through the same call the (T) admission path uses, so the test cannot pass on a
// property admission does not read.
func resolves(r *TenantCARegistry, ca *x509.Certificate) string {
	tenant, _ := r.TenantForVerifiedChains([][]*x509.Certificate{{ca}})
	return tenant
}

// ★★★ AND THE OTHER EDGES HAVE TO STOP ADMITTING IT (2026-08-21, measured). Adopting was add-only, so a
// device CA retired on one Edge kept admitting that organization's devices on every other node until a
// restart: region-a listed one CA for the organization and region-b listed two, minutes after the withdrawal.
// A customer retiring a compromised issuing CA needs it to stop everywhere.
func TestAWithdrawalReachesTheOtherEdges(t *testing.T) {
	shared := &memPersister{}
	edgeA, edgeB := newRegistryForTest(), newRegistryForTest()
	retired, retiredPEM := selfSignedCAForTest(t, "Acme Retired Device CA")
	keep, keepPEM := selfSignedCAForTest(t, "Acme Current Device CA")

	for _, p := range [][]byte{retiredPEM, keepPEM} {
		if _, err := edgeA.Register("tenant_acme", p); err != nil {
			t.Fatal(err)
		}
	}
	if err := edgeA.SaveTo(shared); err != nil {
		t.Fatal(err)
	}
	if _, err := edgeB.LoadFrom(shared); err != nil {
		t.Fatal(err)
	}
	if resolves(edgeB, retired) != "tenant_acme" {
		t.Fatal("setup: the other Edge never admitted the CA that is about to be retired")
	}

	if ok, _ := edgeA.WithdrawAnchor("tenant_acme", shaOf(retired)); !ok {
		t.Fatal("the withdrawal did not happen")
	}
	if err := edgeA.SaveTo(shared, shaOf(retired)); err != nil {
		t.Fatal(err)
	}

	added, removed, err := edgeB.ReconcileFrom(shared)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 || added != 0 {
		t.Fatalf("the other Edge reconciled added=%d removed=%d, so the retirement did not travel", added, removed)
	}
	if got := resolves(edgeB, retired); got != "" {
		t.Fatalf("the other Edge still admits the retired CA (resolves to %q)", got)
	}
	if got := resolves(edgeB, keep); got != "tenant_acme" {
		t.Fatalf("reconciling took the wrong certificate with it: the current CA resolves to %q", got)
	}
}

// An unreadable or empty shared view is not an instruction to forget everything: a node that cannot read the
// fleet keeps admitting exactly who it was admitting.
func TestAnEmptySharedViewDoesNotDisarmTheRegistry(t *testing.T) {
	reg := newRegistryForTest()
	ca, caPEM := selfSignedCAForTest(t, "Acme Device CA")
	if _, err := reg.Register("tenant_acme", caPEM); err != nil {
		t.Fatal(err)
	}
	for _, blob := range [][]byte{nil, []byte(""), []byte("{"), []byte(`{"tenants":[]}`)} {
		if _, removed, _ := reg.Reconcile(blob); removed != 0 {
			t.Fatalf("an unusable shared view removed %d CA(s)", removed)
		}
	}
	if resolves(reg, ca) != "tenant_acme" {
		t.Fatal("the registry disarmed itself on a view it could not use")
	}
}

// A readable stale cache must never replace an authoritative row that cannot be read.
type readFailurePersister struct {
	memPersister
	fail   bool
	writes int
}

func (p *readFailurePersister) Load() ([]byte, error) {
	if p.fail {
		return nil, errors.New("read unavailable")
	}
	return p.memPersister.Load()
}
func (p *readFailurePersister) Save(b []byte) error { p.writes++; return p.memPersister.Save(b) }
func TestRegistrySaveDoesNotOverwriteUnreadableSharedState(t *testing.T) {
	p := &readFailurePersister{}
	peer, local := NewTenantCARegistry(), NewTenantCARegistry()
	other, otherPEM := selfSignedCAForTest(t, "Peer CA")
	own, ownPEM := selfSignedCAForTest(t, "Own CA")
	if _, err := peer.Register("peer", otherPEM); err != nil {
		t.Fatal(err)
	}
	if err := peer.SaveTo(p); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), p.data...)
	writes := p.writes
	if _, err := local.Register("own", ownPEM); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	if err := local.SaveTo(p); err == nil {
		t.Fatal("unreadable shared row overwritten from local cache")
	}
	if p.writes != writes || !bytes.Equal(before, p.data) {
		t.Fatal("read failure changed shared state")
	}
	p.fail = false
	if err := local.SaveTo(p); err != nil {
		t.Fatal(err)
	}
	restarted := NewTenantCARegistry()
	if _, err := restarted.LoadFrom(p); err != nil {
		t.Fatal(err)
	}
	if resolves(restarted, other) != "peer" || resolves(restarted, own) != "own" {
		t.Fatal("retry lost peer or own CA")
	}
}
