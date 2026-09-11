package internalca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func caPEM(t *testing.T, cn string, notAfter time.Time, isCA bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notAfter.Add(-2 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAnAuthorityBelongsToOneOrganizationAndNoOther(t *testing.T) {
	now := time.Now().UTC()
	store, err := NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert(Authority{ID: "a", TenantID: "kaede", Name: "Kaede internal", CertificatePEM: caPEM(t, "Kaede Internal CA", now.Add(24*time.Hour), true)}, now); err != nil {
		t.Fatal(err)
	}
	if got := store.AnchorsPEM("kaede", now); len(got) != 1 {
		t.Fatalf("the organization that authored it must get it back, got %d", len(got))
	}
	// ★ The whole point of the object: another organization's flow must not gain this trust.
	if got := store.AnchorsPEM("northwind", now); len(got) != 0 {
		t.Fatalf("another organization must see nothing, got %d", len(got))
	}
}

func TestAServerCertificateIsRefusedWithTheReasonAReaderCanAct(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(nil)
	_, err := store.Upsert(Authority{ID: "a", TenantID: "kaede", CertificatePEM: caPEM(t, "hq.kaede.internal", now.Add(24*time.Hour), false)}, now)
	if err == nil {
		t.Fatal("a server's own certificate is not an authority and must be refused")
	}
	if !strings.Contains(err.Error(), "not a certificate authority") {
		t.Fatalf("the message must say WHICH mistake was made, got %q", err)
	}
}

func TestAnExpiredAuthorityIsNotQuietlyUsed(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(nil)
	live := caPEM(t, "Kaede Internal CA", now.Add(24*time.Hour), true)
	if _, err := store.Upsert(Authority{ID: "live", TenantID: "kaede", CertificatePEM: live}, now); err != nil {
		t.Fatal(err)
	}
	// Pasted while valid, read a year later.
	later := now.Add(48 * time.Hour)
	if got := store.AnchorsPEM("kaede", later); len(got) != 0 {
		t.Fatalf("an authority that has expired since it was pasted must not be used, got %d", len(got))
	}
	shown := store.List("kaede", later)
	if len(shown) != 1 || !shown[0].Expired {
		t.Fatalf("but it must still be SHOWN, marked expired, or nobody can fix it: %+v", shown)
	}
}

func TestTheRevisionMovesSoACacheDownstreamLearns(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(nil)
	before := store.Revision("kaede")
	if _, err := store.Upsert(Authority{ID: "a", TenantID: "kaede", CertificatePEM: caPEM(t, "Kaede Internal CA", now.Add(24*time.Hour), true)}, now); err != nil {
		t.Fatal(err)
	}
	if store.Revision("kaede") == before {
		t.Fatal("a data path caching a built pool would never see the new authority")
	}
	afterAdd := store.Revision("kaede")
	store.Delete("a", "kaede", now)
	if store.Revision("kaede") == afterAdd {
		t.Fatal("a deleted authority would keep being trusted until restart")
	}
}

func TestTheControlPlanesWholeAnswerEmptiesAnOrganizationItNoLongerLists(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(nil)
	pemA := caPEM(t, "Kaede Internal CA", now.Add(24*time.Hour), true)
	if _, err := store.Upsert(Authority{ID: "a", TenantID: "kaede", CertificatePEM: pemA}, now); err != nil {
		t.Fatal(err)
	}
	// The control plane now lists a different organization only. Kaede's must go.
	store.ReplaceAll([]Authority{{ID: "b", TenantID: "northwind", CertificatePEM: pemA}})
	if got := store.AnchorsPEM("kaede", now); len(got) != 0 {
		t.Fatalf("an organization the control plane no longer lists must stop being trusted, got %d", len(got))
	}
	if got := store.AnchorsPEM("northwind", now); len(got) != 1 {
		t.Fatalf("and the one it does list must be trusted, got %d", len(got))
	}
}

func TestAStoreWithNoDurableHomeRefusesWritesInsteadOfLosingThem(t *testing.T) {
	store := NewUnavailableStore(`relation "internal_certificate_authorities" does not exist`)
	now := time.Now().UTC()
	_, err := store.Upsert(Authority{ID: "a", TenantID: "kaede", CertificatePEM: caPEM(t, "Kaede Internal CA", now.Add(24*time.Hour), true)}, now)
	if err == nil {
		t.Fatal("a write that cannot be kept must be refused, not accepted and lost")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("the refusal must carry the reason so the reader knows to run the migrations, got %q", err)
	}
	// And it must still be READABLE — a node in this state serves flows, it simply vouches for nothing.
	if got := store.AnchorsPEM("kaede", now); len(got) != 0 {
		t.Fatalf("nothing is vouched for, got %d", len(got))
	}
}

func TestAChangeMovesTheVersionOrNoEdgeEverPulls(t *testing.T) {
	now := time.Now().UTC()
	store, _ := NewStore(nil)
	before := store.ConfigGeneration()
	pem := caPEM(t, "Kaede Internal CA", now.Add(24*time.Hour), true)
	if _, err := store.Upsert(Authority{ID: "a", TenantID: "kaede", CertificatePEM: pem}, now); err != nil {
		t.Fatal(err)
	}
	afterAdd := store.ConfigGeneration()
	if afterAdd <= before {
		t.Fatal("an added authority must move the bundle's version")
	}
	// ★ THE DELETE IS THE ONE THAT WAS MEASURED FAILING. An add happened to work because a roll restarted the
	// fleet; the delete had nothing to make anyone re-pull.
	store.Delete("a", "kaede", now)
	if store.ConfigGeneration() <= afterAdd {
		t.Fatal("a deleted authority must move the bundle's version, or every Edge goes on trusting it")
	}
	// And another organization's change moves it too — the sum is over organizations.
	beforeOther := store.ConfigGeneration()
	store.Upsert(Authority{ID: "b", TenantID: "northwind", CertificatePEM: pem}, now)
	if store.ConfigGeneration() <= beforeOther {
		t.Fatal("any organization's change must move the version")
	}
}
