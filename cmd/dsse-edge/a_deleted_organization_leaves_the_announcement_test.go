package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ★★★ THE PROMISE OUTLIVED THE ORGANIZATION, AND THE NEXT RESTART KILLED THE FLEET (2026-09-07, measured by
// deleting an organization and watching the announcement for five minutes, after twenty Edges in three regions
// were found dead in a crash loop).
//
//	REFUSING TO JOIN THIS FLEET: this node cannot keep 18 promise(s) the fleet has already made to devices:
//	tenant_… was promised the name ….wakaba.lab and this node has no certificate for it
//
// All eighteen were organizations that had been deleted hours earlier. The guard is right — a node that cannot
// keep the fleet's promises must not admit devices — so the damage is that deleting an organization ARMS it:
// the deployment runs on, healthy, until some unrelated restart, and then every node in every region refuses
// to start at the same moment, for a cause nobody will connect to a deletion made hours before.
//
// Retirement was implemented and correct in shape — leave the announcement, keep serving, drop only once the
// announcement has moved — but phase one was applied in ONE of the three places the announcement is built. The
// recovery alias left; the anchor and the name stayed. And phase two waits for the announcement to stop naming
// the organization, so it never ran, so the certificate was never dropped, so the two remaining tokens were
// recomputed for ever. Measured, at one-minute recomputes:
//
//	t+135s  recovery-name-for-tenant_j6zi…   GONE
//	t+270s  tenant_j6zi…=154358ed…           still there
//	t+270s  tenant_j6zi…@j6zi….wakaba.lab    still there   ← the token the guard reads

// leafForTest is a certificate with a parsed Leaf carrying the name, because ServerNameFor reads
// Leaf.DNSNames — a fixture without one silently produces no recovery-name token and the assertion about it
// passes for the wrong reason.
func leafForTest(t *testing.T, dnsName string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, Leaf: leaf}
}

func anchorPEMForTest(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// announcementFor is the same three sources the recompute in steer_agent_policy_routes.go concatenates, in the
// same order, so this asserts what the fleet is actually told rather than what one helper returns.
func announcementFor(t *transportTenantCerts) string {
	announced := append([]string{}, t.AnchorFingerprints()...)
	announced = append(announced, t.ServerNameAnnouncements()...)
	for tenant := range t.anchorsByTenant() {
		if t.IsRetiring(tenant) {
			continue
		}
		if name, ok := t.ServerNameFor(tenant); ok {
			announced = append(announced, "recovery-name-for-"+tenant+"=recovery."+name)
		}
	}
	return strings.Join(announced, ",")
}

func TestADeletedOrganizationLeavesTheWholeAnnouncement(t *testing.T) {
	const tenant = "tenant_going_away"
	const name = "goingaway.dsse.invalid"

	restore := transportTenantCertificates
	transportTenantCertificates = newTransportTenantCerts()
	t.Cleanup(func() { transportTenantCertificates = restore })
	certs := transportTenantCertificates
	certs.put(tenant, []string{name}, leafForTest(t, name), anchorPEMForTest(t, name+" Transport CA"))

	if a := announcementFor(certs); !strings.Contains(a, tenant+"@"+name) {
		t.Fatalf("the control failed: the name is not announced to begin with: %q", a)
	}

	// Phase one, exactly as the material fetch runs it when the control plane no longer knows the organization.
	if !certs.BeginRetiring(tenant) {
		t.Fatal("a served organization could not be marked for retirement")
	}

	announced := announcementFor(certs)
	// ★ THE NAME IS THE ONE THE FLEET-PROMISE GUARD READS. Every other assertion here can pass while this one
	// fails and the deployment still dies on its next restart.
	if strings.Contains(announced, tenant+"@") {
		t.Fatalf("a retiring organization is still PROMISED a name — the next node to start will refuse to "+
			"join the fleet over it: %q", announced)
	}
	if strings.Contains(announced, tenant+"=") {
		t.Fatalf("a retiring organization's anchor is still announced, so phase two can never run and the "+
			"promise above can never be withdrawn: %q", announced)
	}
	if strings.Contains(announced, "recovery-name-for-"+tenant) {
		t.Fatalf("a retiring organization's recovery alias is still announced: %q", announced)
	}

	// ★ AND IT IS STILL SERVED. A promise is kept until it has been withdrawn with a serial; dropping first is
	// the order that took this deployment down in August.
	if _, _, ok := certs.For(name); !ok {
		t.Fatal("the name stopped being served the moment it was marked — phase two must wait for the " +
			"announcement to move, and a device that has not fetched yet still dials this name")
	}

	// Phase two: the announcement no longer names it, so the certificate may go. This is the step that could
	// never be reached while the tokens above survived.
	if strings.Contains(announcementFor(certs), tenant) {
		t.Fatal("the announcement still names the organization, so phase two is still blocked")
	}
	if dropped := certs.StopServing(tenant); dropped != 1 {
		t.Fatalf("stopping served %d name(s), want 1", dropped)
	}
	if _, _, ok := certs.For(name); ok {
		t.Fatal("the name is still served after the retirement finished")
	}
}

// An organization that is NOT retiring keeps every token. The fix must withdraw a promise, not stop making
// them — a node that announces nothing fails the same guard from the other direction.
func TestAServedOrganizationKeepsItsWholeAnnouncement(t *testing.T) {
	const tenant = "tenant_staying"
	const name = "staying.dsse.invalid"

	restore := transportTenantCertificates
	transportTenantCertificates = newTransportTenantCerts()
	t.Cleanup(func() { transportTenantCertificates = restore })
	certs := transportTenantCertificates
	certs.put(tenant, []string{name}, leafForTest(t, name), anchorPEMForTest(t, name+" Transport CA"))

	announced := announcementFor(certs)
	for _, want := range []string{tenant + "@" + name, tenant + "=", "recovery-name-for-" + tenant} {
		if !strings.Contains(announced, want) {
			t.Fatalf("a served organization lost %q from the announcement: %q", want, announced)
		}
	}
}
