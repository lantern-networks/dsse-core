package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// Both agent-facing TLS doors must reject a certificate under tenant B when the global enrolled
// identity has an existing tenant A owner. A certificate CN is not a tenant identity.
func TestKnownDeviceOwnerMustMatchCertificateTenantAtBothAgentDoors(t *testing.T) {
	dir := t.TempDir()
	caA := makeTestCA(t, dir, "tenant-A-CA", 51)
	caB := makeTestCA(t, dir, "tenant-B-CA", 52)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir,
		map[string]string{"tenant-a": caA.pemPath, "tenant-b": caB.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("same-device", "tenant-a", "test", "2026-10-23T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	toState := func(ca testCA, id string) tls.ConnectionState {
		t.Helper()
		chains := leafSignedBy(t, ca, id, reg.Pool)
		if len(chains) == 0 || len(chains[0]) == 0 {
			t.Fatalf("no verified chain for %s", id)
		}
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
	}
	own := toState(caA, "same-device")
	foreign := toState(caB, "same-device")
	unknown := toState(caB, "fresh-device")

	t.Run("secure transport", func(t *testing.T) {
		cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{ListenAddr: "127.0.0.1:0",
			LabAutoCert: true, LabMode: true, TenantCARegistry: reg,
			RequireEnrolledIdentity: true, EnrolledLedger: ledger})
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
			t.Fatal("strict enrolment gate admitted anonymous connection")
		}
		if err := cfg.VerifyConnection(own); err != nil {
			t.Fatalf("owner denied: %v", err)
		}
		if err := cfg.VerifyConnection(foreign); err == nil {
			t.Fatal("foreign tenant with same CN admitted")
		}
		if err := cfg.VerifyConnection(unknown); err == nil {
			t.Fatal("unenrolled identity admitted")
		}
	})
	t.Run("secure transport without strict enrollment gate", func(t *testing.T) {
		cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{ListenAddr: "127.0.0.1:0",
			LabAutoCert: true, LabMode: true, TenantCARegistry: reg, EnrolledLedger: ledger})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.VerifyConnection == nil {
			t.Fatal("known-owner tenant check not installed")
		}
		if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Fatalf("optional client certificate contract changed: %v", cfg.ClientAuth)
		}
		if err := cfg.VerifyConnection(tls.ConnectionState{}); err != nil {
			t.Fatalf("anonymous lab bootstrap denied by owner-only check: %v", err)
		}
		if err := cfg.VerifyConnection(own); err != nil {
			t.Fatalf("owner denied: %v", err)
		}
		if err := cfg.VerifyConnection(foreign); err == nil {
			t.Fatal("foreign tenant with same CN admitted without strict enrollment gate")
		}
	})

	t.Run("main agent door", func(t *testing.T) {
		oldDoor, oldRefused := agentDoorAdmission, agentIdentityRefused
		t.Cleanup(func() { agentDoorAdmission, agentIdentityRefused = oldDoor, oldRefused })
		rev := revocation.NewAdmissionRevocations()
		setAgentDoorAdmission(reg, ledger, rev)
		if err := agentDoorAdmission(own); err != nil {
			t.Fatalf("owner denied: %v", err)
		}
		if err := agentDoorAdmission(foreign); err == nil {
			t.Fatal("foreign tenant with same CN admitted")
		}
		// Freshly enrolled devices can reach another Edge before inventory replication catches up.
		if err := agentDoorAdmission(unknown); err != nil {
			t.Fatalf("unknown bootstrap device denied: %v", err)
		}
		if err := agentDoorAdmission(tls.ConnectionState{}); err != nil {
			t.Fatalf("anonymous enrolment denied: %v", err)
		}
		rev.Revoke("fresh-device", "test")
		if err := agentDoorAdmission(unknown); err == nil {
			t.Fatal("revoked device admitted")
		}
	})
}
