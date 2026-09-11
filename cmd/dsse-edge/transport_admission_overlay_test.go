package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/revocation"
)

// The live (T) VerifyConnection admission closure must consult the revocation overlay: a revoked identity is
// rejected at the handshake even though it is still enrolled, regardless of the revocation reason (admin
// kill-switch, mesh/federation, re-attestation). Un-revoking (Restore) re-admits it.
func TestTransportAdmission_RevocationOverlayWiredIntoHandshake(t *testing.T) {
	rev := revocation.NewAdmissionRevocations()
	cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{
		ListenAddr:              "127.0.0.1:0",
		LabAutoCert:             true,
		LabMode:                 true,
		RequireEnrolledIdentity: true,
		EnrolledIdentities:      map[string]struct{}{"mac-dev-1": {}, "conn-lab-1": {}},
		AdmissionRevocations:    rev,
	})
	if err != nil {
		t.Fatalf("build tls cfg: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("expected admission VerifyConnection to be set")
	}

	// Baseline: both enrolled identities are admitted.
	if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err != nil {
		t.Fatalf("enrolled identity must be admitted before revocation: %v", err)
	}
	// A HARD revocation (admin kill-switch) must reject the identity even though it is still enrolled — the SAME
	// closure sees it (it holds the overlay by ref).
	rev.Revoke("mac-dev-1", "admin_kill_switch")
	if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err == nil {
		t.Fatal("hard-revoked identity must be denied at the handshake even though still enrolled")
	}
	// A different enrolled, non-revoked identity is still admitted (revocation is per-identity).
	if err := cfg.VerifyConnection(csWithCN("conn-lab-1")); err != nil {
		t.Fatalf("non-revoked enrolled identity must remain admitted: %v", err)
	}
	// Restore (re-enroll / re-attest) re-admits it.
	rev.Restore("mac-dev-1")
	if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err != nil {
		t.Fatalf("restored identity must be admitted again: %v", err)
	}

	// Every revocation reason hard-blocks — there is no per-reason self-heal at the handshake (the W-2 agent-dark
	// auto-revocation/self-heal path was removed). A revoked identity stays denied until an explicit Restore.
	rev.Revoke("mac-dev-1", "agent_dark")
	if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err == nil {
		t.Fatal("a revoked identity must be denied at the handshake regardless of reason (no self-heal)")
	}
	if _, gone := rev.IsRevoked("mac-dev-1"); !gone {
		t.Fatal("the revocation must NOT be auto-cleared by a handshake")
	}
}

// The overlay alone (no enrolled requirement) still installs the admission closure and rejects hard-revoked ids.
func TestTransportAdmission_OverlayInstallsGateWithoutEnrolment(t *testing.T) {
	rev := revocation.NewAdmissionRevocations()
	rev.Revoke("mac-dev-1", "admin_kill_switch")
	cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{
		ListenAddr:           "127.0.0.1:0",
		LabAutoCert:          true,
		LabMode:              true,
		AdmissionRevocations: rev, // no RequireEnrolledIdentity, no tenant binding
	})
	if err != nil {
		t.Fatalf("build tls cfg: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("overlay presence must install the admission gate")
	}
	if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err == nil {
		t.Fatal("hard-revoked identity must be denied even when enrolment is not required")
	}
	if err := cfg.VerifyConnection(csWithCN("anyone-else")); err != nil {
		t.Fatalf("non-revoked identity should pass when enrolment is not required: %v", err)
	}
}
