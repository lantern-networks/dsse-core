package main

import (
	"testing"
	"time"
)

func pathByID(t *testing.T, rep pkiPathsReport, id string) pkiPath {
	t.Helper()
	for _, p := range rep.Paths {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("no path %q in %+v", id, rep.Paths)
	return pkiPath{}
}

// A path must reference the certificate inventory by item ID — the property that keeps the paths view and
// the certificates view telling one story.
func TestPKIPathsReferenceInventoryItems(t *testing.T) {
	transport := testCertPEM(t, "transport-leaf")
	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:              time.Now(),
		TransportCertPEM: transport,
		TransportListen:  "0.0.0.0:18543",
	})

	rep := buildPKIPaths(pkiPathsInput{
		Now:               time.Now(),
		Inventory:         inv,
		MainListen:        "0.0.0.0:8443",
		TransportListen:   "0.0.0.0:18543",
		RecoveryListen:    "0.0.0.0:18545",
		TrustBundleSerial: 4,
		DeviceCertCount:   2,
	})

	dt := pathByID(t, rep, "device_transport")
	if dt.ServerCertID != "transport_server" {
		t.Fatalf("device_transport must reference the inventory item, got %q", dt.ServerCertID)
	}
	if len(dt.Addresses) != 2 {
		t.Fatalf("transport + recovery addresses expected, got %v", dt.Addresses)
	}
	if dt.ServerCertDays == nil || *dt.ServerCertDays < 0 {
		t.Fatalf("days-left must be computed server-side, got %v", dt.ServerCertDays)
	}
	if dt.Count != 2 || dt.ClientAuth != "device_certificate" {
		t.Fatalf("device count / client auth wrong: %+v", dt)
	}

	td := pathByID(t, rep, "trust_distribution")
	if td.TrustSerial != 4 {
		t.Fatalf("distribution serial must be carried, got %d", td.TrustSerial)
	}
}

// Paths exist only where this node's configuration establishes them: a node with no transport listener has
// no device path, a node without a config source pulls nothing, only the receiver has audit ingest.
func TestPKIPathsFollowConfiguration(t *testing.T) {
	rep := buildPKIPaths(pkiPathsInput{
		Now:                time.Now(),
		MainListen:         "0.0.0.0:8443",
		AuditIngestEnabled: true,
	})
	for _, p := range rep.Paths {
		if p.ID == "device_transport" || p.ID == "trust_distribution" || p.ID == "config_pull" {
			t.Fatalf("path %q asserted without configuration", p.ID)
		}
	}
	pathByID(t, rep, "audit_ingest")

	rep2 := buildPKIPaths(pkiPathsInput{Now: time.Now(), ConfigSourceURL: "https://cp:9443"})
	if pathByID(t, rep2, "config_pull").Extra != "https://cp:9443" {
		t.Fatal("config_pull must carry the real source URL")
	}
}

// An expiring server certificate turns the path's status to attention — decided here, never in the browser.
func TestPKIPathsExpiryDrivesStatus(t *testing.T) {
	inv := pkiCertificateInventory{Items: []pkiCertificateItem{{
		ID: "transport_server", Role: "transport_server", Subject: "CN=t",
		NotAfter: time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}}}
	rep := buildPKIPaths(pkiPathsInput{Now: time.Now(), Inventory: inv, TransportListen: ":18543"})
	if pathByID(t, rep, "device_transport").Status != "attention" {
		t.Fatal("a certificate 10 days from expiry must mark the path for attention")
	}
}
