package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ ONE MALFORMED SAN COSTS THE DEPLOYMENT, NOT THE ENTRY (2026-08-28, measured on the lab minutes after
// per-node names were added).
//
// The wildcard that names a node — *.admin.<host> — was derived from EVERY name the deployment answers on,
// so a deployment with aliases got *.admin.cp-a.dsse.lab and *.admin.edge-a.dsse.lab, which nothing routes;
// and once the wildcard was itself among those names, *.admin.*.admin.dsse.lab, which is not a DNS name at
// all. macOS then answered
//
//	SSL certificate problem: unsupported or invalid name syntax
//
// for EVERY name in the certificate — including the four plane names that had been working all morning. The
// deployment was healthy and nothing could verify it.
func TestNoNameInTheCertificateIsMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example,cp-a.dsse.example,edge-a.dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, leaf := range []string{"transport.crt", "management.crt", "edge-identity.crt"} {
		body, err := os.ReadFile(filepath.Join(dir, leaf))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(body)
		if block == nil {
			t.Fatalf("%s is not a certificate", leaf)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", leaf, err)
		}
		for _, name := range cert.DNSNames {
			if strings.Count(name, "*") > 1 || (strings.Contains(name, "*") && !strings.HasPrefix(name, "*.")) {
				t.Errorf("%s carries %q, which is not a DNS name — one of these makes the WHOLE certificate "+
					"unusable, so every plane name in it stops verifying too", leaf, name)
			}
			if strings.Contains(strings.TrimPrefix(name, "*."), "*") {
				t.Errorf("%s carries %q, a wildcard inside a wildcard", leaf, name)
			}
		}
	}
}

// ★ AND THE NODE WILDCARD IS DERIVED FROM THE DEPLOYMENT'S OWN NAME. One name, not one per alias: the aliases
// are other ways to reach the same deployment, and *.admin.<alias> is a name nothing routes and no operator
// would think to point anywhere.
func TestTheNodeWildcardIsTheDeploymentsOwnNameOnly(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example,cp-a.dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "transport.crt"))
	block, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	wildcards := []string{}
	for _, n := range cert.DNSNames {
		if strings.HasPrefix(n, "*.") {
			wildcards = append(wildcards, n)
		}
	}
	if len(wildcards) != 1 || wildcards[0] != "*.admin.dsse.example" {
		t.Errorf("the certificate carries %v; it should carry exactly one node wildcard, on the deployment's "+
			"own name", wildcards)
	}
}
