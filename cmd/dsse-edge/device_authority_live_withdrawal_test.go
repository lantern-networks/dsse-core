package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func isolatedDeviceAuthorityPools(t *testing.T) {
	t.Helper()
	oldSigners := tenantDeviceIdentity
	tenantDeviceIdentity = &tenantDeviceSigners{signers: map[string]*deviceca.Signer{}, rotation: map[string]deviceAuthorityFingerprints{}}
	edgeClientCAsMu.Lock()
	base, registry, anchors, pool := edgeClientBaseAnchors, edgeClientRegistryAnchors, edgeClientAnchors, edgeClientCAs.Load()
	edgeClientBaseAnchors = nil
	edgeClientRegistryAnchors = nil
	edgeClientAnchors = nil
	edgeClientCAs.Store(nil)
	edgeClientCAsMu.Unlock()
	oldTransport, oldSeed, oldStore := transportClientCAPool.Load(), transportClientSeedPEM.Load(), deviceClientCAs
	deviceClientCAs = nil
	transportClientSeedPEM.Store(nil)
	transportClientCAPool.Store(nil)
	t.Cleanup(func() {
		tenantDeviceIdentity = oldSigners
		deviceClientCAs = oldStore
		transportClientSeedPEM.Store(oldSeed)
		transportClientCAPool.Store(oldTransport)
		edgeClientCAsMu.Lock()
		defer edgeClientCAsMu.Unlock()
		edgeClientBaseAnchors = base
		edgeClientRegistryAnchors = registry
		edgeClientAnchors = anchors
		edgeClientCAs.Store(pool)
	})
}
func deviceLeafForCA(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "device"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
}
func deviceMaterialForCA(t *testing.T, tenant string, ca *x509.Certificate, key *ecdsa.PrivateKey, anchors string) tenantDeviceMaterial {
	t.Helper()
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return tenantDeviceMaterial{AdmissionComplete: true, AdmissionCAPEM: anchors, TenantID: tenant, CACertPEM: string(encodeCertPEM(ca)), CAKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})), AnchorPEM: anchors, NotAfter: time.Now().Add(time.Hour).Format(time.RFC3339)}
}

// Exercise the real TLS verification path: a successful retire must reject an
// unexpired old device certificate while current, operator and other-tenant
// credentials keep working. Checking only the registry or a status field missed it.
func TestDeviceAuthorityRetirementChangesBothLiveTLSPools(t *testing.T) {
	isolatedDeviceAuthorityPools(t)
	reg := tenantca.NewTenantCARegistry()
	old, oldPEM, oldKey := deviceAdmissionTestCA(t, "rotating-device-ca")
	next, nextPEM, nextKey := deviceAdmissionTestCA(t, "rotating-device-ca")
	operator, operatorPEM, operatorKey := deviceAdmissionTestCA(t, "operator")
	other, otherPEM, otherKey := deviceAdmissionTestCA(t, "other-organization")
	byo, byoPEM, byoKey := deviceAdmissionTestCA(t, "customer-owned")
	addEdgeClientCAPEM(operatorPEM)
	if _, err := reg.Register("tenant_other", otherPEM); err != nil {
		t.Fatal(err)
	}
	current := deviceMaterialForCA(t, "tenant_rotating", old, oldKey, string(oldPEM))
	current.AdmissionCAPEM += string(byoPEM)
	if err := tenantDeviceIdentity.Install(current, reg, nil); err != nil {
		t.Fatal(err)
	}
	staleSection := deviceCABundleSection(reg, nil)
	staleSection.ManagedTenants = []string{"tenant_rotating"}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("unverified request reached handler")
		}
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: server.TLS.Certificates, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: edgeClientCAPool()}, nil
	}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	verify := func(label string, cert tls.Certificate, accepted bool) {
		t.Helper()
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}}, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		res, err := client.Post(server.URL, "application/json", nil)
		if res != nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
		if accepted && (err != nil || res.StatusCode != 204) {
			t.Fatalf("%s refused: %v", label, err)
		}
		if !accepted && err == nil {
			t.Fatalf("%s was still admitted after retirement", label)
		}
	}
	oldLeaf := deviceLeafForCA(t, old, oldKey)
	nextLeaf := deviceLeafForCA(t, next, nextKey)
	byoLeaf := deviceLeafForCA(t, byo, byoKey)
	verify("old before overlap", oldLeaf, true)
	verify("same organization BYO before overlap", byoLeaf, true)
	overlap := deviceMaterialForCA(t, "tenant_rotating", next, nextKey, string(oldPEM)+string(nextPEM))
	overlap.AdmissionCAPEM += string(byoPEM)
	if err := tenantDeviceIdentity.Install(overlap, reg, nil); err != nil {
		t.Fatal(err)
	}
	verify("old during overlap", oldLeaf, true)
	verify("new during overlap", nextLeaf, true)
	verify("same organization BYO during overlap", byoLeaf, true)
	retired := deviceMaterialForCA(t, "tenant_rotating", next, nextKey, string(nextPEM))
	retired.AdmissionCAPEM += string(byoPEM)
	if err := tenantDeviceIdentity.Install(retired, reg, nil); err != nil {
		t.Fatal(err)
	}
	verify("old after retirement", oldLeaf, false)
	verify("new after retirement", nextLeaf, true)
	verify("same organization BYO after retirement", byoLeaf, true)
	verify("operator", deviceLeafForCA(t, operator, operatorKey), true)
	verify("other organization", deviceLeafForCA(t, other, otherKey), true)
	if _, err := old.Verify(x509.VerifyOptions{Roots: transportClientCAPool.Load(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Fatal("separate transport listener still trusts retired CA")
	}
	if _, err := next.Verify(x509.VerifyOptions{Roots: transportClientCAPool.Load(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatal(err)
	}
	// An older registry distribution must not resurrect the retired CA or remove
	// the incoming one on a node whose material fetch already superseded it.
	applyDeviceCABundleSection(reg, staleSection, nil, nil)
	verify("old after stale config", oldLeaf, false)
	verify("new after stale config", nextLeaf, true)
	verify("same organization BYO after stale config", byoLeaf, true)
	if n := reg.Registrations()["tenant_rotating"]; n != 2 {
		t.Fatalf("registry retained %d device authorities", n)
	}
	// A restarted Edge reconstructs its signer from the complete CP answer. It
	// needs no local history to retain BYO or to reject the old managed identity.
	tenantDeviceIdentity = &tenantDeviceSigners{signers: map[string]*deviceca.Signer{}}
	applyDeviceCABundleSection(reg, staleSection, nil, nil)
	verify("old before material arrives after restart", oldLeaf, false)
	verify("new before material arrives after restart", nextLeaf, true)
	verify("BYO before material arrives after restart", byoLeaf, true)
	legacy := *staleSection
	legacy.ManagedComplete = false
	legacy.ManagedTenants = nil
	applyDeviceCABundleSection(reg, &legacy, nil, nil)
	verify("old after legacy config on restart", oldLeaf, false)
	verify("new after legacy config on restart", nextLeaf, true)
	if err := tenantDeviceIdentity.Install(retired, reg, nil); err != nil {
		t.Fatal(err)
	}
	verify("BYO after signer restart", byoLeaf, true)
	verify("old after signer restart", oldLeaf, false)
	// Explicit BYO withdrawal must travel through the same material path. An old
	// config section must not resurrect either kind of withdrawn authority.
	retired.AdmissionCAPEM = string(nextPEM)
	if err := tenantDeviceIdentity.Install(retired, reg, nil); err != nil {
		t.Fatal(err)
	}
	applyDeviceCABundleSection(reg, staleSection, nil, nil)
	verify("BYO after explicit withdrawal", byoLeaf, false)
	verify("managed after BYO withdrawal", nextLeaf, true)
}

func TestDeviceAuthorityInstallPersistenceFailureRetainsPreviousTrust(t *testing.T) {
	isolatedDeviceAuthorityPools(t)
	reg := tenantca.NewTenantCARegistry()
	old, oldPEM, oldKey := deviceAdmissionTestCA(t, "old")
	next, nextPEM, nextKey := deviceAdmissionTestCA(t, "next")
	first := deviceMaterialForCA(t, "tenant_failure", old, oldKey, string(oldPEM))
	if err := tenantDeviceIdentity.Install(first, reg, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := reg.Snapshot()
	beforePool := edgeClientCAPool()
	beforeSigner := tenantDeviceIdentity.For("tenant_failure")
	failed := deviceMaterialForCA(t, "tenant_failure", next, nextKey, string(nextPEM))
	if err := tenantDeviceIdentity.Install(failed, reg, func(*tenantca.TenantCARegistry) error { return fmt.Errorf("injected disk failure") }); err == nil {
		t.Fatal("unpersisted replacement succeeded")
	}
	after, _ := reg.Snapshot()
	if string(before) != string(after) || beforePool != edgeClientCAPool() || beforeSigner != tenantDeviceIdentity.For("tenant_failure") {
		t.Fatal("failed persistence changed live trust or issuer")
	}
}
