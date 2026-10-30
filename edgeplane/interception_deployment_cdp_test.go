package edgeplane

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

// Follow the generated deployment: the shared interception authority is an
// intermediate under the deployment root and carries deployment CRL locations.
// No tenant-owned interception authority is provisioned for a fresh tenant.
func TestDeploymentIssuerCDPHandshakes(t *testing.T) {
	now := time.Now().UTC()
	root := newDeploymentCRLRootProvider(t, now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	points, err := deploymentcrl.DistributionPoints([]string{"http://crl-a.example.test", "http://crl-b.example.test"}, root.cert, root.cert)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Deployment Interception CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
		MaxPathLen: 0, MaxPathLenZero: true, CRLDistributionPoints: points}
	der, err := x509.CreateCertificate(rand.Reader, template, root.cert, key.Public(), root.key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.CheckSignatureFrom(root.cert); err != nil {
		t.Fatal(err)
	}
	provider := &testECDSARootProvider{cert: issuer, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key}
	for _, mode := range []string{"shared", "another_tenant_has_own_authority"} {
		t.Run(mode, func(t *testing.T) {
			engine, err := NewNetworkExtensionLabTLSInterceptionWithProvider([]string{"*"}, func() time.Time { return now }, provider)
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.ConfigureDeploymentInterceptionCRL(root.CertPEM()); err != nil {
				t.Fatal(err)
			}
			if mode == "another_tenant_has_own_authority" {
				otherRoot, otherIssuer, otherKey, _ := tenantOfflineBundle(t, "other", now)
				if _, err := engine.LoadOfflineTenantIntermediate("tenant_other", otherRoot, otherIssuer, otherKey); err != nil {
					t.Fatal(err)
				}
			}
			_, _, enabled, err := engine.SignTenantLeafCRL("tenant_new", now)
			if err != nil || enabled {
				t.Fatalf("shared deployment authority must not publish a tenant CRL: enabled=%v error=%v", enabled, err)
			}
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			defer clientRaw.Close()
			_ = serverRaw.SetDeadline(time.Now().Add(5 * time.Second))
			_ = clientRaw.SetDeadline(time.Now().Add(5 * time.Second))
			roots := x509.NewCertPool()
			roots.AddCert(root.cert)
			server := tls.Server(serverRaw, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				leaf, err := engine.leafCertificate("tenant_new", "example.com")
				return &leaf, err
			}})
			client := tls.Client(clientRaw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "example.com"})
			done := make(chan error, 1)
			go func() { done <- server.Handshake() }()
			clientErr := client.Handshake()
			serverErr := <-done
			if clientErr != nil || serverErr != nil {
				t.Fatalf("deployment CDP handshake failed: client=%v; server=%v", clientErr, serverErr)
			}
			chain := client.ConnectionState().VerifiedChains[0]
			if len(chain) != 3 || !chain[1].Equal(issuer) || !slices.Equal(chain[1].CRLDistributionPoints, points) {
				t.Fatal("deployment authority or its existing CRL locations changed")
			}
			leafPoints, err := deploymentcrl.DistributionPoints([]string{"http://crl-a.example.test", "http://crl-b.example.test"}, root.cert, issuer)
			if err != nil || !slices.Equal(chain[0].CRLDistributionPoints, leafPoints) {
				t.Fatalf("leaf must name its immediate signer's CRL, not its parent's: %v", err)
			}
			rootCRL, err := inspectioncrl.Sign(root.cert, root.key, big.NewInt(1), nil, now, 30*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			issuerCRL, err := inspectioncrl.Sign(issuer, key, big.NewInt(1), nil, now, 30*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			lists := map[string][]byte{deploymentcrl.Fingerprint(root.cert): rootCRL, deploymentcrl.Fingerprint(issuer): issuerCRL}
			if err := deploymentcrl.VerifyStatus(chain, lists, now); err != nil {
				t.Fatalf("complete Online revocation path: %v", err)
			}
			if err := deploymentcrl.VerifyStatus(chain, lists, now.Add(31*time.Minute)); err == nil {
				t.Fatal("expired CRLs accepted")
			}
			revokedCRL, err := inspectioncrl.Sign(issuer, key, big.NewInt(2), []x509.RevocationListEntry{{SerialNumber: chain[0].SerialNumber, RevocationTime: now, ReasonCode: 1}}, now, 30*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			lists[deploymentcrl.Fingerprint(issuer)] = revokedCRL
			if err := deploymentcrl.VerifyStatus(chain, lists, now); err == nil {
				t.Fatal("revoked interception leaf accepted")
			}
		})
	}
}

// Use the generated deployment hierarchy, with a real signature over every CDP.
func deploymentCDPFixture(t *testing.T, mutate func(*x509.Certificate, *x509.Certificate)) (*testECDSARootProvider, *testECDSARootProvider, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	root := newDeploymentCRLRootProvider(t, now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	points, err := deploymentcrl.DistributionPoints([]string{"http://crl.example.test"}, root.cert, root.cert)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Deployment Interception CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true, CRLDistributionPoints: points}
	if mutate != nil {
		mutate(tmpl, root.cert)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, key.Public(), root.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return root, &testECDSARootProvider{cert: cert, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key}, now
}

func TestDeploymentLeafCDPBindingAndCache(t *testing.T) {
	for _, name := range []string{"missing-root", "wrong-root", "wrong-issuer-point", "wrong-deployment", "credentials", "query", "parent-is-not-root", "valid"} {
		t.Run(name, func(t *testing.T) {
			root, provider, now := deploymentCDPFixture(t, func(cert, root *x509.Certificate) {
				switch name {
				case "wrong-issuer-point":
					cert.CRLDistributionPoints = []string{"http://crl.example.test/pki/deployment-crl/" + deploymentcrl.Fingerprint(root) + "/" + strings.Repeat("0", 64) + ".crl"}
				case "wrong-deployment":
					cert.CRLDistributionPoints = []string{"http://crl.example.test/pki/deployment-crl/" + strings.Repeat("0", 64) + "/" + deploymentcrl.Fingerprint(root) + ".crl"}
				case "credentials":
					cert.CRLDistributionPoints = []string{"http://user:pass@crl.example.test/pki/deployment-crl/" + deploymentcrl.Fingerprint(root) + "/" + deploymentcrl.Fingerprint(root) + ".crl"}
				case "query":
					cert.CRLDistributionPoints[0] += "?next=other"
				}
			})
			engine, err := NewNetworkExtensionLabTLSInterceptionWithProvider([]string{"*"}, func() time.Time { return now }, provider)
			if err != nil {
				t.Fatal(err)
			}
			roots := root.CertPEM()
			switch name {
			case "missing-root":
				roots = nil
			case "wrong-root":
				roots = newTestECDSARootProvider(t, now).CertPEM()
			case "parent-is-not-root":
				roots = provider.CertPEM()
			}
			err = engine.ConfigureDeploymentInterceptionCRL(roots)
			if name != "valid" {
				if err == nil {
					t.Fatal("invalid binding accepted")
				}
				if _, err = engine.leafCertificate("tenant", "example.com"); err == nil {
					t.Fatal("unconfigured CDP issuer minted leaf")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := engine.leafCertificate("tenant", "example.com")
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseCertificate(leaf.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			parsed.CRLDistributionPoints = nil
			staleDER, err := x509.CreateCertificate(rand.Reader, parsed, provider.cert, engine.leafKey.Public(), provider.key)
			if err != nil {
				t.Fatal(err)
			}
			leaf.Certificate[0] = staleDER
			// Even a stale cache entry whose metadata still advertises a CDP must be checked against DER.
			engine.leafCache["\x00\x00example.com"] = leaf
			fresh, err := engine.leafCertificate("tenant", "example.com")
			if err != nil {
				t.Fatal(err)
			}
			actual, err := x509.ParseCertificate(fresh.Certificate[0])
			if err != nil || len(actual.CRLDistributionPoints) != 1 {
				t.Fatalf("cached CDP-less leaf reused: %v", err)
			}
			if fresh.Leaf.SerialNumber.Cmp(parsed.SerialNumber) == 0 {
				t.Fatal("stale leaf serial reused")
			}
		})
	}
}

type droppingDeploymentCDPSigner struct{ crypto.Signer }

func (s droppingDeploymentCDPSigner) SignCert(template, issuer *x509.Certificate, public crypto.PublicKey, purpose string) ([]byte, error) {
	copy := *template
	copy.CRLDistributionPoints = nil
	return x509.CreateCertificate(rand.Reader, &copy, issuer, public, s.Signer)
}

type droppingDeploymentCDPProvider struct{ *testECDSARootProvider }

func (p droppingDeploymentCDPProvider) Signer() crypto.Signer {
	return droppingDeploymentCDPSigner{p.key}
}
func TestDeploymentLeafCDPRequiredFromPurposeBoundSigner(t *testing.T) {
	root, provider, now := deploymentCDPFixture(t, nil)
	engine, err := NewNetworkExtensionLabTLSInterceptionWithProvider([]string{"*"}, func() time.Time { return now }, droppingDeploymentCDPProvider{provider})
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.ConfigureDeploymentInterceptionCRL(root.CertPEM()); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.leafCertificate("tenant", "example.com"); err == nil {
		t.Fatal("signer dropped required leaf CDP")
	}
}

func newDeploymentCRLRootProvider(t *testing.T, now time.Time) *testECDSARootProvider {
	t.Helper()
	root := newTestECDSARootProvider(t, now)
	template := *root.cert
	template.KeyUsage |= x509.KeyUsageCRLSign
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, root.key.Public(), root.key)
	if err != nil {
		t.Fatal(err)
	}
	root.cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	root.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return root
}

func TestDeploymentLeafCRLConfigurationDoesNotReinterpretOfflineAuthority(t *testing.T) {
	root, provider, now := deploymentCDPFixture(t, nil)
	keyDER, err := x509.MarshalECPrivateKey(provider.key)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate([]string{"*"}, func() time.Time { return now }, root.CertPEM(), provider.CertPEM(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), "")
	if err != nil {
		t.Fatal(err)
	}
	original := engine.offlineIssuer
	if err = engine.ConfigureDeploymentInterceptionCRL(nil); err != nil {
		t.Fatalf("offline authority was reinterpreted as shared deployment: %v", err)
	}
	if engine.offlineIssuer != original || engine.deploymentCRLIssuer != nil {
		t.Fatal("offline issuer was replaced")
	}
}
