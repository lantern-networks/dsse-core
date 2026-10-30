package edgeplane

import (
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
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

// Follow the generated deployment: the shared interception authority is an
// intermediate under the deployment root and carries deployment CRL locations.
// No tenant-owned interception authority is provisioned for a fresh tenant.
func TestDeploymentIssuerCDPHandshakes(t *testing.T) {
	now := time.Now().UTC()
	root := newTestECDSARootProvider(t, now)
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
		})
	}
}
