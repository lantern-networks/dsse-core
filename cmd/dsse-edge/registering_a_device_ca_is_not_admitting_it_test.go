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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// ★★★ REGISTERING A DEVICE CA IS NOT ADMITTING ITS DEVICES (2026-08-22, measured on the lab).
//
// The tenant CA registry answers "which organization does this chain belong to" and feeds the admin surface.
// What the TLS listener verifies a CLIENT certificate against is a separate pool, and the only thing adding to
// it after start-up is the 30-second reconcile — which adds only what IT adopted from the shared store. An
// authority installed from control-plane material updates the in-memory registry first, so the reconcile finds
// nothing new and never touches the pool.
//
// Measured: a device-identity authority created while the fleet was running registered cleanly, appeared on
// every screen, issued a certificate through POST /enroll — and that device was refused at the handshake,
// with the Edge naming the OTHER authority as the candidate it had tried, because both carry the same subject.
// Every Edge would have had to restart.
func TestInstallingADeviceAuthorityAlsoLetsItsDevicesConnect(t *testing.T) {
	before := len(edgeClientAnchorsSnapshotForTest())

	caCert, caPEM, caKey := deviceAdmissionTestCA(t, "Probe Device Identity CA")
	keyPEM, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	registry := tenantca.NewTenantCARegistry()

	if err := tenantDeviceIdentity.Install(tenantDeviceMaterial{
		AdmissionComplete: true,
		AdmissionCAPEM:    string(caPEM),
		TenantID:          "tenant_probe_admission",
		CACertPEM:         string(caPEM),
		CAKeyPEM:          string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})),
		AnchorPEM:         string(caPEM),
	}, registry, nil); err != nil {
		t.Fatalf("install: %v", err)
	}

	// The registry knows whose it is — that was already true and is not what broke.
	if tenant, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{caCert}}); !ok ||
		tenant != "tenant_probe_admission" {
		t.Fatalf("the registry does not resolve the installed authority: %q %v", tenant, ok)
	}

	// ★ AND THE LISTENER WILL NOW ACCEPT A CLIENT SIGNED BY IT. Without this the device is issued an identity
	// it cannot use until every Edge restarts.
	after := edgeClientAnchorsSnapshotForTest()
	if len(after) <= before {
		t.Fatal("installing a device-identity authority did not add it to what the listener verifies client " +
			"certificates against — every device enrolled under it would be refused at the handshake")
	}
	found := false
	for _, c := range after {
		if c.Equal(caCert) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("the installed authority is not among the listener's client CAs")
	}
}

func edgeClientAnchorsSnapshotForTest() []*x509.Certificate {
	edgeClientCAsMu.Lock()
	defer edgeClientCAsMu.Unlock()
	out := make([]*x509.Certificate, len(edgeClientAnchors))
	copy(out, edgeClientAnchors)
	return out
}

func deviceAdmissionTestCA(t *testing.T, cn string) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

// And the call site, because a pool nothing feeds is the shape this whole finding is.
func TestTheDeviceAuthorityInstallAddsToTheListenerPool(t *testing.T) {
	raw, err := os.ReadFile("tenant_device_signers.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), "setEdgeClientRegistryCAs(") {
		t.Fatal("Install no longer adds the authority to the listener's client CA pool, so a device-identity " +
			"authority created while the fleet is running admits nobody until every Edge restarts")
	}
}

// ★★★ AND THE LISTENER MUST READ THE POOL PER HANDSHAKE (2026-08-22, measured — this is what actually broke).
//
// Adding the authority to edgeClientCAs was necessary and not sufficient. addEdgeClientCAs does not MUTATE
// the pool: it builds a new one and swaps the pointer. A listener that assigned tls.Config.ClientCAs once at
// start-up therefore verified against the set that existed when it booted, for the life of the process — so
// every CA registered at runtime was invisible to it, and only restarting every Edge appeared to "fix" it.
//
// Measured on the lab: a device enrolled under an authority created after boot was refused at the handshake,
// with the Edge naming the OTHER authority as the candidate it had tried (both carry the same subject), which
// reads as a signing failure rather than as a stale trust set. After the change, the same shape connects with
// the process untouched.
func TestTheListenerReadsTheClientCAPoolPerHandshake(t *testing.T) {
	previous := edgeClientCAPool()
	t.Cleanup(func() { edgeClientCAs.Store(previous) })
	first := x509.NewCertPool()
	edgeClientCAs.Store(first)
	config := mainEdgeListenerClientTLSConfig(&tls.Config{}, "admin")
	before, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil || before.ClientCAs != first {
		t.Fatal("initial trust pool not selected")
	}
	cert, _, _ := deviceAdmissionTestCA(t, "Pool Indirection Probe CA")
	second := x509.NewCertPool()
	second.AddCert(cert)
	edgeClientCAs.Store(second)
	after, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil || after.ClientCAs != second || after.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatal("listener did not adopt the new client CA pool on the next handshake")
	}
	if after.GetConfigForClient != nil {
		t.Fatal("per-connection TLS config recurses")
	}
	if before.ClientCAs != first {
		t.Fatal("existing connection configuration was mutated")
	}
	raw, err := os.ReadFile("edge_server_hardening.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "srv.TLSConfig = mainEdgeListenerClientTLSConfig(srv.TLSConfig, door)") {
		t.Fatal("live listener no longer uses the per-connection trust configuration")
	}
}
