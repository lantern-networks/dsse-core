package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestMeshProductionSecurityGuard locks in the production posture: outside -lab-mode a configured
// inter-region mesh must verify the peer and be authenticated; lab-mode keeps the looser local posture.
func TestMeshProductionSecurityGuard(t *testing.T) {
	const caFile = "/tmp/peer-ca.pem"
	cases := []struct {
		name                                              string
		lab                                               bool
		meshPeers, meshSecret, meshClientCert, meshPeerCA string
		skipVerify                                        bool
		revPeers, revSecret, allowedPeers                 string
		wantErr                                           bool
	}{
		{name: "no mesh -> ok", wantErr: false},
		{name: "lab mode allows loose posture (no allowlist needed)", lab: true, meshPeers: "region-a=ws://h:1/x", skipVerify: true, revPeers: "region-a=http://h:2", wantErr: false},
		{name: "prod skip-verify forbidden", meshPeers: "region-a=wss://h:1/x", meshPeerCA: caFile, meshSecret: "s", skipVerify: true, allowedPeers: "edge-a", wantErr: true},
		{name: "prod requires pinned CA", meshPeers: "region-a=wss://h:1/x", meshSecret: "s", allowedPeers: "edge-a", wantErr: true},
		{name: "prod requires wss", meshPeers: "region-a=ws://h:1/x", meshPeerCA: caFile, meshSecret: "s", allowedPeers: "edge-a", wantErr: true},
		{name: "prod requires secret or client cert", meshPeers: "region-a=wss://h:1/x", meshPeerCA: caFile, allowedPeers: "edge-a", wantErr: true},
		{name: "prod mesh requires ingress allowlist", meshPeers: "region-a=wss://h:1/x", meshPeerCA: caFile, meshSecret: "s", wantErr: true},
		{name: "prod mesh ok with secret + allowlist", meshPeers: "region-a=wss://h:1/x", meshPeerCA: caFile, meshSecret: "s", allowedPeers: "edge-a", wantErr: false},
		{name: "prod mesh ok with client cert + allowlist", meshPeers: "region-a=wss://h:1/x", meshPeerCA: caFile, meshClientCert: "/tmp/c.pem", allowedPeers: "edge-a", wantErr: false},
		{name: "prod revocation requires secret", revPeers: "region-a=https://h:2", allowedPeers: "edge-a", wantErr: true},
		{name: "prod revocation requires https", revPeers: "region-a=http://h:2", revSecret: "s", allowedPeers: "edge-a", wantErr: true},
		{name: "prod revocation requires ingress allowlist", revPeers: "region-a=https://h:2", revSecret: "s", wantErr: true},
		{name: "prod revocation ok with allowlist", revPeers: "region-a=https://h:2", revSecret: "s", allowedPeers: "edge-a", wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceMeshProductionSecurity(tc.lab, tc.meshPeers, tc.meshSecret, tc.meshClientCert, tc.meshPeerCA, tc.skipVerify, tc.revPeers, tc.revSecret, tc.allowedPeers)
			if (err != nil) != tc.wantErr {
				t.Fatalf("enforceMeshProductionSecurity = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestMeshIngressAuth locks the receiver-side peer authorization: with an allowlist, only a VERIFIED mTLS
// identity that is a member is accepted and the secret fallback is OFF; without an allowlist the lab fallback
// (verified mTLS or secret) applies.
func TestMeshIngressAuth(t *testing.T) {
	allow := parseMeshIngressAllowedPeers("edge-a, edge-b")

	// ★★★ THE PEER IS VERIFIED AGAINST THE DEPLOYMENT'S OWN AUTHORITY, NOT THE DEVICE-IDENTITY TREE
	// (2026-08-25). That tier proves endpoints and connectors; a sibling Edge is
	// neither, and the trees are per-organization — so verifying a peer Edge there would let a CUSTOMER's
	// device CA mint something this ingress accepts. Hence the test builds a real operator CA and signs the
	// peer identities with it, rather than handing the helper a pre-declared VerifiedChains, which asserted
	// only that the struct field was populated.
	operatorCA, operatorKey := meshTestCA(t, "deployment operator CA")
	otherCA, otherKey := meshTestCA(t, "some customer device CA")
	setMeshPeerAuthority(meshTestPool(operatorCA), []*x509.Certificate{operatorCA})

	mTLS := func(id string) *http.Request { return meshTestRequest(t, id, operatorCA, operatorKey) }
	// A leaf with the SAME NAME, signed by a different tree. Nothing about the name distinguishes it.
	foreign := func(id string) *http.Request { return meshTestRequest(t, id, otherCA, otherKey) }
	secretReq := func(hdr, val string) *http.Request {
		r := httptest.NewRequest("GET", "/mesh/ingress/tunnel", nil)
		r.Header.Set(hdr, val)
		return r
	}

	// allowlist mode
	if _, ok := meshIngressAuth(mTLS("edge-a"), allow, "s3cr3t", "x-mesh-secret"); !ok {
		t.Fatal("allowlisted peer edge-a must be accepted")
	}
	if _, ok := meshIngressAuth(mTLS("rogue-device"), allow, "s3cr3t", "x-mesh-secret"); ok {
		t.Fatal("a verified-but-not-allowlisted enrolled cert MUST be rejected (the core gap)")
	}
	if _, ok := meshIngressAuth(secretReq("x-mesh-secret", "s3cr3t"), allow, "s3cr3t", "x-mesh-secret"); ok {
		t.Fatal("secret fallback MUST be disabled when an allowlist is configured")
	}
	// lab fallback (no allowlist)
	if _, ok := meshIngressAuth(mTLS("any-device"), nil, "s3cr3t", "x-mesh-secret"); !ok {
		t.Fatal("lab: any verified mTLS identity is accepted without an allowlist")
	}
	if _, ok := meshIngressAuth(secretReq("x-mesh-secret", "s3cr3t"), nil, "s3cr3t", "x-mesh-secret"); !ok {
		t.Fatal("lab: matching secret is accepted without an allowlist")
	}
	if _, ok := meshIngressAuth(secretReq("x-mesh-secret", "wrong"), nil, "s3cr3t", "x-mesh-secret"); ok {
		t.Fatal("lab: wrong secret rejected")
	}

	// ★ THE ONE THIS CHANGE EXISTS FOR. An allowlisted NAME signed by another tree must be refused — in
	// allowlist mode and in the lab fallback alike, because the fallback's "any verified mTLS identity" has
	// to mean verified against THIS deployment.
	if _, ok := meshIngressAuth(foreign("edge-a"), allow, "s3cr3t", "x-mesh-secret"); ok {
		t.Fatal("a peer named edge-a but issued by another authority was accepted")
	}
	if _, ok := meshIngressAuth(foreign("edge-a"), nil, "", "x-mesh-secret"); ok {
		t.Fatal("lab fallback accepted a leaf from another authority")
	}

	// ★ AND THE OTHER DIRECTION: because this Edge now advertises the deployment authority so a peer can
	// present itself, certificates rooted there also verify on the ordinary listener. One must never read as
	// an endpoint — that would be the deployment's own certificate acting as somebody's device.
	peerLeaf := meshTestRequest(t, "edge-a", operatorCA, operatorKey)
	peerLeaf.TLS.VerifiedChains = [][]*x509.Certificate{{peerLeaf.TLS.PeerCertificates[0], operatorCA}}
	if id, ok := transportDeviceIdentityFromRequest(peerLeaf); ok {
		t.Fatalf("a certificate rooted at the deployment authority was read as device identity %q", id)
	}
}

// meshTestCA makes a self-signed CA usable for client-auth chains.
func meshTestCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func meshTestPool(ca *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

// meshTestRequest builds a request carrying a client leaf with CommonName id, issued by ca. VerifiedChains is
// deliberately left EMPTY: the ingress must do its own verification, so a test that populated it would pass
// against the very code path being removed.
func meshTestRequest(t *testing.T, id string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *http.Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/mesh/ingress/tunnel", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	return r
}
