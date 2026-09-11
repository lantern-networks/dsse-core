package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A deployment's PKI, small enough to stand up in a test and real enough that the checks under test are doing
// actual certificate verification rather than string comparison.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue mints a leaf for name. notAfter lets a test produce the expired case without waiting for it.
func (ca *testCA) issue(t *testing.T, name string, notBefore, notAfter time.Time, dnsNames ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issue %s: %v", name, err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// anEnrolledConnector writes the state directory the connector itself would have left behind after a
// successful first run. The filenames are the connector's (cmd/dsse-connector), which is the contract these
// checks are built on.
func anEnrolledConnector(t *testing.T, dir string, st persistedState, identityCert, identityKey, issuer, anchors []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(st)
	write := func(name string, data []byte) {
		if data == nil {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(stateFileName, body)
	write(identityCertName, identityCert)
	write(identityKeyName, identityKey)
	write(identityIssuerName, issuer)
	write(pinnedAnchorName, anchors)
}

func checkNamed(results []verifyResult, name string) (verifyResult, bool) {
	for _, r := range results {
		if r.name == name {
			return r, true
		}
	}
	return verifyResult{}, false
}

func mustCheck(t *testing.T, results []verifyResult, name string) verifyResult {
	t.Helper()
	r, ok := checkNamed(results, name)
	if !ok {
		t.Fatalf("no check named %q in %v", name, results)
	}
	return r
}

// ★★★ THE FAILURE THAT LOOKS LIKE SUCCESS. A connector that was installed but never started has a state
// directory and nothing in it; on 2026-08-23 one logged a line naming a connector id while in that state. The
// walk must say the token was never spent, not that the machine is fine.
func TestAConnectorThatHasNeverRunSaysSo(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	results := verifyConnector(state, "/bin/true", "dsse-connector", time.Now())
	r := mustCheck(t, results, "this connector has enrolled")
	if r.ok || !strings.Contains(r.note, "token has not been spent") {
		t.Fatalf("got %+v", r)
	}
}

// ★★★ AN IDENTITY THAT EXISTS IS NOT AN IDENTITY THIS DEPLOYMENT ISSUED. A connector's identity is minted by
// the organization's own certificate authority at enrolment. The negative case is run against a control that
// differs in exactly one thing — which CA signed the leaf — so a pass cannot be a blind measurement.
func TestAnIdentityFromAnotherDeploymentIsRefused(t *testing.T) {
	ours := newTestCA(t, "this deployment's connector CA")
	theirs := newTestCA(t, "some other deployment's connector CA")
	now := time.Now()
	st := persistedState{ConnectorID: "conn-abc123", Site: "tokyo-dc", TenantID: "t1",
		EdgeEndpoints: "region-a=https://a.example"}

	// Control: signed by the issuer on this machine.
	good := t.TempDir()
	crt, key := ours.issue(t, "conn-abc123", now.Add(-time.Hour), now.Add(time.Hour))
	anEnrolledConnector(t, good, st, crt, key, ours.pem, ours.pem)
	if r := mustCheck(t, verifyConnector(good, "/bin/true", "dsse-connector", now),
		"the identity came from this deployment"); !r.ok {
		t.Fatalf("the control must pass, or the negative below proves nothing: %+v", r)
	}

	// The case: a leaf from a different authority, with the same subject, beside our issuer.
	bad := t.TempDir()
	fcrt, fkey := theirs.issue(t, "conn-abc123", now.Add(-time.Hour), now.Add(time.Hour))
	anEnrolledConnector(t, bad, st, fcrt, fkey, ours.pem, ours.pem)
	r := mustCheck(t, verifyConnector(bad, "/bin/true", "dsse-connector", now),
		"the identity came from this deployment")
	if r.ok || !strings.Contains(r.note, "does not chain") {
		t.Fatalf("a certificate from another authority passed: %+v", r)
	}
}

// The Edge attributes a connector's flows to the name in its certificate, so a certificate naming somebody
// else is a connector filed under somebody else.
func TestAnIdentityThatNamesSomebodyElseIsRefused(t *testing.T) {
	ca := newTestCA(t, "connector CA")
	now := time.Now()
	dir := t.TempDir()
	crt, key := ca.issue(t, "conn-somebody-else", now.Add(-time.Hour), now.Add(time.Hour))
	anEnrolledConnector(t, dir, persistedState{ConnectorID: "conn-abc123", Site: "s", TenantID: "t1",
		EdgeEndpoints: "region-a=https://a.example"}, crt, key, ca.pem, ca.pem)
	r := mustCheck(t, verifyConnector(dir, "/bin/true", "dsse-connector", now), "the identity names this connector")
	if r.ok || !strings.Contains(r.note, "conn-abc123") {
		t.Fatalf("got %+v", r)
	}
}

func TestAnExpiredIdentityIsSaidToBeExpired(t *testing.T) {
	ca := newTestCA(t, "connector CA")
	now := time.Now()
	dir := t.TempDir()
	crt, key := ca.issue(t, "conn-abc123", now.Add(-48*time.Hour), now.Add(-time.Hour))
	anEnrolledConnector(t, dir, persistedState{ConnectorID: "conn-abc123", Site: "s", TenantID: "t1",
		EdgeEndpoints: "region-a=https://a.example"}, crt, key, ca.pem, ca.pem)
	r := mustCheck(t, verifyConnector(dir, "/bin/true", "dsse-connector", now), "the identity is valid now")
	if r.ok || !strings.Contains(r.note, "expired") {
		t.Fatalf("got %+v", r)
	}
}

// ★★★ COUNTING DOORS IS NOT REACHING THEM, AND NEITHER IS A HANDSHAKE. The three cases below are the three
// this walk met on 2026-08-26: a door that serves this connector, a door that is up and answers 404 for it
// (region-a, live — the connector failed over off it while an earlier version of this check reported both
// doors reachable), and an address with nothing behind it. Only the first is reachable.
func TestADoorThatDoesNotAnswerForThisConnectorIsNamed(t *testing.T) {
	// ★ Resolve the door name in the test, not in the OS. ".localhost" is loopback by RFC 6761 on Linux and
	// macOS and is NOT resolved on Windows, so without this the test fails on one developer machine for a
	// reason that has nothing to do with the code (2026-08-31).
	realDial := doorDialContext
	doorDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && strings.HasSuffix(host, ".localhost") {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return realDial(ctx, network, addr)
	}
	t.Cleanup(func() { doorDialContext = realDial })

	ca := newTestCA(t, "edge transport CA")
	now := time.Now()
	const connectorID = "conn-abc123"

	srvCert, srvKey := ca.issue(t, "edge.localhost", now.Add(-time.Hour), now.Add(time.Hour), "edge.localhost")
	pair, err := tls.X509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatalf("server pair: %v", err)
	}
	// door(status) stands up a door that answers the connector's profile poll with the given status.
	door := func(status int) (string, func()) {
		mux := http.NewServeMux()
		mux.HandleFunc("/connectors/"+connectorID+"/profile", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("x-connector-secret") != "runtime-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{}`))
		})
		ln, lerr := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
		if lerr != nil {
			t.Fatalf("listen: %v", lerr)
		}
		srv := &http.Server{Handler: mux}
		go func() { _ = srv.Serve(ln) }()
		return fmt.Sprintf("https://edge.localhost:%d", ln.Addr().(*net.TCPAddr).Port), func() { _ = srv.Close() }
	}

	serving, stop1 := door(http.StatusOK)
	defer stop1()
	// ★ UP, SHAKES HANDS, AND WILL NOT CARRY THIS CONNECTOR. This is the live region-a case.
	refusing, stop2 := door(http.StatusNotFound)
	defer stop2()
	absent := func() string {
		l, lerr := net.Listen("tcp", "127.0.0.1:0")
		if lerr != nil {
			t.Fatalf("pick a free port: %v", lerr)
		}
		p := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		return fmt.Sprintf("https://edge.localhost:%d", p)
	}()

	ident, identKey := ca.issue(t, connectorID, now.Add(-time.Hour), now.Add(time.Hour))
	base := persistedState{ConnectorID: connectorID, Site: "tokyo-dc", TenantID: "t1", RuntimeSecret: "runtime-secret"}

	walk := func(endpoints string) verifyResult {
		t.Helper()
		st := base
		st.EdgeEndpoints = endpoints
		dir := t.TempDir()
		anEnrolledConnector(t, dir, st, ident, identKey, ca.pem, ca.pem)
		return mustCheck(t, verifyConnector(dir, "/bin/true", "dsse-connector", now), "each door answers this connector")
	}

	// Control first: the door that serves this connector passes. Without it the failures below prove nothing.
	if r := walk("region-a=" + serving); !r.ok {
		t.Fatalf("the control must pass: %+v", r)
	}

	// ★ THE CASE AN EARLIER VERSION OF THIS CHECK CALLED REACHABLE. Both doors complete a TLS handshake.
	r := walk("region-a=" + refusing + ";region-b=" + serving)
	if r.ok {
		t.Fatalf("a door that answers 404 for this connector passed: %+v", r)
	}
	if !strings.Contains(r.note, "1 of 2") || !strings.Contains(r.note, "region-a") || !strings.Contains(r.note, "404") {
		t.Fatalf("the failure must name which door and what it said: %q", r.note)
	}

	// And an address with nothing behind it is a different failure, said differently.
	if r := walk("region-a=" + serving + ";region-b=" + absent); r.ok || !strings.Contains(r.note, "region-b") {
		t.Fatalf("an absent door passed or was not named: %+v", r)
	}
}

// A connector with no service is running until the machine restarts, and then the site is off the network.
// It is reported as a failure rather than a footnote because nothing else on the machine will mention it.
func TestNoServiceMeansItDoesNotComeBack(t *testing.T) {
	ca := newTestCA(t, "connector CA")
	now := time.Now()
	dir := t.TempDir()
	crt, key := ca.issue(t, "conn-abc123", now.Add(-time.Hour), now.Add(time.Hour))
	anEnrolledConnector(t, dir, persistedState{ConnectorID: "conn-abc123", Site: "s", TenantID: "t1",
		EdgeEndpoints: "region-a=https://a.example"}, crt, key, ca.pem, ca.pem)
	r := mustCheck(t, verifyConnector(dir, "/bin/true", "a-service-nothing-installed", now),
		"it comes back after a reboot")
	if r.ok || !strings.Contains(r.note, "unreachable") {
		t.Fatalf("got %+v", r)
	}
	// And the other half of surviving a reboot: the program itself.
	missing := mustCheck(t, verifyConnector(dir, filepath.Join(dir, "not-here"), "x", now),
		"the program this machine starts is on it")
	if missing.ok {
		t.Fatalf("a missing program passed: %+v", missing)
	}
}
