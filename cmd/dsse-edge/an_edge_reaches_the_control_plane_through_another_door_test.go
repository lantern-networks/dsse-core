package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// closedDoor is an address on this machine that nothing answers: a door whose container was stopped.
func closedDoor(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// TestTheEdgeBesideAStoppedDoorStillReachesTheControlPlane reproduces C-1 of the third walk: the leader's
// entrance was stopped, its Edge could not check an administrator's session for six minutes, and every screen
// that asked that Edge waited and got 401. The control plane was up behind the other doors.
func TestTheEdgeBesideAStoppedDoorStillReachesTheControlPlane(t *testing.T) {
	var sessions atomic.Int32
	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/session" {
			sessions.Add(1)
			io.WriteString(w, `{"ok":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer cp.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cp.Certificate())

	ownDoor := closedDoor(t)
	_, port, _ := net.SplitHostPort(ownDoor)
	saved := http.DefaultTransport.(*http.Transport).DialContext
	defer func() { edgeDoors.Store(nil); http.DefaultTransport.(*http.Transport).DialContext = saved }()

	// Before: no other door is configured, and the stopped door is all there is.
	client := &http.Client{Transport: edgeTransport(&tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})}
	if _, err := client.Get("https://127.0.0.1:" + port + "/admin/session"); err == nil {
		t.Fatal("the test's own door answered; it is meant to be stopped")
	}

	installEdgeDoors(cp.Listener.Addr().String(), ownDoor)
	resp, err := client.Get("https://127.0.0.1:" + port + "/admin/session")
	if err != nil {
		t.Fatalf("with another door named, the session check still failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || sessions.Load() != 1 {
		t.Fatalf("status=%d sessions=%d; the control plane behind the other door should have answered once", resp.StatusCode, sessions.Load())
	}

	// A dial that is not to this machine's door takes no detour: an identity provider or a connector that does
	// not answer must fail as itself, not be retried at the deployment's doors.
	other := closedDoor(t)
	_, otherPort, _ := net.SplitHostPort(other)
	if _, err := client.Get("https://127.0.0.1:" + otherPort + "/admin/session"); err == nil {
		t.Fatal("a dial to an address that is not this machine's door was sent to another door")
	}
	if sessions.Load() != 1 {
		t.Fatalf("sessions=%d; the detour was taken for an address that is not this machine's door", sessions.Load())
	}
}

// TestEveryControlPlaneClientCanLeaveThroughAnotherDoor: the fix is worth what its call sites are. An Edge
// builds its own http.Transport in a dozen places; any one built for the control plane without edgeDial
// would go back to failing at a stopped door, without a word.
func TestEveryControlPlaneClientCanLeaveThroughAnotherDoor(t *testing.T) {
	// Transports that do not talk to the control plane, by file and the text that marks the line, and why.
	notTheControlPlane := []struct{ file, marker, why string }{
		{"an_identity_provider_may_be_on_a_private_authority.go", "Transport: &http.Transport{", "an identity provider"},
		{"interception_hsm_agent.go", "Transport: &http.Transport{", "the interception key's HSM agent"},
		{"main.go", "mimicConnectorTransport := &http.Transport{", "connector traffic, with its own dialer"},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
	lines:
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "&http.Transport{") || strings.Contains(line, "edgeDial") {
				continue
			}
			for _, ok := range notTheControlPlane {
				if ok.file == name && strings.Contains(line, ok.marker) {
					continue lines
				}
			}
			t.Errorf("%s builds a transport that cannot leave through another door: %s", name, strings.TrimSpace(line))
		}
	}
}

// TestTheFallbackWorksForTheNamesADeploymentUses — review C3-R1. A generated Edge asks admin.<region>.<host>,
// a NAME that its hosts file maps to this machine's door, and the door is configured as an address. The first
// version compared the two strings, so on a generated deployment the fallback was never taken; the test above
// used an address in the URL and passed.
func TestTheFallbackWorksForTheNamesADeploymentUses(t *testing.T) {
	var sessions atomic.Int32
	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions.Add(1)
		io.WriteString(w, `{"ok":true}`)
	}))
	defer cp.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cp.Certificate())
	ownDoor := closedDoor(t)
	_, port, _ := net.SplitHostPort(ownDoor)
	saved := http.DefaultTransport.(*http.Transport).DialContext
	defer func() { edgeDoors.Store(nil); http.DefaultTransport.(*http.Transport).DialContext = saved }()
	installEdgeDoors(cp.Listener.Addr().String(), ownDoor)
	// The deployment's name for the control plane resolves to this machine's (stopped) door, as the container's
	// hosts file makes it.
	edgeDoors.Load().Lookup = func(_ context.Context, host string) ([]string, error) {
		if host == "admin.region-a.c.example.test" {
			return []string{"127.0.0.1"}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// What the transport hands the dialer: the URL's host, unresolved. The stopped door is reached by the
			// resolved address; the dialer must see that the name is the door.
			return edgeDial(ctx, network, address)
		},
	}}
	edgeDoors.Load().Dial = func(ctx context.Context, network, address string, wait time.Duration) (net.Conn, error) {
		if strings.HasPrefix(address, "admin.region-a.c.example.test:") {
			address = net.JoinHostPort("127.0.0.1", port) // the hosts file's answer: the stopped door
		}
		return (&net.Dialer{Timeout: wait}).DialContext(ctx, network, address)
	}
	resp, err := client.Get("https://admin.region-a.c.example.test:" + port + "/admin/session")
	if err != nil {
		t.Fatalf("a generated deployment's name for the control plane did not take the other door: %v", err)
	}
	resp.Body.Close()
	if sessions.Load() != 1 {
		t.Fatalf("sessions=%d; the control plane behind the other door should have answered", sessions.Load())
	}
	// A name that does not resolve to this machine's door is not detoured.
	if _, err := client.Get("https://idp.example.test:" + port + "/"); err == nil || sessions.Load() != 1 {
		t.Fatalf("a name that is not this machine's door was sent to another door (sessions=%d, err=%v)", sessions.Load(), err)
	}
}
