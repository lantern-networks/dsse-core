package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
)

func refusalTestEngine(t *testing.T) (*edgeplane.NetworkExtensionLabTLSInterception, *x509.CertPool) {
	t.Helper()
	engine, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, time.Now)
	if err != nil || engine == nil {
		t.Fatalf("interception engine: %v", err)
	}
	engine.SetSNIBasedDecision(true)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(engine.RootCertificatePEM()) {
		t.Fatal("the engine's anchor did not parse")
	}
	return engine, pool
}

func refusalTestDecision() model.AccessDecision {
	user, reason := "someone@example.test", "Request matched an active deny policy."
	return model.AccessDecision{ID: "dec_ref_open_1", Decision: "deny", TenantID: "tenant_secret_id",
		UserID: &user, PolicyID: "pol_internal_7", Reason: &reason}
}

// Acceptance C, fourth walk (2026-11-08): a browser that reached a denied site over IPv6 was refused at the flow's
// OPEN and got a closed connection, while the same site over IPv4 showed the refusal page. A refusal at the OPEN
// is now answered with the page, under the leaf the device trusts, with the flow's address as its only
// destination and nothing dialled.
func TestABrowserRefusedAtTheOpenIsShownThePage(t *testing.T) {
	engine, pool := refusalTestEngine(t)
	device, edge := net.Pipe()
	defer device.Close()
	served := make(chan bool, 1)
	go func() {
		defer edge.Close()
		served <- serveSteerRefusalPage(edge, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
			Host: "2606:4700:10::6814:1a88", Port: 443, TenantID: "tenant_secret_id"}, "https", engine, refusalTestDecision())
	}()
	client := tls.Client(device, &tls.Config{ServerName: "example.org", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := client.Handshake(); err != nil {
		t.Fatalf("the device could not complete TLS with the leaf it trusts: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.org/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "ja")
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("no answer on the refused flow: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("got %d %q, want the 403 page", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, want := range []string{"このサイトはブロックされています", "example.org", "dec_ref_open_1"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, leak := range []string{"tenant_secret_id", "someone@example.test", "pol_internal_7"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the page shows the internal value %q", leak)
		}
	}
	if !<-served {
		t.Fatal("the page was written but the call says it was not")
	}
}

func TestAPlainHTTPFlowRefusedAtTheOpenIsShownThePage(t *testing.T) {
	device, edge := net.Pipe()
	defer device.Close()
	go func() {
		defer edge.Close()
		serveSteerRefusalPage(edge, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "10.47.1.30", Port: 8080},
			"http", nil, refusalTestDecision())
	}()
	req, _ := http.NewRequest(http.MethodGet, "http://10.47.1.30:8080/", nil)
	req.Header.Set("Accept", "text/html")
	go func() { _ = req.Write(device) }()
	resp, err := http.ReadResponse(bufio.NewReader(device), req)
	if err != nil {
		t.Fatalf("no answer on the refused flow: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "10.47.1.30") {
		t.Fatalf("got %d, want the page naming the site:\n%s", resp.StatusCode, body)
	}
}

// A destination the organization does not decrypt is not answered under a leaf it would never otherwise be shown.
func TestABypassedDestinationRefusedAtTheOpenIsClosedAsBefore(t *testing.T) {
	engine, pool := refusalTestEngine(t)
	engine.SetBypassHosts([]string{"example.org"})
	device, edge := net.Pipe()
	defer device.Close()
	served := make(chan bool, 1)
	go func() {
		defer edge.Close()
		served <- serveSteerRefusalPage(edge, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
			Host: "2606:4700:10::6814:1a88", Port: 443}, "https", engine, refusalTestDecision())
	}()
	client := tls.Client(device, &tls.Config{ServerName: "example.org", RootCAs: pool, MinVersion: tls.VersionTLS12})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := client.Handshake(); err == nil {
		t.Fatal("a bypassed destination was answered under the interception leaf")
	}
	if <-served {
		t.Fatal("a bypassed destination reports a page served")
	}
}

func TestANonWebFlowRefusedAtTheOpenIsNotHeld(t *testing.T) {
	engine, _ := refusalTestEngine(t)
	device, edge := net.Pipe()
	defer device.Close()
	defer edge.Close()
	done := make(chan bool, 1)
	go func() {
		done <- serveSteerRefusalPage(edge, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "10.47.1.30", Port: 22},
			"ssh", engine, refusalTestDecision())
	}()
	select {
	case served := <-done:
		if served {
			t.Fatal("an ssh flow was answered with a web page")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a refused ssh flow was held open waiting for a web request")
	}
}

// The helper is only worth anything if the refusal at the OPEN calls it.
func TestTheRefusalAtTheOpenCallsThePage(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	at := strings.Index(text, `logWarnf("steer_mux_denied device=%q`)
	if at < 0 {
		t.Fatal("the steer-mux refusal line is gone; this guard no longer finds the branch it protects")
	}
	end := strings.Index(text[at:], "return\n")
	if end < 0 || !strings.Contains(text[at:at+end], "serveSteerRefusalPage(vc,") {
		t.Fatal("the steer-mux refusal no longer answers web traffic with the page")
	}
}
