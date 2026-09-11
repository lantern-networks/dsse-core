package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func nodeServing(t *testing.T, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func trustingClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

// ★★★ A NODE ON A DIFFERENT BUILD SERVES STALE CONFIGURATION AND ITS SYMPTOMS READ AS DEFECTS (2026-08-25). A
// control plane left on an older image made a removed device still admitted and blocking answer 404, and this
// deployment's own verification reported all three as failures of the product.
func TestTwoBuildsInOneDeploymentAreReported(t *testing.T) {
	a := nodeServing(t, `{"build":{"version":"1.0.0","commit":"aaaaaaa","stamped":true}}`)
	b := nodeServing(t, `{"build":{"version":"1.0.0","commit":"bbbbbbb","stamped":true}}`)
	res := verifyOneBuild(trustingClient(), []string{a.URL, b.URL})
	if len(res) != 1 || res[0].ok {
		t.Fatalf("two builds were not reported: %+v", res)
	}
	if !strings.Contains(res[0].note, "aaaaaaa") || !strings.Contains(res[0].note, "bbbbbbb") {
		t.Fatalf("the report does not name the builds: %q", res[0].note)
	}

	// The guard: the same build on both passes, so the check above is about disagreement and not about the
	// check refusing everything.
	c := nodeServing(t, `{"build":{"version":"1.0.0","commit":"aaaaaaa","stamped":true}}`)
	res = verifyOneBuild(trustingClient(), []string{a.URL, c.URL})
	if len(res) != 1 || !res[0].ok {
		t.Fatalf("one build on both nodes did not pass: %+v", res)
	}
}

// ★ TWO UNSTAMPED BUILDS HAVE NOT BEEN SHOWN TO AGREE. A plain `go build` reports "unknown", and treating two
// of those as a match passes exactly the deployment this exists to catch.
func TestUnstampedBuildsAreNotAMatch(t *testing.T) {
	a := nodeServing(t, `{"build":{"version":"0.0.0-dev","commit":"unknown","stamped":false}}`)
	b := nodeServing(t, `{"build":{"version":"0.0.0-dev","commit":"unknown","stamped":false}}`)
	res := verifyOneBuild(trustingClient(), []string{a.URL, b.URL})
	if len(res) != 1 || res[0].ok {
		t.Fatalf("two unstamped builds were accepted as the same: %+v", res)
	}
}

// A node that does not report a build at all IS the answer: it predates this being reported.
func TestANodeThatDoesNotSayIsItselfTheFinding(t *testing.T) {
	a := nodeServing(t, `{"build":{"version":"1.0.0","commit":"aaaaaaa","stamped":true}}`)
	old := nodeServing(t, `{"status":"ok"}`)
	res := verifyOneBuild(trustingClient(), []string{a.URL, old.URL})
	if len(res) != 1 || res[0].ok {
		t.Fatalf("a node that reports no build was accepted: %+v", res)
	}
}
