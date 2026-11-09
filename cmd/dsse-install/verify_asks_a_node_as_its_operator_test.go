package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func walkDir(t *testing.T, env string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func markClosed(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, runtimeDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimePath(dir, adminBootstrappedMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeReadToken(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	path := privateInstallReadTokenDestination(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("read-only\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// The walk presents the narrowest credential it holds, and after the deployment is closed it never falls back to
// the break-glass credential — that one is refused then, and sending it everywhere would be sending the
// deployment's strongest secret for nothing.
func TestTheWalkAsksANodeWithTheNarrowestCredentialItHolds(t *testing.T) {
	env := "ADMIN_TOKEN=break-glass\nEDGE_CP_TOKEN=fleet\n"

	dir := walkDir(t, env)
	if got, _ := nodeDetailCredential(dir); got != "break-glass" {
		t.Fatalf("before -bootstrap-admin the walk must use the armed break-glass credential, got %q", got)
	}

	markClosed(t, dir)
	if got, _ := nodeDetailCredential(dir); got != "fleet" {
		t.Fatalf("after -bootstrap-admin the walk must use the fleet token, got %q", got)
	}

	writeReadToken(t, dir, 0o644)
	if got, _ := nodeDetailCredential(dir); got != "fleet" {
		t.Fatalf("a read token anybody on the machine can read is not used, got %q", got)
	}
	writeReadToken(t, dir, 0o600)
	if got, kind := nodeDetailCredential(dir); got != "read-only" || !strings.Contains(kind, "read-only") {
		t.Fatalf("the installation's read-only token is the narrowest and comes first, got %q (%s)", got, kind)
	}

	closedWithoutFleet := walkDir(t, "ADMIN_TOKEN=break-glass\n")
	markClosed(t, closedWithoutFleet)
	if got, _ := nodeDetailCredential(closedWithoutFleet); got != "" {
		t.Fatalf("a closed deployment must not fall back to the break-glass credential, got %q", got)
	}

	if got, _ := nodeDetailCredential(t.TempDir()); got != "" {
		t.Fatalf("a machine with no deployment files holds nothing, got %q", got)
	}
}

func TestTheWalkSaysWhenItCannotAskANodeWhatItIs(t *testing.T) {
	previous, previousKind := nodeDetailBearer, nodeDetailCredentialKind
	defer func() { nodeDetailBearer, nodeDetailCredentialKind = previous, previousKind }()

	nodeDetailBearer, nodeDetailCredentialKind = "", ""
	if r := verifyTheWalkCanAskANodeWhatItIs(); r.ok || !strings.Contains(r.note, "-bootstrap-admin") {
		t.Fatalf("a walk without a credential must fail this line and say where to run: %+v", r)
	}
	nodeDetailBearer, nodeDetailCredentialKind = "secret-value", "the fleet's token (EDGE_CP_TOKEN)"
	r := verifyTheWalkCanAskANodeWhatItIs()
	if !r.ok || strings.Contains(r.note, "secret-value") {
		t.Fatalf("the line must pass and must never carry the value: %+v", r)
	}
}

func TestANodesHealthIsAskedWithTheCredential(t *testing.T) {
	previous := nodeDetailBearer
	defer func() { nodeDetailBearer = previous }()
	nodeDetailBearer = "fleet"
	seen := ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	if code, _, err := getNodeHealth(srv.Client(), srv.URL+"/healthz"); err != nil || code != 200 {
		t.Fatalf("health: %d %v", code, err)
	}
	if seen != "Bearer fleet" {
		t.Fatalf("the walk asked without its credential: %q", seen)
	}
}

// Review HEALTH-R3 (2026-11-09): the verified HTTPS node answered 302/307 to a plain-HTTP address on the same
// host, and the client followed it with the bearer still attached. The credential now goes over HTTPS only,
// and a redirect is returned rather than followed — by getNodeHealth and by every client deploymentClient builds.
func TestTheWalksCredentialNeverLeavesTheVerifiedConnection(t *testing.T) {
	previous := nodeDetailBearer
	defer func() { nodeDetailBearer = previous }()
	nodeDetailBearer = "fleet"

	plainSaw := make(chan string, 4)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainSaw <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"status":"ok","role":"edge"}`))
	}))
	defer plain.Close()

	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+"/healthz", code)
		}))
		got, _, err := getNodeHealth(secure.Client(), secure.URL+"/healthz")
		secure.Close()
		if err != nil || got != code {
			t.Fatalf("redirect %d: the walk must return the redirect unfollowed, got %d %v", code, got, err)
		}
		select {
		case auth := <-plainSaw:
			t.Fatalf("redirect %d: the plain-HTTP server was reached (Authorization present: %v)", code, auth != "")
		default:
		}
	}

	// A plain URL is refused before anything is sent.
	if _, _, err := getNodeHealth(plain.Client(), plain.URL+"/healthz"); err == nil {
		t.Fatal("the walk sent its credential over plain HTTP")
	}
	select {
	case <-plainSaw:
		t.Fatal("the plain-HTTP server was reached directly")
	default:
	}

	// And the deployment client itself does not follow redirects, so no call made through it can be led away.
	dir := t.TempDir()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/admin/config-bundle", http.StatusFound)
	}))
	defer secure.Close()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(dir, "deployment-anchor.pem"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := deploymentClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := get(client, secure.URL+"/admin/config-bundle", "break-glass"); err != nil || got != http.StatusFound {
		t.Fatalf("deploymentClient followed a redirect: %d %v", got, err)
	}
	select {
	case <-plainSaw:
		t.Fatal("deploymentClient carried the credential to the plain-HTTP server")
	default:
	}
}

// Every read of a node's /healthz in the walk goes through getNodeHealth. One written as get(client, …, "")
// would read only the status and report a healthy node as one that "did not say".
func TestEveryHealthReadInTheWalkPresentsTheCredential(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	anonymous := regexp.MustCompile(`get\([^\n]*"/healthz", ""\)`)
	readers := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if loc := anonymous.FindIndex(src); loc != nil {
			t.Fatalf("%s reads /healthz without the walk's credential: %s", f, src[loc[0]:loc[1]])
		}
		readers += strings.Count(string(src), `getNodeHealth(client, `)
	}
	if readers < 14 {
		t.Fatalf("expected the walk's fourteen field-reading /healthz calls to present the credential, found %d", readers)
	}
}
