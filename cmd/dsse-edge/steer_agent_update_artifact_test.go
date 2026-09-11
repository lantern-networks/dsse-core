package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// requireFileIdentity skips, loudly, on a host where fileIdentity cannot pin a file to its bytes.
//
// ★ THE CAPABILITY IS PROBED, not runtime.GOOS. artifact_identity_other.go returns zeros deliberately and says
// so — "this platform cannot pin the file", so the cache falls back to size+mtime — which is exactly the
// property the test below asserts is not enough. On such a host a failure there is not a defect being caught;
// it is the documented fallback, and it sends somebody to look for a bug in code doing what it says. The Edge
// ships on linux and darwin, where the check runs for real.
//
// Probing rather than listing means a host that GAINS an implementation starts running the test with no edit
// here. Closing the gap on Windows is not a one-liner and should not be guessed at: os.FileInfo carries no
// file index there (it needs the handle, via GetFileInformationByHandle), and NTFS file-system tunneling
// re-uses a deleted file's creation time for ~15 seconds — so the two fields that look like an answer are the
// ones that would quietly lie in precisely this scenario.
func requireFileIdentity(t *testing.T) {
	t.Helper()
	probe := filepath.Join(t.TempDir(), "identity-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(probe)
	if err != nil {
		t.Fatal(err)
	}
	if inode, device, ctime := fileIdentity(fi); inode == 0 && device == 0 && ctime.IsZero() {
		t.Skipf("SKIPPED on %s — fileIdentity cannot pin a file on this host, so the artifact cache pins by "+
			"size+mtime alone and the property under test is one the Edge deliberately does not have here. "+
			"NOTHING WAS VERIFIED; the linux and darwin runs cover it.", runtime.GOOS)
	}
}

// artifactResponse drives the handler with a device identity and returns what it wrote.
//
// ★ THESE USED A REAL httptest.Server AND THE TRANSITION ESCAPE (2026-08-13). When release bytes moved inside
// the tunnel, three tests about how bytes are READ from disk — streaming, the hash cache, re-verification after
// a same-size replacement — could no longer present a client certificate, so they ran with the anonymous escape
// on. That escape is gone now that both agents courier, and these ask the handler directly instead: the
// behaviour under test is handler-side, and a test that needs a security control disabled is a test that will
// keep it alive.
func artifactResponse(t *testing.T, mux *http.ServeMux) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, artifactRequest("darwin", "arm64"))
	return rec
}

func artifactEdge(t *testing.T, dir string, m agentupdate.Manifest) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerSteerAgentUpdateArtifactRoute(mux, serverConfig{
		AgentUpdateArtifactDir: dir,
		PublishedUpdates: &publishedUpdates{byTarget: map[string]publishedUpdate{
			updateTargetKey(m.Platform, m.Arch): {Manifest: m},
		}},
	})
	return mux
}

func writeArtifact(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// artifactRequest asks for release bytes the way an AGENT does since 2026-08-13: inside the tunnel, with a
// verified device certificate. The endpoint used to be deliberately anonymous; it is not, because the (T)
// listener refuses to start without mandatory mTLS and an anonymous route therefore cost a second global
// address per customer, while leaving the fleet's current build retrievable by anyone who could reach it.
func artifactRequest(platform, arch string) *http.Request {
	r := httptest.NewRequest("GET", "/steer/agent-update-artifact?platform="+platform+"&arch="+arch, nil)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "dev-1"}}
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	return r
}

// ★ AND WITHOUT ONE IT IS REFUSED. This is the whole point of the move: an unenrolled anonymous caller pulled
// 25,931,776 bytes from the lab, so "is this fleet mid-rollout of a build with public weaknesses" was not
// private either.
func TestAgentUpdateArtifactRefusesACallerWithNoDeviceIdentity(t *testing.T) {
	dir := t.TempDir()
	body := []byte("a notarized package, pretend")
	digest := writeArtifact(t, dir, "darwin-arm64-0.2.0.pkg", body)
	mux := artifactEdge(t, dir, agentupdate.Manifest{
		Platform: "darwin", Arch: "arm64", Version: "0.2.0",
		ArtifactSHA256: digest, NotAfter: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/steer/agent-update-artifact?platform=darwin&arch=arm64", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — anonymous callers can read the fleet's current build", rec.Code)
	}
	if rec.Body.Len() > 200 {
		t.Fatalf("the refusal returned %d bytes; it must not leak the package", rec.Body.Len())
	}
}

func TestAgentUpdateArtifactIsServedWhenItMatchesTheManifest(t *testing.T) {
	dir := t.TempDir()
	body := []byte("a notarized package, pretend")
	digest := writeArtifact(t, dir, "darwin-arm64-0.2.0.pkg", body)

	mux := artifactEdge(t, dir, agentupdate.Manifest{
		Platform: "darwin", Arch: "arm64", Version: "0.2.0",
		ArtifactSHA256: digest, NotAfter: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, artifactRequest("darwin", "arm64"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(body) {
		t.Error("the bytes served are not the bytes on disk")
	}
}

// ★ THE DIGEST IS CHECKED BEFORE SERVING. An artifact that does not match the manifest is a release mistake,
// and it has to fail on the machine that made it. Without this, every endpoint downloads the whole package and
// then refuses it with a message about an untrusted release — the fleet reports a substitution attack, and the
// truth is that someone rebuilt without republishing.
func TestAgentUpdateArtifactRefusesBytesThatDoNotMatchTheManifest(t *testing.T) {
	dir := t.TempDir()
	writeArtifact(t, dir, "darwin-arm64-0.2.0.pkg", []byte("rebuilt, never republished"))

	mux := artifactEdge(t, dir, agentupdate.Manifest{
		Platform: "darwin", Arch: "arm64", Version: "0.2.0",
		ArtifactSHA256: strings.Repeat("a", 64), NotAfter: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, artifactRequest("darwin", "arm64"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: an edge must not hand out bytes it has itself published a different digest for", rec.Code)
	}
}

func TestAgentUpdateArtifactMissingFileIsNotFound(t *testing.T) {
	mux := artifactEdge(t, t.TempDir(), agentupdate.Manifest{
		Platform: "darwin", Arch: "arm64", Version: "0.2.0",
		ArtifactSHA256: strings.Repeat("b", 64), NotAfter: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, artifactRequest("darwin", "arm64"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// ★ The filename comes from the MANIFEST, so a caller cannot steer the path — but the manifest is still an
// input, and a version carrying a separator must never become a path a file server opens.
func TestArtifactFileNameRefusesAnythingThatCouldLeaveTheDirectory(t *testing.T) {
	for _, tc := range []struct{ platform, arch, version string }{
		{"darwin", "arm64", "../../etc/passwd"},
		{"darwin", "arm64", "0.2.0/../.."},
		{"darwin", "../arm64", "0.2.0"},
		{"linux", "amd64", "0.2.0"}, // no extension defined: not a shape we publish
		{"darwin", "arm64", ""},
	} {
		if got := artifactFileName(tc.platform, tc.arch, tc.version); got != "" {
			t.Errorf("artifactFileName(%q,%q,%q) = %q, want refusal", tc.platform, tc.arch, tc.version, got)
		}
	}
	if got := artifactFileName("darwin", "arm64", "0.2.0"); got != "darwin-arm64-0.2.0.pkg" {
		t.Errorf("the ordinary case broke: %q", got)
	}
}

// ★ The served bytes must name their own version. The URL cannot (nothing a caller controls may select a file),
// so a device whose manifest is one release behind downloads these bytes and refuses them against its own
// manifest — in the words of a substitution attack, for the most ordinary reason there is. The header is what
// lets the endpoint tell a stale manifest from a tampered artifact.
func TestServedArtifactNamesItsVersion(t *testing.T) {
	dir := t.TempDir()
	body := []byte("a package")
	sum := sha256.Sum256(body)
	m := agentupdate.Manifest{Version: "9.9.9", Platform: "darwin", Arch: "arm64",
		ArtifactSHA256: hex.EncodeToString(sum[:]), ArtifactSize: int64(len(body))}
	if err := os.WriteFile(filepath.Join(dir, "darwin-arm64-9.9.9.pkg"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := artifactResponse(t, artifactEdge(t, dir, m))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get(agentupdate.ArtifactVersionHeader); got != "9.9.9" {
		t.Errorf("%s = %q, want 9.9.9 — an endpoint cannot tell a stale manifest from a substitution without it",
			agentupdate.ArtifactVersionHeader, got)
	}
}

// ★ This route is unauthenticated by design, and it used to hash the whole artifact on EVERY request —
// including a Range request for one byte. Tens of megabytes of disk read per call, from anyone who can reach
// the port, in parallel: the check that protects a release was also the cheapest way to exhaust an Edge.
func TestTheArtifactIsHashedOncePerFileNotOncePerRequest(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("x"), 4096)
	sum := sha256.Sum256(body)
	m := agentupdate.Manifest{Version: "9.9.9", Platform: "darwin", Arch: "arm64",
		ArtifactSHA256: hex.EncodeToString(sum[:]), ArtifactSize: int64(len(body))}
	path := filepath.Join(dir, "darwin-arm64-9.9.9.pkg")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	// The cache is keyed on the path, so a previous test's entry must not answer for this one.
	verifiedArtifactsMu.Lock()
	delete(verifiedArtifacts, path)
	verifiedArtifactsMu.Unlock()

	mux := artifactEdge(t, dir, m)
	get := func() int { return artifactResponse(t, mux).Code }
	for i := 0; i < 5; i++ {
		if code := get(); code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, code)
		}
	}

	// ★ REPLACED BYTES MUST BE RE-VERIFIED. A cache keyed on the path alone turns "verify before serving" into
	// "verified once, long ago", which is worse than the cost it saved.
	if err := os.WriteFile(path, bytes.Repeat([]byte("y"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	// Modification time is part of the identity; make sure it actually moved on a coarse filesystem.
	newer := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatal(err)
	}
	if code := get(); code != http.StatusConflict {
		t.Fatalf("a replaced artifact was served on the strength of an old verification: status %d", code)
	}
}

// ★ A REPLACEMENT THAT KEEPS size AND mtime MUST NOT READ AS A CACHE HIT (2026-08-12, fourth review). Build
// tools, rsync -t and anyone deliberate can produce one; the verified answer would then be served for bytes
// nobody hashed.
func TestAnArtifactReplacedWithTheSameSizeAndTimeIsStillReVerified(t *testing.T) {
	requireFileIdentity(t)
	dir := t.TempDir()
	body := bytes.Repeat([]byte("x"), 2048)
	sum := sha256.Sum256(body)
	m := agentupdate.Manifest{Version: "9.9.9", Platform: "darwin", Arch: "arm64",
		ArtifactSHA256: hex.EncodeToString(sum[:]), ArtifactSize: int64(len(body))}
	path := filepath.Join(dir, "darwin-arm64-9.9.9.pkg")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	verifiedArtifactsMu.Lock()
	delete(verifiedArtifacts, path)
	verifiedArtifactsMu.Unlock()

	mux := artifactEdge(t, dir, m)
	get := func() int { return artifactResponse(t, mux).Code }
	if code := get(); code != http.StatusOK {
		t.Fatalf("first fetch: %d", code)
	}

	// Replace atomically with DIFFERENT bytes of the SAME length, and restore the timestamp.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, bytes.Repeat([]byte("y"), 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if code := get(); code != http.StatusConflict {
		t.Fatalf("★ a same-size, same-mtime replacement was served on an old verification: %d", code)
	}
}
