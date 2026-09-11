package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// artifactRec is a courier pointed at a temp directory, so the staged path is a real path on any host and the
// tests exercise the same rename that runs in the service.
type artifactRec struct {
	dir  string
	logs []string
}

func newArtifactRec(t *testing.T, baseURL string) (*artifactCourier, *artifactRec) {
	t.Helper()
	rec := &artifactRec{dir: t.TempDir()}
	return &artifactCourier{
		client:   &http.Client{Timeout: 5 * time.Second},
		baseURL:  baseURL,
		platform: "windows",
		arch:     "amd64",
		interval: time.Hour,
		logf:     func(f string, a ...any) { rec.logs = append(rec.logs, fmt.Sprintf(f, a...)) },
		// The real StagedPath, minus %ProgramData%: the same rollbackstore.FileName validation a version from
		// the network meets in the service.
		stagedPath: func(version string) (string, error) {
			name, err := rollbackstore.FileName(version)
			if err != nil {
				return "", err
			}
			return filepath.Join(rec.dir, name), nil
		},
	}, rec
}

// artifactServer serves body with the version header, and counts how many times the body was actually asked for.
func artifactServer(t *testing.T, version string, body []byte, hits *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		if version != "" {
			w.Header().Set(agentupdate.ArtifactVersionHeader, version)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestArtifactCourierStagesUnderTheNameTheUpdaterLooksFor(t *testing.T) {
	var hits int64
	pkg := []byte("MSI-BYTES-0.2.1")
	srv := artifactServer(t, "0.2.1+3f8f2b02", pkg, &hits)
	c, rec := newArtifactRec(t, srv.URL)

	if err := c.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	// The name is the contract with updateplatform.StagedPath; a package under any other name is one the
	// updater never opens.
	want := filepath.Join(rec.dir, "dsse-agent-0.2.1+3f8f2b02.msi")
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("staged file %s: %v", want, err)
	}
	if string(got) != string(pkg) {
		t.Fatalf("staged bytes = %q, want %q", got, pkg)
	}
	// No .partial left behind.
	entries, _ := os.ReadDir(rec.dir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly the staged file, got %d entries", len(entries))
	}
}

// The loop runs on the manifest's refresh interval. Without the size skip, an up-to-date device pulls the
// whole package every pass forever — which is the fleet paying for its own idleness, on the Edge's uplink.
func TestArtifactCourierDoesNotRefetchWhatIsAlreadyStaged(t *testing.T) {
	var hits int64
	pkg := []byte("MSI-BYTES-0.2.1")
	srv := artifactServer(t, "0.2.1", pkg, &hits)
	c, rec := newArtifactRec(t, srv.URL)

	for i := 0; i < 3; i++ {
		if err := c.refreshOnce(context.Background()); err != nil {
			t.Fatalf("refreshOnce %d: %v", i, err)
		}
	}
	if hits != 3 {
		t.Fatalf("expected three requests (the skip is decided from the response), got %d", hits)
	}
	staged := filepath.Join(rec.dir, "dsse-agent-0.2.1.msi")
	fi, err := os.Stat(staged)
	if err != nil {
		t.Fatalf("stat staged: %v", err)
	}
	if fi.Size() != int64(len(pkg)) {
		t.Fatalf("staged size = %d, want %d", fi.Size(), len(pkg))
	}
	// Only one log line: the first pass staged, the other two skipped in silence.
	if len(rec.logs) != 1 {
		t.Fatalf("expected one 'staged' log, got %d: %v", len(rec.logs), rec.logs)
	}
}

// 404 is the normal answer for most devices most of the time, and must never disturb a package a device is
// holding while it waits for its maintenance window.
func TestArtifactCourier404IsQuietAndKeepsWhatIsStaged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no agent update is published", http.StatusNotFound)
	}))
	defer srv.Close()
	c, rec := newArtifactRec(t, srv.URL)

	staged := filepath.Join(rec.dir, "dsse-agent-0.2.0.msi")
	if err := os.WriteFile(staged, []byte("ALREADY-HERE"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := c.refreshOnce(context.Background())
	if !errors.Is(err, errArtifactNotPublished) {
		t.Fatalf("err = %v, want errArtifactNotPublished", err)
	}
	if b, _ := os.ReadFile(staged); string(b) != "ALREADY-HERE" {
		t.Fatalf("a 404 disturbed the staged package: %q", b)
	}
}

// 401 is the failure this change introduces, and it must not read as a missing release: the repair is on the
// transport, not in the publish lane.
func TestArtifactCourier401NamesTheTunnelAndKeepsWhatIsStaged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "a verified device identity is required", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, rec := newArtifactRec(t, srv.URL)

	staged := filepath.Join(rec.dir, "dsse-agent-0.2.0.msi")
	if err := os.WriteFile(staged, []byte("ALREADY-HERE"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := c.refreshOnce(context.Background())
	if err == nil {
		t.Fatal("expected an error for HTTP 401")
	}
	if errors.Is(err, errArtifactNotPublished) {
		t.Fatalf("a 401 must not read as 'nothing published': %v", err)
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "tunnel") {
		t.Fatalf("the 401 message must say what it is and where the repair is; got %v", err)
	}
	if b, _ := os.ReadFile(staged); string(b) != "ALREADY-HERE" {
		t.Fatalf("a 401 disturbed the staged package: %q", b)
	}
}

// Without a version there is no name, and inventing one would put the package where the updater never looks.
func TestArtifactCourierRefusesAPackageWithNoVersionHeader(t *testing.T) {
	var hits int64
	srv := artifactServer(t, "", []byte("MSI"), &hits)
	c, rec := newArtifactRec(t, srv.URL)

	err := c.refreshOnce(context.Background())
	if err == nil {
		t.Fatal("expected an error when the edge names no version")
	}
	if entries, _ := os.ReadDir(rec.dir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

// The version arrives from the network. A name that would have to be repaired to become a path is a name
// nobody meant, so it is refused — the validation lives in rollbackstore and is not reimplemented here.
func TestArtifactCourierRefusesAVersionThatWouldEscapeTheStagingDirectory(t *testing.T) {
	for _, version := range []string{
		`..\..\Windows\System32\evil`,
		"../../etc/passwd",
		".hidden",
		"-leading-dash",
		"has space",
	} {
		t.Run(version, func(t *testing.T) {
			var hits int64
			srv := artifactServer(t, version, []byte("MSI"), &hits)
			c, rec := newArtifactRec(t, srv.URL)

			err := c.refreshOnce(context.Background())
			if err == nil {
				t.Fatalf("version %q was accepted", version)
			}
			if entries, _ := os.ReadDir(rec.dir); len(entries) != 0 {
				t.Fatalf("nothing should have been written, found %d entries", len(entries))
			}
		})
	}
}

// A truncated transfer must be caught here. Left to the updater it arrives as a digest mismatch, which is the
// sentence reserved for "artefacts are being substituted, look tonight".
func TestArtifactCourierRefusesATruncatedBodyAndKeepsWhatIsStaged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(agentupdate.ArtifactVersionHeader, "0.2.1")
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	}))
	defer srv.Close()
	c, rec := newArtifactRec(t, srv.URL)

	prior := filepath.Join(rec.dir, "dsse-agent-0.2.0.msi")
	if err := os.WriteFile(prior, []byte("ALREADY-HERE"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := c.refreshOnce(context.Background())
	if err == nil {
		t.Fatal("expected an error for a short body")
	}
	if b, _ := os.ReadFile(prior); string(b) != "ALREADY-HERE" {
		t.Fatalf("a truncated fetch disturbed the staged package: %q", b)
	}
	// And it left no half-written file under the real name.
	if _, serr := os.Stat(filepath.Join(rec.dir, "dsse-agent-0.2.1.msi")); serr == nil {
		t.Fatal("a truncated body was staged under the real name")
	}
}

// The replace has no window in which the staged path holds nothing: the updater hashes whatever it finds
// there, so an empty moment is a healthy device reporting a package it will refuse.
func TestArtifactCourierReplacesAStalePackageInPlace(t *testing.T) {
	var hits int64
	fresh := []byte("MSI-BYTES-NEWER-AND-LONGER")
	srv := artifactServer(t, "0.2.1", fresh, &hits)
	c, rec := newArtifactRec(t, srv.URL)

	staged := filepath.Join(rec.dir, "dsse-agent-0.2.1.msi")
	if err := os.WriteFile(staged, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("staged file: %v", err)
	}
	if string(got) != string(fresh) {
		t.Fatalf("staged bytes = %q, want %q", got, fresh)
	}
}
