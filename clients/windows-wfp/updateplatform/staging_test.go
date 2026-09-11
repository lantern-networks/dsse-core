package updateplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// stagedInto points StagedRoot at a scratch tree so no test can write into a real ProgramData.
func stagedInto(t *testing.T) {
	t.Helper()
	t.Setenv("ProgramData", t.TempDir())
}

func manifestFor(body []byte, url string) agentupdate.Manifest {
	sum := sha256.Sum256(body)
	return agentupdate.Manifest{
		Version:        "0.2.0",
		Platform:       agentupdate.PlatformWindows,
		Arch:           agentupdate.ArchAMD64,
		Delivery:       agentupdate.DeliveryDSSE,
		ArtifactURL:    url,
		ArtifactSHA256: hex.EncodeToString(sum[:]),
		ArtifactSize:   int64(len(body)),
	}
}

func serving(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestStagePlacesAVerifiedArtifact(t *testing.T) {
	stagedInto(t)
	body := []byte("this is a pretend MSI payload")
	srv := serving(t, body)

	got, err := Stage(context.Background(), srv.Client(), manifestFor(body, srv.URL))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	want, _ := StagedPath("0.2.0")
	if got != want {
		t.Fatalf("Stage placed %q, want %q", got, want)
	}
	onDisk, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("read staged: %v", err)
	}
	if string(onDisk) != string(body) {
		t.Fatalf("staged bytes differ from what was served")
	}
	// No temp files may survive: a leftover *.partial is a half-download that a later reader could mistake
	// for something meaningful.
	leftovers, _ := filepath.Glob(filepath.Join(StagedRoot(), "*.partial"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files survived a successful stage: %v", leftovers)
	}
}

// TestUnverifiedBytesNeverReachTheRunnablePath is the security property this file exists for.
//
// Execute hands StagedPath to msiexec. If a download landed there before being verified, a crash or a killed
// service would leave an unverified payload sitting exactly where a privileged install looks — and the next
// tick would find it "already staged". The digest must be checked while the file is still un-runnable.
func TestUnverifiedBytesNeverReachTheRunnablePath(t *testing.T) {
	stagedInto(t)
	body := []byte("the real payload")
	// Serve something else entirely, under a manifest describing the real payload.
	srv := serving(t, []byte("TAMPERED payload of the same-ish size"))

	_, err := Stage(context.Background(), srv.Client(), manifestFor(body, srv.URL))
	if err == nil {
		t.Fatal("Stage accepted bytes that do not match the manifest")
	}
	dst, _ := StagedPath("0.2.0")
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Fatal("a rejected download is sitting at the path Execute would hand to msiexec")
	}
	leftovers, _ := filepath.Glob(filepath.Join(StagedRoot(), "*.partial"))
	if len(leftovers) != 0 {
		t.Fatalf("a rejected download was left behind: %v", leftovers)
	}
}

// TestStageIsIdempotentAndDoesNotRefetch: the tick loop calls this on every pass while waiting for a
// maintenance window, which may be days. Re-downloading tens of megabytes each tick would be a bug an
// operator experiences as their link being saturated.
func TestStageIsIdempotentAndDoesNotRefetch(t *testing.T) {
	stagedInto(t)
	body := []byte("payload that should be fetched exactly once")
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(body)
	}))
	defer s.Close()
	m := manifestFor(body, s.URL)

	for i := 0; i < 3; i++ {
		if _, err := Stage(context.Background(), s.Client(), m); err != nil {
			t.Fatalf("Stage pass %d: %v", i, err)
		}
	}
	if hits != 1 {
		t.Fatalf("artifact fetched %d times, want 1", hits)
	}
}

// TestCorruptedStagedFileIsRefetched: the re-check is a verification, not a name lookup. Days can pass
// between staging and installing, and a file that no longer matches must not be handed to an installer just
// because it has the right name.
func TestCorruptedStagedFileIsRefetched(t *testing.T) {
	stagedInto(t)
	body := []byte("payload that will be corrupted on disk")
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(body)
	}))
	defer s.Close()
	m := manifestFor(body, s.URL)

	staged, err := Stage(context.Background(), s.Client(), m)
	if err != nil {
		t.Fatalf("first Stage: %v", err)
	}
	if err := os.WriteFile(staged, []byte("corrupted"), 0o644); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := Stage(context.Background(), s.Client(), m); err != nil {
		t.Fatalf("second Stage: %v", err)
	}
	if hits != 2 {
		t.Fatalf("a corrupted staged file was reused (fetches=%d, want 2)", hits)
	}
}

// TestOversizedBodyIsRefused: without a bound, a server that streams forever fills the endpoint's disk — and
// this runs as SYSTEM on a machine whose network is this product's responsibility.
func TestOversizedBodyIsRefused(t *testing.T) {
	stagedInto(t)
	body := []byte("small declared payload")
	m := manifestFor(body, "")
	srv := serving(t, []byte(strings.Repeat("x", len(body)*10)))
	m.ArtifactURL = srv.URL

	_, err := Stage(context.Background(), srv.Client(), m)
	if err == nil {
		t.Fatal("Stage accepted a body larger than the manifest declared")
	}
	if !strings.Contains(err.Error(), "declared") {
		t.Fatalf("error does not explain the size refusal: %v", err)
	}
}

// TestNoDeclaredSizeIsRefused: an unbounded download is not something to attempt hopefully.
func TestNoDeclaredSizeIsRefused(t *testing.T) {
	stagedInto(t)
	srv := serving(t, []byte("anything"))
	m := manifestFor([]byte("anything"), srv.URL)
	m.ArtifactSize = 0
	if _, err := Stage(context.Background(), srv.Client(), m); err == nil {
		t.Fatal("Stage accepted a manifest with no declared artifact size")
	}
}

// TestMDMDeliveryIsNotFetched: under MDM the management system holds the payload, and fetching it anyway
// would be a second, unmanaged download path for a privileged install.
func TestMDMDeliveryIsNotFetched(t *testing.T) {
	stagedInto(t)
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer s.Close()
	m := manifestFor([]byte("x"), s.URL)
	m.Delivery = agentupdate.DeliveryMDM

	_, err := Stage(context.Background(), s.Client(), m)
	if !errors.Is(err, ErrDeliveryNotOurs) {
		t.Fatalf("err = %v, want ErrDeliveryNotOurs", err)
	}
	if hits != 0 {
		t.Fatalf("an MDM-delivered artifact was fetched %d times", hits)
	}
}

// TestHTTPErrorIsNotStaged: a 404 body must not become the installer.
func TestHTTPErrorIsNotStaged(t *testing.T) {
	stagedInto(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer s.Close()
	if _, err := Stage(context.Background(), s.Client(), manifestFor([]byte("x"), s.URL)); err == nil {
		t.Fatal("Stage accepted a 404 response")
	}
	dst, _ := StagedPath("0.2.0")
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("an error response was staged")
	}
}

func TestClearStaged(t *testing.T) {
	stagedInto(t)
	body := []byte("payload")
	srv := serving(t, body)
	if _, err := Stage(context.Background(), srv.Client(), manifestFor(body, srv.URL)); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := ClearStaged("0.2.0"); err != nil {
		t.Fatalf("ClearStaged: %v", err)
	}
	dst, _ := StagedPath("0.2.0")
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("staged artifact survived ClearStaged")
	}
	// Removing something that is not there is not an error: a tick loop clearing after an install must not
	// fail because the install already replaced things.
	if err := ClearStaged("0.2.0"); err != nil {
		t.Fatalf("ClearStaged on an absent file: %v", err)
	}
}

// ★ The gap between staging and executing, which is the whole maintenance window by design. Stage verified
// these bytes; that was days ago, and the file sits at a predictable path under %ProgramData% until msiexec
// opens it as SYSTEM. A present, non-empty file is not evidence that it is still the package that passed.
func TestASubstitutedStagedPackageIsRefusedAtLaunchTime(t *testing.T) {
	body := []byte(strings.Repeat("MSI", 400))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }))
	defer srv.Close()
	m := manifestFor(body, srv.URL)
	stagedInto(t)

	staged, err := Stage(context.Background(), srv.Client(), m)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := VerifyStaged(m); err != nil {
		t.Fatalf("a freshly staged package must verify: %v", err)
	}

	// Same length, different bytes: the shape a substitution actually takes, and the one a size check misses.
	if err := os.WriteFile(staged, []byte(strings.Repeat("EVL", 400)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStaged(m); err == nil {
		t.Fatal("a substituted package of the right length was accepted for a privileged install")
	}
}

// And a truncated one, which is the accidental version of the same thing — a filesystem that lost the tail.
func TestATruncatedStagedPackageIsRefusedAtLaunchTime(t *testing.T) {
	body := []byte(strings.Repeat("MSI", 400))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }))
	defer srv.Close()
	m := manifestFor(body, srv.URL)
	stagedInto(t)

	staged, err := Stage(context.Background(), srv.Client(), m)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := os.WriteFile(staged, body[:50], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStaged(m); err == nil {
		t.Fatal("a truncated package was accepted for a privileged install")
	}
}

// A server that sends FEWER bytes than declared must not be staged at all — the counterpart to the oversized
// case, and the one a limit-reader alone does not catch.
func TestATruncatedDownloadIsNotStaged(t *testing.T) {
	body := []byte(strings.Repeat("MSI", 400))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body[:100]) }))
	defer srv.Close()
	m := manifestFor(body, srv.URL)
	stagedInto(t)

	if _, err := Stage(context.Background(), srv.Client(), m); err == nil {
		t.Fatal("a short download was staged")
	}
	entries, _ := os.ReadDir(StagedRoot())
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".partial") {
			t.Fatalf("a failed download left %s in the staging directory", e.Name())
		}
	}
}

// ★ Two 404s that need different repairs must not read the same on the device. Measured on a live Mac: an Edge
// that predates the artifact route answers net/http's own "404 page not found"; an Edge that has the route but
// lost the file answers "the published manifest's artifact is not on this edge". The status is identical and
// the fix is not — rebuild the Edge, or put the package back.
func TestAFailedFetchCarriesTheBodyThatDistinguishesIt(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{name: "stale edge", status: 404, body: "404 page not found\n", want: "404 page not found"},
		{name: "missing file", status: 404, body: "the published manifest's artifact is not on this edge\n",
			want: "artifact is not on this edge"},
		{name: "digest mismatch", status: 409, body: "the artifact on this edge does not match the published manifest\n",
			want: "does not match the published manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, strings.TrimSuffix(tc.body, "\n"), tc.status)
			}))
			defer srv.Close()
			m := agentupdate.Manifest{Version: "9.9.9", ArtifactURL: srv.URL, ArtifactSize: 10,
				ArtifactSHA256: strings.Repeat("0", 64)}
			_, err := Stage(context.Background(), srv.Client(), m)
			if err == nil {
				t.Fatal("a non-200 must not stage")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not carry %q — the device cannot tell which failure this is", err, tc.want)
			}
		})
	}
}

// A hostile or broken origin must not get to write its whole page into the log of a machine running as SYSTEM.
func TestAFailedFetchTruncatesAndFlattensTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(strings.Repeat("A\n\tB ", 4000)))
	}))
	defer srv.Close()
	m := agentupdate.Manifest{Version: "9.9.9", ArtifactURL: srv.URL, ArtifactSize: 10,
		ArtifactSHA256: strings.Repeat("0", 64)}
	_, err := Stage(context.Background(), srv.Client(), m)
	if err == nil {
		t.Fatal("a 500 must not stage")
	}
	if n := len(err.Error()); n > 600 {
		t.Errorf("error is %d bytes: a failed download must not be a channel into the endpoint's log", n)
	}
	if strings.ContainsAny(err.Error(), "\n\t") {
		t.Error("the body must be flattened: an origin does not get to reformat somebody's log")
	}
}
