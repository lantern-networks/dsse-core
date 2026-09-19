package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// connectorProgramTestMux stands the routes up with an admin identity already resolved, which is what the real
// adminEndpoint does after authenticating. The tenant is the thing under test in half of these, so it is a
// parameter rather than a constant.
func connectorProgramTestMux(root string, enforcingEdge bool, tenantID string) *http.ServeMux {
	mux := http.NewServeMux()
	as := func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), adminIdentityContextKey{},
				adminIdentity{PrincipalID: "adm_test", TenantID: tenantID})
			h(w, r.WithContext(ctx))
		}
	}
	registerConnectorProgramRoutes(mux, as, root, enforcingEdge, nil, nil, testEvaluator())
	return mux
}

func publishConnectorProgram(t *testing.T, mux *http.ServeMux, platform, arch string, body []byte, digest string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut,
		"/admin/connector-program?platform="+platform+"&arch="+arch, strings.NewReader(string(body)))
	req.Header.Set("x-artifact-sha256", digest)
	req.Header.Set("x-artifact-filename", "dsse-connector-"+platform+"-"+arch+".tar.gz")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ★★★ BYTES THAT ARE NOT THE ONES DECLARED ARE REFUSED, AND NOTHING IS STORED. A truncated upload that lands
// anyway is downloaded by a customer and run on a machine inside their network. The control runs first: the
// same publish with the right digest must succeed, or the refusal below proves only that the test is broken.
func TestAConnectorProgramWhoseBytesAreNotTheOnesDeclaredIsRefused(t *testing.T) {
	root := t.TempDir()
	mux := connectorProgramTestMux(root, false, "t1")
	body := []byte("#!/bin/sh\necho connector\n")

	if rr := publishConnectorProgram(t, mux, "linux", "amd64", body, sha256Of(body)); rr.Code != 200 {
		t.Fatalf("the control must pass: %d %s", rr.Code, rr.Body.String())
	}
	// A different target, so the refusal cannot be confused with "it was already there".
	rr := publishConnectorProgram(t, mux, "linux", "arm64", body, sha256Of([]byte("something else")))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "not the ones declared") {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	// ★ THE PATH COMES FROM THE CODE UNDER TEST, NOT FROM A COPY OF IT. Written by hand, this looked at
	// root/t1/… while the store had moved to root/tenants/t1/… — a check that passed because it was looking
	// somewhere nothing is ever written. A negative assertion needs to be aimed at the real place.
	refusedDir, derr := connectorProgramDir(root, "t1", "linux-arm64")
	if derr != nil {
		t.Fatal(derr)
	}
	if _, err := os.Stat(filepath.Join(refusedDir, connectorProgramBytesName)); err == nil {
		t.Fatalf("a refused publish stored its bytes anyway")
	}
	// The guard for that: the accepted publish above IS where this expects to find things.
	acceptedDir, aerr := connectorProgramDir(root, "t1", "linux-amd64")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if _, err := os.Stat(filepath.Join(acceptedDir, connectorProgramBytesName)); err != nil {
		t.Fatalf("this test is looking in the wrong place — the accepted publish is not at %s: %v", acceptedDir, err)
	}
	// And no half-written temporary is left where the next list would trip over it. Any dot-prefixed entry:
	// the staging name belongs to durablefile, so naming its pattern here would be a check that stops being
	// true the day that package changes it — and would pass for the wrong reason in the meantime.
	entries, _ := os.ReadDir(refusedDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("a refused publish left %s behind", e.Name())
		}
	}
}

// ★ NO DIGEST IS NOT A PUBLISH. Without one there is nothing to tell a complete upload from a truncated one.
func TestAConnectorProgramPublishedWithNoDigestIsRefused(t *testing.T) {
	root := t.TempDir()
	mux := connectorProgramTestMux(root, false, "t1")
	req := httptest.NewRequest(http.MethodPut, "/admin/connector-program?platform=linux&arch=amd64",
		strings.NewReader("bytes"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "x-artifact-sha256") {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
}

// ★★★ ONE ORGANIZATION'S PROGRAM IS NOT ANOTHER'S TO READ. This is the family that keeps recurring here: a
// handler that never mentions a tenant answers for whoever asks.
func TestAConnectorProgramIsNotVisibleToAnotherOrganization(t *testing.T) {
	root := t.TempDir()
	body := []byte("theirs")
	if rr := publishConnectorProgram(t, connectorProgramTestMux(root, false, "t1"),
		"linux", "amd64", body, sha256Of(body)); rr.Code != 200 {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}

	// Control: the organization it was published for sees it and can take it.
	own := connectorProgramTestMux(root, false, "t1")
	rr := httptest.NewRecorder()
	own.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
	if !strings.Contains(rr.Body.String(), "linux") {
		t.Fatalf("the control must see its own program: %s", rr.Body.String())
	}

	other := connectorProgramTestMux(root, false, "t2")
	list := httptest.NewRecorder()
	other.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
	if strings.Contains(list.Body.String(), "linux") {
		t.Fatalf("another organization's program is listed: %s", list.Body.String())
	}
	get := httptest.NewRecorder()
	other.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/admin/connector-program?platform=linux&arch=amd64", nil))
	if get.Code != http.StatusNotFound {
		t.Fatalf("another organization downloaded it: %d", get.Code)
	}
	if strings.Contains(get.Body.String(), "theirs") {
		t.Fatalf("the bytes crossed organizations")
	}
}

// The bytes come back with the digest beside them, so whoever carries them can check what arrived without
// going back to the screen that offered them.
func TestTheDownloadCarriesItsOwnDigest(t *testing.T) {
	root := t.TempDir()
	mux := connectorProgramTestMux(root, false, "t1")
	body := []byte("the connector program")
	if rr := publishConnectorProgram(t, mux, "darwin", "arm64", body, sha256Of(body)); rr.Code != 200 {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/connector-program?platform=darwin&arch=arm64", nil))
	if rr.Code != 200 || rr.Body.String() != string(body) {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("x-artifact-sha256") != sha256Of(body) {
		t.Fatalf("the digest did not travel with the bytes: %q", rr.Header().Get("x-artifact-sha256"))
	}
	if !strings.Contains(rr.Header().Get("Content-Disposition"), "dsse-connector-darwin-arm64.tar.gz") {
		t.Fatalf("the download has no name: %q", rr.Header().Get("Content-Disposition"))
	}
}

// ★ AN EMPTY LIST IS AN ANSWER WITH A CONSEQUENCE. A screen showing "0" cannot be acted on by the person
// reading it; the deployment says what the zero means for a customer standing in front of a machine.
func TestNoProgramPublishedSaysWhatThatMeans(t *testing.T) {
	mux := connectorProgramTestMux(t.TempDir(), false, "t1")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
	if rr.Code != 200 {
		t.Fatalf("an empty store is not an error: %d", rr.Code)
	}
	var body struct {
		Count int    `json:"count"`
		Note  string `json:"note"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Count != 0 || !strings.Contains(body.Note, "nothing to put on the machine") {
		t.Fatalf("got %+v", body)
	}
}

// control-plane-only, said the way the agent artifact route beside it says it: an Edge that pulls its
// configuration holds no copy, and a write accepted here would be lost on the next poll.
func TestAnEnforcingEdgeSaysWhereToPublishInstead(t *testing.T) {
	mux := connectorProgramTestMux(t.TempDir(), true, "t1")
	body := []byte("x")
	rr := publishConnectorProgram(t, mux, "linux", "amd64", body, sha256Of(body))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "control plane") {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
}

// ★ THE TARGET BECOMES A DIRECTORY NAME. A platform that can carry a path is a publish that can write outside
// the store, and a download that can read outside it.
func TestATargetThatIsNotATargetIsRefused(t *testing.T) {
	root := t.TempDir()
	mux := connectorProgramTestMux(root, false, "t1")
	for _, bad := range []string{"../../etc", "linux/../..", ".."} {
		body := []byte("x")
		if rr := publishConnectorProgram(t, mux, bad, "amd64", body, sha256Of(body)); rr.Code != http.StatusBadRequest {
			t.Fatalf("%q was accepted: %d %s", bad, rr.Code, rr.Body.String())
		}
	}
	// Control: a real target name is accepted, so the refusals above are about the names and not the route.
	body := []byte("x")
	if rr := publishConnectorProgram(t, mux, "linux", "amd64", body, sha256Of(body)); rr.Code != 200 {
		t.Fatalf("the control must pass: %d %s", rr.Code, rr.Body.String())
	}
}

// ★★★ A LANE NOTHING SETS IS DARK. The installer generates deployments that pass -state-dir and nothing else;
// a connector-program directory that needed its own flag would be absent on every one of them, and the screen
// would offer a download that cannot exist.
func TestTheProgramDirectoryDefaultsUnderTheStateDirectory(t *testing.T) {
	if got := resolveConnectorProgramDir("", "/var/lib/dsse"); got != filepath.Join("/var/lib/dsse", "connector-programs") {
		t.Fatalf("got %q", got)
	}
	if got := resolveConnectorProgramDir("/srv/programs", "/var/lib/dsse"); got != "/srv/programs" {
		t.Fatalf("an operator's own choice must win: %q", got)
	}
	if got := resolveConnectorProgramDir("", ""); got != "" {
		t.Fatalf("with nothing to default under, there is nothing: %q", got)
	}
}

// ★★★ THE DEPLOYMENT'S OWN PROGRAM IS AVAILABLE TO EVERY ORGANIZATION IT SERVES. Seeding into one tenant's
// directory would give the first organization a working "Add connector" and every later one a screen saying
// there is nothing to put on the machine — a difference invisible from the side that works.
func TestTheDeploymentsOwnProgramIsOfferedToEveryOrganization(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, connectorProgramDeploymentScope, "linux-amd64")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	body := []byte("the deployment's own")
	if err := os.WriteFile(filepath.Join(dir, connectorProgramBytesName), body, 0o640); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(connectorProgramMeta{Platform: "linux", Arch: "amd64",
		FileName: "dsse-connector-linux-amd64.tar.gz", SHA256: sha256Of(body), Size: int64(len(body))})
	if err := os.WriteFile(filepath.Join(dir, connectorProgramMetaName), meta, 0o640); err != nil {
		t.Fatal(err)
	}

	for _, tenant := range []string{"t1", "t2", "an-organization-onboarded-later"} {
		mux := connectorProgramTestMux(root, false, tenant)
		list := httptest.NewRecorder()
		mux.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
		if !strings.Contains(list.Body.String(), "linux") {
			t.Fatalf("%s sees no program: %s", tenant, list.Body.String())
		}
		get := httptest.NewRecorder()
		mux.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/admin/connector-program?platform=linux&arch=amd64", nil))
		if get.Code != 200 || get.Body.String() != string(body) {
			t.Fatalf("%s could not take it: %d", tenant, get.Code)
		}
	}

	// ★ AND AN OPERATOR'S PUBLISH FOR ONE ORGANIZATION WINS FOR THAT ORGANIZATION ONLY.
	theirs := []byte("published for t1")
	if rr := publishConnectorProgram(t, connectorProgramTestMux(root, false, "t1"),
		"linux", "amd64", theirs, sha256Of(theirs)); rr.Code != 200 {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	one := httptest.NewRecorder()
	connectorProgramTestMux(root, false, "t1").ServeHTTP(one,
		httptest.NewRequest(http.MethodGet, "/admin/connector-program?platform=linux&arch=amd64", nil))
	if one.Body.String() != string(theirs) {
		t.Fatalf("t1 did not get its own: %q", one.Body.String())
	}
	other := httptest.NewRecorder()
	connectorProgramTestMux(root, false, "t2").ServeHTTP(other,
		httptest.NewRequest(http.MethodGet, "/admin/connector-program?platform=linux&arch=amd64", nil))
	if other.Body.String() != string(body) {
		t.Fatalf("t2 got something other than the deployment's own: %q", other.Body.String())
	}
}

// The seed publishes once, never overwrites, and refuses to call a half-set of programs "the program".
func TestSeedingPublishesTheProgramsBesideThisBinaryAndFollowsTheBuild(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	connector := filepath.Join(bin, "dsse-connector")
	installer := filepath.Join(bin, "dsse-connector-install")
	if err := os.WriteFile(connector, []byte("connector bytes"), 0o755); err != nil {
		t.Fatal(err)
	}

	// ★ WITHOUT THE INSTALLER THERE IS NOTHING WORTH HANDING OVER: a customer given only dsse-connector is
	// back on the command line this whole change removed.
	seedConnectorProgramFromThisImage(root, []string{connector, installer}, "linux", "amd64")
	if _, ok := readConnectorProgramMeta(filepath.Join(root, connectorProgramDeploymentScope, "linux-amd64")); ok {
		t.Fatalf("a package with no installer in it was published")
	}

	if err := os.WriteFile(installer, []byte("installer bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	seedConnectorProgramFromThisImage(root, []string{connector, installer}, "linux", "amd64")
	first, ok := readConnectorProgramMeta(filepath.Join(root, connectorProgramDeploymentScope, "linux-amd64"))
	if !ok || first.Size == 0 || len(first.SHA256) != 64 {
		t.Fatalf("nothing was published: %+v", first)
	}
	if first.FileName != "dsse-connector-linux-amd64.tar.gz" {
		t.Fatalf("the download has no usable name: %q", first.FileName)
	}

	// Running again on the SAME build changes nothing: the seed is idempotent, and a deployment restarting
	// must not churn the file every time.
	seedConnectorProgramFromThisImage(root, []string{connector, installer}, "linux", "amd64")
	again, _ := readConnectorProgramMeta(filepath.Join(root, connectorProgramDeploymentScope, "linux-amd64"))
	if again.SHA256 != first.SHA256 || again.PublishedAt != first.PublishedAt {
		t.Fatalf("the seed rewrote an identical program")
	}

	// ★★★ BUT A DEPLOYMENT THAT UPGRADES HANDS OUT WHAT IT NOW RUNS. Keeping the previous build here gives
	// every customer a connector older than the Edge it enrols into, silently and for ever. Measured on the
	// release lab: the fleet was on one build and the screen was offering an archive from the one before.
	// The stamp is the build, so this stands in for "the image changed".
	stale := connectorProgramMeta{Platform: "linux", Arch: "amd64", FileName: first.FileName,
		SHA256: first.SHA256, Size: first.Size, Version: "0.0.0-dev+anolderbuild",
		PublishedAt: first.PublishedAt, PublishedBy: "this deployment"}
	body, _ := json.MarshalIndent(stale, "", "  ")
	if err := os.WriteFile(filepath.Join(root, connectorProgramDeploymentScope, "linux-amd64",
		connectorProgramMetaName), body, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installer, []byte("a different build"), 0o755); err != nil {
		t.Fatal(err)
	}
	seedConnectorProgramFromThisImage(root, []string{connector, installer}, "linux", "amd64")
	refreshed, _ := readConnectorProgramMeta(filepath.Join(root, connectorProgramDeploymentScope, "linux-amd64"))
	if refreshed.Version == "0.0.0-dev+anolderbuild" || refreshed.SHA256 == first.SHA256 {
		t.Fatalf("the deployment went on handing out a program from another build: %+v", refreshed)
	}
}

// ★ AND AN OPERATOR'S OWN PUBLISH IS NEVER TOUCHED BY THE SEED. The refresh above applies to the half that is
// not a choice; the half an operator published FOR an organization is one, and it lives elsewhere.
func TestSeedingNeverTouchesWhatAnOperatorPublished(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	for _, n := range []string{"dsse-connector", "dsse-connector-install"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte(n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	theirs := []byte("published by an operator for t1")
	if rr := publishConnectorProgram(t, connectorProgramTestMux(root, false, "t1"),
		"linux", "amd64", theirs, sha256Of(theirs)); rr.Code != 200 {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	seedConnectorProgramFromThisImage(root, []string{filepath.Join(bin, "dsse-connector"),
		filepath.Join(bin, "dsse-connector-install")}, "linux", "amd64")

	dir, err := connectorProgramDir(root, "t1", "linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := readConnectorProgramMeta(dir)
	if !ok || m.SHA256 != sha256Of(theirs) {
		t.Fatalf("the seed replaced what an operator published: %+v", m)
	}
}

func TestConnectorProgramCatalogueRefusesIncompleteStorage(t *testing.T) {
	for _, kind := range []string{"scope-file", "missing-meta", "broken-meta", "wrong-target", "bad-digest", "negative-size", "unsafe-name", "missing-bytes", "short-bytes"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			mux := connectorProgramTestMux(root, false, "t1")
			body := []byte("original-program")
			if rr := publishConnectorProgram(t, mux, "linux", "amd64", body, sha256Of(body)); rr.Code != 200 {
				t.Fatal(rr.Body.String())
			}
			dir, _ := connectorProgramDir(root, "t1", "linux-amd64")
			metadata := filepath.Join(dir, connectorProgramMetaName)
			raw, err := os.ReadFile(metadata)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "scope-file":
				must(os.RemoveAll(filepath.Dir(dir)))
				must(os.WriteFile(filepath.Dir(dir), []byte("broken"), 0600))
			case "missing-meta":
				must(os.Remove(metadata))
			case "broken-meta":
				must(os.WriteFile(metadata, []byte("{"), 0600))
			case "missing-bytes":
				must(os.Remove(filepath.Join(dir, connectorProgramBytesName)))
			case "short-bytes":
				must(os.WriteFile(filepath.Join(dir, connectorProgramBytesName), []byte("short"), 0600))
			default:
				var m connectorProgramMeta
				must(json.Unmarshal(raw, &m))
				switch kind {
				case "wrong-target":
					m.Arch = "arm64"
				case "bad-digest":
					m.SHA256 = "bad"
				case "negative-size":
					m.Size = -1
				case "unsafe-name":
					m.FileName = "../program"
				}
				changed, _ := json.Marshal(m)
				must(os.WriteFile(metadata, changed, 0600))
			}
			// A healthy shared seed must not hide a broken override as an apparent fallback.
			seed := filepath.Join(root, "deployment", "linux-amd64")
			must(os.MkdirAll(seed, 0700))
			must(os.WriteFile(filepath.Join(seed, connectorProgramMetaName), raw, 0600))
			must(os.WriteFile(filepath.Join(seed, connectorProgramBytesName), body, 0600))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
			if rr.Code != 503 || strings.Contains(rr.Body.String(), root) || strings.Contains(rr.Body.String(), "programs\"") {
				t.Fatalf("unverified catalogue: %d %s", rr.Code, rr.Body.String())
			}
			other := httptest.NewRecorder()
			connectorProgramTestMux(root, false, "t2").ServeHTTP(other, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
			if other.Code != 200 || !strings.Contains(other.Body.String(), "linux") {
				t.Fatalf("foreign damage leaked: %d %s", other.Code, other.Body.String())
			}
			// Explicit repair restores the same record; reads must not repair or delete it themselves.
			if kind == "scope-file" {
				must(os.Remove(filepath.Dir(dir)))
			}
			must(os.MkdirAll(dir, 0700))
			must(os.WriteFile(metadata, raw, 0600))
			must(os.WriteFile(filepath.Join(dir, connectorProgramBytesName), body, 0600))
			recovered := httptest.NewRecorder()
			mux.ServeHTTP(recovered, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
			if recovered.Code != 200 || recovered.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("retry: %d %s", recovered.Code, recovered.Body.String())
			}
			after, _ := os.ReadFile(metadata)
			if string(after) != string(raw) {
				t.Fatal("read changed metadata")
			}
		})
	}
}

func TestConnectorProgramCatalogueDistinguishesMissingAndUnavailableRoots(t *testing.T) {
	for _, kind := range []string{"fresh", "missing", "unconfigured", "root-file", "deployment-file", "deployment-corrupt"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			code := 200
			switch kind {
			case "missing":
				root = filepath.Join(root, "not-created")
			case "unconfigured":
				root = ""
				code = 503
			case "root-file":
				root = filepath.Join(root, "file")
				if err := os.WriteFile(root, []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
				code = 503
			case "deployment-file":
				if err := os.WriteFile(filepath.Join(root, "deployment"), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
				code = 503
			case "deployment-corrupt":
				if err := os.MkdirAll(filepath.Join(root, "deployment", "linux-amd64"), 0700); err != nil {
					t.Fatal(err)
				}
				code = 503
			}
			rr := httptest.NewRecorder()
			connectorProgramTestMux(root, false, "t1").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/connector-programs", nil))
			if rr.Code != code {
				t.Fatalf("%d %s", rr.Code, rr.Body.String())
			}
			if code == 200 {
				var b struct {
					Programs []connectorProgramMeta `json:"programs"`
					Count    int                    `json:"count"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil || b.Programs == nil || len(b.Programs) != 0 || b.Count != 0 {
					t.Fatal(rr.Body.String())
				}
			}
		})
	}
}
