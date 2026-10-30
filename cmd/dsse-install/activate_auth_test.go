package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
)

type activationFixture struct {
	mu               sync.Mutex
	store            *authrollout.Store
	census           authrollout.Manifest
	server           *httptest.Server
	edges            []authInstallEdge
	posts, edgeReads int
	getState         func(authrollout.State) authrollout.State
	status           func(string, map[string]any)
	conflict         bool
	readIdentity     map[string]any
}

func newActivationFixture(t *testing.T) *activationFixture {
	t.Helper()
	f := &activationFixture{store: authrollout.NewStore(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "rollout.json")})}
	f.census = authrollout.Manifest{Deployment: "example.test", Generation: 1}
	for i, role := range []string{"cp", "edge", "edge"} {
		f.census.Members = append(f.census.Members, authrollout.Member{ID: fmt.Sprintf("member-%d", i), Role: role, Version: "baseline", CertificateSHA256: fmt.Sprintf("%064x", i+1)})
	}
	if err := f.store.Configure(context.Background(), 0, f.census); err != nil {
		t.Fatal(err)
	}
	f.report(t, time.Now())
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		expected := "Bearer disposable-test-token"
		if r.URL.Path == "/admin/session" || strings.HasSuffix(r.URL.Path, "/admin/config-sync-status") {
			expected = "Bearer read-only-test-token"
		}
		if r.Header.Get("Authorization") != expected {
			w.WriteHeader(401)
			return
		}
		state, err := f.store.Read()
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		switch {
		case r.URL.Path == "/admin/session" && r.Method == "GET":
			if f.readIdentity != nil {
				json.NewEncoder(w).Encode(f.readIdentity)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"auth_method": "admin_api_token", "api_token_id": "read-token-id", "scopes": []string{"admin.state.read"}})
			}
		case r.URL.Path == "/admin/auth-rollout" && r.Method == "GET":
			if f.getState != nil {
				state = f.getState(state)
			}
			json.NewEncoder(w).Encode(state)
		case r.URL.Path == "/admin/auth-rollout/activate" && r.Method == "POST":
			f.posts++
			if f.conflict {
				f.conflict = false
				w.WriteHeader(409)
				return
			}
			var input struct {
				Generation uint64
				Features   []string
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if err := f.store.Activate(r.Context(), input.Generation, input.Features, time.Now()); err != nil {
				t.Error(err)
				w.WriteHeader(409)
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"activated": true})
		case strings.HasSuffix(r.URL.Path, "/admin/config-sync-status"):
			f.edgeReads++
			id := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
			raw, _ := json.Marshal(state.Manifest)
			hash := sha256.Sum256(raw)
			status := map[string]any{"state_available": true, "node_id": id, "generation": state.Manifest.Generation, "revision": state.Revision, "complete": state.Complete, "enabled_features": state.Enabled, "census_sha256": hex.EncodeToString(hash[:])}
			if f.status != nil {
				f.status(id, status)
			}
			json.NewEncoder(w).Encode(map[string]any{"auth_rollout": status})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.server.Close)
	for _, m := range f.census.Members {
		if m.Role == "edge" {
			f.edges = append(f.edges, authInstallEdge{m.ID, f.server.URL + "/" + m.ID})
		}
	}
	return f
}

func (f *activationFixture) report(t *testing.T, now time.Time) {
	t.Helper()
	features := append(slices.Clone(sharedFleetAuthFeatures), authrollout.DeviceUserFeature)
	for _, m := range f.census.Members {
		if err := f.store.Record(context.Background(), m.CertificateSHA256, authrollout.Report{NodeID: m.ID, Generation: f.census.Generation, Version: "reviewed", Features: features}, now); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *activationFixture) activate(ctx context.Context) (authInstallResult, error) {
	return activateFleetAuthentication(ctx, f.server.Client(), f.server.URL, "disposable-test-token", "read-only-test-token", f.census, f.edges, sharedFleetAuthFeatures, time.Millisecond)
}

type activationRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f activationRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type cancelAfterEdgeStatusBody struct {
	io.ReadCloser
	reachedEOF bool
	onClose    func()
}

func (b *cancelAfterEdgeStatusBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.reachedEOF = true
	}
	return n, err
}

func (b *cancelAfterEdgeStatusBody) Close() error {
	err := b.ReadCloser.Close()
	if b.reachedEOF {
		b.onClose()
	}
	return err
}

func TestInstallAuthenticationRetainsFeaturesWaitsForEveryEdgeAndResumes(t *testing.T) {
	f := newActivationFixture(t)
	if err := f.store.Activate(context.Background(), 1, []string{authrollout.EvidenceFeature, authrollout.DeviceUserFeature}, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.conflict = true
	// A committed CP response alone is insufficient; one Edge has not applied it.
	f.status = func(id string, status map[string]any) {
		if id == "member-2" {
			status["state_available"] = false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := f.activate(ctx)
	if err == nil || result.Phase != "waiting-for-edge-application" || !slices.Contains(result.Waiting, "member-2") {
		t.Fatalf("premature success: %+v %v", result, err)
	}
	if f.postCount() != 2 {
		t.Fatalf("conflict not retried once: %d", f.postCount())
	}
	state, _ := f.store.Read()
	if !slices.Contains(state.Enabled, authrollout.DeviceUserFeature) {
		t.Fatal("existing opt-in feature was dropped")
	}
	f.mu.Lock()
	f.status = nil
	f.mu.Unlock()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	result, err = f.activate(ctx2)
	if err != nil || result.Phase != "ready" || result.AppliedEdges != 2 || f.postCount() != 2 {
		t.Fatalf("resume repeated mutation or missed Edge: %+v %v", result, err)
	}
}

func TestInstallAuthenticationNeverActivatesIncompleteOrStaleCensus(t *testing.T) {
	for _, kind := range []string{"missing", "stale", "wrong-generation"} {
		t.Run(kind, func(t *testing.T) {
			f := newActivationFixture(t)
			f.getState = func(s authrollout.State) authrollout.State {
				switch kind {
				case "missing":
					delete(s.Observed, "member-2")
				case "stale":
					for id, o := range s.Observed {
						o.ReceivedAt = time.Now().Add(-authrollout.FreshFor)
						s.Observed[id] = o
					}
				case "wrong-generation":
					s.Manifest.Generation++
				}
				return s
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			result, err := f.activate(ctx)
			if err == nil || result.Phase == "ready" || f.postCount() != 0 {
				t.Fatalf("unsafe activation: %+v posts=%d error=%v", result, f.postCount(), err)
			}
		})
	}
}

func TestInstallAuthenticationRejectsMissingTargetsUntrustedTLSAndRedirects(t *testing.T) {
	f := newActivationFixture(t)
	f.edges = f.edges[:1]
	if _, err := f.activate(context.Background()); err == nil || f.postCount() != 0 {
		t.Fatal("accepted an Edge subset")
	}
	f.edges = append(f.edges, authInstallEdge{"member-2", f.server.URL + "/member-2"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := activateFleetAuthentication(ctx, http.DefaultClient, f.server.URL, "disposable-test-token", "read-only-test-token", f.census, f.edges, sharedFleetAuthFeatures, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "TLS verification failed") {
		t.Fatalf("untrusted TLS was retried/bypassed: %v", err)
	}
	leaked := false
	trap := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer trap.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, trap.URL, 307) }))
	defer redirect.Close()
	_, err = activateFleetAuthentication(ctx, redirect.Client(), redirect.URL, "disposable-test-token", "read-only-test-token", f.census, f.edges, sharedFleetAuthFeatures, time.Millisecond)
	if err == nil || leaked {
		t.Fatal("followed credential-bearing redirect")
	}
}

func TestInstallAuthenticationRejectsWrongAppliedIdentityAndCensus(t *testing.T) {
	for _, kind := range []string{"identity", "manifest", "incomplete", "generation", "features", "revision"} {
		t.Run(kind, func(t *testing.T) {
			f := newActivationFixture(t)
			f.status = func(_ string, s map[string]any) {
				switch kind {
				case "identity":
					s["node_id"] = "another-edge"
				case "manifest":
					s["census_sha256"] = "wrong"
				case "incomplete":
					s["complete"] = false
				case "generation":
					s["generation"] = uint64(2)
				case "features":
					s["enabled_features"] = []string{authrollout.EvidenceFeature}
				case "revision":
					s["revision"] = uint64(0)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Stop only after the second Edge's status response has been fully
			// read and closed. A short wall-clock timeout can fire while the CP
			// is still confirming activation under package-suite load.
			client := f.server.Client()
			base := client.Transport
			statusRead := make(chan struct{})
			var once sync.Once
			client.Transport = activationRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
				response, err := base.RoundTrip(req)
				if err == nil && req.URL.Path == "/member-2/admin/config-sync-status" && response.StatusCode == http.StatusOK {
					response.Body = &cancelAfterEdgeStatusBody{ReadCloser: response.Body, onClose: func() {
						once.Do(func() { close(statusRead); cancel() })
					}}
				}
				return response, err
			})
			r, err := activateFleetAuthentication(ctx, client, f.server.URL, "disposable-test-token", "read-only-test-token", f.census, f.edges, sharedFleetAuthFeatures, time.Millisecond)
			select {
			case <-statusRead:
			default:
				t.Fatal("did not inspect both Edge status responses before cancellation")
			}
			if err == nil || r.Phase != "waiting-for-edge-application" || r.AppliedEdges != 0 || !slices.Equal(r.Waiting, []string{"member-1", "member-2"}) {
				t.Fatalf("accepted wrong adoption: %+v %v", r, err)
			}
		})
	}
}

func (f *activationFixture) postCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.posts }

func TestInstallActivationRejectsBroadOrUnidentifiableReadCredentialBeforeEdgeContact(t *testing.T) {
	for _, kind := range []string{"broad", "missing-scope", "session", "unnamed", "operator-reused"} {
		t.Run(kind, func(t *testing.T) {
			f := newActivationFixture(t)
			f.readIdentity = map[string]any{"auth_method": "admin_api_token", "api_token_id": "reader-id", "scopes": []string{"admin.state.read"}}
			readToken := "read-only-test-token"
			switch kind {
			case "broad":
				f.readIdentity["scopes"] = []string{"admin.state.read", "admin.policy.write"}
			case "missing-scope":
				f.readIdentity["scopes"] = []string{}
			case "session":
				f.readIdentity["auth_method"] = "admin_session"
			case "unnamed":
				delete(f.readIdentity, "api_token_id")
			case "operator-reused":
				readToken = "disposable-test-token"
			}
			_, err := activateFleetAuthentication(context.Background(), f.server.Client(), f.server.URL, "disposable-test-token", readToken, f.census, f.edges, sharedFleetAuthFeatures, time.Millisecond)
			if err == nil || f.postCount() != 0 || f.edgeReads != 0 {
				t.Fatal("unsafe read credential reached Edge or changed authority")
			}
		})
	}
}
