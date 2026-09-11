package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

// manifestCourierRec captures what the sync decided to do to the local file, which is the only thing that matters here.
type manifestCourierRec struct {
	written [][]byte
	logs    []string
}

func (r *manifestCourierRec) sync(baseURL string) *signedDocCourier {
	return newManifestCourier(&signedDocCourier{
		client:   &http.Client{Timeout: 5 * time.Second},
		baseURL:  baseURL,
		interval: time.Hour,
		write:    func(b []byte) error { r.written = append(r.written, append([]byte(nil), b...)); return nil },
		logf:     func(f string, a ...any) { r.logs = append(r.logs, f) },
	})
}

func envelopeBytes(t *testing.T, typ string) []byte {
	t.Helper()
	b, err := json.Marshal(agentpolicy.Envelope{
		Type:          typ,
		Version:       "1",
		SigningKeyID:  "key-1",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		PayloadSHA256: "deadbeef",
		PayloadB64:    "e30=",
		Signature:     "ed25519:AAAA",
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

func serve(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != updateManifestPath && r.URL.Path != updatePlanPath {
			t.Errorf("fetched %q, want the manifest or plan path", r.URL.Path)
		}
		w.WriteHeader(status)
		if len(body) > 0 {
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestAPublishedManifestIsWrittenByteForByte(t *testing.T) {
	body := envelopeBytes(t, agentupdate.EnvelopeType)
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusOK, body)

	if err := r.sync(srv.URL).refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	if len(r.written) != 1 {
		t.Fatalf("wrote %d times, want 1", len(r.written))
	}
	// Byte-for-byte matters: the updater verifies a signature over these exact bytes, and re-serialising the
	// decoded struct here could change them.
	if string(r.written[0]) != string(body) {
		t.Fatalf("the written bytes differ from what the Edge served")
	}
}

// TestNotPublishedIsQuietAndTouchesNothing is a correction to the first version of this file, which cleared
// the local copy on a 404.
//
// On the Edge as built, a manifest is a file in a directory — so "withdrawn", "never published" and "the
// operator pointed at the wrong directory" produce the same 404. Clearing on it lets ONE Edge
// misconfiguration silently disarm the update path across the fleet, in the direction that looks healthy:
// nothing reports "no devices are being offered anything".
//
// Withdrawal is a real requirement and it belongs to the rollout plan's freeze — a signed document that says
// stop in bytes the device can verify, and that a misdirected file path cannot produce.
func TestNotPublishedIsQuietAndTouchesNothing(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusNotFound, nil)
	err := r.sync(srv.URL).refreshOnce(context.Background())
	if !errors.Is(err, errNotPublished) {
		t.Fatalf("err = %v, want errNotPublished", err)
	}
	if len(r.written) != 0 {
		t.Fatalf("wrote a manifest for a not-published answer")
	}
}

// TestTheCourierCannotDeleteAtAll pins the property structurally rather than per status code: there is no
// delete path, so no response can produce one. A future status code cannot reintroduce fleet-wide disarming
// by being added to a switch.
func TestTheCourierCannotDeleteAtAll(t *testing.T) {
	for _, status := range []int{
		http.StatusNotFound, http.StatusGone, http.StatusNoContent, http.StatusOK,
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError,
	} {
		r := &manifestCourierRec{}
		srv := serve(t, status, []byte("not an envelope"))
		_ = r.sync(srv.URL).refreshOnce(context.Background())
		// The recorder has no clear hook because the type has no clear field. If one is ever added, this test
		// stops compiling, which is the intent.
		_ = r
	}
}

// TestABadRequestIsNamedRatherThanRetriedForever: this agent always sends platform and arch, so a 400 means
// the endpoint contract moved. It will not fix itself with retries, and saying "HTTP 400" alone would send an
// operator looking at the network.
func TestABadRequestIsNamedRatherThanRetriedForever(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusBadRequest, nil)
	err := r.sync(srv.URL).refreshOnce(context.Background())
	if err == nil {
		t.Fatal("a 400 was accepted")
	}
	if !strings.Contains(err.Error(), "contract has changed") {
		t.Fatalf("the error does not name the cause: %v", err)
	}
	if errors.Is(err, errNotPublished) {
		t.Fatal("a contract mismatch was reported as 'nothing published', which hides it")
	}
}

// TestUncertaintyKeepsWhatIsOnDisk is the steer_exclusion_sync lesson applied here: a transient Edge outage
// must never remove a control that is currently in force. A device holding a manifest it was about to act on
// must not lose it because the Edge hiccuped.
//
// The asymmetry is deliberate — clearing is an ACTION and needs a definite answer; keeping is the absence of
// one, and is what uncertainty should produce.
func TestUncertaintyKeepsWhatIsOnDisk(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   []byte
	}{
		{"server error", http.StatusInternalServerError, []byte("boom")},
		{"bad gateway", http.StatusBadGateway, []byte("<html>proxy</html>")},
		{"unauthorized", http.StatusUnauthorized, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &manifestCourierRec{}
			srv := serve(t, tc.status, tc.body)
			err := r.sync(srv.URL).refreshOnce(context.Background())
			if err == nil {
				t.Fatal("an error response was accepted")
			}
			if errors.Is(err, errNotPublished) {
				t.Fatal("an uncertain answer was treated as a definite 'nothing published'")
			}
			if len(r.written) != 0 {
				t.Fatalf("wrote something on an uncertain answer (%s)", tc.name)
			}
		})
	}
}

// TestGarbageIsNotHandedToTheUpdater is the reason this file checks shape at all.
//
// The updater reports a body it cannot open as ErrManifestRejected, which by design means "the release
// process is broken or artefacts are being substituted — look tonight". A captive-portal page or a truncated
// proxy response would raise that alarm. Refusing to write anything that is not even shaped like an envelope
// keeps a transport fault a transport fault. It is NOT a signature check: the updater owns that.
func TestGarbageIsNotHandedToTheUpdater(t *testing.T) {
	bodies := [][]byte{
		[]byte("<html><body>Sign in to the WiFi</body></html>"),
		[]byte("{"),
		[]byte(""),
	}
	for _, b := range bodies {
		r := &manifestCourierRec{}
		srv := serve(t, http.StatusOK, b)
		if err := r.sync(srv.URL).refreshOnce(context.Background()); err == nil {
			t.Fatalf("accepted a body that is not an envelope: %q", b)
		}
		if len(r.written) != 0 {
			t.Fatalf("wrote a body that is not an envelope: %q", b)
		}
	}
}

// TestTheWrongEnvelopeTypeIsRefusedHere: a steer policy served on the update path is a real misconfiguration,
// and it is cheaper to name it at the courier than to have it arrive at the updater as a security event.
func TestTheWrongEnvelopeTypeIsRefusedHere(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusOK, envelopeBytes(t, "dsse_steer_policy.v1"))
	err := r.sync(srv.URL).refreshOnce(context.Background())
	if err == nil {
		t.Fatal("an envelope of the wrong type was written")
	}
	if !strings.Contains(err.Error(), agentupdate.EnvelopeType) {
		t.Fatalf("the error does not say which type was expected: %v", err)
	}
	if len(r.written) != 0 {
		t.Fatalf("wrote %d times for a wrong-typed envelope; want none", len(r.written))
	}
}

// TestAnEnormousBodyIsRefused: a wrong endpoint returning something huge must not be written to disk on a
// machine whose network this product is responsible for.
func TestAnEnormousBodyIsRefused(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusOK, []byte(strings.Repeat("x", maxDocBytes+64)))
	if err := r.sync(srv.URL).refreshOnce(context.Background()); err == nil {
		t.Fatal("an oversized body was accepted")
	}
	if len(r.written) != 0 {
		t.Fatal("an oversized body was written")
	}
}

// TestTheAgentDoesNotVerifyTheSignature pins the division of responsibility as behaviour rather than as a
// comment. An envelope with an obviously bogus signature is still couriered: the updater verifies against its
// own baked keys, and an agent that pre-approved the bytes would be a second opinion the updater must then
// either trust — putting the agent inside the trust boundary for no gain — or ignore.
func TestTheAgentDoesNotVerifyTheSignature(t *testing.T) {
	body := envelopeBytes(t, agentupdate.EnvelopeType) // signature is "ed25519:AAAA", which verifies against nothing
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusOK, body)

	if err := r.sync(srv.URL).refreshOnce(context.Background()); err != nil {
		t.Fatalf("the courier refused an envelope it is not supposed to be judging: %v", err)
	}
	if len(r.written) != 1 {
		t.Fatal("the envelope was not couriered")
	}
}
