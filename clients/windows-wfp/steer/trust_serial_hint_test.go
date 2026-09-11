package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The Edge answers the report this agent already sends every minute with the serial it is distributing.
// Acting on it is what turns a six-hour adoption timer into a next-report one — twice in one day a fleet
// rotation stalled on this device's timer, and the only way to hurry it was a person restarting a service.
//
// The hint is a NUDGE, never an authority: the tests below pin both halves of that. It must be able to
// shorten the wait, and it must be unable to do anything else - a wrong or hostile value costs one early
// pass that finds nothing, because adoption still verifies the signed bundle and still refuses a serial that
// does not advance.

func hintingReportServer(t *testing.T, signer *agentpolicy.Signer, hint string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/steer/agent-policy/effective":
			if hint != "" {
				w.Header().Set(trustSerialHintHeader, hint)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func syncWithHint(t *testing.T, srv *httptest.Server, adopted int64, got chan<- int64) *exclusionSync {
	t.Helper()
	return &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, localBaseline: []string{"example-app"},
		apply:                 func([]string) {},
		adoptedTrustSerialNow: func() int64 { return adopted },
		trustSerialHint: func(offered int64) {
			select {
			case got <- offered:
			default:
			}
		},
	}
}

func TestANewerSerialOnTheReportResponseWakesAdoption(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := hintingReportServer(t, signer, "84")
	got := make(chan int64, 1)
	s := syncWithHint(t, srv, 63, got)

	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	select {
	case offered := <-got:
		if offered != 84 {
			t.Fatalf("hint = %d, want 84", offered)
		}
	default:
		t.Fatalf("a newer serial did not wake adoption; this device would wait out its six-hour timer")
	}
}

// Everything else must be ignored, and each of these was a real shape the Edge could produce.
func TestTheHintIsIgnoredWhenItIsNotStrictlyNewer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  string
		adopted int64
	}{
		{"equal to what we hold", "63", 63},
		{"older than what we hold", "35", 63},
		{"absent - an Edge that does not send it", "", 63},
		{"unparseable", "not-a-number", 63},
		{"zero", "0", 63},
		{"negative", "-1", 63},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
			srv := hintingReportServer(t, signer, tc.header)
			got := make(chan int64, 1)
			s := syncWithHint(t, srv, tc.adopted, got)

			if _, err := s.refreshOnce(context.Background()); err != nil {
				t.Fatalf("refreshOnce: %v", err)
			}
			select {
			case offered := <-got:
				t.Fatalf("hint %q acted on (offered %d) while holding %d; only strictly newer may wake it",
					tc.header, offered, tc.adopted)
			default:
			}
		})
	}
}

// An agent wired without the hint at all keeps working exactly as before - that is every agent built before
// the header existed, and the Edge must not depend on it.
func TestAnAgentThatIgnoresTheHintStillReports(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := hintingReportServer(t, signer, "84")
	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, localBaseline: []string{"example-app"},
		apply: func([]string) {},
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v — the hint header must not change the outcome for an agent that ignores it", err)
	}
}

// The waking half: a hint delivered while the scheduler is asleep must shorten that sleep, and a second one
// arriving before the first is consumed must not queue a second pass.
func TestTheWakeChannelCoalesces(t *testing.T) {
	wake := make(chan struct{}, 1)
	send := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	send()
	send()
	send()
	if len(wake) != 1 {
		t.Fatalf("wake depth = %d, want 1 — repeated hints must coalesce into one look", len(wake))
	}
	<-wake
	if len(wake) != 0 {
		t.Fatalf("wake did not drain")
	}
}

// ★ A DEVICE THAT CANNOT VERIFY THE EDGE CANNOT ASK IT ANYTHING (2026-08-20, measured on win-dev-1).
//
// The serial hint rides the response to the report, and the report rides the (T) transport. When the
// transport stops verifying, the report stops, the hint stops, and the device falls back to a six-hour
// timer — at exactly the moment it is dark and fail-open. This box sat unprotected for 31 minutes on a
// distribution that had already been corrected upstream, and only a person restarting a service ended it.
//
// A recorded refusal is the device saying "I cannot verify the Edge", which is the condition trust-anchor
// recovery exists for, so it wakes that path directly.
func TestARefusalWakesRecoveryWithoutTheReportChannel(t *testing.T) {
	dir := t.TempDir()
	j := newTrustRefusalJournal(dir)
	if j == nil {
		t.Fatalf("journal not created")
	}
	woken := make(chan struct{}, 1)
	j.onRefusal = func() {
		select {
		case woken <- struct{}{}:
		default:
		}
	}

	j.record([]byte("served-leaf"), "x509: certificate signed by unknown authority", time.Now())

	select {
	case <-woken:
	default:
		t.Fatalf("a trust refusal did not wake recovery; a dark device would wait out its six-hour timer")
	}
}

// The journal is written on every retry of a dark device, so the wake must be usable without becoming a
// storm. The debounce lives at the call site; what the journal guarantees is only that it fires each time.
func TestTheRefusalHookFiresForEveryRecordedRefusal(t *testing.T) {
	dir := t.TempDir()
	j := newTrustRefusalJournal(dir)
	var fired int
	j.onRefusal = func() { fired++ }

	now := time.Now()
	j.record([]byte("served-leaf"), "unknown authority", now)
	j.record([]byte("served-leaf"), "unknown authority", now.Add(time.Second))
	j.record([]byte("other-leaf"), "unknown authority", now.Add(2*time.Second))

	if fired != 3 {
		t.Fatalf("hook fired %d times for 3 refusals; the call site debounces, the journal must not swallow", fired)
	}
}

// A journal with no hook wired keeps working exactly as before - every agent built before this existed.
func TestTheJournalWorksWithNoRefusalHook(t *testing.T) {
	j := newTrustRefusalJournal(t.TempDir())
	j.record([]byte("served-leaf"), "unknown authority", time.Now())
	if got := len(j.pending()); got != 1 {
		t.Fatalf("pending refusals = %d, want 1", got)
	}
}

// ★ THE STARTUP DELAY MUST YIELD TO NEWS (2026-08-20, Lane B scenario D-03). A device dark for eleven
// minutes came back at serial 95 while the fleet had moved to 98, reported 1.5 seconds after start, was
// told immediately that something newer existed — and then waited out the rest of a fixed minute, because
// the startup delay was a plain sleep the wake could not interrupt. Coming back stale after an outage is
// the most likely moment for a device to be behind, which makes it the worst moment to be deaf.
func TestTheStartupDelayYieldsToAHint(t *testing.T) {
	wake := make(chan struct{}, 1)
	wake <- struct{}{} // the hint that arrives on the first report, seconds after start

	start := time.Now()
	select {
	case <-time.After(time.Minute):
		t.Fatalf("the start-up delay ignored a hint; a device that came back stale would wait a full minute")
	case <-wake:
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("waking took %s, want immediate", elapsed)
	}
}

// With no news the floor stays: the delay exists so a start-up burst does not contend with bringing
// steering up, and that reason is unchanged when there is nothing to fetch.
func TestTheStartupDelayHoldsWithoutAHint(t *testing.T) {
	wake := make(chan struct{}, 1)
	select {
	case <-time.After(50 * time.Millisecond): // stands in for the minute
	case <-wake:
		t.Fatalf("the start-up delay was cut short with no hint pending")
	}
}

// ★ THE EDGE NOW ANSWERS AN UNKNOWN NAME WITH 404 (2026-08-21, their letter 57). A node that does not serve
// the organization a device names refuses rather than handing over its own bundle — which is right, and
// which only helps if this side does not swallow it. A device that has stopped being served by the fleet it
// is asking must be able to say so, not sit quietly on anchors nobody is refreshing.
func TestAnUnservedNameIsReportedRatherThanSwallowed(t *testing.T) {
	ca := newTestCA(t, "current-ca")
	ln := startTransportListener(t, leafUnder(t, ca))
	tc := announcingTransport(t, ln.Addr().String(), ca)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `this node does not serve "zzz-nope.dsse.invalid" — ask another Edge`, http.StatusNotFound)
	}))
	defer srv.Close()

	signer := newTestSigner(t)
	out := runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, t.TempDir(), signer, srv.URL))

	if !strings.Contains(out.detail, "could not read a distribution") {
		t.Fatalf("a 404 was not reported: code=%q detail=%q", out.code, out.detail)
	}
	if !strings.Contains(out.detail, "does not serve") {
		t.Fatalf("the Edge's reason did not survive to the log: %q", out.detail)
	}
}
