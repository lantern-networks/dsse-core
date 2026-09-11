package main

import (
	"bufio"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a hand-advanced clock so coalescing/TTL is tested deterministically (no sleeps).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// recordingLauncher counts launches per resource so the test can assert coalescing.
type recordingLauncher struct {
	mu    sync.Mutex
	calls map[string]int
	urls  map[string]string
}

func newRecordingLauncher() *recordingLauncher {
	return &recordingLauncher{calls: map[string]int{}, urls: map[string]string{}}
}

func (r *recordingLauncher) launch(resource, url string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[resource]++
	r.urls[resource] = url
}

func (r *recordingLauncher) count(resource string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[resource]
}

// newTestCoordinator wires a coordinator to a recording launcher + fake clock. The launch goroutine is
// awaited via a WaitGroup so assertions don't race the async dispatch.
func newTestCoordinator(ttl time.Duration) (*stepUpCoordinator, *recordingLauncher, *fakeClock, *sync.WaitGroup) {
	rl := newRecordingLauncher()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	wg := &sync.WaitGroup{}
	c := newStepUpCoordinator(ttl, func(resource, url string) {
		defer wg.Done()
		rl.launch(resource, url)
	}, nil)
	c.now = clk.now
	return c, rl, clk, wg
}

func TestStepUp_TriggerLaunchesOnce(t *testing.T) {
	c, rl, _, wg := newTestCoordinator(30 * time.Second)
	wg.Add(1)
	if !c.Trigger("10.0.0.5:445", "https://edge:8443/clientless/auth/start?return_to=10.0.0.5:445") {
		t.Fatal("first Trigger should launch")
	}
	wg.Wait()
	if got := rl.count("10.0.0.5:445"); got != 1 {
		t.Fatalf("want 1 launch, got %d", got)
	}
	if rl.urls["10.0.0.5:445"] == "" {
		t.Fatal("launcher should receive the portal URL")
	}
}

func TestStepUp_CoalescesBurstToSameResource(t *testing.T) {
	c, rl, clk, wg := newTestCoordinator(30 * time.Second)
	wg.Add(1) // only the first call should launch
	// A burst of blocked flows to the SAME resource within the window: portal opens exactly once.
	for i := 0; i < 5; i++ {
		c.Trigger("10.0.0.5:3389", "https://edge/portal")
		clk.add(time.Second) // still inside the 30s window
	}
	wg.Wait()
	if got := rl.count("10.0.0.5:3389"); got != 1 {
		t.Fatalf("burst should coalesce to 1 launch, got %d", got)
	}
}

func TestStepUp_DistinctResourcesEachPrompt(t *testing.T) {
	c, rl, _, wg := newTestCoordinator(30 * time.Second)
	wg.Add(2)
	c.Trigger("10.0.0.5:445", "https://edge/portal?a")
	c.Trigger("10.0.0.9:22", "https://edge/portal?b")
	wg.Wait()
	if rl.count("10.0.0.5:445") != 1 || rl.count("10.0.0.9:22") != 1 {
		t.Fatalf("distinct resources should each prompt once: %v", rl.calls)
	}
}

func TestStepUp_RePromptsAfterTTL(t *testing.T) {
	c, rl, clk, wg := newTestCoordinator(30 * time.Second)
	wg.Add(2) // first launch, then a re-prompt after the window elapses
	c.Trigger("10.0.0.5:445", "https://edge/portal")
	clk.add(31 * time.Second) // window elapsed -> the resource re-prompts
	c.Trigger("10.0.0.5:445", "https://edge/portal")
	wg.Wait()
	if got := rl.count("10.0.0.5:445"); got != 2 {
		t.Fatalf("want re-prompt after TTL (2 launches), got %d", got)
	}
}

func TestStepUp_NoOpWhenDisabledOrEmpty(t *testing.T) {
	// nil receiver: safe no-op (caller never has to guard).
	var nilCoord *stepUpCoordinator
	if nilCoord.Trigger("r", "https://x") {
		t.Fatal("nil coordinator must be a no-op")
	}
	// nil launcher (--stepup-portal=false analog): no-op.
	disabled := newStepUpCoordinator(time.Second, nil, nil)
	if disabled.Trigger("r", "https://x") {
		t.Fatal("nil launcher must be a no-op")
	}
	// empty URL (edge advertised no portal): no-op even with a real launcher.
	var launched int32
	withLauncher := newStepUpCoordinator(time.Second, func(string, string) { atomic.AddInt32(&launched, 1) }, nil)
	if withLauncher.Trigger("r", "   ") {
		t.Fatal("empty portal URL must be a no-op")
	}
	if atomic.LoadInt32(&launched) != 0 {
		t.Fatal("launcher must not be called for an empty URL")
	}
}

// TestReadCONNECTStatus_CapturesStepUpHeader proves the agent recovers X-Dsse-Stepup-Url off a 401 CONNECT
// response (previously the header was drained and discarded) and leaves the reader at the body.
func TestReadCONNECTStatus_CapturesStepUpHeader(t *testing.T) {
	const portal = "https://edge:8443/clientless/auth/start?return_to=10.0.0.5%3A445&idp=corp&acr=phishing_resistant"
	raw := "HTTP/1.1 401 Unauthorized\r\n" +
		stepUpChallengeHeader + ": " + portal + "\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"decision":"authenticate"}`
	r := bufio.NewReader(strings.NewReader(raw))
	status, headers, err := readCONNECTStatus(r)
	if err != nil {
		t.Fatalf("readCONNECTStatus: %v", err)
	}
	if status != 401 {
		t.Fatalf("want status 401, got %d", status)
	}
	if got := headers.Get(stepUpChallengeHeader); got != portal {
		t.Fatalf("step-up header mismatch:\n got %q\nwant %q", got, portal)
	}
	// The reader must be positioned at the start of the body, not consumed past it.
	body, _ := r.ReadString('}')
	if !strings.Contains(body, `"decision":"authenticate"`) {
		t.Fatalf("reader should be left at the body, got %q", body)
	}
}

// TestReadCONNECTStatus_AllowHasNoStepUp confirms a 200 allow carries no step-up header (the agent must not
// prompt on an allow) and the reader is left at the tunnel payload.
func TestReadCONNECTStatus_AllowHasNoStepUp(t *testing.T) {
	raw := "HTTP/1.1 200 Connection Established\r\n\r\nTUNNELBYTES"
	r := bufio.NewReader(strings.NewReader(raw))
	status, headers, err := readCONNECTStatus(r)
	if err != nil {
		t.Fatalf("readCONNECTStatus: %v", err)
	}
	if status != 200 {
		t.Fatalf("want 200, got %d", status)
	}
	if got := strings.TrimSpace(headers.Get(stepUpChallengeHeader)); got != "" {
		t.Fatalf("allow must carry no step-up header, got %q", got)
	}
	rest, _ := r.ReadString(0)
	if !strings.HasPrefix(rest, "TUNNELBYTES") {
		t.Fatalf("reader should be left at the tunnel body, got %q", rest)
	}
}
