package main

import (
	"strings"
	"sync"
	"time"
)

// stepUpChallengeHeader is the response header the Edge sets on an "authenticate" deny for a steered
// (native: SMB/RDP/WinRM) flow: it carries the clientless step-up portal URL the agent opens out-of-band.
// Mirror of the Edge-side const (cmd/edge/federated_auth_gate.go). A native TCP client cannot follow a 302,
// so the AGENT mediates the step-up by surfacing this URL to the user; the browser flow it opens is itself
// steered, so the (T) transport identity on the broker callback is THIS device and the minted grant binds
// to it automatically. The retried native connection then finds the grant and is allowed.
const stepUpChallengeHeader = "X-Dsse-Stepup-Url"

// stepUpCoordinator mediates agent-driven step-up. On a 401 + stepUpChallengeHeader for a steered flow the
// user initiated, it surfaces a prompt and opens the portal URL in the default browser -- coalescing repeat
// blocks to the SAME resource so a burst of flows (a browser opening many connections, an SMB mount
// retrying, RDP reconnecting) opens the portal ONCE within a window. It is pure / cross-platform and unit
// testable: the actual toast+browser launch is an injected func (defaultStepUpLauncher on Windows; a no-op
// stub elsewhere) and the clock is injectable. It NEVER allows a flow -- the upstream deny stands
// (fail-closed); this only gives the user a way to complete the step-up.
type stepUpCoordinator struct {
	mu      sync.Mutex
	pending map[string]time.Time // resource -> the time we last opened the portal for it
	ttl     time.Duration        // suppress re-prompting the same resource within this window
	launch  func(resource, portalURL string)
	now     func() time.Time
	logf    func(format string, args ...any)
}

// newStepUpCoordinator builds a coordinator with the given coalesce window and launcher. A non-positive ttl
// defaults to 30s. launch == nil yields a coordinator whose Trigger is a no-op (prompting disabled).
func newStepUpCoordinator(ttl time.Duration, launch func(resource, portalURL string), logf func(string, ...any)) *stepUpCoordinator {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &stepUpCoordinator{
		pending: map[string]time.Time{},
		ttl:     ttl,
		launch:  launch,
		now:     time.Now,
		logf:    logf,
	}
}

// Trigger surfaces the step-up portal for resource (the recovered original destination) unless one is
// already in-flight for it within the coalesce window. Returns true if it launched the portal this call,
// false if it was a no-op (coalesced, disabled, or no URL). Safe on a nil receiver and nil launcher, so the
// caller can always call it without guarding.
func (c *stepUpCoordinator) Trigger(resource, portalURL string) bool {
	if c == nil || c.launch == nil || strings.TrimSpace(portalURL) == "" {
		return false
	}
	now := c.now()
	c.mu.Lock()
	c.gcLocked(now)
	if last, ok := c.pending[resource]; ok && now.Sub(last) < c.ttl {
		c.mu.Unlock()
		return false // coalesced: a portal for this resource is already open / recently opened
	}
	c.pending[resource] = now
	c.mu.Unlock()
	if c.logf != nil {
		c.logf("steer_stepup resource=%s opening step-up portal", resource)
	}
	// Launch off the flow-handling goroutine: opening a browser / showing a toast must not block the flow
	// teardown (the flow is already denied and about to close).
	go c.launch(resource, portalURL)
	return true
}

// gcLocked drops resources whose coalesce window has elapsed, so a resource blocked again later re-prompts.
func (c *stepUpCoordinator) gcLocked(now time.Time) {
	for k, t := range c.pending {
		if now.Sub(t) >= c.ttl {
			delete(c.pending, k)
		}
	}
}
