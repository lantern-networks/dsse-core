package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// stepUpChallengeHeader is the response header the Edge sets on an "authenticate" deny for a steered
// (native: SMB/RDP/WinRM) flow: it carries the clientless step-up portal URL the agent opens out-of-band.
// Mirror of the Edge-side constant. A native TCP client cannot follow a 302,
// so the agent opens the validated Portal URL for the originating OS session.
// The server checks the signed device binding, OIDC evidence and current policy;
// opening a browser does not itself authorize the waiting connection.
const stepUpChallengeHeader = "X-Dsse-Stepup-Url"

// stepUpCoordinator mediates agent-driven step-up. On a 401 + stepUpChallengeHeader for a steered flow the
// user initiated, it surfaces a prompt and opens the portal URL in the default browser -- coalescing repeat
// blocks to the SAME resource so a burst of flows (a browser opening many connections, an SMB mount
// retrying, RDP reconnecting) opens the portal ONCE within a window. It is pure / cross-platform and unit
// testable: the actual toast+browser launch is an injected func (defaultStepUpLauncher on Windows; a no-op
// stub elsewhere) and the clock is injectable. It NEVER allows a flow -- the upstream deny stands
// (fail-closed); this only gives the user a way to complete the step-up.
type stepUpOwner struct {
	PID     uint32
	Session uint32
	SID     string
	Created uint64
	LogonID uint64
}

type trackedStepUpRequest struct {
	id       string
	expires  time.Time
	owner    stepUpOwner
	resource string
}

type stepUpResultQuery struct {
	RequestID string `json:"request_id"`
	Principal string `json:"os_principal"`
	Session   string `json:"os_session"`
}

type stepUpCoordinator struct {
	launchForOwner func(string, string, stepUpOwner)
	resultForOwner func(string, stepUpOwner)
	validate       func(string) bool
	mu             sync.Mutex
	pending        map[string]time.Time            // resource -> the time we last opened the portal for it
	requestIDs     map[string]trackedStepUpRequest // owner/resource -> validated request, kept beyond the prompt coalesce window
	ttl            time.Duration                   // suppress re-prompting the same resource within this window
	launch         func(resource, portalURL string)
	now            func() time.Time
	logf           func(format string, args ...any)
}

// newStepUpCoordinator builds a coordinator with the given coalesce window and launcher. A non-positive ttl
// defaults to 30s. launch == nil yields a coordinator whose Trigger is a no-op (prompting disabled).
func newStepUpCoordinator(ttl time.Duration, launch func(resource, portalURL string), logf func(string, ...any)) *stepUpCoordinator {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &stepUpCoordinator{
		pending:    map[string]time.Time{},
		requestIDs: map[string]trackedStepUpRequest{},
		ttl:        ttl,
		launch:     launch,
		now:        time.Now,
		logf:       logf,
	}
}

// Trigger surfaces the step-up portal for resource (the recovered original destination) unless one is
// already in-flight for it within the coalesce window. Returns true if it launched the portal this call,
// false if it was a no-op (coalesced, disabled, or no URL). Safe on a nil receiver and nil launcher, so the
// caller can always call it without guarding.
func (c *stepUpCoordinator) Trigger(resource, portalURL string) bool {
	return c.TriggerForOwner(resource, portalURL, stepUpOwner{})
}

func (c *stepUpCoordinator) TriggerForOwner(resource, portalURL string, owner stepUpOwner) bool {
	if c == nil || (c.launch == nil && c.launchForOwner == nil) || strings.TrimSpace(portalURL) == "" {
		return false
	}
	if c.validate != nil && !c.validate(portalURL) {
		if c.logf != nil {
			c.logf("steer_stepup_refused reason=invalid_or_expired_portal_request")
		}
		return false
	}
	if c.launchForOwner != nil && (owner.PID == 0 || owner.SID == "" || owner.Session == 0) {
		if c.logf != nil {
			c.logf("steer_stepup_refused reason=originating_interactive_session_unknown")
		}
		return false
	}
	key := owner.SID + "|" + fmt.Sprint(owner.Session) + "|" + fmt.Sprint(owner.LogonID) + "|" + resource
	u, err := url.Parse(portalURL)
	requestID := ""
	if err == nil && len(u.Query()["request_id"]) == 1 {
		requestID = u.Query().Get("request_id")
	}
	now := c.now()
	c.mu.Lock()
	c.gcLocked(now)
	if last, ok := c.pending[key]; ok && now.Sub(last) < c.ttl {
		c.mu.Unlock()
		return false // coalesced: a portal for this resource is already open / recently opened
	}
	if len(c.pending) >= 32 {
		c.mu.Unlock()
		return false
	}
	if validStepUpRequestID(requestID) && len(c.requestIDs) >= 256 && c.requestIDs[key].id == "" {
		c.mu.Unlock()
		return false
	}
	c.pending[key] = now
	if validStepUpRequestID(requestID) {
		c.requestIDs[key] = trackedStepUpRequest{id: requestID, expires: now.Add(10 * time.Minute), owner: owner, resource: resource}
	}
	c.mu.Unlock()
	if c.logf != nil {
		c.logf("steer_stepup resource=%s opening step-up portal", resource)
	}
	// Launch off the flow-handling goroutine: opening a browser / showing a toast must not block the flow
	// teardown (the flow is already denied and about to close).
	validator, clock, launchForOwner, launch, logf := c.validate, c.now, c.launchForOwner, c.launch, c.logf
	go func() {
		// Scheduling a user-session browser can lag behind the flow callback.
		// Bound the prompt from receipt using Go's monotonic clock, while the
		// validator keeps its endpoint-clock-skew allowance. The Portal still
		// owns the exact signed expiry and can reject a late arrival.
		elapsed := clock().Sub(now)
		if elapsed < 0 || elapsed >= 120*time.Second || (validator != nil && !validator(portalURL)) {
			c.mu.Lock()
			if last, ok := c.pending[key]; ok && last.Equal(now) {
				delete(c.pending, key)
				if tracked := c.requestIDs[key]; tracked.id == requestID {
					delete(c.requestIDs, key)
				}
			}
			c.mu.Unlock()
			if logf != nil {
				logf("steer_stepup_refused reason=invalid_before_browser_launch")
			}
			return
		}
		if launchForOwner != nil {
			launchForOwner(resource, portalURL, owner)
		} else {
			launch(resource, portalURL)
		}
	}()
	return true
}

func validStepUpRequestID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, ch := range id {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

// HandleResultForOwner accepts only an AUTH_RESULT for a request that this
// exact OS session received from a validated Portal URL. A browser page cannot
// call this and a result from a different flow/user cannot clear the notice.
func (c *stepUpCoordinator) HandleResultForOwner(resource, requestID, result string, owner stepUpOwner) bool {
	if c == nil || !validStepUpRequestID(requestID) || (result != "resumed" && result != "not_resumed") {
		return false
	}
	key := owner.SID + "|" + fmt.Sprint(owner.Session) + "|" + fmt.Sprint(owner.LogonID) + "|" + resource
	c.mu.Lock()
	tracked := c.requestIDs[key]
	if tracked.id != requestID {
		c.mu.Unlock()
		return false
	}
	if !c.now().Before(tracked.expires) {
		delete(c.requestIDs, key)
		c.mu.Unlock()
		return false
	}
	delete(c.pending, key)
	delete(c.requestIDs, key)
	notify := c.resultForOwner
	c.mu.Unlock()
	if notify != nil {
		go notify(result, owner)
	}
	return true
}

// Only requests the privileged service itself observed may be queried. The
// server additionally binds each lookup to the verified mTLS device/tenant.
func (c *stepUpCoordinator) pendingResultQueries() []stepUpResultQuery {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(c.now())
	queries := make([]stepUpResultQuery, 0, len(c.requestIDs))
	for _, tracked := range c.requestIDs {
		principal, session := tracked.owner.authPrincipal(), tracked.owner.authSession()
		if principal != "" && session != "" && validStepUpRequestID(tracked.id) {
			queries = append(queries, stepUpResultQuery{tracked.id, principal, session})
		}
	}
	return queries
}

func (c *stepUpCoordinator) HandleQueriedResult(requestID, result string) bool {
	if c == nil || !validStepUpRequestID(requestID) {
		return false
	}
	c.mu.Lock()
	var match trackedStepUpRequest
	for _, tracked := range c.requestIDs {
		if tracked.id == requestID {
			if match.id != "" {
				c.mu.Unlock()
				return false
			}
			match = tracked
		}
	}
	c.mu.Unlock()
	if match.id == "" {
		return false
	}
	return c.HandleResultForOwner(match.resource, requestID, result, match.owner)
}

// gcLocked drops resources whose coalesce window has elapsed, so a resource blocked again later re-prompts.
func (c *stepUpCoordinator) gcLocked(now time.Time) {
	for k, t := range c.pending {
		if now.Sub(t) >= c.ttl {
			delete(c.pending, k)
		}
	}
	for k, request := range c.requestIDs {
		if !now.Before(request.expires) {
			delete(c.requestIDs, k)
		}
	}
}

// One incarnation per privileged agent process, combined with the token's logon
// LUID. PID and WTS session numbers alone can be reused after logout/restart.
var authAgentEpoch = func() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}()

func (o stepUpOwner) authPrincipal() string {
	if o.PID == 0 || o.Session == 0 || o.SID == "" || o.LogonID == 0 || authAgentEpoch == "" {
		return ""
	}
	return "windows:" + o.SID
}
func (o stepUpOwner) authSession() string {
	if o.authPrincipal() == "" {
		return ""
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d", authAgentEpoch, o.SID, o.Session, o.LogonID)))
	return hex.EncodeToString(h[:])
}
func authorityWithAuthOwner(authority string, o stepUpOwner) string {
	if o.authPrincipal() == "" {
		return authority
	}
	if !strings.ContainsRune(authority, 0) {
		authority += "\x00"
	} else {
		authority += " "
	}
	return authority + "op=" + o.authPrincipal() + " ls=" + o.authSession()
}

// Legacy Portals omit owner fields during a rolling update. A new Portal signs
// both, and the privileged launcher must not deliver a different user's request.
func stepUpOwnerMatchesURL(owner stepUpOwner, u *url.URL) bool {
	if u == nil {
		return false
	}
	q := u.Query()
	if !q.Has("os_principal") && !q.Has("os_session") {
		return true
	}
	return len(q["os_principal"]) == 1 && len(q["os_session"]) == 1 && owner.authPrincipal() != "" && q.Get("os_principal") == owner.authPrincipal() && q.Get("os_session") == owner.authSession()
}
