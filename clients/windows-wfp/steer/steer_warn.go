package main

import (
	"encoding/json"
	"strings"
	"sync"
)

// warnPayload is the WARN(4) steer-mux frame body the Edge sends for a Warn-staged East-West rule (the S3 stage of
// the east-west lifecycle). Unlike STEPUP, the flow is ALREADY allowed + forwarded — this is a passive
// "this internal connection is monitored; authentication will soon be required" notice so the operator can watch
// what a rule WOULD affect before flipping it to Enforce. Nothing is held, retried, or opened. The Edge also sends
// an English `message` fallback; like the macOS NE we ignore it and render localized text from dest + service.
type warnPayload struct {
	Message     string `json:"message"`
	Destination string `json:"destination"`
	Service     string `json:"service"`
}

// warnNotifier surfaces the Warn-stage notice, coalesced once per owner and "service|destination" (belt
// and suspenders with the Edge's own once-per-connection coalescing). It is pure / cross-platform and unit
// testable: the actual toast is an injected func (defaultWarnLauncher on Windows; a no-op stub elsewhere). It
// NEVER holds/retries/opens anything — a WARN frame is fire-and-forget.
type warnNotifier struct {
	mu       sync.Mutex
	seen     map[warnNoticeKey]struct{}
	announce func(dest, service string, owner stepUpOwner)
	logf     func(format string, args ...any)
}

type warnNoticeKey struct {
	owner       stepUpOwner
	destination string
	service     string
}

// newWarnNotifier builds a notifier. announce == nil yields a no-op notification (notices disabled).
func newWarnNotifier(announce func(dest, service string, owner stepUpOwner), logf func(format string, args ...any)) *warnNotifier {
	return &warnNotifier{seen: map[warnNoticeKey]struct{}{}, announce: announce, logf: logf}
}

func validWarnOwner(owner stepUpOwner) bool {
	return owner.PID != 0 && owner.Created != 0 && owner.Session != 0 && owner.SID != "" && owner.LogonID != 0
}

func warnOwnerStillCurrent(owner stepUpOwner, capture func(uint32) stepUpOwner) bool {
	return validWarnOwner(owner) && capture(owner.PID) == owner
}

// NotifyForOwner parses a WARN frame payload and shows it only to the originating flow owner.
// Without a verified owner it cannot select a user's desktop safely. Safe on a nil receiver.
func (w *warnNotifier) NotifyForOwner(payload []byte, owner stepUpOwner) {
	if w == nil || w.announce == nil || !validWarnOwner(owner) {
		return
	}
	var p warnPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return
	}
	dest := strings.TrimSpace(p.Destination)
	service := strings.TrimSpace(p.Service)
	if dest == "" {
		return
	}
	key := warnNoticeKey{owner: owner, destination: dest, service: service}
	w.mu.Lock()
	if _, ok := w.seen[key]; ok {
		w.mu.Unlock()
		return // coalesced: already announced this resource to this flow owner
	}
	w.seen[key] = struct{}{}
	w.mu.Unlock()
	if w.logf != nil {
		w.logf("steer_warn_notice dest=%s service=%s (monitored; auth soon required)", dest, service)
	}
	// Show off the demux goroutine: a toast must not block the mux read loop (the flow is already forwarded).
	go w.announce(dest, service, owner)
}
