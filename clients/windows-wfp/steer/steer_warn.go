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

// warnNotifier surfaces the Warn-stage notice, coalesced once per "service|destination" per agent session (belt
// and suspenders with the Edge's own once-per-connection coalescing). It is pure / cross-platform and unit
// testable: the actual toast is an injected func (defaultWarnLauncher on Windows; a no-op stub elsewhere). It
// NEVER holds/retries/opens anything — a WARN frame is fire-and-forget.
type warnNotifier struct {
	mu       sync.Mutex
	seen     map[string]struct{}
	announce func(dest, service string)
	logf     func(format string, args ...any)
}

// newWarnNotifier builds a notifier. announce == nil yields a no-op Notify (notices disabled).
func newWarnNotifier(announce func(dest, service string), logf func(format string, args ...any)) *warnNotifier {
	return &warnNotifier{seen: map[string]struct{}{}, announce: announce, logf: logf}
}

// Notify parses a WARN frame payload and shows the passive notice once per service|destination. Safe on a nil
// receiver and nil launcher, so the caller can always call it without guarding.
func (w *warnNotifier) Notify(payload []byte) {
	if w == nil || w.announce == nil {
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
	key := service + "|" + dest
	w.mu.Lock()
	if _, ok := w.seen[key]; ok {
		w.mu.Unlock()
		return // coalesced: already announced this resource this session
	}
	w.seen[key] = struct{}{}
	w.mu.Unlock()
	if w.logf != nil {
		w.logf("steer_warn_notice dest=%s service=%s (monitored; auth soon required)", dest, service)
	}
	// Show off the demux goroutine: a toast must not block the mux read loop (the flow is already forwarded).
	go w.announce(dest, service)
}
