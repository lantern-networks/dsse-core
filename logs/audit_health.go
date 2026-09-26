package logs

import (
	"sync"
	"time"
)

// AuditWriteHealth describes observations in this Writer instance, not durable
// recovery, fsync guarantees, fleet health, or downstream delivery completion.
type AuditWriteHealth struct {
	Status                  string `json:"status"`
	Scope                   string `json:"scope"`
	Attempts                uint64 `json:"attempts"`
	PrimarySuccesses        uint64 `json:"primary_successes"`
	PrimaryFailures         uint64 `json:"primary_failures"`
	HookFailures            uint64 `json:"hook_failures"`
	LastSuccessAt           string `json:"last_success_at,omitempty"`
	LastPrimaryFailureAt    string `json:"last_primary_failure_at,omitempty"`
	LastPrimaryFailurePhase string `json:"last_primary_failure_phase,omitempty"`
	LastHookFailureAt       string `json:"last_hook_failure_at,omitempty"`
}

type auditWriteMonitor struct {
	mu     sync.Mutex
	health AuditWriteHealth
}

func (w *Writer) observeAuditWrite(phase string, err error) {
	w.auditMonitor.mu.Lock()
	defer w.auditMonitor.mu.Unlock()
	h := &w.auditMonitor.health
	h.Attempts++
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err == nil || phase == "hook" {
		h.PrimarySuccesses++
		h.LastSuccessAt = now
	}
	if err != nil {
		if phase == "hook" {
			h.HookFailures++
			h.LastHookFailureAt = now
		} else {
			h.PrimaryFailures++
			h.LastPrimaryFailureAt = now
			h.LastPrimaryFailurePhase = phase
		}
	}
}

func (w *Writer) AuditHealth() AuditWriteHealth {
	h := AuditWriteHealth{Status: "unavailable", Scope: "writer_process_lifetime"}
	if w == nil {
		return h
	}
	w.auditMonitor.mu.Lock()
	h = w.auditMonitor.health
	w.auditMonitor.mu.Unlock()
	h.Scope = "writer_process_lifetime"
	h.Status = "unknown"
	if h.Attempts > 0 {
		h.Status = "healthy"
	}
	if h.PrimaryFailures > 0 {
		h.Status = "degraded"
	}
	return h
}
