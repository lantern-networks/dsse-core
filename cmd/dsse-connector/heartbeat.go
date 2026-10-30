package main

import (
	"context"
	"log"
	"net/http"
	"time"
)

// Heartbeat liveness is separate from management request budgets and healthy
// long-lived data streams. Preserve an operator/client's shorter deadline.
func connectorHeartbeatHTTPClient(base *http.Client, timeout time.Duration) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	if client.Timeout <= 0 || client.Timeout > timeout {
		client.Timeout = timeout
	}
	return &client
}

func runConnectorHeartbeats(ctx context.Context, doors *connectorEndpoints, send func(string) error, register func(), interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var tested connectorDoorSelection
	consecutive := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		selected := doors.selection()
		if selected.url == "" {
			consecutive = 0
			continue // no data or heartbeat through the profile-only address
		}
		err := send(selected.url)
		if ctx.Err() != nil {
			return
		}
		if doors.selection() != selected {
			consecutive = 0
			continue
		}
		if err == nil {
			consecutive = 0
			continue
		}
		if tested != selected {
			consecutive = 0
			tested = selected
		}
		consecutive++
		log.Printf("send connector heartbeat (%d in a row): %v", consecutive, err)
		if consecutive < 3 {
			continue
		}
		if doorIsUnreachable(err) {
			next := doors.advanceIfSelected(selected, err)
			if next == "" || doors.selection() != selected {
				// A failed heartbeat describes the old door, not the new one.
				// Existing fleet identity and the tunnel workers already let the
				// connector join another Edge. Check that door's heartbeat before
				// deciding it needs registration. A redundant registration can wait
				// for CP reporting and falsely move a healthy replacement Region.
				// A real unknown/refused identity still reaches register below on
				// that door's own consecutive HTTP failures.
				consecutive = 0
				continue
			}
		}
		register()
		consecutive = 0
	}
}
