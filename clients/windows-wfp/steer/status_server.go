package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/agentstatus"
)

// status_server.go — the read-only agent-status endpoint the tray reads. A loopback HTTP listener serves the
// agentstatus.Holder snapshot; it exposes NO secrets (tenant/region/protection state only — never keys/tokens),
// and loopback is the access boundary for this cut. A named-pipe + SDDL ACL is the hardening follow-up: it would
// let the endpoint authorize the caller instead of trusting every local process on loopback.
//
// deriveProtection is pure so it is unit-tested; the serve/fetch use only net/http so they run on any OS.

// deriveProtection maps observable agent state to the tray-facing protection state:
//   - disarmed to the native network → CaptiveOnboarding (captive window open) else Disarmed (fail-open outage)
//   - armed + Edge reachable → Steering (protected)
//   - armed + Edge unreachable → Dark (fail-closed, blocked)
func deriveProtection(disarmed, captiveActive, edgeReachable bool) agentstatus.Protection {
	if disarmed {
		if captiveActive {
			return agentstatus.CaptiveOnboarding
		}
		return agentstatus.Disarmed
	}
	if edgeReachable {
		return agentstatus.Steering
	}
	return agentstatus.Dark
}

// serveStatus serves GET /status (the holder's JSON) over ln until stop closes. Read-only.
func serveStatus(stop <-chan struct{}, ln net.Listener, holder *agentstatus.Holder, logf func(string, ...any)) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		b, err := holder.JSON()
		if err != nil {
			http.Error(w, "status", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed && logf != nil {
		logf("status_server: %v", err)
	}
}

// fetchStatus reads the agent status from a loopback status endpoint (tray side).
func fetchStatus(addr string, timeout time.Duration) (agentstatus.Status, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("http://" + addr + "/status")
	if err != nil {
		return agentstatus.Status{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return agentstatus.Parse(b)
}
