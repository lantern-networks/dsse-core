//go:build windows

// steer_heartbeat.go — FR / W-2 endpoint liveness: the WFP steering agent periodically sends an AUTHENTICATED
// device heartbeat to the Edge over the (T) mTLS tunnel (presenting the device client cert). This is the
// liveness signal the Edge's agent-dark sweep watches (): while
// the agent runs, heartbeats keep last_seen fresh and the device is "alive"; killing the agent stops the
// heartbeats, so the Edge sees the device go dark and (with -w2-agent-dark-sweep) auto-revokes its trust.
//
// It rides the SAME (T) transport as steering (pinned CA + device mTLS), so the Edge records the heartbeat's
// transport identity from the verified client cert -- not a client-claimed id. Self-contained: shares nothing
// with the redirect/inbound paths. Run via `--mode heartbeat` (liveness-only) or, in production, alongside
// steering as a concurrent goroutine.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/runstate"
)

type heartbeatConfig struct {
	deviceID string // device identity to register/heartbeat (should match the client cert CN)
	tenantID string // tenant the device belongs to, from --device-tenant: what self-registration writes
	// profileTenantID is the VERIFIED install profile's tenant, used ONLY as the fallback for the runstate
	// record. Separate from tenantID on purpose: that one decides what this agent would WRITE to the Edge when
	// it self-registers a device the Edge does not know, and it stays operator-typed. This one only answers
	// "which tenant does this device believe it is in", for a check another process performs locally.
	profileTenantID string
	interval        time.Duration   // heartbeat period (keep < the Edge soft-dark threshold to stay alive)
	timeout         time.Duration   // 0 = run until interrupted
	transport       transportConfig // (T) mTLS — REQUIRED (the device identity comes from the client cert)
}

// transportHTTPClient returns an http.Client whose connections ride the (T) mTLS tunnel (pinned CA + device
// client cert), so requests reach the Edge with the verified transport identity. Mirrors httpGetExport.
func transportHTTPClient(tc transportConfig) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tc.dial(10 * time.Second)
			},
		},
	}
}

// deviceRegisterBody / deviceHeartbeatBody build the JSON payloads (pure; unit-tested). now is passed in so
// the heartbeat timestamp is testable and the caller controls freshness.
func deviceRegisterBody(cfg heartbeatConfig) map[string]any {
	return map[string]any{
		"id":                 cfg.deviceID,
		"tenant_id":          cfg.tenantID,
		"device_trust_level": "managed",
		"status":             "active",
		"agent_version":      agentVersion(),
	}
}

// deviceHeartbeatBody carries the posture axes this agent can ACTUALLY read, not just the one it happened to
// send. The Edge re-derives device trust from whatever posture a heartbeat contains (DerivePostureTrustLevel),
// and this used to contain only enforcement_agent_healthy — so disk encryption and firewall came back
// "unknown" and failed their checks, and win-dev-1 sat at noncompliant permanently while BitLocker and the
// firewall were both on. The agent had those readings the whole time: it collects them for the steer-mux
// CONNECT headers, and simply never put them here.
//
// STILL UNREPORTED, on both platforms: screen lock. The default posture policy requires it, so this fleet
// cannot reach `managed` on evidence alone. That is an operator decision to make explicitly — relax the
// requirement, or add a sensor for it — and NOT something to paper over by having the Edge ignore axes a
// report omits, which would let any endpoint reach `managed` by staying quiet about the parts it fails.
func deviceHeartbeatBody(cfg heartbeatConfig, now time.Time, agentHealthy bool) map[string]any {
	posture := map[string]any{
		"enforcement_agent_healthy": agentHealthy,
		"collected_at":              now.UTC().Format(time.RFC3339),
		"source":                    "windows_collector",
	}
	// Fail-safe, same rule as the CONNECT headers: a signal that cannot be read is OMITTED (the Edge shows it
	// as unknown) and never guessed. An empty status means the read failed, not that the feature is off.
	if enc := diskEncryptionStatus(); enc != "" {
		posture["disk_encryption_enabled"] = enc == "on"
	}
	if fw := firewallStatus(); fw != "" {
		posture["firewall_enabled"] = fw == "on"
	}
	if os := osDescription(); os != "" {
		posture["os_version"] = os
	}
	return map[string]any{
		"id":            cfg.deviceID,
		"tenant_id":     cfg.tenantID,
		"status":        "active",
		"agent_version": agentVersion(),
		"timestamp":     now.UTC().Format(time.RFC3339),
		"posture":       posture,
	}
}

// enforcementHealth reports whether the WFP enforcement is actually in force (not just whether this agent
// process is alive) plus a short non-secret reason for observability (W-3). Three layers, fail-closed:
//  1. the control device \\.\DsseWfp opens -> the driver is LOADED (the device exists only between
//     DriverEntry and unload, so a service-stop / driver-unload makes this fail);
//  2. a read-only stats IOCTL answers -> the driver is RESPONSIVE (not a wedged/zombie handle);
//  3. all six WFP filters are installed -> the driver's filters were not individually deleted while it stays
//     loaded (an admin tamper that 1+2 alone would miss).
//
// Any failure => unhealthy => the Edge's W-3 posture path degrades trust and revokes east-west grants. A
// non-admin cannot unload the driver or delete filters ( device ACL / WFP needs admin), so this flags an
// admin-level tamper or a crashed/partial driver in the pre-full-silence window (W-2 catches full silence).
func enforcementHealth() (bool, string) {
	h, err := openWFPDevice()
	if err != nil {
		return false, "driver-not-loaded"
	}
	defer syscall.CloseHandle(h)
	// Only used as a liveness probe: the bytes are never parsed, so DSSE_STATS may grow without touching this.
	// Sized well past the struct (60 bytes at DSSE_STATS_VERSION 2) on purpose — an output buffer smaller than
	// the struct returns STATUS_BUFFER_TOO_SMALL, which would read here as "driver-unresponsive" and raise a
	// false W-3 tamper signal. A tight fit would have made the next field added to the struct do exactly that.
	var stats [256]byte
	var ret uint32
	if err := syscall.DeviceIoControl(h, ioctlWFPGetStats, nil, 0, &stats[0], uint32(len(stats)), &ret, nil); err != nil || ret < 4 {
		return false, "driver-unresponsive"
	}
	count, ok := dsseFiltersPresent()
	if !ok {
		return false, "wfp-filter-enum-failed"
	}
	if count < len(dsseFilterNames) {
		return false, fmt.Sprintf("wfp-filters-incomplete(%d/%d)", count, len(dsseFilterNames))
	}
	return true, fmt.Sprintf("filters=%d/%d", count, len(dsseFilterNames))
}

func (cfg heartbeatConfig) baseURL() string { return "https://" + cfg.transport.host }

// postJSONStatus posts body and returns the HTTP status code, so a caller can tell "the Edge does not know this
// device" (404) apart from a transport failure. postJSON keeps the simpler ok-codes contract on top of it.
func postJSONStatus(client *http.Client, url string, body any) (int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func postJSON(client *http.Client, url string, body any, okCodes ...int) error {
	code, err := postJSONStatus(client, url, body)
	if err != nil {
		return err
	}
	for _, c := range okCodes {
		if code == c {
			return nil
		}
	}
	return fmt.Errorf("POST %s -> unexpected status %d", url, code)
}

// deviceIDFromClientCert returns the CN of the (T) device client certificate. The Edge takes the device
// identity from the VERIFIED client cert regardless of what the body claims, so the CN is the correct default
// for --device-id — and it makes liveness work on an already-enrolled box without editing the installed
// service's baked-in argument list.
func deviceIDFromClientCert(tc transportConfig) string {
	if tc.clientCert == nil {
		return ""
	}
	leaf := tc.clientCert.Leaf
	if leaf == nil {
		if len(tc.clientCert.Certificate) == 0 {
			return ""
		}
		parsed, err := x509.ParseCertificate(tc.clientCert.Certificate[0])
		if err != nil {
			return ""
		}
		leaf = parsed
	}
	return leaf.Subject.CommonName
}

// recordedTenant is the tenant written into the runstate record: the operator's --device-tenant if given,
// otherwise the VERIFIED install profile's.
//
// The fallback exists because of what the MSI actually installs. Its service line is
// `--service-run --config-store` and nothing else, so --device-tenant is empty on every device the product
// installs — and the plan-addressing check would have run device-only on all of them while looking complete.
// The profile's tenant is a CP-SIGNED statement about this device, which is a better answer than a typed flag
// rather than a worse one; it is only used here, never for self-registration.
func recordedTenant(cfg heartbeatConfig) string {
	if t := strings.TrimSpace(cfg.tenantID); t != "" {
		return t
	}
	return strings.TrimSpace(cfg.profileTenantID)
}

// startBackgroundHeartbeat runs the W-2 liveness loop ALONGSIDE an enforcing mode rather than instead of it.
// `--mode heartbeat` is a separate, exclusive mode that returns before the steering data path starts, so an
// agent running `--mode redirect` — which is what the installed service runs — sent NO heartbeats at all.
// last_seen_at then went stale on a device that was actively enforcing, and the Edge's agent-dark sweep saw a
// working device as dark and revoked its trust (the stale agent_dark revocations that had to be cleared by hand).
//
// It must never take enforcement down: every failure is logged and retried on the next tick. A missing device
// identity or transport is reported LOUDLY instead of silently skipped — an operator who cannot see that
// liveness is off has no way to anticipate the agent-dark revocation that follows.
func startBackgroundHeartbeat(cfg heartbeatConfig, stop <-chan struct{}) {
	if !cfg.transport.enabled || cfg.transport.clientCert == nil {
		fmt.Fprintln(os.Stderr, "heartbeat: DISABLED — no (T) transport with a device client cert. "+
			"The Edge will see this device as dark even while it steers, and the agent-dark sweep may revoke its trust.")
		return
	}
	if cfg.deviceID == "" {
		cfg.deviceID = deviceIDFromClientCert(cfg.transport)
	}
	if cfg.deviceID == "" {
		fmt.Fprintln(os.Stderr, "heartbeat: DISABLED — no --device-id given and the (T) client cert has no CN to fall back to.")
		return
	}
	if cfg.interval <= 0 {
		cfg.interval = 15 * time.Second
	}

	// ★ RECORD WHO THIS BOX PROVED ITSELF TO BE, here and nowhere else (2026-08-12, fourth review). A second
	// process — DsseUpdater — has to check that a rollout plan addressed to a device is addressed to THIS one;
	// without it, a validly signed plan for a machine in an earlier wave opens this machine's wave. The updater
	// deliberately holds no network identity, so it reads what the running agent recorded.
	//
	// This is the one place in the agent that has the ANSWER: cfg.deviceID above is either the operator's
	// --device-id or the CN of the verified (T) client certificate, resolved a few lines up. Writing it where
	// the service starts — the obvious place, next to the version — would have written an empty string, which
	// is exactly what the previous attempt did: an API added, called from nowhere, and a check that could never
	// run while looking implemented.
	runstate.WriteWithIdentity(agentVersion(), cfg.deviceID, recordedTenant(cfg))

	client := transportHTTPClient(cfg.transport)
	beatURL := cfg.baseURL() + "/devices/" + cfg.deviceID + "/heartbeat"

	beat := func() {
		healthy, reason := enforcementHealth() // W-3: report REAL WFP enforcement health, not process liveness
		code, err := postJSONStatus(client, beatURL, deviceHeartbeatBody(cfg, time.Now(), healthy))
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "heartbeat: send failed: %v\n", err)
			return
		case code == http.StatusNotFound:
			// The Edge does not know this device. Register, then beat on the next tick. Registration runs ONLY
			// on 404 so a routine beat can never overwrite an already-enrolled device's stored tenant and trust
			// level with this agent's (possibly unset) --device-tenant.
			if cfg.tenantID == "" {
				fmt.Fprintf(os.Stderr, "heartbeat: device %q is unknown to the Edge and --device-tenant is unset; "+
					"refusing to self-register into an empty tenant. Set --device-tenant or enroll the device.\n", cfg.deviceID)
				return
			}
			if err := postJSON(client, cfg.baseURL()+"/devices/register", deviceRegisterBody(cfg),
				http.StatusCreated, http.StatusOK); err != nil {
				fmt.Fprintf(os.Stderr, "heartbeat: register after 404 failed: %v\n", err)
				return
			}
			fmt.Printf("heartbeat: registered device %q (the Edge did not know it)\n", cfg.deviceID)
			return
		case code != http.StatusAccepted && code != http.StatusOK:
			fmt.Fprintf(os.Stderr, "heartbeat: POST %s -> unexpected status %d\n", beatURL, code)
			return
		}
		enf := "healthy"
		if !healthy {
			enf = "UNHEALTHY"
		}
		fmt.Printf("heartbeat sent device=%s enforcement=%s (%s)\n", cfg.deviceID, enf, reason)
		// The beat has just proved the route and the certificate. Anything DsseUpdater has queued goes now.
		drainUpdateReports(cfg, client)
	}

	go func() {
		fmt.Printf("heartbeat: liveness enabled alongside steering — device %q every %s over (T) mTLS\n",
			cfg.deviceID, cfg.interval)
		beat() // beat immediately: an enforcing device must not look dark for a whole interval on startup
		ticker := time.NewTicker(cfg.interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop: // nil in the foreground path: blocks forever, so the loop simply runs until exit
				fmt.Println("heartbeat: agent stopping — no further beats (the device goes dark, as intended)")
				return
			case <-ticker.C:
				beat()
			}
		}
	}()
}

// runHeartbeat registers the device once, then sends a heartbeat every interval over the (T) mTLS tunnel until
// timeout/interrupt. Stopping the process stops the heartbeats => the device goes dark at the Edge.
func runHeartbeat(cfg heartbeatConfig) error {
	if !cfg.transport.enabled || cfg.transport.clientCert == nil {
		return fmt.Errorf("--mode heartbeat requires the (T) transport with a device client cert " +
			"(--edge-transport-url + --transport-pinned-ca + --transport-client-cert/--transport-client-key)")
	}
	if cfg.deviceID == "" {
		return fmt.Errorf("--mode heartbeat requires --device-id (should match the client cert CN)")
	}
	if cfg.interval <= 0 {
		cfg.interval = 15 * time.Second
	}
	client := transportHTTPClient(cfg.transport)

	if err := postJSON(client, cfg.baseURL()+"/devices/register", deviceRegisterBody(cfg),
		http.StatusCreated, http.StatusOK); err != nil {
		return fmt.Errorf("register device (edge reachable over (T)? cert enrolled?): %w", err)
	}
	fmt.Printf("heartbeat: device %q registered; sending every %s over (T) mTLS (agent-liveness for W-2)\n",
		cfg.deviceID, cfg.interval)

	send := func() {
		healthy, reason := enforcementHealth() // W-3: report REAL WFP enforcement health, not just process liveness
		if err := postJSON(client, cfg.baseURL()+"/devices/"+cfg.deviceID+"/heartbeat",
			deviceHeartbeatBody(cfg, time.Now(), healthy), http.StatusAccepted, http.StatusOK); err != nil {
			fmt.Fprintf(os.Stderr, "heartbeat: send failed: %v\n", err)
			return
		}
		enf := "healthy"
		if !healthy {
			enf = "UNHEALTHY"
		}
		fmt.Printf("heartbeat sent device=%s enforcement=%s (%s)\n", cfg.deviceID, enf, reason)
		// The beat has just proved the route and the certificate. Anything DsseUpdater has queued goes now.
		drainUpdateReports(cfg, client)
	}
	send() // first beat immediately so the device is alive right away

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	deadline := time.Time{}
	if cfg.timeout > 0 {
		deadline = time.Now().Add(cfg.timeout)
	}
	for {
		<-ticker.C
		send()
		if !deadline.IsZero() && time.Now().After(deadline) {
			fmt.Println("heartbeat: timeout reached; stopping (device will go dark)")
			return nil
		}
	}
}
