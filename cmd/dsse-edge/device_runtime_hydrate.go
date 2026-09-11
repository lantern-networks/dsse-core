package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Rehydrating the device-runtime view from the control plane on startup.
//
// The view an operator reads at GET /admin/device-runtime lives in an in-memory map on the Edge, and its ONLY
// writers are the steer-mux CONNECT handler and the per-flow OPEN frames. That makes a device's presence in the
// fleet view a side effect of the transport: restart the Edge and the map is empty, and a device only reappears
// when it happens to dial a NEW mux. A busy Windows box does that within seconds; a Mac with a warm pool, or one
// whose flows take the non-tunnel path, may not do it for hours. Measured on the lab: `docker restart` alone
// removed mac-dev-1 from the view and it did not return until the agent itself was restarted, while steering
// never stopped. A fleet view that quietly loses devices is worse than one that says nothing.
//
// The durable record already exists and is current — the Edge emits a device_state change event, ships it, and
// the control plane persists it (`deviceStateChangeEmit`, main.go). Nothing ever read it back. This is that read:
// persistence belongs on the control plane and the Edge is the fetcher, which is the same shape as the
// steer-exclusion pull next to it.
//
// One-shot at startup, not a poll: live CONNECT/OPEN traffic keeps the view fresh once running, so the only gap
// worth closing is starting from nothing. Best-effort by design — an Edge that refused to start because the
// control plane was briefly unreachable would trade a display gap for an outage, and a failed hydration leaves
// exactly the empty map the Edge has today.

const (
	// deviceRuntimeHydrateWait bounds one attempt. The fetch is now the control plane's compact per-device
	// answer rather than a scan of the shipped log — see hydrate — so this budget is generous rather than
	// tight. It was neither before: the log query measured 10.7s against it and lost three times in one
	// afternoon.
	deviceRuntimeHydrateWait = 20 * time.Second
)

// deviceRuntimeHydrateSource reads the durable device-state history from a control plane.
type deviceRuntimeHydrateSource struct {
	url      string // control-plane admin base, e.g. https://controlplane:9443
	token    string // bearer; the CP scopes the result to this token's tenant
	tenantID string
	client   *http.Client
}

// hydrate seeds the in-memory runtime view from the control plane's device_state history. Returns the number of
// devices restored. Rows arrive newest-first, so the FIRST row seen for a device is the one that wins — later
// rows are older history and must not overwrite it.
func (s deviceRuntimeHydrateSource) hydrate(ctx context.Context, store *endpointRuntimeStore) (int, error) {
	if store == nil {
		return 0, fmt.Errorf("device runtime store is nil")
	}
	// ★ THE COMPACT ANSWER, NOT THE RAW LOG (2026-08-14). This asked for the newest 2000 device_state ROWS and
	// threw away all but the newest per device. The control plane now keeps exactly that — one record per
	// device, folded at arrival — and answers it here, so this fetch is O(devices) instead of O(how much the
	// fleet steers.
	//
	// It had become the difference between working and not. Once a steering device began re-shipping once a
	// minute, the log query measured 10.7s against this fetch's 20s budget and lost the race three times in one
	// afternoon; a single timeout then degrades the fleet view for the LIFE OF THE PROCESS, because
	// logged-in users only refill when a device happens to open a new flow. The 2000-row cap was the other
	// half: at 1440 rows per day per steering device it stopped being a 48-hour window and became "whatever the
	// noisiest devices left room for", which drops the quiet ones first.
	endpoint := strings.TrimRight(s.url, "/") + "/admin/device-runtime"
	if tenant := strings.TrimSpace(s.tenantID); tenant != "" {
		endpoint += "?tenant_id=" + url.QueryEscape(tenant)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("control plane returned %d for the device-state history: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Devices   map[string]map[string]any `json:"devices"`
		FleetWide bool                      `json:"fleet_wide"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, fmt.Errorf("decode the control plane's device view: %w", err)
	}
	// ★ REFUSE A ONE-NODE ANSWER (2026-08-14). fleet_wide=false means the control plane answered from its own
	// live map because its projection had not been seeded yet — a real answer, but not the fleet's. Seeding
	// this Edge from it would restore a few devices and mark the job done, and the retry loop that exists
	// precisely because one failure degrades the view for the life of the process would never fire.
	if !payload.FleetWide {
		return 0, fmt.Errorf("the control plane answered for its own node only (fleet_wide=false) — it has not " +
			"built the fleet picture yet, and seeding from that would hide the gap rather than retry it")
	}
	rows := make([]map[string]any, 0, len(payload.Devices))
	for id, d := range payload.Devices {
		row := map[string]any{"device_id": id, "tenant_id": s.tenantID}
		for k, v := range d {
			row[k] = v
		}
		// seedFromHistory keys freshness off `timestamp`; the view spells that field last_seen.
		if _, ok := row["timestamp"]; !ok {
			row["timestamp"] = d["last_seen"]
		}
		rows = append(rows, row)
	}
	return store.seedFromHistory(rows), nil
}

// seedFromHistory fills empty entries from newest-first history rows. It NEVER overwrites a device the live
// transport has already reported: a CONNECT that landed while this was in flight is current, and history is not.
func (s *endpointRuntimeStore) seedFromHistory(rows []map[string]any) int {
	restored := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range rows {
		deviceID := strings.TrimSpace(stringFromRow(row, "device_id"))
		if deviceID == "" {
			continue
		}
		if _, live := s.m[deviceID]; live {
			continue // already known — from a live CONNECT, or from a newer row in this same pass
		}
		seen, ok := aiUsageRowTime(row)
		if !ok {
			continue // a row we cannot place in time cannot claim to be the latest state
		}
		e := &deviceRuntimeInfo{
			tenant:        strings.TrimSpace(stringFromRow(row, "tenant_id")),
			os:            strings.TrimSpace(stringFromRow(row, "os")),
			loggedInUsers: map[string]bool{},
			lastSeen:      seen.UTC(),
		}
		if users, ok := row["logged_in_users"].([]any); ok {
			for _, u := range users {
				if name := strings.TrimSpace(fmt.Sprint(u)); name != "" {
					e.loggedInUsers[name] = true
				}
			}
		}
		if v, ok := row["disk_encryption_enabled"].(bool); ok {
			e.posture.DiskEncryptionEnabled = &v
		}
		if v, ok := row["firewall_enabled"].(bool); ok {
			e.posture.FirewallEnabled = &v
		}
		// ★ WHERE IT WAS STEERING, AND THAT IT WAS (2026-08-14). Restoring the state without these makes the
		// first CONNECT after a restart look like a device that just STARTED steering — a transition, and an
		// event shipped as history that did not happen. It also loses the one fact a fleet-wide view exists to
		// carry: which Edge this device is on.
		e.edge = strings.TrimSpace(stringFromRow(row, "edge"))
		e.sourceIP = strings.TrimSpace(stringFromRow(row, "source_ip"))
		if ls := strings.TrimSpace(stringFromRow(row, "last_steered")); ls != "" {
			if at, perr := time.Parse(time.RFC3339, ls); perr == nil {
				e.lastSteered = at.UTC()
				e.steering = true
			}
		}
		// Seed the change signature from what was restored, so the first live report of the SAME state does not
		// look like a transition and emit a spurious change event.
		e.lastSig = e.changeSignature()
		s.m[deviceID] = e
		restored++
	}
	return restored
}
