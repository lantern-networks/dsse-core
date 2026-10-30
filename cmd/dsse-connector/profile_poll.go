package main

// profile_poll.go — the connector re-reads the deployment's configuration instead of living on what its
// enrolment token happened to carry.
//
// ★★★ THE TOKEN IS ONE-TIME AND SHORT-LIVED; THE CONFIGURATION IS NOT (the operator's framing, 2026-08-26).
// An endpoint has both — a token to get in, and a profile it fetches again whenever the deployment's answer
// moves. A connector had only the token, so the doors it could use were frozen on the day it enrolled: add a
// region and no connector already in the field could ever fail over to it.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// connectorProfilePollEvery is how often the deployment's configuration is re-read. Slow on purpose: adding a
// region is a deliberate act by an operator, not an event to chase, and every poll is a request an Edge
// serves for every connector.
const connectorProfilePollEvery = 5 * time.Minute

type connectorProfileAnswer struct {
	SchemaVersion string   `json:"schema_version"`
	TenantID      string   `json:"tenant_id"`
	EdgeEndpoints []string `json:"edge_endpoints"`
	Note          string   `json:"note"`
}

// pollConnectorProfile keeps this connector's door list matching the deployment's, and persists it so a
// restart does not go back to what the token said.
func pollConnectorProfile(ctx context.Context, doors *connectorEndpoints, stateDir, connectorID, connectorSecret, tenantID string, tlsConfig *tls.Config) {
	client := newConnectorEdgeHTTPClient(tlsConfig)
	read := func() {
		if err := refreshConnectorProfile(ctx, client, doors, stateDir, connectorID, connectorSecret, tenantID, tlsConfig != nil); err != nil {
			// A transport/authority failure leaves the last verified decision in
			// force. An authoritative empty list is handled separately below.
			log.Printf("connector profile poll: %v", err)
		}
	}
	go func() {
		read()
		ticker := time.NewTicker(connectorProfilePollEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				read()
			}
		}
	}()
}

func refreshConnectorProfile(ctx context.Context, client *http.Client, doors *connectorEndpoints,
	stateDir, connectorID, connectorSecret, tenantID string, pinnedTLS bool) error {
	at := doors.profileDoor()
	if at == "" {
		return fmt.Errorf("no verified profile GET address")
	}
	answer, err := fetchConnectorProfile(ctx, client, at, connectorID, connectorSecret)
	if err != nil {
		return err
	}
	if answer.SchemaVersion != "connector_profile.v1" || strings.TrimSpace(tenantID) == "" ||
		answer.TenantID != tenantID || answer.EdgeEndpoints == nil {
		return fmt.Errorf("profile schema, tenant or door list could not be verified")
	}
	list := strings.Join(answer.EdgeEndpoints, ";")
	if len(answer.EdgeEndpoints) == 0 {
		if doors.withdraw(at) {
			log.Printf("connector: deployment withdrew all data doors; existing tunnels closed; profile GET only")
		}
		return persistConnectorDoors(stateDir, "", at, true)
	}
	next := parseConnectorEndpoints(list)
	if next.count() != len(answer.EdgeEndpoints) {
		return fmt.Errorf("profile contains an invalid Edge door")
	}
	if err := validateConnectorDoorURLs(next, pinnedTLS); err != nil {
		return fmt.Errorf("rejected deployment Edge doors: %w", err)
	}
	if doors.replace(next) {
		log.Printf("connector doors updated from the deployment: %s — %s", doors.describe(), answer.Note)
	}
	return persistConnectorDoors(stateDir, list, "", false)
}

func fetchConnectorProfile(ctx context.Context, client *http.Client, edgeURL, connectorID, connectorSecret string) (connectorProfileAnswer, error) {
	url := fmt.Sprintf("%s/connectors/%s/profile", strings.TrimRight(edgeURL, "/"), connectorID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return connectorProfileAnswer{}, err
	}
	if connectorSecret != "" {
		req.Header.Set(connectorSecretHeader, connectorSecret)
	}
	// The retained profile-only address is a single verified management GET,
	// not permission to follow a redirect to another data or management host.
	profileClient := *client
	profileClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := profileClient.Do(req)
	if err != nil {
		return connectorProfileAnswer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return connectorProfileAnswer{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var answer connectorProfileAnswer
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return connectorProfileAnswer{}, err
	}
	return answer, nil
}

// persistConnectorDoors writes the current list into the saved state, so the next start begins where this
// connector actually is rather than where its token pointed months ago.
func persistConnectorDoors(stateDir, list, profileDoor string, withdrawn bool) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil
	}
	path := filepath.Join(stateDir, "connector-state.json")
	st, ok, err := loadConnectorState(path)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("enrolled connector state is missing")
	}
	if st.EdgeEndpoints == list && st.DoorListWithdrawn == withdrawn && st.ProfileDoorURL == profileDoor {
		return nil
	}
	st.EdgeEndpoints = list
	st.DoorListWithdrawn = withdrawn
	st.ProfileDoorURL = profileDoor
	if err := saveConnectorState(path, st); err != nil {
		return fmt.Errorf("persist deployment door decision: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}
