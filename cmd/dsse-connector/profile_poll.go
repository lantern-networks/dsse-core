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
	EdgeEndpoints []string `json:"edge_endpoints"`
	Note          string   `json:"note"`
}

// pollConnectorProfile keeps this connector's door list matching the deployment's, and persists it so a
// restart does not go back to what the token said.
func pollConnectorProfile(ctx context.Context, doors *connectorEndpoints, stateDir, connectorID, connectorSecret string, tlsConfig *tls.Config) {
	client := newConnectorEdgeHTTPClient(tlsConfig)
	read := func() {
		answer, err := fetchConnectorProfile(ctx, client, doors.current(), connectorID, connectorSecret)
		if err != nil {
			// Best-effort, like the routes poll beside it: the last known list keeps working, and a deployment
			// that is briefly unreachable is not a reason to forget where its doors are.
			return
		}
		list := strings.Join(answer.EdgeEndpoints, ";")
		if strings.TrimSpace(list) == "" {
			return
		}
		if !doors.replace(parseConnectorEndpoints(list)) {
			return
		}
		log.Printf("connector doors updated from the deployment: %s — %s", doors.describe(), answer.Note)
		persistConnectorDoors(stateDir, list)
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

func fetchConnectorProfile(ctx context.Context, client *http.Client, edgeURL, connectorID, connectorSecret string) (connectorProfileAnswer, error) {
	url := fmt.Sprintf("%s/connectors/%s/profile", strings.TrimRight(edgeURL, "/"), connectorID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return connectorProfileAnswer{}, err
	}
	if connectorSecret != "" {
		req.Header.Set(connectorSecretHeader, connectorSecret)
	}
	resp, err := client.Do(req)
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
func persistConnectorDoors(stateDir, list string) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return
	}
	path := filepath.Join(stateDir, "connector-state.json")
	st, ok, err := loadConnectorState(path)
	if !ok || err != nil {
		return
	}
	if st.EdgeEndpoints == list {
		return
	}
	st.EdgeEndpoints = list
	if err := saveConnectorState(path, st); err != nil {
		log.Printf("connector: could not persist the deployment's door list (%v) — it will be re-read on the "+
			"next poll, but a restart before then goes back to the previous one", err)
		return
	}
	_ = os.Chmod(path, 0o600)
}
