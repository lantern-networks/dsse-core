package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
)

var sharedFleetAuthFeatures = []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.CeremonyRecoveryFeature, authrollout.RevocationReauthenticationFeature}

type authInstallEdge struct{ ID, URL string }
type authInstallResult struct {
	Deployment   string   `json:"deployment"`
	Generation   uint64   `json:"generation"`
	Phase        string   `json:"phase"`
	Features     []string `json:"features,omitempty"`
	Waiting      []string `json:"waiting,omitempty"`
	AppliedEdges int      `json:"applied_edges"`
}

func sameAuthCensus(want, got authrollout.Manifest) bool {
	if want.Deployment != got.Deployment || want.Generation != got.Generation || len(want.Members) != len(got.Members) {
		return false
	}
	byID := map[string]authrollout.Member{}
	for _, m := range want.Members {
		byID[m.ID] = m
	}
	for _, m := range got.Members {
		other, ok := byID[m.ID]
		if !ok || other.Role != m.Role || other.CertificateSHA256 != m.CertificateSHA256 || other.Retired != m.Retired || other.RetirementReason != m.RetirementReason {
			return false
		}
	}
	return true
}

func authInstallRequest(ctx context.Context, client *http.Client, method, endpoint, token string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, fmt.Errorf("invalid activation endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		var untrusted x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalid x509.CertificateInvalidError
		if errors.As(err, &untrusted) || errors.As(err, &hostname) || errors.As(err, &invalid) {
			return 0, nil, fmt.Errorf("activation authority TLS verification failed; correct deployment trust without bypassing validation")
		}
		return http.StatusServiceUnavailable, nil, nil
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return 0, nil, fmt.Errorf("invalid activation authority response")
	}
	if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode >= 300 && response.StatusCode < 400 || response.StatusCode == 400 || response.StatusCode == 404 {
		return response.StatusCode, nil, fmt.Errorf("activation endpoint refused the operation (HTTP %d); verify the operator token and current server version", response.StatusCode)
	}
	return response.StatusCode, raw, nil
}

func activateFleetAuthentication(ctx context.Context, client *http.Client, base, token, edgeToken string, census authrollout.Manifest, edges []authInstallEdge, requested []string, poll time.Duration) (authInstallResult, error) {
	result := authInstallResult{Deployment: census.Deployment, Generation: census.Generation, Phase: "waiting-for-members"}
	if err := census.Validate(); err != nil {
		return result, err
	}
	if len(edges) == 0 || poll <= 0 {
		return result, fmt.Errorf("activation requires every declared Edge target")
	}
	wantedEdges := map[string]bool{}
	for _, member := range census.Members {
		if member.Role == "edge" && !member.Retired {
			wantedEdges[member.ID] = true
		}
	}
	urls := map[string]bool{}
	for _, edge := range edges {
		if !wantedEdges[edge.ID] || urls[edge.URL] {
			return result, fmt.Errorf("activation targets must name each declared Edge exactly once")
		}
		delete(wantedEdges, edge.ID)
		urls[edge.URL] = true
	}
	if len(wantedEdges) > 0 {
		return result, fmt.Errorf("activation is missing a declared Edge target")
	}
	// Refuse redirects even if the caller supplies a more permissive client:
	// never forward an operator token to a Location chosen by a server.
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &copyClient
	if edgeToken == "" || edgeToken == token {
		return result, fmt.Errorf("Edge inspection requires a separate admin.state.read-only credential")
	}
	// Confirm the credential's actual scope at the CP before any Edge sees it.
	// A misplaced operator-token file must not become an implicit fallback.
	code, raw, err := authInstallRequest(ctx, client, "GET", base+"/admin/session", edgeToken, nil)
	if err != nil {
		return result, err
	}
	var identity struct {
		AuthMethod string   `json:"auth_method"`
		Scopes     []string `json:"scopes"`
		TokenID    string   `json:"api_token_id"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &identity) != nil || identity.AuthMethod != "admin_api_token" || identity.TokenID == "" || len(identity.Scopes) != 1 || identity.Scopes[0] != "admin.state.read" {
		return result, fmt.Errorf("Edge inspection credential must be a named API token with exactly admin.state.read; no broader credential is sent to Edges")
	}
	wait := func() error {
		timer := time.NewTimer(poll)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return fmt.Errorf("authentication setup timed out in phase %s; fix the listed members and rerun the same command", result.Phase)
		case <-timer.C:
			return nil
		}
	}
	var committed authrollout.State
	for {
		code, raw, err := authInstallRequest(ctx, client, "GET", base+"/admin/auth-rollout", token, nil)
		if err != nil {
			return result, err
		}
		if code == http.StatusOK {
			var state authrollout.State
			if json.Unmarshal(raw, &state) != nil || state.Validate() != nil {
				return result, fmt.Errorf("authority returned an invalid authentication census")
			}
			if !sameAuthCensus(census, state.Manifest) {
				return result, fmt.Errorf("authority census differs from this complete plan; reconcile the generation and member identities before activation")
			}
			features := append(append([]string{}, state.Enabled...), requested...)
			slices.Sort(features)
			features = slices.Compact(features)
			result.Features = features
			if state.Complete && hasAllFeatures(state.Enabled, features) {
				committed = state
				break
			}
			result.Waiting = nil
			for _, m := range state.Manifest.Members {
				if m.Retired {
					continue
				}
				o, ok := state.Observed[m.ID]
				if !ok || o.Generation != state.Manifest.Generation || time.Since(o.ReceivedAt) >= authrollout.FreshFor || !hasAllFeatures(o.Features, features) {
					result.Waiting = append(result.Waiting, m.ID)
				}
			}
			if len(result.Waiting) == 0 {
				body, _ := json.Marshal(map[string]any{"generation": state.Manifest.Generation, "features": features})
				code, _, err = authInstallRequest(ctx, client, "POST", base+"/admin/auth-rollout/activate", token, body)
				if err != nil {
					return result, err
				}
				if code != 200 && code != 409 && code < 500 {
					return result, fmt.Errorf("activation was not committed (HTTP %d)", code)
				}
				result.Phase = "confirming-activation"
			}
		} else if code < 500 {
			return result, fmt.Errorf("cannot inspect authentication authority (HTTP %d)", code)
		}
		if err := wait(); err != nil {
			return result, err
		}
	}
	result.Phase = "waiting-for-edge-application"
	manifest, _ := json.Marshal(committed.Manifest)
	hash := sha256.Sum256(manifest)
	wantHash := hex.EncodeToString(hash[:])
	for {
		result.Waiting = nil
		result.AppliedEdges = 0
		for _, edge := range edges {
			code, raw, err := authInstallRequest(ctx, client, "GET", edge.URL+"/admin/config-sync-status", edgeToken, nil)
			if err != nil {
				return result, err
			}
			var status struct {
				Auth struct {
					Available  bool     `json:"state_available"`
					NodeID     string   `json:"node_id"`
					Generation uint64   `json:"generation"`
					Revision   uint64   `json:"revision"`
					Complete   bool     `json:"complete"`
					Features   []string `json:"enabled_features"`
					Census     string   `json:"census_sha256"`
				} `json:"auth_rollout"`
			}
			if code != 200 || json.Unmarshal(raw, &status) != nil || !status.Auth.Available || status.Auth.NodeID != edge.ID || !status.Auth.Complete || status.Auth.Generation != committed.Manifest.Generation || status.Auth.Revision < committed.Revision || status.Auth.Census != wantHash || !hasAllFeatures(status.Auth.Features, committed.Enabled) {
				result.Waiting = append(result.Waiting, edge.ID)
				continue
			}
			result.AppliedEdges++
		}
		if len(result.Waiting) == 0 {
			// A concurrent census or capability change must not be reported
			// ready using an earlier set of targets or weaker enabled features.
			code, raw, err := authInstallRequest(ctx, client, "GET", base+"/admin/auth-rollout", token, nil)
			if err != nil {
				return result, err
			}
			var current authrollout.State
			if code != 200 || json.Unmarshal(raw, &current) != nil || current.Validate() != nil {
				return result, fmt.Errorf("could not confirm the final authority state; rerun setup")
			}
			if !sameAuthCensus(committed.Manifest, current.Manifest) {
				return result, fmt.Errorf("authentication census changed during setup; reconcile the complete plan before retrying")
			}
			if !current.Complete || !hasAllFeatures(current.Enabled, committed.Enabled) {
				return result, fmt.Errorf("authority activation regressed during setup")
			}
			currentManifest, _ := json.Marshal(current.Manifest)
			if currentHash := sha256.Sum256(currentManifest); hex.EncodeToString(currentHash[:]) != wantHash {
				return result, fmt.Errorf("authority census changed during setup")
			}
			if !slices.Equal(committed.Enabled, current.Enabled) {
				committed = current
				result.Features = append([]string{}, current.Enabled...)
				continue
			}
			result.Phase = "ready"
			return result, nil
		}
		if err := wait(); err != nil {
			return result, err
		}
	}
}

func hasAllFeatures(have, want []string) bool {
	for _, f := range want {
		if !slices.Contains(have, f) {
			return false
		}
	}
	return true
}

func runActivateAuth(ctx context.Context, dir, planPath, cp, token, edgeToken, extraFeatures string) (authInstallResult, error) {
	var empty authInstallResult
	plan, err := loadInstallPlan(dir, planPath)
	if err != nil {
		return empty, err
	}
	if !declaredNodeMapProfile(plan.Profile) {
		return empty, fmt.Errorf("shared-fleet setup requires a declared shared-fleet profile; use the rolling-upgrade procedure for legacy deployments")
	}
	raw, err := os.ReadFile(filepath.Join(dir, authCensusFile))
	if err != nil {
		return empty, err
	}
	var census authrollout.Manifest
	if json.Unmarshal(raw, &census) != nil {
		return empty, fmt.Errorf("invalid local authentication census")
	}
	if census.Deployment != plan.Deployment {
		return empty, fmt.Errorf("census belongs to another deployment")
	}
	wanted := map[string]string{}
	for _, m := range plan.machines() {
		if m.Holds.has("control-plane") {
			wanted[authMemberID(m.Name, "cp")] = "cp"
		}
		if m.Holds.has("edges") {
			wanted[authMemberID(m.Name, "edge")] = "edge"
		}
	}
	for _, member := range census.Members {
		if member.Retired {
			continue
		}
		if wanted[member.ID] != member.Role {
			return empty, fmt.Errorf("the complete plan and local census disagree on active members")
		}
		delete(wanted, member.ID)
	}
	if len(wanted) != 0 {
		return empty, fmt.Errorf("the local census omits a planned member")
	}
	features := append([]string{}, sharedFleetAuthFeatures...)
	if extraFeatures != "" {
		for _, f := range strings.Split(extraFeatures, ",") {
			if f != authrollout.DeviceUserFeature {
				return empty, fmt.Errorf("the only additional opt-in feature is device-user-session-v1; prepare user assignments and endpoints first")
			}
			features = append(features, f)
		}
	}
	if cp == "" {
		cp = "https://" + plan.PlaneNamesFor(plan.foundingRegion().ID)["admin"]
	}
	cp = resolveDoorArguments(cp)
	u, err := url.Parse(cp)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return empty, fmt.Errorf("control plane must be a direct HTTPS management origin without authentication parameters")
	}
	client, err := deploymentClient(dir)
	if err != nil {
		return empty, err
	}
	defer client.CloseIdleConnections()
	var edges []authInstallEdge
	for _, target := range plan.nodeAdminTargets() {
		if target.Role != "edge" {
			continue
		}
		region, m, _ := plan.find(target.Machine)
		owner := m
		if plan.dedicatedMultiEdge() {
			owner = region.controlPlane()
		}
		endpoint := resolveDoorArguments("https://" + target.Label + ".admin." + plan.Deployment + "@" + owner.reachableAt())
		edges = append(edges, authInstallEdge{ID: authMemberID(m.Name, "edge"), URL: endpoint})
	}
	return activateFleetAuthentication(ctx, client, strings.TrimSuffix(cp, "/"), token, edgeToken, census, edges, features, 2*time.Second)
}
