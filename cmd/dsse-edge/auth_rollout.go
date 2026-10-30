package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
)

// The authority and an Edge's monotonic cache have different keys. Never let a
// delayed bundle overwrite the authority or a CP promotion reset completion.
type authRolloutRuntime struct {
	statusMu                  sync.Mutex
	lastAttempt, lastAccepted time.Time
	receiveStatus             string
	decisionMu                sync.Mutex
	decisionState             *authrollout.Distribution
	decisionRevision          uint64
	decisionNextRead          time.Time
	decisionAuthority         *authrollout.Store
	decisionCache             *authrollout.Cache
	expected                  *authrollout.Member
	deployment                string
	authority                 *authrollout.Store
	cache                     *authrollout.Cache
}

var theAuthRollout atomic.Pointer[authRolloutRuntime]

func newAuthRolloutRuntime(config serverConfig) (*authRolloutRuntime, error) {
	authority := strings.TrimSpace(config.ConfigSourceURL) == ""
	path := strings.TrimSpace(config.GrantStorePath)
	if path != "" && storeBackend(path) != "postgres" {
		path += ".auth-rollout"
	} else {
		path = ""
	}
	var p blobstore.Persister
	var e error
	if authority && cpStateBlobDB != nil {
		p = postgresBlobPersister{db: cpStateBlobDB, key: "auth_rollout_v1"}
	} else {
		p, e = cpStateBlobPersister(path, nil, "auth_rollout_cache_v1")
	}
	if e != nil {
		return nil, e
	}
	if p == nil {
		return nil, nil
	} // existing ephemeral standalone test/development mode
	r := &authRolloutRuntime{}
	if report := config.AuthRolloutReporter; report != nil {
		r.expected = &report.member
		r.deployment = report.census.Deployment
	}
	if authority {
		r.authority = authrollout.NewStore(p)
		_, e = r.authority.Read()
	} else {
		r.cache = authrollout.NewCache(authrollout.NewStore(p))
		_, e = r.cache.Read()
	}
	return r, e
}
func (r *authRolloutRuntime) distribution(now time.Time) (*authrollout.Distribution, error) {
	if r == nil {
		return nil, nil
	}
	if r.authority != nil {
		return r.authority.Distribute(now)
	}
	if r.cache == nil {
		return nil, fmt.Errorf("authentication rollout cache unavailable")
	}
	d, e := r.cache.Read()
	if e != nil {
		return nil, e
	}
	if d.State.Schema == 0 {
		return nil, nil
	}
	return &d, nil
}

// Authorization may check many grants for one held flow. Polling the shared
// authority or decoding the Edge cache on every candidate makes a transient
// storage fault an immediate fleet-wide authentication outage. Local writes
// invalidate this snapshot immediately; writes by another process are seen
// within the short polling bound. A mixed-phase read failure still fails
// closed. Once completed, enabled features are one-way and the last verified
// snapshot remains usable during a storage outage.
const authRolloutDecisionPoll = 500 * time.Millisecond

func (r *authRolloutRuntime) decisionDistribution(now time.Time) (*authrollout.Distribution, error) {
	if r == nil {
		return nil, nil
	}
	r.decisionMu.Lock()
	defer r.decisionMu.Unlock()
	var revision uint64
	if r.authority != nil {
		revision = r.authority.LocalRevision()
	} else if r.cache != nil {
		revision = r.cache.LocalRevision()
	}
	if !r.decisionNextRead.IsZero() && r.authority == r.decisionAuthority && r.cache == r.decisionCache && revision == r.decisionRevision && now.Before(r.decisionNextRead) {
		return r.decisionState, nil
	}
	if r.authority != r.decisionAuthority || r.cache != r.decisionCache {
		// A different persistence source cannot inherit a previous source's
		// completed state, even if their local revision numbers coincide.
		r.decisionState = nil
	}
	d, err := r.distribution(now)
	r.decisionAuthority, r.decisionCache = r.authority, r.cache
	r.decisionRevision = revision
	r.decisionNextRead = now.Add(authRolloutDecisionPoll)
	if err != nil {
		if r.decisionState != nil && r.decisionState.State.Complete && r.isExpectedMember(r.decisionState) {
			return r.decisionState, nil
		}
		r.decisionState = nil
		return nil, err
	}
	r.decisionState = d
	return d, nil
}
func (r *authRolloutRuntime) acceptLegacy(gr grantstore.Grant, digest string, now time.Time) bool {
	if r == nil || gr.Issuer != "" || gr.ProviderConfigSHA256 != "" || gr.RequiresModernReader() {
		return false
	}
	d, e := r.decisionDistribution(now)
	return e == nil && d != nil && r.isExpectedMember(d) && d.AcceptLegacy(gr.TenantID, gr.IdPID, digest, now)
}
func (r *authRolloutRuntime) featureEnabled(feature string) bool {
	if r == nil {
		return true
	} // standalone runtime, no distributed deployment
	d, e := r.decisionDistribution(time.Now())
	return e == nil && d != nil && r.isExpectedMember(d) && d.FeatureEnabled(feature, time.Now())
}
func (r *authRolloutRuntime) adopt(d *authrollout.Distribution, verified bool, now time.Time) error {
	if d == nil {
		return nil
	} // old CP cannot undo a persisted completion latch
	if !verified {
		return fmt.Errorf("authentication rollout requires a signed configuration bundle")
	}
	if r == nil || r.cache == nil {
		return fmt.Errorf("authentication rollout has no durable Edge cache")
	}
	return r.cache.Adopt(context.Background(), *d, now)
}
func decodeAuthRollout(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}
func registerAuthRolloutRoutes(mux *http.ServeMux, admin func(string, http.HandlerFunc) http.HandlerFunc, runtime *authRolloutRuntime) {
	if runtime == nil || runtime.authority == nil {
		return
	}
	store := runtime.authority
	mux.HandleFunc("GET /admin/auth-rollout", admin("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		s, e := store.Read()
		if e != nil {
			writeError(w, 503, fmt.Errorf("authentication rollout unavailable"))
			return
		}
		writeJSON(w, 200, s)
	}))
	mux.HandleFunc("PUT /admin/auth-rollout", admin("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		ctx := captureCPWriteLease(r.Context())
		var body struct {
			PreviousGeneration uint64               `json:"previous_generation"`
			Manifest           authrollout.Manifest `json:"manifest"`
		}
		if decodeAuthRollout(w, r, &body) != nil {
			writeError(w, 400, fmt.Errorf("invalid deployment census"))
			return
		}
		if e := store.Configure(ctx, body.PreviousGeneration, body.Manifest); e != nil {
			writeError(w, 409, fmt.Errorf("deployment census was not committed: %w", e))
			return
		}
		writeJSON(w, 200, map[string]bool{"saved": true})
	}))
	mux.HandleFunc("POST /admin/auth-rollout/activate", admin("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		ctx := captureCPWriteLease(r.Context())
		var body struct {
			Generation uint64   `json:"generation"`
			Features   []string `json:"features"`
		}
		if decodeAuthRollout(w, r, &body) != nil {
			writeError(w, 400, fmt.Errorf("invalid activation"))
			return
		}
		for _, f := range body.Features {
			if f != authrollout.EvidenceFeature && f != authrollout.SingleRequestFeature && f != authrollout.DeviceUserFeature && f != authrollout.CeremonyRecoveryFeature && f != authrollout.RevocationReauthenticationFeature {
				writeError(w, 400, fmt.Errorf("this CP does not support the requested feature"))
				return
			}
		}
		if e := store.Activate(ctx, body.Generation, body.Features, time.Now()); e != nil {
			writeError(w, 409, fmt.Errorf("authentication rollout not activated: %w", e))
			return
		}
		writeJSON(w, 200, map[string]bool{"activated": true})
	}))
	mux.HandleFunc("POST /fleet-capabilities/report", func(w http.ResponseWriter, r *http.Request) {
		ctx := captureCPWriteLease(r.Context())
		// No lab bypass: a bearer, a claimed CN or body field is not node evidence.
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			writeError(w, 403, fmt.Errorf("verified member certificate required"))
			return
		}
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		var body authrollout.Report
		if decodeAuthRollout(w, r, &body) != nil {
			writeError(w, 400, fmt.Errorf("invalid capability report"))
			return
		}
		if e := store.Record(ctx, hex.EncodeToString(sum[:]), body, time.Now()); e != nil {
			writeError(w, 409, fmt.Errorf("capability report was not committed"))
			return
		}
		// Activation is rechecked under the authority transaction; missing or stale
		// members leave the mixed phase intact. Downgrades are never automatic.
		_ = store.Activate(ctx, body.Generation, []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature}, time.Now())
		writeJSON(w, 200, map[string]bool{"recorded": true})
	})
}

// An upgraded binary outside the expected fleet is not allowed to use a census
// belonging to other nodes, even if it received the deployment's config bundle.
func (r *authRolloutRuntime) isExpectedMember(d *authrollout.Distribution) bool {
	if r == nil || r.expected == nil || d.State.Manifest.Deployment != r.deployment {
		return false
	}
	for _, n := range d.State.Manifest.Members {
		if !n.Retired && n.ID == r.expected.ID && n.Role == r.expected.Role && n.CertificateSHA256 == r.expected.CertificateSHA256 {
			return true
		}
	}
	return false
}

// Auxiliary rollout failure must never suppress policies, revocations or IdP updates.
func (r *authRolloutRuntime) receive(d *authrollout.Distribution, verified bool, now time.Time) {
	if r == nil {
		return
	}
	err := r.adopt(d, verified, now)
	status := "accepted"
	if d == nil {
		status = "omitted"
	}
	if err != nil {
		status = "rejected"
	}
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	if status != r.receiveStatus {
		log.Printf("authentication_rollout_receive status=%s", status)
	}
	r.receiveStatus = status
	r.lastAttempt = now
	if status == "accepted" {
		r.lastAccepted = now
	}
}
func (r *authRolloutRuntime) statusSnapshot() map[string]any {
	if r == nil {
		return map[string]any{"enabled": false}
	}
	r.statusMu.Lock()
	out := map[string]any{"enabled": true, "status": r.receiveStatus, "last_attempt": r.lastAttempt, "last_accepted": r.lastAccepted, "state_available": false}
	r.statusMu.Unlock()
	// Only the authenticated config-sync-status surface includes this view.
	// Read the actual durable cache, not the availability fallback used by
	// authorization decisions, so an installer cannot mistake an unreadable
	// state store for freshly applied activation.
	if d, err := r.distribution(time.Now()); err == nil && d != nil && r.isExpectedMember(d) {
		manifest, _ := json.Marshal(d.State.Manifest)
		hash := sha256.Sum256(manifest)
		out["state_available"] = true
		out["node_id"] = r.expected.ID
		out["generation"] = d.State.Manifest.Generation
		out["revision"] = d.State.Revision
		out["complete"] = d.State.Complete
		out["enabled_features"] = d.State.Enabled
		out["census_sha256"] = hex.EncodeToString(hash[:])
	}
	return out
}
