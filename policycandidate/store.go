package policycandidate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// ErrPersistence identifies a candidate change that could not be saved.
var ErrPersistence = errors.New("policy candidate persistence failed")

type RuntimeStore interface {
	List(context.Context, string, ListOptions) (ListResponse, error)
	Get(context.Context, string, string) (Candidate, bool, error)
	Upsert(context.Context, Candidate, string, time.Time) (Candidate, error)
	Review(context.Context, string, string, ReviewRequest, time.Time) (Candidate, bool, error)
}

type ListOptions struct {
	Status        string
	CandidateType string
	Limit         int
}

type ListResponse struct {
	Candidates []Candidate `json:"candidates"`
	Count      int         `json:"count"`
	Limit      int         `json:"limit"`
}

type Candidate struct {
	CandidateID    string   `json:"candidate_id"`
	TenantID       string   `json:"tenant_id"`
	CandidateType  string   `json:"candidate_type"`
	Source         string   `json:"source"`
	ProposedAction string   `json:"proposed_action"`
	ApplicationID  string   `json:"application_id"`
	ServiceFamily  string   `json:"service_family"`
	ReasonCodes    []string `json:"reason_codes"`
	// Cert-pinning detection candidates carry only non-secret observation metadata (a normalized host/
	// SNI + port, a reason code, and how many times/last when it was observed) — never raw IPs, payloads,
	// user material, certificates, or tokens.
	Host         string  `json:"host,omitempty"`
	SNI          string  `json:"sni,omitempty"`
	Port         int     `json:"port,omitempty"`
	FailureCount int     `json:"failure_count,omitempty"`
	LastObserved *string `json:"last_observed,omitempty"`
	// Confidence + SuggestedAction classify how safe it is to act on a cert-pin candidate from its non-secret
	// evidence (design: approve an ENTITY, not an IP). An unattributed candidate — identified only by a raw IP
	// literal with no SNI — is "low" / "investigate_only" and must NEVER be presented as a strong active-bypass
	// approval target. A hostname/SNI gives a named entity, so it is "medium" / "review". Empty on non-cert-pin
	// candidates. Advisory metadata only — it does not itself bypass anything (materialize still gates that).
	Confidence      string `json:"confidence,omitempty"`
	SuggestedAction string `json:"suggested_action,omitempty"`
	// AttributionSource records how the candidate's named entity was recovered: "dns_tunnel_correlation" (the
	// design's highest-trust evidence — a DNS-over-tunnel answer tied the flow's IP to its FQDN), else empty
	// (the name came from SNI/hostname, or it stayed an unattributed raw IP). ObservedIP keeps the originating
	// connect-by-IP address as evidence when the entity was recovered from DNS. Non-secret, cert-pin only.
	AttributionSource string `json:"attribution_source,omitempty"`
	ObservedIP        string `json:"observed_ip,omitempty"`
	// Connector UX Slice 4 (connector_discovered candidates) — additive, omitempty. A connector-discovered
	// candidate is a destination a tenant's connector DECLARES it can reach (reachable_routes) that is not yet
	// published as a private_app. It is never auto-published/auto-allowed; an administrator approves it (as
	// web|tcp|network) to materialize a published Private App via the publish path. The destination itself is
	// carried in Host (non-secret — reachable-route domains are already in the admin route projection). These
	// fields are attribution only (by design): which connector/site observed it and the non-secret evidence.
	ObservedFromConnectorID string   `json:"observed_from_connector_id,omitempty"`
	ObservedFromSite        string   `json:"observed_from_site,omitempty"`
	Namespace               string   `json:"namespace,omitempty"`
	PublishProtocol         string   `json:"publish_protocol,omitempty"`
	Evidence                []string `json:"evidence,omitempty"`
	Status                  string   `json:"status"`
	ReviewReasonCode        string   `json:"review_reason_code"`
	ReviewedAt              *string  `json:"reviewed_at"`
	UpdatedAt               *string  `json:"updated_at"`
}

type ReviewRequest struct {
	Decision         string `json:"decision"`
	ReviewReasonCode string `json:"review_reason_code"`
}

type Store struct {
	mu              sync.RWMutex
	candidates      map[string]map[string]Candidate
	persister       blobstore.Persister // when set, candidates are persisted here so they survive a restart
	sharedKnown     bool
	sharedUncertain bool
	dirty           bool // a failed save may have replaced storage without confirming durability
	// receipts records the reports applied (see ApplyReport). On a shared store the row is authoritative and this
	// is only the copy a detached edit works on.
	receipts map[string]ReportReceipt
}

func NewStore() *Store {
	return &Store{candidates: map[string]map[string]Candidate{}}
}

func (store *Store) List(ctx context.Context, tenantID string, options ListOptions) (ListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ListResponse{}, fmt.Errorf("tenant_id is required")
	}
	status := strings.TrimSpace(options.Status)
	if status != "" && !validStatus(status) {
		return ListResponse{}, fmt.Errorf("candidate status %s is invalid", status)
	}
	candidateType := strings.TrimSpace(options.CandidateType)
	if candidateType != "" && !validType(candidateType) {
		return ListResponse{}, fmt.Errorf("candidate_type %s is invalid", candidateType)
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.refreshSharedLocked(ctx); err != nil {
		return ListResponse{}, err
	}

	rows := []Candidate{}
	for _, candidate := range store.candidates[tenantID] {
		if status != "" && candidate.Status != status {
			continue
		}
		if candidateType != "" && candidate.CandidateType != candidateType {
			continue
		}
		rows = append(rows, copyCandidate(candidate))
	}
	sortCandidates(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return ListResponse{
		Candidates: rows,
		Count:      count,
		Limit:      limit,
	}, nil
}

func (store *Store) Get(ctx context.Context, tenantID, candidateID string) (Candidate, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	candidateID = strings.TrimSpace(candidateID)
	if tenantID == "" {
		return Candidate{}, false, fmt.Errorf("tenant_id is required")
	}
	if candidateID == "" {
		return Candidate{}, false, fmt.Errorf("candidate_id is required")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.refreshSharedLocked(ctx); err != nil {
		return Candidate{}, false, err
	}

	candidate, ok := store.candidates[tenantID][candidateID]
	if !ok {
		return Candidate{}, false, nil
	}
	return copyCandidate(candidate), true, nil
}

func (store *Store) Upsert(ctx context.Context, candidate Candidate, tenantID string, now time.Time) (Candidate, error) {
	normalized, err := normalize(candidate, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		return sharedCandidateMutation(store, ctx, func(next *Store) (Candidate, error) { return next.Upsert(ctx, candidate, tenantID, now) })
	}

	if err := store.putLocked(normalized); err != nil {
		return copyCandidate(normalized), err
	}
	return copyCandidate(normalized), nil
}

func (store *Store) Review(ctx context.Context, tenantID, candidateID string, review ReviewRequest, now time.Time) (Candidate, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	candidateID = strings.TrimSpace(candidateID)
	if tenantID == "" {
		return Candidate{}, false, fmt.Errorf("tenant_id is required")
	}
	if candidateID == "" {
		return Candidate{}, false, fmt.Errorf("candidate_id is required")
	}
	review.Decision = strings.TrimSpace(review.Decision)
	if !validReviewDecision(review.Decision) {
		return Candidate{}, false, fmt.Errorf("review decision %s is invalid", review.Decision)
	}
	review.ReviewReasonCode = strings.TrimSpace(review.ReviewReasonCode)
	if review.ReviewReasonCode != "" && !safeAdminCatalogRef(review.ReviewReasonCode) {
		return Candidate{}, false, fmt.Errorf("review_reason_code is invalid")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		result, err := sharedCandidateMutation(store, ctx, func(next *Store) (candidateLookup, error) {
			c, found, err := next.Review(ctx, tenantID, candidateID, review, now)
			return candidateLookup{c, found}, err
		})
		return result.candidate, result.found, err
	}

	candidate, ok := store.candidates[tenantID][candidateID]
	if !ok {
		return Candidate{}, false, nil
	}
	return store.applyReviewLocked(candidate, review, now)
}

// applyReviewLocked preserves the same save/error contract for ordinary review
// and conditional publication approval. The caller holds mu.
func (store *Store) applyReviewLocked(candidate Candidate, review ReviewRequest, now time.Time) (Candidate, bool, error) {
	reviewedAt := now.UTC().Format(time.RFC3339)
	candidate.Status = review.Decision
	candidate.ReviewReasonCode = review.ReviewReasonCode
	candidate.ReviewedAt = &reviewedAt
	candidate.UpdatedAt = &reviewedAt
	if err := store.putLocked(candidate); err != nil {
		return copyCandidate(candidate), true, err
	}
	return copyCandidate(candidate), true, nil
}

// putLocked publishes only after the candidate snapshot has been saved.
func (store *Store) putLocked(candidate Candidate) error {
	next := store.cloneLocked()
	if next[candidate.TenantID] == nil {
		next[candidate.TenantID] = map[string]Candidate{}
	}
	next[candidate.TenantID][candidate.CandidateID] = copyCandidate(candidate)
	return store.commitLocked(next)
}

func normalize(candidate Candidate, tenantID string, now time.Time) (Candidate, error) {
	return normalizeWithEvidenceValidation(candidate, tenantID, now, true)
}

// Observations author new counters/timestamps but do not edit an administrator's
// historical review metadata. Validate the new observation and preserve that review.
func normalizeObservation(candidate Candidate, tenantID string, now time.Time) (Candidate, error) {
	reason, reviewed := candidate.ReviewReasonCode, candidate.ReviewedAt
	candidate.ReviewReasonCode, candidate.ReviewedAt, candidate.UpdatedAt = "", nil, nil
	next, err := normalize(candidate, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}
	next.ReviewReasonCode, next.ReviewedAt = reason, reviewed
	return next, nil
}

func normalizeWithEvidenceValidation(candidate Candidate, tenantID string, now time.Time, validateEvidence bool) (Candidate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Candidate{}, fmt.Errorf("tenant_id is required")
	}
	candidate.CandidateID = strings.TrimSpace(candidate.CandidateID)
	if candidate.CandidateID == "" {
		return Candidate{}, fmt.Errorf("candidate_id is required")
	}
	if strings.Contains(candidate.CandidateID, "/") {
		return Candidate{}, fmt.Errorf("candidate_id cannot contain slash")
	}
	candidate.TenantID = strings.TrimSpace(candidate.TenantID)
	if candidate.TenantID == "" {
		candidate.TenantID = tenantID
	}
	if candidate.TenantID != tenantID {
		return Candidate{}, fmt.Errorf("candidate tenant_id %s does not match authenticated tenant_id %s", candidate.TenantID, tenantID)
	}
	candidate.Source = strings.TrimSpace(candidate.Source)
	if candidate.Source == "" {
		candidate.Source = SourceUnmatchedFlow
	}
	if !validSource(candidate.Source) {
		return Candidate{}, fmt.Errorf("candidate source %s is invalid", candidate.Source)
	}
	certPin := candidate.Source == SourceCertPinningDetection
	connectorDiscovered := candidate.Source == SourceConnectorDiscovered
	candidate.CandidateType = strings.TrimSpace(candidate.CandidateType)
	if candidate.CandidateType == "" {
		switch {
		case certPin:
			candidate.CandidateType = "bypass_policy"
		case connectorDiscovered:
			candidate.CandidateType = "private_app"
		default:
			candidate.CandidateType = "allow_policy"
		}
	}
	if !validType(candidate.CandidateType) {
		return Candidate{}, fmt.Errorf("candidate_type %s is invalid", candidate.CandidateType)
	}
	candidate.ProposedAction = strings.TrimSpace(candidate.ProposedAction)
	if candidate.ProposedAction == "" {
		candidate.ProposedAction = proposedActionForCandidateType(candidate.CandidateType)
	}
	if !validAction(candidate.ProposedAction) {
		return Candidate{}, fmt.Errorf("proposed_action %s is invalid", candidate.ProposedAction)
	}
	candidate.ApplicationID = strings.TrimSpace(candidate.ApplicationID)
	if strings.Contains(candidate.ApplicationID, "/") {
		return Candidate{}, fmt.Errorf("application_id cannot contain slash")
	}
	candidate.ServiceFamily = strings.TrimSpace(candidate.ServiceFamily)
	candidate.Host = normalizeHostValue(candidate.Host)
	candidate.SNI = normalizeHostValue(candidate.SNI)
	candidate.PublishProtocol = strings.TrimSpace(candidate.PublishProtocol)
	if candidate.PublishProtocol != "" && !validPublishProtocol(candidate.PublishProtocol) {
		return Candidate{}, fmt.Errorf("publish_protocol %s is invalid", candidate.PublishProtocol)
	}
	candidate.ObservedFromConnectorID = strings.TrimSpace(candidate.ObservedFromConnectorID)
	if candidate.ObservedFromConnectorID != "" && !safeAdminCatalogRef(candidate.ObservedFromConnectorID) {
		return Candidate{}, fmt.Errorf("observed_from_connector_id is invalid")
	}
	candidate.ObservedFromSite = strings.TrimSpace(candidate.ObservedFromSite)
	if candidate.ObservedFromSite != "" && !safeAdminCatalogRef(candidate.ObservedFromSite) {
		return Candidate{}, fmt.Errorf("observed_from_site is invalid")
	}
	candidate.Namespace = strings.TrimSpace(candidate.Namespace)
	if candidate.Namespace != "" && !safeAdminCatalogRef(candidate.Namespace) {
		return Candidate{}, fmt.Errorf("namespace is invalid")
	}
	candidate.Evidence = normalizedStringList(candidate.Evidence)
	switch {
	case certPin:
		// cert-pinning candidates are identified by host/SNI, not an application id.
		if candidate.ServiceFamily == "" {
			candidate.ServiceFamily = "https"
		}
		if candidate.Host == "" && candidate.SNI == "" {
			return Candidate{}, fmt.Errorf("cert-pinning candidate requires host or sni")
		}
		if candidate.Port < 0 || candidate.Port > 65535 {
			return Candidate{}, fmt.Errorf("port is out of range")
		}
		if candidate.FailureCount < 0 {
			return Candidate{}, fmt.Errorf("failure_count cannot be negative")
		}
	case connectorDiscovered:
		// connector-discovered candidates are identified by the declared reachable DESTINATION (Host), not an
		// application id (the application id is minted only at approve/publish time). No auto-publish: this just
		// records the proposal.
		if candidate.Host == "" {
			return Candidate{}, fmt.Errorf("connector-discovered candidate requires a destination (host)")
		}
		if candidate.Port < 0 || candidate.Port > 65535 {
			return Candidate{}, fmt.Errorf("port is out of range")
		}
		if candidate.ServiceFamily == "" {
			candidate.ServiceFamily = "https"
		}
	default:
		if candidate.ApplicationID == "" {
			return Candidate{}, fmt.Errorf("application_id is required")
		}
		if candidate.ServiceFamily == "" {
			return Candidate{}, fmt.Errorf("service_family is required")
		}
	}
	candidate.ReasonCodes = normalizedStringList(candidate.ReasonCodes)
	candidate.Status = strings.TrimSpace(candidate.Status)
	if candidate.Status == "" {
		candidate.Status = "pending"
	}
	if !validStatus(candidate.Status) {
		return Candidate{}, fmt.Errorf("candidate status %s is invalid", candidate.Status)
	}
	if validateEvidence {
		if err := validateCandidateEvidence(candidate); err != nil {
			return Candidate{}, err
		}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	candidate.UpdatedAt = &updatedAt
	return candidate, nil
}

func validType(candidateType string) bool {
	switch candidateType {
	case "allow_policy", "bypass_policy", "private_app":
		return true
	default:
		return false
	}
}

// validPublishProtocol mirrors the appcatalog publish app-type enum (web|tcp|network). Connector-discovered
// candidates carry a suggested publish protocol; the administrator can override it at approve time.
func validPublishProtocol(publishProtocol string) bool {
	switch publishProtocol {
	case "web", "tcp", "network":
		return true
	default:
		return false
	}
}

// SourceCertPinningDetection marks a candidate proposed by the edge's cert-pinning detector: a host
// repeatedly rejected the interception leaf, so it is proposed as a TLS decrypt-bypass candidate for an
// administrator to approve. Detection only proposes — it never auto-bypasses.
const SourceCertPinningDetection = "cert_pinning_detection"

func validSource(source string) bool {
	switch source {
	// "policy_learning" is the retired name for SourceUnmatchedFlow. Policy Learning was removed on
	// 2026-08-05, but candidates recorded under the old name are already on disk, and a durable store that
	// rejects its own history fails closed on load and takes the whole candidate list with it.
	case "policy_learning", SourceUnmatchedFlow, "operator", "import", SourceCertPinningDetection, SourceConnectorDiscovered:
		return true
	default:
		return false
	}
}

func validAction(action string) bool {
	switch action {
	case "allow", "bypass", "publish":
		return true
	default:
		return false
	}
}

func validStatus(status string) bool {
	switch status {
	// pending: awaiting an admin decision. approved: admin accepted the bypass but it is not yet applied.
	// materialized: the approved bypass has been written into the SWG TLS bypass policy (the only state in
	// which traffic is actually decrypt-bypassed). rejected: declined. suppressed: known, notifications
	// muted, but not bypassed. dismissed: retained for back-compat (treated like suppressed).
	case "pending", "approved", "materialized", "rejected", "suppressed", "dismissed":
		return true
	default:
		return false
	}
}

func validReviewDecision(decision string) bool {
	switch decision {
	case "approved", "rejected", "suppressed", "dismissed":
		return true
	default:
		return false
	}
}

func proposedActionForCandidateType(candidateType string) string {
	switch candidateType {
	case "bypass_policy":
		return "bypass"
	case "private_app":
		return "publish"
	default:
		return "allow"
	}
}

func copyCandidate(candidate Candidate) Candidate {
	candidate.ReasonCodes = append([]string(nil), candidate.ReasonCodes...)
	candidate.Evidence = append([]string(nil), candidate.Evidence...)
	copyString := func(p *string) *string {
		if p == nil {
			return nil
		}
		value := *p
		return &value
	}
	candidate.LastObserved = copyString(candidate.LastObserved)
	candidate.ReviewedAt = copyString(candidate.ReviewedAt)
	candidate.UpdatedAt = copyString(candidate.UpdatedAt)
	return candidate
}

func sortCandidates(candidates []Candidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Status != candidates[j].Status {
			return candidates[i].Status < candidates[j].Status
		}
		return candidates[i].CandidateID < candidates[j].CandidateID
	})
}

// normalizedStringList trims, de-dups, drops empties (order-preserving) — package-local copy.
func normalizedStringList(values []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}

// safeAdminCatalogRef reports whether value is a safe catalog identifier (alphanumerics + _-).
func safeAdminCatalogRef(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

// CountForTenant / RemoveTenant put the observed policy candidates into a tenant's data footprint and its
// erasure (2026-08-18). A candidate names a destination this organization's devices could not be inspected
// against — an observation ABOUT them — so it is theirs to have erased. Keyed by tenant at the top level.
func (s *Store) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.candidates[tenantID])
}

func (s *Store) RemoveTenant(tenantID string) (int, error) {
	return s.RemoveTenantContext(context.Background(), tenantID)
}

func (s *Store) RemoveTenantContext(ctx context.Context, tenantID string) (int, error) {
	if s == nil {
		return 0, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(candidateSharedPersister); ok {
		return sharedCandidateMutation(s, ctx, func(next *Store) (int, error) { return next.RemoveTenantContext(ctx, tenantID) })
	}
	n := len(s.candidates[tenantID])
	if n == 0 && !s.dirty {
		return 0, nil
	}
	next := s.cloneLocked()
	delete(next, tenantID)
	if err := s.commitLocked(next); err != nil {
		return 0, err
	}
	return n, nil
}
