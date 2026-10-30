// Package authrollout tracks an operator-declared, complete deployment census.
// Recent reporters are observations of that census, never its membership source.
package authrollout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

const Schema = 1
const EvidenceFeature = "grant-evidence-v1"
const SingleRequestFeature = "single-request-v1"
const DeviceUserFeature = "device-user-session-v1"
const CeremonyRecoveryFeature = "ceremony-recovery-v1"
const RevocationReauthenticationFeature = "revocation-reauthentication-v1"
const FreshFor = 2 * time.Minute

var errUnchangedState = errors.New("unchanged authentication rollout state")

var ErrConflict = errors.New("authentication rollout state conflict")
var ErrNotReady = errors.New("not all expected nodes have confirmed the required capabilities")

// Member pins an individual CP or Edge process identity, not an endpoint's
// tenant identity or a self-reported node name. Version is the operator's
// inventory of the installed version before the first capability report.
// Retired members remain in the census with an explicit reason.
type Member struct {
	ID                string `json:"id"`
	Role              string `json:"role"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Version           string `json:"version"`
	Retired           bool   `json:"retired,omitempty"`
	RetirementReason  string `json:"retirement_reason,omitempty"`
}
type Manifest struct {
	Deployment string   `json:"deployment"`
	Generation uint64   `json:"generation"`
	Members    []Member `json:"members"`
	// Explicitly capture current provider configuration at the start of a
	// migration. A legacy grant must not survive a subsequent IdP replacement.
	Providers map[string]string `json:"provider_digests,omitempty"`
}

// ProviderKey keeps tenant/IdP names out of deployment-wide compatibility state.
// JSON framing before hashing makes the two input fields unambiguous.
func ProviderKey(tenant, idp string) string {
	b, _ := json.Marshal([]string{tenant, idp})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Report struct {
	Generation uint64   `json:"generation"`
	NodeID     string   `json:"node_id"`
	Version    string   `json:"version"`
	Features   []string `json:"features"`
}
type Observation struct {
	Report
	ReceivedAt time.Time `json:"received_at"`
}
type State struct {
	Schema   int      `json:"schema"`
	Manifest Manifest `json:"manifest"`
	Revision uint64   `json:"revision"`
	// Complete is a durable one-way latch. Neither a stale report nor a new
	// membership generation may reopen legacy acceptance.
	Complete bool                   `json:"complete"`
	Enabled  []string               `json:"enabled_features,omitempty"`
	Observed map[string]Observation `json:"observed"`
}

func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && strings.ToLower(s) == s
}
func (m Manifest) Validate() error {
	if strings.TrimSpace(m.Deployment) == "" || m.Generation == 0 || len(m.Members) == 0 || len(m.Members) > 4096 {
		return fmt.Errorf("invalid deployment census")
	}
	ids, pins := map[string]bool{}, map[string]bool{}
	cp, edge := false, false
	for _, n := range m.Members {
		if n.ID == "" || n.ID != strings.TrimSpace(n.ID) || (n.Role != "cp" && n.Role != "edge") || n.Version == "" || !validHash(n.CertificateSHA256) || ids[n.ID] || pins[n.CertificateSHA256] {
			return fmt.Errorf("invalid or duplicate member identity")
		}
		if n.Retired != (strings.TrimSpace(n.RetirementReason) != "") {
			return fmt.Errorf("retirement requires an explicit reason")
		}
		ids[n.ID], pins[n.CertificateSHA256] = true, true
		if !n.Retired {
			cp = cp || n.Role == "cp"
			edge = edge || n.Role == "edge"
		}
	}
	if !cp || !edge {
		return fmt.Errorf("census requires active CP and Edge members")
	}
	for k, d := range m.Providers {
		if !validHash(k) || !validHash(d) {
			return fmt.Errorf("invalid provider baseline")
		}
	}

	return nil
}
func normalizeFeatures(features []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(features))
	if len(features) > 128 {
		return nil, fmt.Errorf("too many capabilities")
	}
	for _, f := range features {
		if f == "" || len(f) > 128 || f != strings.TrimSpace(f) || seen[f] {
			return nil, fmt.Errorf("invalid or duplicate capability")
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}
func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
func (s State) Validate() error {
	if s.Schema != Schema || s.Revision == 0 {
		return fmt.Errorf("unsupported or invalid rollout snapshot")
	}
	if e := s.Manifest.Validate(); e != nil {
		return e
	}
	if _, e := normalizeFeatures(s.Enabled); e != nil {
		return e
	}
	if s.Complete && !contains(s.Enabled, EvidenceFeature) {
		return fmt.Errorf("completed rollout has no evidence capability")
	}
	if !s.Complete && len(s.Enabled) > 0 {
		return fmt.Errorf("mixed rollout cannot enable new features")
	}
	members := map[string]Member{}
	for _, n := range s.Manifest.Members {
		members[n.ID] = n
	}
	for id, o := range s.Observed {
		n, ok := members[id]
		if !ok || n.Retired || o.NodeID != id || o.Generation != s.Manifest.Generation || o.Version == "" || o.ReceivedAt.IsZero() {
			return fmt.Errorf("invalid capability observation")
		}
		if _, e := normalizeFeatures(o.Features); e != nil {
			return e
		}
	}
	return nil
}
func (s State) ready(features []string, now time.Time) bool {
	for _, n := range s.Manifest.Members {
		if n.Retired {
			continue
		}
		o, ok := s.Observed[n.ID]
		if !ok || o.Generation != s.Manifest.Generation || now.Before(o.ReceivedAt) || !now.Before(o.ReceivedAt.Add(FreshFor)) {
			return false
		}
		for _, f := range features {
			if !contains(o.Features, f) {
				return false
			}
		}
	}
	return true
}

// Store requires a transactional persister for shared use. Local file stores
// are single-owner only. Failed or ambiguous commits never publish candidate state.
type Store struct {
	mu sync.Mutex
	p  blobstore.Persister
	// localRevision invalidates process-local authorization snapshots after a
	// successful write. Other processes are discovered by bounded polling.
	localRevision uint64
}

func NewStore(p blobstore.Persister) *Store { return &Store{p: p} }
func (s *Store) LocalRevision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localRevision
}
func decode(raw []byte) (State, error) {
	var s State
	if len(raw) == 0 {
		return s, nil
	}
	if e := json.Unmarshal(raw, &s); e != nil {
		return s, e
	}
	return s, s.Validate()
}
func (s *Store) Read() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.p == nil {
		return State{}, fmt.Errorf("rollout persistence is required")
	}
	b, e := s.p.Load()
	if e != nil {
		return State{}, e
	}
	return decode(b)
}
func (s *Store) edit(ctx context.Context, fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.p == nil {
		return fmt.Errorf("rollout persistence is required")
	}
	apply := func(b []byte) ([]byte, error) {
		v, e := decode(b)
		if e != nil {
			return nil, e
		}
		if e = fn(&v); e != nil {
			return nil, e
		}
		if e = v.Validate(); e != nil {
			return nil, e
		}
		return json.Marshal(v)
	}
	if p, ok := s.p.(interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	}); ok {
		err := p.UpdateContext(ctx, apply)
		if errors.Is(err, errUnchangedState) {
			return nil
		}
		if err == nil {
			s.localRevision++
		}
		return err
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := s.p.Load()
	if e != nil {
		return e
	}
	b, e = apply(b)
	if errors.Is(e, errUnchangedState) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	e = blobstore.UnconfirmedSave(s.p.Save(b))
	if e == nil {
		s.localRevision++
	}
	return e
}

// Configure uses a generation CAS. Removed nodes must be explicitly retired;
// an empty/lately-reported list can never accidentally declare an upgrade done.
func (s *Store) Configure(ctx context.Context, previous uint64, m Manifest) error {
	if e := m.Validate(); e != nil {
		return e
	}
	return s.edit(ctx, func(v *State) error {
		if v.Manifest.Generation != previous || m.Generation != previous+1 {
			return ErrConflict
		}
		if previous > 0 {
			if v.Manifest.Deployment != m.Deployment {
				return ErrConflict
			}
			next := map[string]Member{}
			for _, n := range m.Members {
				next[n.ID] = n
			}
			for _, n := range v.Manifest.Members {
				other, ok := next[n.ID]
				if !ok || other.Role != n.Role || other.CertificateSHA256 != n.CertificateSHA256 || (n.Retired && !other.Retired) {
					return fmt.Errorf("members cannot disappear, change identity, or be unretired")
				}
			}
			// A stale inventory must not extend legacy acceptance to a changed IdP.
			a, _ := json.Marshal(v.Manifest.Providers)
			b, _ := json.Marshal(m.Providers)
			if string(a) != string(b) {
				return fmt.Errorf("provider baseline is immutable during an upgrade")
			}
		}
		v.Schema = Schema
		v.Manifest = m
		v.Revision++
		v.Observed = map[string]Observation{}
		return nil
	})
}

// Record accepts a certificate fingerprint verified by the transport, NEVER a
// fingerprint from the request body. The server supplies time, not the reporter.
func (s *Store) Record(ctx context.Context, verifiedCertificate string, report Report, now time.Time) error {
	features, e := normalizeFeatures(report.Features)
	if e != nil {
		return e
	}
	report.Features = features
	if report.Version == "" || now.IsZero() {
		return fmt.Errorf("invalid version report")
	}
	return s.edit(ctx, func(v *State) error {
		if v.Schema == 0 || report.Generation != v.Manifest.Generation {
			return ErrConflict
		}
		found := false
		for _, n := range v.Manifest.Members {
			if n.ID == report.NodeID && !n.Retired && n.CertificateSHA256 == verifiedCertificate {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("reporter is not the expected member")
		}
		for _, f := range v.Enabled {
			if !contains(features, f) {
				return fmt.Errorf("report would downgrade an activated capability")
			}
		}
		// Keep fresh reports while a member advertises an additional capability
		// that an operator may still activate. Otherwise a completed subset would
		// make later activation impossible once its old reports expired.
		allAdvertisedEnabled := true
		for _, feature := range report.Features {
			allAdvertisedEnabled = allAdvertisedEnabled && contains(v.Enabled, feature)
		}
		if v.Complete && allAdvertisedEnabled {
			if previous, ok := v.Observed[report.NodeID]; ok && reflect.DeepEqual(previous.Report, report) {
				return errUnchangedState
			}
		}
		v.Observed[report.NodeID] = Observation{Report: report, ReceivedAt: now.UTC()}
		v.Revision++
		return nil
	})
}

// Activate is an operator/CP action, checked again in the same transaction as
// the latch. A CP restart or promotion reads the same immutable completion.
func (s *Store) Activate(ctx context.Context, generation uint64, features []string, now time.Time) error {
	features, e := normalizeFeatures(features)
	if e != nil {
		return e
	}
	if !contains(features, EvidenceFeature) {
		return fmt.Errorf("evidence capability is required")
	}
	for _, feature := range features {
		if feature == "cross-scope-identity-evidence-v1" {
			return fmt.Errorf("cross-scope identity evidence is not supported")
		}
	}
	return s.edit(ctx, func(v *State) error {
		if v.Schema == 0 || generation != v.Manifest.Generation {
			return ErrConflict
		}
		for _, f := range v.Enabled {
			if !contains(features, f) {
				return fmt.Errorf("enabled capabilities cannot be removed")
			}
		}
		if v.Complete && reflect.DeepEqual(v.Enabled, features) {
			return errUnchangedState
		}
		if !v.ready(features, now) {
			return ErrNotReady
		}
		v.Complete = true
		v.Enabled = features
		v.Revision++
		return nil
	})
}
