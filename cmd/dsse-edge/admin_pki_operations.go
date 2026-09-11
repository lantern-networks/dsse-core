package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// Staged operations — the sequence an operator must not get wrong, tracked by the system instead of by
// their memory.④ of docs/pki_ux_ideal_design.ja.md.
//
// Replacing what devices trust is four acts in a fixed order: distribute the new certificate, wait until
// every device holds it, switch the Edge onto it, and only then withdraw the old one. Each act already has
// its own endpoint and its own gate. What did not exist was anything that knew an operation was IN FLIGHT —
// so the order lived in a runbook and in the operator's head, and a Console that showed four unrelated
// buttons was asking them to remember it.
//
// THE STAGE IS NOT STORED. Only the intent is: which certificate we are moving to, who started it, when.
// Every stage is then computed from what is measurably true right now — is it distributed, do devices report
// holding it, does the Edge present a chain that verifies against it, have the others been withdrawn. A
// stored stage drifts from reality the moment anything happens outside the wizard (a restart, a direct API
// call, a rollback), and a progress bar that disagrees with the deployment is worse than none. A computed
// stage cannot drift, survives a restart with no recovery logic, and correctly shows an operation somebody
// else advanced by hand.

const pkiOperationSchemaVersion = "admin_pki_operations.v1"

// pkiOperationIntent is all that is persisted.
type pkiOperationIntent struct {
	Kind          string `json:"kind"` // "transport_trust_rotation"
	TargetSHA256  string `json:"target_sha256"`
	TargetSubject string `json:"target_subject,omitempty"`
	StartedBy     string `json:"started_by,omitempty"`
	StartedAt     string `json:"started_at"`
	SchemaVersion string `json:"schema_version"`
}

type pkiOperationStore struct {
	mu      sync.Mutex
	path    string
	current *pkiOperationIntent
}

func openPKIOperationStore(path string) (*pkiOperationStore, error) {
	s := &pkiOperationStore{path: strings.TrimSpace(path)}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read pki operation store %s: %w", s.path, err)
	}
	var intent pkiOperationIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		// A corrupt record must not block the deployment: an operation is a piece of guidance, not a gate.
		logInfof("pki_operation store %s is unreadable (%v) — continuing with no operation in flight", s.path, err)
		return s, nil
	}
	if strings.TrimSpace(intent.TargetSHA256) != "" {
		s.current = &intent
	}
	return s, nil
}

func (s *pkiOperationStore) Current() *pkiOperationIntent {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil
	}
	c := *s.current
	return &c
}

func (s *pkiOperationStore) persistLocked() error {
	if s.current == nil {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	blob, err := json.MarshalIndent(s.current, "", "  ")
	if err != nil {
		return err
	}
	// ★ ONE DURABLE WRITE (2026-08-14). Staged by hand and finished on a bare os.Rename — see
	// ops/checks/one_durable_write.sh: the gate matched only the copies that fsync the directory, so the
	// ones that never did were invisible to it and read as compliant.
	return durablefile.Write(s.path, blob, 0o600)
}

func (s *pkiOperationStore) Start(intent pkiOperationIntent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		return fmt.Errorf("an operation is already in flight (%s) — finish or abandon it first", s.current.Kind)
	}
	s.current = &intent
	return s.persistLocked()
}

func (s *pkiOperationStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = nil
	return s.persistLocked()
}

// --- the computed view -----------------------------------------------------------------------------------

type pkiOperationStage struct {
	Key  string `json:"key"`
	Done bool   `json:"done"`
	// Blocked carries the reason this stage cannot be completed yet — the gate speaking, not a guess.
	Blocked string `json:"blocked,omitempty"`
	// Detail is a measured value (names, counts) the Console renders as-is.
	Detail string `json:"detail,omitempty"`
}

type pkiOperationView struct {
	SchemaVersion string              `json:"schema_version"`
	InFlight      bool                `json:"in_flight"`
	Kind          string              `json:"kind,omitempty"`
	TargetSHA256  string              `json:"target_sha256,omitempty"`
	TargetSubject string              `json:"target_subject,omitempty"`
	StartedBy     string              `json:"started_by,omitempty"`
	StartedAt     string              `json:"started_at,omitempty"`
	Stages        []pkiOperationStage `json:"stages,omitempty"`
	// NextStage is the first stage that is not done — the one thing to do now.
	NextStage string `json:"next_stage,omitempty"`
	Complete  bool   `json:"complete"`
}

// pkiOperationFacts is everything the stages are computed FROM — all of it measured, none of it remembered.
type pkiOperationFacts struct {
	// Distributed is the set currently in the trust distribution.
	Distributed []*x509.Certificate
	// TargetCovered / TargetBlockedReason come from the same readiness the withdrawal gate uses.
	TargetCovered      bool
	TargetCoverageNote string
	// PresentedChain is what the Edge serves on the transport listener right now.
	PresentedChain []*x509.Certificate
	// ServedAdoption is how far the fleet has re-handshaked onto the presented certificate.
	ServedAdoption *serverCertAdoptionReport
}

func buildPKIOperationView(intent *pkiOperationIntent, f pkiOperationFacts) pkiOperationView {
	out := pkiOperationView{SchemaVersion: pkiOperationSchemaVersion}
	if intent == nil {
		return out
	}
	out.InFlight = true
	out.Kind = intent.Kind
	out.TargetSHA256 = intent.TargetSHA256
	out.TargetSubject = intent.TargetSubject
	out.StartedBy = intent.StartedBy
	out.StartedAt = intent.StartedAt

	var target *x509.Certificate
	others := 0
	for _, c := range f.Distributed {
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == intent.TargetSHA256 {
			target = c
			continue
		}
		others++
	}

	// 1. Distributed — the safe direction, and the only stage the operator performs blind.
	distributed := pkiOperationStage{Key: "distribute", Done: target != nil}
	if target == nil {
		distributed.Blocked = "this certificate is not being distributed yet"
	} else {
		distributed.Detail = "distributed alongside " + fmt.Sprint(others) + " other certificate(s)"
	}
	out.Stages = append(out.Stages, distributed)

	// 2. Trusted by every device — measured from device reports plus operator assertions.
	trusted := pkiOperationStage{Key: "adopt", Done: target != nil && f.TargetCovered}
	if !trusted.Done {
		trusted.Blocked = f.TargetCoverageNote
	}
	out.Stages = append(out.Stages, trusted)

	// 3. The Edge presents a certificate this one verifies — and every device has re-handshaked onto it.
	// Two conditions, because a switch nobody has connected through is not a switch that has happened.
	switched := pkiOperationStage{Key: "switch"}
	if target != nil && len(f.PresentedChain) > 0 && verifiesCurrentChain(target, f.PresentedChain) {
		// Not "nobody is on the previous one" — EVERY enrolled device must have been seen on this one.
		// A device with no sighting at all lands in NotSeen, not OnPrevious, and sightings are held in
		// memory: an Edge restart empties them, so reading only OnPrevious flips this stage from blocked
		// to DONE precisely when the least is known. That is the applied-is-not-adopted failure this
		// wizard exists to prevent, reproduced inside it (review R1).
		var pending []string
		if f.ServedAdoption != nil {
			pending = append(append([]string{}, f.ServedAdoption.OnPrevious...), f.ServedAdoption.NotSeen...)
			sort.Strings(pending)
		}
		switch {
		case f.ServedAdoption == nil:
			switched.Blocked = "adoption cannot be measured on this node, so a switch cannot be confirmed"
		case len(pending) > 0:
			switched.Blocked = "not yet seen on it: " + strings.Join(pending, ", ")
			switched.Detail = "the Edge is presenting it; these devices have not handshaked since"
		case len(f.ServedAdoption.OnCurrent) == 0:
			// No device has been observed at all — an empty list is not a fleet that re-handshaked.
			switched.Blocked = "no device has handshaked onto it yet"
		default:
			switched.Done = true
			switched.Detail = "presented, and re-handshaked by " + strings.Join(f.ServedAdoption.OnCurrent, ", ")
		}
	} else if !trusted.Done {
		switched.Blocked = "switch only after every device trusts it"
	} else {
		switched.Blocked = "the Edge is not presenting a certificate this one verifies"
	}
	out.Stages = append(out.Stages, switched)

	// 4. The others are gone. Retiring earlier is what strands a device.
	retired := pkiOperationStage{Key: "retire", Done: target != nil && others == 0}
	if !retired.Done {
		if !switched.Done {
			retired.Blocked = "withdraw the others only after the switch is complete"
		} else {
			retired.Blocked = fmt.Sprint(others) + " other certificate(s) still distributed"
		}
	}
	out.Stages = append(out.Stages, retired)

	for _, st := range out.Stages {
		if !st.Done {
			out.NextStage = st.Key
			break
		}
	}
	out.Complete = out.NextStage == ""
	return out
}

func registerAdminPKIOperations(mux *http.ServeMux, store *pkiOperationStore, view func() pkiOperationView,
	distributed func() []*x509.Certificate,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	record func(r *http.Request, action, targetID, reason string, metadata map[string]any)) {

	mux.HandleFunc("GET /admin/pki/operations", adminEndpoint("admin.certs.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, view())
	}))

	mux.HandleFunc("POST /admin/pki/operations", adminEndpoint("admin.certs.write", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeError(w, http.StatusConflict, fmt.Errorf("staged operations are not enabled on this node (-pki-operation-store)"))
			return
		}
		var req struct {
			Kind         string `json:"kind"`
			TargetSHA256 string `json:"target_sha256"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode operation: %w", err))
			return
		}
		kind := strings.TrimSpace(req.Kind)
		if kind == "" {
			kind = "transport_trust_rotation"
		}
		target := strings.ToLower(strings.TrimSpace(req.TargetSHA256))
		if target == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("target_sha256 is required — the certificate this rotation is moving TO"))
			return
		}
		// The target must be a certificate that is actually distributed. Starting a rotation towards the
		// OUTGOING one computed every stage against the wrong certificate and told the operator to withdraw
		// the new one — instructions that undo the rotation they were following (review R10④).
		subject := ""
		for _, c := range distributed() {
			sum := sha256.Sum256(c.Raw)
			if hex.EncodeToString(sum[:]) == target {
				subject = c.Subject.CommonName
			}
		}
		if subject == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("no distributed certificate has that fingerprint — add the certificate this rotation is moving to before starting it"))
			return
		}
		by := ""
		if identity, ok := adminIdentityFromRequest(r); ok {
			by = strings.TrimSpace(identity.PrincipalLabel)
			if by == "" {
				by = identity.PrincipalID
			}
		}
		intent := pkiOperationIntent{
			Kind: kind, TargetSHA256: target, TargetSubject: subject, StartedBy: by,
			StartedAt: time.Now().UTC().Format(time.RFC3339), SchemaVersion: pkiOperationSchemaVersion,
		}
		if err := store.Start(intent); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		logInfof("pki_operation_started kind=%q target=%s by=%q", kind, target, by)
		if record != nil {
			record(r, "pki_operation_started", target, "a staged PKI operation was started",
				map[string]any{"kind": kind, "target_subject": subject})
		}
		writeJSON(w, http.StatusOK, view())
	}))

	mux.HandleFunc("DELETE /admin/pki/operations", adminEndpoint("admin.certs.write", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeError(w, http.StatusConflict, fmt.Errorf("staged operations are not enabled on this node"))
			return
		}
		if err := store.Clear(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Abandoning tracks nothing further; it does NOT undo what the stages already did — the deployment is
		// wherever the completed stages left it, which is why the view is computed rather than remembered.
		logInfof("pki_operation_abandoned")
		if record != nil {
			record(r, "pki_operation_abandoned", "", "a staged PKI operation was abandoned (completed stages are not undone)", nil)
		}
		writeJSON(w, http.StatusOK, view())
	}))
}
