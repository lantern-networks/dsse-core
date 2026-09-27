package main

import (
	"crypto/x509"
	"encoding/pem"
	"sort"
	"strings"
	"sync"
	"time"

	agentpolicy "github.com/lantern-networks/dsse-core/agentpolicy"
)

// Observed (reverse-telemetry) steer exclusions — the G2 "effective set is visible" half of
// docs/steer_exclusions_purpose_and_gaps_analysis.md.
//
// The Edge knows the admin-RESOLVED set it serves a device (steerexclusion.ResolveForDevice = layer 3 only).
// It does NOT know the device's local loop-prevention floor (layer 1) or its dev scaffold (layer 2, e.g. the
// hardcoded self-exclusion), because those live on the endpoint and are merged there. So an admin who
// only ever sees the authored policy cannot tell what a device ACTUALLY excludes — the "invisible effective
// configuration" gap, and exactly why a hardcoded local exclusion never shows up in the console.
//
// This store closes that gap with OBSERVABILITY (not authority): the endpoint agent reports its merged
// effective set back over the (T) mTLS transport, keyed to the identity the client cert PROVES, and the Edge
// caches the latest report per device for the admin console to read. It is best-effort and in-memory: a
// restart simply re-populates from the next round of agent reports. It never feeds enforcement — it only
// makes the truth representable.
type observedExclusionStore struct {
	mu       sync.Mutex
	byKey    map[string]observedExclusionEntry // tenantID\x00deviceIdentity -> latest report
	capacity int                               // max devices retained; <=0 = unbounded
}

// observedExclusionEntry is one device's latest self-reported effective exclusion set, enriched with a
// record-time classification of each effective AppID (so Query/ByApp/anomalous are simple field reads — and
// the same shape works for a durable Postgres backend). Classification is computed once when the device
// reports, against the admin-resolved set + the known-floor allowlist (see classifyEffectiveExclusions).
// observedTrustRefusal is one (certificate, reason) pair a device declined, folded across its retries.
type observedTrustRefusal struct {
	ServedSHA256 string    `json:"served_sha256,omitempty"`
	Reason       string    `json:"reason"`
	FirstAt      time.Time `json:"first_at"`
	LastAt       time.Time `json:"last_at"`
	Count        int       `json:"count"`
	// Destination is which flow the refusal was seen on. Empty for a transport refusal, which is about the
	// Edge itself and has nowhere else to point; carried for an INTERCEPTION refusal, where the whole
	// question is "which site is broken on this machine".
	Destination string `json:"destination,omitempty"`
}

type observedExclusionEntry struct {
	TenantID                string   `json:"tenant_id"`
	DeviceIdentity          string   `json:"device_identity"`
	DeviceGroup             string   `json:"device_group"`
	Platform                string   `json:"platform"`                    // "macos" | "windows" | "" (reporter-declared, advisory)
	EffectiveAppSigningIDs  []string `json:"effective_app_signing_ids"`   // the full merged set the device applies (floor+scaffold+admin)
	ServerAppSigningIDCount int      `json:"server_app_signing_id_count"` // how many of those came from the admin (server) set, if the reporter knows
	// Record-time classification (subsets of EffectiveAppSigningIDs). "floor" is derivable = effective − admin −
	// unmanaged, so it is not stored separately. Unmanaged = neither admin-authored nor a known floor → flagged.
	AdminAppSigningIDs     []string `json:"admin_app_signing_ids"`
	UnmanagedAppSigningIDs []string `json:"unmanaged_app_signing_ids"`
	// IgnoredAppSigningIDs is what the device received and deliberately did not apply — a form its OS cannot
	// use, or a bare value it could not read as an identifier. Reporter-declared and optional; an agent that
	// does not send it leaves this nil, which means "did not say" and NOT "ignored nothing". It exists so the
	// console can state the DEVICE's reason rather than infer one from the AppID's shape, an inference that
	// drifts the moment an agent's parser changes.
	IgnoredAppSigningIDs []string  `json:"ignored_app_signing_ids,omitempty"`
	ReportedAt           time.Time `json:"reported_at"`
	// Device steering state (Phase 1, reporter-declared, advisory), reported in the same POST as the effective
	// exclusions so the console device page can show a device's live posture without a separate channel.
	Posture                  string `json:"posture,omitempty"`                     // steering|disarmed|captive_onboarding|dark|stopped
	FailOpenConfigured       bool   `json:"fail_open_configured,omitempty"`        // fail-open permitted (vs fail-CLOSED)
	RegionFailoverEnabled    bool   `json:"region_failover_enabled,omitempty"`     // region-failover active on the device
	ActiveRegion             string `json:"active_region,omitempty"`               // region endpoint currently in use
	ServerInitiatedRuleCount int    `json:"server_initiated_rule_count,omitempty"` // applied server-initiated (inbound) rules
	// SHA-256 fingerprints of the transport CAs this device currently PINS.
	//
	// Rotating the transport CA needs an overlap — publish the next CA, wait until every device holds it, then
	// start signing with it. The mechanism for holding two exists; what was missing is the fact an operator
	// needs before cutting over: WHICH devices already have the new one. Without it the choice is to switch and
	// hope, and a device that has not picked it up cannot come back on its own, because fetching the new CA
	// happens over the tunnel it can no longer establish.
	//
	// Fingerprints, not certificates: a hash identifies the CA without putting certificate bodies into
	// telemetry, and it is what an operator compares against the CA they are about to deploy.
	PinnedTransportCASHA256 []string `json:"pinned_transport_ca_sha256,omitempty"`
	// AdoptedTrustSerial is the distribution the reported anchors came from. 0 = the device did not say,
	// which is the state every agent is in until it ships a build that does.
	AdoptedTrustSerial int64 `json:"adopted_trust_serial,omitempty"`
	// RenewalRecoverySNISent is the recovery name this device holds from the trust bundle and would send when
	// its own certificate has expired. Empty means IT DID NOT SAY — never "it holds none".
	//
	// ★★★ THE FIELD EXISTED ON ONE PLATFORM AND NOBODY READ IT (2026-08-19). Windows shipped it in 0.2.10;
	// this Edge did not parse it and macOS did not send it, so the question the fold's last step turns on — has every
	// device been told where to recover, before the port it recovers on is closed — had no answer at all. A
	// reported field with no reader is the same silence as no field, and closing the port on that silence
	// strands exactly the machines that were switched off when the announcement went out.
	RenewalRecoverySNISent string `json:"renewal_recovery_sni_sent,omitempty"`
	// TransportServerNameSent is the SNI this device actually presents on its transport connection.
	//
	// ★★★ THIS IS THE EVIDENCE THE the enrolment fold FOLD TURNS ON, AND IT HAD NO READER (2026-08-22, found by the gate
	// beside this one on the day it was written). The folded enrolment and recovery paths are selected BY the
	// name a device sends; whether a device is sending the ORGANIZATION's name or the deployment's address is
	// therefore the whole question, and it is the one thing no measurement here could answer. The agent has
	// been reporting it; this side discarded it at the door.
	//
	// Reporter-declared and advisory, exactly like the recovery name beside it: it says what the device sent,
	// never whether that was acceptable.
	TransportServerNameSent string `json:"transport_server_name_sent,omitempty"`
	// RenewalRecoveryTarget is the address:port this device would actually DIAL to recover, as it resolves it
	// — not the name it happens to hold.
	//
	// ★★★ HOLDING A NAME IS NOT BEING ABLE TO REACH IT (2026-08-20, reported from win-dev-1). The dedicated
	// recovery port was closed on the evidence that every agent REPORTED the name. One of those agents
	// reported it and would still have dialled the closed port, because sending a name and resolving a
	// destination were two different pieces of code on that platform. The gate read the first and concluded
	// the second.
	//
	// Empty means the device did not say, which is not "it would reach us".
	RenewalRecoveryTarget string `json:"renewal_recovery_target,omitempty"`
	// PinnedInterceptionRootSHA256 are the interception roots this device found in its own trust store.
	// Empty means it did not say — which is not the same as "trusts none", and the gate must read it that way.
	PinnedInterceptionRootSHA256 []string `json:"pinned_interception_root_sha256,omitempty"`
	// InterceptionRootPinSHA256 is the ONE root this device was INSTALLED pinned to, as distinct from the ones
	// above that it happens to hold.
	//
	// ★ THE DIFFERENCE DECIDES A WITHDRAWAL (2026-08-16). Ending a replacement overlap — the Edge stopping the
	// announcement of the authority devices are moving off — is safe only when no device is still pinned to
	// it. "Every device holds the new root" does not establish that: an agent pinned to the old one and armed
	// stands aside the moment the Edge stops naming it, whatever else is in its trust store. Gating on the
	// holding fact would be a safeguard that reports success and takes the fleet offline.
	//
	// Empty means the agent HAS NOT SAID, which is unknown and never "not pinned" — the gate keeps those apart.
	InterceptionRootPinSHA256 string `json:"interception_root_pin_sha256,omitempty"`
	// TrustRefusals is what this device DECLINED to trust, carried late because a refusal cannot travel over
	// the connection it caused to fail. This is the signal that separates "the fleet refused a certificate"
	// from "the fleet is switched off" — the two were indistinguishable during the 2026-07-31 outage, and
	// that is why it took 47 minutes. Reporter-declared, therefore sanitised and never fed to enforcement.
	TrustRefusals []observedTrustRefusal `json:"trust_refusals,omitempty"`
	// InterceptionRefusals is what this device's own probe found wrong with the certificates INTERCEPTION is
	// serving it — a different question from TrustRefusals above, which is about the Edge's own certificate.
	//
	// ★★★ THE THIRD TIME A REPORTED FIELD ARRIVED WITH NO READER (2026-08-22). win-dev-1 shipped 0.2.21
	// EV-signed and measured, with an agent that opens one flow every fifteen minutes, completes the
	// handshake so the chain can be READ, and verifies it twice — once with Go against a pool built from that
	// machine's own root stores, once with the platform verifier — because on 2026-08-21 the same chain was
	// accepted by Chrome and refused by openssl, git and Node over pathLenConstraint:0. It posts them as
	// "interception_refusals". This struct did not name that, so every one of them would have been discarded
	// at the door, exactly like renewal_recovery_target on 2026-08-20 and the reported field before it.
	//
	// The verifier's own sentences travel verbatim, including the second verifier's disagreement, which is why
	// the reason cap here is larger than the transport one: rounding that off would perform the very
	// classification this journal exists to prevent.
	InterceptionRefusals []observedTrustRefusal `json:"interception_refusals,omitempty"`
	// FallbackClientCertPEM is the client certificate this device would present if its renewed identity
	// stopped working — the bootstrap credential its automated-renewal store falls back to. The retire gate
	// only sees the certificate a device is PRESENTING, and on 2026-08-02 that blind spot cost an outage: a
	// CA was retired while the fleet presented renewed certificates, a device then fell back to its
	// bootstrap, and the bootstrap chained to the CA that had just been retired.
	//
	// A certificate body, where every other trust field here is a fingerprint, because the question the gate
	// must answer is "which anchor ISSUES this" — and that is a signature check against each anchor, not a
	// fingerprint comparison against material the device may not even hold (a bootstrap p12 often carries
	// only the leaf). It is public material the device already presents on every fallback handshake.
	// Reporter-declared and parse-validated; used ONLY to make CA retirement harder, never to admit anything.
	FallbackClientCertPEM string `json:"fallback_client_cert_pem,omitempty"`
	// AgentPolicyPublicKeys is the set of policy-signing keys this device would accept — its provisioned pin
	// PLUS any key it adopted from a trust bundle. It answers, from the Edge, the one question the
	// config-signing key rotation turns on: has this device adopted the next key yet? Signing must not switch
	// to a key a device does not hold, or that device freezes on its last policy. Reporter-declared, so it is
	// evidence of readiness, never authority — nothing signs because a device claims to accept a key.
	AgentPolicyPublicKeys []string `json:"agent_policy_public_keys,omitempty"`
}

// acceptsAgentPolicyKey reports whether this device said it would verify policy signed by the given key
// (hex, case-insensitive). The switch-readiness question, per device.
func (e observedExclusionEntry) acceptsAgentPolicyKey(keyHex string) bool {
	want := strings.ToLower(strings.TrimSpace(keyHex))
	if want == "" {
		return false
	}
	for _, k := range e.AgentPolicyPublicKeys {
		if strings.ToLower(strings.TrimSpace(k)) == want {
			return true
		}
	}
	return false
}

// pinsTransportCA reports whether this device already trusts the given CA fingerprint (case-insensitive hex).
func (e observedExclusionEntry) pinsTransportCA(sha256Hex string) bool {
	want := strings.ToLower(strings.TrimSpace(sha256Hex))
	if want == "" {
		return false
	}
	for _, got := range e.PinnedTransportCASHA256 {
		if strings.ToLower(strings.TrimSpace(got)) == want {
			return true
		}
	}
	return false
}

// anomalous reports whether the device applies any exclusion that is neither admin-authored nor a known floor.
func (e observedExclusionEntry) anomalous() bool { return len(e.UnmanagedAppSigningIDs) > 0 }

// appClass labels one effective AppID for the aggregate/by-app view.
const (
	appClassAdmin     = "admin"
	appClassFloor     = "floor"
	appClassUnmanaged = "unmanaged"
)

// classifyEffectiveExclusions splits a device's effective set into admin (∈ the admin-resolved set), floor
// (matches the known-floor allowlist), and unmanaged (everything else — the flagged signal). adminResolved is
// the set the Edge authored for this device (ResolveForDevice); knownFloor is the configured floor allowlist
// (exact strings or `prefix*`). Matching is case-insensitive. Returns (admin, unmanaged); floor is the rest.
func classifyEffectiveExclusions(effective []string, adminResolved map[string]struct{}, knownFloor []string) (admin, unmanaged []string) {
	admin = make([]string, 0)
	unmanaged = make([]string, 0)
	for _, id := range effective {
		t := strings.TrimSpace(id)
		if t == "" {
			continue
		}
		if _, ok := adminResolved[strings.ToLower(t)]; ok {
			admin = append(admin, t)
			continue
		}
		if matchesKnownFloor(t, knownFloor) {
			continue // floor — expected, not flagged
		}
		unmanaged = append(unmanaged, t)
	}
	return admin, unmanaged
}

// matchesKnownFloor reports whether id matches any known-floor pattern (case-insensitive; a trailing `*` is a
// prefix match, otherwise exact).
func matchesKnownFloor(id string, patterns []string) bool {
	lid := strings.ToLower(strings.TrimSpace(id))
	for _, p := range patterns {
		lp := strings.ToLower(strings.TrimSpace(p))
		if lp == "" {
			continue
		}
		if strings.HasSuffix(lp, "*") {
			if strings.HasPrefix(lid, strings.TrimSuffix(lp, "*")) {
				return true
			}
		} else if lid == lp {
			return true
		}
	}
	return false
}

// adminResolvedSet builds the lowercased membership set used by classifyEffectiveExclusions.
func adminResolvedSet(resolved []string) map[string]struct{} {
	s := make(map[string]struct{}, len(resolved))
	for _, r := range resolved {
		t := strings.TrimSpace(r)
		if t != "" {
			s[strings.ToLower(t)] = struct{}{}
		}
	}
	return s
}

func newObservedExclusionStore(capacity int) *observedExclusionStore {
	return &observedExclusionStore{byKey: map[string]observedExclusionEntry{}, capacity: capacity}
}

func observedExclusionKey(tenantID, deviceIdentity string) string {
	return tenantID + "\x00" + deviceIdentity
}

// Record stores (overwriting) a device's latest report. Identity+tenant are caller-supplied from the proven
// mTLS context, never from the request body. When the store is at capacity and this is a new device, the
// oldest-reporting device is evicted so a churn of devices cannot grow memory without bound.
func (s *observedExclusionStore) Record(e observedExclusionEntry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := observedExclusionKey(e.TenantID, e.DeviceIdentity)
	if _, exists := s.byKey[key]; !exists && s.capacity > 0 && len(s.byKey) >= s.capacity {
		s.evictOldestLocked()
	}
	s.byKey[key] = e
}

func (s *observedExclusionStore) evictOldestLocked() {
	oldestKey := ""
	var oldest time.Time
	for k, v := range s.byKey {
		if oldestKey == "" || v.ReportedAt.Before(oldest) {
			oldestKey, oldest = k, v.ReportedAt
		}
	}
	if oldestKey != "" {
		delete(s.byKey, oldestKey)
	}
}

// List returns every device report for one tenant, newest first. Tenant scoping is enforced here so a
// tenant admin can never read another tenant's device reports.
func (s *observedExclusionStore) List(tenantID string) []observedExclusionEntry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]observedExclusionEntry, 0)
	for _, v := range s.byKey {
		if v.TenantID != tenantID {
			continue
		}
		out = append(out, v)
	}
	// Offset pagination needs a stable order when devices report at the same
	// instant. Match the PostgreSQL store's timestamp/identity ordering.
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReportedAt.Equal(out[j].ReportedAt) {
			return out[i].DeviceIdentity < out[j].DeviceIdentity
		}
		return out[i].ReportedAt.After(out[j].ReportedAt)
	})
	return out
}

// observedQueryFilter is the server-side filter for the paginated observed query (scale: never return the
// whole fleet). All fields are optional; empty = no constraint.
type observedQueryFilter struct {
	Device        string // device identity: exact, or prefix match when it ends with `*`
	Group         string // device-group exact
	App           string // only devices whose effective set contains this AppID (case-insensitive)
	AnomalousOnly bool   // only devices with ≥1 unmanaged effective entry
	Limit         int    // page size (caller clamps; <=0 → default applied by caller)
	Offset        int    // forward pagination offset (decoded from the opaque cursor)
}

// observedQueryResult is one page plus the total matching count (for the summary + next cursor).
type observedQueryResult struct {
	Entries []observedExclusionEntry
	Total   int
	Offset  int // the offset this page started at
}

// observedByAppEntry is one AppID's fleet-wide aggregate.
type observedByAppEntry struct {
	AppID       string `json:"app_id"`
	DeviceCount int    `json:"device_count"`
	Class       string `json:"class"` // admin | floor | unmanaged (unmanaged wins if it is ever unmanaged)
}

type observedByAppResult struct {
	Apps        []observedByAppEntry
	DeviceTotal int
}

// observedExclusionStoreAPI is the read/record surface the admin handlers use, so an in-memory cache and a
// durable Postgres backend are interchangeable (Phase 3).
type observedExclusionStoreAPI interface {
	Record(observedExclusionEntry)
	Query(tenantID string, f observedQueryFilter) observedQueryResult
	ByApp(tenantID string, limit int) observedByAppResult
	// Readiness for a transport-CA rotation: which enrolled devices already hold the CA about to be deployed.
	TransportCAReadiness(tenantID, sha256Hex string, knownDevices []string) transportCAReadiness
	// RecoveryNameReadiness answers the fold's last step: may the dedicated recovery port close? Only an affirmative
	// from every enrolled device counts; silence is "not yet".
	RecoveryNameReadiness(tenantID, name string, knownDevices []string) recoveryNameReadiness
	TransportCAReadinessAtSerial(tenantID, sha256Hex string, knownDevices []string, currentSerial int64) transportCAReadiness
}

var _ observedExclusionStoreAPI = (*observedExclusionStore)(nil)

// parseObservedKnownFloor splits the comma-separated known-floor allowlist flag into trimmed, non-empty
// patterns (each exact or `prefix*`).
func parseObservedKnownFloor(raw string) []string {
	out := make([]string, 0)
	for _, p := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func deviceMatches(deviceIdentity, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.HasSuffix(filter, "*") {
		return strings.HasPrefix(strings.ToLower(deviceIdentity), strings.ToLower(strings.TrimSuffix(filter, "*")))
	}
	return strings.EqualFold(deviceIdentity, filter)
}

func effectiveContains(effective []string, app string) bool {
	if app == "" {
		return true
	}
	for _, id := range effective {
		if strings.EqualFold(strings.TrimSpace(id), strings.TrimSpace(app)) {
			return true
		}
	}
	return false
}

// Query returns one filtered, paginated page of device reports (newest first), plus the total matching count.
func (s *observedExclusionStore) Query(tenantID string, f observedQueryFilter) observedQueryResult {
	all := s.List(tenantID) // already newest-first, tenant-scoped
	matched := make([]observedExclusionEntry, 0, len(all))
	for _, e := range all {
		if !deviceMatches(e.DeviceIdentity, f.Device) {
			continue
		}
		if f.Group != "" && !strings.EqualFold(e.DeviceGroup, f.Group) {
			continue
		}
		if !effectiveContains(e.EffectiveAppSigningIDs, f.App) {
			continue
		}
		if f.AnomalousOnly && !e.anomalous() {
			continue
		}
		matched = append(matched, e)
	}
	total := len(matched)
	offset := f.Offset
	if offset < 0 || offset > total {
		offset = total
	}
	end := total
	if f.Limit > 0 && offset+f.Limit < end {
		end = offset + f.Limit
	}
	return observedQueryResult{Entries: matched[offset:end], Total: total, Offset: offset}
}

// ByApp aggregates, across all of a tenant's reporting devices, how many apply each AppID and its class
// (unmanaged wins if the app is unmanaged on any device, else admin if admin anywhere, else floor). Returns
// the top `limit` apps (unmanaged first, then by device count desc).
func (s *observedExclusionStore) ByApp(tenantID string, limit int) observedByAppResult {
	all := s.List(tenantID)
	type agg struct {
		original     string
		devices      map[string]struct{}
		anyAdmin     bool
		anyUnmanaged bool
	}
	byKey := map[string]*agg{}
	for _, e := range all {
		adminSet := map[string]struct{}{}
		for _, a := range e.AdminAppSigningIDs {
			adminSet[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
		}
		unmanagedSet := map[string]struct{}{}
		for _, u := range e.UnmanagedAppSigningIDs {
			unmanagedSet[strings.ToLower(strings.TrimSpace(u))] = struct{}{}
		}
		for _, id := range e.EffectiveAppSigningIDs {
			t := strings.TrimSpace(id)
			if t == "" {
				continue
			}
			k := strings.ToLower(t)
			a, ok := byKey[k]
			if !ok {
				a = &agg{original: t, devices: map[string]struct{}{}}
				byKey[k] = a
			}
			a.devices[e.DeviceIdentity] = struct{}{}
			if _, isAdmin := adminSet[k]; isAdmin {
				a.anyAdmin = true
			}
			if _, isUnmanaged := unmanagedSet[k]; isUnmanaged {
				a.anyUnmanaged = true
			}
		}
	}
	out := make([]observedByAppEntry, 0, len(byKey))
	for _, a := range byKey {
		class := appClassFloor
		if a.anyUnmanaged {
			class = appClassUnmanaged
		} else if a.anyAdmin {
			class = appClassAdmin
		}
		out = append(out, observedByAppEntry{AppID: a.original, DeviceCount: len(a.devices), Class: class})
	}
	// Unmanaged first (most worth attention), then by device count desc, then app id for stability.
	classRank := func(c string) int {
		switch c {
		case appClassUnmanaged:
			return 0
		case appClassAdmin:
			return 1
		default:
			return 2
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if classRank(out[i].Class) != classRank(out[j].Class) {
			return classRank(out[i].Class) < classRank(out[j].Class)
		}
		if out[i].DeviceCount != out[j].DeviceCount {
			return out[i].DeviceCount > out[j].DeviceCount
		}
		return out[i].AppID < out[j].AppID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	// device total = distinct devices for the tenant.
	devices := map[string]struct{}{}
	for _, e := range all {
		devices[e.DeviceIdentity] = struct{}{}
	}
	return observedByAppResult{Apps: out, DeviceTotal: len(devices)}
}

// normalizeReportedIDs trims, drops blanks, and collapses case-insensitive duplicates while preserving
// first-seen order — the same shape the agent applies, so the console shows a clean list.
func normalizeReportedIDs(ids []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		t := strings.TrimSpace(id)
		if t == "" {
			continue
		}
		k := strings.ToLower(t)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, t)
	}
	return out
}

// observedPostureValues is the closed set of device-reported posture strings the store accepts. Anything else
// (empty, unknown, or an injected value) normalizes to "" so a compromised/buggy reporter cannot paint an
// arbitrary label on the console device page. Mirrors agentstatus.Protection.
var observedPostureValues = map[string]struct{}{
	"steering": {}, "disarmed": {}, "captive_onboarding": {}, "dark": {}, "stopped": {}, "error": {},
}

// normalizeReportedPosture clamps a device-reported posture to the known enum (else "").
func normalizeReportedPosture(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if _, ok := observedPostureValues[p]; ok {
		return p
	}
	return ""
}

// boundReportedString trims a device-reported advisory string and caps its length (defense against an
// oversized/abusive value inflating the store or the console payload).
func boundReportedString(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

// normalizeReportedFingerprints sanitizes device-reported CA fingerprints.
//
// Reporter-declared input, so it is clamped rather than trusted: SHA-256 hex only, exact length, deduplicated,
// and bounded in number. A device legitimately pins one or two CAs during a rotation overlap; a report with
// hundreds is either a bug or an attempt to bloat the telemetry store, and neither should be recorded.
func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// normalizeReportedPolicyKeys sanitises a device-reported set of accepted policy-signing keys to exactly the
// shapes the verifier accepts (Ed25519 or ECDSA-P256), deduplicated and bounded. Reporter-declared, so a
// malformed entry is dropped rather than counted — an entry here inflates a device's apparent readiness for
// the signing-key switch, and nothing else must be able to.
func normalizeReportedPolicyKeys(values []string) []string {
	const maxKeys = 8
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		k := strings.ToLower(strings.TrimSpace(raw))
		if seen[k] || !agentpolicy.AcceptedPublicKeyHex(k) {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) >= maxKeys {
			break
		}
	}
	return out
}

func normalizeReportedFingerprints(values []string) []string {
	const maxFingerprints = 8
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		fp := strings.ToLower(strings.TrimSpace(raw))
		fp = strings.ReplaceAll(fp, ":", "") // accept both colon-separated and bare hex
		if len(fp) != 64 || seen[fp] {
			continue
		}
		valid := true
		for _, ch := range fp {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		seen[fp] = true
		out = append(out, fp)
		if len(out) >= maxFingerprints {
			break
		}
	}
	return out
}

// normalizeReportedFallbackCert sanitizes a device-reported fallback client certificate: it must be ONE
// parseable certificate in a bounded PEM, and what is stored is the re-encoding of what PARSED — never the
// reporter's bytes verbatim. Anything else records as empty, which the gate reads as "did not say".
func normalizeReportedFallbackCert(raw string) string {
	const maxPEM = 16 * 1024
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxPEM {
		return ""
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// carryForwardFallbackCert keeps the previously recorded fallback credential when the incoming report does
// not carry one. See the Record call site for why omission must not erase it.
func carryForwardFallbackCert(store observedExclusionStoreAPI, tenantID, identity, incoming string) string {
	if incoming != "" || store == nil {
		return incoming
	}
	prior := store.Query(tenantID, observedQueryFilter{Device: identity, Limit: 1})
	if len(prior.Entries) == 0 {
		return ""
	}
	return prior.Entries[0].FallbackClientCertPEM
}

// transportCAReadiness answers the question an operator has to settle before rotating the transport CA:
// which devices already trust the CA I am about to switch to?
//
// Rotating without that answer means switching and hoping. A device that has not picked up the new CA cannot
// recover on its own — it can no longer verify the Edge, and the new CA would have arrived over the tunnel it
// can no longer establish — so the cost of cutting over too early is a device that needs a human.
type transportCAReadiness struct {
	SHA256 string `json:"sha256"`
	// Ready and NotReady are device identities, not counts alone: "34 of 40" tells an operator to wait, but
	// only the list tells them WHICH six to chase.
	Ready    []string `json:"ready"`
	NotReady []string `json:"not_ready"`
	// Silent devices have never reported. They are counted apart from NotReady on purpose: "has not told us"
	// is a different situation from "has told us it does not have it", and only the second is fixable by
	// waiting. A device that is switched off shows up here, and switching over while it is off is exactly how
	// it comes back dead.
	Silent []string `json:"silent"`
	// NeverReportedAnything is the subset of Silent that has sent NO telemetry at all, as opposed to having
	// reported while omitting which CAs it pins. The two look identical in a count and are not the same
	// problem: the second is an agent that will start reporting, the first is an identity that may have no
	// agent behind it — a connector, say, which is enrolled because it needs an identity but does not run the
	// steering agent and will therefore never report a pinned CA.
	//
	// That distinction decides whether waiting helps. Adoption cannot reach every device while such an
	// identity is enrolled, so an operator watching the percentage would wait for a number that cannot
	// arrive; seeing WHICH kind of silence they are looking at is what turns that into a decision.
	NeverReportedAnything []string `json:"never_reported_anything"`
	ReadyPct              int      `json:"ready_pct"`
	SafeToCut             bool     `json:"safe_to_cut"`
	// NotAdopters are enrolled identities this distribution cannot reach at all — service identities that pin
	// the Edge CA handed to them at enrolment and never read a trust bundle. Named rather than dropped: a
	// denominator that shrinks in silence is a gate that stops measuring.
	NotAdopters []string `json:"not_adopters,omitempty"`
}

// TransportCAReadiness computes readiness for one CA fingerprint over the devices known to the enrolled
// inventory. knownDevices comes from the inventory rather than from telemetry, so a device that has never
// reported still appears — otherwise the fleet would look 100% ready simply because the ones missing the CA
// are the ones not talking.
// transportCAReportShelfLife is how long a device's statement about what it trusts stays evidence. Agents
// report on their policy poll (minutes), so a fortnight is generous — it is long enough that a laptop away
// for a week still counts, and short enough that a machine gone since before the last rotation does not.
const transportCAReportShelfLife = 14 * 24 * time.Hour

// TransportCAReadiness answers "may this certificate be withdrawn". currentSerial is the distribution the
// Edge is serving now; a device that reports an OLDER one is verifying against a set it has since been sent
// a replacement for, so its fingerprints describe something no longer in use. Pass 0 to skip the comparison.
func (s *observedExclusionStore) TransportCAReadinessAtSerial(tenantID, sha256Hex string, knownDevices []string,
	currentSerial int64) transportCAReadiness {
	out := s.transportCAReadiness(tenantID, sha256Hex, knownDevices, currentSerial)
	return out
}

func (s *observedExclusionStore) TransportCAReadiness(tenantID, sha256Hex string, knownDevices []string) transportCAReadiness {
	return s.transportCAReadiness(tenantID, sha256Hex, knownDevices, 0)
}

func (s *observedExclusionStore) transportCAReadiness(tenantID, sha256Hex string, knownDevices []string,
	currentSerial int64) transportCAReadiness {
	want := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(sha256Hex, ":", "")))
	out := transportCAReadiness{SHA256: want, Ready: []string{}, NotReady: []string{}, Silent: []string{}, NeverReportedAnything: []string{}}
	if want == "" {
		return out
	}
	reported := map[string]observedExclusionEntry{}
	for _, e := range s.List(tenantID) {
		reported[strings.ToLower(strings.TrimSpace(e.DeviceIdentity))] = e
	}
	for _, device := range knownDevices {
		id := strings.ToLower(strings.TrimSpace(device))
		if id == "" {
			continue
		}
		entry, ok := reported[id]
		// A report has a shelf life. "Ready" is a claim about what a device holds NOW, and one made six
		// months ago says nothing about a machine that has since been re-imaged — yet it would open the
		// withdrawal gate just as readily as this morning's (review R10①). A stale report is treated as
		// silence, which is the state that makes an operator look rather than proceed.
		if ok && !entry.ReportedAt.IsZero() && time.Since(entry.ReportedAt) > transportCAReportShelfLife {
			out.Silent = append(out.Silent, device)
			continue
		}
		switch {
		case !ok || len(entry.PinnedTransportCASHA256) == 0:
			out.Silent = append(out.Silent, device)
			if !ok {
				out.NeverReportedAnything = append(out.NeverReportedAnything, device)
			}
		case currentSerial > 0 && entry.AdoptedTrustSerial > 0 && entry.AdoptedTrustSerial < currentSerial:
			// It holds the certificate, but from a distribution that has since been superseded. Whatever it is
			// verifying with, it is not what this Edge last handed out — and "ready" must mean the current set.
			out.NotReady = append(out.NotReady, device)
		case entry.pinsTransportCA(want):
			out.Ready = append(out.Ready, device)
		default:
			out.NotReady = append(out.NotReady, device)
		}
	}
	total := len(out.Ready) + len(out.NotReady) + len(out.Silent)
	if total > 0 {
		out.ReadyPct = len(out.Ready) * 100 / total
	}
	// Safe ONLY when every known device has said it holds the CA. Not a threshold: the whole point is that the
	// stragglers are the ones that cannot recover, so "almost all" is the state in which cutting over creates
	// exactly the devices that need a human.
	out.SafeToCut = total > 0 && len(out.Ready) == total
	return out
}

// normalizeReportedTrustRefusals bounds what a device may say about its own refusals. The reason is the
// device's own words and is kept as such — classifying it into a code here would discard the part nobody
// anticipated — but it is length-capped, the list is capped, and a refusal with no reason is dropped rather
// than displayed as an empty row. Nothing here reaches enforcement; it is evidence for a human.
// mergeTrustRefusals keeps refusals across reports. A device clears its journal once the Edge accepts it, so
// the next report carries none — and replacing the stored list with that empty one would destroy the only
// copy of the evidence, moments after finally receiving it. Merged by (certificate, reason), keeping the
// higher count and the later timestamp, newest kept when the cap bites.
func mergeTrustRefusals(existing, incoming []observedTrustRefusal) []observedTrustRefusal {
	const maxRefusals = 32
	out := append([]observedTrustRefusal{}, existing...)
	for _, add := range incoming {
		found := false
		for i := range out {
			if out[i].ServedSHA256 != add.ServedSHA256 || out[i].Reason != add.Reason {
				continue
			}
			found = true
			if add.Count > out[i].Count {
				out[i].Count = add.Count
			}
			if add.LastAt.After(out[i].LastAt) {
				out[i].LastAt = add.LastAt
			}
			if !add.FirstAt.IsZero() && (out[i].FirstAt.IsZero() || add.FirstAt.Before(out[i].FirstAt)) {
				out[i].FirstAt = add.FirstAt
			}
			break
		}
		if !found {
			out = append(out, add)
		}
	}
	if len(out) > maxRefusals {
		sort.Slice(out, func(i, j int) bool { return out[i].LastAt.After(out[j].LastAt) })
		out = out[:maxRefusals]
	}
	return out
}

// normalizeReportedInterceptionRefusals is the same bounding with a LARGER reason cap.
//
// ★ THE SECOND VERIFIER'S OBJECTION IS AT THE END (2026-08-22). win-dev-1's probe verifies each chain twice —
// Go against the machine's own root pool, then the platform verifier — and carries both sentences verbatim,
// because on 2026-08-21 the same chain was accepted by Chrome and refused by openssl, git and Node over
// pathLenConstraint:0, and a single verifier reproduces exactly the confusion this journal exists to end.
// Cutting the reason at the transport cap would truncate the disagreement, which is to say it would perform
// the classification the whole design refuses to perform. Their journal caps at 600; so does this.
func normalizeReportedInterceptionRefusals(in []observedTrustRefusal) []observedTrustRefusal {
	return normalizeRefusalsWithReasonCap(in, 600)
}

func normalizeReportedTrustRefusals(in []observedTrustRefusal) []observedTrustRefusal {
	return normalizeRefusalsWithReasonCap(in, 300)
}

func normalizeRefusalsWithReasonCap(in []observedTrustRefusal, maxReason int) []observedTrustRefusal {
	const maxRefusals = 32
	out := make([]observedTrustRefusal, 0, len(in))
	for _, r := range in {
		reason := strings.TrimSpace(r.Reason)
		if reason == "" {
			continue
		}
		if len(reason) > maxReason {
			reason = reason[:maxReason]
		}
		count := r.Count
		if count < 1 {
			count = 1
		}
		out = append(out, observedTrustRefusal{
			// A device cannot be trusted to say WHICH certificate is correct — only which one it saw — so this
			// is hex-normalised exactly like the anchor fingerprints beside it and compared, never believed.
			ServedSHA256: firstOrEmpty(normalizeReportedFingerprints([]string{r.ServedSHA256})),
			Reason:       reason,
			FirstAt:      r.FirstAt.UTC(),
			LastAt:       r.LastAt.UTC(),
			Count:        count,
			// Length-capped like the reason, and kept as the device's own words: it is a destination, not an
			// identifier this side resolves.
			Destination: boundReportedString(r.Destination, 253),
		})
		if len(out) == maxRefusals {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *observedExclusionStore) RecoveryNameReadiness(tenantID, name string,
	knownDevices []string) recoveryNameReadiness {
	return measureRecoveryNameReadiness(s.List(tenantID), name, knownDevices, time.Now())
}
