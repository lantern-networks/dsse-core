package main

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/policy"
	policyrule "github.com/lantern-networks/dsse-core/policyrule"
	tenantca "github.com/lantern-networks/dsse-core/tenantca"
	"github.com/lantern-networks/dsse-core/vlan"

	"github.com/lantern-networks/dsse-core/model"
)

// CP→Edge config distribution (Phase 1 — docs/edge_config_distribution_phase1_design.md). The control plane
// is the source of truth for runtime admin config; each Edge PULLS a versioned config bundle and applies it
// to its in-memory stores so a fleet enforces identically. Generalizes steer_exclusion_sync. Fail-safe: a
// fetch/decode error keeps the last good config. Required section errors leave a generation unapplied
// for retry; sections already changed are not rolled back.
// Slice 1 carries access policies; further resources (east-west, dns, …) fold into the bundle.

type configBundleSource struct {
	url string // control-plane admin base, e.g. https://controlplane:9443 (single-CP fallback)
	// endpoints, when set (multi-region CP), provides the CURRENT healthy CP base URL (region failover); "" means
	// no in-boundary CP is reachable → keep the last config. See cp_endpoint_failover.go.
	endpoints *cpEndpointSelector
	token     string // bearer (the shared -admin-token); the CP scopes the bundle to this token's tenant
	tenantID  string // the Edge's enforcement tenant (must equal the CP's tenant)
	interval  time.Duration
	client    *http.Client
	status    *configBundleSyncStatus // observability for the fleet-health / staleness signal (may be nil)
	// verifyPubKeyHex, when set, is the public key (hex) the Edge PINS to verify the control plane's SIGNED
	// config bundle (agentpolicy.Envelope). requireSigned rejects an UNSIGNED bundle (fail-closed) when a key is
	// pinned — a compromised CP or bearer-token holder must not be able to push arbitrary policy. Empty key =
	// accept unsigned (lab / no signer). Wired from the shared agent-policy signing key.
	verifyPubKeyHex string
	// verifyKeys, when non-empty, is the SET of accepted signing keys — verified with VerifyAny so the CP may
	// sign with the current key OR a published next key during a rotation overlap. The single verifyPubKeyHex
	// was how the CP→Edge sync silently died at the 2c Ed25519→ECDSA switch: the edge pinned exactly one key and
	// the CP moved to another, so verification failed every poll (same trap the agenttuning path hit). Verifying
	// against the accepted set — the current signer plus the published next keys — makes the sync survive a
	// rotation. Takes precedence over verifyPubKeyHex when set; the single key remains for tests / lab.
	verifyKeys    []string
	requireSigned bool
	// reporter tells the control plane which generation this Edge holds. Best-effort and deliberately outside
	// every decision path: a visibility feature must never be able to interfere with the sync it reports on.
	reporter *fleetConfigReporter
}

// acceptedVerifyKeys is the set of signing keys the CP's config bundle may be signed with: the explicit set
// (current signer + published next keys) when provided, else the single pinned key. The gate at the call site
// guarantees at least one is set, so this never returns empty there.
func (s *configBundleSource) acceptedVerifyKeys() []string {
	if len(s.verifyKeys) > 0 {
		return s.verifyKeys
	}
	if k := strings.TrimSpace(s.verifyPubKeyHex); k != "" {
		return []string{k}
	}
	return nil
}

// configBundleSyncStatus is the observable state of an Edge's config-bundle puller: the LAST CP generation it
// successfully applied (NOT the Edge's own local store counter, which diverges), plus the last error. The
// fleet-health / staleness signal (design) compares LastAppliedGeneration to the control plane's current
// generation; an Edge lagging beyond a threshold is drained by the LB. Safe for concurrent read by the admin
// endpoint / healthz while the puller goroutine writes.
type configBundleSyncStatus struct {
	mu                    sync.RWMutex
	source                string
	interval              time.Duration
	lastAppliedGeneration uint64
	// lastAppliedEpoch is the control plane INCARNATION the applied generation belongs to. Two generations are
	// only comparable within one epoch: the control plane's number is the sum of its stores' in-memory
	// generations, so a restart recomputes it from durable content and it comes back LOWER than what it last
	// published. Without the epoch beside it, a reader comparing the numbers alone declares the Edge ahead of
	// the control plane and calls distribution broken — which is exactly what the lab's posture check did for
	// one poll cycle after every control-plane restart.
	lastAppliedEpoch string
	lastAppliedCount int
	haveApplied      bool
	lastAppliedAt    time.Time
	lastError        string
	lastErrorAt      time.Time
	lastPollAt       time.Time
}

func (s *configBundleSyncStatus) recordApplied(generation uint64, epoch string, count int, at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAppliedGeneration = generation
	s.lastAppliedEpoch = epoch
	s.lastAppliedCount = count
	s.haveApplied = true
	s.lastAppliedAt = at
	s.lastPollAt = at
	s.lastError = ""
}

// recordPoll marks a successful poll that produced no apply (already at/ahead of the CP generation).
func (s *configBundleSyncStatus) recordPoll(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPollAt = at
	s.lastError = ""
}

func (s *configBundleSyncStatus) recordError(err error, at time.Time) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = err.Error()
	s.lastErrorAt = at
	s.lastPollAt = at
}

// snapshot returns the status as a JSON-serializable map for the admin/healthz surface.
func (s *configBundleSyncStatus) snapshot() map[string]any {
	out := map[string]any{"enabled": true}
	if s == nil {
		return map[string]any{"enabled": false}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out["source"] = s.source
	out["poll_interval"] = s.interval.String()
	out["have_applied"] = s.haveApplied
	out["last_applied_generation"] = s.lastAppliedGeneration
	out["last_applied_epoch"] = s.lastAppliedEpoch
	out["last_applied_count"] = s.lastAppliedCount
	if !s.lastAppliedAt.IsZero() {
		out["last_applied_at"] = s.lastAppliedAt.UTC().Format(time.RFC3339)
	}
	if !s.lastPollAt.IsZero() {
		out["last_poll_at"] = s.lastPollAt.UTC().Format(time.RFC3339)
	}
	if s.lastError != "" {
		out["last_error"] = s.lastError
		out["last_error_at"] = s.lastErrorAt.UTC().Format(time.RFC3339)
	}
	return out
}

// configBundlePayload is the wire shape served by GET /admin/config-bundle. generation is the control
// plane's monotonic config version; an Edge applies a bundle only when it is newer than the last applied.
type configBundlePayload struct {
	Applications *applicationCatalogBundle `json:"applications,omitempty"`
	DLP          *dlpConfigBundle          `json:"dlp,omitempty"`
	Generation   uint64                    `json:"generation"`
	// signatureVerified records that THIS payload arrived inside a signature the Edge checked against a pinned
	// key. It is unexported on purpose: encoding/json cannot set an unexported field, so no bundle on the wire
	// can claim it, and a payload built in a test or by hand defaults to false.
	//
	// ★ WHY IT EXISTS (2026-08-15). Bundles may be unsigned — an Edge with no pinned key accepts them, which
	// is right for a lab and for bootstrapping. Config that is wrong can be re-pushed; an ERASURE cannot be
	// undone. So the carried tenant purge is the one instruction that refuses to act on an unsigned bundle,
	// and it needs a fact from the TRANSPORT to know, not a claim from the payload.
	signatureVerified bool
	// Epoch is a per-PROCESS id the control plane generates once at startup. The aggregate generation is the
	// SUM of in-memory per-store counters, which RESET to 0 when the control plane restarts — so a still-
	// running puller with a higher last-applied generation would otherwise see gen <= lastApplied and stop
	// applying (the fleet freezes its config until the CP climbs back). The puller re-baselines whenever the
	// epoch changes (the CP restarted), regardless of generation, closing that gap. Within one CP lifetime the
	// epoch is constant and the generation comparison holds.
	Epoch string `json:"epoch,omitempty"`
	// TenantPolicies carries EVERY tenant's enforcement config, which the single Policies field below cannot:
	// it only ever held the pulling Edge's own tenant. Absent (nil) on an older control plane, in which case
	// the receiving side falls back to that single-tenant field exactly as before.
	TenantPolicies []tenantPolicySection `json:"tenant_policies,omitempty"`
	Policies       []model.Policy        `json:"policies"`
	// TenantConfig carries the tenant's admin-config TOGGLES that live in the admin policy store alongside
	// policies (east-west per-hop authz, server-initiated + legacy exceptions, SWG tenant-restriction
	// rule status). Pointer so an older CP that omits it leaves the Edge's local config untouched (fail-safe)
	// rather than clearing it. Risk activation/scopes are intentionally NOT here — they can be
	// node-locally auto-activated by lateral-movement detection, which the bundle must not clobber (kept
	// node-local until the Phase 3 revocation path; ).
	TenantConfig *policy.TenantConfigBundle `json:"tenant_config,omitempty"`
	// DNSPolicy is the DNS-layer ruleset (deny / sinkhole / stub / ech_strip). It lives in a SEPARATE
	// store (the dnsresolver.Resolver, not policy.Store), so the bundle's Generation is the SUM of the policy-store
	// and DNS generations (both monotonic). Pointer: a CP that omits it leaves the Edge's DNS policy untouched.
	DNSPolicy *dnsresolver.PolicyDTO `json:"dns_policy,omitempty"`
	// Enrolled is the Enrolled Inventory (the admission allowlist — identity + enabled/disabled). A
	// separate store (enrolledinventory.Ledger); its generation folds into the aggregate. Pointer so a CP that
	// omits it leaves the Edge's ledger untouched (fail-safe). When present with entries it REPLACES the set
	// (admission consistent fleet-wide); when present-but-EMPTY it does NOT wipe a non-empty local ledger —
	// apply keeps local (lockout-safe), because an empty section usually means the CP is not the enrolled
	// authority, not "deauthorize everyone". Disable rides at config latency via enabled=false (stays in the
	// list); the emergency kill-switch overlay stays a Phase-3 revocation concern, not distributed here.
	Enrolled *enrolledInventoryBundle `json:"enrolled,omitempty"`
	// Tenants is the tenant model — display name, timezone, region, residency. The CONTROL PLANE is authoritative
	// and the Edge receives it here, because the same tenant existing independently on both planes has already
	// cost two silent failures in one afternoon: a timezone that was stored on the Edge and never reached the
	// session (which the front door routes to the CP), and the same tenant showing three different names across
	// three surfaces. Fixing values by hand does not stop the next one diverging; one authority does.
	//
	// Pointer so a CP that omits it leaves the Edge's models untouched, and present-but-EMPTY does NOT wipe a
	// non-empty local set — same rule as every other section here, for the same reason: an empty section almost
	// always means "this CP is not the authority for that", not "delete everything".
	Tenants *tenantModelBundle `json:"tenants,omitempty"`
	// VLAN is the VLAN/Subnet objects + inter-VLAN boundary policies (a separate store). Pointer so a
	// CP that omits it leaves the Edge's set untouched. When present with content it REPLACES the whole set;
	// present-but-EMPTY does NOT wipe a non-empty local set (apply keeps local — lockout-safe).
	VLAN *vlanBoundaryBundle `json:"vlan,omitempty"`
	// Connectors is the class-1 connector/region catalog (multi-region): every Edge needs a shared view of
	// which connector lives in which region (edge_region_id) + its reachable_routes, so a steered flow can be
	// hairpinned/meshed to the connector's home region. The runtime secret hash is STRIPPED before serving (the
	// served entries are publicConnectorRegistrations). apply UPSERTS each entry, preserving any LOCAL runtime
	// state (a locally-connected connector keeps its tunnel/secret); a present-but-EMPTY catalog does NOT wipe a
	// non-empty local registry (lockout-safe). Pointer so a CP that omits it leaves the Edge's registry untouched.
	Connectors *connectorCatalogBundle `json:"connectors,omitempty"`
	// RouteGovernance carries the connector route-governance DECISIONS (configured bindings + hold/adopt state).
	// The CP-configured model distributes the bindings as config, so a pull-model Edge converges WITHOUT a shared
	// governance store (retiring the shared-file HA workaround). apply REPLACES the local decisions when present
	// with content; a present-but-EMPTY / omitted section does NOT wipe local decisions (lockout-safe). Pointer so
	// a CP that omits it leaves the Edge's decisions untouched. See docs/connector_network_route_advertisement_design.md.
	RouteGovernance *governancePersistState `json:"route_governance,omitempty"`
	// NHI is the Non-Human Identity registry (AI-agent / automation identities + their allowlists). A
	// separate store (nhi.RuntimeStore); its generation folds into the aggregate. Pointer so a CP that omits it
	// leaves the Edge's registry untouched (fail-safe). apply UPSERTS each identity (additive; a locally-known
	// NHI absent from the bundle is not deleted — non-destructive, matching the connector block); a present-but-
	// EMPTY registry does NOT wipe a non-empty local registry (apply keeps local — lockout-safe), because an
	// empty section usually means the CP is not the NHI authority, not "revoke every agent identity".
	NHI *nonHumanIdentityBundle `json:"nhi,omitempty"`
	// HumanIdentities is the people DIRECTORY — the identities an organization's IdP/HR feed produces, and the
	// source policies that describe those feeds. It is here for the same reason NHI is: in the pull-fleet model
	// the enforcing Edges are stateless pullers, so anything they must be able to answer about has to be
	// distributed or it simply is not there.
	//
	// ★ MEASURED BEFORE IT WAS WRITTEN (2026-08-19): the control plane held 90 identities for the lab tenant
	// and BOTH enforcing Edges held zero, because nothing ever carried them. Same lockout-safe shape as NHI —
	// an identity absent from the bundle is not deleted, and a present-but-empty section keeps a non-empty
	// local directory rather than emptying an organization's people list on one bad publish.
	HumanIdentities *humanIdentityBundle `json:"human_identities,omitempty"`
	// DelegatedGrants is the delegated-access-grant store (short-lived OOB-authenticated agent grants). A
	// separate store (delegatedgrant.Store); its generation folds into the aggregate. Pointer so a CP that omits
	// it leaves the Edge's grants untouched (fail-safe). apply UPSERTS each grant (additive; a local grant
	// absent from the bundle is not deleted); a present-but-EMPTY set does NOT wipe a non-empty local set
	// (apply keeps local — lockout-safe), so a non-authoritative CP cannot revoke in-flight agent grants.
	DelegatedGrants *delegatedGrantBundle `json:"delegated_grants,omitempty"`
	// Rules is the AUTHORED rule set (unified policy model: egress access/inspection + east-west per-hop authz)
	// together with the asset-catalog entries those rules name. Added 2026-08-10 after an adopted cert-pin
	// bypass reached one Edge while the device was served by another and every admin surface reported success
	// (docs/authored_policy_reaches_one_edge_not_the_serving_one.md). Pointer so a CP that omits the section
	// leaves the Edge's rules untouched; present-but-empty keeps local (lockout-safe).
	Rules *authoredRuleBundle `json:"rules,omitempty"`
	// Sites is the Site / Connector Group catalog — the thing a connector's bootstrap secret is checked
	// against. Added 2026-08-23 after measuring that nothing had ever carried one: the control plane held one
	// Site and the enforcing Edge held three. Unlike most sections this REPLACES within the organizations it
	// names, because carrying creations and not deletions is the half of the defect that is hardest to see —
	// an operator deletes a Site, watches it go, and the Edge keeps honouring its bootstrap secret. Pointer so
	// a CP that omits it leaves the Edge's catalog untouched; present-but-empty, or incomplete, keeps local.
	Sites *siteCatalogBundle `json:"sites,omitempty"`
	// RegionEndpoints is the class-1 region map — which regions this deployment has and where each answers.
	// Added 2026-08-23 after walking the multi-region install order: it was built from -region-endpoints on
	// each node and from nothing else, so giving every Edge the list was N command-line edits and an Edge
	// somebody missed stayed healthy while handing its devices a shorter map. Pointer so a node that is not
	// the control plane publishes nothing and changes nothing; present-but-empty CLEARS, because a map still
	// naming a region the deployment no longer has sends devices to an address nobody serves.
	RegionEndpoints *regionEndpointBundle `json:"region_endpoints,omitempty"`
	// InspectionPosture is the deployment's decrypt/bypass posture — enforcement, and it differed between two
	// Edges of one fleet twice (2026-08-21 and again 2026-08-23) because it was a per-node store. There is no
	// "empty" for a posture, so the pointer alone carries the question: present means the control plane authors
	// it; absent leaves this Edge's own untouched. See config_bundle_inspection_posture.go.
	InspectionPosture *inspectionPostureBundle `json:"inspection_posture,omitempty"`

	// Licence is the vendor's signed file, carried so every Edge holds what the authority holds. Absent means
	// "this control plane is not the authority for a licence", never "unlicensed" — see config_bundle_licence.go.
	Licence *licenceBundle `json:"licence,omitempty"`
	// DeviceCAs is the device-CA registry — which organization a client certificate belongs to, the entrance to
	// every decision. Its authority was on the enforcement side: the flag was on the Edges and not on the
	// control plane, and the Edges agreed by sharing one Postgres row. Removals are per organization and an
	// empty section removes NOTHING, because an empty registry refuses every device of every organization.
	// See config_bundle_device_cas.go.
	DeviceCAs *deviceCARegistryBundle `json:"device_cas,omitempty"`
	// InternalCAs is what each organization vouches for when an Edge verifies one of ITS OWN private assets.
	// Interception makes the Edge the TLS client to an intranet server, and that direction had no trust
	// anywhere until 2026-09-01: the flow was decrypted correctly and then refused against the platform's
	// public roots. See config_bundle_internal_cas.go, including the two channels this went through first that
	// do not exist on a zero-DB Edge.
	InternalCAs *internalCABundle `json:"internal_cas,omitempty"`
	// Grants is what the fleet has already approved out of band. Without it a grant minted at one Edge
	// releases a flow held at that Edge and nowhere else, and a revocation reaches only the node it was
	// authored on.
	Grants *grantBundle `json:"grants,omitempty"`
	// IdPConnections is which identity provider may sign a user in, per organization. Without it a step-up
	// ceremony reaches the broker and stops: the registry is on the control plane and the Edge has none.
	IdPConnections *idpConnectionBundle `json:"idp_connections,omitempty"`
	// TransportTrust is what devices check before they will talk to an Edge at all — the anchors and the serial
	// the fleet is distributing. Added 2026-08-23: the fleet used to agree about these by sharing one FILE,
	// which works only where every Edge mounts the same directory and is nothing where they do not. Both
	// outages transport_trust_store.go records came from two processes writing that file.
	//
	// Adopted FORWARD ONLY, never empty, and never a set this node cannot sign — the same rules the file
	// already followed, because they were never about the file. See transportTrustStore.AdoptDistribution.
	TransportTrust *transportTrustBundle `json:"transport_trust,omitempty"`
}

// transportTrustBundle carries the fleet's transport-trust distribution, in the store's own state shape so the
// two paths cannot describe it differently.
type transportTrustBundle struct {
	Distribution transportTrustStoreState `json:"distribution"`
}

// authoredRuleBundle carries the rules and the catalog entries they reference AS ONE UNIT.
//
// ★ They cannot be separate sections. A rule names destinations by endpoint id, so a rule that arrives before
// (or without) its catalog entries resolves to no addresses — inert on egress, and on east-west a rule with an
// empty selector is treated as a WILDCARD. Shipping them apart would make the intermediate state a widening.
type authoredRuleBundle struct {
	Rules     []policyrule.Rule       `json:"rules"`
	Endpoints []assetcatalog.Endpoint `json:"endpoints"`
	Groups    []assetcatalog.Group    `json:"groups"`
	Services  []assetcatalog.Service  `json:"services"`
}

// connectorCatalogBundle carries the class-1 connector catalog (descriptors only; runtime secret stripped).
type connectorCatalogBundle struct {
	Connectors []model.ConnectorRegistration `json:"connectors"`
}

// vlanBoundaryBundle carries the VLAN objects + boundary policies as one replace-all unit.
type vlanBoundaryBundle struct {
	Objects  []model.VLANObject         `json:"objects"`
	Policies []model.VLANBoundaryPolicy `json:"policies"`
	// Complete states that this IS the control plane's whole set — including when it is empty.
	//
	// ★★ WITHOUT IT, THE LAST NAMED NETWORK CAN NEVER BE DELETED (2026-08-16, measured on the lab). The
	// receiving side refused to apply an empty set, to avoid a control plane that had lost its store wiping
	// inter-VLAN enforcement off every Edge — a real hazard, and the wrong fix for it. The consequence: an
	// operator deleted the last object on the control plane, got a 200, saw an empty list there, and the
	// object stayed on the enforcing Edge indefinitely. Neither plane would remove it: the Edge refuses its own
	// DELETE with 409 ("authored on the control plane") and the control plane no longer had it to delete.
	//
	// So the fact travels instead of being inferred, the same way tenant deletion does above: the control
	// plane says whether its set is complete, and it only says so when its store is DURABLE. An in-memory
	// control plane that has just restarted is empty for a reason that is not "there are none", and it now
	// says nothing rather than something false.
	Complete bool `json:"complete,omitempty"`
}

// tenantModelBundle carries the tenant models so an explicitly-empty set is distinguishable from an absent one.
type tenantModelBundle struct {
	Tenants []adminTenantModel `json:"tenants"`
	// Deleted names the tenants the control plane has removed. Deletion is CARRIED, never inferred from a
	// tenant's absence above — absence is also what a truncated payload and a non-authoritative control plane
	// look like, and there is no way to tell those apart from the receiving end.
	Deleted []tenantDeletion `json:"deleted,omitempty"`
	// PurgeOrders names the tenants an operator has ordered ERASED. A node's own copy of a tenant's logs is
	// only reachable from that node, so the order has to travel; everything about how it is received is built
	// on the assumption that acting on it wrongly is unrecoverable.
	PurgeOrders []tenantPurgeOrder `json:"purge_orders,omitempty"`
}

// tenantPolicySection is ONE tenant's enforcement config: its policies and its tenant-level settings.
//
// ★ WHY THE BUNDLE NEEDED A PER-TENANT SHAPE (2026-08-15). It carried exactly one tenant's policies — the
// pulling Edge's own, taken from the bearer token's tenant — so a SECOND organization's policies reached no
// Edge at all. Measured on the lab while standing up a second tenant: the policy sat on the control plane
// and both Edges reported zero for it. The tenant registry row arrived, the organization appeared in every
// list, and nothing it said was enforced anywhere. That is "created it, and nothing happens", which is the
// exact failure this whole review exists to end.
type tenantPolicySection struct {
	TenantID string         `json:"tenant_id"`
	Policies []model.Policy `json:"policies"`
	// Config is optional: a tenant with policies but no tenant-level settings carries none, and the receiving
	// side then replaces policies without touching config.
	Config *policy.TenantConfigBundle `json:"config,omitempty"`
}

// tenantPurgeOrder is one carried ERASURE order: which tenant, and when the operator ordered it. Unlike a
// deletion, acting on this destroys data on the receiving node and cannot be undone — see
// applyCarriedTenantPurges for the gates that stand between this list and that act.
type tenantPurgeOrder struct {
	TenantID  string `json:"tenant_id"`
	OrderedAt string `json:"ordered_at,omitempty"`
}

// tenantDeletion is one carried deletion: which tenant, and when it was deleted on the authority.
type tenantDeletion struct {
	TenantID  string `json:"tenant_id"`
	DeletedAt string `json:"deleted_at,omitempty"`
}

// applyCarriedTenantDeletions removes the tenants the control plane named as deleted, and says so in the log.
//
// The control plane is the authority for the tenant registry; what an Edge holds is a runtime copy, so it has
// to be removable. Three things are refused rather than done, each of them loudly:
//
//   - the operator tenant, which backs cross-tenant administration — deleting it strands the operator, the
//     same lockout the control plane's own DELETE route refuses with 409;
//   - a tenant the same payload also asks us to keep, which is a contradiction and not an instruction;
//   - nothing else. A tenant we do not have is not an error: the delete is idempotent by design.
func applyCarriedTenantDeletions(ctx context.Context, store adminTenantModelAdminStore, section *tenantModelBundle, existing []adminTenantModel) error {
	if store == nil || section == nil || len(section.Deleted) == 0 {
		return nil
	}
	kept := make(map[string]bool, len(section.Tenants))
	for _, tenant := range section.Tenants {
		kept[strings.TrimSpace(tenant.TenantID)] = true
	}
	present := make(map[string]adminTenantModel, len(existing))
	for _, tenant := range existing {
		present[strings.TrimSpace(tenant.TenantID)] = tenant
	}
	var failed error
	for _, deletion := range section.Deleted {
		tenantID := strings.TrimSpace(deletion.TenantID)
		if tenantID == "" {
			continue
		}
		if kept[tenantID] {
			log.Printf("config-bundle sync: the control plane sent tenant %q as BOTH present and deleted — keeping it. A deletion has to be unambiguous to be acted on.", tenantID)
			continue
		}
		local, held := present[tenantID]
		if !held {
			continue // already gone here; nothing to do and nothing to report
		}
		if local.IsOperator {
			log.Printf("config-bundle sync: REFUSING to delete tenant %q — it is this node's operator tenant, and removing it would strand cross-tenant administration.", tenantID)
			continue
		}
		if err := store.Delete(ctx, tenantID); err != nil {
			failed = errors.Join(failed, fmt.Errorf("tenant deletion %q: %w", tenantID, err))
			log.Printf("config-bundle sync: deleting tenant %q as instructed by the control plane failed: %v", tenantID, err)
			continue
		}
		log.Printf("config-bundle sync: deleted tenant %q (control plane recorded the deletion at %s). Runtime state keyed to it is no longer served here.",
			tenantID, strings.TrimSpace(deletion.DeletedAt))
	}
	return failed
}

// enrolledInventoryBundle wraps the enrolled set so the bundle can carry an explicitly-empty set (replace all)
// distinct from "the CP omitted it" (leave alone).
type enrolledInventoryBundle struct {
	Entries []enrolledinventory.Entry `json:"entries"`
	// Groups distributes the first-class device-group REGISTRY alongside the entries so a pulling Edge resolves
	// the group risk floor from the CP-authoritative registry. nil = an older CP omitted it (leave local); a
	// present (possibly empty) list is authoritative. An empty registry is not a lockout, so no keep-local guard.
	Groups []enrolledinventory.Group `json:"groups"`
}

// nonHumanIdentityBundle carries the NHI registry so the bundle can distinguish an explicitly-empty
// registry (present-but-empty => keep local, lockout-safe) from "the CP omitted it" (nil => leave alone).
type nonHumanIdentityBundle struct {
	Identities []model.NonHumanIdentity `json:"identities"`
}

// humanIdentityBundle carries the people directory and the source policies that feed it, so a pulling Edge
// holds the same directory the control plane does. Separate from NHI on purpose: the two registries are read
// by different things and an empty one must not be read as a statement about the other.
type humanIdentityBundle struct {
	Identities     []model.HumanIdentity                     `json:"identities"`
	SourcePolicies []humanidentity.HumanIdentitySourcePolicy `json:"source_policies,omitempty"`
}

// delegatedGrantBundle carries the delegated-access-grant set with the same present-but-empty vs
// omitted distinction.
type delegatedGrantBundle struct {
	Grants []model.DelegatedAccessGrant `json:"grants"`
}

// configApplyTargets are the Edge-local stores a config bundle is applied into. Grouping them keeps run/apply
// signatures stable as more separate-store resources fold into the bundle. Any field may be nil (that resource
// is absent on this Edge).
type configApplyTargets struct {
	applications    appcatalog.RuntimeStore
	dlp             *dlpConfigStores
	policyStore     *policy.Store
	resolver        *dnsresolver.Resolver
	enrolled        *enrolledinventory.Ledger
	tenantModels    adminTenantModelAdminStore
	vlan            *vlan.Store
	connectors      *connector.Registry
	nhi             nhi.RuntimeStore
	humanIdentities humanidentity.HumanIdentityDirectoryRuntimeStore
	delegatedGrants *delegatedgrant.Store
	rules           *policyrule.Store
	assets          *assetcatalog.Store
	// sites is the Site / Connector Group catalog — what a connector's bootstrap secret is checked against.
	// Distributed since 2026-08-23; before that each node kept its own and nothing carried one, so the control
	// plane held one Site and the enforcing Edge held three. See config_bundle_sites.go.
	sites adminSiteStore
	// transportTrust is what devices check before they will talk to this Edge — carried in the bundle since
	// 2026-08-23 so the fleet stops agreeing about it through a shared file.
	transportTrust *transportTrustStore
	// inspectionPosture / setInspectionPosture are this Edge's posture, read and written. A pair rather than a
	// store because that is how the rest of the process already reaches it.
	inspectionPosture    func() inspectionposture.Posture
	setInspectionPosture func(inspectionposture.Posture, string) (inspectionposture.Posture, error)

	// licenceStore / licensingGate / licenceAcceptedKeys / licenceMSSPID are what this node needs to accept a
	// licence ON ITS OWN TERMS. The keys and the addressee are deliberately this node's, not the bundle's: a
	// node that would not accept the licence the authority is publishing has to refuse and say so.
	licenceStore        *licenseStore
	licensingGate       *enrolmentLicensing
	licenceAcceptedKeys []*ecdsa.PublicKey
	licenceMSSPID       string
	// deviceCAs and the trust set behind it, so a CARRIED erasure order removes the same things the local
	// purge route does. A node that only heard about the deletion must not keep admitting that organization's
	// devices because the order arrived over the bundle instead of over HTTP.
	deviceCAs            *tenantca.TenantCARegistry
	internalCAs          organizationInternalCAPool
	deviceCARegistryPath string
	deviceTrust          transportTrustAnchorStore
	// onRulesApplied recompiles the in-memory east-west/egress sets and rebuilds the decrypt-bypass set. The
	// compiled sets are DERIVED and in-memory: without this the store would hold the CP's rules while the engine
	// went on enforcing the ones it compiled at boot — the same divergence this section exists to end, moved one
	// layer inward where no admin surface would show it at all.
	onRulesApplied func()
	// The fields below exist only for the carried tenant ERASURE. They are what makes a node able to erase its
	// own copy of a terminated tenant's data — the logs on its disk above all, which nothing else can reach.
	logWriter           *logs.Writer
	localCredentials    *localAdminCredentialStore
	purgeDB             *sql.DB
	legalHold           *legalHoldStore
	enforcementTenantID string
	// nodeName labels this node in the erasure log, so "which node erased what" is answerable afterwards.
	nodeName string
	// erasureOrders remembers the standing erasure orders so this node can answer, on every status report,
	// whether it still holds anything for each of them.
	erasureOrders *tenantErasureOrders
}

// tenantErasureOrders is the standing list of tenants an operator has ordered erased, as this node last heard
// it. Kept so the node can be ASKED, on every status report, whether it is clean — rather than announcing once
// that it acted and never being checkable again.
type tenantErasureOrders struct {
	mu     sync.RWMutex
	tenant []string
}

func (o *tenantErasureOrders) remember(orders []tenantPurgeOrder) {
	if o == nil {
		return
	}
	ids := make([]string, 0, len(orders))
	for _, order := range orders {
		if id := strings.TrimSpace(order.TenantID); id != "" {
			ids = append(ids, id)
		}
	}
	o.mu.Lock()
	o.tenant = ids
	o.mu.Unlock()
}

func (o *tenantErasureOrders) list() []string {
	if o == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return append([]string(nil), o.tenant...)
}

// baseURL is the control-plane base to pull from now: the current healthy CP when region failover is configured
// (multi-region), else the fixed single-CP URL. "" = no in-boundary CP reachable right now.
func (s configBundleSource) baseURL() string {
	if s.endpoints != nil {
		return s.endpoints.CurrentBaseURL()
	}
	return s.url
}

// fetch pulls the tenant's config bundle from the control plane WITHOUT touching any store; the caller
// decides whether to apply based on the generation.
func (s configBundleSource) fetch(ctx context.Context) (configBundlePayload, error) {
	base := s.baseURL()
	if strings.TrimSpace(base) == "" {
		return configBundlePayload{}, fmt.Errorf("no in-boundary control plane reachable (keeping last config)")
	}
	url := strings.TrimRight(base, "/") + "/admin/config-bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return configBundlePayload{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return configBundlePayload{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// ★★★ A NODE THAT SAYS IT DOES NOT LEAD IS A FACT ABOUT THIS CONNECTION (2026-08-27). The control
		// planes sit behind a front door whose health check is GET /leader, so NEW connections reach the
		// leader — but a connection already established is kept, and this client pools them. An Edge that
		// first connected while the other node led kept pulling from it: measured with two Edges of one
		// region applying generations 13 and 8 while both polled in the same second, and the one on 8 stayed
		// there. Dropping the pooled connections makes the next poll dial again, which lands on whoever
		// leads now.
		//
		// The body is read and closed FIRST, because a connection only returns to the pool when its response
		// is finished with and CloseIdleConnections closes only what is idle.
		if strings.Contains(strings.ToLower(string(body)), "does not hold leadership") {
			s.client.CloseIdleConnections()
		}
		return configBundlePayload{}, fmt.Errorf("control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Signature verification (fail-closed). The control plane signs the bundle (agentpolicy.Envelope). When a
	// verify key is pinned, VERIFY the signature and decode the SIGNED payload bytes — a tampered or unsigned
	// bundle is rejected so a compromised CP / stolen bearer token cannot push arbitrary enforcement policy.
	if len(s.verifyKeys) > 0 || strings.TrimSpace(s.verifyPubKeyHex) != "" {
		var env agentpolicy.Envelope
		if uerr := json.Unmarshal(body, &env); uerr == nil && strings.TrimSpace(env.Signature) != "" {
			// VerifyAny against the accepted set (the current signer plus any published next keys), so a rotation
			// overlap — the CP signing with a key the edge has not switched to yet — does not fail the whole sync
			// the way the single-key pin did at the 2c switch. Falls back to the one pinned key for tests / lab.
			signed, verr := agentpolicy.VerifyAny(env, s.acceptedVerifyKeys())
			if verr != nil {
				return configBundlePayload{}, fmt.Errorf("config bundle signature verification failed (rejecting tampered/untrusted config): %w", verr)
			}
			var payload configBundlePayload
			if err := json.Unmarshal(signed, &payload); err != nil {
				return configBundlePayload{}, fmt.Errorf("decode signed config bundle payload: %w", err)
			}
			// Set AFTER the unmarshal, so nothing on the wire can influence it (it is unexported, so nothing
			// could anyway — belt and braces on the one flag an irreversible erasure depends on).
			payload.signatureVerified = true
			return payload, nil
		}
		if s.requireSigned {
			return configBundlePayload{}, fmt.Errorf("config bundle from the control plane is UNSIGNED but a signing key is pinned — rejecting (set -allow-unsigned-config-bundle to accept)")
		}
	}
	// Unsigned path: no key pinned, or unsigned explicitly allowed. Decode the raw bundle.
	var payload configBundlePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return configBundlePayload{}, fmt.Errorf("decode config bundle: %w", err)
	}
	return payload, nil
}

// apply swaps the bundle's resources into the Edge's stores. The policy.Store part (policies + tenant
// config) is applied ATOMICALLY under one lock with one generation bump; the DNS policy lives in a separate
// store (dnsresolver.Resolver) and is swapped atomically there (atomic.Pointer). When the CP omits a section (older
// CP), that store is left untouched (fail-safe). dnsresolver.Resolver may be nil (no resolver on this Edge). Returns
// the policy count applied.
// apply returns how many policies it applied, and whether a SECURITY-CRITICAL section failed.
//
// ★ A FAILED ADMISSION UPDATE WAS RECORDED AS APPLIED (2026-08-13, twenty-fifth review). The enrolled
// inventory learned to refuse a merge it could not persist — and this swallowed that into a log line, after
// which the caller set lastApplied, recorded the generation and printed "applied generation N". The same
// generation is never retried, so an operator who DISABLED a device saw the Edge report itself current while
// that device stayed admitted. Reporting a generation as applied is a claim about every section in it.
func (s configBundleSource) apply(payload configBundlePayload, t configApplyTargets) (int, error) {
	// criticalErr is set by any section whose failure must NOT be reported as an applied generation.
	//
	// ★ THE RULE EXISTED FOR ONE SECTION AND THE INCIDENT IT CAME FROM WAS ABOUT ANOTHER (2026-08-13,
	// twenty-seventh review). Admission got this treatment first, and authored rules — the section whose
	// silent non-arrival is the incident this whole sync path was built to close — went on being logged while
	// lastApplied advanced. ReplaceAll is all-or-nothing, so one malformed rule from the control plane means
	// the Edge keeps enforcing the OLD set, reports itself current, and shouldApplyBundle never retries.
	//
	// The test is not "is this section important" but "can the Edge converge without being asked again". A
	// refused write cannot: nothing re-offers it. So refusals join here and the generation stays unapplied.
	var criticalErr error
	if s.requireSigned && payload.Applications != nil && !payload.signatureVerified {
		return 0, fmt.Errorf("application catalog requires a verified config bundle")
	}
	if err := applyApplicationBundle(t.applications, payload.Applications); err != nil {
		return 0, fmt.Errorf("application catalog: %w", err)
	}
	if payload.TenantConfig != nil {
		if err := policy.ValidateTenantRestrictions(payload.TenantConfig.SaaSTenantRestrictions); err != nil {
			return 0, err
		}
	}
	for _, section := range payload.TenantPolicies {
		if section.Config != nil {
			if err := policy.ValidateTenantRestrictions(section.Config.SaaSTenantRestrictions); err != nil {
				return 0, err
			}
		}
	}
	if payload.DLP != nil {
		if err := t.dlp.Apply(payload.DLP); err != nil {
			return 0, fmt.Errorf("DLP configuration: %w", err)
		}
	}
	now := time.Now().UTC()
	// LOCKOUT-SAFE GUARD (observed live 2026-06-20). The pointer-nil "fail-safe" (a CP that OMITS a section
	// leaves it alone) does not protect in practice: every Edge binary always constructs these stores, so the
	// CP serves each section PRESENT — and present-but-empty when the CP is not the authority for it. A blind
	// replace then WIPES non-empty enforcement state into an availability cliff: empty enrolled = every device
	// deauthorized = admission lockout; empty policies = default-deny-all; empty VLAN = inter-VLAN enforcement
	// silently dropped. So a config PULL must never replace a NON-EMPTY local set with an EMPTY one — keep
	// local and log. An intentional full clear is an explicit admin op, not a side effect of a pull; a device
	// is removed from enforcement via enabled=false (it stays in the list, so the section is non-empty).
	policies := payload.Policies
	if len(policies) == 0 {
		if local := t.policyStore.Snapshot(s.tenantID); len(local) > 0 {
			log.Printf("config-bundle sync: control plane sent ZERO policies while this Edge enforces %d for tenant %s — keeping local policies to avoid a fleet-wide default-deny (lockout-safe).", len(local), s.tenantID)
			policies = local
		}
	}
	var n int
	if payload.TenantConfig != nil {
		var err error
		n, err = t.policyStore.ApplyReceivedBundle(s.tenantID, policies, *payload.TenantConfig, now)
		if err != nil {
			return 0, fmt.Errorf("runtime configuration: %w", err)
		}
	} else {
		n = t.policyStore.ReplaceTenant(s.tenantID, policies, now)
	}
	// EVERY OTHER TENANT. The block above applies this Edge's own tenant, which is all the bundle could carry
	// until now; this applies the rest. A tenant the section does not name is left alone — absence is not an
	// instruction here any more than it is for a deletion.
	//
	// The Edge's own tenant is skipped: it was just applied above, from a section that has the zero-policies
	// lockout guard the loop deliberately does not repeat. A second tenant has no local enforcement to protect
	// yet, and treating "no policies" as "keep whatever you had" would make a genuinely empty new tenant
	// impossible to express.
	for _, section := range payload.TenantPolicies {
		tenantID := strings.TrimSpace(section.TenantID)
		if tenantID == "" || strings.EqualFold(tenantID, strings.TrimSpace(s.tenantID)) {
			continue
		}
		applied := 0
		if section.Config != nil {
			var err error
			applied, err = t.policyStore.ApplyReceivedBundle(tenantID, section.Policies, *section.Config, now)
			if err != nil {
				return 0, fmt.Errorf("runtime configuration for %s: %w", tenantID, err)
			}
		} else {
			applied = t.policyStore.ReplaceTenant(tenantID, section.Policies, now)
		}
		n += applied
	}
	if payload.DNSPolicy != nil && t.resolver != nil {
		if pol, err := dnsresolver.PolicyFromDTO(*payload.DNSPolicy); err == nil {
			// Same lockout-safe rule as every other section, which this one was missing. A DNS policy carries
			// the stub answers that make internal names resolve at all, so replacing a populated one with an
			// empty one does not merely relax enforcement — private hostnames stop resolving, which reaches a
			// user as the browser reporting no internet connection rather than as anything policy-shaped.
			// Present-but-empty means the CP is not the DNS authority far more often than it means "serve
			// nothing", and clearing DNS deliberately is an explicit admin act with its own route.
			if local := t.resolver.CurrentPolicy(); pol.IsEmpty() && !local.IsEmpty() {
				log.Printf("config-bundle sync: control plane sent an EMPTY DNS policy while this Edge serves one (%s) — keeping local to avoid breaking name resolution (lockout-safe).", local.Summary())
			} else {
				t.resolver.SetPolicy(pol) // hot-swap; a malformed DTO is skipped (fail-safe: keep current DNS policy)
			}
		} else {
			log.Printf("config-bundle sync: skipping invalid DNS policy from the control plane: %v", err)
		}
	}
	if payload.Enrolled != nil && t.enrolled != nil {
		if len(payload.Enrolled.Entries) == 0 && len(t.enrolled.List()) > 0 {
			log.Printf("config-bundle sync: control plane sent an EMPTY enrolled inventory while this Edge has %d enrolled identity(ies) — keeping local to avoid wiping admission (lockout-safe). Make the CP the enrolled authority, or disable devices individually (enabled=false).", len(t.enrolled.List()))
		} else {
			// ★ MERGE, NOT REPLACE (2026-08-12, twenty-first review). The CP is the authority on WHICH
			// identities are admitted; only this Edge knows which of them have actually completed an
			// enrolment here, because /enroll runs here and the CP's entries carry no marker. Replacing
			// wholesale erased that, so any unrelated control-plane change made every enrolled device
			// enrollable again by whoever holds a credential for its tenant. MergeAuthoritative keeps the
			// local marker unless the CP's re-enrolment nonce is newer, which is how an administrator's
			// decision to permit one still propagates.
			if merr := t.enrolled.MergeAuthoritative(payload.Enrolled.Entries, now.Format(time.RFC3339)); merr != nil {
				// The rest of the bundle still applies — a policy update should not be held back by this — but
				// the GENERATION must not be recorded as applied, or the retry never happens and the Edge
				// reports itself current while a disabled device stays admitted.
				log.Printf("config-bundle sync: the enrolled inventory was NOT applied: %v", merr)
				criticalErr = fmt.Errorf("enrolled inventory: %w", merr)
			}
		}
		// Device-group registry: nil = CP omitted (leave local); present (even empty) = authoritative. An empty
		// registry is not a lockout (assignments then resolve to no floor), so it needs no keep-local guard.
		if payload.Enrolled.Groups != nil {
			t.enrolled.ReplaceAllGroups(payload.Enrolled.Groups, now.Format(time.RFC3339))
		}
	}
	var tenantApplyErr error
	if payload.Tenants != nil && t.tenantModels != nil {
		ctx := context.Background()
		existing, err := t.tenantModels.List(ctx)
		if err != nil {
			tenantApplyErr = fmt.Errorf("tenant registry read: %w", err)
		} else {
			if len(payload.Tenants.Tenants) == 0 && len(existing) > 0 {
				log.Printf("config-bundle sync: empty tenant set is not a deletion; keeping %d local tenant(s)", len(existing))
			} else {
				for _, tenant := range payload.Tenants.Tenants {
					if _, err := t.tenantModels.Put(ctx, tenant, now); err != nil {
						tenantApplyErr = errors.Join(tenantApplyErr, fmt.Errorf("tenant %q: %w", tenant.TenantID, err))
					}
				}
			}
			tenantApplyErr = errors.Join(tenantApplyErr, applyCarriedTenantDeletions(ctx, t.tenantModels, payload.Tenants, existing))
		}
	}
	if tenantApplyErr != nil {
		criticalErr = errors.Join(criticalErr, tenantApplyErr)
	} else {
		// Never erase or remember an order after uncertain tenant reconciliation.
		// Nodes without a registry can still receive independently signed erasure orders.
		applyCarriedTenantPurges(context.Background(), t, payload, t.nodeName, now)
		if payload.Tenants != nil && t.erasureOrders != nil {
			t.erasureOrders.remember(payload.Tenants.PurgeOrders)
		}
	}
	if payload.VLAN != nil && t.vlan != nil {
		emptyPayload := len(payload.VLAN.Objects) == 0 && len(payload.VLAN.Policies) == 0
		edgeHolds := len(t.vlan.ListObjects()) > 0 || len(t.vlan.ListPolicies()) > 0
		switch {
		case emptyPayload && edgeHolds && !payload.VLAN.Complete:
			log.Printf("config-bundle sync: control plane sent an EMPTY VLAN boundary set without saying it is complete while this Edge has objects/policies — keeping local to avoid dropping inter-VLAN enforcement.")
		case emptyPayload && edgeHolds:
			// The control plane said so, from a durable store. Deleting the last Named Network has to be
			// possible, and it is only possible here.
			log.Printf("config-bundle sync: control plane reports its VLAN boundary set is COMPLETE and empty — clearing %d object(s) and %d policy/policies.",
				len(t.vlan.ListObjects()), len(t.vlan.ListPolicies()))
			if err := t.vlan.ReplaceAll(nil, nil); err != nil {
				criticalErr = errors.Join(criticalErr, err)
			}
		default:
			if err := t.vlan.ReplaceAll(payload.VLAN.Objects, payload.VLAN.Policies); err != nil {
				criticalErr = errors.Join(criticalErr, err)
			}
		}
	}
	if payload.Connectors != nil && t.connectors != nil {
		if len(payload.Connectors.Connectors) == 0 && len(t.connectors.List()) > 0 {
			log.Printf("config-bundle sync: control plane sent an EMPTY connector catalog while this Edge has connectors — keeping local (lockout-safe).")
		} else {
			// UPSERT each catalog entry: Register preserves any LOCAL runtime state (a locally-connected
			// connector keeps its tunnel/runtime-secret), while a remote-region connector arrives as a
			// catalog-only descriptor the reach layer can hairpin/mesh to.
			//
			// ★★★ AND A CONNECTOR THE AUTHORITY NO LONGER HAS IS DROPPED (2026-08-26, measured — it was worse
			// than untidy). Removal used to be deferred until an Edge restarted, on the reasoning that never
			// wiping is lockout-safe. But a lingering connector does not sit quietly: route bindings are keyed
			// by SITE, so every connector in that site inherits them, and the route layer picks among equal
			// matches by id ORDER. A connector deleted hours earlier — in a region that no longer exists —
			// deterministically WON the resolution over the live one, and every flow to that internal
			// destination died with a message about egress. Removing a connector did not stop it being chosen.
			//
			// ★ WHAT IS KEPT IS WHAT THIS NODE KNOWS FIRST-HAND AND CURRENTLY. A connector that registered HERE
			// moments ago is not yet in the authority's copy — its report is a poll behind — so a rule of
			// "absent from the authority means gone" would delete a connector that had just arrived. But
			// "registered here at some point" is not enough either: measured, the connectors this rule was
			// written to remove had ALL registered here earlier in the day, and keeping them on that basis
			// kept exactly the dead ones that were winning route bindings. So the test is recency: a
			// connector this node has heard from lately is one this node knows better than the authority
			// does; one that is absent from the authority and silent here is gone.
			fromAuthority := make(map[string]bool, len(payload.Connectors.Connectors))
			for _, conn := range payload.Connectors.Connectors {
				fromAuthority[strings.TrimSpace(conn.ID)] = true
			}
			{
				remover := t.connectors
				for _, local := range t.connectors.List() {
					id := strings.TrimSpace(local.ID)
					if id == "" || fromAuthority[id] || connectorHeardFromRecently(local, now) {
						continue
					}
					if removed, rerr := remover.RemoveForTenant(strings.TrimSpace(local.TenantID), id); rerr != nil {
						log.Printf("config-bundle sync: %q is gone from the control plane and could not be dropped "+
							"here (%v) — it can still win a route binding against a live connector", id, rerr)
					} else if removed {
						log.Printf("config-bundle sync: dropped connector %q — the control plane no longer has it, "+
							"and this node never saw it register", id)
					}
				}
			}
			for _, conn := range payload.Connectors.Connectors {
				if _, err := t.connectors.Register(conn, now); err != nil {
					log.Printf("config-bundle sync: skipping invalid connector %q from the control plane: %v", conn.ID, err)
					continue
				}
				// Route governance: record the advertised routes. First sight grandfathers the current set
				// (existing deployments keep working); a route advertised LATER is pending until approved.
				if connectorRouteGov != nil {
					if err := connectorRouteGov.SeeRoutesContext(context.Background(), conn.TenantID, conn.ID, conn.ReachableRoutes.CIDRs, now); err != nil {
						criticalErr = errors.Join(criticalErr, fmt.Errorf("route discovery: %w", err))
					}
				}
			}
		}
	}
	// Non-Human Identity registry: UPSERT each identity so agent governance authored on the control plane
	// reaches enforcing Edges. Additive (an NHI absent from the bundle is not deleted — non-destructive, matching
	// the connector block). A present-but-EMPTY registry does NOT wipe a non-empty local one (lockout-safe).
	if payload.NHI != nil && t.nhi != nil {
		if len(payload.NHI.Identities) == 0 {
			if local, _ := t.nhi.List(context.Background(), s.tenantID); len(local) > 0 {
				log.Printf("config-bundle sync: control plane sent an EMPTY non-human identity registry while this Edge has %d NHI(s) — keeping local (lockout-safe).", len(local))
			}
		} else {
			for _, identity := range payload.NHI.Identities {
				if _, err := t.nhi.Upsert(context.Background(), identity, s.tenantID, now); err != nil {
					log.Printf("config-bundle sync: skipping invalid non-human identity %q from the control plane: %v", identity.ID, err)
				}
			}
		}
	}
	// People DIRECTORY: UPSERT each identity so the directory an organization authored on the control plane is
	// the one an enforcing Edge holds. Same shape as NHI above, and for the same measured reason — before this
	// existed the CP held 90 identities for the lab tenant and both Edges held none, so every Edge-side answer
	// about people was drawn from an empty list without ever saying so.
	//
	// Lockout-safe in the same way: a present-but-EMPTY directory does not wipe a non-empty local one. An
	// organization's people list is exactly the kind of thing a single bad publish must not be able to erase.
	if payload.HumanIdentities != nil && t.humanIdentities != nil {
		if len(payload.HumanIdentities.Identities) == 0 {
			if local, _ := t.humanIdentities.List(context.Background(), s.tenantID); len(local) > 0 {
				log.Printf("config-bundle sync: control plane sent an EMPTY people directory while this Edge has %d identity(ies) — keeping local (lockout-safe).", len(local))
			}
		} else {
			applied := 0
			for _, identity := range payload.HumanIdentities.Identities {
				// ★ EACH IDENTITY KEEPS ITS OWN ORGANIZATION. Passing this Edge's tenant would have been the
				// obvious thing and is wrong in both directions: NormalizeHumanIdentity REFUSES a mismatch, so
				// every other organization's people would be dropped with a log line nobody reads — and if it
				// had re-stamped instead of refusing, one Edge would have merged every customer's directory
				// into one. The empty tenant here means "the record says which organization it belongs to".
				if _, err := t.humanIdentities.Upsert(context.Background(), identity, "", now); err != nil {
					log.Printf("config-bundle sync: skipping invalid directory identity %q from the control plane: %v", identity.ID, err)
					continue
				}
				applied++
			}
			log.Printf("config-bundle sync: applied %d of %d directory identity(ies) from the control plane.", applied, len(payload.HumanIdentities.Identities))
		}
		for _, policy := range payload.HumanIdentities.SourcePolicies {
			if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), t.humanIdentities, policy.TenantID, policy, now); err != nil {
				log.Printf("config-bundle sync: skipping invalid identity source policy %q from the control plane: %v", policy.Source, err)
			}
		}
	}
	// delegated-access grants: UPSERT each grant (additive). A present-but-EMPTY set does NOT wipe a
	// non-empty local set (lockout-safe) — a non-authoritative CP must not revoke in-flight agent grants.
	if payload.DelegatedGrants != nil && t.delegatedGrants != nil {
		if len(payload.DelegatedGrants.Grants) == 0 {
			if local := t.delegatedGrants.Snapshot(); len(local) > 0 {
				log.Printf("config-bundle sync: control plane sent an EMPTY delegated-grant set while this Edge has %d grant(s) — keeping local (lockout-safe).", len(local))
			}
		} else {
			for _, grant := range payload.DelegatedGrants.Grants {
				if _, err := t.delegatedGrants.Upsert(grant); err != nil {
					// Continue so updates/revocations of retained IDs can still be applied at capacity.
					// A rejected grant must leave the generation unapplied and eligible for retry.
					criticalErr = errors.Join(criticalErr, fmt.Errorf("delegated grant %q: %w", grant.ID, err))
				}
			}
		}
	}
	// THE TRANSPORT TRUST DISTRIBUTION. Before everything else: these are the anchors a device checks before it
	// will talk to this Edge at all, so a node applying the rest of a bundle while serving the wrong ones is a
	// node nobody can reach.
	if payload.TransportTrust != nil && t.transportTrust != nil {
		t.transportTrust.AdoptDistribution(payload.TransportTrust.Distribution)
	}
	// THE DEVICE-CA REGISTRY. Before the posture and the rules, because everything downstream keys a flow to
	// its organization through this: a rule applied against a registry that has not caught up is applied to the
	// wrong organization or to none.
	// The authorities each organization vouches for over its own private assets. Applied here, next to the
	// device-CA registry, because they are the same kind of fact from opposite directions: that one says which
	// organization a client certificate belongs to, this one says which server certificates an organization's
	// own flows may accept.
	if payload.InternalCAs != nil {
		count, applied, err := applyInternalCABundleSection(t.internalCAs, payload.InternalCAs, log.Printf)
		if err != nil {
			criticalErr = errors.Join(criticalErr, fmt.Errorf("internal authorities: %w", err))
		}
		if applied {
			log.Printf("config_bundle_internal_cas applied=%d", count)
		}
	}
	// What the fleet has already approved out of band, so a flow held on a node that did not run the
	// ceremony is released by the grant that ceremony earned.
	if payload.Grants != nil {
		added, updated, err := applyGrantBundleSection(theGrantStore.Load(), payload.Grants, time.Now().UTC())
		if err != nil {
			criticalErr = errors.Join(criticalErr, fmt.Errorf("access grants: %w", err))
		}
		if added > 0 || updated > 0 {
			log.Printf("config_bundle_grants added=%d updated=%d", added, updated)
		}
	}
	// Which identity provider may sign a user in, for each organization. Applied beside the authorities
	// above because it is the same kind of fact: who this deployment believes, on behalf of whom.
	if payload.IdPConnections != nil {
		if count, applied := applyIdPConnectionBundleSection(theIdPRegistry.Load(), payload.IdPConnections, log.Printf); applied {
			log.Printf("config_bundle_idp_connections applied=%d", count)
		}
	}
	if payload.DeviceCAs != nil && t.deviceCAs != nil {
		added, removed := applyDeviceCABundleSection(t.deviceCAs, payload.DeviceCAs, func(reg *tenantca.TenantCARegistry) error {
			return persistTenantCARegistry(reg, t.deviceCARegistryPath)
		}, log.Printf)
		// ★★★ AND THE LISTENER IS TOLD (2026-08-24). Adopting a device CA into the registry made this Edge able
		// to IDENTIFY an organization's devices and did nothing about whether it would verify one at the
		// handshake: the client-CA pool was built at start-up and never touched again on this path. An
		// organization registered while the fleet was running was admitted by no node until every node had
		// been restarted.
		//
		// Replace registry-owned anchors while retaining the independent operator roots.
		if added > 0 || removed > 0 {
			deviceCAUpdateMu.Lock()
			setEdgeClientRegistryCAs(t.deviceCAs.Anchors())
			deviceCAUpdateMu.Unlock()
		}
	}
	// THE INSPECTION POSTURE. Enforcement: which hosts this Edge decrypts. Applied before the rules block so a
	// bundle that changes both leaves the engine consistent with the posture the rules were authored against.
	if payload.Licence != nil && t.licenceStore != nil {
		applyLicenceBundleSection(payload.Licence, t.licenceStore, t.licensingGate, t.licenceAcceptedKeys,
			t.licenceMSSPID, time.Now().UTC().Format(time.RFC3339), log.Printf)
	}
	if payload.InspectionPosture != nil {
		if _, err := applyInspectionPostureBundleSection(payload.InspectionPosture, t.inspectionPosture, t.setInspectionPosture, log.Printf); err != nil {
			criticalErr = errors.Join(criticalErr, fmt.Errorf("inspection posture: %w", err))
		}
	}
	// THE SITE CATALOG. Applied before the rules block below purely so it sits beside the connector catalog it
	// belongs with; nothing here depends on ordering. See config_bundle_sites.go for why it REPLACES within the
	// organizations the section names rather than upserting — an operator deleting a Site in the Console and
	// the Edge going on honouring its bootstrap secret is the half of the defect that is hardest to see.
	if payload.Sites != nil && t.sites != nil {
		if len(payload.Sites.Sites) == 0 {
			if local, err := t.sites.List(context.Background(), ""); err == nil && len(local) > 0 {
				log.Printf("config-bundle sync: control plane sent an EMPTY Site catalog while this Edge has %d — keeping local (lockout-safe).", len(local))
			}
		}
		applySiteBundleSection(context.Background(), t.sites, payload.Sites, time.Now().UTC(), log.Printf)
	}
	if payload.RegionEndpoints != nil {
		applyRegionEndpointBundleSection(payload.RegionEndpoints, log.Printf)
	}
	// AUTHORED RULES + the catalog they name. Order matters: the catalog goes in FIRST, so that by the time the
	// rules land every id they reference already resolves.
	//
	// The catalog is UPSERTED and the rules are REPLACED, and the asymmetry is deliberate — see the comments in
	// assetcatalog/distribution.go and policyrule/distribution.go. Briefly: the catalog has three owners (CP,
	// enrolled-device sync, built-ins) so replacing it would delete the other two every pull; the rule set has
	// one owner, and an authored allow/bypass that survives its own deletion fails permissive.
	if payload.Rules != nil && t.rules == nil {
		criticalErr = errors.Join(criticalErr, fmt.Errorf("authored rule target is unavailable"))
	}
	if payload.Rules != nil && t.rules != nil {
		// ★ PRESENT-BUT-EMPTY CLEARS, and this is the one section where it must — reversing the rule every
		// other section follows, after live testing showed the alternative is broken (2026-08-10).
		//
		// Elsewhere "present but empty" keeps the local set because empty is AMBIGUOUS and dangerous: an empty
		// enrolled inventory is an admission lockout, empty policies are deny-all. Neither is true here. An
		// empty authored rule set is the ordinary state of a fresh deployment — rules add authorization on top
		// of policy, so having none locks nobody out.
		//
		// Keeping local instead cost the property this whole section exists for: DELETE stopped propagating as
		// soon as it was the LAST rule. Measured — the probe rule was removed on the control plane, the CP went
		// to zero rules, and both Edges kept enforcing it with no way to remove it (their own /admin/rules now
		// refuses writes). A bypass nobody can delete is the permissive direction, reached from the safety rule.
		//
		// The AMBIGUITY is already resolved by the pointer: a control plane that does not author rules omits the
		// section entirely (nil, handled by the condition above) and an older CP has no section to send. Present
		// means "I am the authority for rules"; empty then means "and there are none". The protection against a
		// CP that LOST its rules belongs where it was put — the store is durable by default and a volatile
		// config store fails startup — not in a fallback that breaks deletion.
		// ★ ASSETS RECONCILE FIRST, AND OUTSIDE THE BRANCH BELOW.
		//
		// Upserting alone had no way to remove an asset, so one deleted on the control plane — which answers
		// 200 {"status":"deleted"} — stayed on every Edge forever. Verified live before the fix: still on both
		// edges two minutes after the CP reported it gone.
		//
		// ★★ And the FIRST fix put this inside the "the CP authors at least one rule" branch, where the upserts
		// had always lived. Verified live again, and it did nothing: the rule under test had just been deleted,
		// so the CP was authoring zero rules and the reconciliation was never reached. A deployment with no
		// rules would never reconcile its assets at all — the correct code in a place it does not run, which is
		// indistinguishable from not having written it. `payload.Rules != nil` is the signal that the CP is the
		// authority here; how MANY rules it happens to author is not part of that.
		//
		// Before the rule apply, because a rule may reference an endpoint this bundle introduces. Safe in the
		// other direction too: policyrule validation does not consult the asset catalog, so removing an asset
		// first cannot make the rule set refuse.
		// ★ THE CONTROL PLANE IS THE AUTHORITY FOR ASSETS (operator decision, 2026-08-11): "CP authority is
		// absolute; Edges come and go." An Edge is a replaceable instance, so an asset held only there is lost
		// with it. Reconciling means the bundle can carry the ABSENCE of an asset — which only became meaningful
		// once the Edge's own asset writes were refused (assets_admin.go), because until then absence meant
		// "this instance never heard of it" rather than "the authority does not have it".
		//
		// ★★ THIS DELETED 47 OPERATOR ASSETS the first time it was enabled, on an Edge holding assets the CP had
		// never received (docs/2026-08-11_asset_reconciliation_deleted_47_operator_assets.md). Nothing in the
		// code can distinguish "never migrated" from "deliberately removed"; the cutover is a migration and the
		// migration is ops/migrate_edge_assets_to_cp.sh. What the code CAN do is refuse to be quiet about it,
		// which is why every removal is named below.
		//
		// The protection against a control plane that LOST its catalog is the same one the rules section rests
		// on: the CP's store is durable (-state-dir) and a volatile config store fails startup. It does not
		// belong in a fallback here, because a fallback that keeps local state on an empty payload is precisely
		// what stops deletion from ever propagating.
		//
		// Before the rule apply, because a rule may reference an endpoint this bundle introduces. Safe in the
		// other order too: policyrule validation never consults the asset catalog.
		assetsReady := true
		if t.assets == nil && (len(payload.Rules.Endpoints)+len(payload.Rules.Groups)+len(payload.Rules.Services) > 0) {
			assetsReady = false
			criticalErr = errors.Join(criticalErr, fmt.Errorf("authored asset target is unavailable"))
		}
		if t.assets != nil {
			removed, aerr := t.assets.ReplaceAuthored(payload.Rules.Endpoints, payload.Rules.Groups, payload.Rules.Services)
			if aerr != nil {
				assetsReady = false
				criticalErr = errors.Join(criticalErr, fmt.Errorf("authored assets: %w", aerr))
				log.Printf("config-bundle sync: the control plane's asset catalog was REFUSED, keeping the last good one: %v", aerr)
			} else if len(removed) > 0 {
				log.Printf("config-bundle sync: removed %d asset(s) the control plane does not author: %s",
					len(removed), strings.Join(removed, ", "))
			}
		}
		if assetsReady {
			incoming := payload.Rules.Rules
			if len(incoming) == 0 {
				if local := t.rules.Snapshot(); len(local) > 0 {
					log.Printf("config-bundle sync: the control plane authors NO rules; removing %d rule(s) this Edge still holds: %s", len(local), ruleIDsForLog(local))
				}
				if err := t.rules.ReplaceAll(nil); err != nil {
					log.Printf("config-bundle sync: could not clear the authored rule set: %v", err)
					criticalErr = errors.Join(criticalErr, fmt.Errorf("authored rules (clear): %w", err))
				} else if t.onRulesApplied != nil {
					t.onRulesApplied()
				}
			} else {
				// ★ NAME WHAT IS BEING REMOVED. The control plane is authoritative, so a rule this Edge holds and
				// the CP does not is deleted — including one authored locally before the CP became the authority.
				// That is correct and it is also how a cutover silently drops policy nobody migrated: on the first
				// pull, every Edge-local rule that was never copied up simply disappears. It happened here, to the
				// cert-pin bypass this fleet had adopted. Authority does not have to be quiet about what it erases.
				logRemovedByDistribution(t.rules.Snapshot(), incoming)
				// ALL-OR-NOTHING. ReplaceAll refuses the whole set if any rule is invalid, and the Edge then keeps
				// the last good one: a half-applied policy is an access posture nobody authored.
				if err := t.rules.ReplaceAll(payload.Rules.Rules); err != nil {
					log.Printf("config-bundle sync: REFUSED the control plane's authored rule set, keeping the last good one: %v", err)
					criticalErr = errors.Join(criticalErr, fmt.Errorf("authored rules: %w", err))
				} else if t.onRulesApplied != nil {
					t.onRulesApplied()
				}
			}
		}
	}
	// Route-governance decisions distributed as config: a pull-model Edge adopts the CP's configured bindings +
	// hold/adopt state without a shared governance store. Omitted/legacy empty keeps local;
	// an explicitly complete empty snapshot applies the last deletion.
	if payload.RouteGovernance != nil && connectorRouteGov != nil {
		if err := connectorRouteGov.ImportReceived(context.Background(), payload.RouteGovernance); err != nil {
			criticalErr = errors.Join(criticalErr, fmt.Errorf("route governance: %w", err))
		}
	}
	return n, criticalErr
}

// shouldApplyBundle decides whether a freshly-pulled bundle should be applied: always on the first pull;
// on a control-plane RESTART (the epoch changed) regardless of generation — its in-memory generation reset,
// so the value alone can't be trusted; otherwise only on a NEWER generation within the same epoch.
func shouldApplyBundle(haveApplied bool, lastEpoch string, lastApplied uint64, payload configBundlePayload) bool {
	if !haveApplied {
		return true
	}
	if payload.Epoch != lastEpoch {
		return true // CP restarted — re-baseline (the generation may have reset below ours)
	}
	return payload.Generation > lastApplied
}

// run pulls immediately, then every interval, applying only when the control plane's generation is newer
// than the one last applied. A failed pull keeps the last good config (fail-safe). The first successful
// pull always applies, establishing the CP's set as the Edge's baseline.
func (s configBundleSource) run(ctx context.Context, targets configApplyTargets) {
	var lastApplied uint64
	var lastEpoch string
	haveApplied := false
	pull := func(initial bool) {
		payload, err := s.fetch(ctx)
		if err != nil {
			if initial {
				log.Printf("config-bundle sync: initial pull from %s failed (keeping local config): %v", s.url, err)
			} else {
				log.Printf("config-bundle sync: pull failed (keeping config): %v", err)
			}
			s.status.recordError(err, time.Now().UTC())
			return
		}
		if !shouldApplyBundle(haveApplied, lastEpoch, lastApplied, payload) {
			// ★★★ RUNTIME FACTS RIDE EVERY POLL, BECAUSE THE VERSION DELIBERATELY DOES NOT MOVE FOR THEM
			// (2026-08-26, measured: the deployment's database knew the connector had failed over to
			// region-a, the node holding its tunnel knew, and the two Edges of the region it LEFT went on
			// saying "no live tunnel" — 0 of 10 flows to a private destination — because the fact was kept
			// out of the generation on purpose and nothing else carried it).
			//
			// Keeping it out of the generation is right: a connector flapping between regions must not move
			// the deployment's aggregate version, and a version that never settles closes every gate that
			// waits for one. But "does not move the version" cannot also mean "never arrives". The version
			// governs CONFIGURATION — what exists, what is authored, who may do what. This carries no such
			// authority: it adds nothing, removes nothing, and only says where something already in the
			// catalog is answering right now.
			applyConnectorRuntimeFacts(payload, targets)
			s.status.recordPoll(time.Now().UTC()) // already at/ahead: still a healthy, up-to-date poll
			return
		}
		if haveApplied && payload.Epoch != lastEpoch {
			log.Printf("config-bundle sync: control plane epoch changed (%q -> %q) — assuming a CP restart, re-baselining at generation %d", lastEpoch, payload.Epoch, payload.Generation)
		}
		n, aerr := s.apply(payload, targets)
		if aerr != nil {
			// Do NOT advance: this generation is retried on the next poll, and the Edge does not claim to be
			// current. Everything else in the bundle did apply — the retry re-applies it, which is idempotent.
			// ★ AND THE STATUS KEEPS THE REASON (2026-08-13, twenty-sixth review). recordPoll CLEARS lastError,
			// so the log said "knowingly behind" while the health view went back to looking like a clean poll —
			// the operator's window onto this lost the one fact that explains why the generation is not moving.
			log.Printf("config-bundle sync: generation %d is NOT applied (%v) — it will be retried; this Edge "+
				"is knowingly behind the control plane until it succeeds", payload.Generation, aerr)
			s.status.recordError(aerr, time.Now().UTC())
			return
		}
		lastApplied = payload.Generation
		lastEpoch = payload.Epoch
		haveApplied = true
		s.status.recordApplied(payload.Generation, payload.Epoch, n, time.Now().UTC())
		log.Printf("config-bundle sync: applied generation %d (%d policy(ies)) from the control plane", payload.Generation, n)
	}
	// Reported on EVERY pass, applied or not. Reporting only on change would make a healthy up-to-date Edge
	// indistinguishable from one that stopped polling — and "this Edge went quiet" is the state the incident
	// hid inside, so it has to be the one thing the view can always say.
	tell := func() {
		if s.reporter == nil {
			return
		}
		rules := 0
		if targets.rules != nil {
			rules = len(targets.rules.Snapshot())
		}
		rep := fleetConfigReport{Generation: lastApplied, Epoch: lastEpoch, HaveApplied: haveApplied, RuleCount: rules}
		// And whether this node offers a way back, with how many of its devices have not taken it. Reported
		// rather than asked for: devices meet Edges, so only an Edge can answer it — see the field's comment.
		rep.RecoveryName, rep.DevicesWithoutAWayBack = recoveryWayBackForReport()
		// And which signing authority this node serves under, for the same reason: only an Edge can say it,
		// and a deployment that has quietly become two is visible nowhere else.
		rep.PolicySigningKey = agentPolicyAuthorityForReport()
		// Answer for every standing erasure order by COUNTING now, not by remembering that we once acted. A node
		// that erased and then somehow wrote again says so; a stored flag would keep insisting it was done.
		for _, tenantID := range targets.erasureOrders.list() {
			footprint := countAdminTenantFootprint(ctx, targets.nodeName, tenantID, targets.purgeDB, targets.logWriter,
				targets.localCredentials, targets.enrolled, targets.rules, targets.deviceCAs, targets.vlan,
				// Only what this node has. The rest are named in NotCounted rather than assumed empty — a
				// footprint that omits a store it cannot reach reads as "there was nothing there".
				adminTenantExtraStores{DelegatedGrants: targets.delegatedGrants,
					DeviceIDs: tenantExtraStoresFor(adminTenantExtraStores{}, targets.enrolled, tenantID).DeviceIDs},
				time.Now())
			rep.Erasures = append(rep.Erasures, fleetTenantErasure{
				TenantID: tenantID, Clean: footprint.Clean(), Remaining: footprint.Total,
			})
			if !footprint.Clean() {
				// Residue for a tenant that was ordered erased. It is reported to the control plane either way,
				// but a node that finds data it should not have must also say so where its own operator looks.
				// The re-erasure happens on the next bundle application, or immediately via this node's purge
				// route; it is not run on every poll, because a destructive loop nobody asked for is its own risk.
				log.Printf("WARNING: this node still holds %d record(s)/file(s) for tenant %q, which was ordered ERASED. "+
					"They will go on the next config-bundle application, or now via POST /admin/tenants/%s/purge on THIS node.",
					footprint.Total, tenantID, tenantID)
			}
		}
		if s.status != nil {
			if e, _ := s.status.snapshot()["last_error"].(string); e != "" {
				rep.LastError = e
			}
		}
		if err := s.reporter.report(ctx, rep); err != nil {
			log.Printf("config-bundle sync: could not report this Edge's config status to the control plane (the fleet view will show it as silent): %v", err)
		}
	}
	pull(true)
	tell()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pull(false)
			tell()
		}
	}
}

// ruleIDsForLog renders a rule set as ids for one log line — bounded, because an operator reading "removing 400
// rules" needs the count and a sample, not four hundred ids wrapped across their terminal.
func ruleIDsForLog(rules []policyrule.Rule) string {
	const max = 12
	ids := make([]string, 0, len(rules))
	for i, r := range rules {
		if i == max {
			ids = append(ids, fmt.Sprintf("… and %d more", len(rules)-max))
			break
		}
		ids = append(ids, r.ID)
	}
	return strings.Join(ids, ", ")
}

// logRemovedByDistribution reports the rules the incoming authoritative set does NOT contain.
//
// Silence here would recreate, one level up, the defect this distribution was built to fix: the control plane
// would be right and the operator would not know what it had taken away. A cutover is the dangerous moment —
// every rule authored on an Edge before the CP became authoritative is removed by the first pull.
func logRemovedByDistribution(local, incoming []policyrule.Rule) {
	if len(local) == 0 {
		return
	}
	keep := make(map[string]bool, len(incoming))
	for _, r := range incoming {
		keep[r.TenantID+"\x00"+r.ID] = true
	}
	var gone []policyrule.Rule
	for _, r := range local {
		if !keep[r.TenantID+"\x00"+r.ID] {
			gone = append(gone, r)
		}
	}
	if len(gone) > 0 {
		log.Printf("config-bundle sync: the control plane's rule set does not contain %d rule(s) this Edge holds; they are being REMOVED: %s", len(gone), ruleIDsForLog(gone))
	}
}

// applyCarriedTenantPurges erases, on THIS node, the tenants the control plane has ordered erased.
//
// This is the only instruction in the bundle whose effect cannot be undone. Everything else here can be
// re-pushed if it was wrong; a customer's logs cannot be un-deleted. So it is gated harder than anything else
// in this file, and every refusal is loud:
//
//  1. THE BUNDLE MUST HAVE BEEN SIGNED and verified against a pinned key. Unsigned bundles are accepted for
//     policy — a lab, a bootstrap, an Edge with no key yet — and that is fine, because bad policy is
//     recoverable. Acting on an unsigned erasure order means anything that can answer the config URL can
//     destroy a customer's data.
//  2. THE TENANT MUST BE GONE FROM THE SAME PAYLOAD'S TENANT LIST. The Edge checks the deletion itself rather
//     than trusting the order: erasing a LIVE customer is the worst outcome available here, and one field
//     saying "erase" should never be enough on its own.
//  3. NOT THIS EDGE'S OWN TENANT, and not the operator tenant. An Edge erasing the tenant it is currently
//     enforcing for would take out its own operation on the strength of a remote list.
//
// Erasure is idempotent: a node that has already erased a tenant counts nothing and reports nothing, which is
// why the order can safely be carried forever. That matters more than it sounds — a node offline when the
// order was given is only ever told by a list that is still there when it returns.
func applyCarriedTenantPurges(ctx context.Context, t configApplyTargets, payload configBundlePayload, node string, now time.Time) {
	section := payload.Tenants
	if section == nil || len(section.PurgeOrders) == 0 {
		return
	}
	if !payload.signatureVerified {
		log.Printf("config-bundle sync: REFUSING %d carried tenant erasure order(s) — this bundle was not signed with a "+
			"pinned key. Unsigned config is accepted here because bad policy can be re-pushed; erased data cannot be "+
			"restored, so an erasure needs a signature. Pin a config-bundle verify key to enable fleet-wide erasure.",
			len(section.PurgeOrders))
		return
	}
	live := make(map[string]bool, len(section.Tenants))
	for _, tenant := range section.Tenants {
		live[strings.TrimSpace(tenant.TenantID)] = true
	}
	for _, order := range section.PurgeOrders {
		tenantID := strings.TrimSpace(order.TenantID)
		if tenantID == "" {
			continue
		}
		if live[tenantID] {
			log.Printf("config-bundle sync: REFUSING to erase tenant %q — the same bundle still lists it as an existing "+
				"organization. An erasure order for a live customer is a contradiction, not an instruction.", tenantID)
			continue
		}
		if strings.EqualFold(tenantID, strings.TrimSpace(t.enforcementTenantID)) {
			log.Printf("config-bundle sync: REFUSING to erase tenant %q — it is the tenant this Edge enforces for. "+
				"A node does not destroy its own operation on the strength of a remote list.", tenantID)
			continue
		}
		result := purgeAdminTenantData(ctx, node, tenantID, t.purgeDB, t.logWriter, t.localCredentials, t.enrolled, t.rules,
			t.deviceCAs, t.deviceCARegistryPath, t.deviceTrust, t.vlan,
			adminTenantExtraStores{DelegatedGrants: t.delegatedGrants,
				DeviceIDs: tenantExtraStoresFor(adminTenantExtraStores{}, t.enrolled, tenantID).DeviceIDs},
			t.legalHold, now)
		if len(result.Erased) == 0 && result.Complete {
			continue // nothing here: already erased, or this node never served the tenant. Silence is correct.
		}
		log.Printf("config-bundle sync: erased tenant %q on this node as ordered by the control plane (%s): "+
			"%d store(s) cleared, %d failure(s), complete=%v", tenantID, strings.TrimSpace(order.OrderedAt),
			len(result.Erased), len(result.Failures), result.Complete)
		for _, failure := range result.Failures {
			log.Printf("config-bundle sync: tenant %q erasure INCOMPLETE on this node: %s", tenantID, failure)
		}
	}
}
