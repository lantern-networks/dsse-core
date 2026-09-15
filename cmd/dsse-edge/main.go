package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"
	agentrollout "github.com/lantern-networks/dsse-core/agentrollout"
	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	agenttool "github.com/lantern-networks/dsse-core/agenttool"
	"github.com/lantern-networks/dsse-core/agenttuning"
	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	archive "github.com/lantern-networks/dsse-core/archive"
	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
	catalogfeed "github.com/lantern-networks/dsse-core/catalogfeed"
	certreload "github.com/lantern-networks/dsse-core/certreload"
	configversion "github.com/lantern-networks/dsse-core/configversion"
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/dns"
	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
	eastwest "github.com/lantern-networks/dsse-core/eastwest"
	eastwestobserve "github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/edgeplane"
	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	grantstore "github.com/lantern-networks/dsse-core/grantstore"
	humanapproval "github.com/lantern-networks/dsse-core/humanapproval"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
	inspection "github.com/lantern-networks/dsse-core/inspection"
	inspectionposture "github.com/lantern-networks/dsse-core/inspectionposture"
	knownbypass "github.com/lantern-networks/dsse-core/knownbypass"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
	policyrule "github.com/lantern-networks/dsse-core/policyrule"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/seatallocation"

	"github.com/lantern-networks/dsse-core/internalca"
	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"
	swg "github.com/lantern-networks/dsse-core/swg"
	tenantca "github.com/lantern-networks/dsse-core/tenantca"
	toolcallaudit "github.com/lantern-networks/dsse-core/toolcallaudit"
	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"
	"github.com/lantern-networks/dsse-core/vendorlicense"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/bundle"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/dnsech"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/objectstore"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/schema"
	sessionstore "github.com/lantern-networks/dsse-core/session"
	"github.com/lantern-networks/dsse-core/tunnel"
)

var edgeIDFallbackCounter atomic.Uint64

const (
	adminCSRFTokenKey                = "csrf_token"
	maxEdgeRuntimeJSONBodyBytes      = 1 << 20
	maxIdentitySourceImportBodyBytes = 16 << 20
	agentQualityStaleAfter           = 15 * time.Minute
)

type serverConfig struct {
	// ===================================================================================
	// DEPLOYMENT CONFIGURATION — flag-parsed values (addresses, paths, tokens, durations, toggles).
	// ===================================================================================
	// ── Listener / addresses / URLs ──
	// TransportTLSURL is the (T) address agents already hold. Carried here purely so the setup guide can state
	// remediation with the deployment's real address instead of describing one.
	TransportTLSURL     string
	MainListenAddr      string
	TransportListenAddr string
	// ── Durable paths & files ──
	// Where the "renew certificates issued before T" cutoff is kept. Durable for the same reason: a restart
	// that forgot it would strand every device that had not checked in yet.
	RenewBeforeStorePath string
	// ── PKI / interception / transport trust ──
	TransportCertFile     string
	TransportClientCAFile string
	// Carried for the same reason as TransportTLSURL: the setup guide can only give an operator a usable next
	// step if it knows what this deployment is actually configured with. Prose that says "point the Edge at a
	// signing sidecar" without saying whether one exists here, and where, is a sentence an operator still has
	// to go and research — which is the exact failure the guide is supposed to remove.
	InterceptionHSMAgentSocket string
	// The ONE signed document a device may fetch over a channel it cannot authenticate. Empty/0 = not served.
	TrustBundleCAPEM  string // transport CA anchors published in GET /bootstrap/trust-bundle
	TrustBundleSerial int64  // monotonic; devices refuse anything not advancing past the highest they accepted
	// TransportTrustStorePath enables the runtime-mutable trust set (empty = fixed at startup).
	TransportTrustStorePath string
	// TransportTrustCarriedFromPath is where this node kept the distribution BEFORE it moved into the
	// deployment's database — read once, so the move cannot restart the authority below what the fleet is
	// already serving. Empty on a deployment that never had one.
	TransportTrustCarriedFromPath string
	// TransportTrustSharedStore is that store kept in the deployment's own database rather than on this
	// node's disk. Set only where the node AUTHORS the distribution — a control plane — because the role is
	// held by different machines at different times and a serial that only goes up has to be counted from one
	// place. Enforcement Edges keep the file: what they hold is a cache of what they were given.
	TransportTrustSharedStore    blobstore.Persister
	TenantTrustDistributionStore blobstore.Persister
	TenantTrustDistributor       *tenantTrustDistributor
	DistributedTenantTrust       *tenantTrustDistributionCache
	DLPDistribution              *dlpConfigStores
	// InterceptionAnchorPEM is the certificate a DEVICE must hold for the chain this Edge presents on
	// intercepted traffic to close. See interception_announced_anchor.go — announcing the signing CA instead
	// cost a real machine its whole network on 2026-08-26.
	InterceptionAnchorPEM string

	// InterceptionPendingRootPEM is a root being distributed to endpoint trust stores but not yet used for
	// signing. Advertised to agents so they report whether they hold it, which is what turns switching the
	// interception root from a blind act into a gated one.
	InterceptionPendingRootPEM string
	// AgentPolicyNextPublicKeys are policy-signing keys devices should start accepting BEFORE one of them
	// begins signing. Published in the trust bundle; empty says nothing.
	AgentPolicyNextPublicKeys []string
	// InterceptionReparentStateDir persists a completed interception-root re-parent so adopt survives a
	// restart. Empty = live-only (reverts on restart).
	InterceptionReparentStateDir string

	// PKIOperationStorePath holds the staged-operation intent (empty = staged operations are not offered).
	PKIOperationStorePath string
	// TenantIDForTrust is the tenant every trust measurement is scoped to — this Edge's own tenant. Carried
	// on the config because the admission guard runs where the evaluator is not in scope.
	TenantIDForTrust string
	// TrustBundleCAPath is WHERE the anchors are read from. Adding or withdrawing one is a deployment change —
	// there is no runtime route — so an operator needs the actual path and serial in front of them, not a
	// description of a file they then have to go and locate.
	TrustBundleCAPath string
	// Where a device recovers from once its certificate has expired. Carried in the bundle so a device that has
	// never received a snapshot still learns it; may name only a port, the host coming from the transport.
	TrustBundleRecoveryEndpoint string
	// ── Enrolment / device identity ──
	EnrollToken string // M4c: shared eligibility token POST /enroll accepts
	// Recovery listener settings, carried so the readiness assessment can report whether a device that expired
	// while switched off can come back on its own.
	EnrollRenewGraceListen string
	DeviceIssuingCAFile    string
	// Where an operator's "this identity holds that anchor" assertions are kept.
	TransportAnchorAckStorePath string
	// TransportAnchorAckSharedStore keeps those assertions in the deployment's database instead of on this
	// node's disk. Set only where the node authors — the assertions decide withdrawals, and the node that
	// judges one is whichever control plane leads at that moment.
	TransportAnchorAckSharedStore blobstore.Persister
	EnrolmentTokenStoreMode       string
	EnrolmentTokenMaxLifetime     time.Duration
	EnrolmentTokenMaxOutstanding  int
	EnrollRenewGraceWindow        time.Duration
	EnrollDefaultGroup            string        // M4c: device group the CP assigns at enrollment
	EnrollCertTTL                 time.Duration // M4c: issued device cert validity
	// ── Enrolment / licensing ──
	LicenseAcceptedKeys          []*ecdsa.PublicKey
	LicenseMSSPID                string
	LicenseAllowOversubscription bool
	// ── Policy / decision / catalog ──
	// VLANObjectStorePath persists the Named Networks (VLAN objects) + boundary policies so the Networks
	// catalog survives an Edge restart (it was in-memory only, so a rebuild emptied it). Empty = in-memory.
	// See docs/unified_network_object_design.md.
	VLANObjectStorePath string
	// Where the operator-authored DNS policy is kept, so it outlives the process. Without it a DNS rule
	// written through the admin API is reverted by the next restart.
	DNSPolicyStorePath string
	ObservedKnownFloor []string // known-floor allowlist (exact or `prefix*`): effective entries matching these are "floor", not flagged as unmanaged anomalies
	// ApplicationCatalogStorePath: when set, this lazily-constructed store persists to the given JSON file so
	// operator-authored applications survive a restart. Empty = in-memory only (the prior default, where they
	// vanished on restart).
	ApplicationCatalogStorePath string
	// ApplyMaterializedCertPinBypass, when set, rebuilds the interception engine's decrypt-bypass set
	// from the static bypass list + every materialized cert-pinning candidate for the tenant. The
	// materialize handler calls it so an approved+materialized candidate is actually raw-forwarded
	// (not just status-flipped). nil = no interception engine wired (e.g. headless control plane).
	ApplyMaterializedCertPinBypass func(tenantID string)
	// ── DLP ──
	// DLPClassifierStorePath persists operator-defined custom DLP classifiers so they survive an Edge restart.
	// Empty = in-memory only. "postgres" (needs -postgres-dsn) or a file path.
	DLPClassifierStorePath string
	// DLPAllowlistStorePath persists the operator-declared known-safe DLP values (false-positive tuning) so they
	// survive an Edge restart. Empty = in-memory only. "postgres" (needs -postgres-dsn) or a file path.
	DLPAllowlistStorePath string
	// DLPFingerprintStorePath persists operator EDM datasets (salted hashes only) so they survive an Edge restart.
	// Empty = in-memory only. "postgres" (needs -postgres-dsn) or a file path.
	DLPFingerprintStorePath string
	// DLPPolicyObjectStorePath persists the reusable named DLP Policy objects (S5) across a restart.
	DLPPolicyObjectStorePath string
	// EntitlementStorePath persists per-tenant feature entitlements (the license gate) across a restart.
	EntitlementStorePath string
	// DLPRequiresLicense gates DLP behind a per-tenant license. Zero value (false) = DLP entitled by default
	// (backward compatible / lab). Set true (production paid-feature deployment) to default DLP OFF until a tenant
	// is explicitly licensed via /admin/entitlements.
	DLPRequiresLicense bool
	// DLPBlockUninspectableFiles (-dlp-block-uninspectable-files, default false): under an interrupting DLP
	// rule, a file upload whose text cannot be extracted (encrypted/corrupt container) is BLOCKED instead of
	// forwarded uninspected — closes the corrupt-container DLP bypass at the cost of blocking broken-but-benign
	// uploads.
	DLPBlockUninspectableFiles bool
	// ── SWG / egress / inspection ──
	// InspectionEventsStorePath persists inspection events — notably the DLP findings — so the DLP Findings view
	// survives an Edge restart. Empty = in-memory only. "postgres" (needs -postgres-dsn) or a file path.
	InspectionEventsStorePath string
	// ApplyInspectionPosture, when set, re-applies BOTH inspection layers from the live posture + authored rules:
	// the intercept (decrypt) set — under bypass-default the posture allowlist UNIONED with authored `inspect`
	// egress rules — and the decrypt-bypass set (it folds in ApplyMaterializedCertPinBypass). The rule-change hook
	// calls it so authoring an inspect/bypass rule re-applies the engine sets. nil = no interception engine wired.
	ApplyInspectionPosture func(tenantID string)
	// InspectionPosture / SetInspectionPosture read and change the persisted inspection posture (deployment mode
	// decrypt_all|bypass_default + decrypt allowlist + known-bypass toggle) at runtime (GET/POST
	// /admin/inspection-posture). SetInspectionPosture persists it and re-applies the engine's intercept + bypass
	// sets. nil = no interception engine wired (read reports the default posture; write is rejected).
	InspectionPosture func() inspectionposture.Posture
	// SetInspectionPosture applies + persists the posture. A non-nil error means the posture IS live in the
	// engine but was not persisted (it would revert on restart) — handlers surface it to the admin.
	SetInspectionPosture func(p inspectionposture.Posture, tenantID string) (inspectionposture.Posture, error)
	// InspectionPostureGeneration is the posture store's contribution to the config bundle's aggregate
	// generation. Without it a posture change alters the bundle's contents and not its version, so no Edge
	// re-pulls — see config_bundle_inspection_posture.go.
	InspectionPostureGeneration func() uint64
	// FleetIdentityClaimer is the one place the deployment takes the one-time claim on a device identity.
	//
	// ★ HELD BY THE AUTHORITY, NOT BY THE ISSUER (2026-08-23, measured). It used to be built only inside the
	// branch for a node that ISSUES certificates, so the control plane — which does not — had none, and the
	// routes an Edge asks on answered 404. The authority for a one-time decision does not have to be a party
	// to it.
	FleetIdentityClaimer enrolledinventory.IdentityClaimer
	// StripAltSvc (default true via the -strip-alt-svc flag) drops the Alt-Svc response header on
	// intercepted flows so clients stay on the inspectable TCP path instead of switching to HTTP/3 (QUIC).
	StripAltSvc bool
	// SWGEgressBrowserMimic (opt-in via -swg-egress-browser-mimic, default false) re-originates the device
	// decrypt-all upstream through the egress broker's real Chrome network stack (curl-impersonate) so
	// bot-mitigation (AWS WAF / Akamai / Cloudflare) treats it as a real browser instead of Go. Device path
	// only, and it REQUIRES a reachable broker (EGRESS_BROKER_URL) — there is no in-process fallback engine.
	SWGEgressBrowserMimic bool
	// ── Connector / mesh / multi-region ──
	// The certificate-map inventory (GET /admin/pki/certificates) states where each certificate is used from
	// this node's own configuration; these carry the listener addresses and material paths it needs, because
	// the admin routes are registered in a different scope than the one that parses the flags.
	RegionEndpointURLs            []string
	ConnectorSecret               string
	RequireConnectorRuntimeSecret bool
	MeshEligible                  func(string) bool // destinations that opt into inter-region MESH (vs hairpin default); nil = none
	MeshSecret                    string            // shared secret required on the inbound /mesh/ingress/tunnel link (empty = no check, lab)
	MeshIngressAllowedPeers       map[string]bool   // authorized peer-edge mTLS identities allowed on the mesh + revocation-mesh INGRESS. Non-empty = mTLS-only allowlist (secret fallback disabled). Empty = lab fallback. Closes the "any enrolled cert is accepted" gap ( receiver auth).
	RevocationMeshSecret          string            // shared secret required on the inbound /revocation-mesh/admission push (empty = no check, lab)
	MeshPeerSpec                  string
	// ConnectorEnrollmentEdgeURL / ConnectorEnrollmentStateDir (S4 connector bootstrap) are folded into the
	// one-time enrollment token / rendered command so "Add connector" emits one self-contained command. Empty =
	// edge_url comes from the request body; state dir defaults to /var/lib/dsse-connector.
	ConnectorEnrollmentEdgeURL string
	// LogDir is where this node writes the CANONICAL jsonl. Carried so /healthz can report it: the
	// architecture makes this log the original and the shipment to the control plane the copy, and a relative
	// path resolves inside a container's writable layer, where it dies with the container.
	LogDir                       string
	ConnectorEnrollmentStateDir  string
	ConnectorEnrollmentEdgeCAPEM string
	// ── East-West / NHI / identity ──
	WorkloadAttestationSecret string
	ClientlessAccessEnabled   bool // opt-in. When false (default) the PUBLIC clientless web front door is 404 (no pre-auth web attack surface).
	// ClientlessBaseURL (when non-empty) enables the clientless federated-auth broker and is the RP base for
	// the OIDC redirect_uri. GrantStorePath persists the minted grants.
	ClientlessBaseURL string

	// ClientlessTLSCert/Key are the certificate a browser validates at the step-up portal. Not minted here:
	// the portal is a browser-facing page and its name is one the operator holds.
	ClientlessTLSCert string
	ClientlessTLSKey  string

	// StepUpPortalCertificateIsOperators says the portal is served on a certificate the operator provided —
	// in production, one the world already trusts. It travels in every device profile, because it decides
	// whether a device has to trust anything extra to complete a step-up. See installprofile.DeploymentSpec.
	StepUpPortalCertificateIsOperators bool

	// StepUpBindingSecret is the deployment-wide secret the step-up start URL is signed with. Shared by every
	// Edge, because the Edge that issues a step-up URL is rarely the one that receives it.
	StepUpBindingSecret string
	GrantStorePath      string
	// Durable JSON snapshot paths for the east-west authorization stores. Empty = in-memory only (volatile).
	// When set, the store rehydrates on boot and write-throughs each mutation so in-flight grants / approval
	// outcomes / break-glass requests survive a control-plane restart.
	DelegatedGrantStorePath string
	HumanApprovalStorePath  string
	// EastWestObserveStorePath persists the East-West Observe inventory (learned lateral flows) so it survives a
	// restart. Empty = in-memory only. "postgres" (needs -postgres-dsn) or a file path.
	EastWestObserveStorePath string
	// ── Admin plane ──
	AdminListenAddr            string
	DisableEmbeddedOutboxAdmin bool   // audit/persistence decoupling: when true, do NOT register the /admin/(audit|domain-event)-outbox/* endpoints (durable outbox delivery is the control plane's job). Zero value (false) keeps them registered so existing callers/tests are unchanged; the production binary sets this true by default.
	AuditIngestReceiverToken   string // audit/persistence decoupling: when set (control plane), register POST /audit-ingest (bearer-authed) to receive + persist audit/events shipped by enforcement Edges.
	// AuditShipHealth reports whether what this node records is reaching the authority. nil = this node was
	// never told where to ship, which /healthz reports as absent rather than as healthy.
	AuditShipHealth    func(time.Time) map[string]any
	AdminConsoleOrigin string // separate-host Admin Console origin; used as the post-login redirect target after the IdP callback
	// AdminConsoleOrigins is every address the Console answers on, for the profile's never-steer list. See the
	// flag for why it is stated rather than derived from the region catalogue.
	AdminConsoleOrigins string

	// Endpoints of the TLS paths this node DIALS but does not own the certificate for. They are carried only
	// so the paths view can list them: a registry that silently omits the IdP, the mesh and the stores tells an
	// operator every path is accounted for when eight are not (review C8). Marked externally managed there.
	IdPIssuerURL             string
	HotStoreEndpoint         string
	ColdArchiveEndpoint      string
	AdminInviteEmailSinkPath string // lab email sink: activation messages are appended here (no SMTP)
	// IdPConnectionStorePath: when set, the per-tenant end-user IdP registry persists to this JSON file so
	// registered IdP connections + the default survive a restart. Empty = in-memory only.
	IdPConnectionStorePath string
	// OrganizationDomainsStorePath persists the organization ("our company") domains (S6) across a restart.
	OrganizationDomainsStorePath string
	BreakGlassStorePath          string
	// OperatorTenantID (multi-tenant Admin Console Q5) names the SSE operator's own tenant (-operator-tenant-id).
	// "" = feature off (lab default): no operator tenant, DELETE /admin/tenants accepts any id, IsOperator false.
	// When set, DELETE refuses to remove this tenant (lockout protection); the store seeds/stamps it.
	OperatorTenantID string
	AdminToken       string
	// ── Agent lifecycle / telemetry ──
	AgentTuningScoped   []agenttuning.ScopedTuning // M7 group-scoped captive tuning served signed via GET /steer/agent-tuning (nil = none)
	AgentTargetVersion  string
	AgentReleaseChannel string
	// ── Config distribution & lifecycle ──
	// ConfigSourceURL is the control-plane base this Edge PULLS its config bundle from (the -config-source-url
	// value), or "" when this Edge is authoritative-local. When set, write endpoints for the bundle-distributed
	// config resources are rejected (Phase 1 write-path inversion, design/ 1c): config is authored on the
	// control plane, not a puller Edge — "no node-local source of truth".
	ConfigSourceURL string
	// SteerExclusionSourceURL is the control-plane base this Edge PULLS its steer exclusions from
	// (-steer-exclusion-source-url). Separate from ConfigSourceURL because the two syncs are separate: an Edge
	// can pull exclusions without pulling the config bundle. A write accepted HERE while this is set is erased
	// by the next poll, so the write endpoints refuse it instead — see configWriteRejectedWhenSourced.
	SteerExclusionSourceURL string

	// ===================================================================================
	// INJECTED RUNTIME DEPENDENCIES — live collaborators wired in by the caller (stores, signers, the evaluator, monitors). withDefaults fills the ones a standalone/test run omits.
	// ===================================================================================
	// ── PKI / interception / transport trust ──
	// KeyCustodyMonitor drives /healthz readiness: when the interception signing key cannot sign, this node
	// can no longer intercept any hostname it has not already cached, so the balancer must route NEW flows
	// elsewhere. nil = no monitoring (readiness unaffected).
	KeyCustodyMonitor *edgeplane.KeyCustodyMonitor
	// SecondaryKeyCustodyMonitors functionally probe the online signing keys that are NOT on the traffic path
	// (device-CA, agent-policy). They log/surface a per-key fault but, unlike KeyCustodyMonitor, do NOT gate
	// /healthz — an enrolment-key fault must not drain the traffic node.
	SecondaryKeyCustodyMonitors []*edgeplane.SecondaryKeyCustodyMonitor
	TrustedKeyring              model.TrustedKeyring
	AgentPolicySigner           *agentpolicy.Signer // Ed25519 signer for GET /steer/agent-policy (nil = unsigned)
	// PublishedUpdates are the signed agent-update manifests this edge RELAYS (never signs — see
	// steer_agent_update_routes.go). Nil = nothing published, which devices read as the normal quiet state.
	PublishedUpdates *publishedUpdates
	// AgentUpdateArtifactDir is where the .pkg/.msi named by those manifests lives. Same directory as the
	// manifests by default: a release is one thing, and splitting its two halves across two paths is how one of
	// them gets forgotten.
	AgentUpdateArtifactDir string

	// ConnectorProgramDir is where the programs a customer runs on the machine inside their network are held,
	// so "Add connector" can hand over the program beside the profile. See admin_connector_program.go.
	//
	// ★ IT DEFAULTS UNDER -state-dir ON PURPOSE. A lane that needs a flag of its own is a lane the installer
	// does not set, and a feature nothing sets is dark on every generated deployment — which is how the
	// connector installer itself came to exist in a tree that built it nowhere.
	ConnectorProgramDir string

	// PullsAgentUpdates is whether THIS process takes its published releases from a control plane
	// (-agent-update-source-url). It is what decides whether publishing here is authoring or a write that will
	// be overwritten by the next poll.
	//
	// ★ IT USED TO BE THE ROLLOUT CACHE (2026-08-12, sixth review), which is a DIFFERENT flag. An Edge that
	// pulled updates but not the halt accepted a local publish with 200 — into a store the device-facing route
	// does not read, overwritten on the next pull, so the operator saw success and the fleet saw nothing. An
	// Edge that pulled the halt but authored its own releases had legitimate publishing refused. Two settings
	// that answer different questions must not share one answer.
	PullsAgentUpdates bool
	// PublishedAgentUpdateStore is the control plane's durable set of published release manifests. Nil on an
	// enforcing edge, which pulls instead of owning.
	PublishedAgentUpdateStore *publishedAgentUpdateStore
	// AgentUpdatePins are the update-signing keys this process verifies published manifests against — on the
	// control plane before storing one, and on an edge before relaying one. Both, deliberately: an edge that
	// trusted the channel would let a compromised control plane choose what its fleet runs.
	AgentUpdatePins []string
	// AgentUpdatePublisher is the signing identity a device requires of any package it installs — an Apple
	// Team ID on macOS, its counterpart on Windows. Carried on the config because the install profile states
	// it: an endpoint refuses to install without one, and nothing else on the device knows it.
	AgentUpdatePublisher string
	// AgentUpdateSigner mints update manifests server-side (POST /admin/agent-updates), through a PKCS#11 token.
	// Nil = this process holds no update-signing key and that endpoint refuses; publishing an envelope signed
	// elsewhere still works.
	AgentUpdateSigner *agentpolicy.Signer
	// AgentUpdateSignFloor refuses to sign a version older than one already signed for the same target. Nil
	// means no floor is enforced, which is only correct for tests.
	AgentUpdateSignFloor *agentUpdateSignRatchet
	// AgentRolloutPlans is the control plane's durable halt store. Nil means a volatile one is created — only
	// correct for tests.
	AgentRolloutPlans *agentrollout.AgentRolloutStore
	// AgentRolloutCache is the control plane's answer, pulled by an enforcing Edge. Nil means this process has
	// no control plane to pull from and the file is the authority (the lab, and single-node installs).
	AgentRolloutCache *agentRolloutCache
	// RolloutControlPath is the operator-authored wave schedule and freeze, read fresh per request so a halt
	// takes effect without restarting this process. Empty = no waves and no freeze.
	RolloutControlPath     string
	NetworkExtensionLabTLS *edgeplane.NetworkExtensionLabTLSInterception
	// DeploymentInterceptionRootPEM is the deployment's interception root as a certificate only, for a node
	// that names it in profiles and signs nothing with it. See -deployment-interception-root-cert.
	DeploymentInterceptionRootPEM string
	// ── Enrolment / device identity ──
	AdmissionRevocations *revocation.AdmissionRevocations // W-2/W-7 (T) admission revocation overlay (nil = feature off)
	EnrolledLedger       *enrolledinventory.Ledger        // admin-managed Enrolled Inventory (nil = admin endpoints 503)
	EnrollSigner         *deviceca.Signer                 // M4c device-identity CA signer (nil = POST /enroll disabled)
	// EnrolmentTokens is the admin-issued, one-time, per-device credential that REPLACES EnrollToken: it proves a
	// machine an administrator approved, works once, expires, and records which admin authorised which device.
	EnrolmentTokens      enrolltoken.Authority
	EnrolmentTokenPolicy enrolltoken.Policy
	// IdP-backed enrolment eligibility. nil = only the shared token is accepted. Resolved per request so an
	// operator can add, repoint or REMOVE the connection in the Console without restarting the Edge — a
	// connection that is taken away stops being accepted immediately rather than at the next restart.
	EnrollIdPEligibility *idpEnrollmentEligibility
	// EnrolmentCPReporter tells the control plane about enrolments completed on this Edge. Nil on an Edge
	// with no control plane, where the local ledger IS the authority and there is nobody to tell.
	EnrolmentCPReporter *enrolmentCPReporter
	// DirectoryCPReporter carries a connector-driven directory import to the control plane. Same reason as the
	// enrolment reporter above: a connector reaches the Edge and nothing else, so what lands here has to be
	// carried or the authority never learns about it.
	DirectoryCPReporter *directoryCPReporter
	DeviceStore         deviceRuntimeStore
	// ── Enrolment / licensing ──
	SeatAllocations *seatallocation.Store
	// Licensing reaches the admin routes through config for the same reason every other store does: the routes
	// are registered in a different scope than the one that builds them.
	VendorLicense       *licenseStore
	LicenseRecipientKey *ecdh.PrivateKey
	EnrolmentLicensing  *enrolmentLicensing
	// ── Policy / decision / catalog ──
	Evaluator       decision.Evaluator
	DNSConntrack    *dns.ConntrackStore         // shared DNS resolution conntrack (IP->FQDN recovery); nil = newServerWithConfig creates its own (tests/standalone)
	HighRiskOverlay *revocation.HighRiskOverlay // Phase 3 shared high-risk device overlay (nil = feature off)
	SessionStore    *sessionstore.Store
	RouteProfiles   map[string]edgeplane.ApplicationRouteProfile
	SteerExclusions *steerexclusion.Store // admin-managed steer exclusions (per tenant/device-group/device)

	// InternalCAs holds the authorities each organization vouches for when an Edge verifies one of that
	// organization's PRIVATE assets after decrypting the flow to it. An interface, not the concrete store:
	// asking for a concrete type here is how three data paths in one day were turned off silently the moment
	// the store was swapped for the durable one — the code still compiled and the feature was simply gone.
	InternalCAs             organizationInternalCAPool
	ObservedExclusions      observedExclusionStoreAPI // reverse telemetry: each device's self-reported effective exclusion set (G2 visibility; observability only)
	SteerPosture            steerPostureConfig        // CP-controlled steering posture served signed at GET /steer/agent-policy/posture (Phase 3)
	DecisionStore           *accessdecision.Store
	PolicyStore             policy.RuntimeStore
	ApplicationCatalogStore appcatalog.RuntimeStore
	PolicyCandidateStore    policycandidate.RuntimeStore
	CatalogOverrides        *knownbypass.OverrideStore // per-tenant predefined-catalog overrides (nil = catalog admin endpoints 503)
	CatalogFeed             *catalogfeed.Store         // signed predefined-catalog feed (nil = built-in default only; no feed admin)
	// AssetStore / RuleStore hold the endpoint/group/service catalog and the unified authored rules (model +
	// storage in dsse-core). main creates them so the decrypt-bypass rebuild can include authored egress
	// bypass rules, and passes the same instances here so the admin APIs read/write them. nil = the server
	// creates empty in-process stores (tests / headless).
	AssetStore *assetcatalog.Store
	RuleStore  *policyrule.Store
	// ── SWG / egress / inspection ──
	SWGRuntime       swg.RuntimeConfig
	InspectionEvents *inspection.Store
	// ── Connector / mesh / multi-region ──
	// TransportConnRegistry tracks live (T) sessions so an EXPLICIT ADMIN block can tear them down. Only the
	// admin revoke handler may call it — never an automatic revocation path. nil = teardown unavailable
	// (admission still denies new handshakes).
	TransportConnRegistry *transportConnRegistry
	Registry              connectorRegistryStore
	ProxyClient           *http.Client
	TunnelManager         *tunnel.Manager
	PeerEdges             edgeplane.PeerEdgeProvider // inter-region MESH links (region -> sibling-edge session); nil = mesh fails closed
	// RegionEndpoints is the BOOT value of the class-1 region map. Read it through regionMap.Catalog()
	// instead — the live one is replaced by the control plane's on every applied bundle, and a reader that
	// captures this field sees whatever the command line said at start-up for ever.
	RegionEndpoints           *regionEndpointCatalog
	NetworkExtensionPublisher networkExtensionSnapshotPublisher
	// SiteStore (Connector UX Slice 1b) is the persistent Site / Connector Group catalog (tenant-scoped). nil =
	// the server creates an empty in-memory store, which keeps GET /admin/sites identical to the Slice 1 projection
	// (lab invariant). A file path or "postgres" backend is wired from -site-store.
	SiteStore adminSiteStore

	// tenant isolation: when the Edge is configured with a per-tenant CA registry, the data-plane
	// decision path binds the AUTHORITATIVE tenant (resolved from the verified mTLS issuing CA) onto each
	// decision instead of trusting a client-claimed tenant_id. nil = single-tenant/lab (client-supplied
	// tenant kept). Same registry the (T) admission gate uses.
	TenantCARegistry *tenantca.TenantCARegistry
	// TenantTransportMaterialFromCP records that this node gets each organization's transport material from
	// the control plane rather than from files a person placed on it.
	//
	// ★★★ ONLY SUCH A NODE MAY SHRINK THE FLEET'S ANNOUNCEMENT (2026-08-20, measured). region-a and region-b
	// share one trust store, and only region-a fetches from the control plane. So region-a announced each
	// organization's new authority, region-b recomputed the announcement from what IT holds, dropped them, and
	// advanced the serial — and region-a added them back on its next pass. The two anchors flapped in and out
	// of the signed distribution, the serial climbed two per restart, and the adoption measurement that gates
	// roadmap D's withdrawal could never accumulate: every advance invalidates the evidence below it.
	//
	// A node that is not on the material path cannot tell "this organization has no second authority" from "I
	// was never given it". That is the same rule this repository applies to every other withdrawal: absence of
	// knowledge is not a withdrawal. Such a node may ADD to the announcement and may never remove from it.
	TenantTransportMaterialFromCP bool
	// RenewalRecoverySNI is announced to agents as the name that will reach the expired-certificate renewal
	// path on the main port (the fold's first step). It changes no listener.
	RenewalRecoverySNI string
	// TenantTransportAuthority is set on a CONTROL PLANE: each organization's transport CA, from which
	// short-lived server material is issued to the Edges that must serve that organization's name.
	TenantTransportAuthority *tenantTransportAuthority
	// TenantTransportMaterialTTL is how long that material lives. Short: the fleet is autoscaled.
	TenantTransportMaterialTTL time.Duration
	// TenantInterceptionAuthority is the same idea for interception: the authority an organization signed FOR
	// the operator, from which each Edge is handed a per-Edge tier that expires. The organization's ROOT is
	// not here and never is — it is what their devices trust.
	TenantInterceptionAuthority *tenantInterceptionAuthority
	TenantDeviceAuthority       *tenantDeviceAuthority
	// TenantCARegistryPath is where that registry is written back to. Empty means a CA registered through the
	// admin API is live but NOT durable — the API says so rather than reporting a clean success.
	TenantCARegistryPath string
	// ── East-West / NHI / identity ──
	HumanApprovals          *humanapproval.Store
	DelegatedGrants         *delegatedgrant.Store
	NonHumanIdentities      nhi.RuntimeStore
	EastWestObserveStore    *eastwestobserve.Store // S1 (Observe): east-west lateral-flow inventory (nil = feature off)
	AgentToolStore          agenttool.RuntimeStore
	EndpointInventoryStore  endpointinventory.RuntimeStore
	ToolCallEventAuditStore toolcallaudit.RuntimeStore
	UsageMeters             usagemeter.UsageMeterRuntimeStore
	HumanIdentities         humanidentity.HumanIdentityDirectoryRuntimeStore
	WorkloadAttestations    runtimeWorkloadAttestationNonceStore
	// ── Admin plane ──
	LegalHold           *legalHoldStore         // litigation/e-discovery holds (shared with the retention pruner; nil = none)
	ColdArchive         archive.ColdArchive     // sovereign cold-archive backend (for the audit-chain verify API; nil = none)
	RetentionOverride   *retentionOverrideStore // admin-configurable per-stream retention (shared with the pruner; nil = flags only)
	Writer              *logs.Writer
	ExportObjectStore   adminExportObjectStore
	OIDC                oidcConfig
	LocalCredentials    *localAdminCredentialStore // first-party admin accounts (nil = feature off): invite -> activation link -> password + TOTP -> email+password+TOTP login
	BreakGlassRequests  *breakGlassRequestStore
	DomainEventOutbox   domainEventOutboxWriter
	DomainEventMirror   *domainEventOutboxMirrorMonitor
	AdminExportJobs     adminExportJobAdminStore
	AdminExportWorker   adminExportWorker
	AdminDownloadTokens *adminDownloadTokenStore
	AdminAuditOutbox    adminAuditOutboxDeadReader
	AdminAuth           adminAuthRuntimeStore
	TenantModelStore    adminTenantModelRuntimeStore
	HotStore            hotstore.Store
	HotStoreMirror      *hotStoreAppendMirrorMonitor
	// ── Agent lifecycle / telemetry ──
	AgentTelemetry agenttelemetry.RuntimeStore
	// ── Config distribution & lifecycle ──
	ConfigVersions configversion.Store    // versioning + rollback of admin config (nil = disabled; CP only)
	CPVersions     *cpConfigVersionClient // zero-DB Edge → CP client to ship/read config versions (nil = none)
	LabMode        *bool
	// ConfigSyncStatus (Phase 1 config distribution) is the config-bundle puller's observable state; nil when
	// this Edge is authoritative-local. Exposed via GET /admin/config-sync-status and /healthz.
	ConfigSyncStatus *configBundleSyncStatus
	// RevocationSyncStatus is the FAST revocation poller's observable state; nil when CP→Edge sync is off. It is
	// REPORTED on /healthz and never drains the node — see the handler for why.
	RevocationSyncStatus *revocationSyncStatus
	// ConfigBundleSource (nil unless -config-source-url is set) is the puller; its poll loop is launched inside
	// newServerWithConfig so a pull can apply policies + tenant-config (policy.Store) AND the DNS policy
	// (the separate dnsresolver.Resolver store) together.
	ConfigBundleSource *configBundleSource
	// FleetConfigStatus is the control plane's record of what each Edge reports it is running. nil on an Edge
	// (it reports, it does not aggregate).
	FleetConfigStatus *fleetConfigStatusStore
	// DrainState (Phase 4 graceful drain) is flipped true on SIGTERM; /healthz then reports 503 so the LB
	// drains this Edge before it shuts down. nil = drain feature off (healthz always ok).
	DrainState *atomic.Bool
}

type deviceRuntimeStore interface {
	Register(model.Device, model.PolicyBundle, time.Time) (model.Device, error)
	Heartbeat(model.DeviceHeartbeat, model.PolicyBundle, time.Time) (model.Device, error)
	Get(string) (model.Device, bool)
	List() []model.Device
}

type deviceTenantReader interface {
	ListByTenant(string) ([]model.Device, error)
}

type deviceTenantGetter interface {
	GetByTenant(tenantID, deviceID string) (model.Device, bool, error)
}

var _ adminAuthRuntimeStore = (*adminAuthStore)(nil)

var _ adminExportTaskQueue = (*localAdminExportTaskQueue)(nil)

func (config serverConfig) withDefaults() serverConfig {
	if config.LabMode == nil {
		// In-process tests and legacy lab harnesses construct serverConfig
		// directly. The real binary always passes the explicit --lab-mode flag.
		config.LabMode = boolPtr(true)
	}
	if config.Registry == nil {
		config.Registry = connector.NewRegistry()
	}
	if config.ProxyClient == nil {
		config.ProxyClient = http.DefaultClient
	}
	if config.ConnectorSecret == "" {
		config.ConnectorSecret = defaultConnectorSecret
	}
	if config.TunnelManager == nil {
		config.TunnelManager = tunnel.NewManager()
	}
	if config.SessionStore == nil {
		config.SessionStore = sessionstore.NewStore()
	}
	if config.DeviceStore == nil {
		config.DeviceStore = devicestore.NewStore()
	}
	if config.BreakGlassRequests == nil {
		config.BreakGlassRequests = newBreakGlassRequestStore()
	}
	if err := config.BreakGlassRequests.SetPersister(mustCPStateBlobPersister(config.BreakGlassStorePath, "break_glass")); err != nil {
		log.Fatalf("load break-glass request store %q: %v", config.BreakGlassStorePath, err)
	}
	if config.HumanApprovals == nil {
		config.HumanApprovals = newHumanApprovalEventStore()
	}
	if p, e := cpStateBlobPersister(config.HumanApprovalStorePath, cpStateBlobDB, "human_approvals"); e != nil {
		log.Fatalf("resolve human-approval event store: %v", e)
	} else if err := config.HumanApprovals.SetPersister(p); err != nil {
		log.Fatalf("load human-approval event store %q: %v", config.HumanApprovalStorePath, err)
	}
	if config.DelegatedGrants == nil {
		config.DelegatedGrants = newDelegatedAccessGrantStore()
	}
	if p, e := cpStateBlobPersister(config.DelegatedGrantStorePath, cpStateBlobDB, "delegated_grants"); e != nil {
		log.Fatalf("resolve delegated-grant store: %v", e)
	} else if err := config.DelegatedGrants.SetPersister(p); err != nil {
		log.Fatalf("load delegated-grant store %q: %v", config.DelegatedGrantStorePath, err)
	}
	if config.NonHumanIdentities == nil {
		config.NonHumanIdentities = nhi.NewStore()
	}
	if config.DecisionStore == nil {
		config.DecisionStore = newAccessDecisionStore()
	}
	if config.InspectionEvents == nil {
		config.InspectionEvents = newInspectionEventStore()
	}
	// Durable inspection events (optional): rehydrate on boot + flush periodically so the DLP Findings view
	// survives an Edge restart (without this, every restart wipes the detection history). 90-day retention;
	// Upsert only marks dirty, so a background ticker does the I/O off the hot path.
	if storeShouldBeWired(config.InspectionEventsStorePath) {
		if p, e := cpStateBlobPersister(config.InspectionEventsStorePath, cpStateBlobDB, "inspection_events"); e != nil {
			log.Fatalf("resolve inspection events store %q: %v", config.InspectionEventsStorePath, e)
		} else if p != nil {
			if lerr := config.InspectionEvents.SetPersister(p, 90*24*time.Hour); lerr != nil {
				log.Printf("inspection events store: load prior findings failed (starting fresh): %v", lerr)
			}
			store := config.InspectionEvents
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := store.PersistIfDirty(); err != nil {
						log.Printf("inspection events store: persist failed: %v", err)
					}
				}
			}()
		}
	}
	if config.AdminExportJobs == nil {
		config.AdminExportJobs = newAdminExportJobStore()
	}
	if config.AdminExportWorker == nil {
		config.AdminExportWorker = synchronousAdminExportWorker{}
	}
	if config.AdminDownloadTokens == nil {
		config.AdminDownloadTokens = newAdminDownloadTokenStore()
	}
	// ★ Outstanding download links belong to the FLEET, not to the node that minted them (2026-08-21). See
	// adminDownloadToken.Payload for the measurement. Nothing changes without a shared database.
	if cpStateBlobDB != nil {
		sharedBackend := "postgres"
		if p, e := cpStateBlobPersister(sharedBackend, cpStateBlobDB, "export_download_tokens"); e != nil {
			log.Printf("export download tokens: %v — links will only work on the node that minted them", e)
		} else if serr := config.AdminDownloadTokens.SetPersister(p); serr != nil {
			log.Printf("export download tokens: could not read the fleet's outstanding links (%v)", serr)
		}
	}
	if config.ExportObjectStore == nil && config.Writer != nil {
		if localStore, err := objectstore.NewLocalStore(config.Writer.Dir()); err == nil {
			config.ExportObjectStore = localStore
		} else {
			config.ExportObjectStore = config.Writer
		}
	}
	if config.AdminAuth == nil {
		config.AdminAuth = newAdminAuthStore()
	}
	if config.PolicyStore == nil {
		config.PolicyStore = policy.NewStore(config.Evaluator.Policies)
	}
	if config.ApplicationCatalogStore == nil {
		appStore := newAdminApplicationCatalogStore(config.Evaluator.PolicyBundle.TenantID, config.RouteProfiles, config.Evaluator.PolicyBundle.SaaSCatalog)
		// SetStatePath AFTER the config seed so persisted operator apps/edits overlay (and survive) the seed.
		if err := appStore.SetStatePath(config.ApplicationCatalogStorePath); err != nil {
			log.Fatalf("load application catalog store: %v", err)
		}
		config.ApplicationCatalogStore = appStore
	}
	if config.EastWestObserveStore == nil {
		// S1 (Observe): record the lateral flows the tenant sees so an operator can review + adopt them (S2) and
		// watch the inventory converge before disabling Allow-all (S5). Recording only, no enforcement.
		config.EastWestObserveStore = eastwestobserve.NewStore()
		// Durable inventory (optional): rehydrate on boot + flush periodically so learned flows survive an Edge
		// restart (without this, every restart resets the convergence signal). 90-day retention; Observe only
		// marks dirty, so a background ticker does the I/O off the hot path.
		if storeShouldBeWired(config.EastWestObserveStorePath) {
			if p, e := cpStateBlobPersister(config.EastWestObserveStorePath, cpStateBlobDB, "east_west_observations"); e != nil {
				log.Fatalf("resolve east-west observe store %q: %v", config.EastWestObserveStorePath, e)
			} else if p != nil {
				if lerr := config.EastWestObserveStore.SetPersister(p, 90*24*time.Hour); lerr != nil {
					log.Printf("east-west observe store: load prior inventory failed (starting fresh): %v", lerr)
				}
				store := config.EastWestObserveStore
				go func() {
					for range time.Tick(30 * time.Second) {
						if err := store.PersistIfDirty(); err != nil {
							log.Printf("east-west observe store: persist failed: %v", err)
						}
					}
				}()
			}
		}
	}
	if config.PolicyCandidateStore == nil {
		config.PolicyCandidateStore = policycandidate.NewStore()
	}
	if config.AgentToolStore == nil {
		config.AgentToolStore = agenttool.NewStore(config.Evaluator.PolicyBundle.TenantID, config.Evaluator.Policies)
	}
	if config.EndpointInventoryStore == nil {
		config.EndpointInventoryStore = newAdminEndpointInventoryStore(config.Evaluator.PolicyBundle.TenantID, config.DeviceStore, time.Now())
	}
	if config.TenantModelStore == nil {
		config.TenantModelStore = newAdminTenantModelStore(config.Evaluator.PolicyBundle, time.Now())
	}
	if config.SiteStore == nil {
		// Empty in-memory Site store: GET /admin/sites merges no metadata, reproducing the Slice 1 projection.
		config.SiteStore = newAdminSiteStore()
	}
	if config.ToolCallEventAuditStore == nil {
		config.ToolCallEventAuditStore = toolcallaudit.NewStore()
	}
	if config.UsageMeters == nil {
		// FIFO-bound the IN-MEMORY usage meter (decision records carry a unique id per request and would
		// otherwise grow until OOM, like the inspection/access-decision stores before they were bounded).
		// Production uses -usage-meter-store=postgres which is durable; this bound only protects memory mode.
		config.UsageMeters = usagemeter.NewUsageMeterStoreWithCapacity(usageMeterInMemoryCapacity())
	}
	if config.HumanIdentities == nil {
		config.HumanIdentities = humanidentity.NewHumanIdentityDirectoryStore()
	}
	if err := prepareUserRiskState(context.Background(), config.HighRiskOverlay, config.EnrolledLedger, config.HumanIdentities); err != nil {
		log.Fatalf("prepare risk state: %v", err)
	}
	if config.HotStore == nil && config.Writer != nil {
		config.HotStore = hotstore.NewJSONLStore(config.Writer, adminLogStreamFilenameMap())
	}
	if config.WorkloadAttestations == nil {
		config.WorkloadAttestations = newRuntimeWorkloadAttestationReplayCache()
	}
	if config.TrustedKeyring.TenantID == "" {
		config.TrustedKeyring = model.TrustedKeyring{
			TenantID: config.Evaluator.PolicyBundle.TenantID,
			Version:  "local",
			Keys:     []model.TrustedKeyringKey{},
			Metadata: map[string]any{"source": "local_edge_default"},
		}
	}
	if config.AgentReleaseChannel == "" {
		config.AgentReleaseChannel = "lab"
	}
	return config
}

// inMemoryEventStoreDefaultCapacity bounds the per-event in-memory stores (inspection / human-approval /
// delegated-grant) so a long-running Edge does not grow them until OOM. Generous enough that active
// TTL'd entries are never evicted within their window. Override via DSSE_EVENT_STORE_CAPACITY
// (<=0 disables the bound; tests that construct the store directly stay unbounded).
const inMemoryEventStoreDefaultCapacity = 50000

func inMemoryEventStoreCapacity() int {
	if raw := strings.TrimSpace(os.Getenv("DSSE_EVENT_STORE_CAPACITY")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			return parsed
		}
	}
	return inMemoryEventStoreDefaultCapacity
}

// usageMeterInMemoryCapacity bounds the in-memory usage-meter store (override via
// DSSE_USAGE_METER_STORE_CAPACITY; <=0 disables the bound). Separate knob from the event stores so a
// deployment that keeps usage in memory can size it independently of inspection/decision retention.
func usageMeterInMemoryCapacity() int {
	if raw := strings.TrimSpace(os.Getenv("DSSE_USAGE_METER_STORE_CAPACITY")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			return parsed
		}
	}
	return inMemoryEventStoreDefaultCapacity
}

// evictFIFO drops oldest keys from order until len(live) <= capacity, deleting each from del. Returns the
// trimmed order. capacity<=0 is unbounded (returns order unchanged).
func evictFIFO(order []string, liveLen, capacity int, del func(key string)) []string {
	if capacity <= 0 {
		return order
	}
	for liveLen > capacity && len(order) > 0 {
		oldest := order[0]
		order = order[1:]
		del(oldest)
		liveLen--
	}
	if len(order) > 2*capacity {
		order = append([]string(nil), order...)
	}
	return order
}

// accessDecisionStoreDefaultCapacity bounds the UNPINNED set of the in-memory access-decision store (completed /
// within-grace / legacy entries) as a hard spike/bug backstop. In-flight (pinned) decisions are NOT counted and
// never dropped — concurrent-session limits are environment-specific, surfaced via the in-flight gauge instead.
// Overridable via DSSE_DECISION_STORE_CAPACITY (<=0 disables the count bound).
const accessDecisionStoreDefaultCapacity = 50000

// accessDecisionStoreDefaultTTL is the EVENT-TAIL GRACE: the store keys per decrypted HTTP request
// (model.AccessDecision, RequestMethod/RequestPath). A decision is PINNED while its request is in flight
// (MarkInFlight → MarkComplete, wired in swg_http_egress.go) and thus never evicted for the life of the flow —
// no wall-clock ceiling, so a thin-bandwidth multi-hour download is safe; the transport's byte-progress reap
// guarantees the request completes and unpins. AFTER completion this grace runs (idle from completion) so a
// straggler same-flow event (an inspection/tool-call event validating against the id via the ingest API) is not
// rejected; each such reference refreshes it. It covers only the completion→last-event lag, NOT flow duration, so
// it is SHORT (3 min). Tunable via DSSE_DECISION_STORE_TTL_SECONDS (<=0 disables it) — raise it for
// workloads whose same-flow events lag completion by minutes (e.g. slow human-in-the-loop tool approval). The
// durable record is the access log, not this cache. See docs/edge_decision_store_timeout_design.md.
const accessDecisionStoreDefaultTTL = 3 * time.Minute

type adminDownloadURLResponse struct {
	DownloadURL     string `json:"download_url"`
	ExpiresAt       string `json:"expires_at"`
	PayloadChecksum string `json:"payload_checksum"`
	RowCount        int    `json:"row_count"`
}

func adminTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return fmt.Sprintf("sha256:%x", sum)
}

func newAdminRawToken() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate admin api token: %w", err)
	}
	return "adm_" + base64.RawURLEncoding.EncodeToString(random), nil
}

func rawTokenPrefix(rawToken string) string {
	if len(rawToken) <= 10 {
		return rawToken
	}
	return rawToken[:10]
}

func randomEdgeID(prefix string, fallback time.Time) string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return prefix + hex.EncodeToString(random[:])
	} else {
		log.Printf("WARN: crypto/rand failed for %s id, falling back to process-local entropy: %v", strings.TrimSuffix(prefix, "_"), err)
	}
	return fmt.Sprintf("%s%d_%d_%d", prefix, fallback.UTC().UnixNano(), os.Getpid(), edgeIDFallbackCounter.Add(1))
}

func normalizedAdminRoles(roles []string, defaultRoles []string) []string {
	valid := adminAPITokenRoles
	result := []string{}
	source := roles
	if len(source) == 0 {
		source = defaultRoles
	}
	seen := map[string]bool{}
	for _, role := range source {
		normalized := strings.TrimSpace(role)
		if normalized == "" || !valid[normalized] || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}

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

// SnapshotByTenant returns the tenant's retained decisions in insertion (≈ time) order. Used by the
// AI Ops analytics (access trends / incident timeline). Bounded by the store capacity.

func main() {
	initMetricsStart(time.Now())
	mode := flag.String("mode", "edge", "run mode: edge, postgres-export-worker, postgres-audit-publisher, or postgres-domain-event-publisher")
	listen := flag.String("listen", ":8080", "listen address")
	// the Edge serves TLS, never plaintext. The main -listen serves HTTPS using -tls-cert/-key
	// (or, in -lab-mode, an auto-generated self-signed cert). With neither cert nor lab mode the Edge
	// REFUSES to start unless -allow-insecure-plaintext is explicitly set (loud insecure escape hatch).
	mainTLSCert := flag.String("tls-cert", "", "server certificate PEM for the main -listen (HTTPS); omit in -lab-mode to auto-generate a self-signed cert")
	mainTLSKey := flag.String("tls-key", "", "server private key PEM for the main -listen (HTTPS)")
	allowInsecurePlaintext := flag.Bool("allow-insecure-plaintext", false, "DANGER: serve the main -listen over plaintext HTTP instead of TLS (local debug only; the Edge is TLS-only by default)")
	drainPeriod := flag.Duration("drain-period", 5*time.Second, "Phase 4 graceful drain: on SIGTERM/SIGINT the Edge marks itself unhealthy (/healthz -> 503 so the LB drains it), bleeds in-flight requests for this period, then shuts down cleanly. Enables zero-outage rolling upgrades. SIGKILL still dies immediately (a crash, handled by failover).")
	// GUI / Admin Console separation. The Edge is API-only; the Console is a separate-host app
	// that calls the admin API over TLS. -admin-listen puts the admin+auth surface on its OWN TLS listener
	// (must NOT be loopback — the Console is remote); the data-plane listener then excludes admin+auth.
	adminListen := flag.String("admin-listen", "", "dedicated TLS listener for the admin+auth surface (host:port, must NOT be loopback — the Admin Console is a separate host); empty = admin served on the main listener")
	adminConsoleOrigin := flag.String("admin-console-origin", "", "CORS origin of the separate-host Admin Console (e.g. https://console.internal); enables cross-origin admin API calls for that exact origin only. Empty = no CORS (same-origin only)")
	adminConsoleOrigins := registerAdminConsoleOriginsFlag()
	adminSessionAuthorityURL := flag.String("admin-session-authority-url", "", "centralized admin auth: control-plane session endpoint (e.g. https://controlplane:9443/admin/session). When set, an admin_session cookie not known to this Edge's local store is INTROSPECTED here and accepted on success. Empty = this Edge is the sole session authority")
	adminSessionAuthorityCA := flag.String("admin-session-authority-ca", "", "PEM CA pinning the admin-session-authority's TLS cert (empty = system roots)")
	// (T) secure transport — additive TLS listener for the endpoint↔Edge tunnel. Default OFF; the
	// plaintext -listen is unchanged. mTLS device-identity knobs (client-ca / require-client-cert) are
	// wired for W2.
	transportTLSListen := flag.String("transport-tls-listen", "", "additive TLS listen address for the encrypted endpoint↔Edge transport (empty=disabled)")
	transportTLSCert := flag.String("transport-tls-cert", "", "transport server certificate PEM (omit in -lab-mode to auto-generate a self-signed cert)")
	transportTLSKey := flag.String("transport-tls-key", "", "transport server private key PEM")
	transportTLSClientCA := flag.String("transport-tls-client-ca", "", "CA that signs device client certs for mTLS device identity")
	transportTLSRequireClientCert := flag.Bool("transport-tls-require-client-cert", false, "require + verify a device client certificate (mTLS)")
	// Device enrollment issuance (roadmap M4c): when a device-identity CA cert+key are provided, register the
	// device-facing POST /enroll endpoint that signs device CSRs and assigns tenant/group. Off unless configured.
	deviceCACertPath := flag.String("device-ca-cert", "", "device-identity CA certificate PEM; with --device-ca-key enables the POST /enroll issuance endpoint (M4c)")
	deviceCAKeyPath := flag.String("device-ca-key", "", "device-identity CA private key PEM (EC/PKCS8); with --device-ca-cert enables POST /enroll")
	deviceCertNameSpaceSuffix := flag.String("device-certificate-namespace-suffix", "",
		"DNS namespace issued device certificates are named inside, e.g. \"tenant-a.dsse.local\" — each device gets the SAN <device-id>.<suffix>. "+
			"This is the prerequisite for NAME-CONSTRAINING a per-tenant issuing CA: a bare common name is not a name a constraint can permit, "+
			"which is why constraining the lab intermediate rejected every renewal on 2026-08-02. The common name stays the device id (both agents match on it). "+
			"Empty = issue exactly as before. Distribute certificates carrying the name to the whole fleet BEFORE constraining the intermediate.")
	enrollEligibilityToken := flag.String("enroll-token", "", "POST /enroll: shared eligibility token a device must present to enroll (empty = refuse all)")
	// IdP-backed enrolment eligibility: prove the right to enrol with a person's short-lived, revocable IdP
	// login instead of one shared secret that lives forever on every machine and names nobody. Names an IdP
	// connection id from the registry; empty = only the shared token is accepted.
	enrollIdPConnectionID := flag.String("enroll-idp-connection", "", "POST /enroll: IdP connection id whose ID tokens prove enrolment eligibility (empty = shared token only)")

	enrollIdPRequiredGroup := flag.String("enroll-idp-required-group", "", "POST /enroll: additionally require the IdP token's groups claim to contain this, narrowing \"any employee\" to \"allowed to enrol devices\"")
	enrollDefaultGroup := flag.String("enroll-default-group", "default", "POST /enroll: device group the CP assigns to newly enrolled devices")
	enrollCertTTL := flag.Duration("enroll-cert-ttl", 60*24*time.Hour, "POST /enroll: validity of issued device certs (short-lived; re-issued before expiry)")
	// Recovery for a device that was switched off across its certificate's expiry (a long holiday). Renewal
	// authenticates with the certificate being renewed, so an EXPIRED device cannot even ask — it comes back
	// permanently dead. This listener serves POST /enroll/renew, and nothing else, to such devices. Revocation
	// and enrolment are still enforced; only expiry is relaxed. Off unless an address is given.
	enrollRenewGraceListen := flag.String("enroll-renew-grace-listen", "", "recovery listener for devices whose cert expired while switched off: serves ONLY POST /enroll/renew to expired-but-enrolled, non-revoked identities (empty = disabled)")
	enrollRenewGraceWindow := flag.Duration("enroll-renew-grace-window", 30*24*time.Hour, "how long after expiry a device may still recover through -enroll-renew-grace-listen")
	transportTenantCARegistry := flag.String("transport-tenant-ca-registry", "", "JSON registry of per-tenant CAs {tenants:[{tenant_id,ca_file}]} — Edge trusts each tenant's CA and identifies the tenant by which CA the client cert chains to")
	transportTenantCARegistryCarriedFrom := registerDeviceCARegistryBootstrapFlag()
	transportEnrolledInventory := flag.String("transport-enrolled-inventory", "", "JSON file of enrolled device/connector identities allowed on the (T) transport (admission allowlist)")
	licenseStorePath := flag.String("license-store", "", "durable store for the vendor licence in force AND the highest serial ever accepted. The serial is what refuses an older file with more seats on it, so forgetting it on restart would re-open exactly the replay the signature cannot catch. 'postgres' | file path | empty = defaults to the state dir when -state-dir is set.")
	licenseVendorKeys := flag.String("license-vendor-keys", "", "PEM file holding EVERY vendor public key this deployment accepts licences from. A LIST on purpose: a deployment that accepts one key has no recovery from that key leaking except updating every install by hand, and licences carry no revocation. Empty = licensing is not enforced (single-tenant installs and the reference lab).")
	enforceSeatQuota := registerSeatQuotaFlag()
	licenseAllowOversubscription := flag.Bool("license-allow-oversubscription", false, "let an MSSP allocate more seats than its licence grants. Off by default: allowing it moves the failure to whichever tenant happens to enrol last, whose own administrator is inside their allocation and can neither see the cause nor fix it. The refusal belongs with the party who knows what they promised.")
	licenseRecipientKey := flag.String("license-recipient-key", "", "PEM file holding this deployment's X25519 PRIVATE key, used to open licences the vendor sealed to it. This key protects CONFIDENTIALITY only — losing it lets somebody read licences addressed here, and does NOT let them mint one, which needs the vendor's signing key. That difference is why this lives in a file and the vendor's lives in hardware. Empty = only unsealed licences can be applied.")
	licenseMSSPID := flag.String("license-mssp-id", "", "the MSSP identifier licences must be addressed to. Checked against the signed payload so a licence issued for somebody else cannot be applied here — the protection that makes signing-then-encrypting safe. Empty = accept any addressee (lab only).")
	seatAllocationStore := flag.String("seat-allocation-store", "", "durable JSON store for how an MSSP divides its licensed seat pool among tenants. Losing it reads as zero seats for every tenant and stops enrolment fleet-wide, so it is treated as operator config: 'postgres' | file path | empty = defaults to the state dir when -state-dir is set.")
	enrolmentTokenStore := flag.String("enrolment-token-store", "", "durable JSON store for the admin-issued, one-time enrolment tokens POST /enroll accepts. Durability is a SECURITY property here: the store is what records that a one-time credential has been SPENT, so an in-memory one would un-spend every used token on restart and a copied installer config would work again after any Edge bounce. 'postgres' | file path | empty = defaults to the state dir when -state-dir is set.")
	enrolmentTokenMaxLifetime := flag.Duration("enrolment-token-max-lifetime", 30*24*time.Hour, "the longest lifetime an admin may give a single enrolment token. The lifetime itself is chosen PER TOKEN by the issuer — the window between handing over an installer and the machine enrolling runs from an afternoon at the next desk to a courier delivery — and this bounds that choice so a slip, or a taken-over admin account, cannot mint one that never dies.")
	enrolmentTokenMaxOutstanding := flag.Int("enrolment-token-max-outstanding", 200, "how many UNSPENT enrolment tokens may exist per tenant at once. Counts unspent credentials, not devices ever enrolled — capping the latter would leave a tenant permanently unable to enrol its next machine.")
	enrolClaimFreshDeployment := registerEnrolClaimFreshDeploymentFlag()
	enrolledInventoryStore := flag.String("enrolled-inventory-store", "", "durable JSON store for admin runtime enroll/disable/remove changes to the Enrolled Inventory; restored on boot so they survive a restart (W7). Empty = in-memory only.")
	transportRequireEnrolledIdentity := flag.Bool("transport-require-enrolled-identity", false, "reject the (T) handshake unless the verified client-cert identity is in the enrolled inventory")
	// W4: the (T) transport contract published to the macOS NE in agent_config.json so it dials
	// the Edge over the encrypted tunnel (TLS + optional mTLS) and sends DNS over the tunnel.
	networkExtensionTransportTLSURL := flag.String("network-extension-transport-tls-url", "", "externally reachable (T) transport TLS URL published to the NE (e.g. https://host:18543; empty = omit)")
	networkExtensionTransportPinnedCARef := flag.String("network-extension-transport-pinned-ca-ref", "", "ref/filename of the pinned (T) transport CA PEM the NE pins")
	// Published to endpoints so a device whose certificate expired while it was switched off knows where to
	// renew. It cannot use the (T) transport for that: renewal authenticates with the certificate being
	// renewed, so once it lapses the handshake cannot complete and the device cannot even ask.
	networkExtensionRenewalRecoveryEndpoint := flag.String("network-extension-renewal-recovery-endpoint", "", "host:port of the renewal RECOVERY listener published to endpoints (pairs with -enroll-renew-grace-listen; empty = devices cannot self-recover after a long shutdown)")
	policyPath := flag.String("policy", "../samples/phase1/policy_lab_https_allow.json", "policy JSON path or comma-separated paths")
	bundlePath := flag.String("bundle", "../samples/phase1/policy_bundle_standard.json", "policy bundle JSON path")
	logDir := flag.String("log-dir", "var/logs", "JSONL log directory")
	logRotateMaxBytes := flag.Int64("log-rotate-max-bytes", 134217728, "rotate each JSONL log when it reaches this many bytes (0 = no rotation; default 128 MiB). Prevents unbounded growth / disk fill.")
	logRotateMaxBackups := flag.Int("log-rotate-max-backups", 10, "JSONL log retention: keep this many rotated backups per file (0 = cap only, keep none)")
	logRotateGzip := flag.Bool("log-rotate-gzip", true, "gzip rotated JSONL backups")
	// ★ THESE THREE DEFAULTS ARE CONTAINER PATHS, NOT SOURCE PATHS (2026-08-15). The runtime image has
	// WORKDIR /app/prototype with schemas at /app/schemas and samples at /app/samples, so "../schemas" resolves
	// there. When schemas/ and samples/ moved under oss/ in the source tree, a sweep that repointed
	// every reference rewrote these too — and the Edge then looked for /app/oss/schemas, failed schema
	// validation on its first policy, and would not start. Caught by rebuilding the lab rather than by any
	// test, because no test runs the binary the way the image does.
	schemaDir := flag.String("schema-dir", "../schemas", "schema JSON directory")
	migrationDir := flag.String("migration-dir", "migrations", "PostgreSQL migration directory")
	transportAdmission := registerTransportAdmissionFlags()
	edgeRegionID := flag.String("edge-region-id", "local", "edge region id")
	edgeClusterID := flag.String("edge-cluster-id", "local-edge-001", "edge cluster id")
	// Multi-region MESH : inter-region links to sibling edges.
	// All empty by default -> mesh fails closed (every cross-region app takes the hairpin default).
	meshPeers := flag.String("mesh-peers", "", "inter-region mesh peer edges: 'region=URL;region=URL' where URL is ws(s)://host:port/mesh/ingress/tunnel. Empty = mesh disabled (fail closed)")
	meshSecret := flag.String("mesh-secret", "", "shared secret for the inter-region mesh link (x-mesh-secret header); empty = no check (lab)")
	meshIngressAllowedPeers := flag.String("mesh-ingress-allowed-peers", "", "comma-separated peer-edge mTLS identities (client cert CN) authorized to use the mesh + revocation-mesh INGRESS. When set, the ingress requires a VERIFIED peer mTLS identity in this set and DISABLES the shared-secret fallback (mTLS-only). Required in production for any mesh-participating edge. Empty = lab fallback (verified-mTLS-or-secret).")
	meshEligibleHosts := flag.String("mesh-eligible-hosts", "", "comma-separated destination hosts/domains that opt into inter-region MESH instead of hairpin; empty = none")
	meshPeerInsecureSkipVerify := flag.Bool("mesh-peer-insecure-skip-verify", false, "dev: skip TLS verification when dialing wss:// mesh peers (overridden by -mesh-peer-ca)")
	meshClientCert := flag.String("mesh-client-cert", "", "PEM of this edge's CLIENT identity cert for inter-region mesh-link mTLS (proves this edge to the peer)")
	meshClientKey := flag.String("mesh-client-key", "", "PEM private key for -mesh-client-cert")
	meshPeerCA := flag.String("mesh-peer-ca", "", "PEM CA to PIN/verify the peer edge's server cert on the mesh link (real mutual auth; overrides -mesh-peer-insecure-skip-verify)")
	// Client-side geo-steering: the class-1 region map. The signed GET /steer/region-endpoints hands each
	// device its tenant's RESIDENCY-FILTERED allowed-region endpoints; the agent picks nearest-healthy among them.
	regionEndpoints := flag.String("region-endpoints", "", "class-1 region map for geo-steering: 'region=URL;region=URL' (URL https://host or wss://host). Empty = single-region (no geo-steering)")
	// The ONE signed document a device may fetch over a channel it cannot authenticate. Its authenticity comes
	// from the signature, so it stays reachable when a device's pinned transport CA no longer validates the Edge
	// — the situation in which every other signed document is unreachable, because they all ride the (T) tunnel.
	trustBundleCA := flag.String("trust-bundle-ca", "", "PEM of the transport CA anchors to publish in the signed trust bundle (GET /bootstrap/trust-bundle). Empty = the endpoint is not served")
	trustBundleSerial := flag.Int64("trust-bundle-serial", 0, "monotonic serial for the trust bundle; devices refuse anything that does not advance past the highest they have accepted, so BUMP THIS whenever -trust-bundle-ca changes. 0 = not served")
	connectorSecret := flag.String("connector-secret", defaultConnectorSecret, "shared secret for local connector registration and heartbeat")
	edgeConnectorRegistryStore := flag.String("connector-registry-store", "memory", "connector registry store used by edge runtime: \"memory\", \"postgres\" (needs -connector-registry-postgres-dsn), or a FILE PATH. memory LOSES every registered connector on restart — and because a connector only registers at STARTUP, its heartbeats then 404 forever and the whole fleet disappears from the Console until every connector is restarted. The zero-DB reference Edge should use a path on the shared mount, like -connector-route-governance-store.")
	edgeConnectorRegistryPostgresDSN := flag.String("connector-registry-postgres-dsn", "", "PostgreSQL DSN for edge connector-registry-store=postgres; defaults to -postgres-dsn when omitted")
	requireConnectorRuntimeSecret := flag.Bool("connector-runtime-secret-required", false, "require connector-specific runtime secrets for runtime endpoints outside lab mode; registration still uses -connector-secret")
	workloadAttestationSecret := flag.String("workload-attestation-secret", "", "HMAC secret for runtime workload attestation headers; required outside --lab-mode and must differ from -connector-secret")
	workloadAttestationNonceStore := flag.String("workload-attestation-nonce-store", "memory", "runtime workload attestation nonce store: memory or postgres")
	// Audit/persistence decoupling: allow a zero-DB enforcement Edge to use the in-memory nonce store in
	// production. In-memory = PER-INSTANCE replay protection only (HA wants postgres / the control plane).
	allowEphemeralNonceStore := flag.Bool("allow-ephemeral-attestation-nonce-store", false, "allow an in-memory workload-attestation-nonce-store outside lab mode (zero-DB Edge; per-instance replay protection only)")
	workloadAttestationNoncePostgresDSN := flag.String("workload-attestation-nonce-postgres-dsn", "", "PostgreSQL DSN for workload-attestation-nonce-store=postgres; defaults to -postgres-dsn when omitted")
	devMode := flag.Bool("lab-mode", false, "enable Phase 1 lab-only authentication bypasses for local lab runs")
	trustedKeyringPath := flag.String("trusted-keyring", "", "trusted keyring JSON path served to registered devices")
	protectedAppMapPath := flag.String("protected-app-map", "", "protected app map JSON path for application route profiles")
	swgTenantRestrictionOperatorConfigPath := flag.String("swg-tenant-restriction-operator-config", "", "operator-managed SWG tenant restriction header value config JSON path")
	swgTenantRestrictionOperatorValueStorePath := flag.String("swg-tenant-restriction-operator-value-store", "", "durable operator value store JSON path; Admin API header-value writes persist here so they survive a dataplane restart")
	adminRuntimeStateStorePath := flag.String("admin-runtime-state-store", "", "durable JSON store for Admin-API runtime TOGGLES (tenant-restriction status, east-west enabled/rules/maxTTL); restored on boot so they survive a restart. Empty = in-memory only")
	eastWestObserveStorePath := flag.String("east-west-observe-store", "", "durable store for the East-West Observe inventory (learned lateral flows); restored on boot so observations survive a restart (90-day retention). Empty = in-memory only; \"postgres\" or a file path")
	inspectionEventsStorePath := flag.String("inspection-events-store", "", "durable store for inspection events (notably the DLP findings); restored on boot so the DLP Findings view survives a restart (90-day retention). Empty = in-memory only; \"postgres\" or a file path")
	dlpClassifierStorePath := flag.String("dlp-classifier-store", "", "durable store for operator-defined custom DLP classifiers (/admin/dlp-classifiers); restored + recompiled on boot so custom identifiers survive a restart. Empty = in-memory only; \"postgres\" or a file path")
	dlpAllowlistStorePath := flag.String("dlp-allowlist-store", "", "durable store for operator-declared known-safe DLP values (/admin/dlp-allowlist, false-positive tuning); restored on boot so the allowlist survives a restart. Empty = in-memory only; \"postgres\" or a file path")
	dlpFingerprintStorePath := flag.String("dlp-fingerprint-store", "", "durable store for operator EDM datasets (/admin/dlp-fingerprints, exact-data-match; salted hashes only); restored on boot so fingerprints survive a restart. Empty = in-memory only; \"postgres\" or a file path")
	dlpPolicyObjectStorePath := flag.String("dlp-policy-object-store", "", "durable store for reusable named DLP Policy objects (/admin/dlp-policies, S5); restored on boot. Empty = in-memory only; \"postgres\" or a file path")
	organizationDomainsStorePath := flag.String("organization-domains-store", "", "durable store for the organization domains (/admin/organization-domains, S6) that DLP instance-aware action references as 'our company'. Empty = in-memory only; \"postgres\" or a file path")
	entitlementStorePath := flag.String("entitlement-store", "", "durable store for per-tenant feature entitlements (the license gate, /admin/entitlements); restored on boot. Empty = in-memory only; \"postgres\" or a file path")
	dlpRequiresLicense := flag.Bool("dlp-requires-license", false, "gate DLP behind a per-tenant license (false = DLP entitled by default; true = paid-feature deployment, DLP off until a tenant is licensed via /admin/entitlements)")
	assetCatalogStorePath := flag.String("asset-catalog-store", "", "durable JSON store for the operator-authored endpoint/group/service catalog (Console assets); restored on boot so authored endpoints survive a restart. Enrolled-device endpoints are re-derived from the enrolled inventory and not stored here. Empty = in-memory only")
	policyRuleStorePath := flag.String("policy-rule-store", "", "durable JSON store for authored East-West / Egress rules (the unified rule editor); restored on boot so authored rules survive a restart. Empty = in-memory only")
	applicationCatalogStorePath := flag.String("application-catalog-store", "", "durable store for operator-authored applications; merged on top of the config-seeded catalog on boot so authored apps/edits survive a restart. Empty = in-memory only; a path = file/JSON durability; \"postgres\" = control-plane Postgres backend (reuses the admin-auth-store=postgres connection)")
	idpConnectionStorePath := flag.String("idp-connection-store", "", "durable JSON store for the per-tenant end-user IdP registry (federated-auth connections + default), managed via /admin/idp-connections; restored on boot so registered IdPs survive a restart. Empty = in-memory only")
	stepUpBindingSecret := stepUpBindingSecretFlag()
	clientlessTLSCert, clientlessTLSKey := stepUpPortalCertificateFlags()
	clientlessBaseURL := flag.String("clientless-base-url", "", "when set, enables the clientless federated-auth broker at /clientless/auth/* and is the RP base URL for the OIDC redirect_uri (e.g. https://edge.example.com:8443). Empty = broker disabled (no clientless front door).")
	grantStorePath := flag.String("grant-store", "", "durable JSON store for federated-auth grants minted by the clientless broker; a revoked grant stays revoked across a restart. Empty = in-memory only")
	delegatedGrantStorePath := flag.String("delegated-grant-store", "", "durable JSON store for delegated-access (east-west NHI) grants; in-flight grants and revocations survive a restart. Empty = in-memory only")
	humanApprovalStorePath := flag.String("human-approval-store", "", "durable JSON store for human-approval (step-up ceremony) events; approval outcomes survive a restart. Empty = in-memory only")
	breakGlassStorePath := flag.String("break-glass-store", "", "durable JSON store for break-glass emergency-access requests; a pending/approved request survives a restart instead of being lost mid-ceremony. Empty = in-memory only")
	swgRuntimeTLSDecryptionObserved := flag.Bool("swg-runtime-tls-decryption-observed", false, "non-secret SWG readiness signal indicating default TLS decryption was observed by the runtime")
	swgMacCATrustObserved := flag.Bool("swg-mac-ca-trust-observed", false, "non-secret SWG readiness signal indicating Mac CA trust was observed by the runtime; does not mutate the trust store")
	networkExtensionConfigPublishDir := flag.String("network-extension-config-publish-dir", "", "directory where Admin Console policy snapshots for the macOS Network Extension are written; disabled when empty")
	networkExtensionRuntimeCopyEdgeURL := flag.String("network-extension-runtime-copy-edge-url", "", "host-separated Edge runtime-copy base URL written to Network Extension snapshots")
	networkExtensionRuntimeCopyEndpointPath := flag.String("network-extension-runtime-copy-endpoint-path", networkExtensionSnapshotDefaultEndpointPath, "runtime-copy endpoint path written to Network Extension snapshots")
	networkExtensionRuntimeCopySessionEndpointPath := flag.String("network-extension-runtime-copy-session-endpoint-path", networkExtensionSnapshotDefaultSessionEndpointPath, "session runtime-copy endpoint path written to Network Extension snapshots")
	networkExtensionRuntimeCopyTransportScope := flag.String("network-extension-runtime-copy-transport-scope", networkExtensionSnapshotDefaultTransportScope, "runtime-copy transport scope for Network Extension snapshots: lab_endpoint or real_edge")
	networkExtensionRuntimeCopyEdgeConnectorRealness := flag.String("network-extension-runtime-copy-edge-connector-realness", networkExtensionSnapshotDefaultConnectorRealness, "edge connector realness label for Network Extension snapshots")
	networkExtensionRuntimeCopyPassthroughResolvedIPs := flag.String("network-extension-runtime-copy-passthrough-resolved-ips", "", "comma-separated reviewed Edge IP literals passed through by the Network Extension to avoid Edge reentry")
	networkExtensionRuntimeCopyDownstreamPassthroughSourceAppSigningIdentifiers := flag.String("network-extension-runtime-copy-downstream-passthrough-source-app-signing-identifiers", "", "comma-separated reviewed source app signing identifiers whose Edge downstream TCP connections should pass through the Network Extension")
	networkExtensionRuntimeCopyDownstreamPassthroughDefaultTunnelEnabled := flag.Bool("network-extension-runtime-copy-downstream-passthrough-default-tunnel", false, "allow reviewed runtime-copy downstream source apps to pass through when Network Extension rules use default tunnel")
	networkExtensionRuntimeCopyLabTLSInterceptionHosts := flag.String("network-extension-runtime-copy-lab-tls-interception-hosts", "", "comma-separated reviewed hostnames or *.suffix patterns whose NE runtime-copy 443 flows should receive lab TLS interception instead of raw TCP passthrough")
	// Interception-root scoping (PKI blast-radius bounding). "shared" = one default root for all (current).
	// "per-tenant" = each non-primary tenant's leaves are signed by that tenant's own root. "per-region" =
	// per-tenant roots ALSO scoped to THIS edge's region, so a leaked regional key MITMs only its region and a
	// region's traffic is decryptable only by a key that resides in that region (residency). OPT-IN: the per-
	// tenant/per-region root must first be distributed to those devices' trust stores (MDM) or TLS trust breaks.
	interceptionRootScope := flag.String("interception-root-scope", "shared", "interception-root blast-radius scope: shared | per-tenant | per-region (per the edge's -edge-region-id). OPT-IN: requires the scoped root distributed to devices first")
	interceptionPerTenantRootDir := flag.String("interception-per-tenant-root-dir", "", "directory to durably persist per-tenant interception roots (so they survive a restart instead of regenerating and breaking device trust). Empty = in-memory (lab)")
	interceptionRootKEKFile := flag.String("interception-root-kek-file", "", "path to a 32-byte AES-256 KEK (raw, base64, or hex). When set, persisted interception root keys (default + per-tenant) AND admin TOTP 2FA secrets are SEALED at rest (AES-256-GCM) instead of plaintext; the edge unseals them in memory at startup. Source the KEK from a secret manager")
	// Offline-root mode (PKI hardening): the Edge holds only a name-constrained intermediate (cert+key) signed by
	// an OFFLINE root, plus the root cert as the trust anchor. The crown-jewel root key is never on the Edge.
	// Generate these with `catalog`/`interception-ca` tooling. All three must be set together.
	interceptionIntermediateCert := flag.String("interception-intermediate-cert", "", "PEM path of an offline-root-issued interception INTERMEDIATE certificate (with -interception-intermediate-key + -interception-root-cert). The Edge signs leaves with this intermediate and holds no root key")
	interceptionIntermediateKey := flag.String("interception-intermediate-key", "", "PEM path of the interception intermediate private key (PKCS#8/PKCS#1/SEC1)")
	interceptionAnchorCert := registerInterceptionAnchorFlag()
	interceptionPendingRootCert := flag.String("interception-pending-root-cert", "",
		"PEM of an interception root being DISTRIBUTED to endpoint trust stores but not yet signed under. Its "+
			"fingerprint is advertised to agents so they report whether they hold it, and the certificate "+
			"screen shows how far it has reached. Switching the interception root without this is blind, and "+
			"a machine that missed the distribution loses every HTTPS site at once. Empty = nothing pending.")
	profileInterceptionRootCert := registerDeploymentInterceptionRootFlag()
	interceptionRootCert := flag.String("interception-root-cert", "", "PEM path of the OFFLINE interception root certificate (the trust anchor clients pin; written to -...-root-ca-cert-out). The root private key is NOT given to the Edge")
	// PER-TENANT offline issuers — defined in interception_tenant_issuer_flags.go, beside what they configure.
	interceptionTenantIssuers := registerInterceptionTenantIssuerFlags()
	// Where the published catalogue and each organization's rollout plan live — see agent_release_store_flags.go.
	agentReleaseStores := registerAgentReleaseStoreFlags()
	// Runtime intermediate (lighter option): the Edge's root signs a rotatable intermediate at startup (root key
	// still on the Edge). Use the offline mode above for the strong property.
	interceptionUseIntermediate := flag.Bool("interception-use-intermediate", false, "OPT-IN: sign leaves through a rotatable intermediate the Edge-held root issues (chain [leaf, intermediate, root]); the root key remains on the Edge. For the strong property use -interception-intermediate-cert/-key/-root-cert instead")
	interceptionIntermediatePermittedDNS := flag.String("interception-intermediate-permitted-dns", "", "comma-separated permitted DNS name constraints for the runtime intermediate (empty = unconstrained, correct under decrypt-all)")
	inspectionPostureStorePath := flag.String("inspection-posture-store", "", "durable JSON store for the inspection posture (deployment mode decrypt_all|bypass_default + decrypt allowlist + known-bypass toggle); persists across restart. Empty = in-memory (resets to flag defaults on restart)")
	adminClientCAFile := registerAdminClientCAFlag()
	transportTenantCertDir := registerTransportTenantCertDirFlag()
	renewalRecoverySNI := registerRenewalRecoverySNIFlag()
	tenantModelStorePath := flag.String("tenant-model-store", "", "durable store for tenant model profiles (the super-admin cross-tenant catalog: display name, region, residency, plan, status/lifecycle); restored on boot so tenant profiles survive a restart. Empty = in-memory only (seeded from the active policy bundle tenant); a path = file/JSON durability; \"postgres\" = control-plane Postgres backend (reuses the admin-auth-store=postgres connection)")
	siteStorePath := flag.String("site-store", "", "durable store for the persistent Site / Connector Group catalog (Connector UX Slice 1b: name, region, expected connector count, routing namespace, deployment type, HA policy; bootstrap-secret HASH only). Empty (default) = in-memory only and starts empty, so GET /admin/sites reproduces the read-only connector projection (lab unchanged); a path = file/JSON durability; \"postgres\" = control-plane Postgres backend (reuses the admin-auth-store=postgres connection)")
	connectorEnrollmentEdgeURL := flag.String("connector-enrollment-edge-url", "", "the public Edge transport URL a connector dials, folded into the one-time enrollment token so 'Add connector' emits one self-contained command (no --edge-url to fill). Falls back to the edge_url in the request body when empty")
	connectorProgramDir := registerConnectorProgramFlag()
	connectorEnrollmentStateDir := flag.String("connector-enrollment-state-dir", "", "the --state-dir path rendered into the enrollment command where a connector persists after enrolling (default /var/lib/dsse-connector)")
	connectorEnrollmentEdgeCA := flag.String("connector-enrollment-edge-ca", "", "PEM path of the Edge transport CA to fold into the enrollment token (public, not a secret) so a connector pins it on first run with no separate CA file to hand-place")
	operatorTenantID := flag.String("operator-tenant-id", "", "the SSE operator's own tenant id in the multi-tenant Admin Console. When set, that tenant is seeded (display name \"Operator\", status active), flagged is_operator in GET /admin/tenants, hidden from the Console customer list, and refused for deletion (lockout protection). Empty (default) = feature off: no operator tenant, all tenants shown normally — the lab behavior is unchanged")
	networkExtensionRuntimeCopyLabTLSRootCACertOut := flag.String("network-extension-runtime-copy-lab-tls-root-ca-cert-out", "", "optional file or directory path where the lab TLS interception root CA certificate PEM is written; directories use lantern_dsse_interception_root_ca.pem, and a sibling .key.pem file is stored with 0600 permissions and reused for stable local lab trust")
	networkExtensionRuntimeCopyLabTLSBypassHosts := flag.String("network-extension-runtime-copy-lab-tls-bypass-hosts", "", "comma-separated hostnames or *.suffix patterns the Edge bypasses (raw_forward, never decrypts) even under decrypt-all; the Edge decides bypass here rather than relying on an NE-level passthrough exception (e.g. the AI dev-agent control plane and cert-pinned apps)")
	networkExtensionRuntimeCopyLabTLSSNIBasedIntercept := flag.Bool("network-extension-runtime-copy-lab-tls-sni-based-intercept", false, "decide intercept vs raw_forward from the TLS ClientHello SNI instead of route.Host; robust for connect-by-IP clients (Chrome/IPv6) where route.Host is an IP. Requires steer-all (no intercept-only-domains) so all flows reach the Edge; non-SNI-matching flows are raw_forwarded without decryption")
	// HSM-backed interception key custody (docs/2026-07-28_pki_key_custody_sidecar_decision.ja.md). When a
	// socket is given, the interception CA key lives in a PKCS#11 token held by dsse-hsm-agent and this process
	// never holds it. Empty = the in-process file key (default; unchanged behaviour).
	interceptionHSMAgentSocket := flag.String("interception-hsm-agent-socket", "", "unix socket(s) of dsse-hsm-agent. When set, the interception CA signs through a PKCS#11 token instead of an in-process key. Comma-separated (primary first) forms an HA pool that fails over between replicated HSM appliances; the pool refuses to start unless every sidecar reports the SAME key")
	interceptionHSMAgentToken := flag.String("interception-hsm-agent-token", "", "bearer token for dsse-hsm-agent")
	interceptionHSMAgentKeyID := flag.String("interception-hsm-agent-key-id", "", "key id in the token to sign with. Empty = adopt the only key the agent holds")
	interceptionHSMAgentCert := flag.String("interception-hsm-agent-ca-cert", "", "path to the interception CA certificate for the HSM-held key. Minted (self-signed by the token key) and persisted here on first run")
	interceptionReparentStateDir := flag.String("interception-reparent-state-dir", "", "directory where a completed interception-root RE-PARENT is persisted (root + intermediate PEM) so it survives a restart. When the token key has been re-issued a certificate under a central (MSSP) root via POST /admin/interception-intermediate/adopt, that posture is restored on boot instead of reverting to the self-signed root. Empty = the reparent is live-only (reverts on restart). Certificates only; the signing key stays in the token.")
	networkExtensionRuntimeCopyLabTLSDynamicPinDetection := flag.Bool("network-extension-runtime-copy-lab-tls-dynamic-pin-detection", false, "OPT-IN: dynamically learn cert-pinned destinations from repeated intercept handshake failures and raw_forward them. Default OFF for security: an attacker could deliberately fail handshakes to get their destination raw_forwarded (escaping inspection/tenant-restriction). When OFF, only the static bypass list decides raw_forward; cert-pinned OS infra (Apple daemons etc.) must be listed there explicitly")
	policyCandidateStatePath := flag.String("policy-candidate-store", "", "path to a JSON file persisting policy candidates (incl. cert-pinning bypass proposals). When set, candidates survive an edge restart so an unreviewed proposal is never lost. Empty = in-memory only")
	catalogOverrideStatePath := flag.String("predefined-catalog-override-store", "", "path to a JSON file persisting per-tenant predefined-catalog overrides (force-inspect/disable a curated bypass entry). When set, overrides survive an edge restart. Empty = in-memory only")
	catalogFeedStatePath := flag.String("predefined-catalog-feed-store", "", "path to a JSON file persisting the applied signed predefined-catalog feed + version history (for rollback). Empty = in-memory only")
	catalogFeedTrustedKeysFile := flag.String("predefined-catalog-feed-trusted-keys-file", "", "path to a JSON file mapping signing_key_id -> base64(std) ed25519 public key. A signed catalog feed is applied only if its signer is in this ring. Empty = no feed can be applied (built-in default served)")
	stripAltSvc := flag.Bool("strip-alt-svc", true, "strip the Alt-Svc response header on intercepted flows so clients do not switch to HTTP/3 (QUIC). Default on: QUIC is un-interceptable, so it is disabled by default for a decrypt-all SSE (matching the endpoint UDP/443 drop), which also avoids the QUIC-timeout fallback that slows QUIC-preferring clients like Safari")
	dlpBlockUninspectableFiles := flag.Bool("dlp-block-uninspectable-files", false, "when an interrupting (block/authenticate) DLP rule governs a flow and an uploaded file cannot be text-extracted (encrypted/corrupt/adversarial PDF or Office file), BLOCK the upload instead of forwarding it uninspected. Default off (availability first): the skip is logged either way, but a deliberately-corrupted container is a DLP bypass vehicle — set this for tenants whose block rules must not be evadable that way")
	swgEgressBrowserMimic := flag.Bool("swg-egress-browser-mimic", false, "OPT-IN: re-originate the device decrypt-all upstream through the egress broker's REAL Chrome network stack (curl-impersonate: BoringSSL TLS(JA3/JA4) + HTTP/2(Akamai SETTINGS/pseudo-header order) + header order), so bot-mitigation (AWS WAF / Akamai / Imperva / Cloudflare) treats the intercepted re-originated connection as a real browser instead of Go (fixes Amazon WAF challenge / EC-site 502 without bypassing decryption). REQUIRES EGRESS_BROKER_URL — the Edge refuses to start without it, as no in-process fallback engine exists. Default OFF (Go fingerprint); device decrypt-all path only")
	defaultBypassList := flag.Bool("default-bypass-list", true, "raw-forward a curated set of well-known un-interceptable services (Apple push/iCloud, OS updates, OCSP) by default, so they work out of the box and do not generate cert-pinning detection noise. Set false to intercept everything (then bypass via detection/admin)")
	networkExtensionRuntimeCopyLabTLSProbeOnly := flag.Bool("network-extension-runtime-copy-lab-tls-probe-only", false, "lab-only mode: answer non-probe lab TLS HTTP requests with a synthetic 204 instead of forwarding them through SWG egress")
	networkExtensionRuntimeVerboseLogs := flag.Bool("network-extension-runtime-verbose-logs", false, "DEPRECATED alias for -log-level=debug: emit the high-volume per-request interception logs. Prefer -log-level. Kept for compatibility; either enables the same per-request firehose.")
	logLevelFlag := flag.String("log-level", "info", "operational (stderr) log level: error | warn | info | debug. Default info = a healthy edge under load is nearly silent (per-flow diagnostics are DEBUG-gated and guard-evaluated, so they cost nothing when off). debug turns the per-flow/per-request firehose back on.")
	networkExtensionPassthroughDomains := flag.String("network-extension-passthrough-domains", "", "comma-separated domains the Network Extension should pass through instead of steering to Edge")
	networkExtensionSelfExclusionSigningIdentifiers := flag.String("network-extension-self-exclusion-source-app-signing-identifiers", "", "comma-separated app code-signing identifiers the Network Extension self-excludes (passes through, signature-verified) in addition to the built-in dev-agent defaults; used for dev-machine convenience (e.g. com.apple.Safari)")
	networkExtensionDefaultPassthroughDomainsEnabled := flag.Bool("network-extension-default-passthrough-domains-enabled", true, "include built-in transparent passthrough domains in generated Network Extension agent_config.json")
	clientlessAccessEnabled := flag.Bool("clientless-access", false, "enable the PUBLIC clientless web front door (browser + IdP login → reduced-trust published-app access). OFF by default — it is a pre-auth public web surface; enable only when a deployment needs agentless app access.")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer URL")
	oidcClientID := flag.String("oidc-client-id", "", "OIDC client id")
	oidcClientSecret := flag.String("oidc-client-secret", "", "OIDC client secret")
	oidcRedirectURI := flag.String("oidc-redirect-uri", "", "OIDC redirect URI")
	oidcAuthorizationEndpoint := flag.String("oidc-authorization-endpoint", "", "optional OIDC authorization endpoint override for non-Keycloak IdPs")
	oidcTokenEndpoint := flag.String("oidc-token-endpoint", "", "optional OIDC token endpoint override for non-Keycloak IdPs")
	oidcJWKSURI := flag.String("oidc-jwks-uri", "", "optional OIDC JWKS URI override for non-Keycloak IdPs")
	oidcGroupsClaim := flag.String("oidc-groups-claim", "groups", "OIDC claim name used as user groups")
	oidcHostedDomainClaim := flag.String("oidc-hosted-domain-claim", "", "optional OIDC hosted-domain claim name to append as a synthetic group, e.g. hd for Google Workspace")
	oidcRequiredHostedDomain := flag.String("oidc-required-hosted-domain", "", "optional hosted-domain value required in the OIDC id_token")
	oidcHostedDomainGroup := flag.String("oidc-hosted-domain-group", "", "optional synthetic group value appended when hosted-domain claim is present; defaults to /workspace/<domain>")
	oidcIDPID := flag.String("oidc-idp-id", "idp_keycloak_lab", "server-side IdP id recorded on sessions minted by the OIDC callback (matched by policy required_idp_id). Operator config, never taken from the callback request")
	firstPartyAccounts := flag.Bool("first-party-accounts", false, "enable SaaS-issued first-party admin accounts (invite -> activation link -> password + TOTP 2FA -> email+password+TOTP login)")
	firstPartyIssuer := flag.String("first-party-issuer", "Lantern DSSE", "issuer label shown in the TOTP authenticator app for first-party admin accounts")
	firstPartyStore := flag.String("first-party-store", "memory", "store for first-party admin credentials: memory (lost on restart), postgres, or a JSON snapshot file path.")
	firstPartyStorePostgresDSN := flag.String("first-party-store-postgres-dsn", "", "PostgreSQL DSN for first-party-store=postgres; defaults to -postgres-dsn when omitted")
	connectorRouteGovernanceStorePath := flag.String("connector-route-governance-store", "", "durable + SHARED store for connector route-governance DECISIONS (held/approved/authored): a file path. Survives restart; on a mount shared across the HA fleet (e.g. the reference's ./dataplane-ne, mounted by every region's Edge) all Edges read the SAME decisions, so routing + /connectors/{id}/effective-routes are consistent fleet-wide. Empty = in-memory per-Edge.")
	vlanObjectStorePath := flag.String("vlan-object-store", "", "durable store for Named Networks (VLAN/Subnet objects, /admin/vlan-objects) + boundary policies: \"postgres\" or a FILE PATH. These are ADMIN-CONFIGURED definitions — what the Console's Network Zones page writes and what connector bindings reference by id. Empty = in-memory, meaning every restart ERASES them: that is why the Console's Networks page read permanently empty, since the lab rebuilds the Edge on every change. On a mount shared across the HA fleet (e.g. the reference's ./dataplane-ne) every Edge reads the same definitions.")
	connectorRoutesCPConfigured := flag.Bool("connector-routes-cp-configured", true, "CP-CONFIGURED connector-route model (DEFAULT): a connector's self-reported subnets are non-authoritative DISCOVERY and are NOT routable until the operator adopts (approves) them — no grandfather. Only admin-configured bindings (POST /admin/connectors/{id}/routes, incl. Named-Network references) route. Set =false for the LEGACY grandfather behavior (self-declared routes auto-approved on first sight) — an escape hatch during migration; existing adoptions in -connector-route-governance-store carry over regardless.")
	steerExclusionStoreMode := flag.String("steer-exclusion-store", "memory", "durable store for admin-managed steer exclusions: memory or postgres (control plane).")
	steerExclusionKnownFloor := flag.String("steer-exclusion-known-floor", "a.out,limactl-*", "comma-separated known-floor allowlist (exact or `prefix*`) for the observed-telemetry anomaly view: effective exclusions matching these are classified `floor` (expected loop-prevention/infra), NOT flagged `unmanaged`.")
	steerExclusionStorePostgresDSN := flag.String("steer-exclusion-store-postgres-dsn", "", "PostgreSQL DSN for steer-exclusion-store=postgres; defaults to -postgres-dsn when omitted")
	observedExclusionStoreMode := flag.String("observed-exclusion-store", "memory", "durable store for observed (reverse-telemetry) steer exclusions: memory or postgres. memory is the default (re-populated by the next agent report after a restart); postgres persists each device's latest effective set.")
	observedExclusionStorePostgresDSN := flag.String("observed-exclusion-store-postgres-dsn", "", "PostgreSQL DSN for observed-exclusion-store=postgres; defaults to -postgres-dsn when omitted")
	steerExclusionSourceURL := flag.String("steer-exclusion-source-url", "", "CP→Edge sync: control-plane admin base (e.g. https://controlplane:9443) the enforcing Edge PULLS its steer exclusions from into its in-memory cache (zero-DB durability). Empty = use the local store directly. P-3")
	steerExclusionSourceToken := flag.String("steer-exclusion-source-token", "", "CP→Edge sync: bearer for the control-plane admin API; defaults to -admin-token")
	steerExclusionSourceCA := flag.String("steer-exclusion-source-ca", "", "CP→Edge sync: PEM CA pinning the control plane's TLS cert; defaults to -admin-session-authority-ca, then system roots")
	configSourceCA := registerConfigSourceCAFlag()
	steerExclusionSourcePoll := flag.Duration("steer-exclusion-source-poll", 30*time.Second, "CP→Edge sync: pull interval")
	configSourceURL := flag.String("config-source-url", "", "CP→Edge config distribution: control-plane admin base the Edge PULLS its versioned config bundle from (slice 1: access policies + a monotonic generation) and applies atomically. Empty = use local stores directly. Reuses -steer-exclusion-source-token/-ca and -admin-token defaults.")
	configSourcePoll := flag.Duration("config-source-poll", 10*time.Second, "CP→Edge config distribution: pull interval")
	configSourceEndpoints := flag.String("config-source-endpoints", "", "CP→Edge multi-region control-channel failover: residency-filtered per-region CP endpoint list \"region-a=https://cpA:9443;region-b=https://cpB:9443\". When set, the Edge health-probes each CP's GET /leader and pulls config/revocation from the region that currently holds CP leadership, failing over on region loss — a GSLB-free reuse of the client→Edge regionfailover engine. Empty = single-CP -config-source-url.")
	configSourceHome := flag.String("config-source-home", "", "CP→Edge multi-region: the preferred (home) CP region id for the -config-source-endpoints list (tiebreak / preferred failover target).")
	configSourceStrikes := flag.Int("config-source-strikes", 3, "CP→Edge multi-region: consecutive unhealthy probe rounds before the control channel fails over off the current CP region (hysteresis).")
	deviceCAHSMAgentSocket := flag.String("device-ca-hsm-agent-socket", "",
		"signing-sidecar socket(s) holding the DEVICE CA key, so the Edge signs device certificates without "+
			"ever holding the key. Same sidecar as -interception-hsm-agent-socket; give it a different key id. "+
			"Empty = the device CA is read from -device-ca-key as a file on this host.")
	deviceCAHSMToken := flag.String("device-ca-hsm-token", "", "PKCS#11 token label for -device-ca-hsm-agent-socket")
	deviceCAHSMKeyID := flag.String("device-ca-hsm-key-id", "", "PKCS#11 key id for -device-ca-hsm-agent-socket")
	refuseStartOnUnusableCertificate := flag.Bool("refuse-start-on-unusable-certificate", false,
		"refuse to start when a certificate this node would present is one the fleet's devices would reject. "+
			"Default false: the check always RUNS and always reports, but a node that will not start cannot be "+
			"fixed remotely, so a fleet-wide redeploy with a bad file would take the deployment down entirely "+
			"rather than partially. Set it where failing closed is preferred to serving a certificate nobody "+
			"can verify.")
	isControlPlane := flag.Bool("control-plane", false, "this process IS the control plane, not an Edge that needs one. The control plane runs the same binary as an Edge and until now nothing on its command line said which it was — the difference lived only in which stores happened to be wired. Declaring it makes the startup requirement below expressible, and makes a compose file legible to somebody who has not read the store list.")
	transportAnchorAckStorePath := flag.String("transport-anchor-ack-store", "", "durable store for an operator's per-identity assertions that a transport trust anchor is held by other means (a connector whose CA file was updated, say). Without one, a restart re-closes a withdrawal gate the operator had deliberately opened. File path | empty = defaults to the state dir when -state-dir is set.")
	deviceClientCAStorePath := flag.String("device-client-ca-store", "", "durable, runtime-mutable store for the CAs device client certificates are verified against (seeded from -transport-tls-client-ca on first run). When set, an admin can retire a CA that no observed device still chains to — with no restart. Empty = the flag file is the fixed set.")
	pkiOperationStorePath := flag.String("pki-operation-store", "", "durable record of the staged PKI operation in flight (which certificate a rotation is moving TO). Only the INTENT is stored — every stage is computed from what is measurably true, so the view cannot drift from the deployment and survives a restart with no recovery logic. Empty = staged operations are not offered.")
	transportTrustCarriedFrom := transportTrustCarriedFromFlag()
	transportTrustStorePath := flag.String("transport-trust-store", "", "durable, runtime-mutable store for the certificates devices trust (seeded from -trust-bundle-ca/-trust-bundle-serial on first run). When set, an admin can ADD a certificate and — behind the fleet-coverage gate — WITHDRAW one from the Console, with the distribution serial advancing and the bundle re-signed on every change. Empty = the flag file is the fixed set (change = edit + serial bump + restart).")
	renewBeforeStorePath := flag.String("renew-before-store", "", "durable store for the \"renew every certificate issued before T\" cutoff carried in the signed agent policy. Losing it on restart would stop a fleet-wide renewal half-way through, silently, for every device that had not checked in yet. File path | empty = defaults to the state dir when -state-dir is set.")
	dnsPolicyStorePath := flag.String("dns-policy-store", "", "durable JSON store for the DNS policy an operator authored (deny / sinkhole / stub / forward zones). Without one the policy lives only in memory, so a rule written through the admin API is reverted by the next restart and the deployment quietly returns to its boot environment — observed on 2026-07-30, where a restart dropped the stub that made an internal name resolve and what reached a user was a browser reporting no internet. File path | empty = defaults to the state dir when -state-dir is set.")
	noControlPlane := flag.Bool("no-control-plane", false, "run this Edge with NO control plane, taking its config from local files and flags only. There is no supported DEPLOYMENT of this shape — the control plane is where config, admission and revocation are authored, and an Edge holding its own truth is a fleet of one that drifts from every other node. The flag exists for single-process test harnesses, and it is named so that seeing it on a command line is enough to know the process is not a deployment. Without it, an Edge started with neither -config-source-url nor -config-source-endpoints refuses to start.")
	allowUnsignedConfigBundle := flag.Bool("allow-unsigned-config-bundle", false, "production escape hatch: accept an UNSIGNED CP→Edge config bundle. Default false = when an agent-policy signing key is present the Edge REQUIRES the pulled config bundle to be signed by it and rejects a tampered/unsigned one (a compromised CP / stolen bearer token must not push arbitrary policy). Only affects -config-source-url pull.")
	allowVolatileConfig := flag.Bool("allow-volatile-config", false, "escape hatch for a deliberately EPHEMERAL Edge: permit OPERATOR-CONFIG stores to run in-memory in production instead of FAILING startup. Off by default — a node that owns operator-authored config must not silently lose it on restart, so a volatile CONFIG store is now a startup ERROR, not a warning. Set this only for a throwaway/test Edge; its use is logged. (Runtime stores — sessions, metering — may be volatile regardless; only CONFIG is gated.) Supersedes the old -require-durable-stores, which was opt-in the wrong way round.")
	revocationSourcePoll := flag.Duration("revocation-source-poll", 2*time.Second, "CP→Edge SHARED REVOCATION overlay (Phase 3): FAST pull interval for the admission-revocation feed (kept low so a kill-switch bites fleet-wide within seconds). Uses the same -config-source-url base.")
	admissionRevocationStore := flag.String("admission-revocation-store", "", "durable JSON store for the admission revocation set (Phase 3): the control plane persists its kill-switches here so a restart cannot silently un-revoke. Empty = in-memory only.")
	highRiskStore := flag.String("high-risk-store", "", "durable JSON store for the shared high-risk device overlay (Phase 3): the control plane persists its high-risk markings here so a restart cannot silently clear them. Empty = in-memory only.")
	// Cross-region revocation mesh: peer-region CPs an ORIGIN revocation propagates to. Empty = single-region.
	revocationMeshPeers := flag.String("revocation-mesh-peers", "", "cross-region revocation mesh: peer-region CP base URLs 'region=URL;region=URL'. On an origin revocation this CP pushes to each peer (no-loop). Empty = single-region")
	revocationMeshSecret := flag.String("revocation-mesh-secret", "", "shared secret for the cross-region revocation mesh (x-revocation-mesh-secret header); empty = no check (lab)")
	revocationMeshOutboxStore := flag.String("revocation-mesh-outbox-store", "", "durable store for PENDING cross-region revocation-mesh pushes: a not-yet-acked push survives a CP restart and is resumed on boot, so a kill-switch converges cross-region even across a restart. 'postgres' | file path | empty = in-memory only (defaults to the state dir when -state-dir is set)")
	agentPolicyNextPublicKey := flag.String("agent-policy-next-public-key", "",
		"public key(s) (hex; Ed25519 32-byte or ECDSA-P256 uncompressed-point) to publish in the trust bundle as the NEXT policy-signing key(s) for devices to adopt, WITHOUT this node holding their private half. This is how an HSM-held ECDSA next key is advertised for the config-signing-key switch — the token has the private key, only the public one is handed in here. Comma-separated. Signing is unaffected until an operator makes one of these the active key.")
	agentPolicyHSMAgentSocket := flag.String("agent-policy-hsm-agent-socket", "",
		"unix socket of dsse-hsm-agent for the agent-policy signing key. When set, policy is signed by an ECDSA-P256 key in a PKCS#11 token instead of the on-disk Ed25519 key (-agent-policy-signing-key) — the config-signing key's move into hardware. This is the SWITCH: set it only once every device reports holding the token key (agent_policy_public_keys).")
	agentPolicyHSMAgentToken := flag.String("agent-policy-hsm-agent-token", "", "bearer token for the agent-policy dsse-hsm-agent socket")
	agentPolicyHSMAgentKeyID := flag.String("agent-policy-hsm-agent-key-id", "", "key id in the token to sign agent policy with. Empty = adopt the only key the agent holds")
	agentPolicyNextSigningKeyPath := flag.String("agent-policy-next-signing-key", "",
		"Ed25519 signing-key seed (32-byte hex) file for the NEXT policy-signing key. Its PUBLIC key is published in the signed "+
			"trust bundle alongside the current one, so devices can adopt it BEFORE it starts signing — the overlap that makes "+
			"this key rotatable at all (every agent pins one key today, so changing it without an overlap freezes the fleet's "+
			"policy). Empty = publish nothing and keep today's behaviour.")
	agentUpdate := registerAgentUpdateFlags()
	rolloutControl := registerRolloutControlFlags()
	agentPolicySigningKeyPath := flag.String("agent-policy-signing-key", "", "Ed25519 signing-key seed (32-byte hex) file for GET /steer/agent-policy; absent file is generated+persisted. Empty in -lab-mode = ephemeral key; empty in production = signing disabled. The NE pins the public key via the trusted keyring")
	// CP-controlled steering posture (signed, served at GET /steer/agent-policy/posture). These EDGE flags are
	// the central replacement for the AGENT's --fail-open / --region-failover / --fail-open-cooldown startup
	// flags: set the posture here and every device picks it up on its next fetch — no agent re-registration.
	steerFailOpenMode := flag.String("steer-fail-open-mode", "off", "CP-signed steering posture: 'off' (fail-CLOSED absolute; production residency default) or 'terminal' (permit fail-open as the terminal fallback after region exhaustion). Replaces the agent --fail-open flag.")
	steerRegionFailover := flag.Bool("steer-region-failover", false, "CP-signed steering posture: enable "+
		"region-failover on devices. Replaces the agent --region-failover flag. "+
		"★ HONOURED BY THE WINDOWS AGENT: it re-fetches this posture every minute and, while what it holds and "+
		"what the control plane says disagree, it says so on every round and does NOT switch a running data "+
		"path. region-failover and the cooldown are the CP-authoritative axes; the fail-open PERMISSION is not, "+
		"and this flag can neither grant nor revoke it. "+
		"★★★ NOT READ BY THE macOS AGENT (verified 2026-08-31). There, region-failover is a CAPABILITY rather "+
		"than a policy: it runs when the device holds an agent-policy pin and a (T) transport, and is off when "+
		"it does not — regionFailoverEnabled is regionController != nil. So setting this false does NOT stop a "+
		"capable Mac, and an operator who turns it off has turned it off for half a mixed fleet. What a Mac "+
		"may fail over TO is still this deployment's signed region list, so this is a policy that does not "+
		"reach it rather than a residency boundary it can cross.")
	steerFailOpenCooldownMS := flag.Int("steer-fail-open-cooldown-ms", 0, "CP-signed steering posture: fail-open cooldown in milliseconds (0 = agent default).")
	// M7 group-scoped captive tuning served signed via GET /steer/agent-tuning (same signer as agent-policy).
	// These seed a TENANT-scope override; per-group/device scoping is authored via the admin API (future).
	agentTuningCaptiveTimeout := flag.Int("agent-tuning-captive-timeout-sec", 0, "M7: tenant-scope captive T_max (seconds) served signed via GET /steer/agent-tuning; 0 = no override (agent keeps its current value)")
	agentTuningCaptiveProbe := flag.Int("agent-tuning-captive-probe-sec", 0, "M7: tenant-scope captive probe interval (seconds) served via GET /steer/agent-tuning; 0 = no override")
	allowUnsignedAgentPolicy := flag.Bool("allow-unsigned-agent-policy", false, "production escape hatch: permit running WITHOUT an agent-policy signing key (admin-managed steer exclusions are then UNSIGNED and not tamper-resistant). Default false = production refuses to start without -agent-policy-signing-key.")
	adminInviteEmailSink := flag.String("admin-invite-email-sink", "", "lab email sink file: admin activation messages are appended here (no SMTP). Empty = log only")
	agentTargetVersion := flag.String("agent-target-version", "", "target agent version returned by rollout policy API")
	agentReleaseChannel := flag.String("agent-release-channel", "lab", "agent release channel returned by rollout policy API. One of lab | alpha | pilot | stable — the durable store constrains it, so anything else jams every device's report queue")
	searchCursorSigningSecret := flag.String("search-cursor-signing-secret", "", "stable secret for Admin log search cursor HMAC")
	adminToken := flag.String("admin-token", "", "optional admin API token for /admin endpoints")
	edgeAdminAuthStore := flag.String("admin-auth-store", "memory", "admin auth store used by edge admin APIs: memory or postgres")
	edgeAdminAuthPostgresDSN := flag.String("admin-auth-postgres-dsn", "", "PostgreSQL DSN for edge admin-auth-store=postgres; defaults to -postgres-dsn when omitted")
	edgeUsageMeterStore := flag.String("usage-meter-store", "memory", "usage meter store used by edge runtime: memory or postgres")
	edgeUsageMeterPostgresDSN := flag.String("usage-meter-postgres-dsn", "", "PostgreSQL DSN for edge usage-meter-store=postgres; defaults to -postgres-dsn when omitted")
	edgeDeviceStore := flag.String("device-store", "memory", "device inventory store used by edge runtime: memory or postgres")
	edgeDevicePostgresDSN := flag.String("device-postgres-dsn", "", "PostgreSQL DSN for edge device-store=postgres; defaults to -postgres-dsn when omitted")
	edgeAgentTelemetryStore := flag.String("agent-telemetry-store", "memory", "agent telemetry store used by edge runtime and /admin/agent/quality: memory or postgres")
	edgeAgentTelemetryPostgresDSN := flag.String("agent-telemetry-postgres-dsn", "", "PostgreSQL DSN for edge agent-telemetry-store=postgres; defaults to -postgres-dsn when omitted")
	edgeIdentityDirectoryStore := flag.String("identity-directory-store", "memory", "human identity directory store used by edge usage governance: memory or postgres")
	edgeIdentityDirectoryPostgresDSN := flag.String("identity-directory-postgres-dsn", "", "PostgreSQL DSN for edge identity-directory-store=postgres; defaults to -postgres-dsn when omitted")
	edgeNHIRegistryStore := flag.String("nhi-registry-store", "memory", "NHI registry store used by edge admin APIs: memory or postgres")
	edgeNHIRegistryPostgresDSN := flag.String("nhi-registry-postgres-dsn", "", "PostgreSQL DSN for edge nhi-registry-store=postgres; defaults to -postgres-dsn when omitted")
	edgeAccessLogAll := flag.Bool("access-log-all", true, "log EVERY egress decision to the access log — the sovereign-SSE baseline (full forensic record, paired with tier-to-cold retention). Set -access-log-all=false for policy-driven selective logging: only policy actions (deny/authenticate/step-up) + policy-designated categories (AI SaaS) are logged, routine allows of unmarked traffic are dropped.")
	edgeHotStore := flag.String("hot-store", "jsonl", "hot store used by edge admin APIs: jsonl, postgres, or clickhouse")
	applyAIUsageReportFlags := registerAIUsageReportFlags()
	edgeHotStorePostgresDSN := flag.String("hot-store-postgres-dsn", "", "PostgreSQL DSN for edge hot-store=postgres; defaults to -postgres-dsn when omitted")
	edgeHotStoreClickHouseEndpoint := flag.String("hot-store-clickhouse-endpoint", "", "ClickHouse HTTP endpoint for hot-store=clickhouse (e.g. http://clickhouse:8123)")
	edgeHotStoreClickHouseUser := flag.String("hot-store-clickhouse-user", "", "ClickHouse user for hot-store=clickhouse")
	edgeHotStoreClickHousePassword := flag.String("hot-store-clickhouse-password", "", "ClickHouse password for hot-store=clickhouse")
	edgeHotStoreClickHouseDatabase := flag.String("hot-store-clickhouse-database", "dsse", "ClickHouse database for hot-store=clickhouse")
	edgeHotStoreClickHouseTable := flag.String("hot-store-clickhouse-table", "events", "ClickHouse table for hot-store=clickhouse")
	edgeAdminExportJobStore := flag.String("admin-export-job-store", "memory", "export job store used by edge admin APIs: memory or postgres")
	edgeAdminExportJobPostgresDSN := flag.String("admin-export-job-postgres-dsn", "", "PostgreSQL DSN for edge admin-export-job-store=postgres; defaults to -postgres-dsn when omitted")
	edgeAdminExportWorker := flag.String("admin-export-worker", "sync", "admin export worker used by edge API: sync, local-async, or postgres-queue")
	edgeAdminExportQueuePostgresDSN := flag.String("admin-export-queue-postgres-dsn", "", "PostgreSQL DSN for edge admin-export-worker=postgres-queue; defaults to -postgres-dsn when omitted")
	adminExportDirectAuditJSONL := flag.Bool("admin-export-direct-audit-jsonl", true, "write admin export lifecycle audit events directly to audit.log.jsonl after transactional PostgreSQL outbox commit")
	edgeDomainEventOutbox := flag.String("domain-event-outbox", "disabled", "domain event outbox mirror used by edge API: disabled or postgres")
	edgeDomainEventOutboxPostgresDSN := flag.String("domain-event-outbox-postgres-dsn", "", "PostgreSQL DSN for edge domain-event-outbox=postgres; defaults to -postgres-dsn when omitted")
	postgresDSN := flag.String("postgres-dsn", "", "PostgreSQL DSN for postgres-export-worker mode")
	retentionPollInterval := flag.Duration("retention-poll", time.Hour, "interval to prune aged log/outbox rows (postgres tables; control plane). 0 disables.")
	hotEventsRetention := flag.Duration("hot-events-retention", 720*time.Hour, "delete hot_events older than this (0 = keep forever). Default 30d.")
	outboxPublishedRetention := flag.Duration("outbox-published-retention", 720*time.Hour, "delete PUBLISHED outbox rows older than this (0 = keep). Default 30d.")
	outboxDeadRetention := flag.Duration("outbox-dead-retention", 336*time.Hour, "delete DEAD outbox rows older than this (0 = keep). Default 14d.")
	// Sovereign cold-archive (S3-compatible; NOT AWS). The retention lifecycle tiers aged log segments here
	// instead of deleting them. Endpoint is host:port of a self-hosted MinIO/Ceph (default target) or an in-country
	// provider — never an AWS ARN/URL. Empty endpoint = disabled (prune still deletes; no cold tier).
	coldArchiveEndpoint := flag.String("cold-archive-endpoint", "", "S3-compatible cold-archive endpoint host:port (e.g. minio:9000). Empty = disabled. NOT AWS — self-hosted MinIO/Ceph or an in-country provider.")
	coldArchiveBucket := flag.String("cold-archive-bucket", "", "cold-archive bucket (should be object-lock-enabled for WORM)")
	coldArchiveAccessKey := flag.String("cold-archive-access-key", "", "cold-archive S3 access key")
	coldArchiveSecretKey := flag.String("cold-archive-secret-key", "", "cold-archive S3 secret key")
	coldArchiveRegion := flag.String("cold-archive-region", "", "cold-archive S3 region (optional; most self-hosted stores ignore it)")
	coldArchiveUseSSL := flag.Bool("cold-archive-use-ssl", false, "use TLS to the cold-archive endpoint")
	auditColdRetention := flag.Duration("audit-cold-retention", 8760*time.Hour, "WORM object-lock retention for archived AUDIT-stream segments (tamper-proof). Default 365d. 0 = no lock. Requires an object-lock-enabled bucket.")
	hotEventsRetentionOverrides := flag.String("hot-events-retention-overrides", "audit=8760h,human_approval_events=8760h,delegated_access_grants=8760h", "per-stream hot-events retention overrides (comma list of stream=duration); a stream not listed uses -hot-events-retention. Keep compliance streams (audit/approvals/grants) longer than access. 0 keeps a stream forever.")
	legalHoldStorePath := flag.String("legal-hold-store", "", "durable JSON store for legal holds (litigation/e-discovery). A held tenant's logs are preserved (retention frozen) until released; survives restart. Empty = in-memory only.")
	auditChainStorePath := flag.String("audit-chain-store", "", "durable JSON store for the audit cold-archive tamper-evident hash chain (per-tenant running state). Empty = in-memory only. Requires -cold-archive-endpoint.")
	retentionOverrideStorePath := flag.String("retention-override-store", "", "durable JSON store for admin-configured per-stream retention (Console); overrides -hot-events-retention* at runtime without a redeploy. Empty = in-memory only.")
	// Audit/persistence decoupling: ship audit/access records to a SEPARATE audit/control plane (which owns
	// Postgres + durable outbox). Best-effort, non-blocking; the local jsonl stays canonical. Empty = off.
	auditIngestURL := flag.String("audit-ingest-url", "", "control-plane audit-ingest endpoint; the Edge ships audit/access records there best-effort over HTTPS (empty = off; local jsonl only)")
	auditIngestToken := flag.String("audit-ingest-token", "", "bearer token for the audit-ingest endpoint")
	tenantTransportAuthorityStore, tenantTransportMaterialTTL, tenantTransportMaterialFromCP := registerTenantTransportMaterialFlags()
	tenantInterceptionAuthorityStore := registerTenantInterceptionAuthorityFlag()
	tenantDeviceAuthorityStore := registerTenantDeviceAuthorityFlag()
	mintOperatorCredential, mintOperatorCredentialTTL, mintOperatorCredentialLabel := registerOperatorBootstrapFlags()
	auditIngestCA := flag.String("audit-ingest-ca", "", "PEM CA file pinning the audit-ingest endpoint's TLS cert (empty = system roots)")
	auditIngestIdentity := registerAuditIngestIdentityFlags()
	adminBreakGlassFlagSet := registerAdminBreakGlassFlags()
	// Control-plane side: when set, register POST /audit-ingest to RECEIVE + persist audit/events shipped by
	// enforcement Edges (bearer = this token). Empty = no receiver (the Edge data plane has none).
	auditIngestReceiverToken := flag.String("audit-ingest-receiver-token", "", "bearer token the control plane requires on POST /audit-ingest (enables the audit receiver)")
	// Audit/persistence decoupling: durable outbox delivery/management is the control plane's, not the Edge's.
	// Off by default; set to keep the legacy embedded outbox admin endpoints on this Edge (transitional).
	embeddedOutboxAdmin := flag.Bool("embedded-outbox-admin", false, "register the legacy embedded /admin/(audit|domain-event)-outbox/* endpoints on this Edge (transitional; default off — durable outbox is the audit/control plane's responsibility)")
	postgresRunMigrations := flag.Bool("postgres-run-migrations", true, "apply component-scoped PostgreSQL migrations before starting a PostgreSQL-backed mode")
	workerTenantID := flag.String("worker-tenant-id", "", "tenant id consumed by postgres-export-worker; defaults to policy bundle tenant_id")
	workerID := flag.String("worker-id", "export-worker-local-001", "worker id used for PostgreSQL queue lease ownership")
	workerHotStore := flag.String("worker-hot-store", "jsonl", "hot store used by postgres-export-worker: jsonl or postgres")
	workerPollInterval := flag.Duration("worker-poll-interval", 250*time.Millisecond, "PostgreSQL export worker poll interval")
	workerLeaseDuration := flag.Duration("worker-lease-duration", 30*time.Second, "PostgreSQL export worker lease duration")
	workerLeaseExtensionInterval := flag.Duration("worker-lease-extension-interval", 0, "PostgreSQL export worker lease extension interval; defaults to half of lease duration")
	workerTimeout := flag.Duration("worker-timeout", time.Duration(defaultAdminExportWorkerTimeoutSeconds)*time.Second, "PostgreSQL export worker per-task timeout")
	auditPublisherID := flag.String("audit-publisher-id", "audit-publisher-local-001", "publisher id used for PostgreSQL admin audit outbox publishing")
	auditPublisherPollInterval := flag.Duration("audit-publisher-poll-interval", 250*time.Millisecond, "PostgreSQL admin audit outbox publisher poll interval")
	auditPublisherBatchSize := flag.Int("audit-publisher-batch-size", 100, "PostgreSQL admin audit outbox publisher batch size")
	auditPublisherLockDuration := flag.Duration("audit-publisher-lock-duration", time.Minute, "PostgreSQL admin audit outbox publisher lock duration")
	auditPublisherRetryDelay := flag.Duration("audit-publisher-retry-delay", 30*time.Second, "PostgreSQL admin audit outbox publisher retry delay after delivery failure")
	auditPublisherMaxAttempts := flag.Int("audit-publisher-max-attempts", 5, "PostgreSQL admin audit outbox publisher max attempts before marking a row dead")
	auditPublisherDelivery := flag.String("audit-publisher-delivery", "jsonl", "PostgreSQL admin audit outbox delivery mode: jsonl or webhook")
	auditPublisherWebhookURL := flag.String("audit-publisher-webhook-url", "", "HTTP endpoint for audit-publisher-delivery=webhook")
	auditPublisherWebhookToken := flag.String("audit-publisher-webhook-token", "", "optional bearer token for audit-publisher-delivery=webhook")
	auditPublisherWebhookSecret := flag.String("audit-publisher-webhook-signing-secret", "", "optional HMAC-SHA256 signing secret for audit-publisher-delivery=webhook")
	auditPublisherWebhookKeyID := flag.String("audit-publisher-webhook-signing-key-id", "", "optional HMAC signing key id header for audit-publisher-delivery=webhook")
	auditPublisherWebhookTimeout := flag.Duration("audit-publisher-webhook-timeout", 10*time.Second, "HTTP timeout for audit-publisher-delivery=webhook")
	domainEventPublisherID := flag.String("domain-event-publisher-id", "domain-event-publisher-local-001", "publisher id used for PostgreSQL domain event outbox publishing")
	domainEventPublisherPlane := flag.String("domain-event-publisher-plane", "domain", "event plane consumed by postgres-domain-event-publisher: domain, access, or evidence")
	domainEventPublisherPollInterval := flag.Duration("domain-event-publisher-poll-interval", 250*time.Millisecond, "PostgreSQL domain event outbox publisher poll interval")
	domainEventPublisherBatchSize := flag.Int("domain-event-publisher-batch-size", 100, "PostgreSQL domain event outbox publisher batch size")
	domainEventPublisherLockDuration := flag.Duration("domain-event-publisher-lock-duration", time.Minute, "PostgreSQL domain event outbox publisher lock duration")
	domainEventPublisherRetryDelay := flag.Duration("domain-event-publisher-retry-delay", 30*time.Second, "PostgreSQL domain event outbox publisher retry delay after delivery failure")
	domainEventPublisherMaxAttempts := flag.Int("domain-event-publisher-max-attempts", 5, "PostgreSQL domain event outbox publisher max attempts before marking a row dead")
	domainEventPublisherDelivery := flag.String("domain-event-publisher-delivery", "jsonl", "PostgreSQL domain event outbox delivery mode: jsonl, objectstore, or webhook")
	domainEventPublisherWebhookURL := flag.String("domain-event-publisher-webhook-url", "", "HTTP endpoint for domain-event-publisher-delivery=webhook")
	domainEventPublisherWebhookToken := flag.String("domain-event-publisher-webhook-token", "", "optional bearer token for domain-event-publisher-delivery=webhook")
	domainEventPublisherWebhookSecret := flag.String("domain-event-publisher-webhook-signing-secret", "", "optional HMAC-SHA256 signing secret for domain-event-publisher-delivery=webhook")
	domainEventPublisherWebhookKeyID := flag.String("domain-event-publisher-webhook-signing-key-id", "", "optional HMAC signing key id header for domain-event-publisher-delivery=webhook")
	domainEventPublisherWebhookTimeout := flag.Duration("domain-event-publisher-webhook-timeout", 10*time.Second, "HTTP timeout for domain-event-publisher-delivery=webhook")
	// optional per-client rate limit on the /auth + /admin surfaces (0 = disabled). Default
	// off so it never affects tests/lab; production should enable it (e.g. -admin-rate-limit-rps 20).
	adminRateLimitRPS := flag.Float64("admin-rate-limit-rps", 0, "per-client requests/sec for /auth and /admin endpoints (0 = disabled)")
	adminRateLimitBurst := flag.Float64("admin-rate-limit-burst", 0, "per-client burst for /auth + /admin rate limiting (0 = use rps)")
	rateLimitTrustedProxiesFlag := flag.String("rate-limit-trusted-proxies", "", "comma-separated trusted front-proxy/LB IPs or CIDRs. When set, the rate limiter keys on the rightmost non-proxy X-Forwarded-For entry for connections FROM these proxies (so clients behind a LB don't all collapse to the LB's IP). Empty = X-Forwarded-For ignored (RemoteAddr only, spoof-safe)")
	domainEventPublisherPostgresDSN := flag.String("domain-event-publisher-postgres-dsn", "", "PostgreSQL DSN for postgres-domain-event-publisher mode; defaults to -postgres-dsn when omitted")
	pprofListen := flag.String("pprof-listen", "", "DIAGNOSTIC ONLY: serve net/http/pprof on this addr (e.g. 0.0.0.0:6060) to profile CPU/heap under load. Empty = off. Never enable on a production/public listener — pprof is unauthenticated.")
	stateDir := flag.String("state-dir", "", "durable state directory for OPERATOR-CONFIG stores (Named Networks, connectors, admin accounts, exclusions, device/NHI/identity inventory, …). When set, every config-bearing store persists to ‹state-dir›/‹store›.json BY DEFAULT — no per-store -*-store flag needed, and a store added later inherits durability instead of defaulting to memory. A per-store flag still OVERRIDES the path or selects =postgres. Empty = legacy per-store behaviour (a store with no flag stays in-memory and is LOST on restart). On the zero-DB reference Edge point this at the shared mount, e.g. /dataplane-ne.")
	// -version must work without depending on the rest of this (very large) flag set parsing cleanly, so it is
	// handled before Parse and exits immediately.
	if handleVersionFlag() {
		return
	}
	flag.Parse()

	// ★ the enrolment fold: the document handed to every new device must name one agent-facing port. Said here, at start-up,
	// because it was true for a day and only a code comment knew — see
	// the_configuration_handed_to_an_agent_names_one_port.go.
	warnIfTheAgentConfigurationNamesAnotherPort(*networkExtensionRuntimeCopyEdgeURL, *transportTLSListen)

	// Which DNS suffix this deployment's per-organization names sit under. Declared here rather than inside the
	// Edge's own start-up, because the organization whose name is minted is created on the CONTROL PLANE and
	// that process never reaches the Edge-only block — see organization_id_is_not_a_name.go.
	declareDeploymentNameSuffix(*deploymentNameSuffixFlag, *renewalRecoverySNI)

	// ★★★ A COMMAND, RUN BEFORE ANY OF THE SERVER'S PRECONDITIONS (2026-08-20). -mint-operator-credential
	// writes one record and exits: it carries no traffic, holds no config, and joins no fleet. Placed later it
	// met the checks that exist to stop an ENFORCING Edge from running on its own truth — no control plane, a
	// default connector secret — and each one would have needed an exemption, until the command was a server
	// wearing a disguise. It opens its own connection to the credential store and closes the process.
	if *mintOperatorCredential {
		dsn := strings.TrimSpace(*edgeAdminAuthPostgresDSN)
		if dsn == "" {
			dsn = strings.TrimSpace(*postgresDSN)
		}
		store, closeStore, serr := setupEdgeAdminAuthStore(context.Background(), edgeAdminAuthStoreConfig{
			Mode: *edgeAdminAuthStore, DSN: dsn, MigrationDir: *migrationDir, RunMigrations: *postgresRunMigrations,
		})
		if serr != nil {
			log.Fatalf("mint-operator-credential: open the credential store: %v", serr)
		}
		defer closeStore()
		writer, _ := store.(adminAuthTokenWriter)
		runOperatorBootstrapAndExit(context.Background(), operatorBootstrapDeps{
			OperatorTenantID: strings.TrimSpace(*operatorTenantID),
			Store:            writer,
			Now:              time.Now,
		}, *mintOperatorCredentialTTL, *mintOperatorCredentialLabel)
	}
	// Log the build identity FIRST. Every other startup line is easier to interpret when the log says which
	// binary produced it, and an incident starts with "what is running?".
	log.Printf("starting %s", versionString())
	log.Print(applyCPUHeadroom(*cpuHeadroomCoresFlag))
	log.Print(setConnectorMTLSPresentationRelaxed(*connectorMTLSNotRequiredFlag, *devMode))
	applyAIUsageReportFlags()
	// ★ UNCONDITIONALLY, AND BEFORE ANY MODE BRANCH. The first version sat inside `if *mode == "edge"`, which
	// would have left the break-glass unconfigured — and therefore permanently inert — on the CONTROL PLANE,
	// the one node whose admin API everything else depends on. A credential whose arming depends on which
	// branch of a mode switch you took is not armed.
	//
	// The second argument is the fact that decides how bad the disarmed case is: whether anything ELSE can
	// authenticate here. A node with a durable auth store has named credentials; a node without one and a
	// disarmed token has nothing.
	configureAdminBreakGlass(*adminToken, *adminBreakGlassFlagSet.armed,
		!strings.EqualFold(strings.TrimSpace(*edgeAdminAuthStore), "memory"))
	requireControlPlaneOrExit(*mode, *isControlPlane, *configSourceURL, *configSourceEndpoints, *noControlPlane)
	// Only a CONTROL PLANE aggregates fleet config status; an Edge reports and does not collect. Sized from the
	// CP's own poll interval so a deliberately slow-polling deployment does not paint its own fleet red.
	var fleetConfigStatus *fleetConfigStatusStore
	if *isControlPlane {
		fleetConfigStatus = newFleetConfigStatusStore(*configSourcePoll)
	}
	// ★★ THE SHARED DATABASE IS OPENED FIRST, BECAUSE THE STORE DEFAULTS DEPEND ON IT (2026-08-21). It used to
	// be opened several hundred lines below, which was invisible while an unset store meant "a file": the
	// stores resolved before it simply got paths. The moment an unset store means "share it", those same
	// call sites resolved to "postgres" with no handle yet and the node refused to start —
	// "asset_catalog-store=postgres+import:… requires -postgres-dsn", measured on region-b and the control
	// plane within a minute of the change. Shared state is foundational; it is opened before anything asks
	// for it.
	var cpStateBlobDBErr error
	cpStateBlobDB, cpStateBlobDBErr = newCPStateBlobDB(*postgresDSN, *migrationDir, true)
	if cpStateBlobDBErr != nil {
		log.Fatalf("open CP-state blob store: %v", cpStateBlobDBErr)
	}
	if cpStateBlobDB != nil {
		defer cpStateBlobDB.Close()
	}

	// With a shared database, a store this node holds NO copy of follows the fleet rather than starting from an
	// empty per-node one. See durableStorePath for why the rule is this narrow.
	sharedStateDSNConfigured = cpStateBlobDB != nil

	// Durable-by-default (design/): resolve every CONFIG store's backend from -state-dir before use, so
	// the safe path is the default path. An explicit -‹x›-store (a path or "postgres") always wins; only an unset
	// or "memory" store is redirected to the state dir. With no -state-dir this is a no-op (legacy behaviour).
	// The store name becomes the file name, so a NEW config store is durable the moment it reads the state dir.
	*firstPartyStore = durableStorePath(*stateDir, *firstPartyStore, "first_party_credentials")
	*edgeDeviceStore = durableStorePath(*stateDir, *edgeDeviceStore, "device_inventory")
	*edgeNHIRegistryStore = durableStorePath(*stateDir, *edgeNHIRegistryStore, "nhi_registry")
	*edgeIdentityDirectoryStore = durableStorePath(*stateDir, *edgeIdentityDirectoryStore, "identity_directory")
	*steerExclusionStoreMode = durableStorePath(*stateDir, *steerExclusionStoreMode, "steer_exclusions")
	*dnsPolicyStorePath = durableStorePath(*stateDir, *dnsPolicyStorePath, "dns_policy")
	*renewBeforeStorePath = durableStorePath(*stateDir, *renewBeforeStorePath, "renew_before")
	*transportAnchorAckStorePath = durableStorePath(*stateDir, *transportAnchorAckStorePath, "transport_anchor_acks")
	*highRiskStore = durableStorePath(*stateDir, *highRiskStore, "high_risk_devices")
	// A kill-switch that silently un-revokes on a restart is a security regression, so the admission-revocation
	// set — and the cross-region mesh OUTBOX of pending pushes — are durable-by-default off the state dir (parity
	// with high_risk_devices), not only when the operator remembers the explicit flag.
	*admissionRevocationStore = durableStorePath(*stateDir, *admissionRevocationStore, "admission_revocations")
	*enrolmentTokenStore = durableStorePath(*stateDir, *enrolmentTokenStore, "enrolment_tokens")
	// ★ The authored rule set and the catalog it REFERENCES, added 2026-08-10 — both were missing here, so
	// -state-dir did not mean what its own help text says ("every config-bearing store persists BY DEFAULT").
	//
	// The pair matters more than either alone. On the reference control plane -policy-rule-store was set
	// explicitly and -asset-catalog-store was not, so a CP restart kept every authored rule and dropped the
	// endpoints those rules name. Now that the CP is the authority for rules, that state gets DISTRIBUTED: an
	// egress bypass whose destination resolves to nothing goes inert, and an east-west rule with an empty
	// selector is treated as a WILDCARD. A restart would have quietly widened per-hop authorization fleet-wide.
	*policyRuleStorePath = durableStorePath(*stateDir, *policyRuleStorePath, "policy_rules")
	// ★★★ SIX MORE, AND THE PROMISE IS WHY THEY WERE MISSING (2026-08-24). -state-dir's help says "every
	// config-bearing store persists ... BY DEFAULT — no per-store flag needed, and a store added later
	// inherits durability instead of defaulting to memory". It covered 27 of them. The rest stayed in memory
	// unless somebody named them, and the sentence above is what stopped anybody looking.
	//
	// Measured consequence, one store away from these: the Site catalogue was uncovered, so a generated
	// control plane held it in memory, published complete=false on every config bundle for ever, and every
	// Edge held zero Sites — a connector presenting its bootstrap secret was refused with "the bootstrap
	// secret is not this Site's", which is true and three components away from the missing flag.
	//
	// These six are the ones whose flag help says "durable JSON store ... Empty = in-memory only": a path, so
	// -state-dir can give them one. The stores that select a BACKEND (memory|postgres|clickhouse) cannot be
	// defaulted to a path and are named by the installer instead.
	*auditChainStorePath = durableStorePath(*stateDir, *auditChainStorePath, "audit_chain")
	*deviceClientCAStorePath = durableStorePath(*stateDir, *deviceClientCAStorePath, "device_client_cas")
	*inspectionPostureStorePath = durableStorePath(*stateDir, *inspectionPostureStorePath, "inspection_posture")
	*legalHoldStorePath = durableStorePath(*stateDir, *legalHoldStorePath, "legal_holds")
	*retentionOverrideStorePath = durableStorePath(*stateDir, *retentionOverrideStorePath, "retention_overrides")
	agentUpdatesStorePath, agentRolloutStorePath := agentReleaseStores.updates, agentReleaseStores.rollout
	*agentUpdatesStorePath = durableStorePath(*stateDir, *agentUpdatesStorePath, "agent_updates")
	*agentRolloutStorePath = durableStorePath(*stateDir, *agentRolloutStorePath, "agent_rollout")
	// "memory" only survives here when there is no -state-dir at all, and it means what it says. Left as a
	// value it would be resolved as a FILE NAME, which is the silent-empty-store failure one directory over.
	for _, v := range []*string{agentUpdatesStorePath, agentRolloutStorePath} {
		if strings.TrimSpace(*v) == "memory" {
			*v = ""
		}
	}
	*transportTrustStorePath = durableStorePath(*stateDir, *transportTrustStorePath, "transport_trust")
	*assetCatalogStorePath = durableStorePath(*stateDir, *assetCatalogStorePath, "asset_catalog")
	// The remaining OPERATOR-CONFIG stores the durability contract reports on. They were protected only by the
	// startup gate — unset meant "refuse to boot", which is loud but is NOT what -state-dir's help text says
	// ("every config-bearing store persists BY DEFAULT ... a store added later inherits durability"). Every
	// reference deployment names them by hand, so this changes nothing that runs today (an explicit path or
	// =postgres still wins); it makes the promise true for anyone who sets only -state-dir, and it is the
	// mechanism that stops the NEXT store from being added without durability. File names match what the
	// reference compose already passes, so a deployment that drops its explicit flags keeps its data.
	*applicationCatalogStorePath = durableStorePath(*stateDir, *applicationCatalogStorePath, "application_catalog")
	*breakGlassStorePath = durableStorePath(*stateDir, *breakGlassStorePath, "break_glass")
	*edgeConnectorRegistryStore = durableStorePath(*stateDir, *edgeConnectorRegistryStore, "connector_registry")
	*delegatedGrantStorePath = durableStorePath(*stateDir, *delegatedGrantStorePath, "delegated_grants")
	*enrolledInventoryStore = durableStorePath(*stateDir, *enrolledInventoryStore, "enrolled_inventory")
	*grantStorePath = durableStorePath(*stateDir, *grantStorePath, "grants")
	*humanApprovalStorePath = durableStorePath(*stateDir, *humanApprovalStorePath, "human_approvals")
	*idpConnectionStorePath = durableStorePath(*stateDir, *idpConnectionStorePath, "idp_connections")
	*tenantModelStorePath = durableStorePath(*stateDir, *tenantModelStorePath, "tenant_model")
	*vlanObjectStorePath = durableStorePath(*stateDir, *vlanObjectStorePath, "vlan_objects")
	*adminRuntimeStateStorePath = durableStorePath(*stateDir, *adminRuntimeStateStorePath, "admin_runtime_state")
	// Which certificate each device was last handed is a MEASUREMENT, and a measurement that resets on restart
	// reports a finished rotation as one still waiting for devices that already took it (review C6).
	if p := durableStorePath(*stateDir, "", "server_cert_adoption"); p != "" {
		servedCertSightings.load(p)
	}
	// Refusals are NOT telemetry that re-arrives on the next poll. A device empties its journal once we accept
	// it, so anything lost here is lost for good — and a restart is what happens during a certificate
	// incident. Durable by default, independent of -observed-exclusion-store's mode.
	trustRefusals = newTrustRefusalStore(durableStorePath(*stateDir, "", "trust_refusals"))
	// The interception journal 0.2.21 ships — kept in its own store for the reason on the variable.
	interceptionRefusals = newTrustRefusalStore(durableStorePath(*stateDir, "", "interception_refusals"))
	*seatAllocationStore = durableStorePath(*stateDir, *seatAllocationStore, "seat_allocations")
	*licenseStorePath = durableStorePath(*stateDir, *licenseStorePath, "vendor_license")
	*revocationMeshOutboxStore = durableStorePath(*stateDir, *revocationMeshOutboxStore, "revocation_mesh_outbox")
	// Surface a dropped save from any durable CONFIG store: a swallowed save is invisible (the API returns 200,
	// the operator believes it saved) and loses the config on the next restart — the recurring bug, recreated
	// while looking fixed. Each store keeps serving from memory; this only makes the failure loud.
	devicestore.OnPersistError = func(err error) {
		logErrorf("device_store_save_failed: %v — device inventory will NOT survive a restart", err)
	}
	nhi.OnPersistError = func(err error) {
		logErrorf("nhi_registry_save_failed: %v — NHI registry will NOT survive a restart", err)
	}
	humanidentity.OnPersistError = func(err error) {
		logErrorf("identity_directory_save_failed: %v — identity directory will NOT survive a restart", err)
	}
	steerexclusion.OnPersistError = func(err error) {
		logErrorf("steer_exclusion_save_failed: %v — steer exclusions will NOT survive a restart", err)
	}
	connectorRouteGovPersistPath = strings.TrimSpace(*connectorRouteGovernanceStorePath) // shared+durable governance decisions (HA)
	connectorRouteCPConfigured = *connectorRoutesCPConfigured                            // corrected CP-configured route model (discovery not routable until adopted)
	accessLogAllDecisions = *edgeAccessLogAll                                            // baseline: log every egress decision; -access-log-all=false opts into selective logging
	// Diagnostic pprof endpoint (off by default). net/http/pprof registers on http.DefaultServeMux via its
	// init; this serves that mux on the requested addr so `go tool pprof` can capture a CPU profile while a
	// load test runs. Lab-only — gated behind a flag and meant for a loopback/LAN debug, not production.
	if addr := strings.TrimSpace(*pprofListen); addr != "" {
		// Production guard: pprof is UNAUTHENTICATED and exposes heap/CPU/goroutine internals. In production it
		// must bind loopback only (operators port-forward to it); a non-loopback bind would be a public,
		// unauthenticated profiling surface. Lab may bind anywhere.
		if !*devMode {
			if host, _, err := net.SplitHostPort(addr); err != nil || net.ParseIP(strings.TrimSpace(host)) == nil || !net.ParseIP(strings.TrimSpace(host)).IsLoopback() {
				log.Fatalf("pprof listener %q must be loopback (127.0.0.1/::1) outside -lab-mode — it is unauthenticated; port-forward to reach it", addr)
			}
		}
		go func() {
			log.Printf("pprof diagnostic listener on %s (net/http/pprof)", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("pprof listener %s exited: %v", addr, err)
			}
		}()
	}
	if *mode == "edge" {
		// ★★★ EVERY PROBLEM AT ONCE, NOT ONE PER RESTART (2026-09-05, measured by starting this Edge as
		// somebody who had never seen it). These six checks used to run in a row, each log.Fatalf-ing on the
		// first failure. A first run outside lab-mode therefore took SEVEN attempts: change the connector
		// secret, lengthen it, lengthen the admin token, require connector runtime secrets, supply an
		// attestation secret, choose a nonce store — one restart each, and no way to know how many were left.
		//
		// Every one of these requirements is right. Discovering them one at a time is not: it reads as a
		// product that dislikes you, and it hides the shape of what is actually being asked for, which is
		// "this is what running outside lab-mode costs".
		problems := []string{}
		add := func(what string, err error) {
			if err != nil {
				problems = append(problems, what+": "+err.Error())
			}
		}
		add("connector secret", validateEdgeRuntimeSecretConfig(*devMode, *connectorSecret))
		add("admin token", validateAdminTokenConfig(*devMode, *adminToken))
		add("admin listen address", validateAdminListenAddr(*adminListen))
		add("connector runtime secrets", validateConnectorRuntimeSecretRequiredConfig(*devMode, *edgeConnectorRegistryStore, *requireConnectorRuntimeSecret))
		add("workload attestation secret", validateWorkloadAttestationSecretConfig(*devMode, *connectorSecret, *workloadAttestationSecret))
		add("workload attestation nonce store", validateWorkloadAttestationNonceStoreConfig(*devMode, *workloadAttestationNonceStore, *allowEphemeralNonceStore))
		if !*devMode && strings.EqualFold(strings.TrimSpace(*workloadAttestationNonceStore), "memory") && *allowEphemeralNonceStore {
			log.Printf("WARNING: in-memory workload-attestation-nonce-store in production — PER-INSTANCE replay protection only (an HA fleet should use postgres / the control plane)")
		}
		if len(problems) > 0 {
			log.Printf("REFUSING TO START: %d configuration problem(s). All of them, so this takes one more "+
				"attempt rather than %d:", len(problems), len(problems))
			for i, p := range problems {
				log.Printf("  %d. %s", i+1, p)
			}
			// ★ AND WHAT THEY HAVE IN COMMON, because six separate sentences do not add up to the one fact
			// behind them on their own.
			if !*devMode {
				log.Printf("  Every one of these is a requirement of running OUTSIDE -lab-mode. If this is a " +
					"first look at the product rather than a deployment, -lab-mode supplies them all and says so.")
			}
			log.Fatalf("edge configuration is not usable")
		}
	}
	hotstore.ConfigureSearchCursorSigningSecret(*searchCursorSigningSecret)

	policyPaths := splitPaths(*policyPath)
	if err := validateInputSchemas(*schemaDir, policyPaths, *bundlePath); err != nil {
		log.Fatalf("validate schema: %v", err)
	}

	policies, err := policy.LoadMany(policyPaths)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	pb, err := bundle.Load(*bundlePath)
	if err != nil {
		log.Fatalf("load policy bundle: %v", err)
	}
	writer, err := logs.NewWriter(*logDir)
	if err != nil {
		log.Fatalf("create log writer: %v", err)
	}
	// Bound the JSONL logs so they cannot grow until the disk fills (production hardening). Default on.
	writer.SetRotation(*logRotateMaxBytes, *logRotateMaxBackups, *logRotateGzip)
	// Which node this is, stamped into every device-state change so a fleet-wide reader can say WHERE a device
	// is steering rather than only whether the node it asked has seen it.
	deviceRuntimeEdgeID = strings.TrimSpace(*edgeRegionID) + "/" + strings.TrimSpace(*edgeClusterID)
	edgeRuntimeRegionID = strings.TrimSpace(*edgeRegionID)
	if *logRotateMaxBytes > 0 {
		log.Printf("jsonl log rotation ENABLED (max_bytes=%d max_backups=%d gzip=%t)", *logRotateMaxBytes, *logRotateMaxBackups, *logRotateGzip)
	}
	// tenant isolation: physically partition the per-tenant logs on disk (tenants/<tenant>/<file>),
	// so a tenant's audit/access records are never co-mingled with another's. ReadJSONL aggregates the
	// partitions for operator-wide reads; tenant-scoped reads use ReadJSONLTenant.
	writer.SetTenantPartitionedFiles("access.log.jsonl", "audit.log.jsonl", "device_state.log.jsonl")
	// Persist device-state CHANGE events (OS / logged-in user / posture changed) to the device_state stream — the
	// endpointRuntimeStore emits only on a change, so this records transitions (→ Postgres via the hot store),
	// not every heartbeat. In-memory state stays for live reads; Postgres holds the durable change history.
	deviceStateChangeEmit = func(event map[string]any) {
		if err := writer.Append("device_state.log.jsonl", event); err != nil {
			log.Printf("device_state change append failed: %v", err)
		}
	}
	exportObjectStore, err := objectstore.NewLocalStore(*logDir)
	if err != nil {
		log.Fatalf("create export object store: %v", err)
	}

	evaluator := decision.Evaluator{
		Policies:      policies,
		PolicyBundle:  pb,
		EdgeRegionID:  *edgeRegionID,
		EdgeClusterID: *edgeClusterID,
	}

	var adminHotStore hotstore.Store
	var hotStoreMirrorMonitor *hotStoreAppendMirrorMonitor
	closeAdminHotStore := func() error { return nil }
	var connectorRegistry connectorRegistryStore
	closeConnectorRegistry := func() error { return nil }
	var adminExportJobs adminExportJobAdminStore
	closeAdminExportJobs := func() error { return nil }
	var configuredAdminExportWorker adminExportWorker
	var adminAuditOutbox adminAuditOutboxDeadReader
	closeAdminExportWorker := func() error { return nil }
	var adminAuthStore adminAuthRuntimeStore
	closeAdminAuthStore := func() error { return nil }
	var usageMeters usagemeter.UsageMeterRuntimeStore
	closeUsageMeterStore := func() error { return nil }
	var deviceInventory deviceRuntimeStore
	closeDeviceInventory := func() error { return nil }
	var agentTelemetry agenttelemetry.RuntimeStore
	closeAgentTelemetry := func() error { return nil }
	var humanIdentities humanidentity.HumanIdentityDirectoryRuntimeStore
	closeHumanIdentities := func() error { return nil }
	var workloadAttestations runtimeWorkloadAttestationNonceStore
	closeWorkloadAttestations := func() error { return nil }
	var nhiRegistry nhi.RuntimeStore
	closeNHIRegistryStore := func() error { return nil }
	var domainEventOutbox domainEventOutboxWriter
	var domainEventOutboxMirrorMonitor *domainEventOutboxMirrorMonitor
	closeDomainEventOutbox := func() error { return nil }
	if *mode == "edge" {
		connectorRegistryDSN := strings.TrimSpace(*edgeConnectorRegistryPostgresDSN)
		if connectorRegistryDSN == "" {
			connectorRegistryDSN = *postgresDSN
		}
		connectorRegistry, closeConnectorRegistry, err = setupEdgeConnectorRegistryStore(context.Background(), edgeConnectorRegistryStoreConfig{
			Mode:          *edgeConnectorRegistryStore,
			DSN:           connectorRegistryDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup connector registry store: %v", err)
		}
		defer closeConnectorRegistry()
		// A dropped save means the fleet silently vanishes at the next restart — the exact outage the durable
		// store exists to prevent. Surface it; do not fail the registration (the registry is already serving).
		connector.OnPersistError = func(perr error) {
			logErrorf("connector_registry_save_failed: %v — registered connectors will NOT survive a restart", perr)
		}
		adminAuthDSN := strings.TrimSpace(*edgeAdminAuthPostgresDSN)
		if adminAuthDSN == "" {
			adminAuthDSN = *postgresDSN
		}
		adminAuthStore, closeAdminAuthStore, err = setupEdgeAdminAuthStore(context.Background(), edgeAdminAuthStoreConfig{
			Mode:          *edgeAdminAuthStore,
			DSN:           adminAuthDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup admin auth store: %v", err)
		}
		defer closeAdminAuthStore()
		usageMeterDSN := strings.TrimSpace(*edgeUsageMeterPostgresDSN)
		if usageMeterDSN == "" {
			usageMeterDSN = *postgresDSN
		}
		usageMeters, closeUsageMeterStore, err = setupEdgeUsageMeterStore(context.Background(), edgeUsageMeterStoreConfig{
			Mode:          *edgeUsageMeterStore,
			DSN:           usageMeterDSN,
			SpoolDir:      writer.Dir(),
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup usage meter store: %v", err)
		}
		defer closeUsageMeterStore()
		deviceDSN := strings.TrimSpace(*edgeDevicePostgresDSN)
		if deviceDSN == "" {
			deviceDSN = *postgresDSN
		}
		deviceInventory, closeDeviceInventory, err = setupEdgeDeviceStore(context.Background(), edgeDeviceStoreConfig{
			Mode:          *edgeDeviceStore,
			DSN:           deviceDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup device inventory store: %v", err)
		}
		defer closeDeviceInventory()
		agentTelemetryDSN := strings.TrimSpace(*edgeAgentTelemetryPostgresDSN)
		if agentTelemetryDSN == "" {
			agentTelemetryDSN = *postgresDSN
		}
		agentTelemetry, closeAgentTelemetry, err = setupEdgeAgentTelemetryStore(context.Background(), edgeAgentTelemetryStoreConfig{
			Mode:          *edgeAgentTelemetryStore,
			DSN:           agentTelemetryDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup agent telemetry store: %v", err)
		}
		defer closeAgentTelemetry()
		identityDirectoryDSN := strings.TrimSpace(*edgeIdentityDirectoryPostgresDSN)
		if identityDirectoryDSN == "" {
			identityDirectoryDSN = *postgresDSN
		}
		humanIdentities, closeHumanIdentities, err = setupEdgeHumanIdentityDirectory(context.Background(), edgeHumanIdentityDirectoryConfig{
			Mode:          *edgeIdentityDirectoryStore,
			DSN:           identityDirectoryDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup human identity directory: %v", err)
		}
		defer closeHumanIdentities()
		workloadAttestationNonceDSN := strings.TrimSpace(*workloadAttestationNoncePostgresDSN)
		if workloadAttestationNonceDSN == "" {
			workloadAttestationNonceDSN = *postgresDSN
		}
		workloadAttestations, closeWorkloadAttestations, err = setupEdgeWorkloadAttestationNonceStore(context.Background(), edgeWorkloadAttestationNonceStoreConfig{
			Mode:          *workloadAttestationNonceStore,
			DSN:           workloadAttestationNonceDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup workload attestation nonce store: %v", err)
		}
		defer closeWorkloadAttestations()
		nhiRegistryDSN := strings.TrimSpace(*edgeNHIRegistryPostgresDSN)
		if nhiRegistryDSN == "" {
			nhiRegistryDSN = *postgresDSN
		}
		nhiRegistry, closeNHIRegistryStore, err = setupEdgeNonHumanIdentityStore(context.Background(), edgeNonHumanIdentityStoreConfig{
			Mode:          *edgeNHIRegistryStore,
			DSN:           nhiRegistryDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup NHI registry store: %v", err)
		}
		defer closeNHIRegistryStore()
		hotStoreDSN := strings.TrimSpace(*edgeHotStorePostgresDSN)
		if hotStoreDSN == "" {
			hotStoreDSN = *postgresDSN
		}
		if m := strings.ToLower(storeBackend(*edgeHotStore)); m == "postgres" || m == "clickhouse" {
			hotStoreMirrorMonitor = newHotStoreAppendMirrorMonitor()
		}
		adminHotStore, closeAdminHotStore, err = setupEdgeHotStore(context.Background(), edgeHotStoreConfig{
			Mode:               *edgeHotStore,
			DSN:                hotStoreDSN,
			MigrationDir:       *migrationDir,
			RunMigrations:      *postgresRunMigrations,
			Writer:             writer,
			MirrorMonitor:      hotStoreMirrorMonitor,
			ClickHouseEndpoint: *edgeHotStoreClickHouseEndpoint,
			ClickHouseUser:     *edgeHotStoreClickHouseUser,
			ClickHousePassword: *edgeHotStoreClickHousePassword,
			ClickHouseDatabase: *edgeHotStoreClickHouseDatabase,
			ClickHouseTable:    *edgeHotStoreClickHouseTable,
			// Beside the logs, which is where the canonical copy of these records already lives.
			BacklogSpoolPath: filepath.Join(strings.TrimSpace(*logDir), ".hot_store", "backlog.json"),
		})
		if err != nil {
			log.Fatalf("setup hot store: %v", err)
		}
		defer closeAdminHotStore()
		adminExportJobDSN := strings.TrimSpace(*edgeAdminExportJobPostgresDSN)
		if adminExportJobDSN == "" {
			adminExportJobDSN = *postgresDSN
		}
		adminExportJobs, closeAdminExportJobs, err = setupEdgeAdminExportJobStore(context.Background(), edgeAdminExportJobStoreConfig{
			Mode:          *edgeAdminExportJobStore,
			DSN:           adminExportJobDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup admin export job store: %v", err)
		}
		defer closeAdminExportJobs()
		adminExportQueueDSN := strings.TrimSpace(*edgeAdminExportQueuePostgresDSN)
		if adminExportQueueDSN == "" {
			adminExportQueueDSN = *postgresDSN
		}
		if strings.EqualFold(strings.TrimSpace(*edgeAdminExportWorker), "postgres-queue") && !strings.EqualFold(strings.TrimSpace(*edgeAdminExportJobStore), "postgres") {
			log.Fatalf("admin-export-worker=postgres-queue requires admin-export-job-store=postgres")
		}
		configuredAdminExportWorker, closeAdminExportWorker, err = setupEdgeAdminExportWorker(context.Background(), edgeAdminExportWorkerConfig{
			Mode:                    *edgeAdminExportWorker,
			DSN:                     adminExportQueueDSN,
			MigrationDir:            *migrationDir,
			RunMigrations:           *postgresRunMigrations,
			Timeout:                 *workerTimeout,
			DisableDirectAuditJSONL: !*adminExportDirectAuditJSONL,
		})
		if err != nil {
			log.Fatalf("setup admin export worker: %v", err)
		}
		if worker, ok := configuredAdminExportWorker.(postgresQueueAdminExportWorker); ok && worker.DB != nil {
			adminAuditOutbox = postgresAdminAuditOutboxReader{DB: worker.DB}
		}
		defer closeAdminExportWorker()
		domainEventOutboxDSN := strings.TrimSpace(*edgeDomainEventOutboxPostgresDSN)
		if domainEventOutboxDSN == "" {
			domainEventOutboxDSN = *postgresDSN
		}
		domainEventOutbox, closeDomainEventOutbox, err = setupEdgeDomainEventOutbox(context.Background(), edgeDomainEventOutboxConfig{
			Mode:          *edgeDomainEventOutbox,
			DSN:           domainEventOutboxDSN,
			MigrationDir:  *migrationDir,
			RunMigrations: *postgresRunMigrations,
		})
		if err != nil {
			log.Fatalf("setup domain event outbox: %v", err)
		}
		if domainEventOutbox != nil {
			domainEventOutboxMirrorMonitor = newDomainEventOutboxMirrorMonitor()
			domainEventOutbox = monitoredDomainEventOutbox{Writer: domainEventOutbox, Monitor: domainEventOutboxMirrorMonitor}
		}
		defer closeDomainEventOutbox()
	} else if *mode != "postgres-export-worker" && *mode != "postgres-audit-publisher" && *mode != "postgres-domain-event-publisher" {
		log.Fatalf("unknown mode %q", *mode)
	}
	if err := writer.Append("audit.log.jsonl", decision.BundleLoadedAuditLog(pb, *edgeRegionID, *edgeClusterID)); err != nil {
		log.Fatalf("write startup audit log: %v", err)
	}
	if *mode == "postgres-export-worker" {
		tenantID := strings.TrimSpace(*workerTenantID)
		if tenantID == "" {
			tenantID = pb.TenantID
		}
		if err := runPostgresExportWorker(context.Background(), postgresExportWorkerConfig{
			DSN:                    *postgresDSN,
			MigrationDir:           *migrationDir,
			RunMigrations:          *postgresRunMigrations,
			SchemaDir:              *schemaDir,
			TenantID:               tenantID,
			WorkerID:               *workerID,
			HotStoreMode:           *workerHotStore,
			PollInterval:           *workerPollInterval,
			LeaseDuration:          *workerLeaseDuration,
			LeaseExtensionInterval: *workerLeaseExtensionInterval,
			Timeout:                *workerTimeout,
			Writer:                 writer,
			ObjectStore:            exportObjectStore,
			Evaluator:              evaluator,
		}); err != nil {
			log.Fatalf("postgres export worker: %v", err)
		}
		return
	}
	if *mode == "postgres-audit-publisher" {
		tenantID := strings.TrimSpace(*workerTenantID)
		if tenantID == "" {
			tenantID = pb.TenantID
		}
		if err := runPostgresAuditOutboxPublisher(context.Background(), postgresAuditOutboxPublisherConfig{
			DSN:            *postgresDSN,
			MigrationDir:   *migrationDir,
			RunMigrations:  *postgresRunMigrations,
			TenantID:       tenantID,
			PublisherID:    *auditPublisherID,
			PollInterval:   *auditPublisherPollInterval,
			BatchSize:      *auditPublisherBatchSize,
			LockDuration:   *auditPublisherLockDuration,
			RetryDelay:     *auditPublisherRetryDelay,
			MaxAttempts:    *auditPublisherMaxAttempts,
			Writer:         writer,
			DeliveryMode:   *auditPublisherDelivery,
			WebhookURL:     *auditPublisherWebhookURL,
			WebhookToken:   *auditPublisherWebhookToken,
			WebhookSecret:  *auditPublisherWebhookSecret,
			WebhookKeyID:   *auditPublisherWebhookKeyID,
			WebhookTimeout: *auditPublisherWebhookTimeout,
		}); err != nil {
			log.Fatalf("postgres audit outbox publisher: %v", err)
		}
		return
	}
	if *mode == "postgres-domain-event-publisher" {
		tenantID := strings.TrimSpace(*workerTenantID)
		if tenantID == "" {
			tenantID = pb.TenantID
		}
		publisherDSN := strings.TrimSpace(*domainEventPublisherPostgresDSN)
		if publisherDSN == "" {
			publisherDSN = *postgresDSN
		}
		if err := runPostgresDomainEventOutboxPublisher(context.Background(), postgresDomainEventOutboxPublisherConfig{
			DSN:            publisherDSN,
			MigrationDir:   *migrationDir,
			RunMigrations:  *postgresRunMigrations,
			TenantID:       tenantID,
			EventPlane:     *domainEventPublisherPlane,
			PublisherID:    *domainEventPublisherID,
			PollInterval:   *domainEventPublisherPollInterval,
			BatchSize:      *domainEventPublisherBatchSize,
			LockDuration:   *domainEventPublisherLockDuration,
			RetryDelay:     *domainEventPublisherRetryDelay,
			MaxAttempts:    *domainEventPublisherMaxAttempts,
			Writer:         writer,
			ObjectStore:    exportObjectStore,
			DeliveryMode:   *domainEventPublisherDelivery,
			WebhookURL:     *domainEventPublisherWebhookURL,
			WebhookToken:   *domainEventPublisherWebhookToken,
			WebhookSecret:  *domainEventPublisherWebhookSecret,
			WebhookKeyID:   *domainEventPublisherWebhookKeyID,
			WebhookTimeout: *domainEventPublisherWebhookTimeout,
		}); err != nil {
			log.Fatalf("postgres domain event outbox publisher: %v", err)
		}
		return
	}
	if *mode != "edge" {
		log.Fatalf("unknown mode %q", *mode)
	}
	swgRuntime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath:     *swgTenantRestrictionOperatorConfigPath,
		TenantRestrictionOperatorValueStorePath: *swgTenantRestrictionOperatorValueStorePath,
		PolicyBundle:                            pb,
		RuntimeTLSDecryptionObserved:            *swgRuntimeTLSDecryptionObserved,
		MacCATrustObserved:                      *swgMacCATrustObserved,
	})
	if err != nil {
		log.Fatalf("load SWG runtime config: %v", err)
	}
	trustedKeyring, err := loadEdgeTrustedKeyring(*trustedKeyringPath, pb.TenantID)
	if err != nil {
		log.Fatalf("load trusted keyring: %v", err)
	}
	routeProfiles, err := edgeplane.LoadApplicationRouteProfiles(*protectedAppMapPath)
	if err != nil {
		log.Fatalf("load protected app map: %v", err)
	}
	downstreamPassthroughSourceAppSigningIdentifiers, downstreamPassthroughDefaultTunnelEnabled := networkExtensionRuntimeCopyDownstreamPassthroughConfig(
		*devMode,
		*networkExtensionRuntimeCopyLabTLSInterceptionHosts,
		*networkExtensionRuntimeCopyTransportScope,
		*networkExtensionRuntimeCopyDownstreamPassthroughSourceAppSigningIdentifiers,
		*networkExtensionRuntimeCopyDownstreamPassthroughDefaultTunnelEnabled,
	)
	// Deciding from the SNI requires the network extension to steer EVERY flow to the Edge, because the Edge
	// is what reads the SNI. So no intercept-only-domains list is published — narrowing the steer on the
	// extension's side would defeat it — and everything is steered.
	networkExtensionInterceptOnlyDomains := splitPaths(*networkExtensionRuntimeCopyLabTLSInterceptionHosts)
	if *networkExtensionRuntimeCopyLabTLSSNIBasedIntercept {
		networkExtensionInterceptOnlyDomains = nil
	}
	networkExtensionPublisher, err := newLocalNetworkExtensionSnapshotPublisher(localNetworkExtensionSnapshotPublisherConfig{
		OutputDir:                      *networkExtensionConfigPublishDir,
		EdgeURL:                        *networkExtensionRuntimeCopyEdgeURL,
		RuntimeCopyEndpointPath:        *networkExtensionRuntimeCopyEndpointPath,
		RuntimeCopySessionEndpointPath: *networkExtensionRuntimeCopySessionEndpointPath,
		RuntimeCopyTransportScope:      *networkExtensionRuntimeCopyTransportScope,
		EdgeConnectorRealness:          *networkExtensionRuntimeCopyEdgeConnectorRealness,
		PassthroughResolvedIPs:         splitPaths(*networkExtensionRuntimeCopyPassthroughResolvedIPs),
		RuntimeCopyDownstreamPassthroughSourceAppSigningIdentifiers: downstreamPassthroughSourceAppSigningIdentifiers,
		RuntimeCopyDownstreamPassthroughDefaultTunnelEnabled:        downstreamPassthroughDefaultTunnelEnabled,
		PassthroughDomains:                       splitPaths(*networkExtensionPassthroughDomains),
		DefaultPassthroughDomainsEnabled:         networkExtensionDefaultPassthroughDomainsEnabled,
		SelfExclusionSourceAppSigningIdentifiers: splitPaths(*networkExtensionSelfExclusionSigningIdentifiers),
		InterceptOnlyDomains:                     networkExtensionInterceptOnlyDomains,
		TransportTLSURL:                          *networkExtensionTransportTLSURL,
		TransportPinnedCARef:                     *networkExtensionTransportPinnedCARef,
		RenewalRecoveryEndpoint:                  *networkExtensionRenewalRecoveryEndpoint,
		TransportMTLSRequired:                    *transportTLSRequireClientCert,
		TransportDNSOverTunnelPath:               networkExtensionSnapshotDefaultDNSOverTunnelPath,
	})
	if err != nil {
		// ★ A MISCONFIGURED PUBLISHER USED TO KILL THE EDGE (measured 2026-08-16). This publisher writes an
		// artifact — the agent configuration snapshot. It carries no traffic, enforces nothing, and every
		// device on the node keeps working without it. It was a log.Fatalf, so turning it on with one flag
		// missing (-network-extension-runtime-copy-edge-url) put the reference Edge into a crash loop:
		// enforcement, interception and every tunnel gone, because an optional output could not be configured.
		// Measured by doing exactly that, with a real Mac steering through the node.
		//
		// The publisher is disabled and the reason is loud. Refusing to start is right for material the node
		// cannot serve traffic WITHOUT — the control plane, the signing key — and wrong for something whose
		// absence costs an artifact. The same principle the state-ownership guard was corrected under: a
		// diagnostic that turns a running deployment into a crash loop is worse than the defect it reports.
		log.Printf("interception: WARNING the agent-configuration publisher is NOT running (%v) — nothing is "+
			"published to -network-extension-config-publish-dir, so any device installed from a configuration "+
			"placed by hand will not receive this node's current trusted authorities. The Edge continues to "+
			"serve traffic; fix the publisher's configuration to restore the artifact.", err)
		networkExtensionPublisher = nil
	}
	// Seal interception root keys at rest when a KEK is configured (must be set BEFORE the engine loads/persists
	// any root key so generate->write seals and load unseals).
	if kekPath := strings.TrimSpace(*interceptionRootKEKFile); kekPath != "" {
		kek, kerr := edgeplane.LoadInterceptionRootKEKFromFile(kekPath)
		if kerr != nil {
			log.Fatalf("interception root KEK: %v", kerr)
		}
		edgeplane.SetInterceptionRootKEK(kek)
		log.Printf("interception: root keys SEALED at rest (AES-256-GCM) with the configured KEK")
	}
	// Offline-root mode is selected when all three offline flags are set: the Edge loads a name-constrained
	// intermediate (cert+key) issued by an OFFLINE root + the root cert anchor, and holds NO root key.
	offlineInterCert := strings.TrimSpace(*interceptionIntermediateCert)
	offlineInterKey := strings.TrimSpace(*interceptionIntermediateKey)
	offlineRootCert := strings.TrimSpace(*interceptionRootCert)
	offlineAny := offlineInterCert != "" || offlineInterKey != "" || offlineRootCert != ""
	offlineAll := offlineInterCert != "" && offlineInterKey != "" && offlineRootCert != ""
	if offlineAny && !offlineAll {
		log.Fatalf("offline interception intermediate requires all of -interception-intermediate-cert, -interception-intermediate-key, -interception-root-cert")
	}
	// ★ READ WHERE IT IS NAMED, REFUSED IF IT IS NOT A CERTIFICATE. A node that names a root it cannot parse
	// would issue profiles carrying a value no device can use, and say nothing.
	profileInterceptionRootPEM := ""
	if p := strings.TrimSpace(*profileInterceptionRootCert); p != "" {
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			log.Fatalf("read -deployment-interception-root-cert: %v", rerr)
		}
		if !strings.Contains(string(b), "BEGIN CERTIFICATE") {
			log.Fatalf("-deployment-interception-root-cert %s is not a PEM certificate", p)
		}
		profileInterceptionRootPEM = strings.TrimSpace(string(b))
	}
	var networkExtensionLabTLS *edgeplane.NetworkExtensionLabTLSInterception
	if offlineAll {
		rootPEM, rerr := os.ReadFile(offlineRootCert)
		if rerr != nil {
			log.Fatalf("read -interception-root-cert: %v", rerr)
		}
		interPEM, rerr := os.ReadFile(offlineInterCert)
		if rerr != nil {
			log.Fatalf("read -interception-intermediate-cert: %v", rerr)
		}
		interKeyPEM, rerr := os.ReadFile(offlineInterKey)
		if rerr != nil {
			log.Fatalf("read -interception-intermediate-key: %v", rerr)
		}
		networkExtensionLabTLS, err = edgeplane.NewNetworkExtensionLabTLSInterceptionOfflineIntermediate(splitPaths(*networkExtensionRuntimeCopyLabTLSInterceptionHosts), time.Now, rootPEM, interPEM, interKeyPEM, *networkExtensionRuntimeCopyLabTLSRootCACertOut)
	} else if strings.TrimSpace(*interceptionHSMAgentSocket) != "" {
		// The signing key is in a token behind the sidecar. A failure here is fatal by design: running on with
		// an in-process key after being told to use hardware would silently downgrade custody, which is exactly
		// the gap the operator asked to close.
		// One socket is the single-HSM path; several (comma-separated, primary first) form the HA pool that
		// fails over between replicated appliances (interception_hsm_ha.go). The pool refuses to start unless
		// every sidecar reports the same key, so a mis-cabled standby fails loudly here rather than at failover.
		sockets := splitCommaList(*interceptionHSMAgentSocket)
		var provider *hsmAgentProvider
		provider, err = newHSMAgentPoolProvider(
			sockets,
			strings.TrimSpace(*interceptionHSMAgentToken),
			strings.TrimSpace(*interceptionHSMAgentKeyID),
			strings.TrimSpace(*interceptionHSMAgentCert),
			"DSSE Interception Root", 0, time.Now, log.Printf)
		if err != nil {
			log.Fatalf("interception HSM agent: %v", err)
		}
		if len(sockets) > 1 {
			log.Printf("interception: signing key is in a PKCS#11 token, HA pool over %d sidecars (%s) — this process does NOT hold it", len(sockets), strings.Join(sockets, ", "))
		} else {
			log.Printf("interception: signing key is in a PKCS#11 token via %s — this process does NOT hold it", sockets[0])
		}
		networkExtensionLabTLS, err = edgeplane.NewNetworkExtensionLabTLSInterceptionWithProvider(
			splitPaths(*networkExtensionRuntimeCopyLabTLSInterceptionHosts), time.Now, provider)
		if err == nil && networkExtensionLabTLS != nil && strings.TrimSpace(*networkExtensionRuntimeCopyLabTLSRootCACertOut) != "" {
			// Endpoints trust the ROOT; publish it exactly as the file-key path does.
			if werr := os.WriteFile(strings.TrimSpace(*networkExtensionRuntimeCopyLabTLSRootCACertOut), provider.CertPEM(), 0o644); werr != nil {
				log.Fatalf("write interception root CA cert: %v", werr)
			}
		}
	} else {
		networkExtensionLabTLS, err = edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot(splitPaths(*networkExtensionRuntimeCopyLabTLSInterceptionHosts), time.Now, *networkExtensionRuntimeCopyLabTLSRootCACertOut)
	}
	if err != nil {
		log.Fatalf("configure Network Extension lab TLS interception: %v", err)
	}
	if networkExtensionLabTLS == nil && strings.TrimSpace(*networkExtensionRuntimeCopyLabTLSRootCACertOut) != "" {
		log.Fatalf("network-extension-runtime-copy-lab-tls-root-ca-cert-out requires -network-extension-runtime-copy-lab-tls-interception-hosts")
	}
	// Restore a previously adopted re-parent (interception under a central root, key still in the token)
	// before any traffic is served. Runs after the provider is built — the token key it validates against is
	// live now — and only when a complete persisted pair is present and still matches; otherwise the
	// self-signed root stands. This is what stops a redeploy from silently reverting the migration.
	if networkExtensionLabTLS != nil {
		edgeplane.ReapplyPersistedReparent(networkExtensionLabTLS, strings.TrimSpace(*interceptionReparentStateDir))
		// The anchor may have just moved. The file operators are told to distribute does not move with it in
		// persistent-root mode, so say so rather than leaving a valid-looking certificate that breaks every
		// site on the machine it is installed onto.
		warnIfInterceptionAnchorFileHasDrifted(networkExtensionLabTLS, *networkExtensionRuntimeCopyLabTLSRootCACertOut)
	}
	// The agent configuration now carries the organization's own trusted authorities, so a device's trust is
	// part of what it was installed with rather than a separate manual step that drifts. Wired here because
	// the publisher is built before the interception engine exists.
	if networkExtensionPublisher != nil {
		networkExtensionPublisher.SetTrustedCABundleSource(func(tenantID string) map[string]any {
			return agentTrustedCABundle(networkExtensionLabTLS, tenantID, evaluator.PolicyBundle.TenantID)
		})
		// And the keys a device accepts on an update manifest. Without them the published configuration is one
		// the installer refuses at its last check — a Mac that installs an agent it can never patch is the
		// failure that check exists for, so an artifact missing them is not a usable artifact.
		networkExtensionPublisher.SetUpdateSigningKeys(splitAgentUpdatePins(*agentUpdate.pin))
		networkExtensionPublisher.SetUpdatePublisher(*agentUpdate.publisher)
	}
	// Background key-custody monitor. Runs the functional check on a timer so a dead signing key is found by
	// asking, not by a user tripping over the first uncached hostname — the leaf cache hides exactly that.
	// Its result drives /healthz readiness above.
	keyCustodyMonitorRef := edgeplane.NewKeyCustodyMonitor(func() edgeplane.InterceptionRootProvider {
		if networkExtensionLabTLS == nil {
			return nil
		}
		return networkExtensionLabTLS.DefaultRootProvider()
	}, 30*time.Second, log.Printf)
	if networkExtensionLabTLS != nil {
		keyCustodyMonitorRef.Start()
	}

	// Interception-root blast-radius scoping (PKI). Bounds which key can MITM whom: a leaked regional key reads
	// only its region's traffic (residency), a leaked tenant key only that tenant's. The primary tenant keeps the
	// default root so already-trusting devices are unaffected; other tenants/regions need their root distributed.
	scope := strings.ToLower(strings.TrimSpace(*interceptionRootScope))
	if scope != "" && scope != "shared" && networkExtensionLabTLS == nil {
		log.Fatalf("-interception-root-scope=%s requires interception to be enabled (-network-extension-runtime-copy-lab-tls-interception-hosts)", scope)
	}
	if offlineAll && scope != "" && scope != "shared" {
		log.Fatalf("offline interception intermediate uses a single fixed intermediate and is incompatible with -interception-root-scope=%s", scope)
	}
	if networkExtensionLabTLS != nil && strings.TrimSpace(*interceptionPerTenantRootDir) != "" {
		networkExtensionLabTLS.SetPerTenantInterceptionRootDir(*interceptionPerTenantRootDir)
	}
	// Which organization the node-wide intermediate belongs to. Set ALWAYS, not only when per-tenant issuers
	// are configured: the first bundle can arrive at runtime through the admin API, and if this were still
	// empty at that moment the node would fail closed on the tenant it had been serving all along — the
	// deployment's own traffic stopped by the feature that was supposed to add a second customer. It is inert
	// until a per-tenant issuer exists.
	if networkExtensionLabTLS != nil {
		networkExtensionLabTLS.SetOfflinePrimaryTenant(evaluator.PolicyBundle.TenantID)
	}
	// Per-tenant offline issuers, restored BEFORE traffic. A node that came up serving organizations and then
	// refused them because their bundles had not been read yet would be an outage caused by the ordering of
	// this file.
	if networkExtensionLabTLS != nil && strings.TrimSpace(*interceptionTenantIssuers.dir) != "" {
		loaded, err := networkExtensionLabTLS.LoadOfflineTenantIntermediatesFromDir(*interceptionTenantIssuers.dir)
		if err != nil {
			// Not fatal: refusing to start would take down every organization because one directory is
			// unreadable, and the directory being empty is the ordinary state before the first onboarding.
			log.Printf("interception: WARNING per-tenant offline issuers could not be read from %q (%v) — this node "+
				"signs with the node-wide intermediate only, and any organization that expected its own is NOT intercepted",
				*interceptionTenantIssuers.dir, err)
		} else if loaded > 0 {
			// ★★ THE SENTENCE USED TO ASSERT THAT THE NODE'S OWN ORGANIZATION KEEPS THE NODE-WIDE INTERMEDIATE,
			// AS A FIXED STRING (2026-08-19). It printed that while the line directly above it announced that
			// organization's OWN issuer being loaded — the two disagreed, in the same log, six lines apart, and
			// the false half is the one an operator reads as the summary. The same claim was corrected in the
			// admin route on 2026-08-18 (60353685) and this copy was not, which is what a second copy of a
			// sentence is for.
			//
			// It cost real time today: the note said the node's organization was still on the shared CA, so the
			// difference between the two regions looked like it could not matter, and the fleet was left signing
			// one organization under two authorities.
			nodeOwnHasItsOwn := false
			for _, issuer := range networkExtensionLabTLS.ListOfflineTenantIntermediates() {
				if strings.EqualFold(strings.TrimSpace(issuer.Tenant), strings.TrimSpace(evaluator.PolicyBundle.TenantID)) {
					nodeOwnHasItsOwn = true
					break
				}
			}
			nodeOwn := "and this node's own organization is among them"
			if !nodeOwnHasItsOwn {
				nodeOwn = fmt.Sprintf("%q has none of its own and keeps the node-wide intermediate", evaluator.PolicyBundle.TenantID)
			}
			log.Printf("interception: PER-TENANT OFFLINE SIGNING is in force — %d organization(s) sign under their own "+
				"offline root, %s; every OTHER organization is refused rather than signed under somebody else's CA",
				loaded, nodeOwn)
		}
	}
	switch scope {
	case "", "shared":
		// default: one shared root (unchanged).
	case "per-tenant":
		networkExtensionLabTLS.EnablePerTenantInterceptionRoots(evaluator.PolicyBundle.TenantID)
		log.Printf("interception roots: PER-TENANT (primary %q keeps the default root; other tenants sign under their own)", evaluator.PolicyBundle.TenantID)
	case "per-region":
		networkExtensionLabTLS.EnablePerTenantPerRegionInterceptionRoots(evaluator.PolicyBundle.TenantID, *edgeRegionID)
		log.Printf("interception roots: PER-REGION (region %q; per-tenant roots are region-identifiable — a leaked regional key MITMs only this region)", *edgeRegionID)
	default:
		log.Fatalf("invalid -interception-root-scope %q (want: shared | per-tenant | per-region)", scope)
	}
	// Runtime rotatable intermediate (root key stays on the Edge) — mutually exclusive with offline mode.
	if *interceptionUseIntermediate {
		if offlineAll {
			log.Fatalf("-interception-use-intermediate conflicts with the offline intermediate flags")
		}
		if networkExtensionLabTLS == nil {
			log.Fatalf("-interception-use-intermediate requires interception to be enabled")
		}
		networkExtensionLabTLS.EnableInterceptionIntermediate(splitPaths(*interceptionIntermediatePermittedDNS))
		log.Printf("interception: runtime intermediate ENABLED (chain [leaf, intermediate, root]; root key remains on the Edge)")
	}
	// Policy-candidate store (incl. cert-pinning bypass proposals). Created here so it can be made
	// durable (-policy-candidate-store) and wired to interception detection, then handed to the server.
	policyCandidateStore := policycandidate.NewStore()
	// Persist proposals so an unreviewed candidate survives an edge restart (and, on shared Postgres, a failover).
	if err := policyCandidateStore.SetPersister(mustCPStateBlobPersister(*policyCandidateStatePath, "policy_candidates")); err != nil {
		log.Fatalf("policy candidate store: %v", err)
	}
	// Static bypass set = operator-configured patterns (always) + the curated known-un-interceptable list
	// (Apple push/iCloud, OS updates, OCSP) WHEN enabled. The known-bypass toggle is runtime-mutable — an admin
	// can turn the curated list off/on via POST /admin/inspection-posture — so staticBypass recomputes the
	// base from the current setting and the rebuild below always reflects it. Initialised from -default-bypass-list.
	operatorStaticBypass := splitPaths(*networkExtensionRuntimeCopyLabTLSBypassHosts)
	configuredInterceptHosts := splitPaths(*networkExtensionRuntimeCopyLabTLSInterceptionHosts)
	// Per-tenant predefined-catalog overrides: an admin can force-inspect or disable an individual curated
	// bypass entry (finer-grained than the all-or-nothing known-bypass toggle). staticBypass reads the
	// override store so a change applies on the next rebuild.
	catalogOverrides := knownbypass.NewOverrideStore()
	if err := catalogOverrides.SetPersister(mustCPStateBlobPersister(*catalogOverrideStatePath, "catalog_overrides")); err != nil {
		log.Fatalf("predefined-catalog override store: %v", err)
	}
	// Signed predefined-catalog FEED (proprietary): when a feed is applied it replaces the built-in default
	// catalog (subject to the per-tenant overrides above). The feed is verified against the configured trusted
	// ed25519 keyring; with no keys, no feed can be applied and the built-in default is served.
	catalogFeedKeys, err := loadCatalogFeedTrustedKeys(*catalogFeedTrustedKeysFile)
	if err != nil {
		log.Fatalf("predefined-catalog feed trusted keys: %v", err)
	}
	catalogFeed := catalogfeed.NewStore(catalogFeedKeys)
	if path := strings.TrimSpace(*catalogFeedStatePath); path != "" {
		if err := catalogFeed.SetStatePath(path); err != nil {
			log.Fatalf("predefined-catalog feed store: %v", err)
		}
	}
	// Durable inspection posture (deployment mode + decrypt allowlist + known-bypass toggle). On a fresh store
	// the known-bypass toggle is seeded from -default-bypass-list (mode defaults to decrypt_all). staticBypass
	// and applyInspectionPosture recompute from the live posture so a change (POST /admin/inspection-posture)
	// reflects in the engine's bypass + intercept sets.
	postureStore := inspectionposture.NewStore()
	// ★ THE POSTURE IS ENFORCEMENT, SO IT FOLLOWS THE FLEET (2026-08-21). An explicit path still wins; an Edge
	// that was given none, in a deployment that has shared state, shares this rather than starting from the
	// default and deciding differently from its neighbours about which flows are decrypted.
	postureLoaded := func() (bool, error) {
		// ★★★ AN EDGE NO LONGER SHARES A STORE FOR THIS (2026-08-23). The posture is CONFIGURATION and travels
		// in the signed config bundle now (config_bundle_inspection_posture.go), so the control plane authors it
		// and every Edge takes the same one. The "fall back to the fleet's shared store" line that used to sit
		// here is what gave every enforcement Edge a database connection — and it did not even work: measured a
		// day later, one of the two Edges had no posture store at all and the fleet still disagreed.
		//
		// What stays here is a LOCAL CACHE of the last posture this node was given, so a restart resumes where
		// it was instead of enforcing the default for one poll interval. A cache, not an authority: the next
		// bundle overwrites it, and this Edge refuses to author one (admin_effective_policy_routes.go).
		//
		// A control plane, which authors rather than receives, is given an explicit path.
		value := strings.TrimSpace(*inspectionPostureStorePath)
		if value == "" {
			value = durableStorePath(*stateDir, "", "inspection_posture")
		}
		if value != "" {
			p, e := cpStateBlobPersister(value, cpStateBlobDB, "inspection_posture")
			if e != nil {
				return false, e
			}
			if p != nil {
				return postureStore.SetPersister(p)
			}
		}
		return postureStore.SetStatePath(*inspectionPostureStorePath)
	}
	if loaded, err := postureLoaded(); err != nil {
		log.Fatalf("load inspection posture store: %v", err)
	} else if !loaded {
		seed := postureStore.Get()
		seed.KnownBypassEnabled = *defaultBypassList
		if _, err := postureStore.Set(seed); err != nil {
			// Boot-time seed: a store that cannot persist its posture will silently revert on every
			// restart — refuse to start half-durable rather than run with an invisible config drift.
			log.Fatalf("seed inspection posture store: %v", err)
		}
	}
	staticBypass := func() []string {
		p := postureStore.Get()
		hosts := append([]string{}, operatorStaticBypass...)
		if p.KnownBypassEnabled {
			// Per-tenant overrides drop force-inspected/disabled entries from the curated catalog.
			hosts = append(hosts, catalogOverrides.EffectiveBypassHostsFrom(catalogFeed.EffectiveCatalog().Entries, pb.TenantID)...)
		}
		// SaaS Optimize bypass groups are NO LONGER read here: they are authored Egress bypass rules (unified
		// model Phase B-1) folded into the set via EgressBypassFQDNs below, the single source of truth. A legacy
		// posture.bypass_groups selection is migrated to rules at startup (migratePostureOptimizeBypassToRules).
		return hosts
	}
	// Endpoint/group/service catalog + unified rule authoring (model + storage in dsse-core). Created here so
	// the decrypt-bypass rebuild below can include authored egress rules whose inspection axis is bypass; the
	// admin APIs are registered later once the mux is built. The asset store is populated from the enrolled
	// inventory at registration time.
	assetStore := assetcatalog.NewStore()
	if p, e := cpStateBlobPersister(*assetCatalogStorePath, cpStateBlobDB, "asset_catalog"); e != nil {
		log.Fatalf("resolve asset catalog store: %v", e)
	} else if err := assetStore.SetPersister(p); err != nil {
		log.Fatalf("load asset catalog store: %v", err)
	}
	// Install the shipped SaaS catalog as read-only built-in endpoint groups (Phase A2): a rule's destination
	// can be a catalog group ("openai", "m365_optimize", …) and the engine resolves it to the host patterns.
	assetStore.SetBuiltInCatalog(builtInCatalogAssets())
	// Ship well-known services (SSH/RDP/SMB/HTTPS/…) so every tenant can PICK a Service instead of hand-typing.
	assetStore.SetBuiltInServices(assetcatalog.BuiltInServices())
	// Shared CP-state blob DB (reuses -postgres-dsn): the seam that moves authored-state stores off node-local
	// JSON files onto shared Postgres so a standby CP can serve them — the prerequisite for CP HA. nil on the
	// zero-DB edge (no -postgres-dsn) → stores keep their file paths. See cp_state_blob_persister.go.
	// CP leader election (A/S): the active CP holds a Postgres advisory lock; a standby acquires it on the
	// active's death/failover and takes over (see cp_leader_election.go). nil (no -postgres-dsn) = always leader.
	var cpLeaderErr error
	cpLeaderElectorInstance, cpLeaderErr = newCPLeaderElector(*postgresDSN)
	if cpLeaderErr != nil {
		log.Fatalf("start CP leader election: %v", cpLeaderErr)
	}
	cpLeaderElectorInstance.Start()
	defer cpLeaderElectorInstance.Stop()
	ruleStore := policyrule.NewStore()
	rulePersister, rulePersisterErr := cpStateBlobPersister(*policyRuleStorePath, cpStateBlobDB, "policy_rules")
	if rulePersisterErr != nil {
		log.Fatalf("resolve policy rule store: %v", rulePersisterErr)
	}
	if err := ruleStore.SetPersister(rulePersister); err != nil {
		log.Fatalf("load policy rule store: %v", err)
	}
	// Operational log level (Plane A). Default info = quiet hot path. debug (or the deprecated
	// -network-extension-runtime-verbose-logs) turns the per-flow/per-request firehose back on. setLogLevel
	// unifies the interception verbose-log gate, so there is ONE knob. See docs/logging_what_to_log_design.md.
	logLevel := parseLogLevel(*logLevelFlag)
	if *networkExtensionRuntimeVerboseLogs && logLevel < logLevelDebug {
		logLevel = logLevelDebug // the deprecated flag implies debug
	}
	setLogLevel(logLevel)
	// One DNS resolution conntrack shared between the cert-pin emitter here and the DNS-over-tunnel resolver
	// built inside newServerWithConfig (passed in via serverConfig.DNSConntrack). Sharing it is what lets a
	// connect-by-IP cert-pin observation recover its real FQDN from the DNS answer the same device just resolved.
	edgeDNSConntrack := dns.NewConntrackStore()
	if networkExtensionLabTLS != nil {
		networkExtensionLabTLS.SetProbeOnly(*networkExtensionRuntimeCopyLabTLSProbeOnly)
		networkExtensionLabTLS.SetBypassHosts(staticBypass())
		networkExtensionLabTLS.SetSNIBasedDecision(*networkExtensionRuntimeCopyLabTLSSNIBasedIntercept)
		networkExtensionLabTLS.SetDynamicPinDetectionEnabled(*networkExtensionRuntimeCopyLabTLSDynamicPinDetection)
		// Cert-pinning detection -> bypass-candidate proposal. On repeated interception handshake
		// rejections the engine proposes the host for admin review. Detection is on by default and safe:
		// it never auto-bypasses (auto raw_forward stays opt-in above); only admin approve+materialize
		// applies a decrypt-bypass.
		certPinTenant := pb.TenantID
		networkExtensionLabTLS.SetCertPinCandidateEmitter(func(host string) {
			now := time.Now().UTC()
			// Central point for every interception handshake rejection — count it for /metrics before the
			// DNS-correlation branch below decides how to record the candidate.
			recordInterceptionRejected()
			// A connect-by-IP flow has no SNI here (the emitter passes ""), so it would default to an
			// investigate_only candidate. Recover the real FQDN from the DNS-over-tunnel conntrack first so the
			// admin reviews a named entity, not a bare IP.
			if fqdn, ip, ok := dns.RecoverCertPinName(edgeDNSConntrack, certPinTenant, host, "", now); ok {
				_, _ = policyCandidateStore.ObserveCertPinFailureDNSCorrelated(context.Background(), certPinTenant, fqdn, ip, 443, "interception_handshake_rejected", now)
				return
			}
			_, _ = policyCandidateStore.ObserveCertPinFailure(context.Background(), certPinTenant, host, "", 443, "interception_handshake_rejected", now)
		})
	}
	// applyMaterializedCertPinBypass rebuilds the interception decrypt-bypass set from its sources: the static
	// bypass list + authored egress rules whose inspection axis is bypass. A materialized cert-pinning candidate
	// is NO LONGER a separate bypass source — on materialize it is emitted as an authored bypass rule (and legacy
	// materialized candidates are migrated to rules at startup), so the rule is the cert-pin bypass's SINGLE
	// source. That makes the lifecycle coherent: deleting/disabling the rule actually stops the bypass (it would
	// not if the candidate-store path still bypassed in parallel). SetBypassHosts is a full replace, recomputed
	// from scratch on every change. Called on cert-pin materialize, on authored-rule change, and once at startup.
	applyMaterializedCertPinBypass := func(tenantID string) {
		if networkExtensionLabTLS == nil {
			return
		}
		hosts := staticBypass()
		hosts = append(hosts, policyrule.EgressBypassFQDNs(tenantID, ruleStore.List(tenantID, policyrule.PlaneEgress), assetStore)...)
		networkExtensionLabTLS.SetBypassHosts(hosts)
	}
	// Migrate cert-pin bypasses materialized before they became first-class rules: emit each as an authored Egress
	// rule now (idempotent) so every pinned-site bypass is one consistent rule and the single bypass source above
	// covers them. Done before the first applyInspectionPosture so the migrated rules are in place when the bypass
	// set is first built.
	//
	// ★ NOT ON A CONFIG-PULLING EDGE (2026-08-11). This migration authors rules and endpoint assets from a store
	// only this instance has, and on a CP-authoritative deployment that is a resurrection: the control plane
	// removes them on the next pull, this code recreates them on the next restart, and the two take turns. It was
	// visible in the lab — six cert-pin rules emitted at startup and deleted minutes later by the bundle, every
	// time the Edge came up.
	//
	// Adoption is authored on the control plane now (admin_policy_candidate_routes.go), so a materialized
	// candidate here is a LOCAL OBSERVATION whose authored consequence already lives, or does not live, upstream.
	// An Edge is a replaceable instance; letting one reinstate an inspection bypass out of its own history is
	// exactly the authority this deployment decided the CP holds.
	if strings.TrimSpace(*configSourceURL) == "" {
		for _, c := range materializedCertPinCandidates(policyCandidateStore, pb.TenantID) {
			if err := emitCertPinBypassRule(assetStore, ruleStore, c); err != nil {
				log.Printf("migrate cert-pin bypass %s to rule: %v", c.CandidateID, err)
			}
		}
	} else if n := len(materializedCertPinCandidates(policyCandidateStore, pb.TenantID)); n > 0 {
		// Said out loud, because these bypasses were real decisions someone made on this instance and they are
		// NOT being reinstated. Silence here would read as "there were none".
		log.Printf("cert-pin: %d materialized candidate(s) in this Edge's local store are NOT being re-authored — "+
			"the control plane authors bypasses on this deployment. If one of them should still be in force, add it "+
			"there (POST /admin/cert-pin-bypass) or it does not exist for the fleet.", n)
	}
	// Likewise migrate any legacy SaaS Optimize bypass selection (posture.bypass_groups) to authored rules, so the
	// engine reads ONE bypass source (authored rules) and the Optimize toggle is a real, visible rule. No-op when
	// no Optimize group is enabled (the default), so the decrypt-all North Star path is unchanged.
	if n := migratePostureOptimizeBypassToRules(postureStore, ruleStore, pb.TenantID); n > 0 {
		log.Printf("migrated %d legacy SaaS Optimize bypass group(s) to authored Egress rules", n)
	}
	// applyInspectionPosture applies BOTH layers from the live posture: the intercept (decrypt) host set —
	// decrypt_all restores the configured intercept hosts (typically "*"); bypass_default applies the decrypt
	// allowlist so only those hosts are decrypted and everything else is raw-forwarded (still steered +
	// policy-gated) — and the bypass set. Called at startup (restore a persisted posture) and on posture change.
	applyInspectionPosture := func(tenantID string) {
		if networkExtensionLabTLS != nil {
			p := postureStore.Get()
			if p.Mode == inspectionposture.ModeBypassDefault {
				// bypass-default: the intercept set is an explicit allowlist (posture hosts/groups) UNIONED with
				// authored `inspect` egress rules — so an operator says "decrypt these" by writing a rule, the
				// unified-model counterpart of an authored bypass rule (Phase B-2). Under decrypt-all the intercept
				// set is "*" already, so authored inspect rules are a no-op there and are not folded in.
				hosts := inspectionposture.EffectiveInterceptHosts(p)
				hosts = append(hosts, policyrule.EgressInspectFQDNs(tenantID, ruleStore.List(tenantID, policyrule.PlaneEgress), assetStore)...)
				networkExtensionLabTLS.SetInterceptHosts(hosts)
			} else {
				networkExtensionLabTLS.SetInterceptHosts(configuredInterceptHosts)
			}
		}
		applyMaterializedCertPinBypass(tenantID)
	}
	applyInspectionPosture(pb.TenantID)
	policyStore := policy.NewStore(policies)
	// Restore Admin-API runtime toggles persisted across restarts before serving, so a restart keeps
	// tenant-restriction status / east-west config without manual re-apply.
	//
	// FATAL on a store that exists but cannot be read or parsed. These toggles are security controls whose
	// zero value is OFF, so continuing past a failed load means booting with east-west authorization,
	// tenant-restriction rule status and server-initiated access all disabled — and then PERSISTING that as
	// though an administrator had chosen it, overwriting the evidence of what the posture was. Refusing to
	// start is the loud, recoverable failure; the quiet one leaves a product that looks healthy and enforces
	// less than it claims. An ABSENT store is still an ordinary first boot and is not an error.
	if err := policyStore.SetRuntimeStatePersister(mustCPStateBlobPersister(*adminRuntimeStateStorePath, "admin_runtime_state")); err != nil {
		log.Fatalf("admin runtime state: %v", err)
	}
	if err := networkExtensionPublisher.PublishAdminPolicySnapshot(context.Background(), pb.TenantID, policyStore, pb, time.Now()); err != nil {
		// Same argument as the publisher's own construction above: this WRITES AN ARTIFACT. A full disk or a
		// wrong permission on the output directory is a reason to lose the snapshot, not a reason for an
		// enforcement node to refuse to serve traffic. Loud, and the node comes up.
		log.Printf("WARNING: the initial agent-configuration snapshot was not published (%v) — the directory holds "+
			"no configuration, or a stale one, so a device installed from it would not carry this node's current "+
			"trusted authorities. Traffic is unaffected.", err)
	}

	oidc := oidcConfig{
		Issuer:                *oidcIssuer,
		ClientID:              *oidcClientID,
		ClientSecret:          *oidcClientSecret,
		RedirectURI:           *oidcRedirectURI,
		AuthorizationEndpoint: *oidcAuthorizationEndpoint,
		TokenEndpoint:         *oidcTokenEndpoint,
		JWKSURI:               *oidcJWKSURI,
		GroupsClaim:           *oidcGroupsClaim,
		HostedDomainClaim:     *oidcHostedDomainClaim,
		RequiredHostedDomain:  *oidcRequiredHostedDomain,
		HostedDomainGroup:     *oidcHostedDomainGroup,
		IDPID:                 *oidcIDPID,
	}
	// The anchors a shipping Edge's certificate is verified against. Operator-issued, deliberately separate
	// from the tenant CA registry: an Edge's identity is not a tenant's.
	if p := strings.TrimSpace(*auditIngestIdentity.clientCAs); p != "" {
		pem, rerr := os.ReadFile(p)
		if rerr != nil {
			log.Fatalf("read the audit-ingest client CA %q: %v", p, rerr)
		}
		if !addEdgeClientCAPEM(pem) {
			log.Fatalf("audit-ingest client CA %q contained no usable certificates", p)
		}
		log.Printf("audit-ingest: shipping edges are verified against %s (a client certificate is requested)", p)
	}
	// The Console's own admin client CA. See the flag for why a listener that verifies must be told about a
	// credential the deployment hands out, and why saying so grants nothing.
	if p := strings.TrimSpace(*adminClientCAFile); p != "" {
		pem, rerr := os.ReadFile(p)
		if rerr != nil {
			log.Fatalf("read the admin client CA %q: %v", p, rerr)
		}
		if !addEdgeClientCAPEM(pem) {
			log.Fatalf("admin client CA %q contained no usable certificates", p)
		}
		log.Printf("admin listener: client certificates issued by %s are accepted at the handshake (they authenticate nothing by themselves)", p)
	}
	// Which Edge may ship which tenants' records. Absent is the single-tenant deployment; a control plane
	// serving several tenants needs it, and says so rather than answering a wall of 403s.
	if authority, aerr := loadAuditIngestAuthority(strings.TrimSpace(*auditIngestIdentity.authority)); aerr != nil {
		log.Fatalf("load the audit-ingest authority map: %v", aerr)
	} else if authority != nil {
		setAuditIngestAuthority(authority)
		log.Printf("audit-ingest authority loaded: %d edge identity(ies) mapped to the tenants they may ship for",
			len(authority.byEdge))
	}
	// Per-organization transport server certificates (roadmap D, first slice). Loaded before any listener
	// starts, so the first handshake after a restart already answers for the names that are configured.
	if n, terr := loadTransportTenantCertificates(*transportTenantCertDir); terr != nil {
		log.Printf("transport tenant certificates: WARNING %v — every organization is served the shared certificate", terr)
	} else if n > 0 {
		log.Printf("transport tenant certificates: %d organization(s) are served their own: %s", n,
			strings.Join(transportTenantCertificates.Names(), ", "))
	}
	// load the per-tenant CA registry (fail-closed) when multi-tenant identification is configured.
	// The same registry drives both (T) admission (cross-tenant certs denied at the handshake) and the
	// data-plane authoritative-tenant binding inside newServerWithConfig (decision keyed to the cert's tenant).
	var tenantCAReg *tenantca.TenantCARegistry
	// ★★★ THE REGISTRY BELONGS TO THE FLEET (2026-08-21). See persistTenantCARegistry for the measurement: a
	// customer's device CA reached one Edge and every other node rejected that organization at the handshake.
	// "postgres", or nothing at all where the deployment has a shared database, puts it where every Edge reads
	// it. A path still means a file, unchanged.
	registryValue := strings.TrimSpace(*transportTenantCARegistry)
	// ★★★ A NODE THAT PULLS ITS CONFIG TAKES THE REGISTRY FROM THE BUNDLE, NOT FROM A DATABASE (2026-08-23).
	//
	// This registry answers "which organization does this certificate belong to" — the entrance to every
	// decision — and its authority sat on the ENFORCEMENT side: the flag was on the Edges and not on the
	// control plane, and the Edges agreed by sharing one Postgres row. A whole-snapshot blob keyed only by
	// store name, with no node in the key, written by every node that changes it: the shape behind an anchor
	// that flapped between two Edges sharing one store.
	//
	// It travels in the signed config bundle now (config_bundle_device_cas.go). So the shared-store path below
	// is for a node that AUTHORS — a control plane — and a config-pulling Edge never reaches it, which is what
	// takes the database off the enforcement plane rather than making it agree with itself.
	//
	// What stays on such an Edge is a local file: a CACHE of the registry it was last given, so a restart
	// resumes instead of admitting nobody until the first poll.
	if strings.TrimSpace(*configSourceURL) != "" {
		if registryValue == "" || storeBackend(registryValue) == "postgres" {
			registryValue = durableStorePath(*stateDir, "", "tenant_ca_registry")
		}
	} else if registryValue == "" && cpStateBlobDB != nil && *transportAdmission.multiTenant {
		registryValue = "postgres"
	}
	if storeBackend(registryValue) == "postgres" {
		p, perr := cpStateBlobPersister(registryValue, cpStateBlobDB, "tenant_ca_registry")
		if perr != nil {
			log.Fatalf("tenant CA registry: %v", perr)
		}
		tenantCARegistryShared = p
		if err := initializeSharedDeviceCARegistry(p, strings.TrimSpace(*transportTenantCARegistryCarriedFrom)); err != nil {
			log.Fatalf("initialize shared tenant CA registry: %v", err)
		}
		reg := tenantca.NewTenantCARegistry()
		if added, lerr := reg.LoadFrom(p); lerr != nil {
			log.Fatalf("load tenant CA registry from the shared store: %v", lerr)
		} else {
			log.Printf("tenant CA registry: shared with the fleet (%d CA(s) adopted at start-up) — a device CA "+
				"registered on any Edge admits that organization on all of them", added)
		}
		tenantCAReg = reg
		setDeviceCertificateTenantRegistry(reg)
		setEdgeClientRegistryCAs(reg.Anchors())
		// ★ AND READ AGAIN, BECAUSE A REGISTRATION MADE ELSEWHERE DID NOT EXIST WHEN THIS NODE BOOTED. Reading
		// a shared store once at start-up is the defect this deployment has now found three times in one night
		// (the transport trust store, the export download tokens, and this). Admission is a hot path, so the
		// re-read is on a timer rather than per handshake.
		go func(reg *tenantca.TenantCARegistry, p tenantca.Persister) {
			for range time.Tick(30 * time.Second) {
				// Reconcile, not adopt: a WITHDRAWAL has to travel too. Adopting was add-only, so a device CA
				// retired on one Edge went on admitting that organization's devices on every other one until a
				// restart — measured, one CA listed on region-a and two on region-b minutes after the
				// withdrawal. See TenantCARegistry.Reconcile.
				added, removed, err := reg.ReconcileFrom(p)
				if err != nil {
					log.Printf("tenant CA registry: could not read the fleet's registrations (%v)", err)
					continue
				}
				if added > 0 || removed > 0 {
					setEdgeClientRegistryCAs(reg.Anchors())
					log.Printf("tenant CA registry: %d device CA(s) adopted and %d withdrawn to match the fleet",
						added, removed)
				}
			}
		}(reg, p)
	} else if p := registryValue; p != "" {
		reg, rerr := tenantca.LoadTenantCARegistry(p)
		if rerr != nil {
			// ★★★ A CACHE THAT IS NOT THERE YET IS NOT A FAILURE (2026-08-23, measured — this stopped an Edge
			// from starting the moment the registry became a local cache). On a config-pulling Edge this file
			// is what the last config bundle gave it, so its ABSENCE is the ordinary Day-0 state: a node that
			// has never applied a bundle, or a new one joining the fleet. Refusing to start there turns "no
			// cache yet" into "this Edge is down", and the bundle would have filled it within one poll.
			//
			// A node that AUTHORS the registry — a control plane, or an Edge given an explicit file by an
			// operator — still fails: for it, the file is the authority, and starting without it would admit
			// nobody with nothing on the way to fix that.
			if os.IsNotExist(errors.Unwrap(rerr)) || strings.Contains(rerr.Error(), "no such file or directory") {
				if strings.TrimSpace(*configSourceURL) == "" {
					log.Fatalf("load tenant CA registry: %v", rerr)
				}
				log.Printf("tenant CA registry: no cache at %q yet — this Edge takes the registry from the "+
					"control plane's config bundle and will hold it after the first apply. Devices are refused "+
					"until then, which is the safe direction.", p)
				reg, rerr = tenantca.NewTenantCARegistry(), nil
			} else {
				log.Fatalf("load tenant CA registry: %v", rerr)
			}
		}
		tenantCAReg = reg
		// The same anchors the admin/Console listener offers as its client CAs, ADDED to whatever the
		// audit-ingest identity CA registered — a control plane configured with both used to keep only the
		// later one, and then rejected the operator-issued Edge certificate at the handshake. See
		// edge_client_ca_pool.go.
		setEdgeClientRegistryCAs(reg.Anchors())
		// So an observed device certificate can name the organization it belongs to. Without it the fact is
		// filed under nobody and the control plane refuses to accept it — see device_certificate_facts.go.
		setDeviceCertificateTenantRegistry(reg)
		log.Printf("tenant CA registry loaded: %d tenants (per-tenant CA admission/identification)", reg.TenantCount)
		// And say which of those authorities are running out. The certificate-health screen reports DEVICE
		// certificates; the one certificate whose lapse stops an ENTIRE organization from being admitted had
		// nothing watching it at all. Boot, then daily — a node up for three weeks is the node whose authority
		// is three weeks closer to lapsing.
		watchTenantAuthorityExpiry(reg, time.Now)
	}
	// W-2/W-7: the dynamic (T) admission revocation overlay. Created here so BOTH the admin kill-switch
	// handlers (via serverConfig) and the (T) listener (via secureTransportConfig below) share one instance.
	// Audit/persistence decoupling: ship audit/access records to the separate audit/control plane,
	// best-effort and non-blocking (composes with any postgres hot-store mirror hook). Default off; the
	// local jsonl emission is unchanged and remains canonical.
	// auditShipper is hoisted so the multi-region CP selector (built later, in the config-source block) can be
	// wired into it — audit replay then follows the current CP leader after an Edge→CP region failover.
	var auditShipper *remoteAuditShipper
	// Reported on /healthz. Nil until a shipper exists, which is what "this node was never told where to
	// ship" has to look like from outside.
	var auditShipHealthFn func(time.Time) map[string]any
	if strings.TrimSpace(*auditIngestURL) != "" {
		shipCert, shipKey := strings.TrimSpace(*auditIngestIdentity.cert), strings.TrimSpace(*auditIngestIdentity.key)
		shipper, serr := newRemoteAuditShipper(*auditIngestURL, *auditIngestToken, *auditIngestCA, defaultAuditShipStreams, 0, filepath.Join(*logDir, ".audit_ship", "spool.ndjson"), shipCert, shipKey)
		if serr != nil {
			log.Fatalf("audit shipper: %v", serr)
		}
		writer.AddAppendHook(shipper.hook())
		// Arms shipping of which certificate each device presents. Only meaningful where there is a control
		// plane to ship to — see device_certificate_fact_ship.go for why the withdrawal gate needs it.
		setDeviceCertificateShipWriter(writer)
		// And re-send everything periodically: the control plane's copy is in memory, so without this it would
		// be empty after any restart of it and the withdrawal gate would refuse every retirement again.
		startDeviceCertificateReship()
		auditShipper = shipper
		auditShipHealthFn = shipper.health
		log.Printf("audit shipping enabled -> %s (streams: %s; durable retain-and-replay, local jsonl canonical)", *auditIngestURL, strings.Join(defaultAuditShipStreams, ", "))
	}
	livenessRevocations := revocation.NewAdmissionRevocations()
	if p, e := cpStateBlobPersister(*admissionRevocationStore, cpStateBlobDB, "admission_revocations"); e != nil {
		log.Fatalf("resolve admission-revocation store: %v", e)
	} else {
		livenessRevocations.SetPersister(p) // Phase 3: persist kill-switches across a restart
	}
	// Active session revocation: track live (T) connections by identity so an ADMINISTRATOR can actively CLOSE
	// a blocked device's established tunnels (per-handshake admission already rejects NEW connections; this
	// bites established sessions too, so an admin kill-switch takes full effect in ~2s rather than waiting for
	// the client-side region-failover teardown).
	//
	// ★ INVARIANT: tearing down live sessions is reserved for an EXPLICIT ADMINISTRATOR BLOCK. It is deliberately
	// NOT wired to AdmissionRevocations.SetOnRevoked, because that overlay fires on every revocation path —
	// including ones no human authored: the CP fast-poll feed (ReplaceSynced), cross-region mesh propagation
	// (RevokeFromMesh), and node-reported automatic revocations (default reason "node_reported_auto_revocation",
	// e.g. liveness/agent-dark and risk-derived signals). Firing a fleet-wide kill-switch off a derived signal
	// turns any transient false positive into an outage, and has repeatedly done so. The teardown is therefore
	// invoked from exactly one place: the POST /admin/transport-admission/revoke handler.
	// Automatic revocations still enforce — they deny NEW handshakes via VerifyConnection — they just do not
	// rip down sessions that are already up.
	transportConns := newTransportConnRegistry()
	transportConns.setRevokedCheck(livenessRevocations.IsRevoked) // deny a conn that registers mid-sweep
	// Cross-region revocation mesh: on an ORIGIN revocation, push to the tenant's peer-region CPs.
	revocationMeshPeerList, err := parseRevocationMeshPeers(*revocationMeshPeers)
	if err != nil {
		log.Fatalf("invalid -revocation-mesh-peers: %v", err)
	}
	if len(revocationMeshPeerList) > 0 {
		var meshOutbox *revocationMeshOutbox
		if p, e := cpStateBlobPersister(*revocationMeshOutboxStore, cpStateBlobDB, "revocation_mesh_outbox"); e != nil {
			log.Fatalf("resolve revocation-mesh-outbox store: %v", e)
		} else if meshOutbox, e = newRevocationMeshOutbox(p); e != nil {
			log.Fatalf("load revocation-mesh outbox: %v", e)
		}
		meshSrc := revocationMeshSource{
			originRegion: *edgeRegionID,
			peers:        revocationMeshPeerList,
			secret:       strings.TrimSpace(*revocationMeshSecret),
			client:       &http.Client{Timeout: 15 * time.Second},
			outbox:       meshOutbox,
		}
		livenessRevocations.SetMeshReporter(meshSrc.pushFunc())
		// Durable outbox: drive any pushes that were enqueued but not acked before a restart to completion.
		if n := meshSrc.resumePendingDeliveries(); n > 0 {
			log.Printf("cross-region revocation mesh: resuming %d pending push(es) from the durable outbox", n)
		}
		log.Printf("cross-region revocation mesh: origin region %q -> %d peer region CP(s)", *edgeRegionID, len(revocationMeshPeerList))
	}
	highRiskOverlay := revocation.NewHighRiskOverlay()
	if p, e := cpStateBlobPersister(*highRiskStore, cpStateBlobDB, "high_risk_overlay"); e != nil {
		log.Fatalf("resolve high-risk store: %v", e)
	} else {
		highRiskOverlay.SetPersister(p) // Phase 3: persist high-risk markings across a restart
	}
	// management ledger: created here (empty) so BOTH the admin endpoints (via serverConfig) and the
	// (T) listener (via secureTransportConfig below) share one instance; seeded from the static inventory
	// once it is loaded further down.
	enrolledLedger := enrolledinventory.NewLedger()
	// The admin-issued enrolment tokens POST /enroll accepts. Its persister is attached alongside the ledger's,
	// below, and BEFORE the endpoint is registered — a restart must never re-open a token that was already spent.
	// Seat allocation: how an MSSP divides its licensed pool among the tenants it operates. Durable for a sharp
	// reason — losing it reads as zero seats for every tenant and stops enrolment across the whole fleet.
	seatAllocations := seatallocation.NewStore()
	vendorLicenceStore := newLicenseStore()
	// EVERY vendor key this deployment accepts. Loaded once at boot; an unreadable file is fatal rather than
	// silently unlicensed, because "no keys" and "keys we could not read" would otherwise look identical and
	// one of them means licensing quietly stopped being enforced.
	var licenseRecipient *ecdh.PrivateKey
	if path := strings.TrimSpace(*licenseRecipientKey); path != "" {
		pemText, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read -license-recipient-key %q: %v", path, err)
		}
		licenseRecipient, err = vendorlicense.ParseRecipientPrivateKeyPEM(string(pemText))
		if err != nil {
			log.Fatalf("parse -license-recipient-key %q: %v", path, err)
		}
	}
	var licenseAcceptedKeys []*ecdsa.PublicKey
	if path := strings.TrimSpace(*licenseVendorKeys); path != "" {
		pemText, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read -license-vendor-keys %q: %v", path, err)
		}
		licenseAcceptedKeys, err = vendorlicense.ParsePublicKeysPEM(string(pemText))
		if err != nil {
			log.Fatalf("parse -license-vendor-keys %q: %v", path, err)
		}
		log.Printf("vendor licence: %d accepted signing key(s); licensing is ENFORCED", len(licenseAcceptedKeys))
	}
	// Licensing is enforced exactly when this deployment was given vendor keys. Without them there is nothing to
	// verify against, and a single-tenant install or the reference lab must not be gated at all.
	enrolmentLicensingGate := newEnrolmentLicensing(seatAllocations, enrolledLedger, len(licenseAcceptedKeys) > 0, *enforceSeatQuota)
	// ★ THE DEPLOYMENT'S ONE PLACE TO TAKE AN IDENTITY CLAIM, built on any node that holds a database rather
	// than only on one that issues certificates. The control plane is the authority and does not issue, so
	// building this inside the issuer branch left it with none and the fleet's claim routes answered 404.
	var fleetIdentityClaimer enrolledinventory.IdentityClaimer
	if cpStateBlobDB != nil {
		if c, cerr := setupPostgresEnrolledIdentityClaims(context.Background(), cpStateBlobDB, *migrationDir,
			true, edgeNodeIdentityForClaims(*edgeRegionID, *listen)); cerr != nil {
			log.Fatalf("REFUSING TO START: this node holds the deployment's identity claim and it could not be "+
				"prepared (%v) — every enrolment in the fleet is decided here.", cerr)
		} else {
			fleetIdentityClaimer = c
		}
	}
	// The control plane's coordinates, kept for the two one-time decisions an Edge must not take alone: the
	// enrolment token's spend and the device identity's claim. Both are assigned in the config-source block
	// below, which is the only place the URL, bearer and pinned client exist.
	var (
		configSourceBaseForClaims   string
		configSourceTokenForClaims  string
		configSourceClientForClaims *http.Client
	)
	var enrolmentTokens enrolltoken.Authority
	// Announced once the selection has settled — see the deferred log below. A node that pulls its config
	// replaces the local store with the control plane, and the sentence has to describe the outcome.
	var announceLocalEnrolmentTokens func()
	// Chosen HERE, not later: the runtime config literal below captures this value, and an authority assigned
	// after that point would leave the admin API and the enrolment endpoint holding a nil one. That is not a
	// hypothetical — it happened, and the live Console answered "enrolment tokens are not configured on this
	// Edge" while every unit test passed, because the tests build the store directly and never go through main.
	// "postgres" selects the ROW-backed authority, not a blob in Postgres. That distinction is the whole point:
	// a blob is shared STORAGE but not a shared DECISION — each Edge would load it at boot and mutate its own
	// copy, so two Edges could both honour the same one-time token. With rows, spending is a single conditional
	// UPDATE and the database decides once. Every other value keeps the in-memory store, which is correct for a
	// single Edge and is what the reference deployment runs.
	if strings.EqualFold(strings.TrimSpace(*enrolmentTokenStore), "postgres") {
		if cpStateBlobDB == nil {
			log.Fatalf("-enrolment-token-store=postgres requires -postgres-dsn")
		}
		enrolmentTokens = newPostgresEnrolmentTokenStore(cpStateBlobDB)
		log.Printf("enrolment tokens: postgres (rows) — one-time holds across Edges")
	} else {
		local := enrolltoken.NewStore()
		local.SetPersister(mustCPStateBlobPersister(*enrolmentTokenStore, "enrolment_tokens"))
		enrolmentTokens = local
		// ★ SAID LATER, NOT HERE (2026-08-23). This sentence is what the fleet-uniformity guard reads to decide
		// whether a node keeps one-time tokens to itself — and a config-pulling Edge REPLACES this store with
		// the control-plane authority a few hundred lines below. Logging it here put both sentences in the log
		// and tripped the guard on a node that had done the right thing. Deferred to announceEnrolmentTokenStore
		// so the log says what the node ENDED UP with.
		announceLocalEnrolmentTokens = func() {
			log.Printf("enrolment tokens: local store (%s) — one-time holds within THIS Edge only; a multi-Edge deployment needs -enrolment-token-store=postgres",
				map[bool]string{true: "durable", false: "in-memory"}[strings.TrimSpace(*enrolmentTokenStore) != ""])
		}
	}
	var localCredentials *localAdminCredentialStore
	if *firstPartyAccounts {
		credDSN := strings.TrimSpace(*firstPartyStorePostgresDSN)
		if credDSN == "" {
			credDSN = *postgresDSN
		}
		credPersistence, closeCredStore, err := setupLocalCredentialPersistence(context.Background(), *firstPartyStore, credDSN, *migrationDir, *postgresRunMigrations)
		if err != nil {
			log.Fatalf("setup first-party credential store: %v", err)
		}
		defer closeCredStore()
		localCredentials, err = newLocalAdminCredentialStoreWithPersistence(*firstPartyIssuer, credPersistence)
		if err != nil {
			log.Fatalf("init first-party credential store: %v", err)
		}
		log.Printf("first-party admin accounts enabled (store=%s; invite -> activation link -> password + TOTP login)", strings.TrimSpace(strings.ToLower(*firstPartyStore)))
		// Fail loud (review #24): a TOTP shared secret is a reversible bearer credential. With a DURABLE store
		// but no KEK it is written to disk/DB in PLAINTEXT (protected only by storage perms) — anyone reading
		// the store can mint valid 2FA codes forever. In-memory stores keep it in process memory only, so the
		// warning is scoped to the durable case. Set -interception-root-kek-file to seal secrets at rest.
		if credPersistence != nil && len(edgeplane.GetInterceptionRootKEK()) == 0 {
			log.Printf("WARNING: first-party TOTP secrets are stored in PLAINTEXT (durable store with no -interception-root-kek-file). Anyone who can read the store can forge 2FA. Configure a root KEK to seal them at rest.")
		}
	}

	// Admin-managed steer exclusions (per tenant / device-group / device). Always constructed so the admin API
	// is available; durable on the control plane so admin-set exclusions survive a restart.
	steerExclDSN := strings.TrimSpace(*steerExclusionStorePostgresDSN)
	if steerExclDSN == "" {
		steerExclDSN = *postgresDSN
	}
	steerExclPersistence, closeSteerExcl, err := setupSteerExclusionPersistence(context.Background(), *steerExclusionStoreMode, steerExclDSN, *migrationDir, *postgresRunMigrations)
	if err != nil {
		log.Fatalf("setup steer exclusion store: %v", err)
	}
	defer closeSteerExcl()
	steerExclusions, err := steerexclusion.NewStoreWithPersistence(steerExclPersistence)
	if err != nil {
		log.Fatalf("init steer exclusion store: %v", err)
	}

	// The authorities each organization vouches for when this Edge verifies one of that organization's PRIVATE
	// assets after decrypting the flow to it. Durable in the same place as every other authored object: the
	// same DSN, so a deployment that made its policy durable does not silently keep this one in memory.
	//
	// ★ CONSTRUCTED UNCONDITIONALLY. Building the store only when a flag is set is how a feature ends up
	// present in the code, named in the Console and absent from every deployment.
	internalCAPersistence, closeInternalCAs, internalCAErr := setupInternalCAPersistence(
		context.Background(), strings.TrimSpace(*postgresDSN), *migrationDir, *postgresRunMigrations)
	if internalCAErr != nil {
		log.Printf("internal certificate authorities: no durable store (%v)", internalCAErr)
	} else {
		defer closeInternalCAs()
	}
	internalCAs, err := internalca.NewStore(internalCAPersistence)
	if internalCAErr != nil && err == nil {
		err = internalCAErr
	}
	if err != nil {
		// ★★★ AND IT IS NOT FATAL (2026-09-01). It was, for about an hour: the first roll carrying this store
		// put BOTH control planes of tokyo-west into a restart loop — "relation
		// \"internal_certificate_authorities\" does not exist" — because that node had not run the migration.
		// A region lost its admin plane over an object none of its flows was using yet. A feature that cannot
		// start must remove itself, not the node.
		log.Printf("internal certificate authorities: UNAVAILABLE on this node (%v). Private assets whose "+
			"certificates come from an organization's own authority will not be reachable through this node, "+
			"and the Console will say so rather than accepting authorities it cannot keep. Run the migrations.", err)
		internalCAs = internalca.NewUnavailableStore(err.Error())
	} else if internalCAPersistence != nil {
		// ★ AND IT RE-READS. On a deployment whose Edges share the control plane's database there is no pull
		// lane at all, so the list loaded at boot would be the only list this process ever had: an authority
		// added in the Console would be invisible until every Edge was restarted, while the Console showed it
		// saved.
		go func(store *internalca.Store) {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				if reloadErr := store.Reload(); reloadErr != nil {
					log.Printf("internal certificate authorities: re-read failed (keeping the last good list): %v", reloadErr)
				}
			}
		}(internalCAs)
	}
	// Reverse telemetry: each device's self-reported effective exclusion set, plus what it holds — the anchors
	// it pins, the distribution it adopted, the recovery name it was told (G2).
	//
	// ★★★ "OBSERVABILITY ONLY" STOPPED BEING TRUE AND THE COMMENT DID NOT (2026-08-19). This was described as a
	// cache that never feeds enforcement, so in-memory was sufficient and the reference compose left it that
	// way. Since then the DECISIONS were built on it: whether an authority may be withdrawn from a bundle
	// (transportCAReadiness) and whether the dedicated recovery port may be closed (recoveryNameReadiness).
	// Both turn on "has every device SAID it holds this", and both are irreversible for the devices that had
	// not.
	//
	// In memory that evidence has two holes, measured on the reference lab: a restart erases every report, so
	// the gate answers "silent" for a fleet that is fine; and each Edge only knows the reports IT received, so
	// region-b answered "nobody holds it" about devices that had told region-a. A gate whose evidence is
	// per-process is a gate that gives a different answer depending on which node you ask.
	//
	// So a deployment that makes those decisions should give this a durable, SHARED backend
	// (-observed-exclusion-store=postgres). It stays opt-in because a zero-DB Edge is a supported deployment —
	// but such a node cannot answer the withdrawal or port-closing question, and its readiness verdict must be
	// read as "this node does not know" rather than as "not yet".
	var observedExclusions observedExclusionStoreAPI = newObservedExclusionStore(inMemoryEventStoreCapacity())
	if strings.EqualFold(strings.TrimSpace(*observedExclusionStoreMode), "postgres") {
		obsDSN := strings.TrimSpace(*observedExclusionStorePostgresDSN)
		if obsDSN == "" {
			obsDSN = *postgresDSN
		}
		pgObserved, closeObserved, oerr := setupPostgresObservedExclusionStore(context.Background(), obsDSN, *migrationDir, *postgresRunMigrations)
		if oerr != nil {
			log.Fatalf("setup observed exclusion store: %v", oerr)
		}
		defer closeObserved()
		observedExclusions = pgObserved
	}
	// Config versioning + rollback (V-1): durable on the control plane (where -postgres-dsn is set). The
	// enforcing Edge (no postgres) gets a nil store and does not version. Every admin config change appends
	// an immutable version so an admin can list history and roll back.
	// Sovereign cold-archive backend (S3-compatible; MinIO/Ceph or an in-country provider, NOT AWS). Constructed when an endpoint
	// is configured; held for the retention lifecycle to tier aged segments to (instead of hard-deleting).
	var coldArchive archive.ColdArchive
	if ep := strings.TrimSpace(*coldArchiveEndpoint); ep != "" {
		ca, aerr := archive.New(archive.Config{
			Endpoint: ep, Bucket: *coldArchiveBucket, AccessKey: *coldArchiveAccessKey,
			SecretKey: *coldArchiveSecretKey, Region: *coldArchiveRegion, UseSSL: *coldArchiveUseSSL,
		})
		if aerr != nil {
			log.Printf("cold-archive setup failed (continuing without a cold tier): %v", aerr)
		} else {
			coldArchive = ca
			log.Printf("sovereign cold-archive ENABLED (%s) — aged segments tier to cold instead of delete", ca.Backend())
		}
	}

	// Legal-hold store (litigation/e-discovery): a held tenant's logs are preserved (retention frozen). Available
	// to both the retention pruner and the admin API.
	legalHold := newLegalHoldStore(mustCPStateBlobPersister(*legalHoldStorePath, "legal_hold"))
	// Audit tamper-evident hash-chain state (per-tenant), shared by the pruner (advances it) and the verify API.
	// ★ SEED THE FLEET PROJECTION ONCE (2026-08-14). The rows are folded at arrival from here on, but a control
	// plane that has just restarted has folded none — and until it has, every device that is not live on this
	// node is missing from the fleet view. One bounded read of the history at startup is what makes a restart
	// invisible to the page, and it is the same query that used to run on EVERY load.
	//
	// In a goroutine and best-effort: this query is measured at ~10s on the lab, and a control plane that will
	// not serve until its history has been read is a control plane that will not serve when its history store
	// is slow — which is exactly when everything else needs it.
	go seedFleetDeviceProjection(fleetDeviceProjectionStore, adminHotStore, evaluator.PolicyBundle.TenantID)

	auditChain := newAuditChainStore(mustCPStateBlobPersister(*auditChainStorePath, "audit_chain"))
	// Admin-configurable per-stream retention (Console), shared by the pruner (reads it) and the admin API.
	retentionOverride := newRetentionOverrideStore(mustCPStateBlobPersister(*retentionOverrideStorePath, "retention_override"))

	// W4: prune aged postgres log/outbox rows so the durable tables don't bloat unbounded (control plane).
	// With a cold archive configured, hot_events pruning TIERS aged rows to the sovereign store before delete.
	if dsn := strings.TrimSpace(*postgresDSN); dsn != "" {
		rcfg := retentionConfig{interval: *retentionPollInterval, hotEvents: *hotEventsRetention,
			outboxPublished: *outboxPublishedRetention, outboxDead: *outboxDeadRetention,
			archive: coldArchive, auditColdRetain: *auditColdRetention,
			perStream: parseRetentionOverrides(*hotEventsRetentionOverrides), legalHold: legalHold, auditChain: auditChain, override: retentionOverride}
		if rcfg.enabled() {
			closePruner, perr := startRetentionPruner(context.Background(), dsn, rcfg)
			if perr != nil {
				log.Printf("retention pruner setup failed (continuing without it): %v", perr)
			} else {
				defer closePruner()
			}
		}
	}
	configVersions, closeConfigVersions, err := setupConfigVersionStore(context.Background(), *postgresDSN, *migrationDir, *postgresRunMigrations)
	if err != nil {
		log.Fatalf("setup config version store: %v", err)
	}
	defer closeConfigVersions()
	// CP→Edge sync (P-3): the enforcing Edge pulls its steer exclusions from the control plane into the
	// in-memory cache above, so an Edge restart re-populates from the CP (zero-DB durability) and
	// Console-authored exclusions reach this Edge's devices on the next poll. The same channel also lets the
	// Edge ship/read config VERSIONS to the CP (S6) for Edge-side resources like tenant-restriction.
	var cpVersions *cpConfigVersionClient
	// The agent-rollout cache exists (and this Edge counts as an enforcing one) as soon as a source URL is set.
	// Created here because both the puller below and the server config further down need the same instance.
	agentRolloutPulled := agentRolloutCacheOrNil(*rolloutControl.sourceURL)
	// ★ DURABLE BY DEFAULT, through the same guard every other store uses: with -state-dir set this persists
	// with no flag of its own, which is that lane's whole point — a store added later inherits durability
	// instead of being born volatile. Edges pull this as the AUTHORITY for the halt, so an in-memory copy meant
	// a control-plane restart answered "not frozen" to a fleet somebody had halted during an incident.
	//
	// A store that cannot be READ stops this process. Answering "not frozen" because a file is corrupt is the
	// exact failure this path exists to prevent, and it would look like a perfectly healthy control plane.
	// The control plane's PUBLISHED RELEASES, durable through the same guard. An unreadable store stops the
	// process for the same reason the halt's does: answering "nothing published" to a fleet because a file is
	// corrupt stalls every device with no explanation anywhere.
	publishedDurable := newPublishedAgentUpdateStore()
	// ★★★ IT LIVES WHERE THE DEPLOYMENT'S STATE LIVES, NOT ON THE NODE THAT SERVED THE PUBLISH (2026-08-28,
	// measured). region-a's control plane held the catalogue and region-b's had no file at all — it never
	// received the publish and loads its own disk at start-up. The front door balances both, so an Edge polling
	// every minute was answered 1 target, then 0, then 1, and every device read "nothing published" every other
	// minute. Third instance of one shape in a day; same answer as the other three.
	//
	// -agent-updates-store=postgres is what a deployment with more than one control plane must set, and what
	// this product's installer now writes; a deployment already publishing from a file migrates with
	// postgres+import:<that file>, exactly like every other store here.
	if storeShouldBeWired(*agentUpdatesStorePath) {
		if lerr := publishedDurable.LoadFromPersister(mustCPStateBlobPersister(*agentUpdatesStorePath, "agent_updates"),
			pb.TenantID); lerr != nil {
			log.Fatalf("published agent-update store: %v", lerr)
		}
		if storeBackend(*agentUpdatesStorePath) == "postgres" {
			log.Printf("published agent-update store: shared — every control plane of this deployment answers " +
				"the same published set")
			// ★★★ AND THE BYTES WITH THEM. A shared catalogue over node-local artifacts is a release every
			// node can NAME and only one can HAND OVER — see publishedAgentUpdateStore.shelf.
			publishedDurable.WithArtifactShelf(sharedAgentUpdateArtifactShelf(cpStateBlobDB))
			// And what this node already holds goes onto it, once — see SeedShelfFromDisk. Without this, every
			// release published before the shelf existed would be named by both control planes and served by
			// neither.
			if seeded := publishedDurable.SeedShelfFromDisk(strings.TrimSpace(*agentUpdate.dir),
				splitAgentUpdatePins(*agentUpdate.pin), time.Now()); seeded > 0 {
				log.Printf("published agent-update store: put %d release artifact(s) this node held onto the "+
					"deployment's shelf", seeded)
			}
		}
	}
	agentRolloutDurable := agentrollout.NewAgentRolloutStore()
	// ★★★ AND SO DOES THE HALT (2026-08-28, same measurement). What an organization is TOLD to run had the
	// same node-local life as the catalogue of what exists: an operator freezing a rollout wrote one control
	// plane's disk, and the Edge polling the front door was answered "frozen", then "not frozen", by two nodes
	// that had each been told a different thing. See the note on AgentRolloutStore.blob.
	if storeShouldBeWired(*agentRolloutStorePath) {
		if lerr := agentRolloutDurable.LoadFromPersister(mustCPStateBlobPersister(*agentRolloutStorePath, "agent_rollout")); lerr != nil {
			log.Fatalf("agent rollout store: %v", lerr)
		}
		if storeBackend(*agentRolloutStorePath) == "postgres" {
			log.Printf("agent rollout store: shared — every control plane of this deployment answers the same " +
				"halt and the same desired versions")
		}
	}

	// ★ ITS OWN BLOCK, ITS OWN CLIENT (2026-08-11, second review). The first version started this poller inside
	// the steer-exclusion sync's `if`, so setting ONLY -agent-rollout-source-url created the cache and never
	// pulled into it — and an Edge with an unpulled cache serves FROZEN forever while refusing local writes. A
	// feature whose liveness depends on an unrelated feature being configured is a trap laid for whoever
	// configures exactly what they need.
	if rolloutURL := strings.TrimSpace(*rolloutControl.sourceURL); rolloutURL != "" && agentRolloutPulled != nil {
		caFile := strings.TrimSpace(*steerExclusionSourceCA)
		if caFile == "" {
			caFile = strings.TrimSpace(*configSourceCA)
		}
		if caFile == "" {
			caFile = strings.TrimSpace(*adminSessionAuthorityCA)
		}
		if serr := requireHTTPSSource("agent-rollout", rolloutURL); serr != nil {
			log.Fatalf("%v", serr)
		}
		rolloutClient, cerr := buildSteerExclusionSourceClient(caFile)
		if cerr != nil {
			log.Fatalf("agent-rollout sync client: %v", cerr)
		}
		// ★ THIS CALL CROSSES A PLANE, SO IT NEEDS THE CREDENTIAL FOR THE OTHER PLANE (2026-08-17). It used
		// -admin-token — the token that authenticates callers TO THIS EDGE — to authenticate an outbound pull
		// FROM THE CONTROL PLANE. Those are different credentials on any deployment where they were minted
		// separately, which is every deployment that took least privilege seriously. On the lab the control
		// plane answered 401 every 30 seconds since boot and the agent rollout plan was never fetched; the
		// message ("control plane answered HTTP 401") went to the container log and nowhere else.
		//
		// Every other CP→Edge puller here uses -steer-exclusion-source-token, so that is what this uses, with
		// the old flag kept as the fallback so a deployment where one token serves both keeps working.
		rolloutToken := strings.TrimSpace(*steerExclusionSourceToken)
		if rolloutToken == "" {
			rolloutToken = strings.TrimSpace(*adminToken)
		}
		if rolloutToken == "" {
			log.Fatalf("agent-rollout sync: -agent-rollout-source-url is set but there is no control-plane token to " +
				"authenticate the pull with (-steer-exclusion-source-token, or -admin-token when one credential " +
				"serves both planes); this edge would serve FROZEN forever")
		}
		go agentRolloutSource{url: rolloutURL, token: rolloutToken, tenantID: evaluator.PolicyBundle.TenantID,
			interval: *rolloutControl.poll, client: rolloutClient}.run(context.Background(), agentRolloutPulled)
	}
	if srcURL := strings.TrimSpace(*steerExclusionSourceURL); srcURL != "" {
		token := strings.TrimSpace(*steerExclusionSourceToken)
		if token == "" {
			token = strings.TrimSpace(*adminToken)
		}
		caFile := strings.TrimSpace(*steerExclusionSourceCA)
		if caFile == "" {
			caFile = strings.TrimSpace(*configSourceCA)
		}
		if caFile == "" {
			caFile = strings.TrimSpace(*adminSessionAuthorityCA)
		}
		srcClient, cerr := buildSteerExclusionSourceClient(caFile)
		if cerr != nil {
			log.Fatalf("steer-exclusion sync client: %v", cerr)
		}
		src := steerExclusionSource{
			url: srcURL, token: token, tenantID: evaluator.PolicyBundle.TenantID,
			interval: *steerExclusionSourcePoll, client: srcClient,
		}
		go src.run(context.Background(), steerExclusions)
		// The same lane for the agent-update halt: the control plane owns it, this edge pulls it, and a fetch
		// failure keeps the last good answer rather than reverting to "not halted".

		// Rehydrate the device-runtime view from the control plane's durable device-state history. Without it a
		// restart empties the fleet view and a device only returns when it happens to dial a new mux — measured
		// on the lab as a Mac that stayed missing for hours while steering never stopped. Best-effort and
		// one-shot: live CONNECT/OPEN traffic keeps it fresh once running, and a failure leaves exactly the empty
		// map this Edge would have had anyway. See device_runtime_hydrate.go.
		// ★★ IT RETRIES NOW, AND ONE-SHOT WAS THE DEFECT (2026-08-13, from an operator: the Devices page said
		// "no user" for a Mac somebody was sitting at). The history query takes about 15 seconds on this lab
		// against a 20-second budget, so a control plane that is momentarily busy at Edge startup — which is
		// exactly when an Edge starts, because everything else is starting too — loses the race. One timeout
		// then degrades the fleet view for the LIFE OF THE PROCESS: logged-in users come from steer OPEN frames,
		// so they refill only when a device happens to open a new flow, and posture keeps arriving so the row
		// looks alive and merely userless.
		//
		// The old comment called that "exactly the empty map this Edge would have had anyway", which is true of
		// the first second and false of the next eight hours. Same shape as the connector that exited when the
		// Edge was not up yet: a transient failure made permanent by not trying again.
		go func(hydrate deviceRuntimeHydrateSource) {
			delay := 15 * time.Second
			for attempt := 1; attempt <= 5; attempt++ {
				ctx, cancel := context.WithTimeout(context.Background(), deviceRuntimeHydrateWait)
				restored, herr := hydrate.hydrate(ctx, deviceRuntime)
				cancel()
				if herr == nil {
					log.Printf("device-runtime hydrated from the control plane: %d device(s) restored (attempt %d)",
						restored, attempt)
					return
				}
				if attempt == 5 {
					log.Printf("★ device-runtime hydration failed %d times (%v) — the fleet view will show devices "+
						"as they reconnect, and until a device opens a flow its logged-in user is unknown rather "+
						"than absent", attempt, herr)
					return
				}
				log.Printf("device-runtime hydration attempt %d failed (%v); retrying in %s", attempt, herr, delay)
				time.Sleep(delay)
				if delay < 2*time.Minute {
					delay *= 2
				}
			}
		}(deviceRuntimeHydrateSource{url: srcURL, token: token, tenantID: src.tenantID, client: srcClient})
		cpVersions = &cpConfigVersionClient{url: srcURL, token: token, client: srcClient}
		log.Printf("steer-exclusion CP→Edge sync ENABLED (source=%s tenant=%s poll=%s)", srcURL, src.tenantID, src.interval)
	}
	// Phase 1 config distribution: when -config-source-url is set, this Edge PULLS its versioned config
	// bundle (slice 1: access policies) from the control plane and applies it atomically on each poll, so a
	// fleet enforces identically. Reuses the steer-exclusion source token/CA defaults. Empty = local stores.
	// configSyncStatus (nil when sync is off) exposes the LAST CP generation this Edge applied for the
	// fleet-health / staleness signal — see GET /admin/config-sync-status and /healthz below.
	var configSyncStatus *configBundleSyncStatus
	// The FAST revocation poller's status, so /healthz can be asked whether this node has ever held a set from
	// the control plane. nil = no -config-source-url, i.e. no CP→Edge sync configured at all.
	var revocationSyncState *revocationSyncStatus
	var sharedRevocationSource *revocationSource
	var configBundlePuller *configBundleSource // launched inside newServerWithConfig, where the DNS resolver exists too
	// enrolmentCPReport tells the control plane about enrolments completed HERE. Constructed only when this
	// Edge follows a control plane, because that is exactly when the omission bites: the config bundle
	// rebuilds the enrolled ledger from the CP's copy, and an enrolment the CP never heard of is dropped.
	var enrolmentCPReport *enrolmentCPReporter
	var directoryCPReport *directoryCPReporter
	if cfgURL, cpEndpointsSeed := strings.TrimSpace(*configSourceURL), strings.TrimSpace(*configSourceEndpoints); cfgURL != "" || cpEndpointsSeed != "" {
		token := strings.TrimSpace(*steerExclusionSourceToken)
		if token == "" {
			token = strings.TrimSpace(*adminToken)
		}
		caFile := strings.TrimSpace(*steerExclusionSourceCA)
		if caFile == "" {
			caFile = strings.TrimSpace(*configSourceCA)
		}
		if caFile == "" {
			caFile = strings.TrimSpace(*adminSessionAuthorityCA)
		}
		cfgClient, cerr := buildSteerExclusionSourceClient(caFile)
		if cerr != nil {
			log.Fatalf("config-bundle sync client: %v", cerr)
		}
		// Multi-region control-channel failover: probe each CP's /leader and pull from the region holding
		// leadership; single-CP mode keeps the fixed -config-source-url. GSLB-free (client-driven, residency-safe).
		var cpEndpointSel *cpEndpointSelector
		sourceLabel := cfgURL
		if cpEndpointsSeed != "" {
			cpEndpointSel = newCPEndpointSelector(parseCPEndpoints(cpEndpointsSeed), strings.TrimSpace(*configSourceHome), cfgClient, *configSourcePoll, *configSourceStrikes)
			if cpEndpointSel != nil {
				go cpEndpointSel.run(context.Background())
				sourceLabel = "multi-region:" + cpEndpointsSeed
				log.Printf("config-bundle CP→Edge control-channel region failover ENABLED (endpoints=%q home=%q)", cpEndpointsSeed, strings.TrimSpace(*configSourceHome))
				// Phase 2 (cross_region_control_plane_failover_design.mdc/): extend the SAME CP selector to
				// the audit-ship path so the durable spool replays buffered audit/access records to the current CP
				// leader after an Edge→CP region failover — no lost logs within the spool window.
				if auditShipper != nil {
					auditShipper.setEndpoints(cpEndpointSel)
					log.Printf("audit shipping now follows the multi-region CP selector (region failover-aware, durable retain-and-replay)")
				} else {
					// No fixed -audit-ingest-url, but the multi-region CPs are themselves the audit targets: build a
					// selector-only shipper. The CP admin listener serves /audit-ingest, /leader and the config
					// bundle on one TLS identity, so fall back to the config-source token/CA when the audit-ingest
					// flags are unset.
					auditCA := strings.TrimSpace(*auditIngestCA)
					if auditCA == "" {
						auditCA = caFile
					}
					auditTok := strings.TrimSpace(*auditIngestToken)
					if auditTok == "" {
						auditTok = token
					}
					shipCert, shipKey := strings.TrimSpace(*auditIngestIdentity.cert), strings.TrimSpace(*auditIngestIdentity.key)
					shipper, serr := newRemoteAuditShipper("", auditTok, auditCA, defaultAuditShipStreams, 0, filepath.Join(*logDir, ".audit_ship", "spool.ndjson"), shipCert, shipKey)
					if serr != nil {
						log.Fatalf("audit shipper (multi-region): %v", serr)
					}
					shipper.setEndpoints(cpEndpointSel)
					writer.AddAppendHook(shipper.hook())
					// Arms shipping of which certificate each device presents. Only meaningful where there is a control
					// plane to ship to — see device_certificate_fact_ship.go for why the withdrawal gate needs it.
					setDeviceCertificateShipWriter(writer)
					// And re-send everything periodically: the control plane's copy is in memory, so without this it would
					// be empty after any restart of it and the withdrawal gate would refuse every retirement again.
					startDeviceCertificateReship()
					auditShipper = shipper
					log.Printf("audit shipping enabled -> multi-region CP selector (durable retain-and-replay, local jsonl canonical)")
				}
			}
		}
		// Said out loud whether there is a list or a single URL: an Edge with one control plane looks exactly
		// like one with four until the region answering it dies. See controlChannelStateForReport.
		setCPDataEndpoints(strings.TrimSpace(*cpDataEndpointsFlag))
		setControlChannelState(cpEndpointSel, cfgURL)
		configSyncStatus = &configBundleSyncStatus{source: sourceLabel, interval: *configSourcePoll}
		configBundlePuller = &configBundleSource{
			url: cfgURL, endpoints: cpEndpointSel, token: token, tenantID: evaluator.PolicyBundle.TenantID,
			interval: *configSourcePoll, client: cfgClient, status: configSyncStatus,
			// Tell the control plane which generation this Edge actually holds. Without it, "applied" in the
			// Console means "applied on whichever Edge the console front door proxies to" — the sentence that
			// made the 2026-08-10 incident undiagnosable. See fleet_config_status.go.
			reporter: &fleetConfigReporter{
				url: cfgURL, token: token, client: cfgClient,
				regionID: *edgeRegionID, clusterID: *edgeClusterID, nodeID: edgeNodeIdentity(),
				// The machine this runs on, as the operator declared it — see fleetConfigReport.Machine.
				machine: strings.TrimSpace(os.Getenv("DSSE_NODE_NAME")),
				address: strings.TrimSpace(os.Getenv("DSSE_NODE_ADDRESS")),
			},
		}
		// ★★★ AND THIS EDGE ASKS THE AUTHORITY WHETHER A ONE-TIME TOKEN MAY BE SPENT (2026-08-23). Spending one
		// is the act of deciding that a device may be issued a certificate, and that decision is the control
		// plane's. So a node that PULLS its config holds no token store at all — it asks, and the single
		// conditional write stays exactly where it always was. See enrolment_token_remote.go for why the
		// requirement was real and why it still is not a reason for an enforcement node to hold a database.
		//
		// When the control plane is unreachable, enrolment stops here. Same judgement the licence seat gate
		// makes: enrolment is GROWTH, devices already enrolled are untouched, and an Edge deciding for itself
		// while it cannot reach the authority is exactly how "one-time" becomes "once per Edge".
		//
		// Placed HERE rather than beside the store selection above, because the control plane's URL, bearer and
		// pinned client are built in this block and nowhere earlier — and still before the runtime config
		// literal captures the value, which is the constraint that selection comments about.
		configSourceBaseForClaims, configSourceTokenForClaims, configSourceClientForClaims = cfgURL, token, cfgClient
		if remote := newRemoteEnrolmentTokenAuthority(cfgURL, token, cfgClient); remote != nil {
			enrolmentTokens = remote
			announceLocalEnrolmentTokens = nil // the local store was replaced; do not say this node keeps its own
			log.Printf("enrolment tokens: asked of the control plane at %s — this Edge holds no token store, "+
				"and no device can enrol here while that is unreachable (devices already enrolled are unaffected)",
				cfgURL)
		}
		// The poll goroutine is launched in newServerWithConfig once the DNS resolver (a separate store the
		// bundle also distributes) has been constructed, so a single pull applies policies + tenant-config +
		// DNS together. See serverConfig.ConfigBundleSource.
		log.Printf("config-bundle CP→Edge sync ENABLED (source=%s tenant=%s poll=%s)", sourceLabel, configBundlePuller.tenantID, configBundlePuller.interval)
		// Phase 3 shared revocation overlay: a DEDICATED FAST poller (default 2s) of GET /admin/revocations on
		// the same control plane, applied to the SAME admission overlay the (T) handshake consults — so a
		// device revoked on the CP is refused on THIS node within seconds (reconnect-to-evade blocked). Only the
		// synced layer is touched; this node's own auto-revocations are preserved.
		revocationSyncState = &revocationSyncStatus{}
		revSrc := revocationSource{url: cfgURL, endpoints: cpEndpointSel, token: token, interval: *revocationSourcePoll,
			client: cfgClient, status: revocationSyncState}
		sharedRevocationSource = &revSrc
		// This node reports what it observes to the control plane, which RECORDS it for an administrator. It
		// does not revoke anything, here or there.
		livenessRevocations.SetReporter(revSrc.reportFunc())
		log.Printf("shared-revocation CP→Edge sync ENABLED (source=%s poll=%s; node→CP reporting on — reports are RECORDED for an administrator, never enforced)", sourceLabel, revSrc.interval)
		// Enrolments completed on this Edge are reported to the control plane, with a durable outbox so a
		// CP that is briefly away costs a retry rather than a device. Without this the ledger merge drops
		// devices this Edge itself issued certificates to — see enrolment_cp_report.go.
		// ★ The machine door, when this deployment has one: the Edge proves which node it is with the same
		// certificate the material fetch presents, so a report about ANOTHER organization does not need a
		// human elevation nobody can give a machine. Falls back to the admin door when there is no
		// audit-ingest identity, which is exactly today's behaviour.
		machineURL, machineClient := "", (*http.Client)(nil)
		if base := strings.TrimSpace(*auditIngestURL); base != "" {
			if cfg, terr := auditShipTLSConfig(strings.TrimSpace(*auditIngestCA),
				strings.TrimSpace(*auditIngestIdentity.cert), strings.TrimSpace(*auditIngestIdentity.key)); terr == nil && cfg != nil {
				if trimmed := strings.TrimSuffix(strings.TrimRight(base, "/"), "/audit-ingest"); trimmed != "" {
					machineURL = trimmed + "/enrolment-report"
					machineClient = &http.Client{Timeout: 20 * time.Second,
						Transport: &http.Transport{TLSClientConfig: cfg}}
				}
			}
		}
		enrolmentCPReport = &enrolmentCPReporter{
			url: cfgURL, token: token, client: cfgClient,
			machineURL: machineURL, machineClient: machineClient,
			// ★ THE OUTBOX IS NOT OPTIONAL, AND durableStorePath RETURNS EMPTY WITHOUT -state-dir (found by
			// reading the live log line, which printed "outbox=" — every queued report would have been
			// dropped on the floor, on exactly the Edges least likely to have been given a state dir). The
			// log directory is always set and always durable, so it is the floor rather than nothing.
			outboxPath: enrolmentOutboxPath(*stateDir, *logDir),
			logf:       log.Printf,
		}
		go enrolmentCPReport.drain(context.Background(), 30*time.Second)
		// The same shape for a connector that joins here: it reaches only this Edge, so the authority learns
		// about it by being told, with the same durable outbox so a control plane that is briefly away costs
		// a retry rather than a connector.
		if machineURL != "" && machineClient != nil {
			connectorCPReport = &connectorCPReporter{
				url:        strings.TrimSuffix(strings.TrimRight(machineURL, "/"), "/enrolment-report") + "/connector-report",
				client:     machineClient,
				outboxPath: filepath.Join(filepath.Dir(enrolmentOutboxPath(*stateDir, *logDir)), "connector_cp_outbox.json"),
				logf:       log.Printf,
			}
			go connectorCPReport.drain(context.Background(), 30*time.Second)
			// ★ AND THE GRANTS THIS NODE MINTS, for the same reason and by the same route: a grant lived in
			// one Edge's memory, so an Edge restart dropped every one of them and a region with more than
			// one Edge could run the ceremony on one node and hold the flow on another. A reconcile rather
			// than an outbox — grants are few, small and idempotent, so sending the live set converges after
			// any outage. See grant_cp_report.go.
			go (&grantCPReporter{
				url:    strings.TrimSuffix(strings.TrimRight(machineURL, "/"), "/enrolment-report") + "/grant-report",
				client: machineClient,
				grants: theGrantStore.Load,
				logf:   log.Printf,
			}).reconcile(context.Background(), 30*time.Second)
			log.Printf("connector→CP reporting ENABLED (target=%s) — a connector that joins this node is named "+
				"to the control plane, which is the only place it can be given a name or routes",
				connectorCPReport.url)
		} else {
			log.Printf("★ connector→CP reporting is OFF: this Edge has no machine-door identity, so a connector " +
				"that joins here is known to this node alone — the control plane can give it no name and no " +
				"routes. Configure -audit-ingest-url and -audit-ingest-client-cert/-key")
		}
		// The same shape for the people directory: a connector reaches only the Edge, so an import that lands
		// here has to be carried to the authority or the rest of the deployment never learns about it.
		directoryCPReport = &directoryCPReporter{
			url: cfgURL, token: token, client: cfgClient,
			outboxPath: directoryImportOutboxPath(*stateDir, *logDir),
			logf:       log.Printf,
		}
		go directoryCPReport.drain(context.Background(), 30*time.Second)
		log.Printf("directory-import→CP reporting ENABLED (target=%s outbox=%s) — a connector's directory sync lands on this node and is carried to the control plane, which is what makes the fleet and the Console see the same people", sourceLabel, directoryCPReport.outboxPath)
		log.Printf("enrolment→CP reporting ENABLED (target=%s outbox=%s) — a device enrolled on this node is named to the control plane, so the next config bundle keeps it admitted", sourceLabel, enrolmentCPReport.outboxPath)
	}
	trustBundleCAPEM := ""
	if p := strings.TrimSpace(*trustBundleCA); p != "" {
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			log.Fatalf("read -trust-bundle-ca: %v", rerr)
		}
		trustBundleCAPEM = string(raw)
	}
	// The ACTIVE agent-policy signer. An HSM-held ECDSA key (the config-signing key's destination — no
	// crypto11 binding does Ed25519 in a token) takes precedence over the on-disk Ed25519 key when its flags
	// are set: this is the flip, step 4 of the switch, and it is a config change so it is auditable and
	// reversible by pointing back at the file. Until those flags are set, nothing changes.
	// Functional custody monitors for the online signing keys that are NOT on the traffic path (device-CA,
	// agent-policy). They share the interception key's token but sign rarely, so a per-key fault would otherwise
	// stay invisible until someone enrols a device or edits policy. These log degradation and feed the admin
	// custody surface; they do NOT gate /healthz (that stays the interception key's job — see the monitor's doc).
	var secondaryCustodyMonitors []*edgeplane.SecondaryKeyCustodyMonitor
	var agentPolicySigner *agentpolicy.Signer
	if sock := strings.TrimSpace(*agentPolicyHSMAgentSocket); sock != "" {
		hsmSigner, herr := newHSMAgentSignerForSocket(sock,
			strings.TrimSpace(*agentPolicyHSMAgentToken), strings.TrimSpace(*agentPolicyHSMAgentKeyID))
		if herr == nil {
			agentPolicySigner, err = agentpolicy.NewSignerFromCrypto(hsmSigner)
			// Monitor the HSM-held agent-policy key directly. Verify against its own public half (it signs policy
			// blobs, not a certificate). Only when it is genuinely HSM-backed — the on-disk fallback below is a
			// degraded posture already logged loudly, not something to health-probe.
			if err == nil {
				sgn := hsmSigner
				secondaryCustodyMonitors = append(secondaryCustodyMonitors, edgeplane.NewSecondaryKeyCustodyMonitor(
					"agent_policy",
					func(now func() time.Time) edgeplane.KeyCustodyHealth {
						return edgeplane.ProbeSigningKey(sgn, sgn.Public(), edgeplane.KeyCustodyPKCS11, edgeplane.AgentPolicyKeyCustodyHealthText, now)
					}, 30*time.Second, log.Printf))
			}
		}
		if herr != nil || err != nil {
			// DEGRADE, do not abort the Edge. A config-signing failure only means "policy is not updated" —
			// devices fail-safe to the last verified policy — whereas an Edge that will not boot drops steering
			// itself. This mirrors the device-CA path (degrade + loud), matches never-stop, and is what the
			// Windows agent and the review both asked for over the previous log.Fatalf.
			cause := herr
			if cause == nil {
				cause = err
			}
			err = nil
			logErrorf("agent-policy HSM signer unavailable (%v) — DEGRADING rather than aborting the Edge", cause)
			// Fall back to the on-disk key ONLY IF THE FILE EXISTS: load it, never generate. Generating here
			// would mint a key the fleet has never pinned and sign policy every device rejects (review #34, and
			// the token key-provisioning warning). During the overlap the on-disk Ed25519 key is still in the
			// accepted set, so this keeps policy updates flowing; with no fallback file the signer stays nil and
			// falls through to the existing unsigned-in-production guard below.
			// LoadSigner, not Stat-then-LoadOrGenerateSigner: the latter expresses "load, never generate" as a
			// race, and the call that wins it if the file vanishes in between is the one that MINTS a key. A key
			// minted here is one no device has pinned or adopted, so the Edge would report itself healthy while
			// signing policy the whole fleet rejects.
			if p := strings.TrimSpace(*agentPolicySigningKeyPath); p != "" {
				s, lerr := agentpolicy.LoadSigner(p, *devMode)
				switch {
				case lerr == nil && s != nil:
					// Adopt the fallback ONLY IF devices will accept it: its public key must be in the set this
					// Edge publishes for adoption (-agent-policy-next-public-key). Once the Ed25519 pin is removed
					// from the accepted set (the re-pin task), this on-disk key becomes one no device accepts —
					// and signing with it would be SILENT: the Edge reports healthy, every device rejects the
					// policy, and the symptom is indistinguishable from "nothing changed" (policy-verify failure
					// is device-local; trust_refusals is transport-only). Refuse + loud so the nil-signer guard
					// below stops the Edge loudly instead of signing poison (the trap the Windows agent flagged).
					published := map[string]bool{}
					for _, k := range splitCommaList(*agentPolicyNextPublicKey) {
						published[strings.ToLower(strings.TrimSpace(k))] = true
					}
					if published[strings.ToLower(s.PublicKeyHex())] {
						agentPolicySigner = s
						logWarnf("agent-policy signing DEGRADED to the on-disk key %s (public_key=%s, in the published accepted set) — restart once the HSM sidecar is reachable to return to hardware custody", p, s.PublicKeyHex())
					} else {
						logErrorf("agent-policy on-disk fallback %s (public_key=%s) is NOT in the published accepted set (-agent-policy-next-public-key) — REFUSING it: devices would reject policy signed by it silently. Signing stays disabled; publish this key for adoption or remove the stale fallback file.", p, s.PublicKeyHex())
					}
				case errors.Is(lerr, fs.ErrNotExist):
					logWarnf("agent-policy HSM unavailable and no on-disk fallback key at %s — signing stays disabled (devices keep their last verified policy)", p)
				default:
					logErrorf("agent-policy on-disk fallback %s failed to load: %v — signing stays disabled", p, lerr)
				}
			}
		} else {
			log.Printf("agent-policy signing key is in a PKCS#11 token via %s — this process does NOT hold it", sock)
		}
	} else {
		agentPolicySigner, err = agentpolicy.LoadOrGenerateSigner(*agentPolicySigningKeyPath, *devMode)
	}

	// The downgrade floor. Loaded before anything can sign: a ratchet that starts empty because its file could
	// not be read is not a ratchet, and the version it would then permit is the old one.
	agentUpdateSignFloor := newAgentUpdateSignRatchet(strings.TrimSpace(*stateDir))
	if ferr := agentUpdateSignFloor.Load(); ferr != nil {
		log.Fatalf("update-signing floor: %v — refusing to start, because the alternative is a control plane that "+
			"will sign a downgrade it already refused once", ferr)
	}

	// ★ THE UPDATE-SIGNING KEY, AND THE ONE RULE IT MUST NOT BREAK (2026-08-13). It signs the document that says
	// WHICH CODE RUNS. The agent-policy key signs the rollout plan, which carries the FREEZE that halts a bad
	// release. If those are the same key, the party a halt exists to stop is the party who signs the halt — and
	// the devices already refuse that combination (updateplatform.LoadPins), so an edge configured this way
	// would sign manifests its own fleet rejects while reporting itself healthy.
	//
	// Fatal, not degraded. The other signers degrade because their failure means "configuration stops updating";
	// this misconfiguration means the release and the stop share an authority, and there is no partial version
	// of that worth running.
	var agentUpdateSigner *agentpolicy.Signer
	if sock := strings.TrimSpace(*agentUpdate.hsmSocket); sock != "" {
		keyID := strings.TrimSpace(*agentUpdate.hsmKeyID)
		if keyID != "" && agentPolicySigner != nil && keyID == strings.TrimSpace(*agentPolicyHSMAgentKeyID) {
			log.Fatalf("-agent-update-hsm-agent-key-id and -agent-policy-hsm-agent-key-id are the same key (%q). "+
				"One key signing both the release and the rollout plan means a compromised release key can also "+
				"lift the freeze that would stop it, and every device refuses that pairing anyway.", keyID)
		}
		hsmSigner, herr := newHSMAgentSignerForSocket(sock, strings.TrimSpace(*agentUpdate.hsmToken), keyID)
		if herr != nil {
			// No file fallback, by design: falling back would put the release key on the Edge, which is the one
			// outcome this arrangement exists to prevent. POST refuses while the token is unreachable; publishing
			// an envelope signed elsewhere (PUT) still works, so a release is delayed and never blocked.
			logErrorf("update-signing HSM unavailable (%v) — POST /admin/agent-updates will refuse. Releases can "+
				"still be published by PUTting an envelope signed elsewhere. There is NO on-disk fallback for this "+
				"key on purpose.", herr)
		} else if sgn, serr := agentpolicy.NewSignerFromCrypto(hsmSigner); serr != nil {
			logErrorf("update-signing key from %s is unusable (%v) — POST /admin/agent-updates will refuse", sock, serr)
		} else {
			// ★ THE PUBLIC KEYS ARE COMPARED TOO, not only the ids. Two key ids in one token can name the same
			// key, and the id check above passes for a socket configured with an empty id on both lanes.
			if agentPolicySigner != nil && strings.EqualFold(sgn.PublicKeyHex(), agentPolicySigner.PublicKeyHex()) {
				log.Fatalf("the update-signing key and the agent-policy key are the SAME key (public_key=%s). The "+
					"key that authorises running code must not also sign the rollout plan that can lift a freeze.",
					sgn.PublicKeyHex())
			}
			agentUpdateSigner = sgn
			// ★ AND IT MUST BE A KEY THIS EDGE ITSELF PINS. Publishing verifies the envelope against
			// -agent-update-pin before storing it, so a signer outside that set produces a manifest this control
			// plane refuses one line after minting it — a confusing failure at the worst moment. Said at startup,
			// where it can be fixed, rather than discovered during a release.
			pinned := false
			for _, k := range splitAgentUpdatePins(*agentUpdate.pin) {
				if strings.EqualFold(strings.TrimSpace(k), sgn.PublicKeyHex()) {
					pinned = true
					break
				}
			}
			if !pinned {
				logErrorf("★ the update-signing key %s is NOT in -agent-update-pin: this control plane would sign a "+
					"manifest and then refuse its own signature, and no device pins it either. Add it to the pin set "+
					"(and to update_signing_keys on the devices) before publishing.", sgn.PublicKeyHex())
			}
			log.Printf("update-signing key is in a PKCS#11 token via %s (public_key=%s) — this process does NOT "+
				"hold it, and it is distinct from the agent-policy key", sock, sgn.PublicKeyHex())
		}
	}

	// Published agent-update manifests. Loaded and VERIFIED here, at startup: a manifest this edge cannot check
	// is one every device in the fleet will refuse, and that failure is invisible from the fleet — it looks like
	// thousands of endpoints with a key problem rather than one wrong file on one machine.
	publishedAgentUpdates, agentUpdateErr := agentUpdate.load(time.Now())
	if agentUpdateErr != nil {
		// Fatal rather than degraded. Starting while unable to publish what an operator placed would mean a
		// release that silently never reaches anyone, and the log line saying so scrolls away.
		log.Fatalf("agent-update publication: %v", agentUpdateErr)
	}
	// The NEXT key is only ever published, never signed with here: the overlap is that devices accept it before
	// it is used, so signing with it is a later, separate act (set the HSM signer flags, or point
	// -agent-policy-signing-key at it, once the fleet reports holding it).
	//
	// Two ways to publish a next key. A FILE Ed25519 key (-agent-policy-next-signing-key) is the original path.
	// A raw PUBLIC KEY hex (-agent-policy-next-public-key) is what the token case needs: the ECDSA next key
	// lives in the HSM and has no private half on disk to load, so only its public key is handed in for
	// adoption. Both are sanitised to the shapes the verifier accepts and de-duplicated.
	var agentPolicyNextPublicKeys []string
	seenNext := map[string]bool{}
	addNext := func(hexKey, source string) {
		k := strings.ToLower(strings.TrimSpace(hexKey))
		if k == "" || seenNext[k] || !agentpolicy.AcceptedPublicKeyHex(k) {
			return
		}
		seenNext[k] = true
		agentPolicyNextPublicKeys = append(agentPolicyNextPublicKeys, k)
		log.Printf("agent-policy NEXT signing key published for adoption (source=%s): public_key=%s "+
			"— devices accept it once they take a bundle; only then sign with it", source, k)
	}
	if p := strings.TrimSpace(*agentPolicyNextSigningKeyPath); p != "" {
		next, nerr := agentpolicy.LoadOrGenerateSigner(p, *devMode)
		if nerr != nil {
			log.Fatalf("load -agent-policy-next-signing-key: %v", nerr)
		}
		if next != nil {
			addNext(next.PublicKeyHex(), "file")
		}
	}
	for _, k := range splitCommaList(*agentPolicyNextPublicKey) {
		addNext(k, "public-key")
	}
	if err != nil {
		log.Fatalf("setup agent-policy signing key: %v", err)
	}
	if agentPolicySigner != nil {
		log.Printf("agent-policy signing ENABLED — key_id=%s public_key=%s (anchor this in the device trusted keyring)", agentPolicySigner.KeyID(), agentPolicySigner.PublicKeyHex())
		// And said where the DEPLOYMENT can see it, not only in this node's log. A node whose key differs from
		// its siblings' logs exactly this line and looks healthy; the fleet view is where the difference shows.
		setAgentPolicyAuthority(agentPolicySigner.PublicKeyHex())
	} else if !*devMode {
		// Outside lab the signing key is empty => /steer/agent-policy is UNSIGNED, so admin-managed steer
		// exclusions cannot be tamper-resistant (the endpoint can't verify them). Production refuses to start
		// rather than run silently tamper-vulnerable; -allow-unsigned-agent-policy is the explicit escape hatch
		// for an edge that genuinely does not use steer exclusions.
		if !*allowUnsignedAgentPolicy {
			log.Fatalf("agent-policy signing DISABLED in production (-agent-policy-signing-key empty) — admin-managed steer exclusions would be UNSIGNED and NOT tamper-resistant. Set -agent-policy-signing-key, or pass -allow-unsigned-agent-policy to accept this risk explicitly.")
		}
		log.Printf("WARNING: agent-policy signing DISABLED in production (-allow-unsigned-agent-policy) — admin-managed steer exclusions are UNSIGNED and NOT tamper-resistant")
	}
	// Config-bundle signature verification: when the shared agent-policy signer exists, the PULLING Edge pins its
	// public key to verify the control plane's signed config bundle and (unless -allow-unsigned-config-bundle)
	// REJECTS a tampered/unsigned one — the CP→Edge config path is now signature-verified, not just TLS+bearer.
	if configBundlePuller != nil && agentPolicySigner != nil {
		// Verify the CP's config bundle against the ACCEPTED SET — the current signer plus any published next
		// keys — not a single pinned key. The single key is what silently killed CP→Edge sync at the 2c
		// Ed25519→ECDSA switch (the CP moved to the new key while the edge still pinned the old), and it would
		// break again on the next rotation. verifyPubKeyHex is kept for the status line / single-key fallback.
		configBundlePuller.verifyKeys = append([]string{agentPolicySigner.PublicKeyHex()}, agentPolicyNextPublicKeys...)
		configBundlePuller.verifyPubKeyHex = agentPolicySigner.PublicKeyHex()
		configBundlePuller.requireSigned = !*allowUnsignedConfigBundle
		log.Printf("config-bundle sync: signature verification ENABLED (require_signed=%v, accepted_keys=%d)", configBundlePuller.requireSigned, len(configBundlePuller.verifyKeys))
	}
	drainState := &atomic.Bool{} // Phase 4 graceful drain: SIGTERM flips this; /healthz then 503s so the LB drains us
	// Multi-region MESH fabric: dial the configured sibling edges and keep the links up. With no peers
	// configured, meshPeerEdges stays nil so the reach layer fails closed (every cross-region app hairpins).
	meshPeerConfigs, err := parseMeshPeers(*meshPeers)
	if err != nil {
		log.Fatalf("invalid -mesh-peers: %v", err)
	}
	// SWG forward-proxy SSRF egress guard: ON in production, OFF in lab (loopback test upstreams). Blocks direct
	// egress to internal/link-local/loopback/cloud-metadata addresses on the caller-controlled SWG target path.
	swg.SetInternalBlockEnabled(!*devMode)
	// Rate-limit client-IP attribution behind a trusted LB/proxy (XFF). Empty = RemoteAddr only (spoof-safe).
	rateLimitTrustedProxies = parseTrustedProxies(*rateLimitTrustedProxiesFlag)
	// Durable-store guard: a forgotten -*-store flag silently loses data on restart. Warn loudly (not fatal) for
	// each durability-critical store left in-memory in production. jsonMode: empty value = in-memory.
	// Every store is classed CONFIG (operator-authored, must survive a restart) or RUNTIME (recoverable). See
	//  The list is now COMPLETE for the config-bearing stores — the
	// device / NHI / identity-directory / vlan-object / observed-exclusion stores were previously absent, so
	// their silent volatility never even reached the warning. A CONFIG store missing from this list is the next
	// incident waiting to happen.
	volatileDurableStores := warnVolatileDurableStores(*devMode, []storeDurabilityCheck{
		// CONFIG — operator-authored. Losing any of these on restart is the recurring "it was wiped again" bug.
		{flag: "first-party-store", value: *firstPartyStore, class: storeClassConfig, impact: "admin login credentials"},
		{flag: "enrolled-inventory-store", value: *enrolledInventoryStore, jsonMode: true, class: storeClassConfig, impact: "device admission ledger"},
		{flag: "admission-revocation-store", value: *admissionRevocationStore, jsonMode: true, class: storeClassConfig, impact: "kill-switch revocations — could silently un-revoke"},
		{flag: "high-risk-store", value: *highRiskStore, jsonMode: true, class: storeClassConfig, impact: "high-risk device markings"},
		{flag: "admin-runtime-state-store", value: *adminRuntimeStateStorePath, jsonMode: true, class: storeClassConfig, impact: "admin runtime toggles (tenant-restriction / east-west)"},
		{flag: "grant-store", value: *grantStorePath, jsonMode: true, class: storeClassConfig, impact: "clientless federated-auth grants"},
		{flag: "delegated-grant-store", value: *delegatedGrantStorePath, jsonMode: true, class: storeClassConfig, impact: "delegated-access (east-west NHI) grants — could lose an in-flight revocation"},
		{flag: "human-approval-store", value: *humanApprovalStorePath, jsonMode: true, class: storeClassConfig, impact: "human step-up approval outcomes"},
		{flag: "break-glass-store", value: *breakGlassStorePath, jsonMode: true, class: storeClassConfig, impact: "break-glass emergency-access requests"},
		{flag: "connector-registry-store", value: *edgeConnectorRegistryStore, class: storeClassConfig, impact: "registered connectors — a wipe 404-loops the fleet"},
		{flag: "application-catalog-store", value: *applicationCatalogStorePath, jsonMode: true, class: storeClassConfig, impact: "operator-authored applications"},
		{flag: "tenant-model-store", value: *tenantModelStorePath, jsonMode: true, class: storeClassConfig, impact: "tenant profiles"},
		{flag: "steer-exclusion-store", value: *steerExclusionStoreMode, class: storeClassConfig, impact: "admin-managed steer exclusions"},
		{flag: "policy-rule-store", value: *policyRuleStorePath, jsonMode: true, class: storeClassConfig, impact: "authored east-west / egress rules"},
		{flag: "asset-catalog-store", value: *assetCatalogStorePath, jsonMode: true, class: storeClassConfig, impact: "the endpoints/groups/services authored rules REFERENCE — losing it leaves rules pointing at nothing, which is inert on egress and a WILDCARD on east-west"},
		{flag: "idp-connection-store", value: *idpConnectionStorePath, jsonMode: true, class: storeClassConfig, impact: "registered end-user IdPs"},
		// Previously MISSING from this list — config-bearing yet silently volatile:
		{flag: "vlan-object-store", value: *vlanObjectStorePath, jsonMode: true, class: storeClassConfig, impact: "Named Networks + VLAN boundary policies — empty Networks page"},
		{flag: "device-store", value: *edgeDeviceStore, class: storeClassConfig, impact: "device inventory"},
		{flag: "nhi-registry-store", value: *edgeNHIRegistryStore, class: storeClassConfig, impact: "NHI (non-human identity) registry"},
		{flag: "identity-directory-store", value: *edgeIdentityDirectoryStore, class: storeClassConfig, impact: "human identity directory"},
		{flag: "enrolment-token-store", value: *enrolmentTokenStore, class: storeClassConfig, impact: "admin-issued enrolment tokens — losing it UN-SPENDS every used one-time token, so a copied installer config would enrol again"},
		{flag: "seat-allocation-store", value: *seatAllocationStore, class: storeClassConfig, impact: "MSSP seat allocations — losing it reads as zero seats for every tenant and stops enrolment fleet-wide"},
		// RUNTIME — recoverable. Volatile is a legitimate production choice; reported so it is a known choice.
		{flag: "admin-auth-store", value: *edgeAdminAuthStore, class: storeClassRuntime, impact: "admin sessions / API tokens — a restart logs admins out"},
		{flag: "usage-meter-store", value: *edgeUsageMeterStore, class: storeClassRuntime, impact: "usage / metering records"},
		{flag: "observed-exclusion-store", value: *observedExclusionStoreMode, class: storeClassRuntime, impact: "observed (reverse-telemetry) exclusions — re-derived from telemetry"},
	})
	// The invariant (design/): a volatile OPERATOR-CONFIG store FAILS startup by default — config set
	// through the Console must not be silently lost on restart. This is the teeth that turns the advisory warning
	// into a contract. Passing -state-dir makes every config store durable-by-default (so this passes without any
	// per-store wiring); -allow-volatile-config is the explicit escape hatch for a throwaway Edge. RUNTIME stores
	// are never gated here.
	if *allowVolatileConfig && !*devMode {
		log.Printf("WARNING: -allow-volatile-config is set — OPERATOR-CONFIG stores may run in-memory and be LOST on restart. Use only for a deliberately ephemeral Edge.")
	}
	if bad := requireDurableStoresViolation(*devMode, !*allowVolatileConfig, volatileDurableStores); len(bad) > 0 {
		log.Fatalf("%d OPERATOR-CONFIG store(s) are volatile/in-memory in production: %s — config set through the Console would be LOST on restart. Set -state-dir=<dir> to make them durable-by-default (or give each a JSON path / =postgres). If this Edge is deliberately ephemeral, pass -allow-volatile-config.", len(bad), strings.Join(bad, ", "))
	}
	// Production security posture for the inter-region meshes: outside -lab-mode, a configured mesh MUST verify
	// the peer (pinned CA, no skip-verify, wss/https) and be authenticated (client cert / shared secret). Fail
	// startup rather than run a mesh with a lab-grade escape hatch.
	if err := enforceMeshProductionSecurity(*devMode, *meshPeers, *meshSecret, *meshClientCert, *meshPeerCA, *meshPeerInsecureSkipVerify, *revocationMeshPeers, *revocationMeshSecret, *meshIngressAllowedPeers); err != nil {
		log.Fatalf("%v", err)
	}
	meshPeerTLS, err := buildMeshPeerTLSConfig(*meshClientCert, *meshClientKey, *meshPeerCA, *meshPeerInsecureSkipVerify)
	if err != nil {
		log.Fatalf("invalid mesh peer TLS config: %v", err)
	}
	// Measured, not assumed: an agent steers IPv6 into this node whether or not it can carry it.
	startEgressFamilyMeasurement(strings.TrimSpace(*egressProbeV4Flag), strings.TrimSpace(*egressProbeV6Flag))
	// Who a sibling Edge IS, as opposed to which server certificate to pin. See loadMeshPeerIdentityAuthority.
	if err := loadMeshPeerIdentityAuthority(*meshPeerIdentityCAFlag); err != nil {
		log.Fatalf("%v", err)
	}
	var meshPeerEdges edgeplane.PeerEdgeProvider
	meshRegions := make([]string, 0, len(meshPeerConfigs))
	for _, p := range meshPeerConfigs {
		meshRegions = append(meshRegions, p.region)
	}
	// Said out loud whether there are peers or not: "this deployment has no mesh" and "this deployment's mesh
	// is down" refuse the same flow with the same message, and only one of them is a decision.
	// See mesh_state_report.go.
	setMeshState(meshRegions, len(splitCommaList(*meshEligibleHosts)), nil)
	if registry := startMeshPeerLinks(context.Background(), meshPeerConfigs, *meshSecret, meshPeerTLS); registry != nil {
		meshPeerEdges = registry
		// ★ AND A CONNECTOR IS TOLD. Its own region's siblings relay to whichever node holds it, so the warning
		// it prints every thirty seconds — "a flow arriving on one of the others cannot reach anything behind
		// this connector" — is about a hole this closes. It cannot know that by itself.
		localRegion := strings.TrimSpace(*edgeRegionID)
		setSiblingsRelayProbe(func() bool {
			if localRegion == "" {
				return false
			}
			_, live := registry.PeerEdgeFor(localRegion)
			return live
		})
		setMeshState(meshRegions, len(splitCommaList(*meshEligibleHosts)), func(region string) bool {
			_, live := registry.PeerEdgeFor(region)
			return live
		})
		meshAuth := "shared-secret"
		if meshPeerTLS.RootCAs != nil && len(meshPeerTLS.Certificates) > 0 {
			meshAuth = "mTLS (client cert + pinned peer CA)"
		} else if len(meshPeerTLS.Certificates) > 0 {
			meshAuth = "mTLS client cert"
		}
		log.Printf("multi-region mesh: %d peer edge link(s) configured (dial auth=%s)", len(meshPeerConfigs), meshAuth)
	}
	meshEligible := meshEligibleFromHosts(*meshEligibleHosts)

	// Its own block and its own client, for the reason the rollout sync had to learn: a feature whose liveness
	// depends on an unrelated feature being configured is a trap laid for whoever configures exactly what they
	// need.
	if updURL := strings.TrimSpace(*agentUpdate.sourceURL); updURL != "" {
		caFile := strings.TrimSpace(*steerExclusionSourceCA)
		if caFile == "" {
			caFile = strings.TrimSpace(*configSourceCA)
		}
		if caFile == "" {
			caFile = strings.TrimSpace(*adminSessionAuthorityCA)
		}
		if serr := requireHTTPSSource("agent-update", updURL); serr != nil {
			log.Fatalf("%v", serr)
		}
		updClient, cerr := buildAgentUpdateSourceClient(caFile)
		if cerr != nil {
			log.Fatalf("agent-update sync client: %v", cerr)
		}
		// Same cross-plane credential as the other CP→Edge pullers — see the agent-rollout puller for the
		// defect this shares. -admin-token authenticates callers TO THIS EDGE; the control plane answered 401.
		updateToken := strings.TrimSpace(*steerExclusionSourceToken)
		if updateToken == "" {
			updateToken = strings.TrimSpace(*adminToken)
		}
		if updateToken == "" {
			log.Fatalf("agent-update sync: -agent-update-source-url is set but there is no control-plane token to " +
				"authenticate the pull with (-steer-exclusion-source-token, or -admin-token when one credential " +
				"serves both planes); this edge would publish nothing to its fleet, silently")
		}
		if publishedAgentUpdates == nil {
			publishedAgentUpdates = &publishedUpdates{byTarget: map[string]publishedUpdate{}}
		}
		go agentUpdateSource{url: updURL, token: updateToken,
			trustedKeys: splitAgentUpdatePins(*agentUpdate.pin), artifactDir: strings.TrimSpace(*agentUpdate.dir),
			interval: *agentUpdate.sourcePoll, client: updClient, tenantID: pb.TenantID}.run(context.Background(),
			publishedAgentUpdates)
	}

	// ★ AND THE DEVICE-FACING SET IS SEEDED FROM THE DURABLE STORE AT BOOT (2026-08-13, twenty-ninth review).
	// Publishing now refreshes it when a release becomes active — but a restart threw that away: the set was
	// rebuilt only from the manifest DIRECTORY, so every release published through the API was silently
	// un-offered, while the admin screen restored "active" from the durable store and devices got 404. The two
	// halves of the same fact have to come back the same way.
	// ★ FOR EVERY TENANT, NOT THIS EDGE'S (2026-08-13, thirtieth review #10). The first version reseeded the
	// bundle tenant alone, so on a multi-tenant control plane every other tenant's release stayed un-offered
	// after a restart — the admin screen saying "active", the devices getting 404 — which is precisely the
	// symptom the reseed was written to end.
	if publishedAgentUpdates != nil && publishedDurable != nil {
		tenants := publishedDurable.Tenants()
		if len(tenants) == 0 {
			tenants = []string{pb.TenantID}
		}
		for _, tenant := range tenants {
			refreshDeviceFacingPublished(publishedAgentUpdates, publishedDurable, tenant,
				splitAgentUpdatePins(*agentUpdate.pin))
		}
	}

	// Client-side geo-steering: parse the class-1 region map served (signed) to agents.
	regionEndpointCat, err := parseRegionEndpoints(*regionEndpoints)
	if err != nil {
		log.Fatalf("invalid -region-endpoints: %v", err)
	}
	// ★★★ THE FLAG IS THE FLOOR, NOT THE AUTHORITY (2026-08-23). This is what this node serves until its first
	// successful pull; from then on the control plane's map replaces it — see
	// config_bundle_region_endpoints.go. Seeding the holder here rather than reading the flag at every call
	// site is what makes the replacement possible at all: the map used to be a value captured once at start-up,
	// so a node could only learn about a new region by being restarted with a new command line.
	regionMap.Set(regionEndpointCat)
	if regionEndpointCat != nil {
		log.Printf("geo-steering: %d region endpoint(s) in the class-1 catalog (boot value; the control plane's map replaces it on the first pull)", len(regionEndpointCat.order))
	}

	// Tenant model catalog backend (multi-tenant Admin Console Phase 4). Empty/file path keeps the lab default
	// (file/in-memory durability, unchanged). "postgres" reuses the admin auth Postgres connection on the
	// control plane so tenant profiles persist in the shared durable store without a second DB handle.
	// "postgres+import:<path>" is the same backend, seeded once from the file store this control plane used to
	// keep — see cpStateBlobPersisterImportPrefix. The tenant registry needs its own because it is a native
	// Postgres backend rather than a blob, and because what it would silently drop is the worst of the set: the
	// other organizations, and the DELETION TOMBSTONES, whose absence resurrects every deleted organization on
	// the next bundle.
	var tenantModelStore adminTenantModelRuntimeStore
	if strings.EqualFold(storeBackend(*tenantModelStorePath), "postgres") {
		tenantModelImportFrom := storeImportSource(*tenantModelStorePath)
		pgTenantModel, terr := setupPostgresAdminTenantModelStore(context.Background(), adminAuthStore, *migrationDir, *postgresRunMigrations, pb, *operatorTenantID, tenantModelImportFrom, time.Now().UTC())
		if terr != nil {
			log.Fatalf("setup tenant model store: %v", terr)
		}
		tenantModelStore = pgTenantModel
	} else {
		tenantModelStore = newOperatorAwareAdminTenantModelStore(pb, time.Now().UTC(), *tenantModelStorePath, *operatorTenantID)
	}

	// Persistent Site / Connector Group catalog (Connector UX Slice 1b). Empty/file path keeps the lab default
	// (in-memory starts empty -> GET /admin/sites is the read-only projection; or file/JSON durability).
	// "postgres" reuses the admin auth Postgres connection so Sites persist in the shared durable store.
	var siteStore adminSiteStore
	if strings.EqualFold(strings.TrimSpace(*siteStorePath), "postgres") {
		pgSiteStore, serr := setupPostgresAdminSiteStore(context.Background(), adminAuthStore, *migrationDir, *postgresRunMigrations)
		if serr != nil {
			log.Fatalf("setup site store: %v", serr)
		}
		siteStore = pgSiteStore
	} else {
		siteStore = newDurableAdminSiteStore(*siteStorePath)
	}

	// Operator-authored Application Catalog backend. Empty/file path keeps the lab default (config-seeded in-memory
	// catalog + file/JSON durability of authored entries, unchanged). "postgres" reuses the admin auth Postgres
	// connection so authored applications persist in the shared durable store; the config seed (route profiles +
	// SaaS catalog) is re-derived each boot and authored entries are overlaid on top — identical merge semantics to
	// the file store. Built here (like -site-store / -tenant-model-store) so it overrides the server's nil default.
	applicationCatalogStore, acerr := setupApplicationCatalogStore(context.Background(), *applicationCatalogStorePath, adminAuthStore, *migrationDir, *postgresRunMigrations, pb.TenantID, routeProfiles, pb.SaaSCatalog)
	if acerr != nil {
		log.Fatalf("setup application catalog store: %v", acerr)
	}

	// Device enrollment issuance (M4c): load the device-identity CA signer when configured; nil disables the
	// POST /enroll endpoint (existing deployments without a device CA are unaffected).
	// M7: seed the tenant-scope captive tuning (if configured) served signed via GET /steer/agent-tuning.
	var agentTuningScoped []agenttuning.ScopedTuning
	if *agentTuningCaptiveTimeout > 0 || *agentTuningCaptiveProbe > 0 {
		agentTuningScoped = []agenttuning.ScopedTuning{{
			ScopeType: agenttuning.ScopeTenant,
			Captive:   &agenttuning.CaptiveTuning{TimeoutSec: *agentTuningCaptiveTimeout, ProbeIntervalSec: *agentTuningCaptiveProbe},
		}}
	}

	var enrollSigner *deviceca.Signer
	// The device CA signs at every enrolment and every renewal, which makes it one of the two keys a running
	// node must be able to use — and it was a plain file on disk while the interception signer sat in a
	// token. Same sidecar, same interface: the Edge asks for a signature and never holds the material.
	//
	if sock := strings.TrimSpace(*deviceCAHSMAgentSocket); sock != "" &&
		strings.TrimSpace(*deviceCACertPath) != "" {
		// Comma-separated for an HA pool, matching the interception path (which uses splitCommaList). splitPaths
		// splits on ':' — a colon-based list would turn a comma-separated HA list into one bogus socket named
		// "a,b" and disable /enroll, while a single socket works under either. Keep the two HSM paths consistent.
		provider, perr := newHSMAgentPoolProvider(splitCommaList(sock), *deviceCAHSMToken, *deviceCAHSMKeyID,
			*deviceCACertPath, "", 30*time.Second, time.Now, log.Printf)
		if perr != nil {
			// Refusing to enrol is better than silently falling back to a key on disk: an operator who asked
			// for a token would otherwise get a file and no indication of it.
			log.Printf("enroll: device CA signing sidecar unavailable — POST /enroll DISABLED: %v", perr)
		} else {
			enrollSigner = deviceca.NewSigner(provider.Certificate(), provider.Signer())
			enrollSigner.NameSpaceSuffix = strings.TrimSpace(*deviceCertNameSpaceSuffix)
			log.Printf("enroll: device CA in a token via %s — POST /enroll enabled (key never leaves it)", sock)
			// Functionally monitor the device-CA key (comment above: "one of the two keys a running node must be
			// able to use"). Verify against the device-CA CERTIFICATE's public key so a key/cert divergence — every
			// device leaf then rejected — is caught too. Off the traffic path, so it logs + surfaces but does not
			// gate /healthz. The device-CA key is purpose-bound, so this probe digest is in the sidecar allowlist.
			dcaProvider := provider
			secondaryCustodyMonitors = append(secondaryCustodyMonitors, edgeplane.NewSecondaryKeyCustodyMonitor(
				"device_ca",
				func(now func() time.Time) edgeplane.KeyCustodyHealth {
					cert := dcaProvider.Certificate()
					var pub any // x509.Certificate.PublicKey is any; edgeplane.ProbeSigningKey type-switches on it
					if cert != nil {
						pub = cert.PublicKey
					}
					return edgeplane.ProbeSigningKey(dcaProvider.Signer(), pub, edgeplane.KeyCustodyPKCS11, edgeplane.DeviceCAKeyCustodyHealthText, now)
				}, 30*time.Second, log.Printf))
		}
	} else if strings.TrimSpace(*deviceCACertPath) != "" && strings.TrimSpace(*deviceCAKeyPath) != "" {
		s, eerr := deviceca.LoadSigner(*deviceCACertPath, *deviceCAKeyPath)
		if eerr != nil {
			log.Printf("enroll: device CA load failed — POST /enroll DISABLED: %v", eerr)
		} else {
			enrollSigner = s
			enrollSigner.NameSpaceSuffix = strings.TrimSpace(*deviceCertNameSpaceSuffix)
			log.Printf("enroll: device CA loaded — POST /enroll enabled (default_group=%q ttl=%s)", *enrollDefaultGroup, *enrollCertTTL)
		}
	}

	// ★ THE LEDGER IS LOADED BEFORE THE SERVER IS BUILT, BECAUSE BUILDING IT STARTS THE CP PULL (2026-08-13,
	// twenty-seventh review). newServerWithConfig launches the config-bundle poll loop, which pulls
	// IMMEDIATELY — and the load used to happen afterwards. An operator disables a stolen device on the
	// control plane, the Edge restarts, and if that first pull wins the race it merges into a ledger that is
	// still empty and has no persister, records the generation as applied, and then the durable load replaces
	// everything wholesale: the device is enabled again, the sync reports "applied generation N", and
	// shouldApplyBundle will not re-apply it. The same shape as the backfill-before-load defect fixed one
	// review earlier, in the same startup block.
	//
	// So everything the ledger needs — the static seed, the durable state, the shared identity claim, the
	// backfill and the gates — happens here, before anything can pull.
	// stage-0: load the Enrolled Inventory (fail-closed) when admission gating is configured.
	var transportEnrolled map[string]struct{}
	if p := strings.TrimSpace(*transportEnrolledInventory); p != "" {
		set, lerr := loadEnrolledInventory(p)
		if lerr != nil {
			log.Fatalf("load enrolled inventory: %v", lerr)
		}
		transportEnrolled = set
		log.Printf("transport enrolled inventory loaded: %d identities (admission gate=%t)", len(set), *transportRequireEnrolledIdentity)
	} else if *transportRequireEnrolledIdentity {
		log.Fatalf("-transport-require-enrolled-identity needs -transport-enrolled-inventory")
	}
	// seed the management ledger from the static inventory; the ledger is then authoritative for
	// admission (admin enroll/disable/remove hot-applies). Done before the (T) listener starts.
	enrolledLedger.SeedFromStatic(transportEnrolled, time.Now().UTC().Format(time.RFC3339))
	// W7: durable runtime changes (enroll/disable/remove) — authoritative over the static seed on boot.
	//
	// ★ AN UNREADABLE LEDGER IS FATAL FOR AN ISSUER (2026-08-13, twenty-sixth review). A read or parse failure
	// used to be logged and the process carried on with the static seed — for a node about to hand out
	// certificates that reads as "every identity in the fleet is unenrolled", and it would then CLAIM them all
	// and start issuing in their names. A node that only enforces can still run on the seed and re-pull.
	// ★ A FREE-TEXT CHANNEL JAMS EVERY REPORT QUEUE IN THE FLEET (2026-08-13, twenty-ninth review). The durable
	// store constrains this column to lab|alpha|pilot|stable, and the flag accepted anything — so
	// -agent-release-channel=beta made every outcome INSERT fail the CHECK, the route answer 500, and both
	// clients keep-and-retry, which stops each device's drain at its first report.
	//
	// ★★ IT HAS NOW BEEN IN THE WRONG PLACE TWICE (2026-08-13, thirty-first review #2). First inside
	// `if enrollSigner != nil`, so every Edge that issues no certificates skipped it; then, moving it, inside
	// `if lerr := SetPersisterChecked(…); lerr != nil` — so it ran ONLY when the enrolled inventory failed to
	// load, which is narrower than the version it was fixing. A healthy Edge started happily with
	// -agent-release-channel=Beta and every outcome was silently forced to 'lab'.
	//
	// It belongs at the top of startup and depends on nothing: it is a statement about one flag and one CHECK
	// constraint. TestTheChannelGateIsNotNestedInsideACondition pins that, because both mistakes were invisible
	// in review and neither was catchable by a test of the predicate.
	if !validAgentReleaseChannel(*agentReleaseChannel) {
		log.Fatalf("REFUSING TO START: -agent-release-channel=%q is not one the durable store accepts "+
			"(lab, alpha, pilot, stable — exactly, in lower case, with no surrounding spaces). Every device's "+
			"update outcome would be rejected by the database, answered 500, and retried for ever — so the whole "+
			"fleet's reporting stops on a value nobody reads.", *agentReleaseChannel)
	}

	if lerr := enrolledLedger.SetPersisterChecked(mustCPStateBlobPersister(*enrolledInventoryStore, "enrolled_inventory")); lerr != nil {
		if highRiskOverlay.NeedsMigration() {
			log.Fatalf("legacy risk migration requires readable enrolled inventory: %v", lerr)
		}
		if enrollSigner != nil {
			log.Fatalf("REFUSING TO START: this Edge issues device certificates and its enrolled inventory could "+
				"not be read (%v). Continuing would treat every identity in the fleet as never enrolled, claim "+
				"them, and issue certificates in their names.", lerr)
		}
		log.Printf("enrolled_inventory: the durable store could not be read (%v) — this Edge does not issue "+
			"certificates, so it continues on the static seed and the control plane's next bundle", lerr)
	}
	// Resolve old untyped marks only after both inventories are loaded, and before
	// any feed worker can replace the state being classified.
	if err := prepareUserRiskState(context.Background(), highRiskOverlay, enrolledLedger, humanIdentities); err != nil {
		log.Fatalf("prepare risk state: %v", err)
	}
	if sharedRevocationSource != nil {
		go sharedRevocationSource.run(context.Background(), livenessRevocations, highRiskOverlay)
	}
	// ★★★ AND READ AGAIN, BECAUSE A STANDBY THAT ONLY LEARNS BY RESTARTING IS NOT WARM (2026-08-25). Two
	// control planes share one database precisely so the standby holds what the leader authored. This store
	// was read once at start-up and never again: measured, a device enrolled while both were running appeared
	// on the leader, not on the standby, and appeared on the standby the moment it was restarted. A failover
	// then handed the deployment to a node that had forgotten the fleet.
	//
	// This deployment has now found the same defect in the transport trust store, the export download tokens,
	// the tenant CA registry and here.
	//
	// ★★ ONLY WHEN THIS NODE IS NOT THE ONE WRITING. Administration reaches whichever node holds leadership,
	// so the leader is the author and a leader re-reading could only overwrite itself with an older snapshot.
	// A node with no election — a single control plane — is always the leader and never reloads, which is
	// right: there is nobody else to learn from.
	// storeBackend, not a raw compare: "postgres+import:<path>" selects the SAME backend, and a raw comparison
	// is false for it — which here would silently leave the standby cold on exactly the deployments that were
	// migrated onto shared state.
	if storeBackend(*enrolledInventoryStore) == "postgres" {
		go func(l *enrolledinventory.Ledger) {
			// ★★★ AND THE LAST READ IT DOES IS THE ONE ON PROMOTION (2026-08-25, measured).
			//
			// The loop below stops re-reading the moment this node becomes the leader, which is correct —
			// from then on it is the author. But the snapshot it becomes the author OF is whatever it last
			// read, up to one interval old. Measured on the generated deployment while a device was being
			// enrolled: the leader named 1 and the standby named 0, and the check said what that costs — an
			// Edge that receives a roster missing a device stops admitting it.
			//
			// So the transition is where the read belongs: one final reload at the instant of promotion,
			// before this node starts answering as the authority. Fifteen seconds of staleness is not much
			// until it is the fifteen seconds containing somebody's enrolment.
			wasLeader := cpLeaderElectorInstance != nil && cpLeaderElectorInstance.IsLeader()
			for range time.Tick(15 * time.Second) {
				nowLeader := cpLeaderElectorInstance != nil && cpLeaderElectorInstance.IsLeader()
				if nowLeader {
					if wasLeader {
						continue
					}
					// Just promoted: read once more, as the standby, before acting as the leader.
					wasLeader = true
					if changed, rerr := l.ReloadFromStore(); rerr != nil {
						log.Printf("enrolled_inventory: this node was PROMOTED and could not re-read the "+
							"fleet's roster (%v) — it is now the authority for a roster it knows is older "+
							"than the one it is replacing", rerr)
					} else if changed {
						log.Printf("enrolled_inventory: took up the leader's roster at promotion")
					}
					continue
				}
				wasLeader = false
				changed, rerr := l.ReloadFromStore()
				if rerr != nil {
					log.Printf("enrolled_inventory: this standby could not re-read the fleet's roster (%v) — it "+
						"is serving an older one, and a failover would hand the deployment that", rerr)
					continue
				}
				if changed {
					log.Printf("enrolled_inventory: this standby took up the roster the leader authored")
				}
			}
		}(enrolledLedger)
	}
	// ★ AND THE CLAIM, THE BACKFILL AND THE GATES COME AFTER THE LOAD, NOT BEFORE IT (2026-08-13, twenty-sixth
	// review). They were above, where the ledger is still empty: the backfill claimed nothing, reported
	// success, and the node began issuing with the existing fleet unprotected.
	if enrollSigner != nil {
		// ★ AND THIS GATE HAD NO CALLER (2026-08-13, twenty-seventh review). enrolIssuerNeedsExclusiveStore was
		// written, named, tested — and dropped from the startup path when this block moved, while a comment a
		// few lines away went on claiming "the startup guard refuses a shared POSTGRES store". The blob
		// persister it guards is an unconditional last-write-wins UPSERT, and the SingleWriter protection only
		// wraps the FILE branch, so two issuers on one DSN quietly erase each other's enrolment markers and
		// admin disables — the exact lost update MergeAuthoritative's rollback assumes the persister refuses.
		// A predicate nobody calls is a comment with a test attached.

		if enrolIssuerNeedsExclusiveStore(enrollSigner != nil, *enrolledInventoryStore) {
			log.Fatalf("REFUSING TO START: this Edge issues device certificates and keeps its enrolled " +
				"inventory in a store other processes rewrite wholesale (-enrolled-inventory-store=postgres). " +
				"That store is an unconditional last-write-wins UPSERT, so a second node saving an older " +
				"snapshot erases enrolment records and admin disables from it without a word. Give this Edge " +
				"its own inventory store.")
		}
		// ★★★ OR IT ASKS THE AUTHORITY (2026-08-23). The requirement above is real — "has this identity already
		// enrolled" is a one-time decision and the ledger cannot take it, because it answers from memory and
		// saves as a blob. But it is a requirement for ONE PLACE to decide, not for an enforcement node to hold
		// a database: a node that pulls its config asks the control plane, exactly as it does for a one-time
		// enrolment token. See enrolled_identity_claim_remote.go.
		//
		// This was the seventh postgres dependency, and the only one that was not a -*-store flag — a hard
		// startup requirement, and therefore invisible to a count of the flags.
		if remote := newRemoteEnrolledIdentityClaims(configSourceBaseForClaims, configSourceTokenForClaims,
			configSourceClientForClaims); cpStateBlobDB == nil && remote != nil {
			enrolledLedger.SetIdentityClaimer(remote)
			// ★★★ REFUSING TO ENROL IS NOT REFUSING TO START (2026-08-23, measured — this stopped both Edges).
			//
			// The backfill hands the authority every identity this node already knows to be enrolled, and until
			// it lands another issuer could take one of those names. That is a reason to refuse ENROLMENT. It
			// is not a reason to refuse to start: the control plane restarting for twenty seconds would then
			// take the enforcement plane down with it, and a customer's traffic stops being protected because
			// an unrelated node was rebooting. Measured exactly that way — both Edges died with "connection
			// refused" while the control plane was still coming up in the same rebuild.
			//
			// So it retries in the background, and the ledger refuses to issue until it succeeds — which is the
			// behaviour the claimer already has for an error, so nothing here has to invent a second gate.
			go func(ledger *enrolledinventory.Ledger) {
				for attempt := 1; ; attempt++ {
					n, berr := ledger.BackfillIdentityClaims(context.Background())
					if berr == nil {
						if n > 0 {
							log.Printf("enroll: claimed %d identity(ies) this Edge had already enrolled, with "+
								"the control plane — they cannot now be enrolled by another issuer", n)
						}
						log.Printf("enroll: identity claims are taken with the control plane, not in a database " +
							"of this Edge's own")
						return
					}
					if attempt == 1 {
						log.Printf("enroll: the identities this Edge has already enrolled are NOT yet claimed "+
							"with the control plane (%v) — enrolment is refused here until they are, and this "+
							"Edge goes on enforcing meanwhile", berr)
					}
					time.Sleep(10 * time.Second)
				}
			}(enrolledLedger)
		} else if cpStateBlobDB == nil {
			log.Fatalf("REFUSING TO START: this Edge issues device certificates (-enroll-device-ca) and has " +
				"neither a control plane to take an identity claim with (-config-source-url) nor a database to " +
				"take one in (-postgres-dsn). \"This identity has already enrolled\" would then be answered from " +
				"the state THIS process loaded, so a second issuer — now or later — hands out a certificate for " +
				"a device name this one has already used, and neither can see the other.")
		} else {
			claims, cerr := setupPostgresEnrolledIdentityClaims(context.Background(), cpStateBlobDB, *migrationDir,
				true, edgeNodeIdentityForClaims(*edgeRegionID, *listen))
			if cerr != nil {
				log.Fatalf("REFUSING TO START: this Edge issues device certificates and its identity claim could not "+
					"be prepared (%v).", cerr)
			}
			enrolledLedger.SetIdentityClaimer(claims)
			n, berr := enrolledLedger.BackfillIdentityClaims(context.Background())
			if berr != nil {
				log.Fatalf("REFUSING TO START: the identities this Edge has already enrolled could not be claimed "+
					"in the shared store (%v). Until they are, another issuer can hand out a certificate for a "+
					"device name that is already in use.", berr)
			}
			if n > 0 {
				log.Printf("enroll: claimed %d identity(ies) this Edge had already enrolled before the shared claim "+
					"existed — they cannot now be enrolled by another issuer", n)
			}
			// ★ ONE NODE'S BACKFILL IS NOT THE DEPLOYMENT'S MIGRATION (2026-08-13, twenty-sixth review). During a
			// rolling upgrade a NEW issuer starts with a node-local ledger holding no markers at all: its backfill
			// claims nothing, succeeds, and it begins issuing while every identity only the OLD issuer knows about
			// is still unclaimed. The barrier is what orders that — a node may only declare the migration complete
			// if it actually had enrolments to contribute, or if an operator says this deployment is new.
			if err := ensureIdentityClaimBarrier(context.Background(), cpStateBlobDB, n,
				edgeNodeIdentityForClaims(*edgeRegionID, *listen), *enrolClaimFreshDeployment); err != nil {
				log.Fatalf("REFUSING TO START: %v", err)
			}
		}
	}
	if suffix := strings.TrimSpace(*deviceCertNameSpaceSuffix); suffix != "" && enrollSigner != nil {
		log.Printf("enroll: device certificates are named inside %q (SAN <device-id>.%s) — a per-tenant issuing CA may be "+
			"name-constrained to it ONCE every device holds a certificate carrying the name; constraining earlier refuses renewals", suffix, suffix)
	}

	// Start the off-traffic-path key-custody monitors (device-CA, agent-policy). Each probes once immediately so a
	// key broken at boot is reported at boot, then on its timer. They log/surface; they do not gate readiness.
	names := make([]string, 0, len(secondaryCustodyMonitors))
	for _, m := range secondaryCustodyMonitors {
		m.Start()
		names = append(names, m.Name)
	}
	log.Printf("secondary key-custody monitors started: %d %v", len(secondaryCustodyMonitors), names)

	// ★★★ WIRED BEFORE THE SERVER IS BUILT, BECAUSE THE SERVER DECIDES WHAT TO ANNOUNCE (2026-08-19).
	// This used to run after, next to the listener it belongs to, and the announcement is computed while the
	// server is constructed — so a node that DOES serve the recovery name announced "withdrawn" and the serial
	// never moved to say otherwise. The mirror image of the defect this whole path exists to prevent: first we
	// announced a name nobody served, then we served a name nobody was told about. The announcement has to be
	// read after the answer exists.
	// Recovery path for devices that expired while switched off. Started before the transport listener so a
	// failure here is reported before the Edge starts carrying traffic — it is not fatal, but an operator must
	// not have to discover it when the first holiday laptop comes back.
	// ★ the enrolment fold step 3: the same path, selected by SNI on the transport port. Enabled alongside the dedicated
	// listener, never instead of it — the port closes only once every enrolled device has been measured onto a
	// bundle that names the SNI, and until then a device that has never heard of it must still be able to
	// recover. Nothing changes for any connection that does not send the name.
	if sni := strings.TrimSpace(*renewalRecoverySNI); sni != "" {
		// The SAME configuration the dedicated listener is built with, field for field. Two configurations
		// would be two definitions of who may recover, on one deployment.
		// ★★★ THE CERTIFICATE A DEVICE ACTUALLY MEETS, WHICH IS NOT ALWAYS THE (T) LISTENER'S (2026-08-25,
		// measured on a generated deployment). This read -transport-tls-cert unconditionally. A deployment
		// that has FOLDED the agent plane onto one port — which is what the architecture asks for, and what
		// the installer generates — does not run the (T) listener at all: devices arrive at the main
		// listener's agent-facing door, on its certificate. So the check "does the certificate carry the
		// recovery name" was asked of a file that does not exist, the wiring refused, the name was therefore
		// never announced, and every device the deployment enrolled had no way back.
		//
		// The Edge said so plainly — "the certificate that would be served for %q could not be read" — and
		// the only reader was a log. Ask about the door devices use.
		recoveryCert, recoveryKey, recoveryClientCA := *transportTLSCert, *transportTLSKey, *transportTLSClientCA
		if strings.TrimSpace(recoveryCert) == "" {
			recoveryCert, recoveryKey, recoveryClientCA = *mainTLSCert, *mainTLSKey, *transportTLSClientCA
		}
		enableRenewalRecoveryOnMainPortFrom(sni, enrollRenewGraceConfig{
			Listen:         *enrollRenewGraceListen,
			ServerCert:     recoveryCert,
			ServerKey:      recoveryKey,
			ClientCAFile:   recoveryClientCA,
			TenantRegistry: tenantCAReg,
			Ledger:         enrolledLedger,
			Revocations:    livenessRevocations,
			Signer:         enrollSigner,
			Tenant:         evaluator.PolicyBundle.TenantID,
			CertTTL:        *enrollCertTTL,
			Window:         *enrollRenewGraceWindow,
		})
	}
	// ★★★ the enrolment fold: AND THE OTHER HALF OF THE FOLD — a device that holds NOTHING (2026-08-21).
	//
	// The section's goal is "an agent touches ONE port, enrolment included; in production, 443 only", and it
	// also says a port like 8443 must never appear in the configuration handed to an agent. Measured: this
	// deployment's installer configuration carries exactly that. The paths are already on the transport
	// listener — it serves the same handler as the data port — so the only thing stopping a new device is the
	// handshake asking for a certificate it cannot have.
	//
	// Enabled unconditionally because it reacts to nothing but the name: a connection that does not ask for an
	// enrolment name is untouched, and one that does reaches only what a device holding nothing can need. It
	// lands before the agents, exactly as the recovery fold did.
	if enrollSigner != nil {
		// The deployment-wide enrolment name is the recovery name's BASE with the enrolment prefix — not the
		// recovery name with a prefix in front of it, which is how it first came out ("enrol.recovery.…").
		base := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(*renewalRecoverySNI)), recoveryNamePrefix)
		// The names the certificate on this port actually carries, so the fold cannot offer one it does not.
		served := []string{}
		for _, c := range servedTransportChain(serverConfig{TransportCertFile: *transportTLSCert}) {
			served = append(served, c.DNSNames...)
			break // the leaf is the one that answers the handshake
		}
		enableEnrolmentOnTransportPort(organizationEnrolmentName(base), served)
	}

	// ★★★ AN EDGE ASSEMBLES ITS ORGANIZATIONS BEFORE IT SERVES ANYTHING (2026-08-20). Fetched SYNCHRONOUSLY,
	// here, because the fleet guard — the check that refuses to let a node speak for a fleet whose promises it
	// cannot keep — runs while the server is built, a few lines below. A node that fetched afterwards would be
	// refused for material that was on its way, or worse, would pass the guard having erased the promise.
	var distributedTenantTrust *tenantTrustDistributionCache
	if *tenantTransportMaterialFromCP {
		if agentPolicySigner == nil {
			log.Fatal("canonical tenant trust requires a pinned policy verification key")
		}
		distributedTenantTrust = &tenantTrustDistributionCache{keys: append([]string{agentPolicySigner.PublicKeyHex()}, agentPolicyNextPublicKeys...)}
		endpoint := strings.TrimSpace(*auditIngestURL)
		token := strings.TrimSpace(*auditIngestToken)
		tlsCfg, terr := auditShipTLSConfig(strings.TrimSpace(*auditIngestCA),
			strings.TrimSpace(*auditIngestIdentity.cert), strings.TrimSpace(*auditIngestIdentity.key))
		switch {
		case endpoint == "" || token == "":
			log.Printf("tenant_transport_material NOT fetched: -tenant-transport-material-from-cp is set and the "+
				"audit-ingest endpoint/token it rides on are not — this node will serve only the "+
				"per-organization certificates it has on disk (endpoint=%q token_set=%v)", endpoint, token != "")
		case terr != nil:
			log.Fatalf("tenant transport material: %v", terr)
		default:
			fetcher := newTenantTransportMaterialFetcher(endpoint, token, tlsCfg, func() []string { return nil })
			fetcher.trustDistributions = distributedTenantTrust
			// ★ AND THE START-UP PROMISE GUARD ASKS IT WHETHER AN ORGANIZATION IS STILL ONE OF THIS
			// DEPLOYMENT'S. Wired here, where the fetcher is made, because the guard runs in a closure built
			// before this point and false — refuse — is what it gets until an answer has arrived.
			organizationIsGoneAccordingToTheControlPlane = fetcher.OrganizationIsGone
			// The interception tier goes straight into the engine, in memory. A node with interception off
			// simply does not take one.
			if interception := networkExtensionLabTLS; interception != nil {
				// This node assembles its organizations from the control plane, so what it is handed comes
				// back on its own after a restart — and a short-lived signing key is deliberately not written
				// to a node that may not exist tomorrow. Told so it does not warn about the shape it has.
				interception.OfflineTenantMaterialIsFetched()
				fetcher.loadInterception = func(mat tenantInterceptionMaterial) error {
					_, lerr := interception.LoadOfflineTenantIntermediate(mat.TenantID,
						[]byte(mat.RootPEM), []byte(mat.ChainPEM), []byte(mat.KeyPEM))
					if lerr != nil {
						return lerr
					}
					// ★★★ AND THE ROOT THIS ORGANIZATION IS MOVING TO, ANNOUNCED AND SIGNED UNDER BY NOTHING
					// (2026-08-22). Until now the only way to fill offlineTenantIncomingRoots was an operator
					// calling the announce route by hand on each node — so a node that joined mid-rotation
					// quietly announced nothing, and the devices it served were never asked to adopt.
					//
					// Not fatal: an Edge that cannot announce the incoming root still serves the current one
					// correctly. Refusing here would take interception away over a rotation that has not
					// started yet.
					if root := strings.TrimSpace(mat.IncomingRootPEM); root != "" {
						if _, aerr := interception.AnnounceTenantInterceptionRoot(mat.TenantID, []byte(root)); aerr != nil &&
							!strings.Contains(aerr.Error(), "nothing to announce") {
							log.Printf("interception: %q is moving to a new root and this node could not announce "+
								"it (%v) — its devices will not be asked to adopt it, so do not promote until "+
								"this is resolved", mat.TenantID, aerr)
						}
					} else if interception.WithdrawIncomingTenantRoot(mat.TenantID) {
						// ★★★ AND THE WITHDRAWAL HAS TO TRAVEL TOO (2026-08-22, measured). Withdrawing a staged
						// authority on the control plane stops the material carrying it — and used to tell the
						// Edges nothing, so they went on announcing a root that existed nowhere. Every device
						// would have kept looking for it, and the readiness measurement would have kept
						// reporting a rotation that could no longer be finished or cancelled.
						log.Printf("interception: %q is no longer moving to a new root — this node has stopped "+
							"announcing the one its devices were being asked to adopt", mat.TenantID)
					}
					return nil
				}
			}
			// ★ AND THE AUTHORITY THIS NODE ENROLS THAT ORGANIZATION'S DEVICES UNDER (2026-08-21). Installing
			// it also registers its certificate, because a device is resolved to its organization by the CA
			// that issued it — an authority that can sign and cannot be resolved would produce certificates
			// this deployment issues and then refuses at the handshake.
			fetcher.loadDeviceIdentity = func(mat tenantDeviceMaterial) error {
				return tenantDeviceIdentity.Install(mat, tenantCAReg, func(reg *tenantca.TenantCARegistry) error {
					return persistTenantCARegistry(reg, strings.TrimSpace(*transportTenantCARegistry))
				})
			}
			// ★★★ REPUBLISH THE AGENT CONFIGURATION ONCE THE MATERIAL IT DESCRIBES EXISTS (2026-08-22).
			//
			// The file names the organization's transport and enrolment server names, and those are read from
			// the certificates installed just above. It is written at start-up — measured, both at 21:37:02,
			// with the publish FIRST — so it named an organization with no name, and nothing rewrote it: the
			// only other trigger is an administrator saving a policy.
			//
			// Best effort and never fatal. A configuration file one poll stale is a smaller problem than a
			// node that refuses to serve because it could not write one.
			if networkExtensionPublisher != nil {
				republished := false
				fetcher.afterInstall = func(transport, _, _ int) {
					if transport == 0 || republished {
						return
					}
					republished = true
					if err := networkExtensionPublisher.PublishAdminPolicySnapshot(context.Background(),
						evaluator.PolicyBundle.TenantID, policyStore, evaluator.PolicyBundle, time.Now()); err != nil {
						log.Printf("agent configuration: could not republish after the organization's material "+
							"arrived (%v) — the file still names no transport server name, so a device installed "+
							"from it cannot reach the folded enrolment path", err)
					}
				}
			}
			// ★★★ A FLEET MEMBER THAT STARTS A FEW SECONDS EARLY MUST STILL JOIN (2026-08-21, measured).
			//
			// The first fetch is not fatal by itself — the fleet guard below decides whether what this node
			// HAS is enough — but on a COLD start the node has nothing, so a control plane that is two seconds
			// behind turns into "this node has no certificate for lab.dsse.invalid" and the guard exits the
			// process for good. Measured on this lab: region-b came up before the control plane was listening,
			// logged "first fetch failed … connection refused", and stayed exited; started again by hand with
			// the control plane already up, it joined with zero refusals.
			//
			// In a fleet that grows and shrinks under load, nodes start at arbitrary moments and a control
			// plane restart is routine. A node that gives up on the first refusal is a node that silently
			// never joins.
			//
			// So the fetch is retried for a bounded window, and only then does the guard judge. The window
			// ends: an Edge whose control plane never answers still refuses to run, which is the rule this
			// deployment already holds — it does not fail open and it does not serve from nothing.
			// ★★★ AND "ANSWERED" IS NOT "ANSWERED WITH SOMETHING" (2026-09-02, measured on a fleet that had
			// three customer organizations). A control plane restarted at the same moment as this node — which
			// is every roll, because they are on the same machine — answers 200 with an EMPTY set while it is
			// still assembling. The loop treated a nil error as success, installed material for 0
			// organizations, and the fleet guard below then did exactly what it is for:
			//
			//	REFUSING TO JOIN THIS FLEET: this node cannot keep 3 promise(s) the fleet has already made to
			//	devices: tenant_… was promised the name ….hinoki.lab and this node has no certificate for it
			//
			// The node exits and nothing retries, so a roll took both founding Edges out permanently while the
			// other two regions — whose control planes were already up — came back fine. The guard was right;
			// what was wrong was accepting an empty answer as the authority's answer.
			//
			// So the window is also spent waiting for a NON-EMPTY answer. It stays bounded, and a deployment
			// that genuinely has no organizations still starts: zero is only refused while the answer keeps
			// arriving empty AND the window has time left.
			deadline := time.Now().Add(60 * time.Second)
			for attempt := 1; ; attempt++ {
				_, ferr := fetcher.FetchOnce()
				if ferr == nil && fetcher.installedTenants.Load() == 0 && time.Now().Before(deadline) {
					if attempt == 1 {
						log.Printf("tenant_transport_material: the control plane answered with NO organizations — " +
							"retrying, because a control plane that is still assembling answers exactly like a " +
							"deployment that has none, and this node is refused by the fleet guard if it holds nothing")
					}
					time.Sleep(2 * time.Second)
					continue
				}
				if ferr == nil {
					if attempt > 1 {
						log.Printf("tenant_transport_material: fetched on attempt %d (%d organization(s)) — the "+
							"control plane was not ready when this node started", attempt, fetcher.installedTenants.Load())
					}
					break
				}
				if time.Now().After(deadline) {
					log.Printf("tenant_transport_material first fetch still failing after %d attempt(s) (%v) — "+
						"continuing with whatever this node already holds; the fleet guard will refuse to join "+
						"if that is not enough", attempt, ferr)
					break
				}
				if attempt == 1 {
					log.Printf("tenant_transport_material first fetch failed (%v) — retrying until the control "+
						"plane answers, because a node that starts before it must still be able to join", ferr)
				}
				time.Sleep(2 * time.Second)
			}
			fetcher.Start()
		}
	}

	// ★ THE CONTROL PLANE'S TRANSPORT AUTHORITIES. Built before the server so the route can be registered with
	// them; an empty store means this node issues nothing and Edges keep reading files, which is what every
	// deployment did before 2026-08-20.
	var tenantTransportAuthorityStoreValue *tenantTransportAuthority
	if path := strings.TrimSpace(*tenantTransportAuthorityStore); path != "" {
		persister := mustPKIAuthorityPersister(path, "tenant_transport_authorities")
		seed, lerr := persister.Load()
		if lerr != nil {
			log.Fatalf("tenant transport authorities: %v", lerr)
		}
		// ★ AND THE WAY BACK TO THE SHARED STORE. A control plane that is not the one an authority was created
		// on holds a snapshot from its own start-up; without this it answers "that organization has none" as a
		// fact, and an Edge acts on it. See refreshedRowLocked.
		tenantTransportAuthorityStoreValue = newTenantTransportAuthorityWithReload(seed, persister.Save,
			persister.Load, time.Now)
		// What the published agent configuration names as the organization's transport server name. A control
		// plane serves no organization's certificate itself, so the authority's record is the only source it
		// has — see agentConfigOrganization.
		agentConfigTransportAuthority = tenantTransportAuthorityStoreValue
		log.Printf("tenant transport authorities loaded: %d organization(s) — this control plane can issue "+
			"per-organization server material to Edges", len(tenantTransportAuthorityStoreValue.Organizations()))
	}

	// ★ THE DEVICE-IDENTITY AUTHORITY, for the organizations that do not run a PKI of their own. Same store
	// shape as the other two; see tenant_device_material_authority.go for why the operator may hold this one
	// when it may not hold an interception root.
	var tenantDeviceAuthorityValue *tenantDeviceAuthority
	if storeShouldBeWired(*tenantDeviceAuthorityStore) {
		value := strings.TrimSpace(*tenantDeviceAuthorityStore)
		if value == "" {
			value = "postgres"
		}
		persister := mustPKIAuthorityPersister(value, "tenant_device_authorities")
		seed, lerr := persister.Load()
		if lerr != nil {
			log.Fatalf("tenant device-identity authorities: %v", lerr)
		}
		// The way back to the SHARED store, so a control plane that did not receive a write does not refuse
		// an organization's enrolments as if it had none. See the transport authority's refreshedRowLocked.
		tenantDeviceAuthorityValue = newTenantDeviceAuthorityWithReload(seed, persister.Save, persister.Load, time.Now)
		log.Printf("tenant device-identity authorities loaded: %d organization(s) are enrolled by this "+
			"deployment rather than by a CA of their own", len(tenantDeviceAuthorityValue.Organizations()))
	}

	var tenantInterceptionAuthorityValue *tenantInterceptionAuthority
	if path := strings.TrimSpace(*tenantInterceptionAuthorityStore); path != "" {
		persister := mustPKIAuthorityPersister(path, "tenant_interception_authorities")
		seed, lerr := persister.Load()
		if lerr != nil {
			log.Fatalf("tenant interception authorities: %v", lerr)
		}
		// Same reason as the two above: without a way back to the shared store, a control plane that did not
		// receive the write hands its Edges no interception tier for an organization that has one.
		tenantInterceptionAuthorityValue = newTenantInterceptionAuthorityWithReload(seed, persister.Save,
			persister.Load, time.Now)
		log.Printf("tenant interception authorities loaded: %d organization(s) have delegated interception to "+
			"this control plane", len(tenantInterceptionAuthorityValue.Organizations()))
	}

	refuseStartOnUnusableCertificateFlag = *refuseStartOnUnusableCertificate
	// Said now that the selection has settled: a config-pulling Edge replaced the local store with the control
	// plane's authority, and the fleet-uniformity guard reads this sentence to decide whether a node keeps
	// one-time tokens to itself. Announcing it at construction time put BOTH sentences in the log.
	if announceLocalEnrolmentTokens != nil {
		announceLocalEnrolmentTokens()
	}
	// ★ RESOLVED HERE, NOT AT THE CALL SITE, so "postgres" cannot end up being treated as a filename — which
	// is what a store that only understands paths does with it: it creates one, silently, and the node
	// authors a distribution nobody else can see.
	var transportTrustShared blobstore.Persister
	if storeBackend(*transportTrustStorePath) == "postgres" {
		transportTrustShared = mustCPStateBlobPersister(*transportTrustStorePath, "transport_trust")
	}
	var tenantTrustDistributionStore blobstore.Persister
	if tenantTransportAuthorityStoreValue != nil && agentPolicySigner != nil {
		path := "postgres"
		if storeBackend(*tenantTransportAuthorityStore) != "postgres" {
			if strings.TrimSpace(*stateDir) == "" {
				log.Fatal("canonical tenant trust requires a durable state directory")
			}
			path = filepath.Join(*stateDir, "tenant_trust_distributions.json")
		}
		tenantTrustDistributionStore = mustCPStateBlobPersister(path, "tenant_trust_distributions")
	}
	// ★ SAY WHERE THE FOLD STANDS, EVERY BOOT. the fold's last step closes the dedicated recovery port, and the only
	// evidence that may justify it is every enrolled device SAYING it holds the name. Printed here so the
	// answer is in front of whoever is about to remove the flag, rather than being assembled by hand from two
	// admin routes at the moment of the decision.
	if sni := offeredRenewalRecoverySNI(*renewalRecoverySNI); sni != "" && observedExclusions != nil &&
		enrolledLedger != nil {
		tenant := evaluator.PolicyBundle.TenantID
		known := []string{}
		for _, d := range enrolledLedger.List() {
			// ★★★ EVERY ORGANIZATION'S DEVICES, BECAUSE THE PORT IS THIS NODE'S (2026-08-19). This filtered to
			// the node's own organization on the reasoning that each fleet is measured by whoever announces to
			// it — true for an announcement, wrong for a LISTENER. Closing this port takes the path away from
			// every device that reaches this Edge, and a second organization's laptop reaches the same socket.
			// The filter would have closed it while a Northwind device had never said anything at all.
			known = append(known, d.Identity)
		}
		// ★ THE LEDGER ALREADY SAYS WHAT AN IDENTITY IS, and it says the same thing on every Edge (2026-08-19).
		// This asked the connector registry, which is per-Edge state: region-b's was empty, so it counted the
		// connector and region-a did not, and the two nodes answered the same question differently. Entry.Kind
		// is carried in the shared enrolled ledger and is the deployment's own answer.
		connectorIDs := map[string]bool{}
		for _, e := range enrolledLedger.List() {
			if !e.IsEndpoint() {
				connectorIDs[strings.ToLower(strings.TrimSpace(e.Identity))] = true
			}
		}
		measure := func() recoveryNameReadiness {
			all := []string{}
			for _, d := range enrolledLedger.List() {
				all = append(all, d.Identity)
			}
			kept, notAgents := excludeIdentitiesThatNeverDialRecovery(all, connectorIDs)
			// Reports are recorded per organization, so the answer is assembled per organization and merged —
			// the denominator is every enrolled identity on this node, whoever owns it.
			// Whether the fallback this measurement was built to protect still exists on THIS deployment. It
			// is announced from the same field an agent reads, so the sentence cannot claim a port the bundle
			// does not offer.
			out := recoveryNameReadiness{Name: sni, NotAgents: notAgents,
				DedicatedPortRetired: strings.TrimSpace(*networkExtensionRenewalRecoveryEndpoint) == ""}
			for _, org := range organizationsOf(enrolledLedger, tenant) {
				// ★ EACH ORGANIZATION IS MEASURED AGAINST THE NAME IT WAS TOLD (2026-08-20). An organization on
				// its own transport authority is told recovery.<its name>, because the deployment-wide name is
				// answered by a certificate it no longer trusts. Measuring everybody against the deployment's
				// name would read "no device holds it" a minute after they all adopted a better one — a gate
				// reporting the opposite of what happened.
				askName := sni
				if serverName, ok := transportTenantCertificates.ServerNameFor(org); ok {
					askName = recoveryNameForTenant(*renewalRecoverySNI, serverName)
				}
				// ★ The line has to name what it measured. It used to print the deployment's name while
				// measuring per organization, which is a verdict about one thing wearing the name of another.
				if askName != "" && !strings.Contains(out.Name, askName) {
					if out.Name == "" || out.Name == sni {
						out.Name = askName
					} else {
						out.Name += "," + askName
					}
				}
				part := observedExclusions.RecoveryNameReadiness(org, askName, keptForTenant(enrolledLedger, org, kept))
				firstSerial := int64(0)
				if distributedTenantTrust != nil || tenantTrustDistributionStore != nil {
					firstSerial = canonicalRecoveryNameSince(distributedTenantTrust, tenantTrustDistributionStore,
						append([]string{agentPolicySigner.PublicKeyHex()}, agentPolicyNextPublicKeys...), org, askName)
				} else {
					firstSerial = transportTrust.RecoveryNameSince()
				}
				applyRecoverySerialEvidence(&part, observedExclusions.Query(org, observedQueryFilter{}).Entries, firstSerial)
				out.SerialUnverified = append(out.SerialUnverified, part.SerialUnverified...)
				out.Contradicting = append(out.Contradicting, part.Contradicting...)
				out.Holds = append(out.Holds, part.Holds...)
				out.DoesNotHold = append(out.DoesNotHold, part.DoesNotHold...)
				out.Silent = append(out.Silent, part.Silent...)
				out.NeverReportedAnything = append(out.NeverReportedAnything, part.NeverReportedAnything...)
			}
			return out
		}
		log.Print(measure().Line())
		// ★★★ AND SOMEWHERE A PERSON CAN READ IT BEFORE THEY ACT (2026-08-25, after tearing a deployment down
		// and taking a machine's whole network with it). This measurement names, by device, who has no way
		// back if its certificate breaks — and it existed only as a line in this node's log, on a ten-minute
		// timer, with no reader. It was correct and unread for the whole of the outage it predicted.
		//
		// A destructive act is decided by a person, and a person needs the number BEFORE the act. So it is
		// served, and the installer asks for it.
		snapshot := func() any { return measure() }
		recoveryReadinessSnapshot.Store(&snapshot)
		// ★ AND AGAIN WHILE IT RUNS. The start-up line answers a question an operator asks at an arbitrary
		// moment — "may I close this port now?" — and devices report all day. Logged only when the verdict
		// changes, so a settled deployment stays quiet.
		go func() {
			last := ""
			for range time.Tick(10 * time.Minute) {
				if line := measure().Line(); line != last {
					last = line
					log.Print(line)
				}
			}
		}()
	}

	var transportAnchorAckShared blobstore.Persister
	if storeBackend(*transportAnchorAckStorePath) == "postgres" {
		transportAnchorAckShared = mustCPStateBlobPersister(*transportAnchorAckStorePath, "transport_anchor_acks")
	}
	mux := newServerWithConfig(serverConfig{
		DNSConntrack:                   edgeDNSConntrack,
		VLANObjectStorePath:            strings.TrimSpace(*vlanObjectStorePath),
		PeerEdges:                      meshPeerEdges,
		MeshEligible:                   meshEligible,
		MeshSecret:                     strings.TrimSpace(*meshSecret),
		MeshIngressAllowedPeers:        parseMeshIngressAllowedPeers(*meshIngressAllowedPeers),
		RegionEndpoints:                regionEndpointCat,
		RevocationMeshSecret:           strings.TrimSpace(*revocationMeshSecret),
		PolicyCandidateStore:           policyCandidateStore,
		ApplyMaterializedCertPinBypass: applyMaterializedCertPinBypass,
		CatalogOverrides:               catalogOverrides,
		CatalogFeed:                    catalogFeed,
		ApplyInspectionPosture:         applyInspectionPosture,
		InspectionPosture:              func() inspectionposture.Posture { return postureStore.Get() },
		// So a posture change moves the config bundle's VERSION and not only its contents — without this the
		// section below would be published in every bundle and applied by nobody.
		InspectionPostureGeneration: postureStore.ConfigGeneration,
		SetInspectionPosture: func(p inspectionposture.Posture, tenantID string) (inspectionposture.Posture, error) {
			updated, err := postureStore.Set(p)
			// The in-memory posture IS applied either way (the engine must match what the store holds);
			// the error tells the admin the change will not survive a restart.
			applyInspectionPosture(tenantID)
			return updated, err
		},
		AssetStore:                   assetStore,
		RuleStore:                    ruleStore,
		TenantModelStore:             tenantModelStore,
		SiteStore:                    siteStore,
		ConnectorEnrollmentEdgeURL:   *connectorEnrollmentEdgeURL,
		LogDir:                       *logDir,
		ConnectorEnrollmentStateDir:  *connectorEnrollmentStateDir,
		ConnectorEnrollmentEdgeCAPEM: readEnrollmentEdgeCA(*connectorEnrollmentEdgeCA),
		OperatorTenantID:             strings.TrimSpace(*operatorTenantID),
		ApplicationCatalogStore:      applicationCatalogStore,
		ApplicationCatalogStorePath:  *applicationCatalogStorePath,
		IdPConnectionStorePath:       *idpConnectionStorePath,
		ClientlessBaseURL:            *clientlessBaseURL,
		ClientlessTLSCert:            *clientlessTLSCert,
		ClientlessTLSKey:             *clientlessTLSKey,
		// ★ THE CONTROL PLANE ISSUES PROFILES AND DOES NOT SERVE THE PORTAL, so it cannot see the file. The
		// deployment states it once, in its own environment, and the installer keeps that statement true
		// whenever the pair appears or is taken away — the same bookkeeping the Console's certificate gets.
		StepUpPortalCertificateIsOperators: strings.EqualFold(strings.TrimSpace(os.Getenv("DSSE_STEP_UP_PORTAL_CERTIFICATE")), "operator"),
		StepUpBindingSecret:                *stepUpBindingSecret,
		GrantStorePath:                     *grantStorePath,
		DelegatedGrantStorePath:            *delegatedGrantStorePath,
		HumanApprovalStorePath:             *humanApprovalStorePath,
		EastWestObserveStorePath:           *eastWestObserveStorePath,
		InspectionEventsStorePath:          *inspectionEventsStorePath,
		DLPClassifierStorePath:             *dlpClassifierStorePath,
		DLPAllowlistStorePath:              *dlpAllowlistStorePath,
		DLPFingerprintStorePath:            *dlpFingerprintStorePath,
		DLPPolicyObjectStorePath:           *dlpPolicyObjectStorePath,
		OrganizationDomainsStorePath:       *organizationDomainsStorePath,
		EntitlementStorePath:               *entitlementStorePath,
		DLPRequiresLicense:                 *dlpRequiresLicense,
		BreakGlassStorePath:                *breakGlassStorePath,
		StripAltSvc:                        *stripAltSvc,
		SWGEgressBrowserMimic:              *swgEgressBrowserMimic,
		DLPBlockUninspectableFiles:         *dlpBlockUninspectableFiles,
		Evaluator:                          evaluator,
		ConfigSyncStatus:                   configSyncStatus,
		RevocationSyncStatus:               revocationSyncState,
		ConfigSourceURL:                    strings.TrimSpace(*configSourceURL),
		SteerExclusionSourceURL:            strings.TrimSpace(*steerExclusionSourceURL),
		ConfigBundleSource:                 configBundlePuller,
		FleetConfigStatus:                  fleetConfigStatus,
		DrainState:                         drainState,
		AdmissionRevocations:               livenessRevocations,
		TransportConnRegistry:              transportConns,
		KeyCustodyMonitor:                  keyCustodyMonitorRef,
		SecondaryKeyCustodyMonitors:        secondaryCustodyMonitors,
		HighRiskOverlay:                    highRiskOverlay,
		LegalHold:                          legalHold,
		ColdArchive:                        coldArchive,
		RetentionOverride:                  retentionOverride,
		EnrolledLedger:                     enrolledLedger,
		EnrollSigner:                       enrollSigner,
		AgentTuningScoped:                  agentTuningScoped,
		EnrollToken:                        *enrollEligibilityToken,
		EnrolmentTokens:                    enrolmentTokens,
		FleetIdentityClaimer:               fleetIdentityClaimer,
		SeatAllocations:                    seatAllocations,
		VendorLicense:                      vendorLicenceStore,
		LicenseAcceptedKeys:                licenseAcceptedKeys,
		LicenseRecipientKey:                licenseRecipient,
		LicenseMSSPID:                      strings.TrimSpace(*licenseMSSPID),
		LicenseAllowOversubscription:       *licenseAllowOversubscription,
		EnrolmentLicensing:                 enrolmentLicensingGate,
		EnrolmentTokenPolicy:               enrolltoken.Policy{MaxLifetime: *enrolmentTokenMaxLifetime, MaxOutstanding: *enrolmentTokenMaxOutstanding},
		EnrollRenewGraceListen:             *enrollRenewGraceListen,
		TransportTLSURL:                    *networkExtensionTransportTLSURL,
		RegionEndpointURLs:                 regionEndpointHostsFrom(*regionEndpoints),
		MainListenAddr:                     *listen,
		AdminListenAddr:                    *adminListen,
		TransportListenAddr:                *transportTLSListen,
		TransportCertFile:                  *transportTLSCert,
		TransportClientCAFile:              *transportTLSClientCA,
		DeviceIssuingCAFile:                *deviceCACertPath,
		DNSPolicyStorePath:                 *dnsPolicyStorePath,
		RenewBeforeStorePath:               *renewBeforeStorePath,
		// ★★★ DEFAULTED, BECAUSE LOSING IT STRANDS A RETIREMENT (2026-08-23, measured: no node in the reference
		// deployment had a path for it, so every operator assertion was in memory). This records an operator
		// saying "that device holds the anchor by other means" — a claim, made once, that the transport-CA
		// withdrawal gate then relies on. Losing it on restart does not lose a fact anybody can re-observe: it
		// loses a judgement somebody made, and the gate goes back to refusing a retirement that was already
		// vouched for. Same rule as every other operator-config store: durable by default under -state-dir.
		TransportAnchorAckStorePath:   durableStorePath(*stateDir, *transportAnchorAckStorePath, "transport_anchor_acks"),
		InterceptionHSMAgentSocket:    *interceptionHSMAgentSocket,
		EnrolmentTokenStoreMode:       *enrolmentTokenStore,
		EnrolmentTokenMaxLifetime:     *enrolmentTokenMaxLifetime,
		EnrolmentTokenMaxOutstanding:  *enrolmentTokenMaxOutstanding,
		EnrollRenewGraceWindow:        *enrollRenewGraceWindow,
		EnrollIdPEligibility:          buildEnrollIdPEligibility(*enrollIdPConnectionID, *enrollIdPRequiredGroup, theIdPRegistry.Load),
		EnrolmentCPReporter:           enrolmentCPReport,
		DirectoryCPReporter:           directoryCPReport,
		EnrollDefaultGroup:            *enrollDefaultGroup,
		EnrollCertTTL:                 *enrollCertTTL,
		DisableEmbeddedOutboxAdmin:    !*embeddedOutboxAdmin, // decoupled by default: outbox admin off unless explicitly enabled
		AuditIngestReceiverToken:      *auditIngestReceiverToken,
		AuditShipHealth:               auditShipHealthFn,
		InterceptionAnchorPEM:         readFileOrEmpty(*interceptionAnchorCert),
		InterceptionPendingRootPEM:    readFileOrEmpty(*interceptionPendingRootCert),
		IdPIssuerURL:                  strings.TrimSpace(*oidcIssuer),
		MeshPeerSpec:                  strings.TrimSpace(*meshPeers),
		HotStoreEndpoint:              strings.TrimSpace(*edgeHotStoreClickHouseEndpoint),
		ColdArchiveEndpoint:           strings.TrimSpace(*coldArchiveEndpoint),
		Writer:                        writer,
		ExportObjectStore:             exportObjectStore,
		Registry:                      connectorRegistry,
		ConnectorSecret:               *connectorSecret,
		RequireConnectorRuntimeSecret: *requireConnectorRuntimeSecret,
		WorkloadAttestationSecret:     *workloadAttestationSecret,
		TrustedKeyring:                trustedKeyring,
		RouteProfiles:                 routeProfiles,
		SWGRuntime:                    swgRuntime,
		PolicyStore:                   policyStore,
		OIDC:                          oidc,
		AdminConsoleOrigin:            *adminConsoleOrigin,
		AdminConsoleOrigins:           *adminConsoleOrigins,
		LocalCredentials:              localCredentials,
		SteerExclusions:               steerExclusions,
		InternalCAs:                   internalCAs,
		ObservedExclusions:            observedExclusions,
		ObservedKnownFloor:            parseObservedKnownFloor(*steerExclusionKnownFloor),
		ConfigVersions:                configVersions,
		CPVersions:                    cpVersions,
		AgentPolicySigner:             agentPolicySigner,
		PublishedUpdates:              publishedAgentUpdates,
		AgentUpdateArtifactDir:        strings.TrimSpace(*agentUpdate.dir),
		ConnectorProgramDir:           resolveConnectorProgramDir(*connectorProgramDir, *stateDir),
		PullsAgentUpdates:             strings.TrimSpace(*agentUpdate.sourceURL) != "",
		RolloutControlPath:            *rolloutControl.path,
		AgentRolloutCache:             agentRolloutPulled,
		AgentRolloutPlans:             agentRolloutDurable,
		PublishedAgentUpdateStore:     publishedDurable.WithArtifactDir(strings.TrimSpace(*agentUpdate.dir)),
		AgentUpdatePins:               splitAgentUpdatePins(*agentUpdate.pin),
		AgentUpdatePublisher:          strings.TrimSpace(*agentUpdate.publisher),
		AgentUpdateSigner:             agentUpdateSigner,
		AgentUpdateSignFloor:          agentUpdateSignFloor,
		AgentPolicyNextPublicKeys:     agentPolicyNextPublicKeys,
		InterceptionReparentStateDir:  strings.TrimSpace(*interceptionReparentStateDir),
		TrustBundleCAPEM:              trustBundleCAPEM,
		TransportTrustStorePath:       *transportTrustStorePath,
		TransportTrustSharedStore:     transportTrustShared,
		TenantTrustDistributionStore:  tenantTrustDistributionStore,
		DistributedTenantTrust:        distributedTenantTrust,
		TransportAnchorAckSharedStore: transportAnchorAckShared,
		TransportTrustCarriedFromPath: strings.TrimSpace(*transportTrustCarriedFrom),
		PKIOperationStorePath:         *pkiOperationStorePath,
		TrustBundleCAPath:             strings.TrimSpace(*trustBundleCA),
		TrustBundleSerial:             *trustBundleSerial,
		TrustBundleRecoveryEndpoint:   strings.TrimSpace(*networkExtensionRenewalRecoveryEndpoint),
		TenantTransportMaterialFromCP: *tenantTransportMaterialFromCP,
		SteerPosture:                  steerPostureConfig{FailOpenMode: *steerFailOpenMode, FailOpenCooldownMS: *steerFailOpenCooldownMS, RegionFailover: *steerRegionFailover}.normalized(),
		ClientlessAccessEnabled:       *clientlessAccessEnabled,
		AdminInviteEmailSinkPath:      *adminInviteEmailSink,
		AdminExportJobs:               adminExportJobs,
		AdminExportWorker:             configuredAdminExportWorker,
		AdminAuditOutbox:              adminAuditOutbox,
		AdminAuth:                     adminAuthStore,
		NetworkExtensionPublisher:     networkExtensionPublisher,
		NetworkExtensionLabTLS:        networkExtensionLabTLS,
		DeploymentInterceptionRootPEM: profileInterceptionRootPEM,
		UsageMeters:                   usageMeters,
		DeviceStore:                   deviceInventory,
		HumanIdentities:               humanIdentities,
		WorkloadAttestations:          workloadAttestations,
		AgentTelemetry:                agentTelemetry,
		NonHumanIdentities:            nhiRegistry,
		HotStore:                      adminHotStore,
		HotStoreMirror:                hotStoreMirrorMonitor,
		DomainEventOutbox:             domainEventOutbox,
		DomainEventMirror:             domainEventOutboxMirrorMonitor,
		AgentTargetVersion:            *agentTargetVersion,
		AgentReleaseChannel:           *agentReleaseChannel,
		AdminToken:                    *adminToken,
		LabMode:                       devMode,
		TenantCARegistry:              tenantCAReg,
		TenantCARegistryPath:          strings.TrimSpace(*transportTenantCARegistry),
		RenewalRecoverySNI:            renewalRecoverySNIAnnouncement(*renewalRecoverySNI),
		TenantTransportAuthority:      tenantTransportAuthorityStoreValue,
		TenantTransportMaterialTTL:    *tenantTransportMaterialTTL,
		TenantInterceptionAuthority:   tenantInterceptionAuthorityValue,
		TenantDeviceAuthority:         tenantDeviceAuthorityValue,
	})
	// (T) secure transport: additive TLS listener for the encrypted endpoint↔Edge tunnel. Default
	// OFF; a bind/config error here must NOT take down the plaintext data plane, so it is logged and the
	// Edge continues on -listen.
	seatAllocations.SetPersister(mustCPStateBlobPersister(*seatAllocationStore, "seat_allocations"))
	vendorLicenceStore.SetPersister(mustCPStateBlobPersister(*licenseStorePath, "vendor_license"))
	// Put the stored licence back in force at boot. Without this a restart would leave the gate with no licence
	// while the store still held one — enforcement would read as "no valid licence" and hold every enrolment,
	// which is the wrong answer to a restart.
	if p, ok := vendorLicenceStore.Current(licenseAcceptedKeys, strings.TrimSpace(*licenseMSSPID)); ok {
		enrolmentLicensingGate.Apply(p)
		log.Printf("vendor licence: in force serial=%d seats=%d expires=%s evaluation=%t",
			p.Serial, p.SeatsAt(time.Now().UTC()), p.ExpiresAt, p.IsEvaluation)
	} else if len(licenseAcceptedKeys) > 0 {
		log.Printf("vendor licence: NONE in force — enrolment is held until a licence is applied")
	}
	// single-tenant Edge isolation: when a tenant CA registry is configured, bind this Edge to its
	// own tenant (the policy bundle's tenant) so cross-tenant certs are denied at admission even if the
	// registry trusts other tenants' CAs.
	// ★ ONE EDGE COULD ONLY EVER SERVE ONE TENANT (2026-08-15). This pinned the (T) listener to the node's own
	// bundle tenant whenever a Tenant CA registry was configured, so a second organization's device was denied
	// at the handshake as "cross-tenant" — on an Edge whose whole purpose, for an MSSP, is to serve several
	// customers. secure_transport documents the other mode ("Empty = multi-tenant Edge (tenant resolved per
	// connection and bound downstream instead)") and the downstream half is real and correct:
	// authoritativeTenantForRequest already keys every decision and audit record to the tenant the CERTIFICATE
	// proves, refusing a body that claims a different one. Only this assignment made that mode unreachable.
	//
	// The default stays single-tenant, which is what every existing deployment is: an Edge that suddenly
	// admitted other tenants because a flag flipped underneath it would be the opposite mistake.
	transportExpectedTenant := ""
	if tenantCAReg != nil && !*transportAdmission.multiTenant {
		transportExpectedTenant = evaluator.PolicyBundle.TenantID
	}
	if tenantCAReg != nil && *transportAdmission.multiTenant {
		log.Printf("transport admission: MULTI-TENANT — a device is admitted on whichever registered Tenant CA "+
			"its certificate chains to, and every decision is keyed to that tenant rather than to this node's "+
			"own (%s). A certificate chaining to no registered Tenant CA resolves to no tenant.",
			evaluator.PolicyBundle.TenantID)
	}
	// wrap the mux with the optional /auth + /admin rate limiter (default off). The SAME
	// hardened handler is served on both the plaintext and the (T) TLS listener.
	var hardenedHandler http.Handler = mux
	if *adminRateLimitRPS > 0 {
		limiter := newTokenBucketLimiter(*adminRateLimitRPS, *adminRateLimitBurst)
		hardenedHandler = rateLimitMiddleware(hardenedHandler, limiter, isRateLimitedEdgePath)
		log.Printf("admin/auth rate limit enabled rps=%.1f burst=%.1f", *adminRateLimitRPS, limiter.burst)
	}
	// browser security headers (HSTS over TLS only, CSP/XFO/nosniff/referrer) — outermost so
	// they apply to every response including 429s. Always on (API clients ignore them).
	hardenedHandler = securityHeadersMiddleware(hardenedHandler)
	// CORS for the separate-host Admin Console (opt-in, exact-origin only). Outermost so the
	// preflight OPTIONS short-circuits before auth/rate-limit.
	hardenedHandler = adminConsoleCORSMiddleware(hardenedHandler, *adminConsoleOrigin)
	// W-2/W-7: the (T) handshake consults livenessRevocations (created above, shared with the admin
	// kill-switch handlers) so an auto-revoked (W-2 dark) or manually-revoked (W-7 admin) identity is denied
	// even while still enrolled. Empty by default => admission unchanged unless the sweep or admin revokes.
	// Runtime-mutable device-trust pool: when configured, retiring (or adding) a CA rebuilds the pool every
	// (T) handshake reads — no restart. Opened BEFORE the listeners so the store's set, not the seed file's,
	// is what serves from the first handshake.
	if p := strings.TrimSpace(*deviceClientCAStorePath); p != "" && strings.TrimSpace(*transportTLSClientCA) != "" {
		seedPEM, rerr := os.ReadFile(*transportTLSClientCA)
		if rerr != nil {
			log.Fatalf("device client CA store: read seed %s: %v", *transportTLSClientCA, rerr)
		}
		rebuildPool := func(pems string, serial int64) (func(), error) {
			var registryPool *x509.CertPool
			if tenantCAReg != nil {
				registryPool = tenantCAReg.CertPool()
			}
			pool, perr := deviceTrustPoolFrom(registryPool, pems)
			if perr != nil {
				return nil, perr
			}
			return func() {
				transportClientCAPool.Store(pool)
				// Say which of them belongs to nobody, every time the set changes — the state a half-written
				// withdrawal leaves, and one no screen showed while it was true.
				if tenantCAReg != nil {
					claimed := map[string]bool{}
					for _, fact := range tenantCAReg.Facts(time.Now()) {
						claimed[strings.ToLower(fact.SHA256)] = true
					}
					warnUnattributedDeviceTrustAnchors(parseAllCerts([]byte(pems)),
						func(sha string) bool { return claimed[strings.ToLower(sha)] })
				}
				// Name the anchors every time the set changes — the effective pool has silently diverged
				// from the store once already, and a count would not have shown which CA was missing.
				logDeviceTrustAnchors("store", serial, []byte(pems))
			}, nil
		}
		store, serr := openTransportTrustStore(p, string(seedPEM), 1, rebuildPool)
		if serr != nil {
			log.Fatalf("device client CA store: %v", serr)
		}
		deviceClientCAs = store
		pems, serial := store.Current()
		commit, cerr := rebuildPool(pems, serial)
		if cerr != nil {
			log.Fatalf("device client CA store: %v", cerr)
		}
		commit()
	}
	// ★ HOW MANY PORTS AN AGENT IS EXPECTED TO DIAL ON THIS EDGE. Said at start-up because it is a property
	// of the configuration, not of the traffic: a deployment that grows a second agent-facing port finds out
	// on the day it is configured rather than on the day somebody tries to run it on 443, where they collide.
	if line := describeAgentFacingPorts(agentFacingPorts(agentFacingAddresses{
		MainListen:                *listen,
		PublishedEdgeURL:          *networkExtensionRuntimeCopyEdgeURL,
		TransportListen:           *transportTLSListen,
		RecoveryListen:            *enrollRenewGraceListen,
		PublishedRecoveryEndpoint: *networkExtensionRenewalRecoveryEndpoint,
	})); line != "" {
		log.Printf("edge %s", line)
	}

	if *enrollRenewGraceListen != "" {
		if err := startEnrollRenewGraceListener(enrollRenewGraceConfig{
			Listen:         *enrollRenewGraceListen,
			ServerCert:     *transportTLSCert,
			ServerKey:      *transportTLSKey,
			ClientCAFile:   *transportTLSClientCA,
			TenantRegistry: tenantCAReg,
			Ledger:         enrolledLedger,
			Revocations:    livenessRevocations,
			Signer:         enrollSigner,
			Tenant:         evaluator.PolicyBundle.TenantID,
			CertTTL:        *enrollCertTTL,
			Window:         *enrollRenewGraceWindow,
		}); err != nil {
			log.Printf("enroll renewal RECOVERY listener NOT started: %v — a device whose certificate expires "+
				"while switched off will need manual re-enrolment", err)
		}
	}

	// (The fleet-promise check runs where the announcement is written — steer_agent_policy_routes.go — because
	// a node that reaches the announcement first can erase what it was about to be measured against.)

	// The roster, on the door devices arrive at. Installed here — after the registry, the ledger and the
	// revocation overlay all exist, and before anything serves — because it consults all three.
	setAgentDoorAdmission(tenantCAReg, enrolledLedger, livenessRevocations)
	// Decided once and read by both doors devices can arrive at: the main listener's agent-facing door (which
	// is the one a generated deployment opens) and the secure transport listener.
	trustedFrontDoors := parseTrustedFrontDoors(*trustedFrontDoorsFlag)
	setTrustedFrontDoors(trustedFrontDoors)
	if len(trustedFrontDoors) > 0 {
		log.Printf("agent plane: a PROXY protocol header naming a device's original address is accepted from %s and from nowhere else", *trustedFrontDoorsFlag)
	}
	if transportListener, terr := startSecureTransportListener(secureTransportConfig{
		ListenAddr:              *transportTLSListen,
		CertFile:                *transportTLSCert,
		KeyFile:                 *transportTLSKey,
		ClientCAFile:            *transportTLSClientCA,
		RequireClientCert:       *transportTLSRequireClientCert,
		LabAutoCert:             *devMode,
		LabMode:                 *devMode,
		RequireEnrolledIdentity: *transportRequireEnrolledIdentity,
		EnrolledIdentities:      transportEnrolled,
		EnrolledLedger:          enrolledLedger,
		TenantCARegistry:        tenantCAReg,
		ExpectedTenantID:        transportExpectedTenant,
		AdmissionRevocations:    livenessRevocations,
		TrustedFrontDoors:       trustedFrontDoors,
		ConnRegistry:            transportConns,
		// The store committed its pool above; the listener must serve that set, not re-seed from the flag
		// file — re-seeding is how a restart used to erase every runtime-added device CA.
		ClientCAPoolManagedExternally: deviceClientCAs != nil,
	}, renewalRecoveryAwareHandler(hardenedHandler)); terr != nil {
		log.Printf("edge secure transport (T) NOT started: %v (plaintext -listen continues)", terr)
	} else if transportListener != nil {
		defer transportListener.Close()
	}

	// when a dedicated admin listener is configured, serve the admin+auth surface on its own
	// (non-loopback) TLS listener and EXCLUDE it from the main data-plane listener — so the Admin Console
	// (separate host) reaches the admin API over TLS and the data-plane port carries only steering traffic.
	// Hot-reload registered server certs on SIGHUP with no restart (cert rotation slice 1).
	certreload.InstallSignalHandler()
	// Centralized admin auth: introspect control-plane-minted sessions when configured (slice 1).
	if strings.TrimSpace(*adminSessionAuthorityURL) != "" {
		introspector, err := newSessionIntrospector(*adminSessionAuthorityURL, *adminSessionAuthorityCA)
		if err != nil {
			log.Fatalf("admin session authority: %v", err)
		}
		adminSessionAuthority = introspector
		log.Printf("centralized admin auth ENABLED — unknown admin_session cookies are introspected against %s", strings.TrimSpace(*adminSessionAuthorityURL))
	}
	mainHandler := hardenedHandler
	if strings.TrimSpace(*adminListen) != "" {
		mainHandler = dataPlaneOnlyMiddleware(hardenedHandler)
		go func() {
			log.Printf("edge admin surface on dedicated TLS listener %s (data plane excluded; Console is a separate host)", *adminListen)
			if err := serveMainEdgeListener(*adminListen, "admin", adminSurfaceOnlyMiddleware(hardenedHandler), *mainTLSCert, *mainTLSKey, *devMode, *allowInsecurePlaintext, nil, 0); err != nil {
				log.Fatalf("admin listener: %v", err)
			}
		}()
	}
	// TLS-only (fail-closed plaintext) + Slowloris-safe timeouts, serving the rate-limit +
	// security-headers wrapped handler.
	if err := serveMainEdgeListener(*listen, "agent-plane", mainHandler, *mainTLSCert, *mainTLSKey, *devMode, *allowInsecurePlaintext, drainState, *drainPeriod); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func newServer(evaluator decision.Evaluator, writer *logs.Writer, registry *connector.Registry) http.Handler {
	return newServerWithClient(evaluator, writer, registry, http.DefaultClient)
}

func newServerWithClient(evaluator decision.Evaluator, writer *logs.Writer, registry *connector.Registry, proxyClient *http.Client) http.Handler {
	return newServerWithClientAndSecret(evaluator, writer, registry, proxyClient, defaultConnectorSecret)
}

func newServerWithClientAndSecret(evaluator decision.Evaluator, writer *logs.Writer, registry *connector.Registry, proxyClient *http.Client, connectorSecret string) http.Handler {
	return newServerWithClientSecretAndTunnel(evaluator, writer, registry, proxyClient, connectorSecret, tunnel.NewManager())
}

func newServerWithClientSecretAndTunnel(evaluator decision.Evaluator, writer *logs.Writer, registry *connector.Registry, proxyClient *http.Client, connectorSecret string, tunnelManager *tunnel.Manager) http.Handler {
	return newServerWithClientSecretTunnelAndSession(evaluator, writer, registry, proxyClient, connectorSecret, tunnelManager, sessionstore.NewStore())
}

func newServerWithClientSecretTunnelAndSession(evaluator decision.Evaluator, writer *logs.Writer, registry *connector.Registry, proxyClient *http.Client, connectorSecret string, tunnelManager *tunnel.Manager, sessionStore *sessionstore.Store) http.Handler {
	return newServerWithClientSecretTunnelSessionAndOIDC(evaluator, writer, registry, proxyClient, connectorSecret, tunnelManager, sessionStore, oidcConfig{})
}

func newServerWithClientSecretTunnelSessionAndOIDC(evaluator decision.Evaluator, writer *logs.Writer, registry *connector.Registry, proxyClient *http.Client, connectorSecret string, tunnelManager *tunnel.Manager, sessionStore *sessionstore.Store, oidc oidcConfig) http.Handler {
	return newServerWithConfig(serverConfig{
		Evaluator:       evaluator,
		Writer:          writer,
		Registry:        registry,
		ProxyClient:     proxyClient,
		ConnectorSecret: connectorSecret,
		TunnelManager:   tunnelManager,
		SessionStore:    sessionStore,
		OIDC:            oidc,
	})
}

func runtimeEvaluatorForPolicyStore(base decision.Evaluator, store policy.RuntimeStore) decision.Evaluator {
	if runtimeStore, ok := store.(policy.RuntimeEvaluatorStore); ok {
		return runtimeStore.RuntimeEvaluator(base)
	}
	return base
}

// configWriteRejectedWhenSourced enforces Phase 1 write-path inversion (design / 1c): when this Edge
// pulls its config from a control plane (configSourceURL set), the bundle-distributed config resources are
// CP-authoritative, so authoring them on this puller Edge is rejected with 409 — config has one source of
// truth (the CP), and a node-local write would be silently overwritten by the next pull anyway. Returns true
// (and writes the response) when the write must be rejected; reads are unaffected. resource names the thing
// for the operator-facing error.
func configWriteRejectedWhenSourced(w http.ResponseWriter, configSourceURL, resource string) bool {
	if strings.TrimSpace(configSourceURL) == "" {
		return false
	}
	writeError(w, http.StatusConflict, fmt.Errorf(
		"%s is authored on the control plane, not a config-pulling Edge: write it to the control plane (%s); this Edge pulls its config via -config-source-url and would overwrite a local change on the next poll",
		resource, configSourceURL))
	return true
}

// materializedCertPinBypassHosts returns the host/SNI of every materialized cert-pinning candidate for
// the tenant — the destinations the interception engine should raw-forward (decrypt-bypass). Only
// candidates that an admin has approved and materialized appear here; pending/approved ones do not.
func materializedCertPinBypassHosts(store *policycandidate.Store, tenantID string) []string {
	if store == nil {
		return nil
	}
	resp, err := store.List(context.Background(), tenantID, policycandidate.ListOptions{Status: "materialized", Limit: 1000})
	if err != nil {
		return nil
	}
	hosts := []string{}
	for _, c := range resp.Candidates {
		if c.Source != policycandidate.SourceCertPinningDetection {
			continue
		}
		if h := strings.TrimSpace(c.SNI); h != "" {
			hosts = append(hosts, h)
		}
		if h := strings.TrimSpace(c.Host); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// materializedCertPinBypassRefs is materializedCertPinBypassHosts paired with the candidate id of each bypass, so
// the Egress view can offer a Revoke (suppress the candidate → re-intercept the host), not just display it.
func materializedCertPinBypassRefs(store *policycandidate.Store, tenantID string) []certPinBypassRef {
	if store == nil {
		return nil
	}
	resp, err := store.List(context.Background(), tenantID, policycandidate.ListOptions{Status: "materialized", Limit: 1000})
	if err != nil {
		return nil
	}
	refs := []certPinBypassRef{}
	for _, c := range resp.Candidates {
		if c.Source != policycandidate.SourceCertPinningDetection {
			continue
		}
		host := strings.TrimSpace(c.SNI)
		if host == "" {
			host = strings.TrimSpace(c.Host)
		}
		if host != "" {
			refs = append(refs, certPinBypassRef{Host: host, CandidateID: c.CandidateID})
		}
	}
	return refs
}

// materializedCertPinCandidates returns the full materialized cert-pinning candidates for a tenant — used at
// startup to migrate any that predate the cert-pin-bypass-as-rule model into emitted Egress rules, so every
// pinned-site bypass is a single, consistent authored rule (the rule is the bypass's only source).
func materializedCertPinCandidates(store *policycandidate.Store, tenantID string) []policycandidate.Candidate {
	if store == nil {
		return nil
	}
	resp, err := store.List(context.Background(), tenantID, policycandidate.ListOptions{Status: "materialized", Limit: 1000})
	if err != nil {
		return nil
	}
	out := []policycandidate.Candidate{}
	for _, c := range resp.Candidates {
		if c.Source == policycandidate.SourceCertPinningDetection {
			out = append(out, c)
		}
	}
	return out
}

// registeredIdPIssuersFn is set once the IdP registry exists, which happens after the paths endpoint is
// registered in the same function. Nil until then, which reads as "no sign-in path" rather than a crash.
var registeredIdPIssuersFn func() []string

func registeredIdPIssuers() []string {
	if registeredIdPIssuersFn == nil {
		return nil
	}
	return registeredIdPIssuersFn()
}

// refuseStartOnUnusableCertificateFlag mirrors -refuse-start-on-unusable-certificate for the startup check,
// which runs where the config exists rather than where the flag was parsed.
var refuseStartOnUnusableCertificateFlag bool

func newServerWithConfig(config serverConfig) http.Handler {
	// The startup certificate check runs at the END of this function (just before return), NOT here: it
	// judges the served certificate against the trust anchors, and the runtime trust STORE — the
	// authoritative set once configured — is only opened further down. Run here, the check fell back to the
	// seed file and declared a perfectly served certificate refused (2026-08-02: the seed was three
	// distributions behind the store, and the false verdict sat on the Console's certificate card while
	// every device verified the certificate fine). Listeners start after this function returns, so the
	// check still runs before anything is presented to a device.
	config = config.withDefaults()
	if config.TenantTrustDistributionStore != nil {
		config.TenantTrustDistributor = &tenantTrustDistributor{config: config, store: config.TenantTrustDistributionStore, now: time.Now}
	}
	// Assigned where the broker transport is built (browser-mimic egress, further down this function); declared
	// here so the /healthz closure can capture it. The handler reads it per request, and the assignment happens
	// before any listener starts, so there is no race. Stays nil when browser-mimic egress is off — nil means
	// "no broker to be unhealthy" and Ready reports ready.
	var brokerHealth *edgeplane.BrokerHealthMonitor
	evaluator := config.Evaluator
	writer := config.Writer
	exportObjectStore := config.ExportObjectStore
	registry := config.Registry
	proxyClient := config.ProxyClient
	connectorSecret := config.ConnectorSecret
	requireConnectorRuntimeSecret := config.RequireConnectorRuntimeSecret
	devMode := config.LabMode != nil && *config.LabMode
	workloadAttestationSecret := strings.TrimSpace(config.WorkloadAttestationSecret)
	tunnelManager := config.TunnelManager
	sessionStore := config.SessionStore
	deviceStore := config.DeviceStore
	applyConfiguredPosturePolicy(deviceStore) // B-2: admin-configurable posture ruleset from env
	vlanBoundary := buildVLANBoundaryStore(config)
	edgeDNS := buildEdgeDNSRuntime(config, registry, tunnelManager)
	dnsConntrack := edgeDNS.conntrack
	edgeDNSResolver := edgeDNS.resolver
	edgeDNSPolicyStore := edgeDNS.policyStore
	// "Renew every certificate issued before T", carried in the signed agent policy. Durable: a restart that
	// forgot it would stop a fleet-wide renewal half-way through, and the devices that had not checked in yet
	// would never be told.
	edgeRenewBefore := newRenewBeforeSetting(config.RenewBeforeStorePath)
	if at, ok := edgeRenewBefore.At(); ok {
		log.Printf("device certificates: renewal is being asked of every device whose certificate was issued before %s", at.Format(time.RFC3339))
	}
	dlpRT := buildDLPRuntime(config)
	dlpRuleStore := dlpRT.rules
	dlpAllowlistStore := dlpRT.allowlist
	dlpDeviceRisk := dlpRT.deviceRisk
	entitlementStore := dlpRT.entitlements
	dlpPolicyObjects := dlpRT.policyObjects
	dlpFingerprintStore := dlpRT.fingerprints
	dlpClassifierStore := dlpRT.classifiers
	config.DLPDistribution = &dlpConfigStores{policies: dlpPolicyObjects, classifiers: dlpClassifierStore, fingerprints: dlpFingerprintStore}
	trustedKeyring := config.TrustedKeyring
	routeProfiles := config.RouteProfiles
	swgRuntime := config.SWGRuntime
	oidc := config.OIDC
	breakGlassRequests := config.BreakGlassRequests
	humanApprovals := config.HumanApprovals
	// East-west authenticate-mode held flows record a pending challenge here (E2). The OOB ceremony (E4)
	// completes it and an ephemeral grant (E3) is issued against it to release the flow.
	eastWestAuthChallenges := eastwest.NewAuthChallengeStore()
	delegatedGrants := config.DelegatedGrants
	nonHumanIdentities := config.NonHumanIdentities
	decisionStore := config.DecisionStore
	inspectionEvents := config.InspectionEvents
	domainEventOutbox := config.DomainEventOutbox
	domainEventMirror := config.DomainEventMirror
	adminExportJobs := config.AdminExportJobs
	adminExportWorker := config.AdminExportWorker
	adminDownloadTokens := config.AdminDownloadTokens
	adminAuditOutbox := config.AdminAuditOutbox
	adminAuth := config.AdminAuth
	policyStore := config.PolicyStore
	// Phase 1 config distribution: launch the config-bundle puller HERE (not in the caller) so a pull applies
	// policies + tenant-config (policy.Store) AND the DNS policy (the separate edgeDNSResolver store, built
	// just above) together. The puller needs the concrete *policy.Store for ApplyBundle.
	// startConfigBundleSync defers the CP pull loop until the authored-rule recompile hook exists — see the
	// assignment below. nil when this Edge has no config-bundle source (a standalone/CP node).
	var startConfigBundleSync func(onRulesApplied func())
	assetStore := config.AssetStore
	if assetStore == nil {
		assetStore = assetcatalog.NewStore()
	}
	ruleStore := config.RuleStore
	if ruleStore == nil {
		ruleStore = policyrule.NewStore()
	}
	if config.ConfigBundleSource != nil {
		if concretePolicyStore, ok := policyStore.(*policy.Store); ok {
			connectorCatalogTarget, _ := registry.(*connector.Registry)
			// Started here but not yet armed for rules: startConfigBundleSync is called below, once
			// recompileAuthoredRules exists. A bundle applied before the recompile hook is set would update the
			// stores and leave the engine enforcing the sets it compiled at boot.
			startConfigBundleSync = func(onRulesApplied func()) {
				go config.ConfigBundleSource.run(context.Background(), configApplyTargets{
					applications:    config.ApplicationCatalogStore,
					policyStore:     concretePolicyStore,
					dlp:             config.DLPDistribution,
					resolver:        edgeDNSResolver,
					enrolled:        config.EnrolledLedger,
					tenantModels:    tenantModelAdminStoreOrNil(config.TenantModelStore),
					vlan:            vlanBoundary,
					connectors:      connectorCatalogTarget,
					nhi:             nonHumanIdentities,
					humanIdentities: config.HumanIdentities,
					delegatedGrants: delegatedGrants,
					rules:           ruleStore,
					assets:          assetStore,
					// The Site catalog. Without this the Edge that admits connectors keeps its own list, and a
					// Site created or deleted on the control plane never reaches it — measured 2026-08-23.
					sites: config.SiteStore,
					// What devices check before they will talk to this Edge. Carried in the bundle since
					// 2026-08-23 so the fleet stops agreeing about it through a shared file.
					transportTrust: transportTrust,
					// The posture, so an Edge stops being a second author of its own enforcement.
					inspectionPosture:    config.InspectionPosture,
					setInspectionPosture: config.SetInspectionPosture,
					// ★★★ AND THE LICENCE (2026-08-27). Handing an Edge a vendor key turns licensing on; the
					// licence itself is applied on the control plane and went no further, so a correctly
					// configured paid deployment refused EVERY enrolment. The keys and the addressee here are
					// THIS node's, so the licence is verified where it is enforced.
					licenceStore:         config.VendorLicense,
					licensingGate:        config.EnrolmentLicensing,
					licenceAcceptedKeys:  config.LicenseAcceptedKeys,
					licenceMSSPID:        config.LicenseMSSPID,
					deviceCAs:            config.TenantCARegistry,
					internalCAs:          config.InternalCAs,
					deviceCARegistryPath: strings.TrimSpace(config.TenantCARegistryPath),
					deviceTrust:          trustAnchorStoreOrNil(deviceClientCAs),
					onRulesApplied:       onRulesApplied,
					// For the carried tenant erasure: this node's own copy of a terminated tenant's data. The log
					// writer above all — a tenant's logs sit on every node that served it, and no other node can
					// reach them.
					logWriter:           writer,
					localCredentials:    config.LocalCredentials,
					purgeDB:             adminAuthPostgresDB(adminAuth),
					legalHold:           config.LegalHold,
					enforcementTenantID: config.Evaluator.PolicyBundle.TenantID,
					nodeName:            adminFootprintNodeName(config.ConfigSourceURL),
					erasureOrders:       &tenantErasureOrders{},
				})
			}
		} else {
			log.Printf("config-bundle sync: policy store is not the concrete type; sync disabled")
		}
	}
	networkExtensionPublisher := config.NetworkExtensionPublisher
	applicationCatalogStore := config.ApplicationCatalogStore
	policyCandidateStore := config.PolicyCandidateStore
	agentToolStore := config.AgentToolStore
	endpointInventoryStore := config.EndpointInventoryStore
	tenantModelStore := config.TenantModelStore
	siteStore := config.SiteStore
	operatorTenantID := strings.TrimSpace(config.OperatorTenantID)
	// Which organization operates this deployment — read by every cross-organization gate. Declared here, once,
	// so the answer cannot differ between two of them. See operator_is_an_organization_not_a_role.go.
	declareOperatorTenant(operatorTenantID, tenantModelStore != nil)
	toolCallEventAuditStore := config.ToolCallEventAuditStore
	usageMeters := config.UsageMeters
	humanIdentities := config.HumanIdentities
	adminHotStore := config.HotStore
	hotStoreMirror := config.HotStoreMirror
	agentTelemetry := config.AgentTelemetry
	// The fleet's update history, recovered from the canonical log this process wrote. Without it a control
	// plane restart resets the picture to zero — and the store defaults to memory, so that is the normal case.
	hydrateAgentUpdateTelemetry(agentTelemetry, writer)
	workloadAttestations := config.WorkloadAttestations
	agentTargetVersion := config.AgentTargetVersion
	agentReleaseChannel := config.AgentReleaseChannel
	// admin-managed rollout/rollback plan (per tenant). The runtime rollout endpoint consults this
	// over the static target, so an operator can drive a rollout or roll back a bad agent version at runtime.
	// Built in main where it can be loaded from disk and a corrupt store can stop the process; a nil one here
	// is a test, and gets the volatile behaviour.
	agentRolloutPlans := config.AgentRolloutPlans
	if agentRolloutPlans == nil {
		agentRolloutPlans = agentrollout.NewAgentRolloutStore()
	}
	tcaReg := config.TenantCARegistry // authoritative tenant binding on the decision path
	// Private-app data-plane dependency set, built once and shared by every route that dispatches into
	// handleConnectorApplication. Safe as a value copy: none of these locals is reassigned after this point.
	connAppDeps := connectorApplicationDeps{
		evaluator:                 evaluator,
		policyStore:               policyStore,
		writer:                    writer,
		registry:                  registry,
		tunnelManager:             tunnelManager,
		sessionStore:              sessionStore,
		deviceStore:               deviceStore,
		proxyClient:               proxyClient,
		routeProfiles:             routeProfiles,
		applicationCatalogStore:   applicationCatalogStore,
		humanApprovals:            humanApprovals,
		delegatedGrants:           delegatedGrants,
		nonHumanIdentities:        nonHumanIdentities,
		decisionStore:             decisionStore,
		domainEventOutbox:         domainEventOutbox,
		usageMeters:               usageMeters,
		eastWestAuthChallenges:    eastWestAuthChallenges,
		workloadAttestationSecret: workloadAttestationSecret,
		devMode:                   devMode,
		workloadAttestations:      workloadAttestations,
		highRisk:                  config.HighRiskOverlay,
		enrolledLedger:            config.EnrolledLedger,
	}
	adminToken := strings.TrimSpace(config.AdminToken)
	adminEndpoint := newAdminEndpointMiddleware(evaluator, writer, adminAuditOutbox, adminAuth, adminToken, devMode, tenantModelStore,
		// Does this organization have anybody who can administer it? Second return says whether that could be
		// established at all — an unanswerable question must not read as "nobody". Invited-but-not-activated
		// counts: that person can sign in whenever they like, so the organization is not waiting on anyone.
		func(ctx context.Context, tenantID string) (bool, bool) {
			if config.LocalCredentials != nil {
				if len(config.LocalCredentials.List(strings.TrimSpace(tenantID))) > 0 {
					return true, true
				}
			}
			stats, ok := adminAuth.(adminAuthStatsReader)
			if !ok {
				return false, config.LocalCredentials != nil
			}
			counts, err := stats.AdminAuthStats(ctx, strings.TrimSpace(tenantID))
			if err != nil {
				return false, false
			}
			return counts.Principals > 0, true
		}, config.LocalCredentials)
	mux := http.NewServeMux()
	configSyncStatus := config.ConfigSyncStatus                  // Phase 1 config-bundle puller status (nil = authoritative-local)
	revocationSyncState := config.RevocationSyncStatus           // Phase 3 fast revocation puller status (nil = no CP sync)
	configSourceURL := strings.TrimSpace(config.ConfigSourceURL) // "" unless this Edge pulls config from a CP (write-path inversion)
	// configBundleEpoch is a per-process id for the config bundle: it changes every time THIS edge (acting as a
	// control plane) restarts. The aggregate generation is in-memory and resets on restart, so the epoch lets a
	// puller detect a CP restart and re-baseline instead of freezing on a stale higher generation.
	configBundleEpoch := strconv.FormatInt(time.Now().UnixNano(), 10)
	// Prometheus metrics (unauthenticated, like /healthz) — served ONLY on the admin/management listener (the
	// data plane and public origin 404 it via the surface middlewares), so it is scraped from the management
	// network. Highest-value operational signal for a fail-closed ZTNA: decision throughput + allow/deny rate.
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		setDecisionsInFlight(decisionStore.InFlightCount())
		writePrometheusMetrics(w, time.Now())
	})
	// CP leader status for the follows-leader load balancer (HAProxy httpchk): 200 only on the active CP, 503 on
	// a standby. On the active's death its advisory lock releases, a standby is elected, and the LB routes to it.
	mux.HandleFunc("GET /leader", func(w http.ResponseWriter, r *http.Request) {
		if cpLeaderElectorInstance.IsLeader() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"leader":true}` + "\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"leader":false}` + "\n"))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// Phase 4 graceful drain: once draining, report 503 so the LB stops sending NEW connections here while
		// in-flight requests bleed out. The data port keeps serving until Shutdown — this is what makes a
		// rolling upgrade zero-outage.
		if config.DrainState != nil && config.DrainState.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
			return
		}
		// Key custody readiness. A signing key that cannot sign means this node can no longer intercept any
		// hostname it has not already cached, so in an HA set the balancer must send NEW flows elsewhere. The
		// balancer PULLS this rather than the node pushing itself out: a node broken enough to matter may be
		// too broken to execute a removal, and a hung one fails readiness simply by not answering.
		if ready, reason := config.KeyCustodyMonitor.Ready(); !ready {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "key_custody_unhealthy",
				"detail": reason,
				"note":   "the interception signing key cannot sign; already-cached leaves still work, but no NEW hostname can be intercepted",
			})
			return
		}
		// Egress-broker readiness (design §"What to build" items 2+3): with no fallback engine, a broker that
		// is unusable (consecutive probe failures — see BrokerHealthMonitor for the definition) means decrypt-all
		// egress has no transport, so an HA balancer must send NEW flows to a node whose broker works. The gate
		// is the cached monitor, never a per-request probe. nil monitor = browser-mimic egress off = ready.
		if ready, reason := brokerHealth.Ready(); !ready {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "egress_broker_unusable",
				"detail": reason,
				"note":   "decrypt-all egress has no engine while the broker is unusable (there is no fallback); bypass and connector-tunnel paths are unaffected. In an HA set this node should be drained; on a single node flows fail legibly until the broker recovers",
			})
			return
		}
		body := map[string]any{"status": "ok"}
		// ★★★ WHAT THIS NODE IS, so the deployment's shape can be CHECKED rather than inferred from a compose
		// file (2026-08-23). Two of the architecture's invariants are about which node holds what — the control
		// plane holds the authority, and an enforcement Edge holds no database — and neither could be asked of
		// a running node. It had to be read off the flags of whoever started it, which is not available to an
		// installer verifying a deployment somebody else stood up, and not available at all once the process
		// outlives the file.
		//
		// Neither field is a secret. "This node has a database" and "this node is the control plane" are
		// structural facts a load balancer, an installer and an operator all need, and hiding them would mean
		// the only way to establish the deployment's shape is to trust that it was configured correctly.
		body["role"] = map[bool]string{true: "control-plane", false: "edge"}[edgeIsControlPlane]
		body["holds_database"] = cpStateBlobDB != nil
		// ★★★ AND WHICH BUILD THIS NODE IS (2026-08-25, after an hour spent on a defect that was not one). A
		// control plane left running an older image served STALE configuration to the whole fleet — a removed
		// device was still admitted, blocking answered 404 — and the deployment's own verification reported
		// all three as failures of the product. Nothing anywhere could say that one node was a different
		// build. The reference lab has had a fleet-uniformity check for months, reading labels off containers;
		// a deployment an operator generated has no containers anybody can inspect and no such check.
		//
		// So each node says it about itself, on the endpoint every other check already reads. Not a secret:
		// "which build is running" is a structural fact, and hiding it means the only way to establish it is
		// to trust that everything was deployed at the same time.
		// ★★★ AND WHERE THE CANONICAL LOG GOES (2026-08-26). The architecture makes the local jsonl the
		// ORIGINAL and the shipment the copy, so a control plane being down costs delivery and not the record.
		// -log-dir defaults to a RELATIVE path, which on a container resolves inside the writable layer and
		// dies with it — measured on a generated deployment whose durable volume was mounted and unused.
		// Reported as a path plus the one property that matters, so a check does not have to guess.
		body["logs"] = map[string]any{"dir": config.LogDir, "durable": filepath.IsAbs(config.LogDir)}
		// ★★★ WHETHER THIS NODE'S LAST CONFIGURATION PULL SUCCEEDED (2026-09-03, measured on a deployment
		// that reported 68/68 while every Edge was 401 on every pull).
		//
		// The Edge has tracked this all along and reported it to the CONTROL PLANE — over the same channel.
		// When the credential is missing that report is 401 too, so the fleet view shows nothing: the node
		// cannot report that it cannot report. Every check that read the fleet view therefore passed, and the
		// one check that asked an Edge anything asked whether it had EVER applied a configuration — which is
		// true forever after the first successful pull at boot, including for a node that has been refused
		// every pull since.
		//
		// So it is said HERE, on the node's own unauthenticated health surface, where a checker reaches it
		// without depending on the thing that is broken.
		if configSyncStatus != nil {
			body["config_pull"] = configSyncStatus.snapshot()
		}
		body["build"] = map[string]any{
			"version": buildVersion, "commit": buildCommit, "date": buildDate,
			// An unstamped binary must be recognisable as unstamped rather than quietly matching another
			// unstamped one — two nodes both saying "unknown" have not been shown to agree.
			"stamped": buildCommit != "unknown", "dirty": buildDirty == "true",
		}
		// ★★★ AND WHETHER WHAT THIS NODE RECORDS IS REACHING THE AUTHORITY. It is a path, and a path that
		// has stopped carrying said so only on this node's own stdout — no screen, no check, no endpoint. An
		// Edge goes on enforcing perfectly while its entire history reaches nobody, which is the safe
		// direction for traffic and the worst possible one for an operator, who is looking at reports that
		// are quietly missing a node. Absent here means this node was never told where to ship.
		if config.AuditShipHealth != nil {
			body["audit_shipping"] = config.AuditShipHealth(time.Now())
		}
		// ★ AND WHETHER THAT DATABASE IS ALONE. A control plane INCLUDES its database, so the authority is
		// redundant only if the state is — counting control-plane processes answers a different question.
		// Unknown is reported as unknown: "I could not ask" and "there are none" must not become the same
		// number.
		if cpStateBlobDB != nil {
			db := map[string]any{"replicas_streaming": nil}
			if replicas, known := streamingReplicas(cpStateBlobDB); known {
				db["replicas_streaming"] = replicas
			}
			// ★★★ AND WHERE THEY ARE, WHICH THE COUNT CANNOT SAY (2026-08-27). A deployment whose second
			// region held no database at all passed the count, because the first region's own pair answered
			// it. A replica beside the primary survives a machine; only a replica somewhere else survives the
			// site, and the only way to tell them apart is the name each member calls itself in the cluster.
			if names, known := streamingReplicaNames(cpStateBlobDB); known {
				db["replica_members"] = names
				if elsewhere, ok := replicaOutsideThisRegion(names, config.Evaluator.EdgeRegionID); ok {
					db["replica_outside_this_region"] = elsewhere
				}
			}
			body["database"] = db
		}
		// ★★★ WHICH REGION THIS NODE IS IN, AND WHICH REGIONS IT KNOWS ABOUT (2026-08-23, found by walking the
		// multi-region install order). The class-1 region map is built from -region-endpoints and from nothing
		// else: it is not authored on the control plane and it does not travel in the bundle. So "give every
		// Edge the region entry list" — the step the install order puts after every region exists — is N
		// command-line edits, and an Edge somebody forgot to edit is HEALTHY and hands devices a shorter list.
		// Nothing anywhere said which regions a node knew about, so the question could not even be asked.
		//
		// The digest, not the map: the endpoint URLs are handed to every enrolled device and are not secret,
		// but this route needs no authentication and the ids plus a digest are enough to answer the only
		// question worth asking here — do two nodes of one fleet hand out the SAME map. A differing URL for a
		// matching id moves the digest.
		liveRegions := regionMap.Catalog()
		// ★ HOW MANY RECORDS ARRIVED WITHOUT SAYING WHERE THEY CAME FROM. It should be zero; it was 29,859
		// before anybody counted, because nothing did. Reported here so a producer that forgets becomes a
		// number somebody can watch rather than an empty column nobody queries.
		if with, without := hotstore.IngestRegionCounts(); with+without > 0 {
			body["ingested_records"] = map[string]any{"with_region": with, "without_region": without}
		}
		// Whether a connector in ANOTHER region is reachable from this node, and whether anything is allowed
		// to try. Both empty is fail-closed by design; see mesh_state_report.go.
		// What this node can actually reach the internet BY. An agent captures IPv6 too, and an Edge with no
		// IPv6 leg closes every one of those flows with no bytes. See egress_address_family.go.
		if fam := egressFamiliesForReport(); fam != nil {
			body["egress_address_family"] = fam
		}
		body["mesh"] = meshStateForReport()
		// Where this node takes configuration from, and whether it has anywhere else to go if that region is
		// lost. the multi-region control-plane failover step; see controlChannelStateForReport.
		body["control_channel"] = controlChannelReport()
		body["region_endpoints"] = liveRegions.regionIDs()
		body["region_endpoints_digest"] = liveRegions.digest()
		if region := strings.TrimSpace(config.Evaluator.EdgeRegionID); region != "" {
			body["region"] = region
		}
		if broker := brokerHealth.Health(); broker != nil {
			body["egress_broker"] = broker
		}
		// Phase 1 config distribution: surface the last-applied CP generation so an L4/L7 health check can
		// drain an Edge lagging the fleet (design) without admin auth. Only the integer + timestamps are
		// exposed here (non-sensitive); the full status (source/errors) is behind GET /admin/config-sync-status.
		if configSyncStatus != nil {
			snap := configSyncStatus.snapshot()
			body["config_sync"] = map[string]any{
				"have_applied":            snap["have_applied"],
				"last_applied_generation": snap["last_applied_generation"],
				// The epoch travels with the generation, because the two are only comparable together.
				"last_applied_epoch": snap["last_applied_epoch"],
				"last_applied_at":    snap["last_applied_at"],
				"last_poll_at":       snap["last_poll_at"],
			}
		}
		// The FAST revocation overlay. REPORTED, never a drain signal: a node whose revocation sync is broken is
		// still enforcing everything else, and taking it out of rotation for this would turn a stale kill-switch
		// into an outage. It is here so that "has this node ever heard the control plane's revocation set" can
		// be asked by something other than reading a container log — which is what it took to find that the
		// answer had been NO since boot while /healthz said ok. The posture check is what fails on it.
		if revocationSyncState != nil {
			snap := revocationSyncState.snapshot()
			body["revocation_sync"] = map[string]any{
				"have_applied":         snap["have_applied"],
				"last_applied_at":      snap["last_applied_at"],
				"last_poll_at":         snap["last_poll_at"],
				"consecutive_failures": snap["consecutive_failures"],
				"last_error":           snap["last_error"],
			}
		}
		writeJSON(w, http.StatusOK, body)
	})
	// Phase 1 config distribution: the Edge's config-bundle puller status (the last CP generation it applied,
	// last poll/error). A fleet-health checker compares last_applied_generation to the control plane's current
	// generation (GET /admin/config-bundle on the CP) and drains a lagging Edge. enabled=false when this Edge
	// is authoritative-local (no -config-source-url).
	mux.HandleFunc("GET /admin/config-sync-status", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		if configSyncStatus == nil {
			writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
			return
		}
		writeJSON(w, http.StatusOK, configSyncStatus.snapshot())
	}))
	// Audit/persistence decoupling: the control plane receives audit/events shipped by enforcement Edges and
	// persists them (POST /audit-ingest; registered only when a receiver token is set).
	// The fleet's own channel for the one decision an Edge cannot make alone: may this one-time enrolment
	// token be spent. Registered on whichever node HOLDS the authority — in practice the control plane, since
	// a config-pulling Edge now asks rather than holding a store. See enrolment_token_fleet_routes.go.
	registerEnrolmentTokenFleetRoutes(mux, adminEndpoint, config.EnrolmentTokens, logInfof)
	// The other one-time decision an Edge must not take alone: whether a device identity has already enrolled.
	// Same shape, same reason — see enrolled_identity_claim_fleet_routes.go.
	registerEnrolledIdentityClaimFleetRoutes(mux, adminEndpoint, config.FleetIdentityClaimer, logInfof)
	// Who has no way back, served where a person can read it before a destructive act.
	registerRecoveryReadinessRoute(mux, adminEndpoint)
	registerAuditIngestReceiver(mux, writer, config.AuditIngestReceiverToken, agentTelemetry, config.ObservedExclusions, tcaReg,
		config.LabMode != nil && *config.LabMode)
	// ★ AND THE MATERIAL AN EDGE NEEDS TO SERVE AN ORGANIZATION IT WAS NEVER PREPARED FOR (2026-08-20). Same
	// door as the audit channel, same proof of which Edge is calling — because this one hands out an
	// organization's server identity, and a shared bearer alone must not be enough for that.
	registerTenantTransportMaterialRoute(mux, config.TenantTransportAuthority, config.TenantInterceptionAuthority,
		config.TenantDeviceAuthority, config.AuditIngestReceiverToken, config.TenantTransportMaterialTTL, tcaReg,
		config.LabMode != nil && *config.LabMode, config.TenantTrustDistributor)
	// The machine door for "a device enrolled here", on the same identified channel as the material above.
	registerEnrolmentReportRoute(mux, config.EnrolledLedger, tcaReg, strings.TrimSpace(config.ConfigSourceURL),
		config.LabMode != nil && *config.LabMode)
	// The other half of the same sentence, for connectors — see connector_cp_report.go.
	registerConnectorReportRoute(mux, registry, tcaReg, strings.TrimSpace(config.ConfigSourceURL),
		config.LabMode != nil && *config.LabMode)
	registerTenantTransportAuthorityAdminRoute(mux, adminEndpoint, config.TenantTransportAuthority)
	registerTenantInterceptionAuthorityAdminRoute(mux, adminEndpoint, config.TenantInterceptionAuthority, config.TenantModelStore, newPKITransitionAdmission(config))
	registerTenantDeviceAuthorityAdminRoute(mux, adminEndpoint, config.TenantDeviceAuthority,
		strings.TrimSpace(config.ConfigSourceURL), config.TenantModelStore, newPKITransitionAdmission(config))
	// ★ And the READS for those two tiers, which did not exist until 2026-08-22: every act had a door and
	// only the transport tier could be looked at. See tenant_authority_reads.go.
	registerTenantAuthorityReadRoutes(mux, adminEndpoint, config.TenantDeviceAuthority,
		config.TenantInterceptionAuthority, newPKITransitionAdmission(config))
	// The evidence half of a device-authority rotation. Registered on every node, because the answer is about
	// what THIS node has seen at a handshake and an operator asks each Edge before retiring anything.
	registerDeviceAuthorityRotationRoute(mux, adminEndpoint, config)
	// The evidence half of an interception rotation, on the same reasoning: only an Edge collects what a
	// device reports HOLDING, and promoting before every one of them does is the outage staging prevents.
	registerInterceptionAuthorityRotationRoute(mux, adminEndpoint, config)
	// Whether an organization's devices have moved onto its new transport name — the evidence for dropping the
	// old one, which is a TLS failure for anything still sending it.
	registerTransportNameRenameRoute(mux, adminEndpoint, config)
	registerTenantTransportRotationAdminRoutes(mux, adminEndpoint, config.TenantTransportAuthority, configSourceURL, newPKITransitionAdmission(config))
	// W3: DNS over the encrypted (T) tunnel — the endpoint sends raw DNS here instead of plaintext
	// UDP:53, so the queried domain only appears inside the tunnel and only the Edge resolves it.
	// Gate the DNS-over-tunnel resolver on a verified device identity, exactly like every sibling /steer/*
	// control endpoint (agent-tuning, server-initiated-export, …). Without this the route was an
	// UNAUTHENTICATED open resolver on the (T) listener — any caller that reached it could resolve arbitrary
	// names through the Edge (review #28). The resolver body itself (OverTunnelHandler) is unchanged.
	{
		dnsOverTunnel := dnsresolver.OverTunnelHandler(edgeDNSResolver)
		// Count every resolution. This subsystem previously had no durable output at all, so when it failed for
		// two hours on 2026-08-09 (20,616 agent-side failures) the cause could not be established afterwards.
		// A count, not a log: no qname is involved, and the per-query audit's deliberate silence is unchanged.
		dnsresolver.SetOverTunnelObserver(recordDNSOverTunnel)
		// Declare that this node serves the route, so a zero failure count means "healthy" here and cannot be
		// confused with the zero a node that never registered it also reports.
		setDNSOverTunnelEnabled(true)
		mux.HandleFunc("POST /steer/dns-query", func(w http.ResponseWriter, r *http.Request) {
			if identity, verified := transportDeviceIdentityFromRequest(r); !verified || strings.TrimSpace(identity) == "" {
				writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
				return
			}
			dnsOverTunnel(w, r)
		})
	}
	mux.HandleFunc("GET /admin/state", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		state, err := adminState(runtimeEvaluatorForPolicyStore(evaluator, policyStore), adminTenantIDFromRequest(r), writer, registry, deviceStore, config.EnrolledLedger, humanApprovals, delegatedGrants, decisionStore, inspectionEvents, routeProfiles, !edgeIsControlPlane)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, state)
	}))
	// ★★ THE FLEET SPANS EDGES, AND THIS ANSWERED FOR ONE (2026-08-14, from the operator: a Mac steering
	// perfectly through region-b was reported as not steering, with no user, because the Console reads
	// region-a). A device fails over — by design — and disappears from the node the front door happens to
	// proxy to. "Not steering" and "steering somewhere you are not looking" rendered identically, which is the
	// per-Edge-view family this codebase has already paid for once in authored rules.
	//
	// A control plane holds every Edge's shipped device_state history, so it can answer for the whole fleet:
	// this node's own live map, with anything it has not seen itself filled in from that history, and each row
	// naming the Edge it came from. On an Edge (no such history) the answer is unchanged — its own devices —
	// which is the truthful answer for a node that only knows its own.
	mux.HandleFunc("GET /admin/device-runtime", adminEndpoint("admin.enrollment.read", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		// Scoped to the caller's tenant BEFORE anything else looks at it. See scopeDeviceRuntimeToTenant: this
		// route used to return the node's whole presence map, so a customer's own admin could read another
		// customer's devices, their operating systems, their logged-in users and their posture.
		devices, withheld := scopeDeviceRuntimeToTenant(deviceRuntime.snapshot(now), config.EnrolledLedger, adminTenantIDFromRequest(r))
		fleetWide := false
		if adminHotStore != nil {
			tenantID := adminTenantIDFromRequest(r)
			// ★ FROM THE PROJECTION, NOT FROM A 48-HOUR REPLAY (2026-08-14). This used to query the shipped
			// history on every load. Once a steering device began re-shipping its state once a minute — which
			// is what lets a remote reader answer in the present tense — that query took 10.7 seconds and its
			// 2000-row cap started pushing QUIET devices off the page. The rows are folded at arrival now;
			// see device_runtime_projection.go. The history is still canonical and still what the projection is
			// built from at startup.
			merged, seeded := mergeFleetDeviceRuntimeFromProjection(devices, fleetDeviceProjectionStore, tenantID, now)
			if seeded {
				devices = merged
				fleetWide = true
			} else {
				// Said, not swallowed: an operator reading a fleet page before the projection has been built
				// must not be shown one node's devices as though they were the fleet. "Not seeded yet" and
				// "this fleet has one node" are the same empty answer and must not render the same.
				log.Printf("device-runtime: the fleet projection has not been seeded yet — answering with this " +
					"node's own devices only")
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_device_runtime.v1",
			// Keyed the way the enrolled inventory keys it, so a screen can join the row to its state. See
			// the_runtime_view_is_keyed_the_way_the_ledger_is.go: a Mac called "ShinnoMac-mini" was admitted as
			// "shinnomac-mini" and rendered as "not steering yet" while it was steering.
			"devices": keyDeviceRuntimeTheWayTheLedgerDoes(devices),
			// Devices present on this node that the enrolled ledger cannot attribute to any tenant. Reported
			// rather than silently omitted: a page that drops rows without saying so teaches its reader that
			// the fleet is smaller than it is.
			"withheld_unattributable": withheld,
			// Whether this answer covers the fleet or one node. A screen that cannot tell them apart is how a
			// device steering elsewhere reads as a device steering nowhere.
			"fleet_wide":            fleetWide,
			"no_secret_attestation": true,
		})
	}))
	registerAIOpsRoutes(mux, adminEndpoint, evaluator, policyStore, decisionStore, adminHotStore)
	// Management-plane certificate rotation (slice 2): list the rotatable server certs, and rotate one from the
	// admin surface with NO restart (hot-reload). Validate-before-accept; a bad cert/key never bricks the link.
	registerCertsAdminRoutes(mux, adminEndpoint, config, evaluator, writer)
	registerSteerExclusionRoutes(mux, adminEndpoint, config, evaluator, writer)
	registerInternalCARoutes(mux, adminEndpoint, config)
	// Before rotating the transport CA: which devices already trust the one I am about to switch to?
	//
	// Without this the operator switches and hopes. A device that has not picked up the new CA cannot recover
	// on its own — it can no longer verify the Edge, and the new CA would have arrived over the tunnel it can
	// no longer establish — so cutting over early manufactures exactly the devices that need a human.
	// "What is set up, and what is still missing?" — the fact a Day-0 wizard needs before it can have screens.
	// Distinct from /healthz, which answers "should this node take traffic": a node can be perfectly healthy and
	// still be missing every piece of a production PKI.
	assessPKIReadinessNow := func() pkiReadinessReport {
		in := pkiReadinessInput{
			ControlPlane: edgeIsControlPlane,
			// Counted from the same function the start-up line uses, so the assessment and the log can never
			// disagree about how many doors this Edge asks an agent to dial.
			EnrollConfigured:  config.EnrollSigner != nil,
			EnrollSharedToken: strings.TrimSpace(config.EnrollToken) != "",
			EnrollIdPBacked:   config.EnrollIdPEligibility != nil,
			EnrollAdminTokens: config.EnrolmentTokens != nil,
			// The deployment's own addresses, so the guide can state the remediation with real values instead of
			// leaving an operator to work out which host, port and path it meant.
			RenewalEndpointURL:  strings.TrimSpace(config.TransportTLSURL),
			RecoveryEndpointURL: strings.TrimSpace(config.EnrollRenewGraceListen),
			// The remaining items were prose-only until 2026-07-30: correct advice an operator could not act on
			// without going to look up values this assessment already holds.
			HSMAgentSocket:            strings.TrimSpace(config.InterceptionHSMAgentSocket),
			EnrolmentTokenStore:       strings.TrimSpace(config.EnrolmentTokenStoreMode),
			EnrolmentTokenMaxLifetime: config.EnrolmentTokenMaxLifetime,
			EnrolmentTokenOutstanding: config.EnrolmentTokenMaxOutstanding,
			// Renewal is registered together with the signer, so one implies the other.
			RenewalEndpoint:  config.EnrollSigner != nil,
			RecoveryListener: strings.TrimSpace(config.EnrollRenewGraceListen) != "",
			RecoveryWindow:   config.EnrollRenewGraceWindow,
		}
		// Whether each organization's devices are told to look for the root that signs their traffic. The two
		// announcement paths had drifted, and the device-side signal could not see it: it measures whether the
		// box holds the ANNOUNCED root, which was true while the SIGNING root was another certificate entirely.
		in.InterceptionAnnouncementMismatch = interceptionAnnouncementMismatches(config)
		// Configuration and expiry are different questions and only the second has a date on it. This
		// assessment answered the first for years and never the second.
		if what, until, have, kind, who := soonestPKIExpiryDetailed(config, time.Now()); have {
			in.SoonestExpiryWhat, in.SoonestExpiryIn, in.SoonestExpiryHave = what, until, true
			in.SoonestExpiryKind, in.SoonestExpiryWho = kind, who
		}
		if config.NetworkExtensionLabTLS != nil {
			custody := config.NetworkExtensionLabTLS.KeyCustody()
			if v, ok := custody["custody"].(string); ok {
				in.KeyCustody = v
			}
			if v, ok := custody["healthy"].(bool); ok {
				in.KeyCustodyHealthy = v
			}
			// "checked_at" is absent until the first functional check completes. Its absence means UNKNOWN,
			// which the assessment must not read as working.
			_, in.KeyCustodyChecked = custody["checked_at"]
			interceptionStatus := config.NetworkExtensionLabTLS.InterceptionIntermediateStatus()
			if mode, ok := interceptionStatus["mode"].(string); ok {
				in.IntermediateActive = mode != "none" && mode != "off"
			}
			if _, failed := interceptionStatus["reparent_restore_failed"]; failed {
				in.ReparentRestoreFailed = true
			}
		}
		return assessPKIReadiness(in)
	}
	// The certificate MAP — every certificate and trust material this node is configured with, as objects with
	// where-used relations and install material. The Console's certificate hub renders this per node, and the
	// PATHS view references the same inventory by item ID so the two views cannot disagree.
	buildPKIInventoryNow := func() pkiCertificateInventory {
		in := pkiCertInventoryInput{
			Now:             time.Now(),
			ComponentCerts:  certInventory(),
			MainListen:      strings.TrimSpace(config.MainListenAddr),
			AdminListen:     strings.TrimSpace(config.AdminListenAddr),
			TransportListen: strings.TrimSpace(config.TransportListenAddr),
			RecoveryListen:  strings.TrimSpace(config.EnrollRenewGraceListen),
			DeviceCertCount: len(deviceCertificates.snapshot()),
		}
		in.TrustBundleCAPEM, in.TrustBundleSerial = currentTrustAnchors(config)
		in.InterceptionPendingRootPEM = config.InterceptionPendingRootPEM
		// The registry is the authority for which organization a device-trust CA belongs to — a certificate is
		// admitted AS the tenant whose CA issued it — so the screen is given that same fact instead of reading
		// the owner out of the certificate's name.
		if config.TenantCARegistry != nil {
			owners := map[string]string{}
			for _, fact := range config.TenantCARegistry.Facts(time.Now().UTC()) {
				if sha := strings.TrimSpace(fact.SHA256); sha != "" {
					owners[sha] = fact.TenantID
				}
			}
			in.DeviceCAOwners = owners
		}
		if deviceClientCAs != nil {
			gates := map[string]gateVerdictResult{}
			for _, c := range deviceClientCAs.Anchors() {
				fp := certFingerprint(c)
				ok, v := deviceClientCARetireGate(config, evaluator.PolicyBundle.TenantID, fp)
				gates[fp] = gateVerdictResult{OK: ok, Code: v.Code, Text: v.Text, Params: v.Params}
			}
			in.DeviceCARetireGate = gates
			logInfof("device_ca_retire_gate computed=%d store_anchors=%d", len(gates), len(deviceClientCAs.Anchors()))
		}
		// Who is known to trust each interception root. Silence is kept separate from "does not trust it":
		// a device that has not reported may well hold it, and a gate that reads silence as absence would
		// block forever, while one that reads it as presence would strand a fleet.
		if config.ObservedExclusions != nil {
			// ★★★ MEASURED AGAINST THE ROOT THAT SIGNS, NOT THE NODE'S (2026-08-19). This loop asked only
			// nodeWideInterceptionRootFingerprints, so on a deployment where each organization signs under its
			// own root the measurement landed on the wrong certificate entirely. Measured on the reference lab:
			//
			//   Lab Tenant Interception Root 2028  — signs every leaf, mac-dev-1 reports holding it — trusted=[] silent=[]
			//   Lantern DSSE MSSP Root CA v2       — signs for nobody                                — silent=[conn_lab_001, win-dev-1]
			//
			// The root everybody must hold was measured against NOBODY, and the one nobody needs carried the
			// rows. A healthy device holding exactly the right certificate appeared nowhere.
			//
			// That is not only a screen: the interception-root switch and the withdrawal gate are gated on
			// adoption, so an adoption number keyed to the wrong root is a gate that cannot fail.
			//
			// A root is measured over the devices that MUST HOLD IT: an organization's own root over that
			// organization's devices, and the node-wide root over the organizations it still signs for — which
			// on a fully per-tenant deployment is nobody, so it correctly has no rows at all.
			byRoot := map[string]interceptionRootTrust{}
			// ★★★ MEASURED IN THE ORGANIZATION THAT FILED THE REPORT (2026-09-05). Both of these closures used
			// to read every device's report under config.TenantIDForTrust — this node's own organization — so
			// a device belonging to a customer was silent about material it had reported holding, and the
			// screen said "0% trusted" beside an anchor the whole fleet held. tenant is carried in because
			// reports are stored per organization; see deviceReportedInterceptionRoot.
			measure := func(fp, tenant string, devices []string) {
				fp = strings.TrimSpace(fp)
				if fp == "" {
					return
				}
				t := byRoot[fp]
				if t.Trusted == nil {
					t = interceptionRootTrust{Trusted: []string{}, Silent: []string{}}
				}
				for _, id := range devices {
					holds, said := deviceReportedInterceptionRoot(config, tenant, id, fp)
					switch {
					case !said:
						t.Silent = append(t.Silent, id)
					case holds:
						t.Trusted = append(t.Trusted, id)
					}
				}
				byRoot[fp] = t
			}
			// ★★ FROM THE LEDGER, NOT FROM enabledEnrolledIdentities (2026-08-19, caught by the live gate the
			// moment it was written). That helper filters to the NODE's own organization, so every other
			// organization's root would be measured against an empty candidate list — Northwind's own root,
			// with Northwind's own laptop enrolled, reported an audience of nobody. Adoption with no
			// denominator is the shape that makes a switch gate unfailable, which is the defect one level out
			// from the one being fixed here.
			devicesOf := func(tenants map[string]bool) []string {
				out := []string{}
				if config.EnrolledLedger == nil {
					return out
				}
				for _, entry := range config.EnrolledLedger.List() {
					if !entry.Enabled {
						continue
					}
					tenant := strings.ToLower(strings.TrimSpace(entry.TenantID))
					if tenants != nil && !tenants[tenant] {
						continue
					}
					if id := strings.TrimSpace(entry.Identity); id != "" {
						out = append(out, id)
					}
				}
				return out
			}
			if config.NetworkExtensionLabTLS != nil {
				for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
					tenant := strings.ToLower(strings.TrimSpace(issuer.Tenant))
					if tenant == "" {
						continue
					}
					mine := devicesOf(map[string]bool{tenant: true})
					for _, root := range config.NetworkExtensionLabTLS.OfflineTenantAnnouncedRoots(issuer.Tenant) {
						measure(certFingerprint(root), tenant, mine)
					}
				}
			}
			// The node-wide root, over the organizations it would still sign for. Empty is the answer on a
			// deployment where every organization has an authority of its own.
			served := map[string]bool{}
			for _, tenant := range tenantsWithoutTheirOwnInterceptionIssuer(config) {
				served[strings.ToLower(strings.TrimSpace(tenant))] = true
			}
			// Per organization, not over the pooled list: the node-wide root can still serve several, and each
			// one's devices filed their reports under their own organization.
			for tenant := range served {
				mine := devicesOf(map[string]bool{tenant: true})
				if len(mine) == 0 {
					continue
				}
				for _, fp := range nodeWideInterceptionRootFingerprints(config) {
					measure(fp, tenant, mine)
				}
			}
			in.InterceptionRootTrust = byRoot

			// The same question for the anchors devices verify THE EDGE with. Every enrolled device must hold
			// the shared anchor; an organization's own anchor is measured over that organization's devices,
			// which is what makes roadmap D's last step — withdrawing the shared one from that organization's
			// bundle — a measurement rather than a hope.
			byAnchor := map[string]interceptionRootTrust{}
			// ★★ THE STORE ALREADY ANSWERS THIS, AND MY FIRST VERSION ANSWERED IT WORSE (2026-08-19).
			// TransportCAReadiness has existed for the transport-anchor withdrawal gate all along: it returns
			// Ready / NotReady / Silent, and it ages a report out rather than treating a six-month-old claim as
			// current. I hand-rolled a second reader over the same data and it put a device that had ANSWERED
			// into no list at all — win-dev-1, which reports and does not hold the lab organization's anchor,
			// appeared nowhere on the screen that decides whether that anchor may be withdrawn.
			//
			// A second definition of "who holds this CA" is the shape this project keeps finding. There is one.
			// tenant, again, because TransportCAReadiness reads the reports filed by THAT organization's
			// devices — and merged across organizations, because one anchor can be held by several. Merging
			// rather than overwriting is the difference between "the fleet holds it" and "the last
			// organization I looked at holds it".
			measureAnchor := func(fp, tenant string, devices []string) {
				fp = strings.ToLower(strings.TrimSpace(fp))
				if fp == "" || len(devices) == 0 || config.ObservedExclusions == nil {
					return
				}
				r := config.ObservedExclusions.TransportCAReadiness(tenant, fp, devices)
				t := byAnchor[fp]
				t.Trusted = append(t.Trusted, r.Ready...)
				t.NotHeld = append(t.NotHeld, r.NotReady...)
				t.Silent = append(t.Silent, r.Silent...)
				byAnchor[fp] = t
			}
			sharedPEMs, _ := currentTrustAnchors(config)
			// Every enrolled organization must hold the shared anchor, so it is measured once per organization
			// and the answers are merged. Pooling every device into one call read them all under this node's
			// organization, which is how a Mac that reports its pins every thirty seconds appeared as
			// "not reported".
			for _, tenant := range organizationsOf(config.EnrolledLedger, config.TenantIDForTrust) {
				mine := devicesOf(map[string]bool{strings.ToLower(strings.TrimSpace(tenant)): true})
				if len(mine) == 0 {
					continue
				}
				for _, c := range parseAllCerts([]byte(sharedPEMs)) {
					measureAnchor(certFingerprint(c), tenant, mine)
				}
			}
			for tenant, anchorPEM := range transportTenantCertificates.anchorsByTenant() {
				mine := devicesOf(map[string]bool{strings.ToLower(strings.TrimSpace(tenant)): true})
				for _, c := range parseAllCerts([]byte(anchorPEM)) {
					measureAnchor(certFingerprint(c), tenant, mine)
				}
			}
			in.TransportAnchorTrust = byAnchor
			in.PerTenantTransportAnchors = transportTenantCertificates.anchorsByTenant()
			in.PerTenantPendingTransportAnchors = transportTenantCertificates.pendingAnchorsByTenant()
		}
		// Read from the same files the listeners were configured with. A file that no longer reads simply
		// contributes nothing — this is an inventory, and the absence is visible as a missing row.
		if p := strings.TrimSpace(config.TransportCertFile); p != "" {
			in.TransportCertPEM, _ = os.ReadFile(p)
			// The transport cert registers in the hot-reload registry under its file's derived name, which is
			// what makes "replace" a real capability on its map item.
			in.TransportCertName = deriveCertName(p)
			if served, serr := servedTransportLeaf(); serr == nil {
				report := buildServerCertAdoption(served, servedCertSightings.snapshot(), enabledEnrolledIdentities(config))
				in.TransportAdoption = &report
			}
		}
		if deviceClientCAs != nil {
			pems, _ := deviceClientCAs.Current()
			in.TransportClientCAPEM = []byte(pems)
			in.DeviceClientCARetirable = true
		} else if p := strings.TrimSpace(config.TransportClientCAFile); p != "" {
			in.TransportClientCAPEM, _ = os.ReadFile(p)
		}
		if p := strings.TrimSpace(config.DeviceIssuingCAFile); p != "" {
			in.DeviceIssuingCAPEM, _ = os.ReadFile(p)
		}
		if config.NetworkExtensionLabTLS != nil {
			in.InterceptionEnabled = true
			in.InterceptionRootPEM = config.NetworkExtensionLabTLS.RootCertificatePEM()
			in.IntermediateStatus = config.NetworkExtensionLabTLS.InterceptionIntermediateStatus()
			// Each tenant's own anchor, so this screen can say whose authority intercepts whom.
			for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
				if strings.TrimSpace(issuer.RootPEM) == "" {
					continue
				}
				in.PerTenantInterceptionRoots = append(in.PerTenantInterceptionRoots,
					perTenantInterceptionRoot{Tenant: issuer.Tenant, RootPEM: issuer.RootPEM})
			}
			in.InterceptionPrimaryTenant = config.NetworkExtensionLabTLS.OfflinePrimaryTenant()
		}
		if config.AgentPolicySigner != nil {
			in.AgentPolicySigningPubHex = config.AgentPolicySigner.PublicKeyHex()
		}
		// ★ WHOSE CERTIFICATE THIS IS, FROM THE SIGNATURE. The same rule (T) admission runs on: the organization
		// a certificate belongs to is the one whose REGISTERED CA issued it — never one it names. The fallback
		// this replaces scanned the subject for the text "tenant_", which attributed this deployment's own
		// device CA to "tenant_track_a_uc03a_lab" (the name it was minted with, on a track that is gone) while
		// the registry held that exact certificate against tenant_reference_lab all along.
		in.AttributeOwner = func(c *x509.Certificate) string {
			reg := config.TenantCARegistry
			if reg == nil || c == nil {
				return ""
			}
			byAnchor := map[string]string{}
			for _, f := range reg.Facts(time.Time{}) {
				byAnchor[f.SHA256] = f.TenantID
			}
			// It IS a registered CA: the act of registering it is the attribution.
			if t := byAnchor[tenantca.CAAnchorKey(c)]; t != "" {
				return t
			}
			// Or a registered CA signed it. Chain first (an intermediate in between is still that
			// organization's), then the direct signature, which stands when a validity window or a usage
			// constraint stops a chain from building — attribution is not admission, and a lapsed CA still
			// says whose the certificate was.
			pool := x509.NewCertPool()
			for _, a := range reg.Anchors() {
				pool.AddCert(a)
			}
			if chains, err := c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: c.NotBefore.Add(time.Minute),
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
				if t, ok := reg.TenantForVerifiedChains(chains); ok {
					return t
				}
			}
			for _, a := range reg.Anchors() {
				if c.CheckSignatureFrom(a) == nil {
					return byAnchor[tenantca.CAAnchorKey(a)]
				}
			}
			return ""
		}
		// Whose certificate this is, in the name the deployment recorded for that organization. The screen used
		// to take this from the certificate's own O= field; a name inside the material is not an attribution.
		in.TenantName = func(id string) string {
			store := config.TenantModelStore
			if store == nil {
				return ""
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			profile, err := store.Get(ctx, id)
			if err != nil {
				return ""
			}
			return profile.DisplayName
		}
		inv := buildPKICertificateInventory(in)
		if !edgeIsControlPlane {
			live := liveTenantPKICertificateItems(transportTenantCertificates, tenantDeviceIdentity, config.TenantCARegistry, in.Now)
			inv = mergeLiveTenantPKIInventory(inv, nameOwningOrganizations(live, in.TenantName))
		}
		// ★ AND IT SAYS WHICH MACHINE ASSEMBLED IT. See nodeProvenance: the certificate map is built from more
		// than one node, and a screen that labels a row by the address it asked rather than by what answered
		// will call the control plane's certificate the Edge's the day both addresses reach the same node.
		inv.MeasuredOn = nodeProvenance(evaluator, edgeIsControlPlane)
		return inv
	}
	config.TenantIDForTrust = evaluator.PolicyBundle.TenantID
	registerAdminPKICertificates(mux, buildPKIInventoryNow, config.EnrolledLedger, adminEndpoint)
	// ★★ REFUSALS WERE RECORDED PER TENANT AND READ FOR ONE (2026-08-18). The agent report merges under the
	// DEVICE's tenant (steer_agent_policy_routes.go: trustRefusals.Merge(tenantID, ...) where tenantID is
	// steerDeviceTenant). This read was fixed to config.TenantIDForTrust — the NODE's tenant — so every other
	// tenant's refusals went into the store and came out of nowhere: the operator saw only the node's, and a
	// customer saw the node's filtered down to devices they own, which is empty by construction.
	//
	// A trust refusal is how anyone learns that a certificate replacement is breaking devices. A tenant whose
	// entire fleet is refusing the Edge showed a clean screen, which is the failure this product keeps finding
	// in different clothes: the measurement exists, is collected correctly, and is read for the wrong subject.
	registerAdminTrustRefusals(mux, func(tenant string) adminTrustRefusalReport {
		// ★★ ASK THE LISTENER, THEN ASK THE FILE IT WAS CONFIGURED WITH (2026-09-05). servedTransportLeaf
		// reads a package global that only one listener path sets, and where it is unset this answered ""
		// for every deployment — which used to mean "stale" to every reader. The certificate inventory two
		// lines up has no such trouble: it reads config.TransportCertFile directly, and reported the very
		// certificate this could not name. Same file, same answer, one fallback.
		serving := ""
		if leaf, err := servedTransportLeaf(); err == nil {
			serving = certFingerprint(leaf)
		} else if p := strings.TrimSpace(config.TransportCertFile); p != "" {
			if pem, rerr := os.ReadFile(p); rerr == nil {
				if certs := parseAllCerts(pem); len(certs) > 0 {
					serving = certFingerprint(certs[0])
				}
			}
		}
		if strings.TrimSpace(tenant) == "" {
			// Answering for the deployment: every tenant's, which is who can act on a fleet-wide refusal.
			return buildTrustRefusalsFromStore(trustRefusals.All(), serving)
		}
		return buildTrustRefusalsFromStore(trustRefusals.ForTenant(tenant), serving)
	}, config.EnrolledLedger, adminEndpoint)
	// Staged operations: the order an operator must not get wrong, tracked by the system. Stages are computed
	// from live facts (④ of docs/pki_ux_ideal_design.ja.md), never remembered.
	var pkiOperations *pkiOperationStore
	if p := strings.TrimSpace(config.PKIOperationStorePath); p != "" {
		store, oerr := openPKIOperationStore(p)
		if oerr != nil {
			log.Fatalf("pki operation store: %v", oerr)
		}
		pkiOperations = store
	}
	distributedTrust := func() []*x509.Certificate {
		pems, _ := currentTrustAnchors(config)
		return parseAllCerts([]byte(pems))
	}
	pkiOperationViewNow := func() pkiOperationView {
		facts := pkiOperationFacts{Distributed: distributedTrust()}
		if p := strings.TrimSpace(config.TransportCertFile); p != "" {
			if raw, rerr := os.ReadFile(p); rerr == nil {
				facts.PresentedChain = parseAllCerts(raw)
			}
		}
		if served, serr := servedTransportLeaf(); serr == nil {
			report := buildServerCertAdoption(served, servedCertSightings.snapshot(), enabledEnrolledIdentities(config))
			facts.ServedAdoption = &report
		}
		var intent *pkiOperationIntent
		if pkiOperations != nil {
			intent = pkiOperations.Current()
		}
		if intent != nil && config.ObservedExclusions != nil {
			known := enabledEnrolledIdentities(config)
			cov := anchorCoverage(config, evaluator.PolicyBundle.TenantID, intent.TargetSHA256, known)
			facts.TargetCovered = cov.SafeToCut
			if !cov.SafeToCut {
				// One identity can appear in more than one bucket (silent AND never-reported, say); the
				// operator needs the SET of devices to chase, not a tally of the ways each is missing.
				seen := map[string]bool{}
				pending := []string{}
				for _, id := range append(append(append([]string{}, cov.NotReady...), cov.Silent...), cov.NeverReportedAnything...) {
					if id != "" && !seen[id] {
						seen[id] = true
						pending = append(pending, id)
					}
				}
				sort.Strings(pending)
				facts.TargetCoverageNote = "not yet trusted by: " + strings.Join(pending, ", ")
			}
		}
		return buildPKIOperationView(intent, facts)
	}
	registerAdminPKIOperations(mux, pkiOperations, pkiOperationViewNow, distributedTrust, adminEndpoint,
		func(r *http.Request, action, targetID, reason string, metadata map[string]any) {
			recordPKIMaterialChange(config.Writer, r, evaluator, evaluator.PolicyBundle.TenantID, action,
				"pki_operation", targetID, reason, metadata)
		})
	registerAdminPKIPaths(mux, func() pkiPathsReport {
		kcHealthy := false
		if config.NetworkExtensionLabTLS != nil {
			if v, ok := config.NetworkExtensionLabTLS.KeyCustody()["healthy"].(bool); ok {
				kcHealthy = v
			}
		}
		_, upstreamCAStatErr := os.Stat("/etc/ssl/certs/ca-certificates.crt")
		_, liveTrustSerial := currentTrustAnchors(config)
		return buildPKIPaths(pkiPathsInput{
			Now:                 time.Now(),
			Inventory:           buildPKIInventoryNow(),
			MainListen:          config.MainListenAddr,
			AdminListen:         config.AdminListenAddr,
			TransportListen:     config.TransportListenAddr,
			RecoveryListen:      config.EnrollRenewGraceListen,
			RecoveryWindowHours: int(config.EnrollRenewGraceWindow.Hours()),
			DeviceCertCount:     len(deviceCertificates.snapshot()),
			EnrolmentConfigured: config.EnrollSigner != nil,
			TrustBundleSerial:   liveTrustSerial,
			TrustBundleSignedBy: "",
			InterceptionEnabled: config.NetworkExtensionLabTLS != nil,
			KeyCustodyHealthy:   kcHealthy,
			HSMAgentSocket:      config.InterceptionHSMAgentSocket,
			UpstreamCABundle:    upstreamCAStatErr == nil,
			ConfigSourceURL:     config.ConfigSourceURL,
			AuditIngestEnabled:  strings.TrimSpace(config.AuditIngestReceiverToken) != "",
			IdPIssuerURL:        config.IdPIssuerURL,
			IdPIssuers:          registeredIdPIssuers(),
			MeshPeerSpec:        config.MeshPeerSpec,
			HotStoreEndpoint:    config.HotStoreEndpoint,
			ColdArchiveEndpoint: config.ColdArchiveEndpoint,
		})
	}, adminEndpoint)
	registerAdminPKIReadinessEndpoint(mux, func() pkiReadinessReport {
		return assessPKIReadinessNow()
	}, func() pkiReadinessReport {
		// Run the check, then re-assess so the caller gets the whole page rather than one field they have to
		// merge themselves.
		if config.KeyCustodyMonitor != nil {
			config.KeyCustodyMonitor.Check()
		}
		return assessPKIReadinessNow()
	}, config.EnrolledLedger, adminEndpoint)
	// Ask the fleet to renew. POST sets the cutoff to now (or to a given time); DELETE stops asking. What this
	// does NOT do is reach out to devices — it changes what the signed agent policy says, and each device acts
	// on it the next time it asks. A laptop that is switched off renews when it comes back rather than being
	// missed, which is the difference between a declaration and a command.
	registerDeviceCertificateRoutes(mux, adminEndpoint, config, evaluator, writer, deviceStore, edgeRenewBefore)
	registerTransportTrustAnchorsEndpoint(mux, config, evaluator.PolicyBundle.TenantID, adminEndpoint,
		func(r *http.Request, action, targetID, reason string, metadata map[string]any) {
			// ★★ A DEPLOYMENT-LEVEL ACT BELONGS IN THE OPERATOR'S LEDGER, NOT A CUSTOMER'S (2026-08-21, read
			// on a customer's own audit screen). The device-trust anchor set is the DEPLOYMENT's — which CAs
			// this Edge admits devices under — so it was filed under the node's organization. On a deployment
			// where the node's organization is also a customer, that put rows like
			//
			//   pki_material_changed  device_client_ca_retired
			//   subject="Northwind Device Issuing CA (tenant_northwind)"
			//
			// on tenant_reference_lab's audit screen: another organization's authority, named to a customer
			// who has nothing to do with it. The act is real and must be recorded; it belongs to whoever
			// operates the deployment.
			filedUnder := operatorTenantConfigured()
			if filedUnder == "" {
				filedUnder = evaluator.PolicyBundle.TenantID
			}
			recordPKIMaterialChange(config.Writer, r, evaluator, filedUnder, action,
				"transport_trust_certificate", targetID, reason, metadata)
		})
	registerTransportCAReadinessRoute(mux, adminEndpoint, config, evaluator, deviceStore)
	registerSteerExclusionObservedRoutes(mux, adminEndpoint, config, evaluator, deviceStore)
	registerConfigVersionRoutes(mux, adminEndpoint, config, evaluator)
	registerSteerAgentPolicyRoutes(mux, config, evaluator, writer, deviceStore, edgeRenewBefore, policyStore, tenantModelStore)
	registerSteerAgentUpdateRoutes(mux, config)
	registerSteerAgentUpdateArtifactRoute(mux, config)
	registerSteerAgentUpdatePlanRoutes(mux, config, agentUpdatePlanTenant{id: evaluator.PolicyBundle.TenantID})
	registerVLANRoutes(mux, adminEndpoint, vlanBoundary, configSourceURL)
	registerSWGTenantRestrictionRoutes(mux, adminEndpoint, evaluator, writer, policyStore, swgRuntime, config.CPVersions, configSourceURL)
	registerRiskServerInitiatedRoutes(mux, adminEndpoint, config, evaluator, writer, policyStore, deviceStore, configSourceURL)
	registerEastWestRoutes(mux, adminEndpoint, policyStore, eastWestAuthChallenges, config.CPVersions, config.EastWestObserveStore, configSourceURL)
	registerLogsRetentionRoutes(mux, adminEndpoint, adminHotStore, decisionStore, config.ColdArchive, config.LegalHold, config.RetentionOverride)
	registerUsageEventsRoutes(mux, adminEndpoint, adminAuth, usageMeters, adminHotStore, humanIdentities, nonHumanIdentities)
	registerAgentQualityRoutes(mux, adminEndpoint, evaluator, writer, deviceStore, agentTelemetry, agentRolloutPlans, agentTargetVersion, agentReleaseChannel, config.AgentRolloutCache, adminHotStore)
	// The per-device view the Devices list folds in: everything this lane does has otherwise been reachable
	// only by curl.
	registerAgentDeviceUpdateRoutes(mux, adminEndpoint, deviceStore, config.EnrolledLedger, agentTelemetry,
		publishedStoreOrEmpty(config.PublishedAgentUpdateStore), config.PublishedUpdates,
		agentRolloutPlans, config.AgentRolloutCache, config.AgentUpdatePins)
	registerAgentUpdatePublishRoutes(mux, adminEndpoint, publishedStoreOrEmpty(config.PublishedAgentUpdateStore),
		config.AgentUpdatePins, config.PullsAgentUpdates, writer, evaluator, config.AgentUpdateArtifactDir,
		config.PublishedUpdates, config.AgentUpdateSigner, config.AgentUpdateSignFloor)
	registerAgentUpdateArtifactAdminRoutes(mux, adminEndpoint, publishedStoreOrEmpty(config.PublishedAgentUpdateStore),
		config.AgentUpdatePins, config.AgentUpdateArtifactDir, config.PullsAgentUpdates, writer, evaluator,
		config.PublishedUpdates)
	// ★ THE PROGRAM BESIDE THE PROFILE. "Add connector" tells a customer to run dsse-connector-install, and
	// until this lane existed nothing in the product put that program on their machine — the endpoint agent's
	// artifact route cannot serve it, because that one lives inside the tunnel under mandatory mTLS and a
	// connector has no identity until the program it does not have has enrolled it.
	if !config.PullsAgentUpdates {
		// The node that holds the bytes seeds them: an Edge that pulls its configuration holds no copy and
		// would be publishing into a directory nothing serves from.
		seedConnectorProgramFromThisImage(config.ConnectorProgramDir, connectorProgramsBesideThisBinary(),
			runtime.GOOS, runtime.GOARCH)
	}
	registerConnectorProgramRoutes(mux, adminEndpoint, config.ConnectorProgramDir, config.PullsAgentUpdates)
	registerHumanIdentityRoutes(mux, adminEndpoint, evaluator, writer, humanIdentities, adminAuditOutbox, registry, connectorSecret, devMode, requireConnectorRuntimeSecret, configSourceURL, config.DirectoryCPReporter, config.TenantCARegistry)
	registerNHIRegistryRoutes(mux, adminEndpoint, evaluator, writer, adminAuditOutbox, nonHumanIdentities, configSourceURL)
	bundleGeneration := registerPolicyAdminRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, policyStore, configSourceURL, configBundleEpoch, registry, nonHumanIdentities, humanIdentities, delegatedGrants, edgeDNSResolver, vlanBoundary, tenantModelStore, networkExtensionPublisher, ruleStore, assetStore)
	// The fleet view: which Edges have actually acknowledged the current configuration. Registered wherever the
	// bundle is SERVED (a control plane), because that is the only node every Edge already talks to. Reads the
	// same generation function the bundle uses, so "current" cannot mean two things.
	registerFleetConfigStatusRoutes(mux, adminEndpoint, config.FleetConfigStatus, bundleGeneration)
	registerApplicationAdminRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, policyStore, applicationCatalogStore, registry, tunnelManager, routeProfiles, tenantModelStore, domainEventOutbox, configSourceURL)
	registerInterceptionPKIRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox)
	registerPolicyCandidateRoutes(mux, adminEndpoint, evaluator, writer, adminAuditOutbox, policyStore, policyCandidateStore, applicationCatalogStore, registry, config.AssetStore, config.RuleStore, config.ApplyMaterializedCertPinBypass, configSourceURL)
	registerNHIPillarRoutes(mux, adminEndpoint, evaluator, writer, adminAuditOutbox, agentToolStore, toolCallEventAuditStore, delegatedGrants, humanApprovals, configSourceURL)
	// W-7 manual kill-switch for (T) transport admission (also the W-2 re-admission gate's operator surface):
	// revoke an enrolled device identity from the transport NOW (denied at the next mTLS handshake), restore
	// it (re-enrol/re-attest), or list current revocations. Reuses the W-2 revocation.AdmissionRevocations overlay; nil
	// overlay (feature off) => the list is empty and writes are unavailable.
	registerDeviceAdmissionRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, deviceStore, registry, tcaReg, tenantModelStore, configSourceURL, configBundleEpoch)
	registerTenantCARoutes(mux, adminEndpoint, evaluator, writer, adminAuditOutbox, tcaReg, config.TenantCARegistryPath, tenantModelStore, config)
	registerTenantInstallBundleRoute(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox)
	// The operator's access to a customer's organization (the envelope design): the standing delegation, the time-boxed
	// elevations that the irreversible acts need on top of it, and the organization's own view of both.
	registerOperatorAccessRoutes(mux, adminEndpoint, tenantModelStore, configSourceURL, evaluator, writer,
		adminAuditOutbox, operatorTenantID,
		// Name the principal who last moved a delegation — usually the operator, in another organization.
		func(principalID string) string {
			if config.LocalCredentials == nil {
				return ""
			}
			return config.LocalCredentials.EmailForPrincipal(principalID)
		})
	registerAdminBreakGlassRoute(mux, adminEndpoint)
	registerDNSPolicyRoutes(mux, adminEndpoint, edgeDNSResolver, edgeDNSPolicyStore, configSourceURL)
	registerDLPRoutes(mux, adminEndpoint, evaluator, adminHotStore, dlpRuleStore, dlpAllowlistStore, dlpPolicyObjects, dlpFingerprintStore, dlpClassifierStore, entitlementStore, inspectionEvents, configSourceURL)
	registerEndpointInventoryListRoute(mux, adminEndpoint, config, evaluator, deviceStore, endpointInventoryStore)
	// syncEnrolledAssets mirrors the enrolled devices into the catalog as steered endpoints. The authoritative
	// list is the Enrolled Inventory (the identities admitted on the (T) transport — the Mac NE /
	// Windows WFP devices that actually connect); the endpoint inventory (device registration/heartbeat) is
	// used only to ENRICH hostname/OS when present (it may be empty). It runs at startup AND lazily on each
	// list (so a device enrolled after startup appears without a restart). Idempotent: operator-set aliases /
	// group membership are preserved across re-sync.
	syncEnrolledAssets := func() {
		ledger := config.EnrolledLedger
		if ledger == nil {
			return
		}
		tenant := evaluator.PolicyBundle.TenantID
		type devMeta struct{ host, os string }
		byIdentity := map[string]devMeta{}
		if endpointInventoryStore != nil {
			if inv, ierr := endpointInventoryStore.List(context.Background(), tenant, endpointinventory.ListOptions{Limit: 1000}); ierr == nil {
				for _, ep := range inv.Endpoints {
					byIdentity[ep.EndpointID] = devMeta{ep.Hostname, ep.OS}
				}
			}
		}
		devices := make([]assetcatalog.EnrolledDevice, 0)
		for _, e := range ledger.List() {
			if !e.Enabled {
				continue
			}
			name, platform := e.Identity, ""
			if m, ok := byIdentity[e.Identity]; ok {
				if strings.TrimSpace(m.host) != "" {
					name = m.host
				}
				platform = normalizeAssetPlatform(m.os)
			}
			if platform == "" {
				platform = normalizeAssetPlatform(e.Identity) // best-effort when the device has not reported its OS
			}
			devices = append(devices, assetcatalog.EnrolledDevice{Identity: e.Identity, Name: name, Platform: platform})
		}
		assetStore.SyncEnrolledEndpoints(tenant, devices, time.Now().UTC())
	}
	syncEnrolledAssets()
	registerAssetCatalogAdmin(mux, adminEndpoint, assetStore, syncEnrolledAssets, configSourceURL)

	// Per-tenant end-user IdP registry (federated-auth connections + default), managed from the Console.
	// Durable when -idp-connection-store is set so registered IdPs survive a restart.
	idpConnectionStore := idpregistry.NewStore()
	// The paths view is registered earlier in this function and asks at request time which sign-in endpoints
	// the deployment actually dials. Reading the registry rather than the -oidc-issuer flag is what makes the
	// row appear on a deployment like the reference lab, which registers its IdP from the Console.
	registeredIdPIssuersFn = func() []string {
		seen := map[string]bool{}
		out := []string{}
		for _, c := range idpConnectionStore.List(strings.TrimSpace(config.TenantIDForTrust)) {
			u := strings.TrimSpace(c.Issuer)
			if u == "" || seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, u)
		}
		sort.Strings(out)
		return out
	}
	// Publish it for the enrolment eligibility checker, which is wired BEFORE this point (its registration
	// happens earlier in this function) and resolves the connection per request.
	theIdPRegistry.Store(idpConnectionStore)
	if p, e := cpStateBlobPersister(config.IdPConnectionStorePath, cpStateBlobDB, "idp_connections"); e != nil {
		log.Fatalf("resolve idp connection store: %v", e)
	} else if err := idpConnectionStore.SetPersister(p); err != nil {
		log.Fatalf("load idp connection store: %v", err)
	}
	registerIdPConnectionsAdmin(mux, adminEndpoint, idpConnectionStore, config.ConfigSourceURL, func(r *http.Request, tenant, id, action string) {
		now := time.Now().UTC()
		audit := adminIdPChangeAuditLog(r, tenant, id, action, evaluator, now)
		_ = appendAdminAudit(r.Context(), writer, config.AdminAuditOutbox, audit, now)
	})

	// Organization Domains (S6): the explicit, multi-value "these domains are US" setting DLP instance-aware action
	// references. Durable; the corporate-domain resolver is Organization Domains ∪ IdP verified_domains.
	organizationDomains := newOrganizationDomainsStore()
	if storeShouldBeWired(config.OrganizationDomainsStorePath) {
		if p, e := cpStateBlobPersister(config.OrganizationDomainsStorePath, cpStateBlobDB, "organization_domains"); e != nil {
			log.Fatalf("resolve organization domains store %q: %v", config.OrganizationDomainsStorePath, e)
		} else if p != nil {
			if lerr := organizationDomains.SetPersister(p); lerr != nil {
				log.Printf("organization domains store: load failed (starting fresh): %v", lerr)
			}
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := organizationDomains.PersistIfDirty(); err != nil {
						log.Printf("organization domains store: persist failed: %v", err)
					}
				}
			}()
		}
	}
	registerOrganizationDomainRoutes(mux, adminEndpoint, organizationDomains)
	// The completion definition of "create an organization", answered in one call (the provisioning design
	// design). Registered here because this is where the last of its sources — the IdP registry and the
	// organization domains — come into scope.
	registerOrganizationSetupRoute(mux, adminEndpoint, config, evaluator, tenantModelStore,
		idpConnectionStore, organizationDomains, config.SeatAllocations, entitlementStore, policyStore)
	// Clientless federated-auth broker (, opt-in): the end-user OIDC RP front door at
	// /clientless/auth/* — redirect to the tenant's IdP, validate the ID token, mint a revocable grant. The
	// same grant store also backs the steered-path federated-auth gate (set on the decrypt egress handler
	// below), so an "authenticate" decision on a steered browser flow redirects to the IdP instead of 401.
	var federatedAuthGateForEgress *federatedAuthGate
	// Hoisted out of the branch so the tenant footprint and the erasure can reach it: a store nobody outside
	// this `if` can name is a store no erasure can empty.
	var clientlessGrants *grantstore.Store
	// ★★ AN EDGE IS AN EDGE (2026-08-21). The grant store and its ADMIN routes used to live inside the
	// clientless-broker gate below, so an Edge without -clientless-base-url did not register them at all.
	// Measured as one customer administrator reading the same screen from two Edges seconds apart:
	// GET /admin/grants answered 200 on region-a and 404 on region-b. Which Edge a load balancer picked
	// decided whether the screen existed.
	//
	// Being a broker is genuinely URL-dependent — a node with no base URL cannot mint a browser grant, and that
	// stays behind the gate. Listing and REVOKING grants is not: a revocation is a security act that must be
	// available wherever an administrator lands, and the store is shared, so every node answers the same.
	grantStore := grantstore.NewStore()
	clientlessGrants = grantStore
	if p, e := cpStateBlobPersister(config.GrantStorePath, cpStateBlobDB, "grants"); e != nil {
		log.Fatalf("resolve grant store: %v", e)
	} else if err := grantStore.SetPersister(p); err != nil {
		log.Fatalf("load grant store: %v", err)
	}
	theGrantStore.Store(grantStore)
	registerGrantsAdmin(mux, adminEndpoint, grantStore, evaluator.PolicyBundle.TenantID)
	// ★ AND THE AUTHORITY RECEIVES WHAT THE FLEET MINTED. Registered only on a node that does not pull its
	// own configuration — the same rule the connector report states. See grant_cp_report.go.
	registerGrantReportRoute(mux, grantStore, tcaReg, strings.TrimSpace(config.ConfigSourceURL),
		config.LabMode != nil && *config.LabMode)
	if strings.TrimSpace(config.ClientlessBaseURL) != "" {
		// One signer shared by the gate (signs the verified (T) device into the step-up start URL) and the broker
		// (verifies it before binding a grant) — this is what makes a browser-minted grant per-device even though
		// the broker hop is not steered.
		// ★★★ THE FLEET SHARES THE KEY, OR THE BINDING SILENTLY IS NOT ONE (2026-09-02). See
		// deviceBindingSigner: the step-up URL names the deployment's agent plane, the door hands that
		// connection to whichever Edge it likes, and a per-process key means the Edge that receives the URL
		// cannot verify what the Edge that issued it signed — which reads as "no device identity" and mints
		// a tenant-wide grant instead of a device-bound one.
		deviceSigner := newDeviceBindingSignerFromSecret(config.StepUpBindingSecret)
		if deviceSigner == nil {
			var err error
			if deviceSigner, err = newDeviceBindingSigner(); err != nil {
				log.Fatalf("init device-binding signer: %v", err)
			}
			log.Printf("step-up device binding: no -step-up-binding-secret, so this node signs with a key of " +
				"its own. A step-up that starts here and lands on another Edge will lose its device binding " +
				"(the grant becomes organization-wide). Set the deployment's shared secret on every Edge.")
		}
		configureStepUpPortalCertificate(config.ClientlessBaseURL, config.ClientlessTLSCert, config.ClientlessTLSKey)
		broker := newClientlessBroker(idpConnectionStore, grantStore, &http.Client{Timeout: 10 * time.Second}, config.ClientlessBaseURL, evaluator.PolicyBundle.TenantID, 8*time.Hour, deviceSigner)
		broker.register(mux)
		federatedAuthGateForEgress = &federatedAuthGate{grants: grantStore, brokerBaseURL: config.ClientlessBaseURL, tenantID: evaluator.PolicyBundle.TenantID, signer: deviceSigner}
	}

	// Unified rule authoring (source → destination : service ⇒ action) across the east-west and egress
	// planes. Inbound east-west rules are validated against receiver platforms from the asset catalog
	// (inbound enforces on Windows only). On any rule change we recompile enforcement from scratch:
	//  - egress inspection=bypass → the decrypt-bypass set (config.ApplyMaterializedCertPinBypass folds it in);
	//  - outbound east-west rules → compiled EastWestRules pushed to the policy store as a SEPARATE set
	//    unioned with the legacy /admin/east-west rules (they apply when east-west enforcement is enabled).
	// recompileAuthoredRules rebuilds the compiled east-west + egress rule sets from the (durable) rule store.
	// It runs on every rule change AND once at startup below: the rule store persists across an Edge restart, but
	// the COMPILED sets are in-memory — without the startup seed, per-hop east-west authz (and authored egress
	// policy) would silently NOT enforce after a restart until the next rule edit recompiled them. That is a
	// North-Star-critical gap (lateral per-hop authz off after a reboot), so seed it eagerly.
	// ★★★ THIS COMPILED ONE ORGANIZATION'S RULES AND CALLED IT DONE (2026-08-17, found by authoring a rule for
	// a newly created organization through the Console). The tenant was taken from this node's policy bundle,
	// so a rule authored for ANY OTHER organization was stored, listed, shown as "active · enforce" — and never
	// compiled into a policy, so nothing decided by it. Measured: the rule existed on both planes under the new
	// organization, and the decision preview for the destination it denied returned the default with an empty
	// trace. The organization's own setup checklist agreed with enforcement and disagreed with the screen that
	// had just accepted the rule.
	//
	// Every organization holding authored rules is recompiled, and the node's own is always included so that
	// deleting an organization's last rule still clears its compiled set.
	recompileOneTenant := func(tenant string) {
		// Re-apply BOTH inspection layers: an authored bypass rule feeds the decrypt-bypass set and an authored
		// inspect rule feeds the intercept (decrypt) set under bypass-default. ApplyInspectionPosture folds in the
		// bypass set too, so prefer it; fall back to the bypass-only hook if no interception engine is wired.
		if config.ApplyInspectionPosture != nil {
			config.ApplyInspectionPosture(tenant)
		} else if config.ApplyMaterializedCertPinBypass != nil {
			config.ApplyMaterializedCertPinBypass(tenant)
		}
		if s, ok := policyStore.(interface {
			SetCompiledEastWestRules(string, []decision.EastWestRule)
		}); ok {
			ewCompiled := policyrule.CompileEastWest(tenant, ruleStore.List(tenant, policyrule.PlaneEastWest), assetStore)
			logDebugf("recompileAuthoredRules: tenant=%s east_west authored_rules=%d compiled=%d", tenant, len(ruleStore.List(tenant, policyrule.PlaneEastWest)), len(ewCompiled))
			s.SetCompiledEastWestRules(tenant, ewCompiled)
		} else {
			logDebugf("recompileAuthoredRules: policyStore does NOT implement SetCompiledEastWestRules (compiled east-west NOT applied)")
		}
		if s, ok := policyStore.(interface {
			SetCompiledPolicies(string, []model.Policy)
		}); ok {
			s.SetCompiledPolicies(tenant, policyrule.CompileEgressPolicies(tenant, ruleStore.List(tenant, policyrule.PlaneEgress), assetStore))
		}
	}
	recompileAuthoredRules := func() {
		// ★★ EVERY ORGANIZATION WITH SOMETHING TO CLEAR, NOT ONLY ONES WITH SOMETHING TO BUILD (2026-08-17,
		// measured). This walked the organizations that HAVE authored rules. Deleting an organization's LAST
		// rule removes it from that list, so its compiled set was never rebuilt to empty — and went on
		// enforcing. Measured end to end: a customer deleted a deny rule, the rules screen showed none, the
		// control plane had dropped the policy, and this Edge answered DENY for that destination across two
		// further config pulls and would have forever.
		compiledOwners := []string{}
		if s, ok := policyStore.(interface{ CompiledRuleTenants() []string }); ok {
			compiledOwners = s.CompiledRuleTenants()
		}
		seen := map[string]bool{}
		for _, tenant := range append(append([]string{evaluator.PolicyBundle.TenantID}, ruleStore.Tenants()...), compiledOwners...) {
			if seen[tenant] {
				continue
			}
			seen[tenant] = true
			recompileOneTenant(tenant)
		}
	}
	registerRulesAdmin(mux, adminEndpoint, ruleStore, assetStore, recompileAuthoredRules, func(tenant, ruleID string) {
		// Reverse lifecycle sync: deleting a cert-pin bypass rule un-materializes the pinned-site candidate it
		// came from, so the Pinned Sites view reflects that the bypass is gone (it does not linger "materialized").
		// The bypass itself already stopped — the rule is its single source.
		if !strings.HasPrefix(ruleID, "certpin-rule-") {
			return
		}
		if cps, ok := policyCandidateStore.(*policycandidate.Store); ok {
			candidateID := strings.TrimPrefix(ruleID, "certpin-rule-")
			if _, _, err := cps.Review(context.Background(), tenant, candidateID, policycandidate.ReviewRequest{Decision: "suppressed", ReviewReasonCode: "bypass_rule_deleted"}, time.Now()); err != nil {
				log.Printf("reverse-sync cert-pin candidate %s on rule delete: %v", candidateID, err)
			}
		}
	}, configSourceURL)
	// Seed the compiled rule sets from the durable rule store at startup (see recompileAuthoredRules): without
	// this, east-west per-hop authz + authored egress policy do not enforce after a restart until the next edit.
	recompileAuthoredRules()
	// NOW the CP pull loop may run: the stores it writes into have a live recompile behind them, so an authored
	// rule arriving from the control plane reaches the engine and not just the store.
	if startConfigBundleSync != nil {
		startConfigBundleSync(recompileAuthoredRules)
	}

	// S2 (Candidate + adopt) of the East-West policy-learning lifecycle: turn observed lateral flows into
	// authored East-West rules. The operator reviews the Observe inventory (S1) and selects the UNCOVERED flows;
	// this endpoint materializes each into a plane=east_west rule with who=Any (source=["*"], a destination
	// allow-list, narrowed manually later) and access=allow — the safe first state, NOT deny. It is idempotent:
	// a flow already covered by an effective rule is SKIPPED (no duplicate), so re-adopting the same selection is
	// a no-op. This is the bridge that lets the uncovered-flow count fall to 0, the readiness signal for disabling
	// Allow-all (S5). It reuses the exact same ruleStore.Upsert + recompile as POST /admin/rules, so an adopted
	// rule is indistinguishable from a hand-authored one and is editable/deletable in the normal Rules UI.
	registerEffectivePolicyRoutes(mux, adminEndpoint, config, evaluator, writer, policyStore, deviceStore, assetStore, ruleStore, policyCandidateStore, recompileAuthoredRules)
	registerPredefinedCatalogRoutes(mux, adminEndpoint, config, evaluator, writer)
	// The one file every endpoint needs, issued by the deployment that already holds the key to sign it.
	// See admin_agent_profile_routes.go.
	// ★★★ THE ORGANIZATION'S OWN REGIONS, not the deployment's (2026-08-29). allowedRegionEndpoints emits only
	// the regions an organization may occupy and puts its home region first — and both profile routes asked
	// for it with (nil, ""), so residency was declared on the tenant row, shown on the screen, and ignored by
	// the artefact its devices and connectors actually take. See agentProfileEndpoints.
	tenantRegions := func(tenantID string) []regionEndpoint {
		// Read live rather than captured: a region added after this node started must appear in the next
		// profile without restarting it.
		catalog := regionMap.Catalog()
		id := strings.TrimSpace(tenantID)
		if id == "" || tenantModelStore == nil {
			return catalog.allowedRegionEndpoints(nil, "")
		}
		tenant, ok := organizationSetupTenant(context.Background(), tenantModelStore, id)
		if !ok {
			// An organization this node has no row for is not a reason to hand out a boundary-free list; it is
			// a reason to hand out the deployment's, which is what it did for everyone until today.
			return catalog.allowedRegionEndpoints(nil, "")
		}
		return catalog.allowedRegionEndpoints(tenant.AllowedRegions, tenant.HomeRegion)
	}
	registerAgentProfileRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox,
		strings.TrimSpace(config.ConnectorEnrollmentEdgeURL), tenantRegions)
	// ★ AND A CONNECTOR IS GIVEN THE SAME MAP. Read live, from the same catalogue, for the same reason — see
	// a_connector_is_given_every_door.go.
	connectorEnrollmentRegions = tenantRegions
	registerEndpointInventoryDetailRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, deviceStore, endpointInventoryStore)
	registerTenantAdminRoutes(mux, adminEndpoint, config, evaluator, writer, tenantModelStore, operatorTenantID, adminAuditOutbox, adminAuth, ruleStore, vlanBoundary,
		adminTenantExtraStores{
			TenantRestrictions: managedTenantRestrictionStoreOrNil(policyStore),
			DelegatedGrants:    config.DelegatedGrants,
			HumanApprovals:     config.HumanApprovals,
			ClientlessGrants:   clientlessGrants,
			IdPConnections:     idpConnectionStore,
			HighRisk:           config.HighRiskOverlay,
			Admissions:         config.AdmissionRevocations,
			CatalogOverrides:   config.CatalogOverrides,
			// ★ PASSED, NOT JUST DECLARED. A field on the struct that no call site fills counts nothing, and
			// an erasure over an uncounted store answers complete=true whatever it holds.
			ConnectorRoutes:  connectorRouteGov,
			SeatAllocations:  config.SeatAllocations,
			PolicyCandidates: policyCandidateStoreOrNil(config.PolicyCandidateStore),
			EnrolmentTokens:  enrolmentTokenStoreOrNil(config.EnrolmentTokens),
			// The organization's own transport authority: counted with them, and erased with them.
			TenantTransportAuthorities:    config.TenantTransportAuthority,
			TenantTrustDistributions:      config.TenantTrustDistributor,
			TenantInterceptionAuthorities: config.TenantInterceptionAuthority,
			// What this organization was told to run, and anything published to it alone — counted with them
			// and erased with them. See adminTenantExtraStores.
			AgentRolloutPlans:     config.AgentRolloutPlans,
			PublishedAgentUpdates: config.PublishedAgentUpdateStore,
		}, configSourceURL)
	// ★★★ NOT HOLDING A TUNNEL IS NOT KNOWING THERE IS NONE (2026-09-01, found on the Console: a site with two
	// live connectors read "Down — 0 of 2 connectors online", every connector Offline with a LAST HEARTBEAT
	// frozen at its registration time, while both were serving flows).
	//
	// This asked the local tunnel manager and returned its answer as a FACT either way. A control plane
	// terminates no connector tunnel at all, so it answered false for every connector in the deployment — and
	// adminConnectorOnline takes a non-nil tunnel_connected as authoritative and never looks at the heartbeat.
	// The Console reads the control plane. So every connector was permanently offline on the only screen an
	// operator has, no matter what it was doing.
	//
	// It is wrong on an Edge too, for the same sentence: a connector held by a SIBLING node is not held here,
	// and this node cannot tell that from nobody holding it.
	//
	// The rule was already written down one file over — "a nil resolver leaves TunnelConnected nil = unknown,
	// never asserting a false 'disconnected'". This is that rule applied to the answer as well as to the
	// resolver: yes when this node holds it, and UNKNOWN when it does not, so the reader falls through to the
	// heartbeat, which is the fleet-wide fact rather than this node's view of it.
	connectorTunnelStatus := func(connectorID string) *bool {
		if tunnelManager == nil {
			return nil
		}
		if _, ok := tunnelManager.Get(connectorID); ok {
			connected := true
			return &connected
		}
		return nil
	}
	if connectorRouteGov == nil {
		// ★★★ WHERE THESE DECISIONS LIVE (2026-08-25, measured: a route added to a Site survived being read
		// back and did not survive a restart). cpStateBlobPersister already resolves an unset store to the
		// deployment's shared database when there is one, which is exactly right here — a route is the
		// authority's answer about what a connector fronts, and every control plane has to give the same one.
		var routeGovPersister blobstore.Persister
		if p, e := cpStateBlobPersister(connectorRouteGovPersistPath, cpStateBlobDB, "connector_route_governance"); e != nil {
			log.Fatalf("connector route governance store: %v", e)
		} else {
			routeGovPersister = p
		}
		connectorRouteGov = newConnectorRouteGovernanceWithPersister(connectorRouteGovPersistPath,
			connectorRouteCPConfigured, routeGovPersister)
	}
	// Resolve a connector binding that REFERENCES a Named Network (a VLANObject) to its CIDRs, so a subnet defined
	// ONCE in the vlan-objects surface is reused for connector routing without re-typing (unified network object,
	// docs/unified_network_object_design.md). Tenant-scoped; unknown/foreign network resolves to nothing (safe).
	connectorRouteGov.SetNetworkResolver(func(t, networkID string) (string, []string) {
		o, ok := vlanBoundary.GetObject(networkID)
		if !ok || (strings.TrimSpace(o.TenantID) != "" && o.TenantID != t) {
			return "", nil
		}
		return o.Name, o.CIDRs
	})
	// Admin route governance: read the effective routes (self-declared + held state + admin-authored) and
	// hold/unhold/add/remove them. Only the routable set enters the route layer (connectorForDestination).
	connectorDeclaredRoutes := func(ctx context.Context, tenant, connectorID string) (cidrs, fqdns []string, found bool) {
		conns, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenant)
		if err != nil {
			return nil, nil, false
		}
		for _, c := range conns {
			if c.ID == connectorID {
				return c.ReachableRoutes.CIDRs, c.ReachableRoutes.FQDNDomains, true
			}
		}
		return nil, nil, false
	}
	registerConnectorSiteAdminRoutes(mux, adminEndpoint, config, evaluator, writer, registry, tunnelManager, siteStore, vlanBoundary, domainEventOutbox, adminAuditOutbox, applicationCatalogStore, tenantModelStore, configSourceURL, connectorTunnelStatus, connectorDeclaredRoutes)

	// Establish the east-west plane boundary before serving traffic. Without this the first flows after a
	// restart would be classified against an EMPTY declaration — every declared-internal destination on a
	// public address briefly reading as internet access — until a connector happened to re-register.
	refreshEastWestInternalNetworks(context.Background(), policyStore, registry, evaluator.PolicyBundle.TenantID)
	if rt, ok := policyStore.(interface {
		RuntimeEvaluator(string) decision.Evaluator
	}); ok {
		logDeclaredInternalNetworksAtBoot(rt.RuntimeEvaluator(evaluator.PolicyBundle.TenantID).EastWestInternalNetworks, evaluator.PolicyBundle.TenantID)
	}
	registerOutboxAdminRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, domainEventOutbox, domainEventMirror, hotStoreMirror, exportObjectStore)
	registerExportJobRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, adminExportJobs, adminExportWorker, adminDownloadTokens, exportObjectStore, adminHotStore)
	registerAPITokenRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, adminAuth)
	registerAdminAccountRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, adminAuth, operatorTenantID)
	registerAdminSessionRoutes(mux, adminEndpoint, config, evaluator, writer, adminAuditOutbox, adminAuth, adminDownloadTokens, exportObjectStore, tenantModelStore, devMode)
	mux.HandleFunc("GET /auth/oidc/login", func(w http.ResponseWriter, r *http.Request) {
		loginURL, cookies, err := buildOIDCLoginURL(oidc)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		for _, cookie := range cookies {
			http.SetCookie(w, cookie)
		}
		if returnTo, ok := sanitizeOIDCReturnTo(r.URL.Query().Get("return_to")); ok {
			http.SetCookie(w, oidcReturnToCookie(returnTo))
		}
		// East-west OOB ceremony (E4): carry the held flow's challenge id through the OIDC round-trip.
		if challengeID := strings.TrimSpace(r.URL.Query().Get("challenge_id")); challengeID != "" {
			http.SetCookie(w, eastWestChallengeCookie(challengeID))
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
	})
	mux.HandleFunc("GET /auth/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		event, session, err := sessionFromOIDCCallback(r, proxyClient, oidc, sessionStore, evaluator.PolicyBundle.ID, evaluator.PolicyBundle.TenantID, time.Now())
		if err != nil {
			if writeErr := writer.Append("audit.log.jsonl", authenticationEventFailureAuditLog(err, r, evaluator)); writeErr != nil {
				log.Printf("write OIDC failure audit log: %v", writeErr)
			}
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		appendAuthenticationDomainEvent(r.Context(), domainEventOutbox, event, time.Now())
		if err := writer.Append("audit.log.jsonl", authenticationEventAuditLog(event, session, evaluator)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		http.SetCookie(w, sessionCookie(session))
		// East-west OOB ceremony (E4): if this login resolved a held flow's challenge, issue the grant now
		// (bound to the identity just proven) so the held flow is released. The user then retries.
		if challengeID, ok := eastWestChallengeFromRequest(r); ok {
			http.SetCookie(w, expiredEastWestChallengeCookie())
			if grant, gerr := eastwest.CompleteCeremony(policyStore, eastWestAuthChallenges, challengeID, session.UserID, time.Now()); gerr != nil {
				log.Printf("east_west_ceremony grant_not_issued reason=%s", gerr.Error())
			} else {
				log.Printf("east_west_ceremony_completed protocol=%s", grant.Protocol)
				writeEastWestCeremonySuccess(w)
				return
			}
		}
		if returnTo, ok := oidcReturnToFromRequest(r); ok {
			http.SetCookie(w, expiredOIDCReturnToCookie())
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
		writeJSON(w, http.StatusCreated, session)
	})
	// clientless front door (agentless): a browser reaches a published app with NO endpoint agent.
	// Identity is the VERIFIED IdP session (never client-claimed); an unauthenticated browser is redirected
	// to the IdP login and returned here (mirrors the east-west OOB ceremony). On allow the reduced-trust
	// authorization is granted and the flow is handed to the existing connector publish data path.
	// The live byte-streaming reverse-proxy + real-browser E2E is separate real-environment work.
	mux.HandleFunc("GET /clientless/apps/{application_id}", func(w http.ResponseWriter, r *http.Request) {
		// is OFF by default: the clientless web front door is a PUBLIC pre-auth surface (browser login,
		// OIDC callback, connector reverse-proxy) that materially widens the attack surface beyond the
		// mTLS-gated agent path. It is only present when a deployment explicitly opts in (-clientless-access).
		if !config.ClientlessAccessEnabled {
			http.NotFound(w, r)
			return
		}
		appID := strings.TrimSpace(r.PathValue("application_id"))
		session, authenticated := activeSessionFromRequest(r, sessionStore)
		if !authenticated {
			loginURL, cookies, err := buildOIDCLoginURL(oidc)
			if err != nil {
				writeError(w, http.StatusUnauthorized, fmt.Errorf("clientless access requires an authenticated session"))
				return
			}
			for _, cookie := range cookies {
				http.SetCookie(w, cookie)
			}
			http.SetCookie(w, oidcReturnToCookie(r.URL.RequestURI()))
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		tenantID := session.TenantID
		published := []clientlessPublishedApp{}
		if applicationCatalogStore != nil && appID != "" {
			if entry, found, err := applicationCatalogStore.Get(r.Context(), tenantID, appID); err == nil && found {
				if app, ok := clientlessPublishedAppFromCatalogEntry(entry); ok {
					published = append(published, app)
				}
			}
		}
		outcome := decideClientlessAccess(clientlessAccessRequest{
			TenantID:         tenantID,
			UserID:           session.UserID,
			IdPAuthenticated: true,
			UserGroups:       stringSliceMetadata(session.Metadata, "groups"),
			ApplicationID:    appID,
		}, published)
		if !outcome.Allow {
			writeJSON(w, http.StatusForbidden, map[string]any{"schema_version": "clientless_access.v1", "application_id": appID, "decision": outcome})
			return
		}
		// live relay: the clientless pre-authorization passed (verified IdP session + published +
		// reduced-trust + group). Hand the flow to the EXISTING connector publish data path, which resolves
		// the connector serving this published app, runs the authoritative policy decision, and reverse-
		// proxies the request through the outbound-only connector tunnel to the backend — the browser reaches
		// the app with no endpoint agent and no inbound hole. Returns 404 if no connector is registered for
		// the app (the live connector + real backend is the deployment dependency, not new Edge code).
		log.Printf("clientless_front_door_granted tenant=%q app=%q user=%q -> connector relay", tenantID, appID, session.UserID)
		handleConnectorApplication(w, r, connAppDeps)
	})
	mux.HandleFunc("POST /auth/events", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		var event model.AuthenticationEvent
		if err := decodeLimitedJSONBody(w, r, &event, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode authentication event: %w", err))
			return
		}
		session, err := sessionStore.CreateFromAuthenticationEvent(event, evaluator.PolicyBundle.ID, evaluator.PolicyBundle.TenantID, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		appendAuthenticationDomainEvent(r.Context(), domainEventOutbox, event, time.Now())
		if err := writer.Append("audit.log.jsonl", authenticationEventAuditLog(event, session, evaluator)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, session)
	})
	mux.HandleFunc("POST /break-glass/requests", adminEndpoint("admin.break_glass.write", func(w http.ResponseWriter, r *http.Request) {
		var req breakGlassSessionRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode break-glass request: %w", err))
			return
		}
		// The organization is the CALLER's, not this node's: taking it from the node let a customer of one
		// organization file, approve and cash a break-glass request in another.
		item, err := breakGlassRequests.Create(req, breakGlassCallerTenant(r, evaluator.PolicyBundle.TenantID), time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		appendBreakGlassDomainEvent(r.Context(), domainEventOutbox, item, "break_glass_requested", item.CreatedAt, time.Now())
		if err := writer.Append("audit.log.jsonl", breakGlassLifecycleAuditLog("break_glass_requested", item, evaluator, sourceIPFromRequest(r), "", "")); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, item)
	}))
	mux.HandleFunc("POST /break-glass/requests/{request_id}/approve", adminEndpoint("admin.break_glass.write", func(w http.ResponseWriter, r *http.Request) {
		var req breakGlassApprovalRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode break-glass approval: %w", err))
			return
		}
		if existing, ok := breakGlassRequests.Get(r.PathValue("request_id")); ok &&
			!breakGlassRequestVisibleTo(existing, r, evaluator.PolicyBundle.TenantID) {
			// Absent rather than forbidden: a 403 would confirm the id exists in another organization.
			writeError(w, http.StatusNotFound, fmt.Errorf("break-glass request %s is absent", r.PathValue("request_id")))
			return
		}
		item, err := breakGlassRequests.Approve(r.PathValue("request_id"), req, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		appendBreakGlassDomainEvent(r.Context(), domainEventOutbox, item, "break_glass_approved", item.ApprovedAt, time.Now())
		if err := writer.Append("audit.log.jsonl", breakGlassLifecycleAuditLog("break_glass_approved", item, evaluator, sourceIPFromRequest(r), "", "")); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}))
	mux.HandleFunc("POST /break-glass/requests/{request_id}/issue-session", adminEndpoint("admin.break_glass.write", func(w http.ResponseWriter, r *http.Request) {
		item, ok := breakGlassRequests.Get(r.PathValue("request_id"))
		if !ok || !breakGlassRequestVisibleTo(item, r, evaluator.PolicyBundle.TenantID) {
			writeError(w, http.StatusNotFound, fmt.Errorf("break-glass request %s is absent", r.PathValue("request_id")))
			return
		}
		if item.Status != "approved" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("break-glass request %s status is %s", item.ID, item.Status))
			return
		}
		callerTenant := breakGlassCallerTenant(r, evaluator.PolicyBundle.TenantID)
		event, err := breakGlassAuthenticationEvent(item.SessionRequest(), callerTenant, r, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		event.Metadata["break_glass_request_id"] = item.ID
		session, err := sessionStore.CreateFromAuthenticationEvent(event, evaluator.PolicyBundle.ID, callerTenant, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		issued, err := breakGlassRequests.MarkSessionIssued(item.ID, session.ID, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		appendAuthenticationDomainEvent(r.Context(), domainEventOutbox, event, time.Now())
		if err := writer.Append("audit.log.jsonl", authenticationEventAuditLog(event, session, evaluator)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		appendBreakGlassDomainEvent(r.Context(), domainEventOutbox, issued, "break_glass_session_issued", issued.IssuedAt, time.Now())
		if err := writer.Append("audit.log.jsonl", breakGlassLifecycleAuditLog("break_glass_session_issued", issued, evaluator, sourceIPFromRequest(r), session.ID, event.ID)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		http.SetCookie(w, sessionCookie(session))
		writeJSON(w, http.StatusCreated, session)
	}))
	mux.HandleFunc("POST /break-glass/sessions", adminEndpoint("admin.break_glass.write", func(w http.ResponseWriter, r *http.Request) {
		var req breakGlassSessionRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode break-glass session request: %w", err))
			return
		}
		// ★ Measured before this line existed: an API token belonging to tenant_operator_001 received a 201 and
		// an ACTIVE session in tenant_reference_lab, for a user_id it supplied itself.
		callerTenant := breakGlassCallerTenant(r, evaluator.PolicyBundle.TenantID)
		event, err := breakGlassAuthenticationEvent(req, callerTenant, r, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		session, err := sessionStore.CreateFromAuthenticationEvent(event, evaluator.PolicyBundle.ID, callerTenant, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		appendAuthenticationDomainEvent(r.Context(), domainEventOutbox, event, time.Now())
		if err := writer.Append("audit.log.jsonl", authenticationEventAuditLog(event, session, evaluator)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		http.SetCookie(w, sessionCookie(session))
		writeJSON(w, http.StatusCreated, session)
	}))
	mux.HandleFunc("GET /break-glass/events/export", adminEndpoint("admin.break_glass.read", func(w http.ResponseWriter, r *http.Request) {
		events, err := breakGlassExportEvents(writer)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		events = breakGlassEventsForCaller(events, r, evaluator.PolicyBundle.TenantID)
		if err := writer.Append("audit.log.jsonl", breakGlassExportAuditLog(r, evaluator, len(events))); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSONL(w, http.StatusOK, events)
	}))
	mux.HandleFunc("GET /auth/mock/callback", func(w http.ResponseWriter, r *http.Request) {
		if !devMode {
			writeError(w, http.StatusNotFound, fmt.Errorf("mock authentication callback is disabled"))
			return
		}
		event := mockAuthenticationEventFromCallback(r)
		session, err := sessionStore.CreateFromAuthenticationEvent(event, evaluator.PolicyBundle.ID, evaluator.PolicyBundle.TenantID, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		appendAuthenticationDomainEvent(r.Context(), domainEventOutbox, event, time.Now())
		if err := writer.Append("audit.log.jsonl", authenticationEventAuditLog(event, session, evaluator)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		http.SetCookie(w, sessionCookie(session))
		writeJSON(w, http.StatusCreated, session)
	})
	mux.HandleFunc("GET /sessions/{session_id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		session, ok := sessionStore.Get(r.PathValue("session_id"))
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("session %s is not found", r.PathValue("session_id")))
			return
		}
		writeJSON(w, http.StatusOK, session)
	})
	mux.HandleFunc("POST /devices/register", func(w http.ResponseWriter, r *http.Request) {
		// Device lifecycle endpoint the WFP/NE agent calls over the (T) transport mTLS (steer_heartbeat.go):
		// a verified, enrolled device identity is NOT a connector, so it is exempt from the connector gate (the
		// same device-vs-connector split as CONNECT /steer; -lab-mode used to skip the gate entirely). A
		// non-transport caller on :8443 (no verified device cert) still passes connector authorization.
		if _, transportDeviceAuthenticated := transportDeviceIdentityFromRequest(r); !transportDeviceAuthenticated {
			if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
				return
			}
		}
		var req model.Device
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode device registration: %w", err))
			return
		}
		if certID, verified := transportDeviceIdentityFromRequest(r); verified {
			if !authorizeDeviceSelfReport(w, r, req.ID, connectorSecret, devMode, registry,
				evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret) {
				return
			}
			req.ID = enrolledinventory.NormalizeIdentity(certID)
			boundTenant, err := authoritativeTenantForRequest(r, req.TenantID, tcaReg)
			if err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			req.TenantID = boundTenant
		}
		// The organization is the DEVICE'S, taken from the enrolled inventory by the identity this transport
		// proved — not this node's. See the_organization_is_the_devices_not_the_pullers.go.
		registeringDevice, _ := transportDeviceIdentityFromRequest(r)
		dev, err := deviceStore.Register(req,
			bundleForTheDevicesOrganization(config.EnrolledLedger, evaluator.PolicyBundle, registeringDevice, req.ID),
			time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		appendDeviceDomainEvent(r.Context(), domainEventOutbox, dev, "device_registered", dev.RegisteredAt, time.Now())
		if err := writer.Append("audit.log.jsonl", deviceAuditLog("device_registered", dev, evaluator, sourceIPFromRequest(r))); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, dev)
	})
	mux.HandleFunc("POST /devices/{device_id}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		// Device heartbeat over the (T) transport mTLS (steer_heartbeat.go) — exempt the verified transport
		// device from the connector gate (same split as CONNECT /steer / /devices/register); :8443 callers
		// without a verified device cert still require connector authorization.
		if _, transportDeviceAuthenticated := transportDeviceIdentityFromRequest(r); !transportDeviceAuthenticated {
			if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
				return
			}
		}
		var req model.DeviceHeartbeat
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode device heartbeat: %w", err))
			return
		}
		if req.ID == "" {
			req.ID = r.PathValue("device_id")
		}
		if certID, verified := transportDeviceIdentityFromRequest(r); verified {
			if !authorizeDeviceSelfReport(w, r, req.ID, connectorSecret, devMode, registry,
				evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret) {
				return
			}
			req.ID = enrolledinventory.NormalizeIdentity(certID)
			boundTenant, err := authoritativeTenantForRequest(r, req.TenantID, tcaReg)
			if err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			req.TenantID = boundTenant
		}
		prevTrust := ""
		if cur, ok := deviceStore.Get(req.ID); ok {
			prevTrust = cur.DeviceTrustLevel
		}
		// The organization is the DEVICE'S, not this node's — same reason as registration, and the reason a
		// customer's device used to heartbeat into a 404 for ever.
		provenIdentity, _ := transportDeviceIdentityFromRequest(r)
		devicesBundle := bundleForTheDevicesOrganization(config.EnrolledLedger, evaluator.PolicyBundle, provenIdentity, req.ID)
		dev, err := deviceStore.Heartbeat(req, devicesBundle, time.Now())
		if err != nil {
			// ★★★ AN EDGE THAT FORGOT IS NOT A DEPLOYMENT THAT REFUSED. See
			// a_device_the_deployment_admits_is_not_unknown.go: the runtime store is memory by default, so a
			// restart empties it, and a device the deployment still admits then heartbeats into a 404 for
			// ever while its traffic is carried and decrypted. Rebuilt from the enrolled inventory — the
			// authority on admission — and only for an identity this transport actually verified.
			rebuilt, ok := rehydrateAdmittedDevice(config.EnrolledLedger, deviceStore, provenIdentity, req.ID,
				evaluator.PolicyBundle, time.Now())
			if !ok {
				writeError(w, http.StatusNotFound, err)
				return
			}
			dev = rebuilt
			if beaten, berr := deviceStore.Heartbeat(req, devicesBundle, time.Now()); berr == nil {
				dev = beaten
			}
		}
		// A heartbeat whose posture signals dropped the device out of a trusted tier used to revoke its
		// standing east-west grants right here. It no longer does anything but say so.
		//
		// The trust level is recorded and every decision reads it, so a policy that refuses non-compliant
		// devices refuses this one at its next hop — which is the whole mechanism, and the only one that
		// should exist. Cutting access from inside a heartbeat handler meant enforcement nobody could find in
		// the policy: an operator reading their rules could not tell why the access went away, and the person
		// who lost it had nothing to be shown. Enforcement that cannot be pointed at is not enforcement an
		// operator controls.
		//
		// This is also the case where the signal is least reliable — posture arrives from the endpoint, and a
		// regression can be a failed probe as easily as a real change.
		if req.Posture != nil && devicestore.PostureRegressed(prevTrust, dev.DeviceTrustLevel) {
			// trust levels are non-secret enums (managed/noncompliant/unknown).
			logInfof("device_posture_regression device_trust_prev=%s device_trust_now=%s (recorded; enforcement is the policy's, evaluated per request)",
				prevTrust, dev.DeviceTrustLevel)
		}
		appendDeviceDomainEvent(r.Context(), domainEventOutbox, dev, "device_heartbeat", dev.LastSeenAt, time.Now())
		if err := writer.Append("audit.log.jsonl", deviceAuditLog("device_heartbeat", dev, evaluator, sourceIPFromRequest(r))); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusAccepted, dev)
	})
	mux.HandleFunc("POST /devices/{device_id}/agent-updates", func(w http.ResponseWriter, r *http.Request) {
		// ★ THIS IS A DEVICE TALKING ABOUT ITSELF (2026-08-12, sixth review). It used to require CONNECTOR
		// credentials, which the new senders on both platforms do not hold — they present the device's (T)
		// client certificate and nothing else, so in production every update outcome would have been answered
		// 401 and the fleet view would have stayed empty for a second, subtler reason.
		//
		// Worse in the other direction: the handler bound nothing. Anything holding a connector's runtime
		// secret could report an install for ANY device in the tenant — including a rollback that never
		// happened, or a success for a device that is failing. A fleet view an operator makes decisions from
		// must not accept claims about third parties.
		//
		// So the certificate is the authority, and the identity it proves must equal the device in the PATH and
		// the device in the BODY. The tenant comes from which registered Tenant CA the certificate chains to,
		// never from the body.
		var req model.AgentUpdateEvent
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode agent update event: %w", err))
			return
		}
		if !authorizeDeviceSelfReport(w, r, req.DeviceID, connectorSecret, devMode, registry,
			evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret) {
			return
		}
		if certID, ok := transportDeviceIdentityFromRequest(r); ok {
			// The verified certificate wins over both the path and the body — they were checked against it
			// above, and this makes the record carry the identity that was actually proved.
			req.DeviceID = enrolledinventory.NormalizeIdentity(certID)
		}
		if req.DeviceID == "" {
			req.DeviceID = r.PathValue("device_id")
		}
		boundTenant, terr := authoritativeTenantForRequest(r, req.TenantID, tcaReg)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		if strings.TrimSpace(boundTenant) != "" {
			req.TenantID = boundTenant
		}
		// ★ LOOKED UP IN THE TENANT THE CERTIFICATE PROVES (2026-08-12, ninth review). This used the Edge's own
		// policy-bundle tenant, which is right for a single-tenant deployment and silently wrong for an Edge
		// with several Tenant CAs registered: a legitimate device from any tenant but the default answered 404
		// and could never report an outcome. The tenant was already resolved from the issuing CA three lines
		// above and then not used.
		lookupTenant := strings.TrimSpace(req.TenantID)
		if lookupTenant == "" {
			lookupTenant = evaluator.PolicyBundle.TenantID
		}
		dev, ok, err := deviceForTenant(deviceStore, lookupTenant, req.DeviceID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device inventory is unavailable"))
			return
		}
		// ★ MEMBERSHIP IS THE ENROLMENT LEDGER, NOT THE RUNTIME STORE (2026-08-13, twenty-eighth review). The
		// runtime store is in-memory by default and empties on restart, so a legitimately enrolled device that
		// had not re-registered got 404 for its outcome — and both clients keep-and-retry a non-2xx, so that
		// device's report queue jammed permanently and the outcomes eventually aged out as drops. The moment
		// this matters most is an update that broke the agent, which is exactly when re-registration does not
		// happen. The ledger says who exists; the runtime store only adds what it happens to know.
		if !ok && config.EnrolledLedger != nil {
			// ★ AND IT MUST CHECK THAT THE DEVICE IS STILL ADMITTED (2026-08-13, twenty-ninth review). EntryFor
			// ignores Enabled, so the fallback accepted outcomes from a device an operator had explicitly
			// DISABLED — telemetry, audit and the fleet view all took them, and only after an Edge restart
			// emptied the runtime store, which is when this path is reached. A device that was refused before
			// the restart must not be accepted after it.
			if entry, inLedger := config.EnrolledLedger.EntryFor(req.DeviceID); inLedger && entry.Enabled &&
				deviceGroupVisibleToTenant(entry.TenantID, lookupTenant) {
				dev = model.Device{ID: entry.Identity, TenantID: strings.TrimSpace(entry.TenantID)}
				if dev.TenantID == "" {
					// Reached when the ledger entry carries no tenant and the caller's is empty too — a
					// single-tenant Edge with a legacy entry. deviceGroupVisibleToTenant lets that pair through.
					dev.TenantID = lookupTenant
				}
				ok = true
				log.Printf("agent_update_report device=%q is enrolled but has no runtime record — accepting its "+
					"outcome from the ledger rather than jamming its queue behind a 404", req.DeviceID)
			}
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("device %s is not found in tenant %s", req.DeviceID,
				lookupTenant))
			return
		}
		req, err = normalizeAgentUpdateReportForRuntime(req, dev, agentTargetVersion, agentReleaseChannel, time.Now().UTC())
		if err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		// ★ A RETRY IS THE SAME EVENT (2026-08-12, sixth review). The device outbox retries whenever a response
		// is lost, or when the process dies between "the Edge accepted it" and "the file was removed" — both
		// ordinary. Without this, each retry was audited again and counted again, so the success rate and the
		// audit trail both inflated in proportion to how badly the network was behaving.
		//
		// The durable half is already idempotent (agent_update_events upserts on event_id). What was NOT was
		// everything around it, which is what this guards. In-process and bounded, deliberately: it covers the
		// window a retry actually happens in, and it does not pretend to survive a restart — after one, the
		// upsert still collapses the duplicate row and only the audit line repeats.
		// ★ MARKED SEEN ONLY AFTER IT IS COMMITTED (2026-08-12, seventh review). The id used to be recorded
		// BEFORE the audit and the telemetry, so a failed audit answered 500 and the RETRY was then waved
		// through as a duplicate — the event was lost permanently, and the device deleted its copy on the 202.
		// A receipt written before the thing it acknowledges is not a receipt.
		receipt, alreadyCommitted, mine := reserveAgentUpdateEvent(req.TenantID, req.DeviceID, req.ID)
		if alreadyCommitted {
			writeJSON(w, http.StatusAccepted, map[string]any{"id": req.ID, "duplicate": true,
				"note": "this event was already recorded; nothing was recorded twice"})
			return
		}
		if !mine {
			// Another request is recording this same event right now. Answering 202 would let the device
			// delete its copy before the other request has finished, so it is told to come back.
			writeError(w, http.StatusConflict, fmt.Errorf("this event is being recorded by another request; "+
				"keep it and send it again"))
			return
		}
		committed := false
		defer func() {
			if !committed {
				receipt.release()
			}
		}()
		if err := writer.Append("audit.log.jsonl", agentUpdateAuditLog(req, evaluator, sourceIPFromRequest(r))); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// ★ AND A TELEMETRY FAILURE IS NOT AN ACCEPTANCE. It used to be logged and answered 202, so the device
		// deleted a report that never reached the store it is counted in — the fleet view stays wrong and the
		// only evidence is one line in an Edge log. The device keeps it and retries; the audit line above may
		// then appear twice, which is the direction to be wrong in.
		if agentTelemetry != nil {
			if err := agentTelemetry.RecordUpdate(r.Context(), req); err != nil {
				log.Printf("agent telemetry update record failed: %v", err)
				writeError(w, http.StatusInternalServerError, fmt.Errorf("this outcome was NOT recorded (%w): "+
					"keep it and send it again rather than dropping it", err))
				return
			}
		}
		// ★ AND THE DOWNSTREAM EVENT IS PART OF THE ACKNOWLEDGEMENT. Written best-effort, an outbox failure
		// left the event nowhere at all: not on the device, which drops its copy on the 202, and not
		// downstream. The device keeps it and retries instead.
		if derr := appendAgentUpdateDomainEventErr(r.Context(), domainEventOutbox, req, time.Now()); derr != nil {
			log.Printf("agent update domain event failed: %v", derr)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("this outcome was recorded but its "+
				"downstream event was NOT (%w): keep it and send it again rather than dropping it", derr))
			return
		}
		receipt.commit()
		committed = true
		writeJSON(w, http.StatusAccepted, req)
	})
	mux.HandleFunc("POST /devices/{device_id}/agent-status", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		var req model.AgentStatus
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode agent status: %w", err))
			return
		}
		if req.DeviceID == "" {
			req.DeviceID = r.PathValue("device_id")
		}
		dev, ok, err := deviceForTenant(deviceStore, evaluator.PolicyBundle.TenantID, req.DeviceID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device inventory is unavailable"))
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("device %s is not found", req.DeviceID))
			return
		}
		req, err = normalizeAgentStatusReportForRuntime(req, dev, time.Now().UTC())
		if err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		if err := writer.Append("audit.log.jsonl", agentStatusAuditLog(req, evaluator, sourceIPFromRequest(r))); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if agentTelemetry != nil {
			if err := agentTelemetry.RecordStatus(r.Context(), req); err != nil {
				log.Printf("agent telemetry status record failed: %v", err)
			}
		}
		writeJSON(w, http.StatusAccepted, req)
	})
	mux.HandleFunc("GET /devices/{device_id}/agent-rollout", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		dev, ok, err := deviceForTenant(deviceStore, evaluator.PolicyBundle.TenantID, r.PathValue("device_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device inventory is unavailable"))
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("device %s is not found", r.PathValue("device_id")))
			return
		}
		// the admin rollout/rollback plan (if any) drives the target over the static flag.
		plan := agentRolloutPlans.Get(dev.TenantID)
		targetVersion, releaseChannel, updateRequired := agentrollout.AgentRolloutDecision(plan, dev.AgentVersion, agentTargetVersion, agentReleaseChannel)
		meta := map[string]any{"source": "local_edge"}
		if plan.IsSet() {
			meta["rollout_intent"] = valueOrDefault(plan.Intent, agentrollout.AgentRolloutIntentRollout)
			meta["rollout_frozen"] = plan.Frozen
		}
		writeJSON(w, http.StatusOK, model.AgentRolloutPolicy{
			DeviceID:            dev.ID,
			TenantID:            dev.TenantID,
			CurrentAgentVersion: dev.AgentVersion,
			TargetAgentVersion:  targetVersion,
			ReleaseChannel:      releaseChannel,
			UpdateSource:        "control_plane",
			UpdateRequired:      updateRequired,
			Timestamp:           time.Now().UTC().Format(time.RFC3339),
			Metadata:            meta,
		})
	})
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		devices, err := devicesForTenant(deviceStore, evaluator.PolicyBundle.TenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device inventory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, devices)
	})
	mux.HandleFunc("GET /devices/{device_id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		dev, ok, err := deviceForTenant(deviceStore, evaluator.PolicyBundle.TenantID, r.PathValue("device_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device inventory is unavailable"))
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("device %s is not found", r.PathValue("device_id")))
			return
		}
		writeJSON(w, http.StatusOK, dev)
	})
	mux.HandleFunc("GET /devices/{device_id}/policy-bundle", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		dev, ok, err := deviceForTenant(deviceStore, evaluator.PolicyBundle.TenantID, r.PathValue("device_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device inventory is unavailable"))
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("device %s is not found", r.PathValue("device_id")))
			return
		}
		if dev.TenantID != evaluator.PolicyBundle.TenantID {
			writeError(w, http.StatusForbidden, fmt.Errorf("device tenant_id %s does not match policy bundle tenant_id %s", dev.TenantID, evaluator.PolicyBundle.TenantID))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"device_id":     dev.ID,
			"tenant_id":     dev.TenantID,
			"policy_bundle": evaluator.PolicyBundle,
		})
	})
	mux.HandleFunc("GET /devices/{device_id}/trusted-keyring", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		dev, ok, err := deviceForTenant(deviceStore, evaluator.PolicyBundle.TenantID, r.PathValue("device_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device inventory is unavailable"))
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("device %s is not found", r.PathValue("device_id")))
			return
		}
		if dev.TenantID != trustedKeyring.TenantID {
			writeError(w, http.StatusForbidden, fmt.Errorf("device tenant_id %s does not match trusted keyring tenant_id %s", dev.TenantID, trustedKeyring.TenantID))
			return
		}
		writeJSON(w, http.StatusOK, trustedKeyring)
	})
	mux.HandleFunc("POST /human-approvals/events", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		now := time.Now()
		var event model.HumanApprovalEvent
		if err := decodeLimitedJSONBody(w, r, &event, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode human approval event: %w", err))
			return
		}
		if err := normalizeHumanApprovalEvent(&event, evaluator.PolicyBundle.TenantID, now); err != nil {
			writeError(w, statusForHumanApprovalEventError(err), err)
			return
		}
		if event.ActorNHIID != nil {
			if err := nhi.ValidateUsageReference(r.Context(), nonHumanIdentities, event.TenantID, *event.ActorNHIID, nhi.UsageFromHumanApprovalEvent(event), now); err != nil {
				writeError(w, nhi.StatusForReferenceError(err), err)
				return
			}
		}
		stored, err := humanApprovals.Upsert(event)
		if err != nil {
			writeError(w, statusForHumanApprovalEventError(err), err)
			return
		}
		event = stored
		if err := writer.Append("human_approval_events.log.jsonl", event); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if envelope, err := domainEventOutboxEnvelopeFromHumanApprovalEvent(event, now); err != nil {
			log.Printf("domain event outbox human approval envelope: %v", err)
		} else {
			appendDomainEventOutbox(r.Context(), domainEventOutbox, envelope, now)
		}
		if err := writer.Append("audit.log.jsonl", humanApprovalEventAuditLog(event, evaluator, now)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusAccepted, event)
	})
	mux.HandleFunc("GET /human-approvals/events/{approval_id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		event, ok := humanApprovals.GetForTenant(evaluator.PolicyBundle.TenantID, r.PathValue("approval_id"))
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("human approval event %s is absent", r.PathValue("approval_id")))
			return
		}
		writeJSON(w, http.StatusOK, event)
	})
	mux.HandleFunc("POST /delegated-grants", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		now := time.Now()
		var grant model.DelegatedAccessGrant
		if err := decodeLimitedJSONBody(w, r, &grant, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode delegated access grant: %w", err))
			return
		}
		if err := normalizeDelegatedAccessGrant(&grant, evaluator.PolicyBundle.TenantID, now); err != nil {
			writeError(w, statusForDelegatedGrantError(err), err)
			return
		}
		if err := nhi.ValidateUsageReference(r.Context(), nonHumanIdentities, grant.TenantID, grant.ActorNHIID, nhi.UsageFromDelegatedGrant(grant), now); err != nil {
			writeError(w, nhi.StatusForReferenceError(err), err)
			return
		}
		stored, err := delegatedGrants.Upsert(grant)
		if err != nil {
			writeError(w, statusForDelegatedGrantError(err), err)
			return
		}
		grant = stored
		if err := writer.Append("delegated_access_grants.log.jsonl", grant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		appendDelegatedGrantDomainEvent(r.Context(), domainEventOutbox, grant, "delegated_access_grant_recorded", stringPtrValue(grant.CreatedAt), now)
		if err := writer.Append("audit.log.jsonl", delegatedAccessGrantAuditLog("delegated_access_grant_recorded", grant, evaluator, now)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusAccepted, grant)
	})
	mux.HandleFunc("GET /delegated-grants/{grant_id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		grant, ok := delegatedGrants.GetForTenant(evaluator.PolicyBundle.TenantID, r.PathValue("grant_id"))
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("delegated access grant %s is absent", r.PathValue("grant_id")))
			return
		}
		writeJSON(w, http.StatusOK, grant)
	})
	mux.HandleFunc("POST /delegated-grants/{grant_id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		now := time.Now()
		var req delegatedGrantRevokeRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode delegated access grant revoke request: %w", err))
			return
		}
		grant, err := delegatedGrants.RevokeForTenant(evaluator.PolicyBundle.TenantID, r.PathValue("grant_id"), req.RevocationReason, now)
		if err != nil {
			writeError(w, statusForDelegatedGrantError(err), err)
			return
		}
		if err := writer.Append("delegated_access_grants.log.jsonl", grant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		appendDelegatedGrantDomainEvent(r.Context(), domainEventOutbox, grant, "delegated_access_grant_revoked", stringPtrValue(grant.RevokedAt), now)
		if err := writer.Append("audit.log.jsonl", delegatedAccessGrantAuditLog("delegated_access_grant_revoked", grant, evaluator, now)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, grant)
	})
	mux.HandleFunc("POST /tools/events", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		now := time.Now()
		var event model.ToolCallEvent
		if err := decodeLimitedJSONBody(w, r, &event, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode tool call event: %w", err))
			return
		}
		if err := toolcallaudit.Normalize(&event, evaluator.PolicyBundle.TenantID, now); err != nil {
			writeError(w, statusForToolCallEventError(err), err)
			return
		}
		if err := nhi.ValidateUsageReference(r.Context(), nonHumanIdentities, event.TenantID, event.ActorNHIID, nhi.UsageFromToolCallEvent(event), now); err != nil {
			writeError(w, nhi.StatusForReferenceError(err), err)
			return
		}
		if err := validateToolCallEventReferences(event, evaluator.PolicyBundle.TenantID, decisionStore, humanApprovals, delegatedGrants, inspectionEvents, now); err != nil {
			writeError(w, statusForToolCallEventError(err), err)
			return
		}
		if err := writer.Append("tool_call_events.log.jsonl", event); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if envelope, err := domainEventOutboxEnvelopeFromToolCallEvent(event, now); err != nil {
			log.Printf("domain event outbox tool call envelope: %v", err)
		} else {
			appendDomainEventOutbox(r.Context(), domainEventOutbox, envelope, now)
		}
		if err := writer.Append("audit.log.jsonl", toolCallEventAuditLog(event, evaluator, now)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusAccepted, event)
	})
	mux.HandleFunc("POST /inspection/events", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		now := time.Now()
		var event model.InspectionEvent
		if err := decodeLimitedJSONBody(w, r, &event, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode inspection event: %w", err))
			return
		}
		if err := normalizeInspectionEvent(&event, evaluator.PolicyBundle.TenantID, now); err != nil {
			writeError(w, statusForInspectionEventError(err), err)
			return
		}
		if err := validateInspectionEventReferences(event, evaluator.PolicyBundle.TenantID, decisionStore); err != nil {
			writeError(w, statusForInspectionEventError(err), err)
			return
		}
		event = inspectionEvents.Upsert(event)
		if err := writer.Append("inspection_events.log.jsonl", event); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if envelope, err := domainEventOutboxEnvelopeFromInspectionEvent(event, now); err != nil {
			log.Printf("domain event outbox inspection envelope: %v", err)
		} else {
			appendDomainEventOutbox(r.Context(), domainEventOutbox, envelope, now)
		}
		if err := writer.Append("audit.log.jsonl", inspectionEventAuditLog(event, evaluator, now)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusAccepted, event)
	})
	mux.HandleFunc("GET /inspection/events/{inspection_id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		event, ok := inspectionEvents.Get(r.PathValue("inspection_id"))
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("inspection event %s is absent", r.PathValue("inspection_id")))
			return
		}
		writeJSON(w, http.StatusOK, event)
	})
	mux.HandleFunc("POST /decisions/evaluate", func(w http.ResponseWriter, r *http.Request) {
		runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, runtimeEvaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		var req model.DecisionRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode decision request: %w", err))
			return
		}
		req = enrichDecisionRequestWithSession(req, sessionStore)
		req = enrichDecisionRequestWithRisk(req, deviceStore, config.HighRiskOverlay, config.EnrolledLedger)
		req = dns.EnrichDecisionRequestWithDNS(req, dnsConntrack, time.Now()) // D1: recover FQDN for connect-by-IP / non-TLS flows
		req = deriveDecisionRequestActor(req, delegatedGrants)
		req = nhi.EnrichDecisionRequestWithRisk(r.Context(), req, nonHumanIdentities, time.Now()) // block or gate a high-risk NHI's access (nhi_risk_severity)
		req = enrichDecisionRequestWithTransportIdentity(r, req)                                  // W2: bind verified mTLS device identity (authoritative)
		// tenant isolation: bind the AUTHORITATIVE tenant from the (T) mTLS issuing CA onto the decision
		// (not the client-claimed tenant_id). A body that claims a different tenant than its certificate proves
		// is a cross-tenant attempt — denied here, before evaluation, so a decision can never be keyed to a
		// tenant the connection has not authenticated as. Phase 3 (G1): on a multi-tenant production Edge
		// (registry configured + !devMode) an unresolved tenant is denied here instead of falling back to the
		// seed/primary PolicyBundle tenant; lab/devMode and single-tenant (nil registry) keep the seed fallback.
		boundReq, tenantErr := enrichDecisionRequestWithTransportTenant(r, req, tcaReg, devMode)
		if tenantErr != nil {
			writeError(w, http.StatusForbidden, tenantErr)
			return
		}
		req = boundReq
		var err error
		var attestation runtimeWorkloadAttestationEvidence
		req, attestation, err = enrichDecisionRequestWithRuntimeAttestation(r, req, workloadAttestationSecret, devMode, workloadAttestations, time.Now())
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}

		dec := evaluateWithRuntimeEvidence(r.Context(), runtimeEvaluator, req, humanApprovals, delegatedGrants, nonHumanIdentities, time.Now())
		eastwest.TouchGrantIfSatisfied(policyStore, req, dec, time.Now())
		annotateRuntimeWorkloadAttestationMetadata(&dec, attestation)
		recordNonHumanIdentityRuntimeUse(r.Context(), nonHumanIdentities, &dec, time.Now())
		decisionStore.Upsert(dec)
		recordDecisionMetric(dec.Decision)
		if err := appendAccessDecisionLogs(r.Context(), writer, domainEventOutbox, dec, time.Now()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		usagemeter.RecordUsageMeterDecision(usageMeters, dec, time.Now())

		writeJSON(w, http.StatusOK, dec)
	})
	mux.HandleFunc("POST /dns/strip-ech", func(w http.ResponseWriter, r *http.Request) {
		// D2: a DNS shim forwards a raw DNS response (base64) to strip the ECH SvcParam so the
		// client falls back to plaintext SNI. Managed-device-only + DNS-pinned per design
		runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
		// Managed-device endpoint served on both listeners: a request over the (T) transport mTLS carries a
		// verified, enrolled device identity and is exempt from connector authorization (same device-vs-connector
		// split as CONNECT /steer); a request without a verified device cert must still be connector-authorized.
		if _, transportDeviceAuthenticated := transportDeviceIdentityFromRequest(r); !transportDeviceAuthenticated {
			if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, runtimeEvaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
				return
			}
		}
		var req struct {
			DNSResponseBase64 string `json:"dns_response_base64"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dns strip request: %w", err))
			return
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.DNSResponseBase64))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("dns_response_base64 is not valid base64: %w", err))
			return
		}
		out, stripped, serr := dnsech.StripECHFromDNSResponse(raw)
		logDebugf("dns_ech_strip ech_records_stripped=%d parse_ok=%t", stripped, serr == nil)
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":        "dns_ech_strip.v1",
			"ech_records_stripped":  stripped,
			"dns_response_base64":   base64.StdEncoding.EncodeToString(out),
			"no_secret_attestation": true,
		})
	})
	mux.HandleFunc("POST /ingest/dns-resolution-observation", func(w http.ResponseWriter, r *http.Request) {
		// D1: the Endpoint Agent (or a future Edge DNS resolver) reports a DNS resolution
		// (FQDN -> resolved IPs) so the Edge can recover the FQDN for a later connect-by-IP / non-TLS flow.
		runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, runtimeEvaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		var req dns.ObservationRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dns resolution observation: %w", err))
			return
		}
		// tenant isolation: this observation is recorded in the tenant-keyed DNS conntrack, which later
		// recovers the FQDN for that tenant's connect-by-IP flows (feeds the decision). So the tenant must be
		// the one the (T) mTLS certificate proves — a body claiming another tenant could poison that tenant's
		// FQDN->IP map and skew its policy decisions, and is denied here before any record is taken.
		boundTenant, terr := authoritativeTenantForRequest(r, req.TenantID, tcaReg)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		req.TenantID = boundTenant
		if strings.TrimSpace(req.TenantID) == "" {
			req.TenantID = runtimeEvaluator.PolicyBundle.TenantID
		}
		recorded := dnsConntrack.Record(req, time.Now())
		// Boundary checkpoint (non-secret: counts only; never the FQDN/IP values).
		logDebugf("dns_resolution_ingested tenant=%s recorded_entries=%d", req.TenantID, recorded)
		writeJSON(w, http.StatusOK, dns.ObservationResponse{
			SchemaVersion: "dns_resolution_observation.v1", TenantID: req.TenantID,
			RecordedEntries: recorded, NoSecretAttestation: true,
		})
	})
	// East-west E3: issue an ephemeral grant against a completed challenge (after the OOB ceremony, E4)
	// to RELEASE the held flow. Connector-class runtime auth (lab mode bypasses).
	mux.HandleFunc("POST /east-west/grant", func(w http.ResponseWriter, r *http.Request) {
		runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, runtimeEvaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		var req eastwest.GrantIssueRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode east-west grant request: %w", err))
			return
		}
		resp, err := eastwest.IssueGrantFromChallenge(policyStore, eastWestAuthChallenges, req.ChallengeID, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		log.Printf("east_west_grant_issued tenant=%s protocol=%s", resp.TenantID, resp.Protocol)
		writeJSON(w, http.StatusOK, resp)
	})
	// W3 generic steer-judgment path: a transparently-steered flow (Windows steer-all agent) to an
	// ARBITRARY original destination. Applies policy on that destination; on allow the Edge dials it
	// directly (policy-enforcing forward proxy). No pre-registered app / authority==Destination constraint.
	// Connector-class runtime auth (lab mode bypasses).
	// InterceptAll: when a lab-TLS interception engine is configured, route ALLOWED steered flows through
	// it (decrypt-all on 443) instead of a blind forward, so steer-all https gets the same decrypt +
	// tenant-policy enforcement as the macOS NE path. nil = transparent forward proxy (prior behavior).
	var steerInterceptionDialer edgeplane.NetworkExtensionRuntimeCopyTCPDialer
	if config.NetworkExtensionLabTLS != nil {
		steerInterceptionDialer = edgeplane.NetworkExtensionRuntimeCopyTLSInterceptionDialer{
			Base:                   edgeplane.NetworkExtensionRuntimeCopyNetDialer{},
			Intercepter:            config.NetworkExtensionLabTLS,
			ProbeOnlyDropUnmatched: config.NetworkExtensionLabTLS.ProbeOnlyDropUnmatched(),
		}
	}
	// CONNECT /steer (single-flow tunnel) REMOVED 2026-07-13: both the macOS NE and the Windows WFP agent
	// steer over CONNECT /steer-mux (below); the per-flow tunnel was a confusing dead parallel path. The
	// /steer/* CONTROL sub-paths (dns-query, agent-policy, region-endpoints, …) are unaffected.

	// CONNECT /steer-mux — the MULTIPLEXED steer tunnel: ONE mTLS transport connection carrying MANY browser
	// flows (custom framing, see steer_mux.go), instead of one CONNECT /steer connection per flow. Same device
	// auth as /steer; each demuxed flow runs the IDENTICAL decision + interception (steerEgressForward) as a
	// per-flow virtual conn. This exists so macOS (NWConnection) is not forced to open ~80 concurrent tunnels on
	// a heavy page — the count that overwhelmed Network.framework and stalled interception handshakes.
	mux.HandleFunc("CONNECT /steer-mux", func(w http.ResponseWriter, r *http.Request) {
		runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
		transportDeviceID, transportDeviceAuthenticated := transportDeviceIdentityFromRequest(r)
		// Per-connection (≈ per-device) runtime facts the endpoint agent reports on the CONNECT: OS + posture.
		// Derive the device trust tier from that REAL posture (disk-encryption + firewall) ONCE per connection —
		// this is what lets a machine/non-interactive East-West flow be authorized by DEVICE attestation (verified
		// mTLS device + trusted posture) instead of an impossible OOB ceremony (EastWestRule.DeviceAttestedAuto).
		// Empty when no posture was reported (fail-closed: no posture => not device-attestation-eligible).
		connectDeviceTrustLevel := ""
		if p, ok := deviceRuntime.ingestFromConnect(transportDeviceID, runtimeEvaluator.PolicyBundle.TenantID, r.Header, sourceIPFromRequest(r), time.Now()); ok {
			// The steer-mux CONNECT carries only the NETWORK-ADMISSION posture axes (disk-encryption + firewall),
			// so derive its trust tier against JUST those axes (honoring the env toggles for them). Requiring a
			// signal this channel never carries (screen-lock / agent-health / OS-version, part of the FULL device
			// posture policy) would force EVERY steered device to "noncompliant" and make device-attested East-West
			// impossible. Those richer axes gate the device-store trust (from the full heartbeat), not this tier.
			envPol := posturePolicyFromEnv()
			connectPol := devicestore.PosturePolicy{RequireDiskEncryption: envPol.RequireDiskEncryption, RequireFirewall: envPol.RequireFirewall}
			connectDeviceTrustLevel, _, _ = devicestore.DerivePostureTrustLevel(&p, connectPol)
			logDebugf("device_posture_reported device=%q encryption=%s firewall=%s source=%q trust=%q", transportDeviceID, boolPtrLog(p.DiskEncryptionEnabled), boolPtrLog(p.FirewallEnabled), p.Source, connectDeviceTrustLevel)
		}
		if !transportDeviceAuthenticated {
			if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, runtimeEvaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
				return
			}
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("steer-mux requires connection hijack"))
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		logDebugf("steer_mux_open")
		m := edgeplane.NewSteerMux(clientConn)
		m.Run(func(flowID uint32, authority string, vc *edgeplane.MuxVirtualConn) {
			defer vc.Close()
			// ★★★ AND IS THIS DEVICE STILL ADMITTED — ASKED PER FLOW TOO (2026-08-25, measured on a real
			// endpoint). The comment below already established that a connection-scoped evaluator goes stale
			// on a long-lived mux and rebuilt the POLICY per flow. The device's ADMISSION was left behind:
			// decided once at the handshake and believed for the life of the connection. A real agent pools
			// twelve connections and keeps them warm, so an administrator pressing block stopped nothing it
			// already held — new flows kept opening on old connections and the browsing carried on, while the
			// heartbeat, which did need a new handshake, was correctly refused. See agent_door_admission.go.
			//
			// ★★★ AND THE CONNECTION IS LEFT OPEN — THE FIRST VERSION CLOSED IT, AND THAT RELEASED THE DEVICE
			// TO THE OPEN INTERNET (2026-08-25, measured on a real endpoint hours after the fix landed).
			//
			// Closing the mux made a refusal look exactly like an outage. The agent's fail-open circuit counts
			// consecutive failures and cannot tell "the Edge is gone" from "the Edge answered and refused me",
			// so three closes in a row opened it:
			//
			//	steer_failopen_direct dst=... reason=edge_circuit_open (UNMEDIATED — edge bypassed)
			//	...30 flows direct in a 22-second block window; line.me answered 200 four times
			//
			// Blocking turned a managed device into an unmanaged one. Strictly worse than the defect it
			// fixed: before, a blocked device at least went on being recorded. And --fail-open's own help
			// promises the opposite — "A reachable-but-deny Edge stays enforced" — which is broken precisely
			// when the denial arrives as a dead socket.
			//
			// So the FLOW is refused and the CONNECTION is kept. The device stays mediated, every attempt is
			// recorded, and the agent goes on seeing a live Edge that is answering — which is what
			// reachable-but-deny has to look like from the other end.
			if reason, refused := agentIdentityRefusedNow(transportDeviceID); refused {
				log.Printf("steer_mux_flow_refused device=%q reason=%s flow=%d — refused after this connection "+
					"was established; the connection is kept so this stays a denial and not an outage",
					transportDeviceID, reason, flowID)
				return
			}
			// Rebuild the runtime evaluator PER FLOW so an admin rule change (add/edit/delete) is reflected
			// immediately — the mux CONNECT above builds one once, but the tunnel is long-lived, so a
			// connection-scoped evaluator went stale until the mux reconnected (required an edge restart).
			runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
			// OPEN payload is "host:port", optionally followed by a \x00-delimited per-flow metadata section
			// ("u=<os-user> a=<app>") — the logged-in user who originated the flow (a device can be shared, so
			// this is the only per-user signal); old agents send just "host:port". splitSteerAuthorityMeta parses
			// + strips it and blanks non-interactive / system accounts (macOS _mdnsresponder, Windows
			// NT AUTHORITY\SYSTEM, …). Shared with CONNECT /steer so the two transports cannot diverge.
			var osUser, sourceApp string
			authority, osUser, sourceApp = splitSteerAuthorityMeta(authority)
			// ★ NOT GATED ON THE USER (2026-08-14). This was `if osUser != ""`, and the name it used to have —
			// recordFlowUser — made that look right: no user, nothing to record. But this is the ONLY place a
			// device is credited with carrying traffic, so an agent that sends a flow without `u=` was recorded
			// as not steering AT ALL, and the fleet view showed it idle while this Edge carried its bytes.
			// A missing username is a missing username; it is not an absence of traffic, and the two must not
			// render the same. An empty user is already ignored by the store.
			//
			// (Both current agents do send `u=`, so this was latent rather than the cause of the Mac that was
			// reported idle on 2026-08-14 — that was region-b's shipping, one layer out. Removing the gate is
			// still right: the metadata section is optional by design, and older agents send `host:port` alone.)
			// ★★★ EVERY STEERED FLOW WAS THIS NODE'S OWN ORGANIZATION (2026-08-28, measured by putting a
			// second organization on the lab and running one flow as one of its devices).
			//
			// The device's identity was bound here from the moment this handler was written — transportDeviceID
			// comes from the verified (T) certificate — and its ORGANIZATION never was. The request was seeded
			// with this node's policy-bundle tenant and nothing replaced it, so for every organization on the
			// deployment, every steered flow was decided, inspected and recorded as the operator's own:
			//
			//	the leaf the browser is shown is signed by whichever authority THAT organization has,
			//	the policy applied is that organization's,
			//	and the record says whose flow it was
			//
			// all three read the tenant on this request. Measured: a device of "Suzuran Foods", holding a
			// certificate from Suzuran's own device CA, dialling Suzuran's own transport name, was served a
			// certificate for example.com signed by the DEPLOYMENT's interception root while Suzuran's own
			// issuing CA sat loaded on the same Edge.
			//
			// ★ RESOLVED FROM THE CERTIFICATE, NOT FROM ANYTHING THE DEVICE SAYS. Same source as the
			// /decisions/evaluate path: which registered organization CA the chain leads to.
			//
			// ★★ AND IT SEEDS THE REQUEST RATHER THAN CORRECTING IT. enrichDecisionRequestWithTransportTenant
			// refuses a request whose claimed tenant disagrees with the certificate — correctly, that is a
			// cross-tenant claim — and this request would have "claimed" the node's own tenant on every flow,
			// so every organization but the operator's would have been DENIED instead of misattributed.
			//
			// ★ AN UNRESOLVED CHAIN KEEPS TODAY'S ANSWER, and says so. The /steer path denies it on a
			// multi-tenant production Edge; turning that on here in the same change would convert an
			// attribution defect into an outage for any device whose CA is not in the registry. Named as the
			// remaining half rather than done quietly.
			flowTenant := steerMuxFlowTenant(r, tcaReg, runtimeEvaluator.PolicyBundle.TenantID, transportDeviceID)
			deviceRuntime.recordSteeredFlow(transportDeviceID, flowTenant, osUser, time.Now())
			host, portStr, serr := net.SplitHostPort(authority)
			if serr != nil {
				logWarnf("steer_mux_bad_authority flow=%d", flowID)
				return
			}
			port, _ := strconv.Atoi(portStr)
			req := steerDecisionRequest(flowTenant, host, port)
			// Bind the mux flow's AUTHORITATIVE identity onto the decision request: the verified (T) transport
			// device (mTLS CN, e.g. win-dev-1) + the steered OS-user carried on the mux OPEN metadata. Without
			// this the per-OPEN decision carried NEITHER, so an East-West grant bound to the device (or user)
			// never matched — a Console/Approvals grant for device_id=win-dev-1 could not release the held mux
			// flow (EastWestGrant.matches checks g.DeviceID against req.TransportDeviceIdentity, and the
			// federated step-up gate keys off the device too). Same authoritative identity a real deployment
			// binds a grant to.
			req.TransportDeviceIdentity = transportDeviceID
			if osUser != "" {
				req.SubjectUserID = valueOrDefault(req.SubjectUserID, osUser)
			}
			// Full decision-request enrichment for the steer-mux OPEN — PARITY with POST /decisions/evaluate and
			// the decrypt-all egress path, which the coarse mux OPEN decision previously LACKED. Without this,
			// device/user RISK (high-risk -> block/re-auth, tamper, auth-anomaly, IdP-risk), posture-derived
			// device TRUST + attestation, FQDN recovery for connect-by-IP, delegated-grant ACTOR, and NHI
			// RISK were ALL inert for steered non-https flows (every East-West + raw-forward TCP flow) —
			// https was safe only because the decrypt-all egress path re-decides with full enrichment at intercept.
			// The verified (T) transport device is authoritative; device risk/trust lookups key off it (the steer
			// path carries no client DeviceID). connectDeviceTrustLevel is the posture-derived tier (disk+firewall).
			if transportDeviceAuthenticated {
				req.TransportClientCertVerified = true
			}
			if req.DeviceID == "" {
				req.DeviceID = transportDeviceID
			}
			req.DeviceTrustLevel = valueOrDefault(req.DeviceTrustLevel, connectDeviceTrustLevel)
			req = enrichDecisionRequestWithRisk(req, deviceStore, config.HighRiskOverlay, config.EnrolledLedger)
			req = dns.EnrichDecisionRequestWithDNS(req, dnsConntrack, time.Now())
			req = deriveDecisionRequestActor(req, delegatedGrants)
			req = nhi.EnrichDecisionRequestWithRisk(r.Context(), req, nonHumanIdentities, time.Now())
			// Plane membership, decided the SAME way the evaluator decides it (protocol AND destination
			// locality). Asking IsEastWestProtocol here instead would put a public-internet ssh into the lateral
			// adoption queue while the evaluator sent it to the north-bound plane — and the candidate capture
			// below excludes east-west protocols, so it would be in neither queue.
			// ★ GIVE PLANE MEMBERSHIP AN ADDRESS TO REASON ABOUT (2026-08-14, from the operator: an ssh to
			// github showing up under connector access, and then the rule in their words — traffic to a
			// REGISTERED network is east-west). DestinationIP is never set on this path, so a destination given
			// as a NAME classified as Unknown, and east-west admits Unknown: github.com was governed on the
			// lateral plane and denied for want of a rule. Resolving it once here lets the SAME predicate
			// answer for enforcement and for the inventory, which is the point — they disagreed before only
			// because one of them had been taught to resolve and the other had not.
			//
			// Only DestinationResolvedIP is filled; DestinationIP stays as the client sent it, because other
			// decisions read that one. See east_west_observe_locality.go.
			req = resolveDestinationForLocality(r.Context(), req, runtimeEvaluator.EastWestInternalNetworks, time.Now())
			ewLocality := decision.ClassifyDestinationLocality(req, runtimeEvaluator.EastWestInternalNetworks).String()
			if decision.IsEastWestFlow(req, runtimeEvaluator.EastWestInternalNetworks) {
				logDebugf("steer_mux_ew_identity device=%q cert_verified=%t trust=%q risk=%q user=%q dst_port=%d locality=%s", transportDeviceID, req.TransportClientCertVerified, req.DeviceTrustLevel, req.RiskStateSeverity, req.SubjectUserID, port, ewLocality)
				// S1 (Observe): record this lateral flow in the inventory (source device / Any, logged-in user,
				// dest, service). No enforcement effect — recording only, so the operator can review + adopt (S2)
				// and watch it converge. The user (resolved directory identity, else the OS login user) lets the
				// operator tell HUMAN traffic from SYSTEM/machine traffic (empty user = unattended); see
				// FlowObservation.Human.
				if config.EastWestObserveStore != nil {
					observeUser := strings.TrimSpace(req.SubjectUserID)
					if observeUser == "" {
						observeUser = strings.TrimSpace(osUser)
					}
					config.EastWestObserveStore.Observe(req.TenantID, transportDeviceID, observeUser, host, req.ServiceFamily, port, time.Now())
				}
			}
			dec := evaluateWithRuntimeEvidence(r.Context(), runtimeEvaluator, req, humanApprovals, delegatedGrants, nonHumanIdentities, time.Now())
			decisionStore.Upsert(dec)
			recordDecisionMetric(dec.Decision)
			// A destination refused because NO rule covered it becomes an adoptable candidate, exactly as on the
			// SWG egress path. This path had no capture at all: it governs every steered NON-https flow, so a
			// default-denied destination was refused and then forgotten, leaving an operator no route from "this
			// was blocked" to "here is the rule to write". Measured on 2026-08-05: 62 denies to one address
			// produced zero candidates.
			//
			// It mattered less while Policy Learning deferred the deny — the flow passed anyway. With Default
			// Deny live it is the difference between a fleet an operator can converge and one that just breaks.
			//
			// East-West flows are deliberately EXCLUDED: they already have their own observe → adopt inventory
			// (EastWestObserveStore, recorded above and surfaced on the Connector Access page). Capturing them
			// here as well would put the same flow in two adoption queues that adopt into different planes.
			if decision.IsDefaultDeny(dec) && !decision.IsEastWestFlow(req, runtimeEvaluator.EastWestInternalNetworks) {
				if cs, ok := policyCandidateStore.(*policycandidate.Store); ok {
					if _, cerr := cs.ObserveUnmatchedFlow(r.Context(), req.TenantID, host, req.SNI, port, "", time.Now().UTC()); cerr != nil {
						logDebugf("steer_mux_candidate_capture_failed dst=%q port=%d: %v", host, port, cerr)
					}
				}
			}
			// The steer-mux OPEN decision is a Plane-B record ('s "one structured row per flow"). Until this
			// existed, this path wrote NO structured record at all: an https flow got one later from the SWG path,
			// but a steered NON-https flow (ssh/rdp/smb) was recorded ONLY by the stderr breadcrumbs — so once
			// those moved to DEBUG, a live ssh through the NE left no trace anywhere. Measured, not theorised:
			// `ssh git@github.com` moved access 200 -> 200 and printed nothing at INFO.
			//
			// Uses the same shouldLogAccessDecision policy as the SWG path ( RECONCILE) rather than logging
			// unconditionally, so one logging policy governs every path. Note what that guarantees here: a deny or
			// a step-up is ALWAYS recorded (a rule's log=false cannot suppress a policy action), which is exactly
			// the case the stderr breadcrumbs were the only witness for.
			if shouldLogAccessDecision(dec) {
				if err := appendAccessDecisionLogs(r.Context(), writer, domainEventOutbox, dec, time.Now()); err != nil {
					logErrorf("steer_mux_access_log_failed dst_port=%d decision=%s: %v", port, dec.Decision, err)
				}
			}
			// An UNKNOWN locality on a flow that was then held or denied is the one classification worth saying
			// out loud. East-west plane membership admits unknown deliberately — a control must not switch
			// itself off when an input goes missing — but the cost of that choice is a flow that stalls for a
			// reason nobody can see. Logged only when the flow actually paid for it: an unknown that ended in
			// allow harmed nobody, and an entry per flow would bury the ones that matter.
			if ewLocality == decision.LocalityUnknown.String() && dec.Decision != "allow" &&
				decision.IsEastWestFlow(req, runtimeEvaluator.EastWestInternalNetworks) {
				log.Printf("east_west_locality_unknown dst=%s:%d service=%s decision=%s — the destination could "+
					"not be classified (no parseable address, no declared internal network matched), so this flow "+
					"kept its lateral-plane enforcement and was NOT treated as internet access. If this destination "+
					"is public, the request reached the Edge without a usable address",
					host, port, req.ServiceFamily, dec.Decision)
			}
			if dec.Decision != "allow" && !decisionPermitsConnectorRoute(dec.Decision) {
				allowedByGrant := false
				stepUpURL := ""
				reqACR := ""
				if federatedAuthGateForEgress != nil && decisionRequiresOIDCRedirect(dec.Decision) {
					var reqIdP string
					reqIdP, reqACR = authStepUpRequirements(dec)
					if federatedAuthGateForEgress.hasLiveGrantFor(dec.TenantID, transportDeviceID, reqACR) {
						allowedByGrant = true
					} else {
						stepUpURL = federatedAuthGateForEgress.stepUpURLFor(authority, reqIdP, reqACR, transportDeviceID, dec.TenantID)
					}
				}
				if !allowedByGrant {
					if stepUpURL != "" {
						// A native TCP client can't follow a 302, so — like the single-flow /steer path's
						// X-Dsse-Stepup-Url header — ask the agent to open the step-up portal OOB in a browser.
						_ = vc.SendStepUp(stepUpURL)
						// INFO, not debug. This is the moment a security ceremony STARTS: a flow was held and
						// the user was asked to authenticate out-of-band. It was previously logDebugf, so the
						// entire ceremony lifecycle was invisible at the default level — on 2026-08-05 it could
						// not be established from any log whether a step-up had fired, only by reading a file
						// the agent happens to write. A held flow is exactly the kind of event an operator has
						// to be able to see after the fact.
						// locality= answers the question this line always provoked and never answered: why is
						// this flow on the LATERAL plane? Plane membership is protocol AND destination locality,
						// and until it was printed here the classification could only be inferred from
						// behaviour — win-dev-1 verified the locality fix by watching what happened rather than
						// by reading what was decided. A held flow is exactly where that inference is expensive.
						log.Printf("east_west_stepup_issued device=%s dst=%s:%d service=%s locality=%s decision=%s — flow HELD pending out-of-band authentication",
							transportDeviceID, host, port, req.ServiceFamily, ewLocality, dec.Decision)
						// AUTO-RELEASE (task #5): instead of dropping the held flow, PARK it and wait for the OOB
						// step-up to mint a device grant, then resume forwarding on THIS same connection — so the
						// user's original native client (ssh, etc.) connects with NO manual retry. The NE keeps the
						// flow open on a STEPUP frame (it only writes the URL + notifies the agent app); the flow
						// closes only if WE send CLOSE or the client gives up (peer CLOSE -> vc.closed). The wait is
						// bounded so a native client is never pinned past its own patience; on timeout we fall back
						// to the original drop-and-retry (the client's retried OPEN is then allowed by the grant).
						if federatedAuthGateForEgress != nil &&
							waitForStepUpGrant(r.Context(), federatedAuthGateForEgress, transportDeviceID, reqACR, vc, steerMuxStepUpGrantWait) {
							log.Printf("east_west_stepup_completed device=%s dst=%s:%d service=%s — grant minted during the ceremony; the held flow resumes with no client retry",
								transportDeviceID, host, port, req.ServiceFamily)
							// grant minted during the ceremony — fall through to forward on the held flow.
						} else {
							// A ceremony that was started and did NOT complete. Logged loudly because the
							// user-visible symptom (the connection just fails) says nothing about why, and the
							// two causes — nobody completed the ceremony, versus the ceremony completed but the
							// grant never arrived — need different fixes.
							log.Printf("east_west_stepup_incomplete device=%s dst=%s:%d service=%s waited=%s — no grant arrived; the held flow is dropped and the client must retry",
								transportDeviceID, host, port, req.ServiceFamily, steerMuxStepUpGrantWait)
							return
						}
					} else {
						// ★★★ A DENIAL IS NOT DEBUG, AND IT HAS TO NAME THE DESTINATION (2026-08-25, measured).
						//
						// A flow the Edge decides against closes with zero bytes. From the device that is
						// indistinguishable from a network failure; from the operator it was invisible, because
						// this was the only line and it was at debug level and carried a PORT and no host. Four
						// Edges, an internal destination and a public one, and not one line naming either.
						//
						// "It does not work and nothing says why" is the shape this deployment keeps recording.
						// The decision is the one thing here that is certainly worth a line: it is rare (an
						// allowed flow does not take this branch), it is what somebody is looking for, and
						// without it the only remaining explanation is the network.
						logWarnf("steer_mux_denied device=%q host=%s dst_port=%d family=%s decision=%s reason=%q "+
							"— the flow was closed with no bytes; from the device this looks like a network "+
							"failure, so this line is the only place it does not",
							transportDeviceID, host, port, req.ServiceFamily, dec.Decision, steerDenialReason(dec))
						return
					}
				}
			}
			// Warn stage (S3, learning lifecycle): a matched authenticate/deny rule under Warn ALLOWED this flow
			// (non-holding) but asks us to surface a passive "monitored; authentication will soon be required"
			// notice. Sent once per (service:destination) per mux connection (~device session); the agent
			// coalesces display further. It never holds or closes the flow — forwarding proceeds below.
			if payload, ok := edgeplane.SteerMuxWarnNoticePayload(dec); ok {
				if vc.WarnOnce(req.ServiceFamily + "|" + host) {
					_ = vc.SendWarnNotice(payload)
					logDebugf("steer_mux_warn_notice host=%s dst_port=%d family=%s", host, port, req.ServiceFamily)
				}
			}
			logDebugf("steer_mux_forwarded host=%s dst_port=%d family=%s", host, port, req.ServiceFamily)
			route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: host, Port: port, DeviceIdentity: transportDeviceID, OSUser: osUser, SourceApp: sourceApp, TenantID: req.TenantID, TunnelSourceIP: edgeplane.RemoteAddrString(clientConn), BuiltBy: "steer-mux"}
			if err := steerEgressForward(r.Context(), vc, authority, route, steerInterceptionDialer); err != nil {
				// Coalesced per target: a client retrying one unreachable host sets this line's rate, not the
				// operator. First failure reports immediately; identical repeats fold into a summary count.
				// Keyed by TARGET only (host|port), not by error category: on success we must be able to clear
				// the window, and success carries no category to rebuild a category-keyed key from. The category
				// still rides the message.
				category := edgeplane.NetworkExtensionLabTLSErrorCategory(err)
				key := fmt.Sprintf("%s|%d", host, port)
				if report, suppressed := edgeplane.SteerEgressFailureCoalescer.Observe(key); report {
					// ★★★ AND WHETHER A CONNECTOR FRONTS IT (2026-08-26). "Egress failed" for an INTERNAL
					// destination reads as a network fault, and the two causes need opposite fixes: the Edge
					// dialled the public internet because no connector claims this name (the binding is
					// missing, or has not reached this node), or it chose a connector and could not reach it.
					// Resolved here and not per flow: this is the error path, which is rare, and it is the one
					// moment the answer is worth a round trip.
					// ★★★ AND WHAT WENT WRONG, WHICH THIS LINE HELD AND DID NOT SAY (2026-09-01). It printed a
					// CATEGORY — "unknown_nonsecret" — and a note about the route layer, while `err` sat in
					// scope carrying the actual failure. On a flow to a connector-fronted destination the
					// note says "the failure is the route layer reaching it", which is true and names
					// nothing; the reason a session could not be opened is in the error and only there.
					logErrorf("steer_mux_egress_failed host=%s dst_port=%d category=%s%s%s: %v", host, port, category,
						steerEgressRepeatSuffix(suppressed), steerConnectorRouteNote(r.Context(), registry,
							req.TenantID, host), err)
				}
			} else {
				// Recovered: drop the window so the NEXT failure for this target is reported at once rather than
				// being swallowed as a "repeat" of an old, already-resolved storm.
				edgeplane.SteerEgressFailureCoalescer.Forget(fmt.Sprintf("%s|%d", host, port))
			}
		})
		logDebugf("steer_mux_closed")
	})
	networkExtensionRuntimeCopyTenantID := runtimeEvaluatorForPolicyStore(evaluator, policyStore).PolicyBundle.TenantID
	networkExtensionRuntimeCopySessions := edgeplane.NewNetworkExtensionRuntimeCopySessionManager(0, 0, nil)
	swgEgressConfig := edgeSWGHTTPEgressHandlerConfig{
		TenantCARegistry:              config.TenantCARegistry,
		Evaluator:                     evaluator,
		PolicyStore:                   policyStore,
		PolicyCandidateStore:          policyCandidateStore,
		StripAltSvc:                   config.StripAltSvc,
		Writer:                        writer,
		Registry:                      registry,
		ProxyClient:                   proxyClient,
		InternalCAs:                   config.InternalCAs,
		SWGRuntime:                    swgRuntime,
		SessionStore:                  sessionStore,
		HighRiskOverlay:               config.HighRiskOverlay,
		EnrolledLedger:                config.EnrolledLedger,
		DeviceStore:                   deviceStore,
		HumanApprovals:                humanApprovals,
		DelegatedGrants:               delegatedGrants,
		NonHumanIdentities:            nonHumanIdentities,
		DecisionStore:                 decisionStore,
		InspectionEvents:              inspectionEvents,
		DLPRules:                      dlpRuleStore,
		DLPClassifiers:                dlpClassifierStore,
		DLPAllowlist:                  dlpAllowlistStore,
		DLPFingerprints:               dlpFingerprintStore,
		Entitlements:                  entitlementStore,
		DLPDeviceRisk:                 dlpDeviceRisk,
		DLPPolicies:                   dlpPolicyObjects,
		CorporateDomains:              corporateDomainsResolver(organizationDomains, idpConnectionStore),
		DomainEventOutbox:             domainEventOutbox,
		AdminAuditOutbox:              adminAuditOutbox,
		UsageMeters:                   usageMeters,
		WorkloadAttestationSecret:     workloadAttestationSecret,
		LabMode:                       devMode,
		WorkloadAttestations:          workloadAttestations,
		ConnectorSecret:               connectorSecret,
		RequireConnectorRuntimeSecret: requireConnectorRuntimeSecret,
		DLPBlockUninspectableFiles:    config.DLPBlockUninspectableFiles,
	}
	// Trusted in-process variant for the NE/WFP decrypt-all forward: skips connector authorization because the
	// flow was already device-authenticated at the (T) transport mTLS layer + admitted via enrolled inventory
	// (see DeviceAuthenticatedInProcess). Wired ONLY to SetHTTPHandler below, NEVER to the external mux route —
	// so the auth skip is structurally unforgeable. This is what runs decrypt-all egress without -lab-mode (GAP-1).
	swgEgressDeviceConfig := swgEgressConfig
	swgEgressDeviceConfig.DeviceAuthenticatedInProcess = true
	// Make the INTERCEPT (decrypt-all) egress path connector-aware too: when the Edge re-originates a decrypted
	// request whose destination is fronted by a live connector, the upstream connection goes THROUGH that
	// connector's tunnel (the bypass path already does this via edgeplane.ConnectorEgressDialer). Scoped to the device
	// egress client only; the external connector-route handler keeps its own client. Self-gating — a host fronted
	// by no connector route dials exactly as before.
	// The flow tenant's residency boundary (allowed regions) — the reach layer denies a connector whose region is
	// outside it. Resolved per-flow from the admin tenant model; nil for an unpinned tenant (no restriction).
	tenantResidency := edgeplane.ResidencyResolver(func(tenantID string) []string {
		if tenantModelStore == nil {
			return nil
		}
		tenant, err := tenantModelStore.Get(context.Background(), tenantID)
		if err != nil {
			return nil
		}
		return tenant.AllowedRegions
	})
	// Multi-region MESH: peerEdges/meshEligible come from -mesh-peers/-mesh-eligible-hosts. Both nil when
	// the fabric is unconfigured, so mesh fails closed (self-gating) and every cross-region app hairpins.
	if config.SWGEgressBrowserMimic {
		// Browser-faithful egress, chosen per destination. The public web re-originates through the broker's real
		// Chrome stack; a destination fronted by a LIVE connector goes through that connector's tunnel instead,
		// because an internal app has no bot management in front of it and the broker — a separate process with no
		// knowledge of the route layer — would direct-dial into internal address space, where the SSRF pre-flight
		// then refuses it. Without this split, publishing an app behind a connector makes it UNREACHABLE from a
		// steered browser, which is the core promise of the product.
		mimicConnectorDial := edgeplane.ConnectorEgressDialContextWithCandidates((&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: swg.EgressControl}).DialContext, connectorDestinationResolver(registry), connectorDestinationCandidates(registry), tunnelManager, networkExtensionRuntimeCopyTenantID, evaluator.EdgeRegionID, tenantResidency, config.PeerEdges, config.MeshEligible)
		mimicConnectorTransport := &http.Transport{
			DialContext:         mimicConnectorDial,
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		}
		mimicClient := *proxyClient
		// The browser-faithful broker (curl-impersonate) is the ONLY egress engine on this path — the in-process
		// fhttp/utls mimic was deleted because it does not work on the bot-managed web, so falling back to it turned
		// "the broker is down" into scattered origin-dependent breakage. An unconfigured broker is therefore a
		// startup failure, not a degraded mode (docs/edge_broker_ha_and_health_design.md).
		brokerEgress, err := edgeplane.NewBrokerEgressRoundTripper()
		if err != nil {
			log.Fatalf("swg egress: %v", err)
		}
		// Fold broker health into THIS node's readiness (/healthz): the broker is required with no fallback, so
		// "Edge ready, broker dead" is a lie to the balancer. Cached probe on a timer; the /healthz handler above
		// reads the cache. Startup itself is not gated — the first probe runs async, and an unusable broker at
		// boot flips readiness within ~3 probes rather than blocking the process.
		//
		// Skipped entirely when the engine is EMBEDDED in this process: there is no broker to probe, and probing
		// the sidecar anyway means a deployment that dropped it (the point of embedding) reports itself UNREADY
		// while its egress works perfectly. Observed live on the first unified deployment, where /healthz kept
		// publishing an egress_broker section for a service the Edge no longer talked to. A readiness gate that
		// reports a failure the node does not have is worse than no gate.
		if !edgeplane.EgressEngineEmbedded {
			brokerURL, err := edgeplane.EgressBrokerURLFromEnv()
			if err != nil {
				log.Fatalf("swg egress: %v", err)
			}
			brokerHealth = edgeplane.NewBrokerHealthMonitor(brokerURL, 5*time.Second, log.Printf)
			brokerHealth.Start()
		}
		mimicClient.Transport = edgeplane.NewConnectorOrBrokerRoundTripper(connectorDestinationResolver(registry), networkExtensionRuntimeCopyTenantID, mimicConnectorTransport, brokerEgress)
		swgEgressDeviceConfig.ProxyClient = &mimicClient
		// ★★★ AND THE EXTERNAL ROUTE TOO, WHICH IS WHERE THE AGENTS ACTUALLY ARRIVE (2026-08-18).
		//
		// This was set on the in-process handler ONLY, on the reading that "the macOS NE / Windows WFP
		// decrypt-all egress is served in process". The NE's decrypt-and-forward reaches the edge over the wire
		// at /swg/http-egress instead — the runtime-copy path, which is why the request carries an NE-runtime
		// header whose value is literally "runtime_copy_lab_tls" and why the shared handler has to ask. So the
		// engine every steered device actually egressed through was Go's, and the browser-faithful engine ran
		// for a path that carries almost nothing.
		//
		// Measured: partner.microsoft.com returned the edge's own 502 to a steered browser, on Windows and on
		// this Mac, with a Go crypto/tls error — while the SAME url through the broker returned 301, and the
		// engine's own log showed it had already chased and KEPT the missing cross-signed link:
		//
		//   egress engine: AIA chase learned "Microsoft TLS ECC Root G2" (issued by "DigiCert Global Root G3")
		//
		// The link AIA learns is added to the CURL side's bundle. The Go path never consults it, so every
		// AIA-dependent origin is unreachable through the product while being fine in a plain browser — and
		// during six requests after that line was logged, the engine logged no chase at all, because nothing
		// reached it. Bot-mitigated origins were the same story for the same reason.
		//
		// Connector authorization is untouched: that gate is about who may CALL the route, and this is about
		// which stack dials the origin. Connector-fronted destinations still tunnel — the round tripper picks
		// per destination — so an internal app is unaffected.
		swgEgressConfig.ProxyClient = &mimicClient
		log.Printf("swg egress: BROWSER-FAITHFUL egress enabled (curl-impersonate via the broker; connector-fronted destinations tunnel instead) on the device decrypt-all path, in process AND on the external %s route the agents use", edgeplane.EdgeSWGHTTPEgressPath)
	} else {
		// Engine unchanged on this branch: with the browser-faithful engine off there is nothing to choose, and
		// the external route keeps the client the deployment handed in. Only the ENGINE has to be paired.
		swgEgressDeviceConfig.ProxyClient = edgeplane.ConnectorAwareProxyClient(proxyClient, connectorDestinationResolver(registry), tunnelManager, networkExtensionRuntimeCopyTenantID, evaluator.EdgeRegionID, tenantResidency, config.PeerEdges, config.MeshEligible)
	}
	// Only the steered (decrypt-all) device path gets the federated-auth gate: an "authenticate" decision on
	// a browser flow redirects to the IdP instead of 401. The external connector route keeps serving 401.
	swgEgressDeviceConfig.FederatedAuthGate = federatedAuthGateForEgress
	swgHTTPEgressDeviceHandler := newEdgeSWGHTTPEgressHandler(swgEgressDeviceConfig)
	// External /swg/http-egress route: connector-gated (untrusted callers). Built HERE, after the egress engine
	// is chosen, because the handler captures its config BY VALUE — built before the choice it would keep the
	// plain Go client no matter what the flag said, which is precisely the bug above.
	swgHTTPEgressHandler := newEdgeSWGHTTPEgressHandler(swgEgressConfig)
	// ★ DIAGNOSTIC (2026-08-18): name the concrete egress transport of BOTH handlers at startup.
	//
	// partner.microsoft.com still fails with a Go crypto/tls error after the browser-faithful client was put on
	// both handlers, and the engine logs ZERO AIA chase attempts for it — so the request is reaching neither
	// handler's client, or one of them is not what this code believes it is. Reading the wiring has now been
	// wrong twice; this prints what is actually there.
	log.Printf("swg egress: transports — in-process=%T external(%s)=%T",
		swgEgressDeviceConfig.ProxyClient.Transport, edgeplane.EdgeSWGHTTPEgressPath, swgEgressConfig.ProxyClient.Transport)
	networkExtensionRuntimeCopySessionDialer := edgeplane.NetworkExtensionRuntimeCopyTCPDialer(edgeplane.NetworkExtensionRuntimeCopyNetDialer{})
	// Make raw_forward/bypass egress connector-aware (route layer): a steered flow whose destination is fronted
	// by a LIVE connector egresses THROUGH that connector's tunnel; every other destination direct-dials exactly
	// as before (self-gating — no reachable_routes configured means no match). Reachability only; policy still
	// authorizes the flow. This wraps the BASE dialer, so intercept decisions are unaffected (the interceptor
	// dials its own origin); only the bypass path consults the connector route layer.
	networkExtensionRuntimeCopySessionDialer = edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(registry),
		ListConnectors:   connectorDestinationCandidates(registry),
		Tunnels:          tunnelManager,
		TenantID:         networkExtensionRuntimeCopyTenantID,
		LocalRegion:      evaluator.EdgeRegionID,
		Residency:        tenantResidency,
		PeerEdges:        config.PeerEdges,
		MeshEligible:     config.MeshEligible,
		Direct:           networkExtensionRuntimeCopySessionDialer,
	}
	// ★★★ REACHING A CONNECTOR IS NOT A PROPERTY OF INSPECTION (2026-08-26, measured on the deployment the
	// installer generates, where it took an evening to find).
	//
	// The steer path's connector-aware dialer was assigned ONLY inside the block below — the one guarded on
	// TLS interception being configured. A deployment that does not intercept therefore steered every flow to
	// a DIRECT dial, including flows to internal destinations that a connector fronts. From the device that is
	// a connection that fails; from the Edge it is one line naming a category; and the connector sits there,
	// live, holding the route. In a real deployment (Edge in the cloud, host on-prem) the Edge cannot reach
	// those hosts at all, so this was not a slower path — it was no path.
	//
	// Whether to decrypt and where a destination LIVES are different questions. This sets the reachability
	// answer unconditionally; the interception branch below re-wraps it, keeping the connector-aware dialer
	// underneath, so an intercepting deployment behaves exactly as it did.
	steerInterceptionDialer = networkExtensionRuntimeCopySessionDialer
	if config.NetworkExtensionLabTLS != nil {
		config.NetworkExtensionLabTLS.SetHTTPHandler(swgHTTPEgressDeviceHandler)
		networkExtensionRuntimeCopySessionDialer = edgeplane.NetworkExtensionRuntimeCopyTLSInterceptionDialer{
			Base:                   networkExtensionRuntimeCopySessionDialer,
			Intercepter:            config.NetworkExtensionLabTLS,
			ProbeOnlyDropUnmatched: config.NetworkExtensionLabTLS.ProbeOnlyDropUnmatched(),
		}
		// Make the steer(-mux) intercept path connector-aware too: reuse the same connector-aware interception
		// dialer as the runtime-copy session path (its Base is edgeplane.ConnectorEgressDialer{direct: netDialer}), so a
		// steered flow to an INTERNAL connector-fronted host egresses THROUGH the connector's tunnel instead of a
		// direct Edge dial. Overwrites the direct-Base steerInterceptionDialer built earlier (the connector-route
		// fields — tenantID/residency/etc. — only come into scope here). The /steer-mux handler captured the
		// variable by reference, so it picks this up at request time. Self-gating: no connector fronts a host =>
		// direct dial, byte-identical. In a real deployment (Edge=cloud, host=on-prem) the Edge cannot reach
		// internal hosts directly, so this is required for the agent steer path to reach private apps.
		steerInterceptionDialer = networkExtensionRuntimeCopySessionDialer
	}
	// ★★★ WHOSE FLOW IS THIS. The three data-path handlers used to compare the device's tenant to THIS NODE's,
	// so a device correctly enrolled into a customer organization had every steered flow refused with
	// tenant_scope_mismatch — measured 2026-08-29 on a Mac this same Edge had itself admitted. The certificate
	// is the authority, which is what steerDeviceTenant has said since 2026-08-16 while pointing at the data
	// path as its model. One resolver, shared by all three, so they cannot drift.
	networkExtensionRuntimeCopyDeviceTenant := func(r *http.Request) (string, bool) {
		identity, _ := transportDeviceIdentityFromRequest(r)
		tenant := steerDeviceTenant(r, config, identity, networkExtensionRuntimeCopyTenantID)
		return tenant, strings.TrimSpace(tenant) != ""
	}
	mux.HandleFunc(edgeplane.NetworkExtensionRuntimeCopyRoundTripPath, edgeplane.NewNetworkExtensionRuntimeCopyRoundTripHandler(edgeplane.NetworkExtensionRuntimeCopyRoundTripHandlerConfig{
		TenantID:          networkExtensionRuntimeCopyTenantID,
		DeviceTenant:      networkExtensionRuntimeCopyDeviceTenant,
		TransportIdentity: transportDeviceIdentityFromRequest,
	}))
	mux.HandleFunc(edgeplane.NetworkExtensionRuntimeCopySessionPath, edgeplane.NewNetworkExtensionRuntimeCopySessionHandler(edgeplane.NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID:          networkExtensionRuntimeCopyTenantID,
		DeviceTenant:      networkExtensionRuntimeCopyDeviceTenant,
		Dialer:            networkExtensionRuntimeCopySessionDialer,
		SessionManager:    networkExtensionRuntimeCopySessions,
		TransportIdentity: transportDeviceIdentityFromRequest,
	}))
	mux.HandleFunc(edgeplane.NetworkExtensionRuntimeCopyTunnelPath, edgeplane.NewNetworkExtensionRuntimeCopyTunnelHandler(edgeplane.NetworkExtensionRuntimeCopyTunnelHandlerConfig{
		TenantID:          networkExtensionRuntimeCopyTenantID,
		DeviceTenant:      networkExtensionRuntimeCopyDeviceTenant,
		Dialer:            networkExtensionRuntimeCopySessionDialer,
		TransportIdentity: transportDeviceIdentityFromRequest,
	}))
	mux.HandleFunc(edgeplane.EdgeSWGHTTPEgressPath, swgHTTPEgressHandler)
	mux.HandleFunc("GET "+swg.EdgeSWGTLSReadinessStatusPath, func(w http.ResponseWriter, r *http.Request) {
		runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, runtimeEvaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		writeJSON(w, http.StatusOK, swg.EdgeSWGTLSReadinessStatusFor(runtimeEvaluator, swgRuntime, inspectionEvents, edgeplane.EdgeSWGHTTPEgressPath))
	})
	mux.HandleFunc("POST /logs/access", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		appendRawJSONL(w, r, writer, "access.log.jsonl", tcaReg)
	})
	mux.HandleFunc("POST /logs/audit", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		appendRawJSONL(w, r, writer, "audit.log.jsonl", tcaReg)
	})
	// ★ REMOVED 2026-09-04: "GET /dummy/private-app", which answered {"application_id":"app_dummy_https",
	// "status":"reachable"} on every Edge in every deployment — a hard-coded 200 about an application that
	// does not exist, reachable before any connector had registered. It had no caller.
	// One per server: what it remembers is "have I told the authority about this connector recently", which
	// is a property of this node's conversation with the authority and of nothing else.
	connectorLiveness := newConnectorLivenessCarrier()
	mux.HandleFunc("POST /connectors/register", func(w http.ResponseWriter, r *http.Request) {
		var req model.ConnectorRegistration
		if err := decodeLimitedJSONBody(w, r, &req, maxConnectorRegistrationBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode connector registration: %w", err))
			return
		}
		if err := connectorTenantIsAdmitted(r.Context(), siteStore, req.TenantID, req.ConnectorGroupID,
			evaluator.PolicyBundle.TenantID); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		// A brand-new connector may present its Site's one-time bootstrap secret (carried in the enrollment token)
		// instead of the fleet-shared secret — that's how a token-only bring-up self-registers into its Site.
		// An already-known connector re-registers with its runtime secret, handled by the fallback below.
		if !connectorRegistrationSiteBootstrapAuthorized(r.Context(), siteStore, req.ConnectorGroupID, req.TenantID, r.Header.Get(connectorSecretHeader)) {
			if !authorizeConnectorRegistrationRequest(w, r, connectorSecret, registry, req.ID, req.TenantID, config.TenantCARegistry) {
				return
			}
		}
		// ★★★ WHICH REGION A CONNECTOR IS IN IS NOT THE CONNECTOR'S TO CLAIM (2026-08-25, measured while
		// bringing an inter-region mesh up).
		//
		// It arrived in the request body, defaulting to the connector binary's own default, "local". Every
		// token-enrolled connector in a generated deployment therefore registered as being in a region that
		// does not exist — and the mesh decision is made ON THIS FIELD: an Edge asks "is this connector's
		// region mine?", gets "local" against "region-b", and treats a connector sitting in its own region as
		// remote. So the relay could never be routed correctly, for any connector enrolled the supported way.
		//
		// The region a connector is in IS the region of the Edge it joined. That Edge is the one running this
		// code and it knows its own region, the same way a flow's tenant comes from the CA that issued the
		// certificate rather than from a field the caller filled in.
		req.EdgeRegionID = strings.TrimSpace(evaluator.EdgeRegionID)
		conn, err := registry.Register(req, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Route governance: record the advertised routes. First sight grandfathers the current set; a route
		// advertised LATER (a re-register with a new CIDR) is pending until an operator approves it.
		if connectorRouteGov != nil {
			connectorRouteGov.SeeRoutes(conn.TenantID, conn.ID, conn.ReachableRoutes.CIDRs, time.Now())
		}
		// A connector's routes ARE this tenant's declaration of what is internal, so the east-west plane
		// boundary moves with them. Refreshed here rather than read at decision time: the decision path must
		// not depend on a registry round-trip per flow.
		refreshEastWestInternalNetworks(r.Context(), policyStore, registry, conn.TenantID)
		// ★★★ AND THE AUTHORITY IS TOLD. A connector reaches only an Edge, so without this the deployment's
		// authority never learns it exists — and there is no POST /admin/connectors, so nobody can create it
		// there either. What follows a registration is an operator NAMING it and giving it ROUTES, and both of
		// those are writes to the control plane. See connector_cp_report.go.
		if connectorCPReport != nil {
			connectorCPReport.Report(connectorReport{Registration: conn, TenantID: conn.TenantID})
		}
		if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("connector_registered", conn, nil), time.Now()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, publicConnectorRegistration(conn))
	})
	mux.HandleFunc("POST /connectors/{connector_id}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeConnectorRuntimeRequest(w, r, connectorSecret, registry, r.PathValue("connector_id"), evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		var req model.ConnectorHeartbeat
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode connector heartbeat: %w", err))
			return
		}
		if req.ID == "" {
			req.ID = r.PathValue("connector_id")
		}
		// A heartbeat carries no Site, so the Site is read from what this connector registered as — the
		// registration is where the organization was already admitted, and repeating that decision is the
		// point. A connector this node has never seen falls through to the node's own organization.
		heartbeatSite := ""
		if known, ok := registry.Get(req.ID); ok {
			heartbeatSite = known.ConnectorGroupID
		}
		if err := connectorTenantIsAdmitted(r.Context(), siteStore, req.TenantID, heartbeatSite,
			evaluator.PolicyBundle.TenantID); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		// Capture the prior status so a steady-state heartbeat (no change) records NOTHING — only a STATE CHANGE
		// is an event worth a row . Liveness itself is state, not a
		// per-beat event; recording every ~30s beat floods the connector log and buries real transitions.
		priorStatus := ""
		if prev, ok := registry.Get(req.ID); ok {
			priorStatus = prev.Status
		}
		conn, err := registry.Heartbeat(req, time.Now())
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		// Live discovery refresh: when the heartbeat re-reports the connector's routes, refresh the discovery
		// timing + apply the fail-safe to any NEWLY seen CIDR — without a reconnect. Discovery only (routing is
		// CP-configured). See docs/connector_network_route_advertisement_design.md.
		if connectorRouteGov != nil && req.ReachableRoutes != nil {
			connectorRouteGov.SeeRoutes(conn.TenantID, conn.ID, conn.ReachableRoutes.CIDRs, time.Now())
		}
		if req.ReachableRoutes != nil {
			refreshEastWestInternalNetworks(r.Context(), policyStore, registry, conn.TenantID)
		}
		// Liveness is STATE, not an event: a row per beat (~every 30s per connector) floods the Connector tab
		// and buries the transitions that matter. Record ONLY when the status actually changed (e.g. a recovery
		// from offline/degraded); a steady healthy→healthy beat is silent. Freshness is served from the
		// connector object's last-seen, not from a log row.
		if strings.TrimSpace(conn.Status) != strings.TrimSpace(priorStatus) {
			if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("connector_status_changed", conn, map[string]any{"previous_status": priorStatus, "status": conn.Status}), time.Now()); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		// ★★★ AND THE AUTHORITY LEARNS THAT IT IS ALIVE. Without this the control plane's copy stops at the
		// moment of registration and every connector reads Offline on the Console for ever — see
		// a_connectors_liveness_has_to_reach_the_authority.go, found by looking at the screen.
		if connectorCPReport != nil && connectorLiveness.shouldCarry(conn.ID, conn.Status, evaluator.EdgeRegionID, time.Now()) {
			connectorCPReport.Report(connectorReport{Registration: conn, TenantID: conn.TenantID,
				AttachedRegionID: evaluator.EdgeRegionID})
		}
		writeJSON(w, http.StatusAccepted, conn)
	})
	// Effective reachable routes for a connector: its self-declared set UNION the admin-authored routes. The
	// connector polls this and merges it into its SSRF allowlist, so a flow the Edge routes to it for an
	// admin-authored destination is accepted (without it, the connector refuses — the route it never declared).
	// Connector-authenticated (same gate as heartbeat). See docs/connector_network_route_advertisement_design.md.
	mux.HandleFunc("GET /connectors/{connector_id}/effective-routes", func(w http.ResponseWriter, r *http.Request) {
		cid := r.PathValue("connector_id")
		if !authorizeConnectorRuntimeRequest(w, r, connectorSecret, registry, cid, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		// ★★★ THE CONNECTOR'S OWN ORGANIZATION, NOT THIS NODE'S (2026-09-01, measured on a customer's
		// connector in its own VPC — the fourth of this family in one day).
		//
		// This looked the connector's registrations up under the bundle THIS EDGE pulled, which on a
		// deployment that serves customers is the operator's. So the loop below matched nothing, the answer
		// was {} — a 200 carrying an empty set — and the connector's SSRF guard stayed empty, which is
		// fail-closed and denies every dial.
		//
		// The two halves then disagreed in the worst possible way: the Edge CHOSE this connector for the
		// destination (connector_route_chosen host="10.60.1.176" connector="conn-…") and the connector
		// refused to dial it, so the flow died between two components that were each behaving correctly.
		// Nothing in either log says "the route never reached the connector".
		//
		// The registry holds which organization this connector registered under — that registration is where
		// the organization was admitted — so the tenant comes from there, and only falls back to this node's
		// own when the connector is unknown here (a single-tenant deployment, where they are the same).
		tenant := evaluator.PolicyBundle.TenantID
		if known, ok := registry.Get(cid); ok && strings.TrimSpace(known.TenantID) != "" {
			tenant = strings.TrimSpace(known.TenantID)
		}
		eff := model.ConnectorReachableRoutes{}
		if conns, cerr := connectorRegistrationsForTenantWithContext(r.Context(), registry, tenant); cerr == nil {
			for _, c := range conns {
				if c.ID == cid {
					// The connector's enforcement copy must MATCH the route layer: return the GOVERNED set —
					// held / not-yet-adopted self-declared CIDRs dropped, site- and connector-authored bindings
					// added. Returning the raw declaration meant an operator Hold never reached the connector's
					// SSRF guard (found 2026-07-16, design verification).
					eff = c.ReachableRoutes
					if connectorRouteGov != nil {
						if applied := connectorRouteGov.Apply(tenant, []model.ConnectorRegistration{c}); len(applied) == 1 {
							eff = applied[0].ReachableRoutes
						}
					}
					break
				}
			}
		}
		writeJSON(w, http.StatusOK, eff)
	})
	// ★ THE DURABLE HALF OF A CONNECTOR'S CONFIGURATION. See connector_profile_route.go: the token is
	// one-time, so anything it carries is frozen on the day it was issued.
	registerConnectorProfileRoute(mux, func(w http.ResponseWriter, r *http.Request, cid string) bool {
		return authorizeConnectorRuntimeRequest(w, r, connectorSecret, registry, cid,
			evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry)
	}, evaluator.PolicyBundle.TenantID, strings.TrimSpace(config.ConnectorEnrollmentEdgeURL),
		connectorEnrollmentRegions, func(cid string) string {
			if c, ok := registry.Get(cid); ok {
				return c.ConnectorGroupID
			}
			return ""
		})
	mux.HandleFunc("GET /connectors/{connector_id}/tunnel", func(w http.ResponseWriter, r *http.Request) {
		connectorID := r.PathValue("connector_id")
		if !authorizeConnectorRuntimeRequest(w, r, connectorSecret, registry, connectorID, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
		conn, ok := registry.Get(connectorID)
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is not registered", connectorID))
			return
		}
		// ★ REFUSE BEFORE REGISTERING. A connector spreading over the fleet declares the nodes it already
		// holds; upgrading here would replace and close the session it is asking about. See
		// connectorAlreadyHoldsThisNode.
		if connectorAlreadyHoldsThisNode(r, edgeNodeIdentity()) {
			w.Header().Set(connectorReachedNodeHeader, edgeNodeIdentity())
			writeError(w, http.StatusConflict, fmt.Errorf("connector %s already holds a tunnel on this Edge node (%s); nothing was registered and its existing tunnel is untouched", connectorID, edgeNodeIdentity()))
			return
		}
		// Name this node on the handshake. A connector behind an L4 front door dialled the DOOR's address, so
		// this is the only moment it can learn which member of the fleet it actually reached.
		wsConn, err := tunnel.UpgradeWithHeaders(w, r, connectorTunnelHandshakeHeaders(edgeNodeIdentity(), currentEdgeRegionNodeCount(), siblingsRelayNow()))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tunnelID := randomEdgeID("tun_", time.Now().UTC())
		session, reconnect := tunnelManager.Register(connectorID, tunnelID, wsConn)
		log.Printf("connector_tunnel_attached connector=%s node=%s region=%s reconnect=%t — flows for what this connector fronts can be served from THIS node, and only this node",
			connectorID, edgeNodeIdentity(), evaluator.EdgeRegionID, reconnect)
		// ★★★ SAY WHERE IT IS, NOT WHERE IT SAID IT WOULD BE. This node is terminating the tunnel, so it is the
		// only party that knows which region the connector is actually in — the registration still names
		// wherever it enrolled, which after a failover is the region it LEFT. Recorded as runtime state, so a
		// connector moving between regions cannot move the deployment's config generation.
		if recorder, ok := registry.(connectorAttachmentRecorder); ok {
			if moved, err := recorder.RecordAttachedRegion(connectorID, evaluator.EdgeRegionID); err != nil {
				log.Printf("could not record where connector %s is attached (%s): %v — until this succeeds, "+
					"Edges elsewhere route this connector to whatever region its registration names", connectorID, evaluator.EdgeRegionID, err)
			} else if moved {
				log.Printf("connector_attached_region_changed connector=%s region=%s — the deployment now routes this connector here; before this, flows were being sent to the region it registered in",
					connectorID, evaluator.EdgeRegionID)
				// ★★★ AND TELL THE AUTHORITY, OR THIS REACHES NOBODY. On a deployment where the Edges read
				// their connector catalog FROM the control plane, recording it here writes the copy that gets
				// overwritten — measured: every other node went on routing to the region the connector left,
				// and the database held nothing. Sent only when it CHANGED, so a fleet of nodes all holding
				// one connector does not report on every reconnect.
				connectorCPReport.Report(connectorReport{Registration: conn, TenantID: conn.TenantID, AttachedRegionID: evaluator.EdgeRegionID})
			}
		}
		eventType := "connector_connected"
		if reconnect {
			eventType = "connector_reconnect"
		}
		if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit(eventType, conn, map[string]any{"tunnel_id": tunnelID}), time.Now()); err != nil {
			log.Printf("write connector connected log: %v", err)
		}
		runErr := session.Run()
		tunnelManager.Unregister(connectorID, tunnelID)
		details := map[string]any{"tunnel_id": tunnelID}
		if runErr != nil {
			details["reconnect_reason"] = runErr.Error()
		}
		if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("connector_disconnected", conn, details), time.Now()); err != nil {
			log.Printf("write connector disconnected log: %v", err)
		}
	})
	// Multi-region MESH ingress: the RECEIVER half of a peer-edge link. A sibling edge (region Y) dials
	// here and relays a mesh-eligible flow (already decrypted in Y) as tunnel frames; we bridge each TCP open into
	// THIS edge's local connector egress, so the connector that lives in this region fronts the backend. This edge
	// never decrypts the relayed bytes — decryption-locality (residency) holds by construction.
	mux.HandleFunc("GET /mesh/ingress/tunnel", func(w http.ResponseWriter, r *http.Request) {
		// Self-gate: serve the receiver half ONLY when this edge is configured to receive mesh links (an
		// allowed-peer set, or a mesh secret in lab). An unconfigured edge never exposes the ingress, even though
		// the handler shares the public (T)/data mux.
		if len(config.MeshIngressAllowedPeers) == 0 && config.MeshSecret == "" {
			writeError(w, http.StatusNotFound, fmt.Errorf("mesh ingress is not enabled on this edge"))
			return
		}
		// Authenticate the peer edge. With an allowlist configured this requires a VERIFIED mTLS identity that is
		// an AUTHORIZED sibling edge (secret fallback disabled). Without an allowlist (lab) it falls back to any
		// verified mTLS identity or the shared secret. See meshIngressAuth.
		meshAuth, ok := meshIngressAuth(r, config.MeshIngressAllowedPeers, config.MeshSecret, "x-mesh-secret")
		if !ok {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("mesh ingress requires an authorized peer-edge mTLS identity (allowlisted) or, in lab, a valid x-mesh-secret"))
			return
		}
		// Anti-replay: when a mesh secret is configured, the upgrade must carry a fresh, single-use, HMAC-signed
		// stamp (the upgrade has no body). Rejects a captured upgrade being replayed to open a new tunnel.
		if err := verifyMeshAntiReplay(r.Header, config.MeshSecret, nil, dataMeshReplayGuard, time.Now().UTC()); err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("mesh ingress anti-replay: %w", err))
			return
		}
		wsConn, err := tunnel.Upgrade(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Local egress for the relayed flow: this edge's connector-aware dialer with NO peer edges, so a mesh open
		// resolves to a LOCAL connector (edgeplane.ReachLocal) and can never re-mesh onward (no multi-hop).
		localDialer := edgeplane.ConnectorEgressDialer{
			ResolveConnector: connectorDestinationResolver(registry),
			// The mesh INGRESS side reaches a connector that is local to this region, so the candidate list
			// matters here too: the pair member this node holds a tunnel to is the one that must be used.
			ListConnectors: connectorDestinationCandidates(registry),
			Tunnels:        tunnelManager,
			TenantID:       networkExtensionRuntimeCopyTenantID,
			LocalRegion:    evaluator.EdgeRegionID,
			Residency:      tenantResidency,
			Direct:         edgeplane.NetworkExtensionRuntimeCopyTCPDialer(edgeplane.NetworkExtensionRuntimeCopyNetDialer{}),
		}
		log.Printf("mesh ingress link up from %s (auth=%s)", r.RemoteAddr, meshAuth)
		runErr := serveMeshIngressTunnel(r.Context(), wsConn, localDialer, networkExtensionRuntimeCopyTenantID,
			meshConnectorProber(registry, tunnelManager, evaluator.EdgeRegionID, tenantResidency))
		if runErr != nil {
			log.Printf("mesh ingress link from %s closed: %v", r.RemoteAddr, runErr)
		}
	})
	mux.HandleFunc("GET /connectors", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		connectors, err := connectorRegistrationsForTenantWithContext(r.Context(), registry, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, publicConnectorRegistrations(connectors))
	}))
	mux.HandleFunc("GET /connectors/{connector_id}/health", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		conn, ok, err := connectorRegistrationForTenantWithContext(r.Context(), registry, r.PathValue("connector_id"), adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is not registered", r.PathValue("connector_id")))
			return
		}
		writeJSON(w, http.StatusOK, publicConnectorRegistration(conn))
	}))
	mux.HandleFunc("POST /connectors/{connector_id}/runtime-secret/rotate", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		connectorID := r.PathValue("connector_id")
		if _, ok, err := connectorRegistrationForTenantWithContext(r.Context(), registry, connectorID, adminTenantIDFromRequest(r)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		} else if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is not registered", connectorID))
			return
		}
		var request connectorRuntimeSecretRotateRequest
		if r.Body != nil && r.ContentLength != 0 {
			if err := decodeLimitedJSONBody(w, r, &request, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode connector runtime secret rotation: %w", err))
				return
			}
		}
		runtimeSecret, err := connectorRuntimeSecretForRotation(request)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		now := time.Now().UTC()
		rotatedBy := adminPrincipalIDFromRequest(r)
		conn, ok, err := registry.RotateRuntimeSecretHashForTenantWithMetadata(adminTenantIDFromRequest(r), connectorID, connectorRuntimeSecretHash(runtimeSecret), now, rotatedBy)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is not registered", connectorID))
			return
		}
		details := map[string]any{
			"rotated_by": rotatedBy,
			"rotated_at": now.Format(time.RFC3339),
		}
		if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("connector_runtime_secret_rotated", conn, details), now); err != nil {
			log.Printf("write connector runtime secret rotation log: %v", err)
		}
		writeJSON(w, http.StatusOK, connectorRuntimeSecretRotateResponse{
			Connector:     publicConnectorRegistration(conn),
			RuntimeSecret: runtimeSecret,
			RotatedAt:     now.Format(time.RFC3339),
		})
	}))
	// ★ REMOVED 2026-09-04: "GET|CONNECT /apps/connector/dummy-private-app", two routes that rewrote the
	// request to name "app_dummy_https" and served it. Nothing in this repository called them, and on a
	// deployment they were published paths answering for an application nobody created. An application is
	// named in the path — "/apps/{application_id}" — and one that does not exist is a 404, which is the
	// truthful answer.
	mux.HandleFunc("GET /apps/{application_id}", func(w http.ResponseWriter, r *http.Request) {
		handleConnectorApplication(w, r, connAppDeps)
	})
	mux.HandleFunc("CONNECT /apps/{application_id}", func(w http.ResponseWriter, r *http.Request) {
		handleConnectorApplication(w, r, connAppDeps)
	})

	// Before anything this node presents reaches a device: would the fleet accept it? The guard ran on every
	// change made through the Console and on none made by redeploying, which is the path an operator uses.
	// LAST in this function, deliberately: the trust store opened above is what the fleet actually verifies
	// against, and judging the certificate against the seed file instead produced a false "devices would
	// refuse this" verdict that outlived the restart (2026-08-02).
	reportServedCertificatesAtStartup(config, refuseStartOnUnusableCertificateFlag)

	return mux
}

func appendAccessDecisionLogs(ctx context.Context, writer *logs.Writer, domainEventOutbox domainEventOutboxWriter, dec model.AccessDecision, now time.Time) error {
	accessLog := decision.AccessLogFromDecision(dec)
	// Write the config generation BEFORE the record that references it, so a reader never meets a
	// config_generation_id it cannot resolve (a crash between the two would otherwise strand the record).
	// This is a no-op after the first decision of a generation — the config changes at operator rate, not
	// traffic rate, which is the entire point ofa.
	appendConfigGenerationIfNew(writer, dec)
	if err := writer.Append("access.log.jsonl", accessLog); err != nil {
		return fmt.Errorf("write access log: %w", err)
	}
	if envelope, err := domainEventOutboxEnvelopeFromAccessLog(accessLog, now); err != nil {
		logErrorf("domain event outbox access log envelope: %v", err)
	} else {
		appendDomainEventOutbox(ctx, domainEventOutbox, envelope, now)
	}

	// The separate decision_trace.log.jsonl write + its outbox envelope were removed: the access log now
	// carries CacheStatus (the trace's only unique field) and already ⊇ the trace's metadata, so writing a second
	// near-identical record per decision was pure cost. Historical decision_trace rows remain readable.
	if breakGlassDecisionAuditRequired(dec) {
		if err := writer.Append("audit.log.jsonl", breakGlassDecisionAuditLog(dec, now)); err != nil {
			return fmt.Errorf("write break-glass audit log: %w", err)
		}
	}
	if delegatedAccessDecisionAuditRequired(dec) {
		if err := writer.Append("audit.log.jsonl", delegatedAccessDecisionAuditLog(dec, now)); err != nil {
			return fmt.Errorf("write delegated access audit log: %w", err)
		}
	}
	return nil
}

func eastWestChallengeFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(eastWestChallengeCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", false
	}
	return strings.TrimSpace(cookie.Value), true
}

func writeEastWestCeremonySuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><body><h2>Authentication complete</h2><p>You may now retry your connection.</p></body></html>"))
}

func randomURLToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// readEnrollmentEdgeCA loads the Edge transport CA PEM to fold into enrollment tokens (public, not a secret).
// A read error is non-fatal: the token simply omits the pinned CA and the operator supplies it another way.
func readEnrollmentEdgeCA(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		log.Printf("connector enrollment: could not read edge CA %q: %v (token will omit the pinned CA)", path, err)
		return ""
	}
	return string(pem)
}

func validateEdgeRuntimeSecretConfig(devMode bool, connectorSecret string) error {
	connectorSecret = strings.TrimSpace(connectorSecret)
	if devMode {
		return nil
	}
	if connectorSecret == "" {
		return fmt.Errorf("connector-secret is required when lab-mode is disabled")
	}
	if connectorSecret == defaultConnectorSecret {
		return fmt.Errorf("connector-secret must be changed from the local lab default when lab-mode is disabled")
	}
	if len(connectorSecret) < minProductionSecretLength {
		return fmt.Errorf("connector-secret must be at least %d chars when lab-mode is disabled (it authenticates connector runtime calls; use a long random secret)", minProductionSecretLength)
	}
	return nil
}

func validateConnectorTenant(connectorTenantID, expectedTenantID string) error {
	if connectorTenantID == "" {
		return fmt.Errorf("connector tenant_id is required")
	}
	if expectedTenantID != "" && connectorTenantID != expectedTenantID {
		return fmt.Errorf("connector tenant_id %s does not match edge tenant_id %s", connectorTenantID, expectedTenantID)
	}
	return nil
}

// publishedWebAppRoute reports whether the application is a PUBLISHED web private app with a routable
// destination (publish_protocol=="web" && published && destination!=""). Only such apps take the new
// CONNECT-over-tunnel HTTP-proxy data path; everything else (un-published, no destination, tcp/network
// publish protocol, or empty publish_protocol) keeps the legacy privateBaseURL HTTP-frame path — preserving
// the lab invariant. Fail-closed: a nil catalog or a read error returns false (legacy path).
func publishedWebAppRoute(ctx context.Context, catalog appcatalog.RuntimeStore, tenantID, applicationID string) bool {
	if catalog == nil {
		return false
	}
	entry, found, err := catalog.Get(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(applicationID))
	if err != nil || !found || !entry.Published {
		return false
	}
	if strings.TrimSpace(entry.Destination) == "" {
		return false
	}
	return strings.TrimSpace(entry.PublishProtocol) == "web"
}

func wantsHTMLResponse(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := strings.ToLower(r.Header.Get("accept"))
	return strings.Contains(accept, "text/html")
}

// publishedConnectorGroupForApplication returns the connector_group_id of a PUBLISHED catalog entry for the
// application, or "" when the catalog is unavailable, the entry is absent/unpublished, or it carries no group.
// Used as the fail-closed bridge between a connector-discovered published private app (which fronts behind a
// connector group rather than an enumerated application_ids list) and the live connector that serves it.
func publishedConnectorGroupForApplication(ctx context.Context, catalog appcatalog.RuntimeStore, tenantID, applicationID string) string {
	if catalog == nil {
		return ""
	}
	entry, found, err := catalog.Get(ctx, tenantID, applicationID)
	if err != nil || !found || !entry.Published {
		return ""
	}
	return strings.TrimSpace(entry.ConnectorGroupID)
}

// connectorForDestination resolves the connector that fronts `destination` (a host or IP literal) via the
// connectorRouteGov is the admin route-governance singleton (hold self-declared routes / add authored routes).
// nil-safe: Apply is the identity when unset (tests, and until wired in main).
var connectorRouteGov *connectorRouteGovernance

// connectorRouteGovPersistPath, when set (-connector-route-governance-store), makes the governance DECISIONS
// durable + SHARED across the HA fleet: every Edge mounting the same path reads the same held/approved/authored
// decisions, so routing is consistent fleet-wide and survives a restart. See docs/connector_network_route_advertisement_design.md.
var connectorRouteGovPersistPath string

// connectorRouteCPConfigured selects the CP-configured route model (-connector-routes-cp-configured), now the
// DEFAULT: a connector's self-reported subnets are non-authoritative discovery, routable only after an operator
// adopts them. Set false for the legacy grandfather escape hatch. See docs/connector_network_route_advertisement_design.md.
var connectorRouteCPConfigured bool

func deriveDecisionRequestActor(req model.DecisionRequest, delegatedGrants *delegatedgrant.Store) model.DecisionRequest {
	req.ActorType = ""
	if grantID := strings.TrimSpace(req.DelegatedAccessGrantID); grantID != "" && delegatedGrants != nil {
		if grant, ok := delegatedGrants.GetForTenant(strings.TrimSpace(req.TenantID), grantID); ok && strings.TrimSpace(grant.TenantID) == strings.TrimSpace(req.TenantID) {
			if strings.TrimSpace(req.ActorNHIID) == "" {
				req.ActorNHIID = strings.TrimSpace(grant.ActorNHIID)
			}
			if strings.TrimSpace(req.SubjectUserID) == "" {
				req.SubjectUserID = strings.TrimSpace(grant.SubjectUserID)
			}
			if strings.TrimSpace(req.HumanApprovalEventID) == "" && grant.ApprovalEventID != nil {
				req.HumanApprovalEventID = strings.TrimSpace(*grant.ApprovalEventID)
			}
		}
	}
	req.ActorType = derivedDecisionActorType(req)
	return req
}

func derivedDecisionActorType(req model.DecisionRequest) string {
	if strings.TrimSpace(req.DelegatedAccessGrantID) != "" || strings.TrimSpace(req.AgentTaskSessionID) != "" {
		return "delegated_agent"
	}
	if strings.TrimSpace(req.ActorNHIID) != "" {
		if strings.TrimSpace(req.ToolID) != "" || strings.TrimSpace(req.ToolActionType) != "" || strings.TrimSpace(req.HumanApprovalEventID) != "" {
			return "delegated_agent"
		}
		return "nhi"
	}
	return "human"
}

// policyConditionReferences reports whether condition `key` matches `want` (string, []any, or {op,value/values}).
func policyConditionReferences(conditions map[string]any, key, want string) bool {
	for _, v := range policyConditionStringValues(conditions, key) {
		if v == want {
			return true
		}
	}
	return false
}

// policyConditionStringValues flattens a policy condition value into its string members. It accepts a bare
// string, a []any list, or a {op,value} / {op,values:[…]} comparator shape — the same shapes the evaluator
// matches — and ignores anything else.
func policyConditionStringValues(conditions map[string]any, key string) []string {
	if conditions == nil {
		return nil
	}
	raw, ok := conditions[key]
	if !ok {
		return nil
	}
	values := []string{}
	switch typed := raw.(type) {
	case string:
		values = append(values, typed)
	case []any:
		for _, v := range typed {
			values = append(values, fmt.Sprint(v))
		}
	case []string:
		values = append(values, typed...)
	case map[string]any:
		switch fmt.Sprint(typed["op"]) {
		case "eq", "equals", "contains":
			if v, ok := typed["value"]; ok {
				values = append(values, fmt.Sprint(v))
			}
		case "in":
			if list, ok := typed["values"].([]any); ok {
				for _, v := range list {
					values = append(values, fmt.Sprint(v))
				}
			}
		}
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// steerMuxStepUpGrantWait bounds how long a held native flow is parked waiting for the OOB step-up ceremony to
// mint a grant before we give up and drop it (the client then retries). Long enough for a human to complete an
// interactive IdP login; short enough not to pin a native client past its own connect patience.
const steerMuxStepUpGrantWait = 120 * time.Second
const steerMuxStepUpPollInterval = 500 * time.Millisecond

// waitForStepUpGrant parks a held steer-mux flow until the device earns a live step-up grant (the OOB browser
// ceremony completed) or the bound elapses / the client gives up. Returns true only if a grant appeared, so the
// caller can resume forwarding on the same held connection (auto-release, task #5). It never blocks the mux
// demux: handleOpen runs per-flow in its own goroutine, and peer CLOSE still routes to vc via the demux loop.
func waitForStepUpGrant(ctx context.Context, gate *federatedAuthGate, deviceID, acr string, vc *edgeplane.MuxVirtualConn, maxWait time.Duration) bool {
	deadline := time.Now().Add(maxWait)
	t := time.NewTicker(steerMuxStepUpPollInterval)
	defer t.Stop()
	for {
		if gate.hasLiveGrant(deviceID, acr) {
			return true
		}
		select {
		case <-vc.Closed():
			return false // client/agent gave up (peer CLOSE) or the mux tore down
		case <-ctx.Done():
			return false
		case <-t.C:
			if !time.Now().Before(deadline) {
				return false
			}
		}
	}
}

func adminState(evaluator decision.Evaluator, tenantID string, writer *logs.Writer, registry connectorRegistryStore, deviceStore deviceRuntimeStore, enrolledLedger *enrolledinventory.Ledger, humanApprovals *humanapproval.Store, delegatedGrants *delegatedgrant.Store, decisionStore *accessdecision.Store, inspectionEvents *inspection.Store, routeProfiles map[string]edgeplane.ApplicationRouteProfile, enforcementEdge bool) (map[string]any, error) {
	recentLogs, err := adminRecentLogs(writer, tenantID)
	if err != nil {
		return nil, err
	}
	connectors, err := connectorRegistrationsForTenantWithContext(context.Background(), registry, tenantID)
	if err != nil {
		return nil, err
	}
	devices, err := devicesForTenant(deviceStore, tenantID)
	if err != nil {
		return nil, err
	}
	applications := adminApplications(routeProfiles)
	// ★ THE NODE'S BUNDLE IS NOT THE CALLER'S POLICY SET (2026-08-16, measured). This listed every policy the
	// node evaluates, so a customer with ONE policy of their own was shown three — two of them another
	// organization's, by id, with their decision and priority. /admin/policies right beside it had been
	// filtering by the caller's organization the whole time.
	policies := adminPolicies(policiesForTenant(evaluator.Policies, tenantID))
	return map[string]any{
		"tenant_id": tenantID,
		"edge": map[string]any{
			"edge_region_id":  evaluator.EdgeRegionID,
			"edge_cluster_id": evaluator.EdgeClusterID,
		},
		// ★★ NOT ANOTHER ORGANIZATION'S BUNDLE IDENTITY (2026-08-22) — see policyBundleFactsForTenant.
		"policy_bundle": policyBundleFactsForTenant(evaluator.PolicyBundle.TenantID, evaluator.PolicyBundle.ID,
			evaluator.PolicyBundle.Version, evaluator.PolicyBundle.Status, evaluator.PolicyBundle.BundleType,
			tenantID),
		"applications": applications,
		"policies":     policies,
		// ★ THESE FOUR WERE THE NODE'S TOTALS, HANDED TO WHOEVER ASKED (2026-08-16, measured as a customer
		// administrator: 272 access decisions and 5000 inspection events on an organization with one device).
		// A number about other people's traffic, under this organization's name. Every one of these records
		// carries the organization it belongs to, so the count can simply be the caller's own.
		"counts": map[string]any{
			// ★★★ NOT ZERO FROM A NODE THAT HOLDS NO EVALUATOR FOR THIS ORGANIZATION (2026-09-05, seen on the
			// Console of a deployment stood up from the published tree). A control plane decides nothing, so
			// its evaluator carries no policies for a customer organization and this counted 0 — while the
			// Edge, asked the same question about the same organization, answered 1, and the organization's
			// own Internet Access screen showed that rule as Active. The Overview tile printed "POLICIES 0"
			// for an organization that was being enforced.
			//
			// The tile already knows how to say "unknown": it renders "—" for null. So a node that cannot
			// answer says nothing rather than saying none. Same rule as the organization checklist, which
			// marks this fact as the enforcement edge's.
			"policies":     policyCountForThisNode(policies, enforcementEdge),
			"applications": len(applications),
			"connectors":   len(connectors),
			// ★★★ THE WORD "devices" MEANS ENROLLED, AND IT USED TO MEAN PRESENT (2026-08-27, reported from
			// real hardware by win-dev-1 and confirmed here). This counted the RUNTIME store — a cache of who
			// is currently connected — which a generated deployment keeps in memory, so it returned to zero
			// every time an Edge restarted while the roster still held every device. An operator watched
			// their fleet vanish and come back.
			//
			// ★★ AND IT IS NOT THE NUMBER THEY ARE BILLED ON. The licence counts ledger.CountAdmitted — the
			// enrolled inventory — so the screen was showing a different number under the same word as the
			// one on the invoice. Whatever else a deployment shows, "how many devices do I have" has to be
			// the answer that is durable and that money is counted against.
			//
			// Presence is a real question too and keeps its own name below, so nothing that wanted it loses it.
			// Endpoints, not agents: the connectors are counted on their own tile and listed on their own
			// screen. See adminEnrolledEndpointCount.
			"devices":           adminEnrolledEndpointCount(enrolledLedger, tenantID, len(devices), connectorIdentitiesFor(registry, tenantID)),
			"agents":            adminEnrolledDeviceCount(enrolledLedger, tenantID, len(devices)),
			"devices_present":   len(devices),
			"access_decisions":  dataplaneCountForThisNode(adminStateCount(tenantID, decisionStore.Count, func() int { return len(decisionStore.SnapshotByTenant(tenantID)) }), enforcementEdge),
			"inspection_events": dataplaneCountForThisNode(adminStateCount(tenantID, inspectionEvents.Count, func() int { return len(inspectionEvents.ListByTenant(tenantID)) }), enforcementEdge),
			"human_approval_events": adminStateCount(tenantID, humanApprovals.Count, func() int {
				return countByTenant(humanApprovals.Snapshot(), tenantID, func(e model.HumanApprovalEvent) string { return e.TenantID })
			}),
			"delegated_access_grants": adminStateCount(tenantID, delegatedGrants.Count, func() int {
				return countByTenant(delegatedGrants.Snapshot(), tenantID, func(g model.DelegatedAccessGrant) string { return g.TenantID })
			}),
			"recent_log_streams_count": len(recentLogs),
		},
		"recent_logs": recentLogs,
	}, nil
}

func adminApplications(routeProfiles map[string]edgeplane.ApplicationRouteProfile) []map[string]any {
	ids := make([]string, 0, len(routeProfiles))
	for id := range routeProfiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	apps := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		profile := routeProfiles[id].WithDefaults(id)
		apps = append(apps, map[string]any{
			"application_id":          id,
			"service_family":          profile.ServiceFamily,
			"destination":             profile.Destination,
			"destination_port":        profile.DestinationPort,
			"destination_role":        profile.DestinationRole,
			"application_sensitivity": profile.ApplicationSensitivity,
			"private_path":            profile.PrivatePath,
		})
	}
	return apps
}

func adminPolicies(policies []model.Policy) []map[string]any {
	copied := append([]model.Policy(nil), policies...)
	sort.SliceStable(copied, func(i, j int) bool {
		if copied[i].Priority != copied[j].Priority {
			return copied[i].Priority < copied[j].Priority
		}
		return copied[i].ID < copied[j].ID
	})
	result := make([]map[string]any, 0, len(copied))
	for _, policy := range copied {
		result = append(result, map[string]any{
			"id":                            policy.ID,
			"name":                          policy.Name,
			"priority":                      policy.Priority,
			"decision":                      policy.Action.Decision,
			"status":                        policy.Status,
			"conditions_count":              len(policy.Conditions),
			"service_family":                stringPtrValue(policy.ServiceFamily),
			"required_human_approval":       policy.RequiredHumanApproval,
			"required_token_binding":        policy.RequiredTokenBinding,
			"required_workload_attestation": policy.RequiredWorkloadAttestation,
		})
	}
	return result
}

// adminRecentLogs is the "latest line of each stream" convenience on the state page.
//
// ★★★ IT WAS THE LATEST LINE FULL STOP, WHOEVER ASKED (2026-08-16, measured signed in as Northwind's
// administrator). Four streams came back, every one of them another organization's: an access decision naming
// their real user (WIN-DEV-01\jdoe) and source IP, a device-state audit row naming their device
// (win-dev-1), a config generation and a connector heartbeat. Another organization's people, machines and
// connectors, on a customer's own dashboard.
//
// An empty caller tenant is an unscoped deployment — one organization, no tenant model — and keeps the whole
// node. Otherwise only rows that SAY they are the caller's survive: on a multi-tenant node a row with no
// organization on it is not evidently theirs, and this is a convenience, not the audit surface (that one,
// /admin/logs/*, was scoped already).
func adminRecentLogs(writer *logs.Writer, tenantID string) (map[string]any, error) {
	result := map[string]any{}
	wholeNode := strings.TrimSpace(tenantID) == ""
	for _, filename := range adminLogFilenames() {
		rows, err := writer.ReadJSONL(filename)
		if err != nil {
			return nil, err
		}
		if !wholeNode {
			kept := make([]map[string]any, 0, len(rows))
			for _, row := range rows {
				owner := strings.TrimSpace(stringValue(row["tenant_id"]))
				// A row carrying no organization is kept, the same rule this tree uses everywhere else: on a
				// single-tenant deployment that is the whole log, and dropping it would blank the dashboard of
				// the only organization there is. What is fixed here is the row that SAYS it is somebody
				// else's, which is what the lab was actually serving.
				if owner == "" || strings.EqualFold(owner, tenantID) {
					kept = append(kept, row)
				}
			}
			rows = kept
		}
		summary := map[string]any{
			"count": len(rows),
		}
		if len(rows) > 0 {
			summary["latest"] = rows[len(rows)-1]
		}
		result[filename] = summary
	}
	return result, nil
}

func adminAgentStatusEventSummary(writer *logs.Writer, agentTelemetry agenttelemetry.RuntimeStore, tenantID string) (map[string]any, error) {
	if agentTelemetry != nil {
		return agentTelemetry.StatusSummary(context.Background(), tenantID)
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		return nil, err
	}
	statuses := []model.AgentStatus{}
	for _, row := range rows {
		if stringValue(row["tenant_id"]) != tenantID || stringValue(row["event_type"]) != "agent_status_reported" {
			continue
		}
		metadata, _ := row["metadata"].(map[string]any)
		statuses = append(statuses, model.AgentStatus{
			TenantID:  tenantID,
			Status:    strings.TrimSpace(stringValue(metadata["agent_status"])),
			Metadata:  metadata,
			Timestamp: stringValue(row["timestamp"]),
		})
	}
	return agenttelemetry.StatusSummaryFromEvents(statuses), nil
}

func adminAgentAccessDecisionSummary(writer *logs.Writer, tenantID string) (map[string]any, error) {
	rows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		return nil, err
	}
	decisionCounts := map[string]int{}
	applicationCounts := map[string]int{}
	serviceFamilyCounts := map[string]int{}
	total := 0
	allowed := 0
	withConnector := 0
	for _, row := range rows {
		if stringValue(row["tenant_id"]) != tenantID {
			continue
		}
		total++
		decisionValue := strings.TrimSpace(stringValue(row["decision"]))
		if decisionValue == "" {
			decisionValue = "unknown"
		}
		decisionCounts[decisionValue]++
		if decisionValue == "allow" {
			allowed++
		}
		if connectorID := strings.TrimSpace(stringValue(row["connector_id"])); connectorID != "" {
			withConnector++
		}
		if applicationID := strings.TrimSpace(stringValue(row["application_id"])); applicationID != "" {
			applicationCounts[applicationID]++
		}
		if serviceFamily := strings.TrimSpace(stringValue(row["service_family"])); serviceFamily != "" {
			serviceFamilyCounts[serviceFamily]++
		}
	}
	var allowRate any
	if total > 0 {
		allowRate = float64(allowed) / float64(total)
	}
	return map[string]any{
		"total":                 total,
		"decision_counts":       decisionCounts,
		"application_counts":    applicationCounts,
		"service_family_counts": serviceFamilyCounts,
		"allowed_events":        allowed,
		"with_connector":        withConnector,
		"allow_rate":            allowRate,
	}, nil
}

func writeHotStoreExportRows(ctx context.Context, store hotstore.Store, query hotstore.SearchQuery, objectStore adminExportObjectStore, filename string, onRow func(rowsExported int) error) (string, hotstore.ExportResult, error) {
	if store == nil {
		return "", hotstore.ExportResult{}, fmt.Errorf("hot store is not configured")
	}
	if objectStore == nil {
		return "", hotstore.ExportResult{}, fmt.Errorf("export object store is not configured")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type exportRow struct {
		row map[string]any
		err error
	}
	rows := make(chan exportRow, 16)
	resultCh := make(chan struct {
		result hotstore.ExportResult
		err    error
	}, 1)
	go func() {
		result, err := store.ExportRows(ctx, query, func(row map[string]any) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case rows <- exportRow{row: row}:
				return nil
			}
		})
		if err != nil {
			select {
			case rows <- exportRow{err: err}:
			case <-ctx.Done():
			}
		}
		close(rows)
		resultCh <- struct {
			result hotstore.ExportResult
			err    error
		}{result: result, err: err}
	}()

	rowsWritten := 0
	checksum, writeErr := objectStore.WriteGzipJSONLStream(filename, func() (map[string]any, bool, error) {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case next, ok := <-rows:
			if !ok {
				if err := ctx.Err(); err != nil {
					return nil, false, err
				}
				return nil, false, nil
			}
			if next.err != nil {
				return nil, false, next.err
			}
			rowsWritten++
			if onRow != nil {
				// Alpha workers treat adminExportJobStoppedError from progress writes
				// as an external stop signal, then re-read job state before cleanup.
				if err := onRow(rowsWritten); err != nil {
					return nil, false, err
				}
			}
			return next.row, true, nil
		}
	})
	if writeErr != nil {
		cancel()
		outcome := <-resultCh
		if outcome.err != nil && !errors.Is(outcome.err, context.Canceled) {
			return "", hotstore.ExportResult{}, fmt.Errorf("%w; export stream failed: %v", writeErr, outcome.err)
		}
		return "", hotstore.ExportResult{}, writeErr
	}
	outcome := <-resultCh
	if outcome.err != nil {
		return "", hotstore.ExportResult{}, outcome.err
	}
	return checksum, outcome.result, nil
}

func validateExportPathSegments(job adminExportJob) error {
	for name, value := range map[string]string{
		"tenant_id": job.TenantID,
		"job_id":    job.ID,
		"format":    job.Format,
	} {
		if !safeExportPathSegment(value) {
			return fmt.Errorf("unsafe export %s path segment %q", name, value)
		}
	}
	return nil
}

func safeExportPathSegment(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func absoluteURLForRequest(r *http.Request, path string) string {
	scheme := "http"
	if forwarded := strings.TrimSpace(r.Header.Get("x-forwarded-proto")); forwarded != "" {
		scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "127.0.0.1"
	}
	return scheme + "://" + host + path
}

func boundedIntQuery(raw string, defaultValue, minValue, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		value = defaultValue
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

// adminOperateTenant resolves which tenant an authenticated admin request operates within. By default this is
// the identity's own (non-spoofable, session-bound) tenant. The single controlled exception (Multi-Tenant Admin
// Console design): an operator holding admin.tenant.admin (super_admin / owner-via-*) may "operate within"
// a selected tenant by sending the X-Operate-Tenant header. For everyone else the header is silently IGNORED
// (not an error) and the request stays scoped to self — so a tenant-admin/staff can never reach across tenants.
// Returns overridden=true only when the override was both permitted AND present.
func adminOperateTenant(r *http.Request, identity adminIdentity) (string, bool) {
	// ★ THE ROLE WAS THE WHOLE CHECK, AND THE ROLE IS GRANTED INSIDE A CUSTOMER ORGANIZATION (2026-08-21).
	// See operator_is_an_organization_not_a_role.go: a super_admin of tenant_reference_lab was answered as
	// tenant_northwind on every route that reads this — policies, licence, PKI bundle, the whole audit trail.
	if r != nil && adminIdentityMayActAcrossOrganizations(identity) {
		if override := strings.TrimSpace(r.Header.Get("X-Operate-Tenant")); override != "" {
			return override, true
		}
	}
	return identity.TenantID, false
}

func adminTenantIDFromRequest(r *http.Request) string {
	if identity, ok := adminIdentityFromRequest(r); ok {
		// Resolve the operating tenant: identity's own tenant by default, or — only for an operator holding
		// admin.tenant.admin — the X-Operate-Tenant override. Backward compatible: with no header (or no
		// override permission) this returns identity.TenantID exactly as before. Fail-closed unchanged: an
		// empty resolved tenant returns "" and callers continue to 403.
		if tenantID, _ := adminOperateTenant(r, identity); strings.TrimSpace(tenantID) != "" {
			return tenantID
		}
	}
	return ""
}

func adminAccessDecisionDetail(store hotstore.Store, decisionStore *accessdecision.Store, tenantID, decisionID string) (map[string]any, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	decisionID = strings.TrimSpace(decisionID)
	if decisionID == "" {
		return nil, fmt.Errorf("decision_id is required")
	}
	if store == nil {
		return nil, fmt.Errorf("hot store is not configured")
	}
	decisionItem, hasDecision := decisionStore.Get(decisionID)
	if hasDecision && decisionItem.TenantID != tenantID {
		hasDecision = false
	}
	related, err := store.RelatedByAccessDecisionID(context.Background(), hotstore.RelatedLogQuery{
		TenantID:         tenantID,
		AccessDecisionID: decisionID,
	})
	if err != nil {
		return nil, err
	}
	if !hasDecision && related.TotalRows == 0 {
		return nil, fmt.Errorf("access decision %s is absent", decisionID)
	}
	return map[string]any{
		"access_decision_id": decisionID,
		"access_decision":    decisionValueForAdminDetail(decisionItem, hasDecision),
		"related_logs":       related.RowsByStream,
		"summary": map[string]any{
			"has_runtime_decision": hasDecision,
			"related_log_rows":     related.TotalRows,
		},
	}, nil
}

func decisionValueForAdminDetail(dec model.AccessDecision, ok bool) any {
	if !ok {
		return nil
	}
	return dec
}

func adminRolesFromRequest(r *http.Request) []string {
	if identity, ok := adminIdentityFromRequest(r); ok {
		return append([]string(nil), identity.Roles...)
	}
	return []string{}
}

func adminScopesFromRequest(r *http.Request) []string {
	if identity, ok := adminIdentityFromRequest(r); ok {
		return append([]string(nil), identity.Scopes...)
	}
	return []string{}
}

func adminMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func adminRequestIdentity(r *http.Request, tenantID, legacyToken string, store adminAuthRuntimeStore, devMode bool, now time.Time) (adminIdentity, bool, error) {
	// ★ ARMED, OR IT IS NOT A CREDENTIAL (the machine-credential separation, 2026-08-16). The secret being configured used to be the
	// whole test. Arming is now a separate, explicit decision, and a token that is present but not armed
	// authenticates nothing — the node said so at boot, so this is not a silent refusal.
	if legacyToken != "" && adminBreakGlass.Armed {
		for _, candidate := range adminCredentialCandidates(r) {
			if candidate != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(legacyToken)) == 1 {
				adminBreakGlassAccepted(now)
				// Keep the explicit legacy token first as a Phase 1 break-glass path when the durable Admin Auth Store is unavailable.
				if store != nil {
					if err := store.PersistPrincipal(r.Context(), adminPrincipal{
						ID:        "admin_legacy_token",
						TenantID:  tenantID,
						Subject:   "legacy_admin_token",
						Email:     "legacy-admin-token@example.local",
						Roles:     []string{"owner"},
						IDPID:     "local_edge_legacy_token",
						Status:    "active",
						CreatedAt: now.UTC().Format(time.RFC3339),
						Metadata:  map[string]any{"source": "phase1_legacy_token"},
					}); err != nil {
						log.Printf("persist legacy admin token principal: %v", err)
					}
				}
				// Phase 3 (G1) visibility: the legacy break-glass token always authorizes as `owner` of the
				// SEED/operator tenant (the PolicyBundle/operator TenantID threaded in here). The behaviour is
				// unchanged; in production we additionally emit a non-secret audit line so this seed-tenant,
				// break-glass authentication is never silent. (No secret material is logged.)
				if !devMode {
					log.Printf("admin_auth legacy_token_authenticated principal=admin_legacy_token tenant=%s roles=owner auth_method=legacy_admin_token note=seed_operator_tenant_break_glass", tenantID)
				}
				return adminIdentity{
					PrincipalID: "admin_legacy_token",
					TenantID:    tenantID,
					Roles:       []string{"owner"},
					AuthMethod:  "legacy_admin_token",
				}, true, nil
			}
		}
	}
	if store != nil {
		if cookie, err := r.Cookie("admin_session"); err == nil && strings.TrimSpace(cookie.Value) != "" {
			// Resolved by session id ALONE, so the identity carries the session's own tenant. Passing this
			// node's tenant here meant only administrators of the node's own organization could sign in: every
			// other one — including the operator account, which by design lives in its own tenant — got a
			// cookie and then "admin authentication is required" on every request with it.
			identity, ok, err := store.LookupSessionAdminIdentity(r.Context(), strings.TrimSpace(cookie.Value), "", now)
			if err != nil {
				return adminIdentity{}, false, err
			}
			if ok {
				return identity, true, nil
			}
		}
	}
	// Centralized admin auth: the session may be one minted by the control-plane authority (not known to this
	// Edge's local store). Introspect it against the authority; on success the Edge authorizes as a relying
	// party (docs/admin_auth_centralization_design.md).
	//
	// Phase 3 (G1) tenant binding: the returned identity carries the ACTUAL tenant the control plane bound to
	// the session (identity.TenantID), and that is what every per-resource handler scopes to. This path must
	// never substitute the seed/primary PolicyBundle tenant — the CP-authoritative tenant is used as-is, so a
	// cross-tenant admin request can never be silently authorized against the seeded default.
	if adminSessionAuthority != nil {
		if cookie, err := r.Cookie("admin_session"); err == nil && strings.TrimSpace(cookie.Value) != "" {
			if identity, ok := adminSessionAuthority.introspect(r.Context(), strings.TrimSpace(cookie.Value)); ok {
				return identity, true, nil
			}
		}
	}
	if store != nil {
		for _, candidate := range adminCredentialCandidates(r) {
			// Resolved by token hash ALONE, so the identity carries the token's own tenant — the same rule the
			// session lookup above already follows, and for the same measured reason: passing this node's
			// tenant meant only the node's own organization could use an API token at all.
			identity, ok, err := store.LookupAPITokenAdminIdentity(r.Context(), candidate, "", now)
			if err != nil {
				return adminIdentity{}, false, err
			}
			if ok {
				return identity, true, nil
			}
		}
	}
	// ★★★ AND AN API TOKEN THE AUTHORITY OWNS (2026-08-23). The same relying-party rule the session path above
	// follows: taking the admin-auth database off the enforcement Edges left them able to resolve a cookie the
	// control plane minted and nothing else, so every automation authenticating with a bearer got 401 from an
	// Edge. Measured on the lab's own posture check — six readings lost in one run, reported as missing data
	// rather than as refused authentication.
	if adminSessionAuthority != nil {
		if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
			if identity, ok := adminSessionAuthority.introspectAPIToken(r.Context(), authorization); ok {
				return identity, true, nil
			}
		}
	}
	if legacyToken != "" {
		return adminIdentity{}, false, nil
	}
	// Lab-only bypass: devMode/-lab-mode EXCLUSIVE. In production (devMode==false) this returns
	// unauthenticated above and the bypass below is unreachable. The bypass authorizes as `owner` of the
	// SEED tenant (the PolicyBundle/operator TenantID threaded in) and is intended only for local lab runs
	// with no provisioned admin auth records. It must never be reached on a production multi-tenant Edge.
	if !devMode {
		return adminIdentity{}, false, nil
	}
	if store != nil {
		hasRecords, err := store.HasAuthRecords(r.Context(), tenantID)
		if err != nil {
			return adminIdentity{}, false, err
		}
		if hasRecords {
			return adminIdentity{}, false, nil
		}
	}
	return adminIdentity{
		PrincipalID: "admin_lab_bypass",
		TenantID:    tenantID,
		Roles:       []string{"owner"},
		AuthMethod:  "lab_bypass",
	}, true, nil
}

func adminCredentialCandidates(r *http.Request) []string {
	candidates := []string{}
	if candidate := strings.TrimSpace(r.Header.Get("x-admin-token")); candidate != "" {
		candidates = append(candidates, candidate)
	}
	auth := strings.TrimSpace(r.Header.Get("authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		if candidate := strings.TrimSpace(auth[len("Bearer "):]); candidate != "" {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func adminRequestCarriedCredentials(r *http.Request) bool {
	if cookie, err := r.Cookie("admin_session"); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return true
	}
	return len(adminCredentialCandidates(r)) > 0
}

// tenant_admin is the customer-facing per-tenant administrator role (docs/multi_tenant_admin_console_design.md
// ): full authority WITHIN its own tenant, but structurally unable to hold admin.tenant.admin (the
// cross-tenant operator capability). It is derived from the within-tenant "admin" role so it tracks every
// per-tenant permission automatically, with admin.tenant.admin removed defensively (admin never carries it,
// but the deletion makes the trust-boundary invariant explicit). A tenant-admin can therefore never reach
// another tenant's data plane nor escalate a peer into a cross-tenant operator.
func init() {
	tenantAdmin := make(map[string]bool, len(adminPermissionsByRole["admin"]))
	for permission, granted := range adminPermissionsByRole["admin"] {
		tenantAdmin[permission] = granted
	}
	delete(tenantAdmin, "admin.tenant.admin")
	adminPermissionsByRole["tenant_admin"] = tenantAdmin
}

// adminRoleKnown reports whether a role name exists in the RBAC catalog. Used to reject role assignments that
// reference an unknown role.
func adminRoleKnown(role string) bool {
	_, ok := adminPermissionsByRole[strings.TrimSpace(role)]
	return ok
}

// adminRolesGrantTenantAdmin reports whether any of the roles grants the cross-tenant operator capability
// (admin.tenant.admin) — directly or via the owner "*" wildcard. Used by the privilege-escalation guard so a
// caller without admin.tenant.admin can never promote a peer into a cross-tenant operator (owner/super_admin).
func adminRolesGrantTenantAdmin(roles []string) bool {
	for _, role := range roles {
		allowed := adminPermissionsByRole[strings.TrimSpace(role)]
		if allowed["*"] || allowed["admin.tenant.admin"] {
			return true
		}
	}
	return false
}

// adminOperatorTenantRejectsOwner enforces the multi-tenant Admin Console Q5 convention
// : the SSE operator's OWN tenant (-operator-tenant-id) uses the
// SCOPED super_admin role for cross-tenant administration — never the owner "*" wildcard. Owner conflates
// operator identity with an unbounded grant; super_admin is the least-privilege cross-tenant operator role. The
// guard fires only when the feature is on (operatorTenantID != "") AND the role assignment targets the operator
// tenant AND it includes owner. Feature off (the lab default) or any customer tenant => false, so owner stays
// assignable exactly as before and lab behavior is unchanged.
func adminOperatorTenantRejectsOwner(operatorTenantID, targetTenantID string, roles []string) bool {
	operatorTenantID = strings.TrimSpace(operatorTenantID)
	if operatorTenantID == "" || strings.TrimSpace(targetTenantID) != operatorTenantID {
		return false
	}
	for _, role := range roles {
		if strings.TrimSpace(role) == "owner" {
			return true
		}
	}
	return false
}

// adminEffectiveAdminCount counts the active accounts that can still manage admins (roles granting
// admin.accounts.write). An optional override (overridePrincipalID/overrideRoles) models a pending role change;
// excludePrincipalID models a pending suspend/delete (the account is dropped from the count).
func adminEffectiveAdminCount(accounts []adminAccountSummary, excludePrincipalID, overridePrincipalID string, overrideRoles []string) int {
	count := 0
	for _, acct := range accounts {
		if acct.PrincipalID == excludePrincipalID {
			continue
		}
		if acct.Status != credentialStatusActive {
			continue
		}
		roles := acct.Roles
		if overridePrincipalID != "" && acct.PrincipalID == overridePrincipalID {
			roles = overrideRoles
		}
		if adminPermissionAllowed(roles, "admin.accounts.write") {
			count++
		}
	}
	return count
}

// adminAccountLockoutWouldOccur reports whether a pending change (suspend/delete via excludePrincipalID, or a
// role change via overridePrincipalID/overrideRoles) would leave the tenant with ZERO accounts able to manage
// admins, when at least one exists today. This is the tenant lockout guard. It never blocks when the tenant is
// already in a zero-admin state (nothing left to protect).
func adminAccountLockoutWouldOccur(accounts []adminAccountSummary, excludePrincipalID, overridePrincipalID string, overrideRoles []string) bool {
	before := adminEffectiveAdminCount(accounts, "", "", nil)
	after := adminEffectiveAdminCount(accounts, excludePrincipalID, overridePrincipalID, overrideRoles)
	return before >= 1 && after < 1
}

// adminScopeAllowed narrows an API token to the scopes it was minted with.
//
// ★ IT DID NOT UNDERSTAND THE EITHER-OF SYNTAX, SO WHOLE ROUTES WERE UNREACHABLE BY ANY TOKEN (found live,
// 2026-08-16). The role check learned "a|b" when a handful of routes became "a tenant act on your own
// organization, an operator act on somebody else's". This did not: it compared the token's scopes to the
// literal string "admin.enrollment.read|admin.tenant.admin", which no scope list ever contains. So every
// either-of route answered 403 to a named token while answering 200 to a browser session and to the shared
// break-glass owner token — which is one more reason everything on this deployment ran as the break-glass
// token. Measured on the lab: GET /admin/tenant-cas, 403, with the scope named in the error and present in
// the token.
//
// An either-of gate means ANY of the alternatives authorises, and a scope check has to read it the same way
// the role check does, or the two disagree about what the route requires.
func adminScopeAllowed(identity adminIdentity, permission string) bool {
	if identity.AuthMethod != "admin_api_token" {
		return true
	}
	for _, candidate := range strings.Split(permission, "|") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		for _, scope := range identity.Scopes {
			if scope == "*" || scope == candidate {
				return true
			}
		}
	}
	return false
}

func adminCanCancelExportJob(identity adminIdentity, job adminExportJob) bool {
	if job.TenantID != identity.TenantID {
		return false
	}
	if adminPermissionAllowed(identity.Roles, "admin.export.cancel.all") {
		return true
	}
	return job.CreatedByAdminPrincipalID == identity.PrincipalID
}

func evaluateWithRuntimeEvidence(ctx context.Context, evaluator decision.Evaluator, req model.DecisionRequest, humanApprovals *humanapproval.Store, delegatedGrants *delegatedgrant.Store, nonHumanIdentities nhi.RuntimeStore, now time.Time) model.AccessDecision {
	dec := evaluator.Evaluate(req)
	if dec.Decision != "allow" || !isDelegatedActorType(dec.ActorType) {
		return dec
	}
	policy, _ := policyForDecision(evaluator, dec.PolicyID)

	if reason, evidenceResult, ok := nhi.ValidateRuntimeEvidence(ctx, nonHumanIdentities, req, dec.TenantID, req.ActorNHIID, now); !ok {
		return denyRuntimeEvidence(dec, reason, []string{"policy_matched", evidenceResult}, evidenceResult)
	}

	grantID := req.DelegatedAccessGrantID
	if grantID == "" {
		return denyRuntimeEvidence(dec, "Delegated Access Grant is required for delegated agent access.", []string{"policy_matched", "delegated_grant_absent"}, "delegated_grant_absent")
	}
	grant, ok := delegatedGrants.GetForTenant(dec.TenantID, grantID)
	if !ok {
		return denyRuntimeEvidence(dec, "Delegated Access Grant was not found.", []string{"policy_matched", "delegated_grant_absent"}, "delegated_grant_absent")
	}
	if grant.TenantID != dec.TenantID {
		return denyRuntimeEvidence(dec, "Delegated Access Grant tenant does not match the decision tenant.", []string{"policy_matched", "delegated_grant_mismatch"}, "delegated_grant_mismatch")
	}
	if grant.Status == "revoked" {
		return denyRuntimeEvidence(dec, "Delegated Access Grant has been revoked.", []string{"policy_matched", "delegated_grant_revoked"}, "delegated_grant_revoked")
	}
	if !delegatedgrant.IsActive(grant, now) {
		return denyRuntimeEvidence(dec, "Delegated Access Grant is not active.", []string{"policy_matched", "delegated_grant_expired"}, "delegated_grant_expired")
	}
	if err := validateDelegatedGrantContext(grant, req); err != nil {
		return denyRuntimeEvidence(dec, err.Error(), []string{"policy_matched", "delegated_grant_mismatch"}, "delegated_grant_mismatch")
	}

	requiresApproval := policy.RequiredHumanApproval || req.HumanApprovalEventID != "" || (grant.ApprovalEventID != nil && *grant.ApprovalEventID != "")
	if !requiresApproval {
		markRuntimeEvidenceAllowed(&dec, grant, nil)
		return dec
	}
	approvalID := req.HumanApprovalEventID
	if approvalID == "" && grant.ApprovalEventID != nil {
		approvalID = *grant.ApprovalEventID
	}
	if approvalID == "" {
		return denyRuntimeEvidence(dec, "Human Approval Event is required for this delegated agent access.", []string{"policy_matched", "approval_absent"}, "approval_absent")
	}
	approval, ok := humanApprovals.GetForTenant(dec.TenantID, approvalID)
	if !ok {
		return denyRuntimeEvidence(dec, "Human Approval Event was not found.", []string{"policy_matched", "approval_absent"}, "approval_absent")
	}
	if approval.TenantID != dec.TenantID {
		return denyRuntimeEvidence(dec, "Human Approval Event tenant does not match the decision tenant.", []string{"policy_matched", "approval_mismatch"}, "approval_mismatch")
	}
	if approval.ApprovalResult == "revoked" {
		return denyRuntimeEvidence(dec, "Human Approval Event has been revoked.", []string{"policy_matched", "approval_revoked"}, "approval_revoked")
	}
	if !humanapproval.IsActive(approval, now) {
		return denyRuntimeEvidence(dec, "Human Approval Event is not active.", []string{"policy_matched", "approval_expired"}, "approval_expired")
	}
	if err := validateHumanApprovalContext(approval, grant, req); err != nil {
		return denyRuntimeEvidence(dec, err.Error(), []string{"policy_matched", "approval_mismatch"}, "approval_mismatch")
	}

	markRuntimeEvidenceAllowed(&dec, grant, &approval)
	return dec
}

func policyForDecision(evaluator decision.Evaluator, policyID string) (model.Policy, bool) {
	for _, policy := range evaluator.Policies {
		if policy.ID == policyID {
			return policy, true
		}
	}
	return model.Policy{}, false
}

func denyRuntimeEvidence(dec model.AccessDecision, reason string, reasonCodes []string, evidenceResult string) model.AccessDecision {
	dec.Decision = "deny"
	dec.Reason = &reason
	dec.ReasonCodes = reasonCodes
	dec.Actions = []model.DecisionAction{
		{
			Type: "emit_audit_event",
			Metadata: map[string]any{
				"runtime_evidence_result": evidenceResult,
			},
		},
	}
	dec.TTLSeconds = 30
	if dec.Metadata == nil {
		dec.Metadata = map[string]any{}
	}
	dec.Metadata["runtime_evidence_result"] = evidenceResult
	return dec
}

func sessionIDFromRequest(r *http.Request) string {
	if value := r.URL.Query().Get("session_id"); value != "" {
		return value
	}
	if value := r.Header.Get("x-session-id"); value != "" {
		return value
	}
	cookie, err := r.Cookie("session_id")
	if err == nil {
		return cookie.Value
	}
	return ""
}

// activeSessionFromRequest resolves the verified IdP session for a browser request (session_id cookie /
// header / query) and reports whether it is present and active. Used by the clientless front door so
// the user identity comes from a verified session, never a client-claimed field.
func activeSessionFromRequest(r *http.Request, sessionStore *sessionstore.Store) (model.Session, bool) {
	if sessionStore == nil {
		return model.Session{}, false
	}
	sid := sessionIDFromRequest(r)
	if sid == "" {
		return model.Session{}, false
	}
	session, ok := sessionStore.Get(sid)
	if !ok || session.Status != "active" {
		return model.Session{}, false
	}
	return session, true
}

// riskSeverityRank orders risk severities for the union-model group floor: none < medium < high < critical.
func riskSeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	}
	return 0
}

func maxRiskSeverity(a, b string) string {
	if riskSeverityRank(a) >= riskSeverityRank(b) {
		return a
	}
	return b
}

func mockAuthenticationEventFromCallback(r *http.Request) model.AuthenticationEvent {
	now := time.Now().UTC()
	query := r.URL.Query()
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	subjectUserID := valueOrDefault(query.Get("subject_user_id"), valueOrDefault(query.Get("user_id"), "user_lab_001"))
	sourceIP := sourceIPFromRequest(r)
	deviceID := valueOrDefault(query.Get("device_id"), "dev_lab_001")
	acr := "urn:mfa:fresh"
	amr := splitOptionalCSV(query.Get("amr"))
	if len(amr) == 0 {
		amr = []string{"pwd", "otp"}
	}
	metadata := map[string]any{
		"code":  query.Get("code"),
		"state": query.Get("state"),
	}
	if issuer := strings.TrimSpace(query.Get("issuer")); issuer != "" {
		metadata["issuer"] = issuer
	}
	if email := strings.TrimSpace(query.Get("email")); email != "" {
		metadata["email"] = email
	}
	if groups := splitOptionalCSV(query.Get("groups")); len(groups) > 0 {
		metadata["groups"] = groups
	}
	return model.AuthenticationEvent{
		ID:            randomEdgeID("auth_", now),
		TenantID:      valueOrDefault(query.Get("tenant_id"), "tenant_lab_001"),
		UserID:        valueOrDefault(query.Get("user_id"), "user_lab_001"),
		SubjectUserID: &subjectUserID,
		SessionID:     valueOrDefault(query.Get("session_id"), randomEdgeID("sess_", now)),
		IDPID:         valueOrDefault(query.Get("idp_id"), "idp_keycloak_lab"),
		Method:        "oidc_authorization_code",
		AMR:           amr,
		ACR:           &acr,
		MFAState:      valueOrDefault(query.Get("mfa_state"), "fresh"),
		AuthTime:      now.Format(time.RFC3339),
		ExpiresAt:     &expiresAt,
		SourceIP:      &sourceIP,
		DeviceID:      &deviceID,
		Result:        "success",
		Timestamp:     now.Format(time.RFC3339),
		Metadata:      metadata,
	}
}

func stringMetadata(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func boolMetadata(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "y", "on":
			return true
		default:
			return false
		}
	case float64:
		return typed != 0
	case int:
		return typed != 0
	default:
		return false
	}
}

func stringSliceMetadata(metadata map[string]any, key string) []string {
	if metadata == nil {
		return nil
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, fmt.Sprint(item))
		}
		return values
	default:
		return nil
	}
}

func appendRawJSONL(w http.ResponseWriter, r *http.Request, writer *logs.Writer, filename string, reg *tenantca.TenantCARegistry) {
	var payload map[string]any
	if err := decodeLimitedJSONBody(w, r, &payload, maxEdgeRuntimeJSONBodyBytes); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode log payload: %w", err))
		return
	}
	// tenant isolation: access/audit logs are physically partitioned by the row's tenant_id,
	// so a client must NOT be able to inject a row into another tenant's partition by putting a foreign
	// tenant_id in the body. Stamp the AUTHORITATIVE tenant (resolved from the (T) mTLS issuing CA) onto the
	// row and deny a body that claims a different tenant. No-op on the plaintext listener / without a
	// registry (the claimed value is kept — single-tenant Edge, no other partition to leak into).
	claimed, _ := payload["tenant_id"].(string)
	boundTenant, terr := authoritativeTenantForRequest(r, claimed, reg)
	if terr != nil {
		writeError(w, http.StatusForbidden, terr)
		return
	}
	if strings.TrimSpace(boundTenant) != "" {
		payload["tenant_id"] = boundTenant
	}
	if err := writer.Append(filename, payload); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func writeAdminPreviewJSONL(w http.ResponseWriter, status int, values []map[string]any, appliedLimit int) {
	w.Header().Set("x-export-mode", "preview")
	w.Header().Set("x-export-limit", strconv.Itoa(appliedLimit))
	writeJSONL(w, status, values)
}

func writeJSONL(w http.ResponseWriter, status int, values []map[string]any) {
	w.Header().Set("content-type", "application/x-ndjson")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	for _, value := range values {
		if err := encoder.Encode(value); err != nil {
			log.Printf("write jsonl response: %v", err)
			return
		}
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// readLimitedBody reads the request body up to limit bytes (so a handler can both anti-replay-verify the raw
// bytes and JSON-decode them). Returns the bytes read; oversize bodies error via http.MaxBytesReader.
func readLimitedBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

func normalizeAgentUpdateReportForRuntime(event model.AgentUpdateEvent, device model.Device, targetVersion, releaseChannel string, now time.Time) (model.AgentUpdateEvent, error) {
	if event.TenantID != "" && event.TenantID != device.TenantID {
		return event, fmt.Errorf("agent update tenant_id %s does not match registered tenant_id %s", event.TenantID, device.TenantID)
	}
	if event.ID == "" {
		event.ID = randomEdgeID("aue_", now)
	}
	if event.TenantID == "" {
		event.TenantID = device.TenantID
	}
	if event.DeviceID == "" {
		event.DeviceID = device.ID
	}
	if event.UserID == "" {
		event.UserID = device.UserID
	}
	if event.CurrentAgentVersion == "" {
		event.CurrentAgentVersion = device.AgentVersion
	}
	// ★ A MISSING RUNNING VERSION MUST NOT JAM THE QUEUE (2026-08-13, twenty-ninth review). The store requires
	// this field, and both clients keep-and-retry a non-2xx — so a report without it is refused for ever and
	// every LATER outcome from that device queues behind it. The 404 this lane had one review ago was fixed
	// and the same jam came straight back as a 500, through the ledger fallback's stub device.
	//
	// The device is the only thing that knows, and the case where it does not know is the one that matters
	// most: an agent so broken it cannot read its own version is exactly the agent whose outcome the fleet
	// needs. So the field is filled with what is true — that it is unknown — rather than the record being
	// refused. A field nobody can read is a smaller loss than every subsequent outcome from that machine.
	if strings.TrimSpace(event.CurrentAgentVersion) == "" {
		event.CurrentAgentVersion = "unknown"
	}
	if event.TargetAgentVersion == "" {
		event.TargetAgentVersion = strings.TrimSpace(targetVersion)
	}
	if event.TargetAgentVersion == "" {
		event.TargetAgentVersion = event.CurrentAgentVersion
	}
	// ★ THE DEVICE'S OWN CHANNEL IS NOT TRUSTED TO BE STORABLE (2026-08-13, thirtieth review #9c). The startup
	// gate checks the OPERATOR's flag; this field arrives in the report body, and one endpoint sending "Beta"
	// failed the CHECK constraint, was answered 500, and kept retrying — jamming that device's own drain for
	// ever on a value it chose. Refused into the edge's configured channel rather than rejected, because the
	// outcome it carries is worth more than the label, and a report that cannot be stored is a report nobody
	// ever sees.
	// The device's value is TRIMMED before it is judged and before it is stored: " stable " is a device being
	// sloppy, not a device asking for something the store cannot hold, and the row it produces must be one the
	// CHECK accepts.
	event.ReleaseChannel = strings.TrimSpace(event.ReleaseChannel)
	if !validAgentReleaseChannel(event.ReleaseChannel) {
		if event.ReleaseChannel != "" {
			log.Printf("agent update report: device %s reported release_channel %q, which the durable store will "+
				"not accept — recording it under this edge's channel instead so the outcome is not lost",
				event.DeviceID, event.ReleaseChannel)
		}
		event.ReleaseChannel = strings.TrimSpace(releaseChannel)
	}
	if !validAgentReleaseChannel(event.ReleaseChannel) {
		event.ReleaseChannel = "lab"
	}
	if event.UpdateSource == "" {
		event.UpdateSource = "control_plane"
	}
	if event.UpdateStatus == "" {
		if event.TargetAgentVersion != "" && event.CurrentAgentVersion == event.TargetAgentVersion {
			event.UpdateStatus = "installed"
		} else {
			event.UpdateStatus = "available"
		}
	}
	if event.Timestamp == "" {
		event.Timestamp = now.UTC().Format(time.RFC3339)
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	return event, nil
}

func normalizeAgentStatusReportForRuntime(status model.AgentStatus, device model.Device, now time.Time) (model.AgentStatus, error) {
	if status.TenantID != "" && status.TenantID != device.TenantID {
		return status, fmt.Errorf("agent status tenant_id %s does not match registered tenant_id %s", status.TenantID, device.TenantID)
	}
	if status.TenantID == "" {
		status.TenantID = device.TenantID
	}
	if status.DeviceID == "" {
		status.DeviceID = device.ID
	}
	if status.PolicyBundleID == "" {
		status.PolicyBundleID = device.PolicyBundleID
	}
	if status.PolicyBundleVersion == "" {
		status.PolicyBundleVersion = device.PolicyBundleVersion
	}
	if status.BundleSource == "" {
		status.BundleSource = "remote"
	}
	if status.DeviceTrustLevel == "" {
		status.DeviceTrustLevel = device.DeviceTrustLevel
	}
	if status.DeviceTrustLevel == "" {
		status.DeviceTrustLevel = "unknown"
	}
	if status.Status == "" {
		status.Status = agentRuntimeStatusFromDeviceStatus(device.Status)
	}
	if status.Timestamp == "" {
		status.Timestamp = now.UTC().Format(time.RFC3339)
	}
	if status.Metadata == nil {
		status.Metadata = map[string]any{}
	}
	return status, nil
}

func agentRuntimeStatusFromDeviceStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "healthy", "degraded", "offline":
		return strings.TrimSpace(status)
	default:
		return "healthy"
	}
}

func normalizeHumanApprovalEvent(event *model.HumanApprovalEvent, expectedTenantID string, now time.Time) error {
	if event.ID == "" {
		event.ID = randomEdgeID("hae_", now)
	}
	if event.TenantID == "" {
		event.TenantID = expectedTenantID
	}
	if expectedTenantID != "" && event.TenantID != expectedTenantID {
		return fmt.Errorf("human approval event tenant_id %s does not match edge tenant_id %s", event.TenantID, expectedTenantID)
	}
	if event.ApprovalSource == "" {
		event.ApprovalSource = "admin_console"
	}
	if !validHumanApprovalResult(event.ApprovalResult) {
		return fmt.Errorf("human approval event approval_result %s is invalid", event.ApprovalResult)
	}
	if event.ApprovalResult == "approved" && (event.ApproverUserID == nil || *event.ApproverUserID == "") {
		return fmt.Errorf("human approval event approver_user_id is required for approved result")
	}
	if event.ActorNHIID == nil || *event.ActorNHIID == "" {
		return fmt.Errorf("human approval event actor_nhi_id is required")
	}
	if event.ActionType == nil || *event.ActionType == "" {
		return fmt.Errorf("human approval event action_type is required")
	}
	if event.CreatedAt == "" {
		event.CreatedAt = now.UTC().Format(time.RFC3339)
	}
	if event.ApprovalResult == "approved" {
		if event.ActivatedAt == nil || *event.ActivatedAt == "" {
			event.ActivatedAt = stringPtr(now.UTC().Format(time.RFC3339))
		}
		if event.ExpiresAt == nil || *event.ExpiresAt == "" {
			ttl := intMetadataValue(event.Metadata, "approval_ttl_seconds", 1800)
			if ttl <= 0 {
				ttl = 1800
			}
			if time.Duration(ttl)*time.Second > maxHumanApprovalTTL {
				ttl = int(maxHumanApprovalTTL / time.Second)
			}
			event.ExpiresAt = stringPtr(now.UTC().Add(time.Duration(ttl) * time.Second).Format(time.RFC3339))
		}
	}
	if event.RequestedScopes == nil {
		event.RequestedScopes = []string{}
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	return nil
}

func validHumanApprovalResult(value string) bool {
	switch value {
	case "approved", "denied", "expired", "revoked":
		return true
	default:
		return false
	}
}

func intMetadataValue(metadata map[string]any, key string, fallback int) int {
	if metadata == nil {
		return fallback
	}
	value, ok := metadata[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(typed)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func normalizeInspectionEvent(event *model.InspectionEvent, expectedTenantID string, now time.Time) error {
	if event.ID == "" {
		event.ID = randomEdgeID("ie_", now)
	}
	if event.TenantID == "" {
		event.TenantID = expectedTenantID
	}
	if expectedTenantID != "" && event.TenantID != expectedTenantID {
		return fmt.Errorf("inspection event tenant_id %s does not match edge tenant_id %s", event.TenantID, expectedTenantID)
	}
	if event.PayloadStored && (event.PayloadRef == nil || *event.PayloadRef == "") {
		return fmt.Errorf("inspection event payload_ref is required when payload_stored is true")
	}
	if event.PayloadRef != nil && *event.PayloadRef != "" {
		event.PayloadStored = true
	}
	if event.RetentionPolicy == nil || *event.RetentionPolicy == "" {
		event.RetentionPolicy = stringPtr("metadata_30d")
	}
	if event.Timestamp == "" {
		event.Timestamp = now.UTC().Format(time.RFC3339)
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	return nil
}

func validateInspectionEventReferences(event model.InspectionEvent, expectedTenantID string, decisionStore *accessdecision.Store) error {
	if event.TenantID != expectedTenantID {
		return fmt.Errorf("inspection event tenant_id %s does not match edge tenant_id %s", event.TenantID, expectedTenantID)
	}
	if event.AccessDecisionID != nil && *event.AccessDecisionID != "" {
		dec, ok := decisionStore.Get(*event.AccessDecisionID)
		if !ok {
			return fmt.Errorf("access decision %s is absent", *event.AccessDecisionID)
		}
		if dec.TenantID != event.TenantID {
			return fmt.Errorf("access decision tenant_id does not match inspection event")
		}
		if event.ApplicationID != nil && *event.ApplicationID != "" && dec.ApplicationID != *event.ApplicationID {
			return fmt.Errorf("access decision application_id does not match inspection event")
		}
		if event.SessionID != nil && *event.SessionID != "" && dec.SessionID != nil && *dec.SessionID != *event.SessionID {
			return fmt.Errorf("access decision session_id does not match inspection event")
		}
	}
	return nil
}

func validateToolCallEventReferences(event model.ToolCallEvent, expectedTenantID string, decisionStore *accessdecision.Store, humanApprovals *humanapproval.Store, delegatedGrants *delegatedgrant.Store, inspectionEvents *inspection.Store, now time.Time) error {
	if event.TenantID != expectedTenantID {
		return fmt.Errorf("tool call event tenant_id %s does not match edge tenant_id %s", event.TenantID, expectedTenantID)
	}
	if event.AccessDecisionID != nil && *event.AccessDecisionID != "" {
		dec, ok := decisionStore.Get(*event.AccessDecisionID)
		if !ok {
			return fmt.Errorf("access decision %s is absent", *event.AccessDecisionID)
		}
		if err := validateToolCallAgainstDecision(event, dec); err != nil {
			return err
		}
	}
	if event.DelegatedAccessGrantID != nil && *event.DelegatedAccessGrantID != "" {
		grant, ok := delegatedGrants.GetForTenant(event.TenantID, *event.DelegatedAccessGrantID)
		if !ok {
			return fmt.Errorf("delegated access grant %s is absent", *event.DelegatedAccessGrantID)
		}
		if !delegatedgrant.IsActive(grant, now) {
			return fmt.Errorf("delegated access grant %s is not active", grant.ID)
		}
		if grant.ActorNHIID != event.ActorNHIID {
			return fmt.Errorf("delegated access grant actor_nhi_id does not match tool call event")
		}
		if len(grant.ToolIDs) > 0 && !stringSliceContains(grant.ToolIDs, event.ToolID) {
			return fmt.Errorf("delegated access grant does not allow tool %s", event.ToolID)
		}
	}
	if event.HumanApprovalEventID != nil && *event.HumanApprovalEventID != "" {
		approval, ok := humanApprovals.GetForTenant(event.TenantID, *event.HumanApprovalEventID)
		if !ok {
			return fmt.Errorf("human approval event %s is absent", *event.HumanApprovalEventID)
		}
		if !humanapproval.IsActive(approval, now) {
			return fmt.Errorf("human approval event %s is not active", approval.ID)
		}
		if approval.ActorNHIID != nil && *approval.ActorNHIID != "" && *approval.ActorNHIID != event.ActorNHIID {
			return fmt.Errorf("human approval event actor_nhi_id does not match tool call event")
		}
		if approval.ActionType != nil && *approval.ActionType != "" && *approval.ActionType != event.ActionType {
			return fmt.Errorf("human approval event action_type does not match tool call event")
		}
	}
	if event.InspectionEventID != nil && *event.InspectionEventID != "" {
		inspection, ok := inspectionEvents.Get(*event.InspectionEventID)
		if !ok {
			return fmt.Errorf("inspection event %s is absent", *event.InspectionEventID)
		}
		if inspection.TenantID != event.TenantID {
			return fmt.Errorf("inspection event tenant_id does not match tool call event")
		}
		if inspection.AccessDecisionID != nil && *inspection.AccessDecisionID != "" && event.AccessDecisionID != nil && *event.AccessDecisionID != "" && *inspection.AccessDecisionID != *event.AccessDecisionID {
			return fmt.Errorf("inspection event access_decision_id does not match tool call event")
		}
		if inspection.PayloadRef != nil && *inspection.PayloadRef != "" && event.PayloadRef != nil && *event.PayloadRef != "" && *inspection.PayloadRef != *event.PayloadRef {
			return fmt.Errorf("inspection event payload_ref does not match tool call event")
		}
	}
	return nil
}

func validateToolCallAgainstDecision(event model.ToolCallEvent, dec model.AccessDecision) error {
	if dec.TenantID != event.TenantID {
		return fmt.Errorf("access decision tenant_id does not match tool call event")
	}
	if dec.Decision != "allow" {
		return fmt.Errorf("access decision %s is %s", dec.ID, dec.Decision)
	}
	if dec.ActorNHIID != nil && *dec.ActorNHIID != "" && *dec.ActorNHIID != event.ActorNHIID {
		return fmt.Errorf("access decision actor_nhi_id does not match tool call event")
	}
	if dec.ToolID != nil && *dec.ToolID != "" && *dec.ToolID != event.ToolID {
		return fmt.Errorf("access decision tool_id does not match tool call event")
	}
	if dec.ToolActionType != nil && *dec.ToolActionType != "" && *dec.ToolActionType != event.ActionType {
		return fmt.Errorf("access decision tool_action_type does not match tool call event")
	}
	if event.DelegatedAccessGrantID != nil && *event.DelegatedAccessGrantID != "" && dec.DelegatedAccessGrantID != nil && *dec.DelegatedAccessGrantID != *event.DelegatedAccessGrantID {
		return fmt.Errorf("access decision delegated_access_grant_id does not match tool call event")
	}
	if event.HumanApprovalEventID != nil && *event.HumanApprovalEventID != "" && dec.HumanApprovalEventID != nil && *dec.HumanApprovalEventID != *event.HumanApprovalEventID {
		return fmt.Errorf("access decision human_approval_event_id does not match tool call event")
	}
	if event.PolicyID != nil && *event.PolicyID != "" && dec.PolicyID != *event.PolicyID {
		return fmt.Errorf("access decision policy_id does not match tool call event")
	}
	return nil
}

func proxyToConnector(w http.ResponseWriter, r *http.Request, proxyClient *http.Client, target, applicationID, connectorID string, dec model.AccessDecision) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	resp, err := proxyClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("content-type", resp.Header.Get("content-type"))
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("proxy connector response: %v", err)
	}
}

func proxyViaTunnel(w http.ResponseWriter, r *http.Request, session *tunnel.Session, applicationID string, routeProfiles map[string]edgeplane.ApplicationRouteProfile) {
	response, err := session.RoundTrip(r.Context(), tunnel.Frame{
		Type:          tunnel.FrameHTTPRequest,
		RequestID:     randomEdgeID("req_", time.Now().UTC()),
		ApplicationID: applicationID,
		Method:        http.MethodGet,
		Path:          edgeplane.ApplicationPrivatePath(applicationID, routeProfiles),
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	contentType := response.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadGateway
	}
	w.Header().Set("content-type", contentType)
	w.WriteHeader(statusCode)
	if _, err := io.WriteString(w, response.Body); err != nil {
		log.Printf("write tunnel response: %v", err)
	}
}

func splitPaths(value string) []string {
	parts := strings.Split(value, ",")
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			paths = append(paths, trimmed)
		}
	}
	return paths
}

func networkExtensionRuntimeCopyDownstreamPassthroughConfig(devMode bool, labTLSInterceptionHosts string, transportScope string, explicitSigningIdentifiers string, explicitDefaultTunnelEnabled bool) ([]string, bool) {
	identifiers := splitPaths(explicitSigningIdentifiers)
	if len(identifiers) > 0 {
		return identifiers, explicitDefaultTunnelEnabled
	}
	if devMode &&
		strings.TrimSpace(labTLSInterceptionHosts) != "" &&
		strings.TrimSpace(transportScope) == "real_edge" {
		return []string{"a.out"}, true
	}
	return identifiers, explicitDefaultTunnelEnabled
}

func splitOptionalCSV(value string) []string {
	if value == "" {
		return nil
	}
	return splitPaths(value)
}

func sourceIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func boolPtr(value bool) *bool {
	return &value
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func intMapValue(values map[string]any, key string) int {
	if values == nil {
		return 0
	}
	value, ok := values[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed)
		}
	case string:
		parsed, err := strconv.Atoi(typed)
		if err == nil {
			return parsed
		}
	}
	return 0
}

func firstNonEmptyString(values ...any) string {
	for _, value := range values {
		if text := strings.TrimSpace(stringValue(value)); text != "" {
			return text
		}
	}
	return ""
}

func copyStringMap(input map[string]string) map[string]string {
	copied := map[string]string{}
	for key, value := range input {
		copied[key] = value
	}
	return copied
}

func copyAnyMap(input map[string]any) map[string]any {
	copied := map[string]any{}
	for key, value := range input {
		copied[key] = value
	}
	return copied
}

func stringSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func mapMetadata(value any) map[string]any {
	metadata, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return metadata
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// loadCatalogFeedTrustedKeys reads a JSON map of signing_key_id -> base64(std) ed25519 public key. An empty
// path yields an empty ring (no feed can be applied; the built-in default catalog is served).
func loadCatalogFeedTrustedKeys(path string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	if strings.TrimSpace(path) == "" {
		return keys, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// A missing keyring disables the feed (built-in default served) rather than failing startup — the
			// feed is opt-in; an operator provisions the keyring to enable it.
			return keys, nil
		}
		return nil, fmt.Errorf("read catalog feed trusted keys: %w", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse catalog feed trusted keys: %w", err)
	}
	for id, b64 := range raw {
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("decode catalog feed key %q: %w", id, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("catalog feed key %q has length %d, want %d", id, len(pub), ed25519.PublicKeySize)
		}
		keys[id] = ed25519.PublicKey(pub)
	}
	return keys, nil
}

func loadEdgeTrustedKeyring(path, tenantID string) (model.TrustedKeyring, error) {
	keyring := model.TrustedKeyring{
		TenantID: tenantID,
		Version:  "local",
		Keys:     []model.TrustedKeyringKey{},
		Metadata: map[string]any{"source": "local_edge_default"},
	}
	if strings.TrimSpace(path) == "" {
		return keyring, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return keyring, fmt.Errorf("read trusted keyring: %w", err)
	}
	if err := json.Unmarshal(data, &keyring); err != nil {
		return keyring, fmt.Errorf("parse trusted keyring: %w", err)
	}
	if keyring.TenantID == "" {
		keyring.TenantID = tenantID
	}
	if keyring.Version == "" {
		keyring.Version = "local"
	}
	if keyring.Metadata == nil {
		keyring.Metadata = map[string]any{}
	}
	if tenantID != "" && keyring.TenantID != tenantID {
		return keyring, fmt.Errorf("trusted keyring tenant_id %s does not match policy bundle tenant_id %s", keyring.TenantID, tenantID)
	}
	return keyring, nil
}

func validateInputSchemas(schemaDir string, policyPaths []string, bundlePath string) error {
	if schemaDir == "" {
		return nil
	}
	policySchemaPath := filepath.Join(schemaDir, "policy.schema.json")
	for _, policyPath := range policyPaths {
		if err := schema.ValidateRequiredFiles(policySchemaPath, policyPath); err != nil {
			return fmt.Errorf("validate policy %s: %w", policyPath, err)
		}
	}
	bundleSchemaPath := filepath.Join(schemaDir, "policy_bundle.schema.json")
	if err := schema.ValidateRequiredFiles(bundleSchemaPath, bundlePath); err != nil {
		return fmt.Errorf("validate policy bundle %s: %w", bundlePath, err)
	}
	return nil
}
