package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_site_store.go — Connector UX Slice 1b (// #1). Slice 1 made a
// Site a read-only PROJECTION of connectors grouped by connector_group_id. Slice 1b adds a persistent Site as a
// first-class product object: an administrator creates a Site (name, region, expected connector count, routing
// namespace, deployment type, HA policy) BEFORE any connector exists, then generates an enrollment command.
//
// The store mirrors the multi-tenant tenant model store exactly (admin_tenant_model_store.go +
// admin_tenant_model_postgres.go + postgres_migrations.go): a file/in-memory store for the lab default and a
// Postgres backend behind the same interface, every query tenant-scoped, with the on-disk migration kept in
// lockstep with an in-code schema contract.
//
// Secret-safe by construction: the persisted model carries a bootstrap-secret HASH only (never the plaintext),
// and HTTP responses are built from the secret-safe adminSite projection (which has no hash field), so a hash can
// never reach a Site response. The bootstrap secret plaintext is returned exactly ONCE by the enrollment-command
// endpoint, matching the connector runtime-secret convention.
//
// Lab invariant: with -site-store unset the store is in-memory and starts EMPTY, so GET /admin/sites merges no
// metadata and reproduces the Slice 1 projection byte-for-byte; existing connector enrollment is untouched.

// adminSiteModel is the persistent Site / Connector Group record. site_id doubles as the connector_group_id (the
// projection key), so a persisted Site and its connectors line up on the same id. The bootstrap-secret fields are
// server-managed and never serialized into an admin Site response (responses use the adminSite projection).
type adminSiteModel struct {
	SiteID                 string `json:"site_id"`
	TenantID               string `json:"tenant_id"`
	Name                   string `json:"name,omitempty"`
	Region                 string `json:"region,omitempty"`
	ExpectedConnectorCount int    `json:"expected_connector_count"`
	RoutingNamespace       string `json:"routing_namespace,omitempty"`
	DeploymentType         string `json:"deployment_type,omitempty"`
	HAPolicy               string `json:"ha_policy,omitempty"`
	// BootstrapSecretHash is the sha256:<hex> hash of the last-issued enrollment bootstrap secret. Persisted so a
	// future register path can verify it (additive; not wired into register yet — lab keeps -connector-secret).
	// Never returned in an admin Site response: HTTP uses the adminSite projection which omits it.
	BootstrapSecretHash      string  `json:"bootstrap_secret_hash,omitempty"`
	BootstrapSecretRotatedAt *string `json:"bootstrap_secret_rotated_at,omitempty"`
	CreatedAt                *string `json:"created_at"`
	UpdatedAt                *string `json:"updated_at"`
}

var errAdminSitePersistence = errors.New("site storage unavailable")

// adminSiteStore is the tenant-scoped Site persistence surface. Satisfied by *adminSiteFileStore (file/in-memory)
// and *postgresAdminSiteStore. Every method is tenant-scoped: a tenant can never read/write another tenant's
// Sites (the projection's cross-tenant fail-closed behavior is preserved end to end).

type adminSiteStore interface {
	List(ctx context.Context, tenantID string) ([]adminSiteModel, error)
	Get(ctx context.Context, tenantID, siteID string) (adminSiteModel, bool, error)
	Upsert(ctx context.Context, site adminSiteModel, now time.Time) (adminSiteModel, error)
	Delete(ctx context.Context, tenantID, siteID string) error
	// ConfigGeneration is a monotonic counter that advances on every write. The config bundle's version is a
	// sum of these, and an Edge applies a bundle only when that number is newer.
	//
	// ★★★ IT IS IN THE INTERFACE BECAUSE THE TYPE ASSERTION IS WHAT ALLOWED THE SILENCE (2026-08-24). The
	// bundle collected this through `store.(interface{ ConfigGeneration() uint64 })`, so a backend without
	// the method contributed 0 and nothing said so. The file store had it; the POSTGRES store — the one a
	// production deployment uses — did not, so authoring a Site changed the bundle's contents and never its
	// version, and no connector could enrol on any real deployment. Here, a backend that omits it does not
	// compile.
	ConfigGeneration() uint64
}

type adminSiteFileStore struct {
	mu    sync.RWMutex
	sites map[string]adminSiteModel // key: tenantID + "\x00" + siteID
	// path is an optional durable snapshot file (JSON). "" = in-memory only — the lab default, which starts empty
	// so the Site projection is unchanged. When set, the store loads it on construction and atomically rewrites it
	// after every mutation, the same file durability the tenant model store uses.
	path string
	// generation advances on every mutation, and the config bundle's aggregate generation includes it.
	//
	// ★★★ WITHOUT IT NOTHING PROPAGATES (2026-08-23, measured). An Edge applies a bundle only when the
	// aggregate generation is NEWER than what it last applied. The Site section was added to the bundle,
	// published correctly, and never applied: creating a Site on the control plane changed the bundle's
	// CONTENTS without changing its VERSION. Exactly what the tenant registry's note beside the sum records
	// about organizations, one store later.
	generation uint64
}

// ConfigGeneration is this store's contribution to the bundle's aggregate generation. Monotonic within a
// process; a restart resets it, which the bundle's EPOCH already covers — an Edge that sees a new epoch
// re-baselines rather than concluding the config went backwards.
func (store *adminSiteFileStore) ConfigGeneration() uint64 {
	if store == nil {
		return 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.generation
}

type adminSiteSnapshot struct {
	Sites []adminSiteModel `json:"sites"`
}

func newAdminSiteStore() *adminSiteFileStore {
	return newDurableAdminSiteStore("")
}

// newDurableAdminSiteStore builds the store, loading from the durable snapshot at path when present. A non-empty
// path makes the store restart-resilient; "" keeps it in-memory (lab default, starts empty).
func newDurableAdminSiteStore(path string) *adminSiteFileStore {
	store := &adminSiteFileStore{sites: map[string]adminSiteModel{}, path: strings.TrimSpace(path)}
	if store.path != "" {
		if loaded, ok := loadAdminSiteSnapshot(store.path); ok {
			for _, site := range loaded {
				store.sites[adminSiteKey(site.TenantID, site.SiteID)] = site
			}
		}
	}
	return store
}

func adminSiteKey(tenantID, siteID string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(siteID)
}

func loadAdminSiteSnapshot(path string) ([]adminSiteModel, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	var snapshot adminSiteSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, false
	}
	return snapshot.Sites, true
}

// mutatedLocked persists before advancing the generation. The caller holds the
// write lock and restores its mutation if persistence fails.
func (store *adminSiteFileStore) mutatedLocked() error {
	if err := store.persistLocked(); err != nil {
		return fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	store.generation++
	return nil
}

func (store *adminSiteFileStore) persistLocked() error {
	if store.path == "" {
		return nil
	}
	sites := make([]adminSiteModel, 0, len(store.sites))
	for _, site := range store.sites {
		sites = append(sites, site)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].TenantID != sites[j].TenantID {
			return sites[i].TenantID < sites[j].TenantID
		}
		return sites[i].SiteID < sites[j].SiteID
	})
	data, err := json.MarshalIndent(adminSiteSnapshot{Sites: sites}, "", "  ")
	if err != nil {
		return err
	}
	tmp := store.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(store.path), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, store.path)
}

func (store *adminSiteFileStore) List(_ context.Context, tenantID string) ([]adminSiteModel, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := make([]adminSiteModel, 0)
	for _, site := range store.sites {
		if site.TenantID == tenantID {
			out = append(out, site)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SiteID < out[j].SiteID })
	return out, nil
}

func (store *adminSiteFileStore) Get(_ context.Context, tenantID, siteID string) (adminSiteModel, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	siteID = strings.TrimSpace(siteID)
	if tenantID == "" {
		return adminSiteModel{}, false, fmt.Errorf("tenant_id is required")
	}
	if siteID == "" {
		return adminSiteModel{}, false, fmt.Errorf("site_id is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	site, ok := store.sites[adminSiteKey(tenantID, siteID)]
	if !ok {
		return adminSiteModel{}, false, nil
	}
	return site, true, nil
}

func (store *adminSiteFileStore) Upsert(_ context.Context, site adminSiteModel, now time.Time) (adminSiteModel, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := adminSiteKey(site.TenantID, site.SiteID)
	if existing, ok := store.sites[key]; ok {
		if site.CreatedAt == nil {
			site.CreatedAt = copyStringPtr(existing.CreatedAt)
		}
		// Bootstrap-secret material is server-managed (issued only by the enrollment-command path). A plain Upsert
		// (e.g. a Console metadata edit) never carries it, so preserve the existing hash/rotated-at.
		if strings.TrimSpace(site.BootstrapSecretHash) == "" {
			site.BootstrapSecretHash = existing.BootstrapSecretHash
			site.BootstrapSecretRotatedAt = copyStringPtr(existing.BootstrapSecretRotatedAt)
		}
	}
	normalized, err := normalizeAdminSiteModel(site, now)
	if err != nil {
		return adminSiteModel{}, err
	}
	previous, existed := store.sites[key]
	store.sites[key] = normalized
	if err := store.mutatedLocked(); err != nil {
		if existed {
			store.sites[key] = previous
		} else {
			delete(store.sites, key)
		}
		return adminSiteModel{}, err
	}
	return normalized, nil
}

func (store *adminSiteFileStore) Delete(_ context.Context, tenantID, siteID string) error {
	tenantID = strings.TrimSpace(tenantID)
	siteID = strings.TrimSpace(siteID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if siteID == "" {
		return fmt.Errorf("site_id is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := adminSiteKey(tenantID, siteID)
	if _, ok := store.sites[key]; !ok {
		return nil // idempotent
	}
	previous := store.sites[key]
	delete(store.sites, key)
	if err := store.mutatedLocked(); err != nil {
		store.sites[key] = previous
		return err
	}
	return nil
}

// normalizeAdminSiteModel validates and canonicalizes a Site record. site_id and tenant_id are mandatory; the
// rest are optional tokens / display text. Reuses the tenant-model validators so the safety rules are identical.
func normalizeAdminSiteModel(site adminSiteModel, now time.Time) (adminSiteModel, error) {
	site.SiteID = strings.TrimSpace(site.SiteID)
	if site.SiteID == "" {
		return adminSiteModel{}, fmt.Errorf("site_id is required")
	}
	if strings.Contains(site.SiteID, "/") {
		return adminSiteModel{}, fmt.Errorf("site_id cannot contain slash")
	}
	if !safeAdminTenantToken(site.SiteID) {
		return adminSiteModel{}, fmt.Errorf("site_id is invalid")
	}
	site.TenantID = strings.TrimSpace(site.TenantID)
	if site.TenantID == "" {
		return adminSiteModel{}, fmt.Errorf("tenant_id is required")
	}
	if !safeAdminTenantToken(site.TenantID) {
		return adminSiteModel{}, fmt.Errorf("tenant_id is invalid")
	}
	site.Name = strings.TrimSpace(site.Name)
	if site.Name != "" && !safeAdminTenantDisplayText(site.Name) {
		return adminSiteModel{}, fmt.Errorf("name is invalid")
	}
	if err := normalizeAdminTenantOptionalToken(&site.Region, "region"); err != nil {
		return adminSiteModel{}, err
	}
	if err := normalizeAdminTenantOptionalToken(&site.RoutingNamespace, "routing_namespace"); err != nil {
		return adminSiteModel{}, err
	}
	if err := normalizeAdminTenantOptionalToken(&site.DeploymentType, "deployment_type"); err != nil {
		return adminSiteModel{}, err
	}
	if err := normalizeAdminTenantOptionalToken(&site.HAPolicy, "ha_policy"); err != nil {
		return adminSiteModel{}, err
	}
	if site.ExpectedConnectorCount < 0 {
		return adminSiteModel{}, fmt.Errorf("expected_connector_count must be non-negative")
	}
	site.BootstrapSecretHash = strings.TrimSpace(site.BootstrapSecretHash)
	if site.BootstrapSecretHash != "" && !connectorRuntimeSecretHashValid(site.BootstrapSecretHash) {
		return adminSiteModel{}, fmt.Errorf("bootstrap_secret_hash must be sha256:<64 lowercase hex>")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if site.CreatedAt != nil {
		if err := normalizeAdminRFC3339StringPtr(&site.CreatedAt, "created_at"); err != nil {
			return adminSiteModel{}, err
		}
	}
	if site.CreatedAt == nil {
		createdAt := now.UTC().Format(time.RFC3339)
		site.CreatedAt = &createdAt
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	site.UpdatedAt = &updatedAt
	return site, nil
}

// adminSiteEnrollmentCommandResponse is the once-only enrollment-command payload. BootstrapSecret is the
// plaintext bootstrap secret returned EXACTLY ONCE (only its hash is persisted). The Console must surface it with
// a copy-now-it-will-not-be-shown-again warning, the same convention as the connector runtime secret.
type adminSiteEnrollmentCommandResponse struct {
	SiteID          string `json:"site_id"`
	TenantID        string `json:"tenant_id"`
	Command         string `json:"command"`
	Token           string `json:"token"`
	BootstrapSecret string `json:"bootstrap_secret"`
	IssuedAt        string `json:"issued_at"`
	// Warning is a human-readable reminder that the secret is shown only once (also enforced by the API: only the
	// hash is stored).
	Warning string `json:"warning"`
	// Doors is every address this connector will be able to reach the deployment on, in order, and Note says
	// what that list means for the estate behind it.
	//
	// ★★★ THE SCREEN ISSUED A CREDENTIAL AND SHOWED NOTHING ABOUT WHAT IT CONFIGURES (2026-08-26). The device
	// profile screen beside it states its own rule: nothing is typed, every value is one the deployment
	// already knows — and it shows them, because an operator deciding whether this is right has to be able to
	// SEE it. This modal printed one opaque token and a command. Whether the connector it produces can survive
	// losing a region was invisible, and it could not, which is how that went unnoticed.
	Doors     []string `json:"doors"`
	DoorsNote string   `json:"doors_note"`
	// CAPinned is whether this connector's first connection — the one carrying its CSR — verifies what it is
	// talking to. Shown because it is the moment that matters most and the one nobody can check afterwards.
	CAPinned bool `json:"ca_pinned"`
	// VerifyCommand is what the customer runs on the same machine afterwards to find out what it ended up
	// with. See adminSiteEnrollmentVerifyCommand.
	VerifyCommand string `json:"verify_command"`
	// Profile is the same issue in the form a customer can carry: a file to download and hand to the
	// installer, instead of a wall of base64 to select out of a browser. See connectorInstallProfile.
	//
	// ★★★ IT IS THE SAME ISSUE, NOT A SECOND ONE. Minting rotates the Site's bootstrap secret, so a customer
	// who downloaded a profile and then pressed the button again for a command holds one working credential
	// and one that silently is not. Both representations therefore come out of THIS response.
	Profile connectorInstallProfile `json:"profile"`
}

// connectorInstallProfile is the downloadable half of "Add connector" — a connector's equivalent of the
// endpoint agent's install profile, carrying the one-time token together with the durable configuration.
//
// ★ THE FILE IS A CREDENTIAL UNTIL THE FIRST RUN, and Note says so in the file itself, because a file is
// copied, mailed and left in a downloads folder in a way a screen that says it once is not.
type connectorInstallProfile struct {
	Kind          string   `json:"kind"`
	IssuedAt      string   `json:"issued_at,omitempty"`
	TenantID      string   `json:"tenant_id"`
	Site          string   `json:"site"`
	EdgeEndpoints []string `json:"edge_endpoints"`
	EdgeCAPEM     string   `json:"edge_ca,omitempty"`
	StateDir      string   `json:"state_dir,omitempty"`
	Token         string   `json:"token"`
	Note          string   `json:"note,omitempty"`
	// ★★★ THE ORGANIZATION'S OWN DOOR, WHICH THIS FILE NEVER CARRIED (2026-09-07, found by giving twenty
	// organizations a connector each). A device's profile has carried the organization's transport name and
	// its own transport anchors since 2026-08-28; a connector's carried EdgeCAPEM alone, and EdgeCAPEM is a
	// node-wide flag pointing at the deployment anchor. So every connector of every organization dialled the
	// shared name and pinned the deployment's root, on a deployment where all three regions were already
	// serving that organization's own certificate for its own name.
	//
	// ★★ EMITTED ONLY WHEN THE ORGANIZATION HAS AN AUTHORITY IN FORCE HERE, and the two fields move together:
	// a name without anchors turns every dial into a verification failure, and anchors without a name pin a
	// certificate that will never be offered. Absent means "the deployment's shared certificate", which is
	// what a connector has always been given and stays correct for an organization that has no door of its own.
	OrganizationServerName string `json:"organization_server_name,omitempty"`
	// OrganizationEnrolmentServerName is the name for the connection that carries the CSR. The Edge folds
	// enrolment onto the transport port BY the name in the ClientHello, so the first connection asks for
	// "enrol." + the organization's name — the same name, and the same reasoning, as a device's.
	OrganizationEnrolmentServerName string `json:"organization_enrolment_server_name,omitempty"`
	// OrganizationAnchorsPEM is the organization's own transport authority: what this connector verifies the
	// Edge against instead of the deployment root, for every connection under the two names above.
	OrganizationAnchorsPEM string `json:"organization_anchors,omitempty"`
}

// connectorInstallProfileKind is the schema discriminator the installer checks, so that another of this
// deployment's JSON documents landing in the same downloads folder is refused by name rather than applied.
const connectorInstallProfileKind = "dsse_connector_install_profile.v1"

func buildConnectorInstallProfile(tenantID, siteID, token, issuedAt string, p enrollmentTokenParams) connectorInstallProfile {
	stateDir := strings.TrimSpace(p.StateDir)
	if stateDir == "" {
		stateDir = "/var/lib/dsse-connector"
	}
	return connectorInstallProfile{
		Kind:          connectorInstallProfileKind,
		IssuedAt:      issuedAt,
		TenantID:      strings.TrimSpace(tenantID),
		Site:          strings.TrimSpace(siteID),
		EdgeEndpoints: enrollmentDoorList(p),
		EdgeCAPEM:     strings.TrimSpace(p.EdgeCAPEM),
		StateDir:      stateDir,
		Token:         token,
		Note: "This file is a credential until the connector it installs has run once. " +
			connectorProfileNote(enrollmentDoorList(p)),
		OrganizationServerName:          strings.TrimSpace(p.OrganizationServerName),
		OrganizationEnrolmentServerName: strings.TrimSpace(p.OrganizationEnrolmentServerName),
		OrganizationAnchorsPEM:          strings.TrimSpace(p.OrganizationAnchorsPEM),
	}
}

// enrollmentTokenParams are the Edge-side coordinates folded into a connector's one-time token so its first run
// needs no edge-url/tenant/site flags. EdgeCAPEM (the transport CA to pin) is public, not a secret. StateDir is
// only rendered into the shown command (where the connector persists after enrolling).
type enrollmentTokenParams struct {
	EdgeURL string
	// EdgeEndpoints is every door this deployment answers on, "region=URL;region=URL". See
	// a_connector_is_given_every_door.go: without it a connector installed the supported way has one door and
	// cannot fail over.
	EdgeEndpoints string
	Region        string
	Cluster       string
	EdgeCAPEM     string
	StateDir      string
	// OrganizationServerName / OrganizationEnrolmentServerName / OrganizationAnchorsPEM are the organization's
	// own door and the authority that signs it. Set together or not at all — see connectorInstallProfile.
	OrganizationServerName          string
	OrganizationEnrolmentServerName string
	OrganizationAnchorsPEM          string
}

// buildConnectorEnrollmentToken encodes everything a connector needs to reach and enroll into its Site into one
// opaque base64url token (the Console's "Add connector" hands this out; it is single-use + short-lived).
func buildConnectorEnrollmentToken(tenantID, siteID, bootstrapSecret string, p enrollmentTokenParams) string {
	payload := map[string]any{
		"v":         1,
		"edge_url":  strings.TrimSpace(p.EdgeURL),
		"tenant_id": strings.TrimSpace(tenantID),
		"site":      strings.TrimSpace(siteID),
		"bootstrap": strings.TrimSpace(bootstrapSecret),
	}
	if strings.TrimSpace(p.EdgeEndpoints) != "" {
		payload["edge_endpoints"] = strings.TrimSpace(p.EdgeEndpoints)
	}
	if strings.TrimSpace(p.Region) != "" {
		payload["region"] = strings.TrimSpace(p.Region)
	}
	if strings.TrimSpace(p.Cluster) != "" {
		payload["cluster"] = strings.TrimSpace(p.Cluster)
	}
	if strings.TrimSpace(p.EdgeCAPEM) != "" {
		payload["edge_ca"] = p.EdgeCAPEM
	}
	// The organization's own door travels in the token as well as the profile, because the printed command
	// carries only the token and a connector installed from it must reach the same place as one installed
	// from the file.
	if n := strings.TrimSpace(p.OrganizationServerName); n != "" && strings.TrimSpace(p.OrganizationAnchorsPEM) != "" {
		payload["org_server_name"] = n
		payload["org_anchors"] = strings.TrimSpace(p.OrganizationAnchorsPEM)
		if e := strings.TrimSpace(p.OrganizationEnrolmentServerName); e != "" {
			payload["org_enrol_server_name"] = e
		}
	}
	data, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(data)
}

// adminSiteEnrollmentCommand renders the ONE self-contained command an operator runs to bring up a connector: a
// single --token (which carries the Edge URL, tenant, Site, and pinned CA) plus a --state-dir the connector
// persists into, so every later start reconnects with no token.
//
// ★★★ IT USED TO END IN TWO BLANKS TO FILL (2026-08-23, measured). The last two lines were
// "--connector-client-cert <your connector certificate>" and its key — a placeholder, because the Edge requires
// a certificate issued by the connector's own organization and the token could not carry one. Running the
// command as printed enrolled the connector and then stopped:
//
//	connector transport TLS: connector identity certificate is mandatory outside dev mode (mTLS)
//
// A command with a blank in it is not a command, and "go and run a certificate authority first" is not a step
// a product gets to ask for. The connector now obtains that certificate as part of its first run, through the
// same POST /enroll a laptop uses — see connector_enrolment_identity.go — so what is printed here is the whole
// of it again. An operator who issues connector identities from their own PKI still passes the two flags by
// hand and is left alone; they are simply no longer the only way to start.
// ★★★ AND IT USED TO HAND OUT A PROCESS, NOT AN INSTALLATION (2026-08-26, operator's instruction). What was
// printed here started `dsse-connector` in a terminal: not a service, nothing that comes back after a reboot,
// and no answer to "did that work" beyond the absence of an error. Everything a customer needed after typing
// it — did it enrol, did the deployment issue it an identity, can it reach more than one region — was left to
// whoever typed it. The command below installs instead: it places the program and a service, refuses to write
// anything when the token names no address to dial, and says what it made. See cmd/dsse-connector-install.
//
// The raw `dsse-connector` line still works and is what an operator issuing connector identities from their
// own PKI runs by hand. It is no longer what a customer is HANDED, because a customer being handed the harder
// path with no way to check it is how a connector spent a day fronting nothing while every screen was green.
func adminSiteEnrollmentCommand(token, stateDir string) string {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		stateDir = "/var/lib/dsse-connector"
	}
	lines := []string{
		"dsse-connector-install \\",
		"  --token " + token + " \\",
		"  --state-dir " + stateDir,
	}
	return strings.Join(lines, "\n")
}

// adminSiteEnrollmentVerifyCommand is the second half of the same screen: the one thing the customer can run
// to find out whether the first half worked.
//
// ★ IT IS SHOWN BECAUSE THE ANSWER IS NOT VISIBLE FROM HERE. The Console shows a connector as Connected the
// moment a tunnel arrives, and a connector holding ONE of its two doors looks exactly like a connector holding
// both — until the day the door it holds is the one that goes. That question is answered on the machine, by
// dialling the doors with the connector's own material, so it is asked there.
func adminSiteEnrollmentVerifyCommand(stateDir string) string {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		stateDir = "/var/lib/dsse-connector"
	}
	return "dsse-connector-install --verify --state-dir " + stateDir
}

// adminSiteEnrollmentCommandIssue mints a fresh bootstrap secret for a Site, persists ONLY its hash (rotating any
// previous one), and returns the plaintext exactly once with the rendered command. The Site must already exist
// (found=false otherwise) so an enrollment command is always bound to a real, tenant-scoped Site.
func adminSiteEnrollmentCommandIssue(ctx context.Context, store adminSiteStore, tenantID, siteID string, params enrollmentTokenParams, now time.Time) (adminSiteEnrollmentCommandResponse, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	siteID = strings.TrimSpace(siteID)
	if tenantID == "" {
		return adminSiteEnrollmentCommandResponse{}, false, fmt.Errorf("tenant_id is required")
	}
	if siteID == "" {
		return adminSiteEnrollmentCommandResponse{}, false, fmt.Errorf("site_id is required")
	}
	if strings.Contains(siteID, "/") {
		return adminSiteEnrollmentCommandResponse{}, false, fmt.Errorf("site_id cannot contain slash")
	}
	site, ok, err := store.Get(ctx, tenantID, siteID)
	if err != nil {
		return adminSiteEnrollmentCommandResponse{}, false, err
	}
	if !ok {
		// The Site is projection-only so far: its record is derived from a live connector's group id and was
		// never persisted. Adding a connector to a Site shown in the Console must not 404 — persist a minimal
		// Site so it can carry the bootstrap-secret hash below.
		site = adminSiteModel{SiteID: siteID, TenantID: tenantID}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	secret, err := randomURLToken(32)
	if err != nil {
		return adminSiteEnrollmentCommandResponse{}, false, fmt.Errorf("generate bootstrap secret: %w", err)
	}
	issuedAt := now.UTC().Format(time.RFC3339)
	site.BootstrapSecretHash = connectorRuntimeSecretHash(secret)
	site.BootstrapSecretRotatedAt = &issuedAt
	if _, err := store.Upsert(ctx, site, now); err != nil {
		return adminSiteEnrollmentCommandResponse{}, false, err
	}
	token := buildConnectorEnrollmentToken(tenantID, siteID, secret, params)
	return adminSiteEnrollmentCommandResponse{
		SiteID:          siteID,
		TenantID:        tenantID,
		Command:         adminSiteEnrollmentCommand(token, params.StateDir),
		VerifyCommand:   adminSiteEnrollmentVerifyCommand(params.StateDir),
		Profile:         buildConnectorInstallProfile(tenantID, siteID, token, issuedAt, params),
		Token:           token,
		BootstrapSecret: secret,
		IssuedAt:        issuedAt,
		Warning:         "Copy the bootstrap secret now; it is shown only once and only its hash is stored.",
		// ★ WHAT THIS CREDENTIAL CONFIGURES, SHOWN. See the field comments: a screen that issues a credential
		// and says nothing about the connector it produces cannot be checked by the person pressing the button.
		Doors:     enrollmentDoorList(params),
		DoorsNote: connectorProfileNote(enrollmentDoorList(params)),
		CAPinned:  strings.TrimSpace(params.EdgeCAPEM) != "",
	}, true, nil
}

// enrollmentDoorList is the doors this token gives a connector, in order — the list when the deployment has
// one, otherwise the single address it knows.
func enrollmentDoorList(p enrollmentTokenParams) []string {
	if list := strings.TrimSpace(p.EdgeEndpoints); list != "" {
		// ★ SPLIT THE WAY THE CONNECTOR SPLITS. cmd/dsse-connector/region_failover.go accepts ';' ',' and a
		// newline; this accepted only ';'. A comma-separated pair therefore counted as ONE door, and the
		// screen this feeds told the operator their site had a single address — under the warning about what
		// a single address means — while the connector was quietly failing over between two. The screen and
		// the program have to read the operator's list identically or the screen is fiction.
		out := []string{}
		for _, entry := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ',' || r == '\n' }) {
			if entry = strings.TrimSpace(entry); entry != "" {
				out = append(out, entry)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if u := strings.TrimSpace(p.EdgeURL); u != "" {
		return []string{u}
	}
	return nil
}

// adminSiteAuditLog records a Site lifecycle action (create / update / delete / enrollment-command) with the same
// non-secret metadata boundary as the connector management audit: the bootstrap secret and its hash are never
// recorded (only a boolean that one is configured).
func adminSiteAuditLog(eventType string, site adminSiteModel, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := strings.TrimPrefix(eventType, "admin_site_")
	result := "success"
	reason := "Site lifecycle action by admin."
	targetType := "admin_site"
	siteID := site.SiteID
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       site.TenantID,
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &siteID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"name_present":                site.Name != "",
			"region_present":              site.Region != "",
			"expected_connector_count":    site.ExpectedConnectorCount,
			"routing_namespace_present":   site.RoutingNamespace != "",
			"deployment_type_present":     site.DeploymentType != "",
			"ha_policy_present":           site.HAPolicy != "",
			"bootstrap_secret_configured": site.BootstrapSecretHash != "",
			"bootstrap_secret_recorded":   false,
			"reason_codes":                []string{"admin_site_lifecycle"},
		},
	}
}
