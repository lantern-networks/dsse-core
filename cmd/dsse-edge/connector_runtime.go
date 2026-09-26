package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	tenantca "github.com/lantern-networks/dsse-core/tenantca"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

const (
	connectorSecretHeader             = "x-connector-secret"
	connectorIDHeader                 = "x-connector-id"
	connectorRuntimeSecretHashPrefix  = "sha256:"
	defaultConnectorSecret            = "local-connector-secret"
	maxConnectorRegistrationBodyBytes = 1 << 20
)

type connectorRegistryStore interface {
	Register(model.ConnectorRegistration, time.Time) (model.ConnectorRegistration, error)
	Heartbeat(model.ConnectorHeartbeat, time.Time) (model.ConnectorRegistration, error)
	RotateRuntimeSecretHashWithMetadata(id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error)
	RotateRuntimeSecretHashForTenantWithMetadata(tenantID, id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error)
	Get(id string) (model.ConnectorRegistration, bool)
	List() []model.ConnectorRegistration
}

// ★★★ THE ADMIN ACTS ASSERTED A CONCRETE TYPE, SO THE DURABLE STORE COULD DO NEITHER (2026-08-25). Renaming
// and removing a connector were reached by asserting *connector.Registry — the in-memory one. The moment the
// control plane was moved to the deployment's database, which is where it belongs, both answered 501: an
// operator could no longer rename a connector, and REMOVING one is how a customer takes a connector's access
// away. A durable store that cannot revoke is worse than the split it fixed.
//
// Named by what the act needs, so a third store is a matter of implementing two methods rather than adding a
// third type assertion.
type connectorRegistryRemover interface {
	RemoveForTenant(tenantID, id string) (bool, error)
}

type connectorRegistryRenamer interface {
	SetDisplayNameForTenant(tenantID, id, name string) (model.ConnectorRegistration, bool, error)
}

// connectorAttachmentRecorder is the slice a node needs to say WHERE a connector's tunnel terminated. Named
// by the act, not by a store: both the in-memory registry and the deployment's database implement it, and a
// third would need this one method rather than another type assertion.
type connectorAttachmentRecorder interface {
	RecordAttachedRegion(id, region string) (bool, error)
}

// connectorLivenessRecorder writes what a reporting Edge OBSERVED about a connector it holds — that it was
// heard from, and what it said — without touching the fields an operator authored. See Registry.RecordLiveness.
type connectorLivenessRecorder interface {
	RecordLiveness(id, status, heartbeatAt string) (bool, error)
}

type connectorRegistryTenantReader interface {
	ListByTenant(ctx context.Context, tenantID string) ([]model.ConnectorRegistration, error)
	GetByTenant(ctx context.Context, tenantID, connectorID string) (model.ConnectorRegistration, bool, error)
}

type connectorRuntimeSecretRotateRequest struct {
	RuntimeSecret string `json:"runtime_secret"`
}

type connectorRuntimeSecretRotateResponse struct {
	Connector     model.ConnectorRegistration `json:"connector"`
	RuntimeSecret string                      `json:"runtime_secret"`
	RotatedAt     string                      `json:"rotated_at"`
}

func appendConnectorLog(ctx context.Context, writer *logs.Writer, domainEventOutbox domainEventOutboxWriter, event map[string]any, now time.Time) error {
	if err := writer.Append("connector.log.jsonl", event); err != nil {
		return fmt.Errorf("write connector log: %w", err)
	}
	if envelope, err := domainEventOutboxEnvelopeFromConnectorLog(event, now); err != nil {
		log.Printf("domain event outbox connector log envelope: %v", err)
	} else {
		appendDomainEventOutbox(ctx, domainEventOutbox, envelope, now)
	}
	return nil
}

func authorizeConnectorRequest(w http.ResponseWriter, r *http.Request, connectorSecret string) bool {
	if connectorSecret == "" {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("connector shared secret is not configured"))
		return false
	}
	if !connectorSecretMatches(r.Header.Get(connectorSecretHeader), connectorSecret) {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("connector shared secret is invalid"))
		return false
	}
	return true
}

// connectorRegistrationSiteBootstrapAuthorized reports whether the presented secret matches the Site's current
// one-time bootstrap-secret hash (minted by the enrollment command / carried in the token). Used to admit a
// brand-new connector's first self-register into its Site without the fleet-shared secret. Returns false (never
// an error) when there is no site store, no Site, or no issued bootstrap secret, so the caller falls back.
func connectorRegistrationSiteBootstrapAuthorized(ctx context.Context, store adminSiteStore, siteID, tenantID, presentedSecret string) bool {
	siteID = strings.TrimSpace(siteID)
	tenantID = strings.TrimSpace(tenantID)
	if store == nil || siteID == "" || tenantID == "" || strings.TrimSpace(presentedSecret) == "" {
		return false
	}
	site, ok, err := store.Get(ctx, tenantID, siteID)
	if err != nil || !ok {
		return false
	}
	hash := strings.TrimSpace(site.BootstrapSecretHash)
	if hash == "" {
		return false
	}
	return connectorRuntimeSecretMatches(presentedSecret, hash)
}

func authorizeConnectorRegistrationRequest(w http.ResponseWriter, r *http.Request, connectorSecret string, registry connectorRegistryStore, connectorID, tenantID string, tenantCAs *tenantca.TenantCARegistry) bool {
	connectorID = strings.TrimSpace(connectorID)
	tenantID = strings.TrimSpace(tenantID)
	// ★★★ REGISTERING IS PART OF CONNECTING TO THE FLEET. A connector holds one tunnel per Edge it is using,
	// so it registers with each — and being unknown to a particular Edge is the ORDINARY state of a connector
	// that has just failed over to it, not a reason to refuse. Its certificate names it and names its
	// organization; that is the same authentication every other Edge accepts. See
	// connector_is_a_fleet_client.go.
	if fleet := connectorFleetIdentityFromRequest(r, connectorID, tenantCAs); fleet.authenticatesAnywhere(tenantCAs) {
		if !fleet.contradictsRegistry(connectorTenantFromRegistry(registry, connectorID)) {
			return true
		}
		writeError(w, http.StatusUnauthorized, fmt.Errorf(
			"connector %q belongs to a different organization here than the certificate presented for it", connectorID))
		return false
	}
	if registry != nil && connectorID != "" && tenantID != "" {
		conn, ok, err := connectorRegistrationForTenantWithContext(r.Context(), registry, connectorID, tenantID)
		if err != nil {
			log.Printf("connector registry registration auth lookup failed: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("connector registry is unavailable"))
			return false
		}
		if ok {
			if hash := connectorRuntimeSecretHashFromMetadata(conn.Metadata); hash != "" {
				if !connectorRuntimeSecretMatches(r.Header.Get(connectorSecretHeader), hash) {
					writeError(w, http.StatusUnauthorized, fmt.Errorf("connector runtime secret is invalid"))
					return false
				}
				return true
			}
		}
	}
	return authorizeConnectorRequest(w, r, connectorSecret)
}

func authorizeConnectorRuntimeRequest(w http.ResponseWriter, r *http.Request, connectorSecret string, registry connectorRegistryStore, connectorID, tenantID string, requireRuntimeSecret bool, tenantCAs *tenantca.TenantCARegistry) bool {
	hash, knownConnector, tenantMatched, err := connectorRuntimeSecretHashForTenantConnector(r.Context(), registry, connectorID, tenantID)
	connectorTenant := connectorTenantFromRegistry(registry, connectorID)
	if err != nil {
		log.Printf("connector registry auth lookup failed: %v", err)
		writeError(w, http.StatusInternalServerError, fmt.Errorf("connector registry is unavailable"))
		return false
	}

	// ★★★ A CONNECTOR CONNECTS TO THE FLEET, NOT TO ONE EDGE (the operator's decision, 2026-08-26). Its
	// certificate names it and names its organization; neither fact belongs to this node, and neither changes
	// from Edge to Edge. See connector_is_a_fleet_client.go for what was measured.
	fleet := connectorFleetIdentityFromRequest(r, connectorID, tenantCAs)
	if fleet.authenticatesAnywhere(tenantCAs) {
		if fleet.contradictsRegistry(connectorTenant) {
			writeError(w, http.StatusUnauthorized, fmt.Errorf(
				"connector %q belongs to a different organization here than the certificate presented for it",
				connectorID))
			return false
		}
		// A runtime secret is verified when this node happens to hold one — a second factor costs nothing when
		// it is there — but its ABSENCE is no longer a refusal, because it only ever meant "this connector has
		// not registered with THIS Edge yet".
		if hash != "" && !connectorRuntimeSecretMatches(r.Header.Get(connectorSecretHeader), hash) {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("connector runtime secret is invalid"))
			return false
		}
		return true
	}

	if !tenantMatched {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("connector is not registered for this tenant"))
		return false
	}
	// strict per-connector authentication: a verified mTLS cert MUST be bound to THIS connector, IN THIS
	// ORGANIZATION. Being CA-signed is not enough — another connector's cert, a device cert, or a certificate
	// naming this connector but issued by another organization's CA (even with the right shared secret) is
	// rejected. A connector belongs to exactly one organization, so its identity has to come from that
	// organization's PKI; see connector_identity_tenant_binding.go.
	//
	// The organization compared against is the one the REGISTRY holds for this connector, not the node's own
	// and not anything the caller said.
	bound, certID, present := connectorMTLSIdentityBoundToTenant(r, connectorID, connectorTenant, tenantCAs)
	if present && !bound {
		writeError(w, http.StatusUnauthorized, fmt.Errorf(
			"connector mTLS identity %q is not bound to connector id %q in its own organization", certID, connectorID))
		return false
	}
	// ★ NOT PRESENTING ONE USED TO BE THE WEAKER PATH (2026-08-19). The check above ran only when a
	// certificate was there, so a caller that presented nothing skipped it entirely and possession of a
	// secret was the whole of the authentication. A gate that is easier to pass by offering less is not a
	// gate. Presentation is now required, and a deployment that cannot yet do it says so out loud.
	if !present && !connectorMTLSPresentationRelaxed {
		writeError(w, http.StatusUnauthorized, fmt.Errorf(
			"this connector did not present a certificate: a connector authenticates with a certificate issued "+
				"by its own organization's device CA, and a shared secret alone is not enough"))
		return false
	}
	if hash != "" {
		if !connectorRuntimeSecretMatches(r.Header.Get(connectorSecretHeader), hash) {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("connector runtime secret is invalid"))
			return false
		}
		return true
	}
	if requireRuntimeSecret {
		if strings.TrimSpace(connectorID) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("connector id is required for runtime secret authentication"))
			return false
		}
		if !knownConnector {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("connector is not registered"))
			return false
		}
		// ★ AND SAY WHICH OF THE TWO THIS IS. A catalog descriptor carries no credential, so this Edge has
		// never seen this connector register — 404 is the true answer and it is the one that makes the
		// connector register here, which is how a credential arrives. 401 said "you are not who you say" and
		// left it retrying for ever against an entry it could not satisfy.
		writeError(w, http.StatusNotFound, fmt.Errorf(
			"this Edge holds a catalog entry for connector %q and no registration — register with this Edge",
			connectorID))
		return false
	}
	return authorizeConnectorRequest(w, r, connectorSecret)
}

func connectorSecretMatches(candidate, expected string) bool {
	candidate = strings.TrimSpace(candidate)
	expected = strings.TrimSpace(expected)
	if candidate == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}

func connectorRuntimeSecretHashForTenantConnector(ctx context.Context, registry connectorRegistryStore, connectorID, tenantID string) (string, bool, bool, error) {
	connectorID = strings.TrimSpace(connectorID)
	if registry == nil || connectorID == "" {
		return "", false, true, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if reader, ok := registry.(connectorRegistryTenantReader); ok && tenantID != "" {
		conn, ok, err := reader.GetByTenant(ctx, tenantID, connectorID)
		if err != nil {
			return "", false, false, err
		}
		if !ok {
			return "", false, false, nil
		}
		return connectorRuntimeSecretHashFromMetadata(conn.Metadata), true, true, nil
	}
	conn, ok := registry.Get(connectorID)
	if !ok {
		return "", false, true, nil
	}
	if tenantID != "" && conn.TenantID != tenantID {
		return "", true, false, nil
	}
	return connectorRuntimeSecretHashFromMetadata(conn.Metadata), true, true, nil
}

func connectorRuntimeSecretHashFromMetadata(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	raw, ok := metadata["runtime_secret_hash"]
	if !ok {
		return ""
	}
	hash, ok := raw.(string)
	if !ok {
		return ""
	}
	hash = strings.TrimSpace(hash)
	if len(hash) != len(connectorRuntimeSecretHashPrefix)+64 || !strings.HasPrefix(hash, connectorRuntimeSecretHashPrefix) {
		return ""
	}
	for _, r := range strings.TrimPrefix(hash, connectorRuntimeSecretHashPrefix) {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return hash
}

func connectorRuntimeSecretMatches(candidate, expectedHash string) bool {
	candidate = strings.TrimSpace(candidate)
	expectedHash = strings.TrimSpace(expectedHash)
	if candidate == "" || expectedHash == "" {
		return false
	}
	return connectorSecretMatches(connectorRuntimeSecretHash(candidate), expectedHash)
}

func connectorRuntimeSecretHash(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return fmt.Sprintf("%s%x", connectorRuntimeSecretHashPrefix, sum)
}

func connectorRuntimeSecretForRotation(request connectorRuntimeSecretRotateRequest) (string, error) {
	secret := strings.TrimSpace(request.RuntimeSecret)
	if secret == "" {
		generated, err := randomURLToken(32)
		if err != nil {
			return "", fmt.Errorf("generate connector runtime secret: %w", err)
		}
		return generated, nil
	}
	if len(secret) < 24 {
		return "", fmt.Errorf("connector runtime_secret must be at least 24 characters")
	}
	return secret, nil
}

func publicConnectorRegistrations(connectors []model.ConnectorRegistration) []model.ConnectorRegistration {
	public := make([]model.ConnectorRegistration, len(connectors))
	for i, conn := range connectors {
		public[i] = publicConnectorRegistration(conn)
	}
	return public
}

func publicConnectorRegistration(conn model.ConnectorRegistration) model.ConnectorRegistration {
	if conn.ApplicationIDs != nil {
		conn.ApplicationIDs = append([]string(nil), conn.ApplicationIDs...)
	}
	if conn.Metadata == nil {
		return conn
	}
	metadata := make(map[string]any, len(conn.Metadata))
	for key, value := range conn.Metadata {
		if key == "runtime_secret_hash" {
			metadata["runtime_secret_configured"] = connectorRuntimeSecretHashFromMetadata(conn.Metadata) != ""
			continue
		}
		metadata[key] = value
	}
	conn.Metadata = metadata
	return conn
}

func authorizeEdgeRuntimeRequestForConnector(w http.ResponseWriter, r *http.Request, connectorSecret string, devMode bool, registry connectorRegistryStore, tenantID string, requireRuntimeSecret bool, tenantCAs *tenantca.TenantCARegistry) bool {
	if devMode {
		return true
	}
	return authorizeConnectorRuntimeRequest(w, r, connectorSecret, registry, r.Header.Get(connectorIDHeader), tenantID, requireRuntimeSecret, tenantCAs)
}

// validateConnectorRuntimeSecretRequiredConfig refuses a deployment where connectors authenticate with ONE
// SHARED SECRET.
//
// ★ IT USED TO ASK WHICH DATABASE, NOT WHICH DEPLOYMENT (2026-08-19, measured on the reference lab). The
// requirement fired only when the connector registry was backed by Postgres — so the reference Edge, which is
// deliberately ZERO-DB and keeps that registry in a FILE, escaped it entirely. The topology this product
// recommends was the topology the guard did not cover, and the lab ran with `-lab-mode` off, no per-connector
// secret registered, and every connector authenticating with the single -connector-secret.
//
// The question a guard like this has to ask is what KIND of deployment this is, and the deployment already
// says so: lab-mode is the declaration that this node is not serving anybody. Everything else must give each
// connector its own credential.
func validateConnectorRuntimeSecretRequiredConfig(devMode bool, connectorRegistryStoreMode string, requireRuntimeSecret bool) error {
	if devMode || requireRuntimeSecret {
		return nil
	}
	return fmt.Errorf("connector-runtime-secret-required must be true outside lab-mode: without it every " +
		"connector authenticates with the one shared -connector-secret, so possessing that secret is enough " +
		"to be any connector this node serves")
}

func connectorApplicationReturnTo(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil {
		return "", false
	}
	// X-Original-URI is the nginx auth_request convention, which is what an ingress in front of this
	// actually sets. It used to be a branded copy of that name — and NOTHING in this repo ever wrote it, so
	// the first candidate was always empty and the return-to silently came from the proxied request URI
	// instead of the external one the user typed. The fallback is still correct and still second.
	for _, candidate := range []string{
		r.Header.Get("x-original-uri"),
		r.URL.RequestURI(),
	} {
		if returnTo, ok := sanitizeOIDCReturnTo(candidate); ok {
			return returnTo, true
		}
	}
	return "", false
}

func connectorForApplication(ctx context.Context, r *http.Request, registry connectorRegistryStore, catalog appcatalog.RuntimeStore, tenantID, applicationID string) (model.ConnectorRegistration, bool, error) {
	// An explicit disabled catalog entry overrides both enumerated connector apps
	// and published-group fallback. Keep absent catalog entries compatible with
	// existing file-defined applications.
	if catalog != nil {
		entry, found, err := catalog.Get(ctx, tenantID, applicationID)
		if err != nil {
			return model.ConnectorRegistration{}, false, fmt.Errorf("application catalog cannot be read")
		}
		if found && entry.Status == "disabled" {
			return model.ConnectorRegistration{}, false, nil
		}
	}
	if connectorID := r.URL.Query().Get("connector_id"); connectorID != "" {
		conn, ok, err := connectorRegistrationForTenantWithContext(ctx, registry, connectorID, tenantID)
		if err != nil {
			return model.ConnectorRegistration{}, false, err
		}
		if !ok {
			return conn, false, nil
		}
		if connectorRouteUnavailable(conn) {
			return model.ConnectorRegistration{}, false, nil
		}
		for _, candidate := range conn.ApplicationIDs {
			if candidate == applicationID {
				return conn, true, nil
			}
		}
		// Connector-group fallback (explicit connector_id): a connector-discovered private app is published with
		// a connector_group_id but is NOT enumerated in the connector's application_ids. If the explicitly chosen
		// connector belongs to the app's published connector group, it fronts the app. Fail-closed: only a
		// published catalog entry with a non-empty group matching this live connector's group resolves.
		if group := publishedConnectorGroupForApplication(ctx, catalog, tenantID, applicationID); group != "" && strings.TrimSpace(conn.ConnectorGroupID) == group {
			return conn, true, nil
		}
		return model.ConnectorRegistration{}, false, nil
	}
	connectors, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenantID)
	if err != nil {
		return model.ConnectorRegistration{}, false, err
	}
	for _, conn := range connectors {
		if connectorRouteUnavailable(conn) {
			continue
		}
		for _, candidate := range conn.ApplicationIDs {
			if candidate == applicationID {
				return conn, true, nil
			}
		}
	}
	// Connector-group fallback (no explicit connector_id): a connector-discovered private app fronts behind a
	// connector GROUP, not an enumerated application_ids list. The approve-private-app path stamps the published
	// catalog entry's connector_group_id from the candidate's observed_from site; without this fallback a
	// freshly-approved discovered app reports "No reachable connector" even though a live connector in its group
	// fronts it. Fail-closed: requires a published entry with a non-empty group AND a live connector in exactly
	// that group.
	if group := publishedConnectorGroupForApplication(ctx, catalog, tenantID, applicationID); group != "" {
		for _, conn := range connectors {
			if connectorRouteUnavailable(conn) {
				continue
			}
			if strings.TrimSpace(conn.ConnectorGroupID) == group {
				return conn, true, nil
			}
		}
	}
	return model.ConnectorRegistration{}, false, nil
}

func connectorRouteUnavailable(conn model.ConnectorRegistration) bool {
	return conn.Status == "offline"
}

func connectorRegistrationForTenant(registry connectorRegistryStore, connectorID, tenantID string) (model.ConnectorRegistration, bool) {
	conn, ok := registry.Get(connectorID)
	if !ok || strings.TrimSpace(tenantID) == "" || conn.TenantID != tenantID {
		return model.ConnectorRegistration{}, false
	}
	return conn, true
}

func connectorRegistrationForTenantWithContext(ctx context.Context, registry connectorRegistryStore, connectorID, tenantID string) (model.ConnectorRegistration, bool, error) {
	if reader, ok := registry.(connectorRegistryTenantReader); ok {
		return reader.GetByTenant(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(connectorID))
	}
	conn, ok := connectorRegistrationForTenant(registry, connectorID, tenantID)
	return conn, ok, nil
}

func connectorRegistrationsForTenant(registry connectorRegistryStore, tenantID string) []model.ConnectorRegistration {
	if strings.TrimSpace(tenantID) == "" {
		return nil
	}
	connectors := registry.List()
	filtered := make([]model.ConnectorRegistration, 0, len(connectors))
	for _, conn := range connectors {
		if conn.TenantID == tenantID {
			filtered = append(filtered, conn)
		}
	}
	return filtered
}

func connectorRegistrationsForTenantWithContext(ctx context.Context, registry connectorRegistryStore, tenantID string) ([]model.ConnectorRegistration, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	if reader, ok := registry.(connectorRegistryTenantReader); ok {
		return reader.ListByTenant(ctx, tenantID)
	}
	return connectorRegistrationsForTenant(registry, tenantID), nil
}

// connector ROUTE layer (reachable_routes), among the tenant's LIVE connectors — the destination-driven
// counterpart of connectorForApplication. namespace is the flow's site / virtual-network context (used only for
// IP routes). Reachability only: policy still authorizes the flow separately. Returns ok=false when no live
// connector fronts the destination (fail-closed — no implicit reach).
func connectorForDestination(ctx context.Context, registry connectorRegistryStore, tenantID, destination, namespace string) (model.ConnectorRegistration, bool, error) {
	connectors, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenantID)
	if err != nil {
		return model.ConnectorRegistration{}, false, err
	}
	live := make([]model.ConnectorRegistration, 0, len(connectors))
	for _, conn := range connectors {
		if !connectorRouteUnavailable(conn) {
			live = append(live, conn)
		}
	}
	// Admin route governance: the route layer sees only the EFFECTIVE routes — self-declared CIDRs the operator
	// HELD are dropped, admin-authored CIDRs are added. Nil (unset) is the identity. See
	// docs/connector_network_route_advertisement_design.md.
	live = connectorRouteGov.Apply(tenantID, live)
	id, ok := connector.ResolveConnectorForDestination(destination, namespace, live)
	if !ok {
		return model.ConnectorRegistration{}, false, nil
	}
	for _, conn := range live {
		if conn.ID == id {
			return conn, true, nil
		}
	}
	return model.ConnectorRegistration{}, false, nil
}

// connectorsForDestination is connectorForDestination returning EVERY connector that fronts the destination,
// most specific first.
//
// ★★★ A SITE HOLDS MORE THAN ONE CONNECTOR ON PURPOSE (the operator's reminder, 2026-08-26). Bindings are
// authored on the SITE, so an HA pair fronts the same names, and choosing one of them by id order sends every
// flow to the same member — and fails outright when that member is the one THIS Edge cannot reach, while its
// partner sits there live holding the same route. Reachability is not knowable here: it depends on tunnels and
// mesh links the caller owns. So this hands over the candidates and the caller takes the first that answers.
func connectorsForDestination(ctx context.Context, registry connectorRegistryStore, tenantID, destination, namespace string) ([]model.ConnectorRegistration, error) {
	connectors, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenantID)
	if err != nil {
		return nil, err
	}
	live := make([]model.ConnectorRegistration, 0, len(connectors))
	for _, conn := range connectors {
		if !connectorRouteUnavailable(conn) {
			live = append(live, conn)
		}
	}
	live = connectorRouteGov.Apply(tenantID, live)
	byID := make(map[string]model.ConnectorRegistration, len(live))
	for _, conn := range live {
		byID[conn.ID] = conn
	}
	ordered := connector.ResolveConnectorsForHost(destination, live)
	if len(ordered) == 0 {
		// The IP fallback stays single-answer: it is namespace-scoped and there is no HA question in it yet.
		if conn, ok, ferr := connectorForDestination(ctx, registry, tenantID, destination, namespace); ferr == nil && ok {
			return []model.ConnectorRegistration{conn}, nil
		}
		return nil, nil
	}
	out := make([]model.ConnectorRegistration, 0, len(ordered))
	for _, id := range ordered {
		if conn, ok := byID[id]; ok {
			out = append(out, conn)
		}
	}
	return out, nil
}

// decisionPermitsConnectorRoute lists the verdicts that let a flow reach a connector route. "observe" was in
// this list because Policy Learning could return it for an unmatched request; that mechanism was removed on
// 2026-08-05 and nothing produces the value any more. Dropped rather than left as a dead case, so a decision
// value nobody emits cannot quietly permit a route if something starts emitting it again — an unknown verdict
// now falls to the default and is refused.
func decisionPermitsConnectorRoute(decision string) bool {
	switch decision {
	case "allow", "warn", "audit_only":
		return true
	default:
		return false
	}
}

func connectorAudit(eventType string, conn model.ConnectorRegistration, details map[string]any) map[string]any {
	event := map[string]any{
		"id":                 randomEdgeID("connlog_", time.Now().UTC()),
		"event_type":         eventType,
		"connector_id":       conn.ID,
		"tenant_id":          conn.TenantID,
		"connector_group_id": conn.ConnectorGroupID,
		"status":             conn.Status,
		"edge_region_id":     conn.EdgeRegionID,
		"edge_cluster_id":    conn.EdgeClusterID,
		"last_heartbeat_at":  conn.LastHeartbeatAt,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
	}
	for key, value := range details {
		event[key] = value
	}
	return event
}

// connectorAuditAppender binds edgeplane's connector-audit seam to this process's
// log writer + domain-event outbox (adapters live in the composition root).
func connectorAuditAppender(writer *logs.Writer, domainEventOutbox domainEventOutboxWriter) edgeplane.ConnectorAuditFunc {
	return func(ctx context.Context, eventType string, conn model.ConnectorRegistration, details map[string]any) error {
		return appendConnectorLog(ctx, writer, domainEventOutbox, connectorAudit(eventType, conn, details), time.Now())
	}
}

// connectorDestinationResolver binds edgeplane's connector-resolve seam to this
// process's registry (with route governance applied inside connectorForDestination).
func connectorDestinationResolver(registry connectorRegistryStore) edgeplane.ConnectorResolveFunc {
	return func(ctx context.Context, tenantID, destination, namespace string) (model.ConnectorRegistration, bool, error) {
		return connectorForDestination(ctx, registry, tenantID, destination, namespace)
	}
}

// authorizeDeviceSelfReport authorizes a request in which a DEVICE reports something about ITSELF.
//
// ★ WHY THIS IS NOT THE CONNECTOR AUTHORIZER (2026-08-12, sixth review). Two different failures were living in
// one function:
//
//   - the senders that actually make these requests — the macOS network extension and DsseSteer — present the
//     device's (T) client certificate and NOTHING ELSE. The connector authorizer wants a connector id and a
//     runtime secret, so in production (lab-mode off, runtime secret required) every one of these would be
//     answered 401. The lane built to fill an empty fleet view would have left it empty, for a second reason
//     nobody would connect to the first.
//   - and in the other direction it bound nothing. Anything holding a connector's runtime secret could report
//     an install — or a rollback that never happened — for ANY device in the tenant. A fleet view an operator
//     makes decisions from must not accept claims about third parties.
//
// The rule: when a verified client certificate is present, the identity it proves must equal the device named
// in the path AND, when the body names one, in the body. The tenant is derived by the caller from the issuing
// CA. Two of the three matching is not enough — the point is that all three are the same device.
//
// devMode still short-circuits, as everywhere else: the lab's plaintext listener presents no certificate, and
// requiring one there would mean the lab could not exercise this path at all.
func authorizeDeviceSelfReport(w http.ResponseWriter, r *http.Request, bodyDeviceID string,
	connectorSecret string, devMode bool, registry connectorRegistryStore, tenantID string,
	requireRuntimeSecret bool) bool {
	pathDeviceID := strings.TrimSpace(r.PathValue("device_id"))
	certID, verified := transportDeviceIdentityFromRequest(r)
	if verified {
		if strings.TrimSpace(certID) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("the client certificate carries no identity, so "+
				"this report cannot be attributed to a device"))
			return false
		}
		if pathDeviceID != "" && !strings.EqualFold(pathDeviceID, certID) {
			writeError(w, http.StatusForbidden, fmt.Errorf("this certificate proves device %q and the report is "+
				"addressed to %q: a device may only report about itself", certID, pathDeviceID))
			return false
		}
		if b := strings.TrimSpace(bodyDeviceID); b != "" && !strings.EqualFold(b, certID) {
			writeError(w, http.StatusForbidden, fmt.Errorf("this certificate proves device %q and the report "+
				"claims to be about %q", certID, b))
			return false
		}
		return true
	}
	// ★ NO CERTIFICATE, NO REPORT — OUTSIDE THE LAB (2026-08-12, seventh review). The previous version fell
	// back to connector credentials here, and the reasoning was wrong: nothing binds an authenticated CONNECTOR
	// to the device named in the path, so anything holding a connector's runtime secret could file outcomes for
	// every device in the tenant. "It can only claim what the path says" is not a limit when the path is also
	// the attacker's.
	//
	// There is no legitimate relay for this today: both senders are on the device and hold its certificate. If
	// one is ever needed, it needs a signed device assertion — not a shared secret — and that is a design, not
	// a fallback.
	//
	// devMode still passes: the lab's plaintext listener presents no certificate, and requiring one there would
	// mean the lab could not exercise this path at all.
	if devMode {
		return true
	}
	writeError(w, http.StatusUnauthorized, fmt.Errorf("an update outcome must be presented over the device's own "+
		"(T) client certificate: this request has no verified certificate, and connector credentials do not "+
		"establish which device an outcome is about"))
	return false
}

// seenAgentUpdateEvents remembers recently accepted update-event ids so a retry is not counted twice.
//
// Bounded and in-process on purpose. The durable store already upserts on event_id; what needed protecting is
// the audit append and the domain-event outbox beside it, which have no such key. A restart forgets this — and
// after one, the upsert still collapses the duplicate row, so the residue is a repeated audit line rather than
// an inflated success rate. Stating that limit is better than implying a guarantee this does not make.
type agentUpdateReceiptState struct {
	at        time.Time
	committed bool
	// gen distinguishes THIS reservation from an earlier one for the same key.
	//
	// ★ A STALE QUEUE ENTRY DELETED A LIVE RESERVATION (2026-08-12, ninth review). The eviction queue keeps one
	// entry per reservation; releasing a key and reserving it again left the OLD entry in the queue, and when
	// that old entry reached the front it deleted whatever was in the map — a live reservation, or a committed
	// receipt. Deleting a committed receipt lets the same event be written twice; deleting a live reservation
	// lets two requests write it at once. Both are the failure the receipt exists to prevent, arriving later.
	gen uint64
}

type agentUpdateReceiptQueueEntry struct {
	key string
	gen uint64
}

var seenAgentUpdateEvents = struct {
	mu    sync.Mutex
	ids   map[string]agentUpdateReceiptState
	order []agentUpdateReceiptQueueEntry
	gen   uint64
}{ids: map[string]agentUpdateReceiptState{}}

const seenAgentUpdateEventsMax = 4096

// agentUpdateReceiptKey scopes an event id to the device that sent it.
//
// ★ THE ID IS CLIENT INPUT (2026-08-12, seventh review). Keyed on the id alone, one device could suppress
// another's event by choosing the same string — including across tenants. The id is only ever meaningful
// beside the device it came from, and that device is now proven by a certificate before this is reached.
func agentUpdateReceiptKey(tenantID, deviceID, id string) string {
	return strings.ToLower(strings.TrimSpace(tenantID)) + "\x00" +
		strings.ToLower(strings.TrimSpace(deviceID)) + "\x00" + strings.TrimSpace(id)
}

// agentUpdateReceipt is what a reservation returns: whether this request owns the event, and what to do with
// the reservation afterwards.
type agentUpdateReceipt struct {
	key string
	gen uint64
}

// reserveAgentUpdateEvent claims an event id for THIS request, atomically.
//
// ★ CHECK-THEN-MARK WAS TWO LOCKS (2026-08-12, eighth review). Two concurrent retries of the same event could
// both find it unrecorded, both pass, and both write the audit line and the downstream event. Reserving and
// checking under ONE lock is the only version of this that means anything, because the whole purpose is to
// decide which of several simultaneous requests owns the write.
//
// A reservation that is not committed is RELEASED, so a request that failed half way does not leave the event
// permanently unrecordable — which would be the same "lost forever" outcome as marking it before the write.
//
// An empty id is never reserved: two events with no id are two events, and collapsing them would lose one.
func reserveAgentUpdateEvent(tenantID, deviceID, id string) (receipt agentUpdateReceipt, alreadyCommitted bool,
	ok bool) {
	if strings.TrimSpace(id) == "" {
		return agentUpdateReceipt{}, false, true
	}
	key := agentUpdateReceiptKey(tenantID, deviceID, id)
	seenAgentUpdateEvents.mu.Lock()
	defer seenAgentUpdateEvents.mu.Unlock()
	if state, held := seenAgentUpdateEvents.ids[key]; held {
		if state.committed {
			return agentUpdateReceipt{}, true, false
		}
		// Another request is mid-write. Not committed, so this one must not proceed and must not be told it
		// was recorded: the device retries, and by then the other request has finished or released.
		return agentUpdateReceipt{}, false, false
	}
	seenAgentUpdateEvents.gen++
	gen := seenAgentUpdateEvents.gen
	seenAgentUpdateEvents.ids[key] = agentUpdateReceiptState{at: time.Now(), gen: gen}
	seenAgentUpdateEvents.order = append(seenAgentUpdateEvents.order, agentUpdateReceiptQueueEntry{key: key, gen: gen})
	// ★ AN IN-FLIGHT RESERVATION IS NEVER EVICTED, AND ONE OF THEM MUST NOT DISABLE THE CAP (2026-08-12,
	// ninth and tenth reviews). Evicting the oldest whatever it was let a flood of 4,097 distinct ids push out
	// a reservation that was still BEING WRITTEN, so a second request for that id became its owner and produced
	// the double audit the receipt exists to prevent. Stopping at the first uncommitted one then had the
	// opposite failure: one slow request at the head froze the cap, and every committed receipt behind it grew
	// the map without bound.
	//
	// So the scan SKIPS uncommitted entries and keeps looking for a committed one to drop. Uncommitted
	// reservations are bounded by the requests actually in flight — the server's own concurrency — not by this
	// cap, which is what the cap was never able to bound anyway.
	for len(seenAgentUpdateEvents.order) > seenAgentUpdateEventsMax {
		evicted := false
		for i, candidate := range seenAgentUpdateEvents.order {
			state, held := seenAgentUpdateEvents.ids[candidate.key]
			if held && state.gen == candidate.gen && !state.committed {
				continue // still being written
			}
			seenAgentUpdateEvents.order = append(seenAgentUpdateEvents.order[:i:i],
				seenAgentUpdateEvents.order[i+1:]...)
			if held && state.gen == candidate.gen {
				delete(seenAgentUpdateEvents.ids, candidate.key)
			}
			evicted = true
			break
		}
		if !evicted {
			// Everything queued is in flight. Nothing to drop, and nothing is leaking: these clear as their
			// requests finish.
			break
		}
	}
	return agentUpdateReceipt{key: key, gen: gen}, false, true
}

// commit marks the reservation as fully written. Everything the handler had to record has been recorded.
func (r agentUpdateReceipt) commit() {
	if r.key == "" {
		return
	}
	seenAgentUpdateEvents.mu.Lock()
	defer seenAgentUpdateEvents.mu.Unlock()
	// Only this reservation's own entry is promoted: if it was evicted and re-reserved by someone else, that
	// request owns the key now.
	if state, held := seenAgentUpdateEvents.ids[r.key]; !held || state.gen != r.gen {
		return
	}
	seenAgentUpdateEvents.ids[r.key] = agentUpdateReceiptState{at: time.Now(), committed: true, gen: r.gen}
}

// release drops an uncommitted reservation so a retry can claim it.
func (r agentUpdateReceipt) release() {
	if r.key == "" {
		return
	}
	seenAgentUpdateEvents.mu.Lock()
	defer seenAgentUpdateEvents.mu.Unlock()
	if state, held := seenAgentUpdateEvents.ids[r.key]; held && !state.committed && state.gen == r.gen {
		delete(seenAgentUpdateEvents.ids, r.key)
	}
}

// agentUpdateEventCommitted is the read-only question, for tests and for callers that only want to know.
func agentUpdateEventCommitted(tenantID, deviceID, id string) bool {
	if strings.TrimSpace(id) == "" {
		return false
	}
	seenAgentUpdateEvents.mu.Lock()
	defer seenAgentUpdateEvents.mu.Unlock()
	state, ok := seenAgentUpdateEvents.ids[agentUpdateReceiptKey(tenantID, deviceID, id)]
	return ok && state.committed
}

// connectorTenantFromRegistry returns the organization the REGISTRY says this connector belongs to. Empty when
// the connector is unknown — and empty is refused by the binding check rather than waved through, because an
// unknown connector is exactly the case where a certificate from anywhere would otherwise pass.
func connectorTenantFromRegistry(registry connectorRegistryStore, connectorID string) string {
	if registry == nil || strings.TrimSpace(connectorID) == "" {
		return ""
	}
	conn, ok := registry.Get(strings.TrimSpace(connectorID))
	if !ok {
		return ""
	}
	return strings.TrimSpace(conn.TenantID)
}

// connectorMTLSPresentationRelaxed lets a deployment that cannot yet issue connector certificates keep
// running, and is set from -connector-mtls-not-required. It is deliberately a package-level value written
// once at startup rather than a parameter threaded through thirty call sites: the answer is a property of
// the deployment, not of the request, and a per-call-site copy is where two answers start to differ.
//
// It is NOT free. The startup line says what it costs, and the declared security posture carries it, so a
// deployment running this way cannot do so quietly.
var connectorMTLSPresentationRelaxed bool

// setConnectorMTLSPresentationRelaxed records the deployment's answer and returns the line to log.
func setConnectorMTLSPresentationRelaxed(relaxed, labMode bool) string {
	connectorMTLSPresentationRelaxed = relaxed || labMode
	if !connectorMTLSPresentationRelaxed {
		return "connector authentication: a certificate issued by the connector's OWN organization's device CA is required"
	}
	if labMode {
		return "connector authentication: certificate presentation NOT required (-lab-mode) — a caller holding the " +
			"shared connector secret can be any connector this node serves"
	}
	return "connector authentication: certificate presentation NOT required (-connector-mtls-not-required) — a " +
		"caller holding the shared connector secret can be any connector this node serves; this is a declared " +
		"exception, not a default"
}

// connectorRecentlyHeardWindow is how long a connector this node has heard from counts as first-hand,
// current knowledge — longer than a heartbeat interval and far shorter than a working day.
const connectorRecentlyHeardWindow = 3 * time.Minute

// connectorHeardFromRecently reports that THIS node has current first-hand knowledge of a connector.
//
// ★★★ IT IS RECENCY, NOT HISTORY (2026-08-26, measured). "This connector once registered here" keeps a
// registration for ever, and the entries that had to be removed had all registered here earlier the same day —
// so that test kept precisely the dead ones. A connector heartbeats continuously while it is using a node, so
// silence plus absence from the authority is the whole truth about it.
func connectorHeardFromRecently(conn model.ConnectorRegistration, now time.Time) bool {
	last := strings.TrimSpace(conn.LastHeartbeatAt)
	if last == "" {
		last = strings.TrimSpace(conn.RegisteredAt)
	}
	if last == "" {
		return false
	}
	at, err := time.Parse(time.RFC3339, last)
	if err != nil {
		// Unparseable: keep it. Deleting a connector because a timestamp could not be read would turn a
		// formatting problem into an outage for whatever is behind it.
		return true
	}
	return now.Sub(at.UTC()) < connectorRecentlyHeardWindow
}

// connectorDestinationCandidates hands the dialer every connector that fronts a destination. See
// connectorsForDestination: a site's HA pair fronts the same names, and only the dialer knows which member it
// can reach.
func connectorDestinationCandidates(registry connectorRegistryStore) edgeplane.ConnectorCandidatesFunc {
	return func(ctx context.Context, tenantID, destination, namespace string) ([]model.ConnectorRegistration, error) {
		return connectorsForDestination(ctx, registry, tenantID, destination, namespace)
	}
}
