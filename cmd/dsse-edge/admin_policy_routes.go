package main

// Policy CRUD + config-bundle admin routes, moved verbatim out of newServerWithConfig
// (Phase 2 route-registration split). Takes serverConfig whole for the signed
// config-bundle assembly deps.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	policystore "github.com/lantern-networks/dsse-core/policy"
	policyrule "github.com/lantern-networks/dsse-core/policyrule"
	"github.com/lantern-networks/dsse-core/vlan"
)

func registerPolicyAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, policyStore policystore.RuntimeStore, configSourceURL string, configBundleEpoch string, registry connectorRegistryStore, nonHumanIdentities nhi.RuntimeStore, humanIdentities humanidentity.HumanIdentityDirectoryRuntimeStore, delegatedGrants *delegatedgrant.Store, edgeDNSResolver *dnsresolver.Resolver, vlanBoundary *vlan.Store, tenantModelStore adminTenantModelRuntimeStore, networkExtensionPublisher networkExtensionSnapshotPublisher, ruleStore *policyrule.Store, assetStore *assetcatalog.Store) (bundleGeneration func() (uint64, string)) {
	publishAndAudit := func(w http.ResponseWriter, r *http.Request, item model.Policy, operation string, now time.Time) bool {
		snapshotStatus := "not_requested"
		if networkExtensionPublisher != nil {
			snapshotStatus = "published"
			runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
			if err := networkExtensionPublisher.PublishAdminPolicySnapshot(r.Context(), item.TenantID, policyStore, runtimeEvaluator.PolicyBundle, now); err != nil {
				snapshotStatus = "unconfirmed"
				logInfof("admin policy snapshot publication: %v", err)
			}
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminPolicyMutationAuditLog(r, item, evaluator, now, operation, snapshotStatus), now)
		if snapshotStatus == "unconfirmed" {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":  "Policy change applied on this server; Network Extension snapshot publication is unconfirmed. Reload the policy state and check distribution before retrying.",
				"status": "partial", "applied": true, "policy_id": item.ID, "tenant_id": item.TenantID, "ne_snapshot_status": snapshotStatus,
			})
			return false
		}
		return true
	}
	mux.HandleFunc("GET /admin/policies", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		options := policystore.ListOptions{
			Status: strings.TrimSpace(r.URL.Query().Get("status")),
			Limit:  boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := policyStore.List(r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	// Phase 1 config distribution (docs/edge_config_distribution_phase1_design.md): the control plane serves
	// a versioned config bundle that each Edge pulls (configBundleSource) and applies atomically, so a fleet
	// enforces identically. Slice 1 carries access policies + a monotonic generation; further resources fold
	// in over time. Read-only; the Edge consumes this from the CP when -config-source-url is set.
	// ★ ONE definition of "the control plane's current generation". The fleet-status view compares each Edge's
	// reported generation against it, so a second expression computing the same sum would be two answers to the
	// question this whole area exists to make answerable — an Edge could read as current against one and
	// lagging against the other, and neither reader would know a rival definition existed.
	applicationState := &applicationBundleState{}
	baseBundleGeneration := func() (uint64, string) {
		var connectorGen, nhiGen, delegatedGrantGen, ruleGen uint64
		// Asked for by the METHOD, not by the store's type. See postgresConnectorRegistryStore.ConfigGeneration:
		// this term was read from the in-memory registry by concrete type, so it went silently to zero the
		// moment the control plane's registry became the deployment's database — and a bundle whose version
		// does not move is a bundle no Edge pulls.
		if c, ok := registry.(interface{ ConfigGeneration() uint64 }); ok && c != nil {
			connectorGen = c.ConfigGeneration()
		}
		if nonHumanIdentities != nil {
			nhiGen = nonHumanIdentities.ConfigGeneration()
		}
		// The people directory belongs in this sum for the same reason the tenant registry does: the bundle
		// carries it, and an Edge applies a bundle only when this number is newer. Without it, adding somebody
		// on the control plane would change the bundle's CONTENTS and not its VERSION, and no Edge would pull.
		var directoryGen uint64
		if carrier, ok := humanIdentityDirectoryCarrier(humanIdentities); ok {
			directoryGen = carrier.ConfigGeneration()
		}
		if delegatedGrants != nil {
			delegatedGrantGen = delegatedGrants.ConfigGeneration()
		}
		if ruleStore != nil {
			ruleGen += ruleStore.ConfigGeneration()
		}
		// The licence belongs in this sum for exactly the reason the directory does: the bundle carries it, and
		// an Edge applies a bundle only when this number is newer. Without it, applying a licence changes the
		// bundle's CONTENTS and not its VERSION, and no Edge ever sees it — measured, with the whole fleet
		// holding enrolment while the control plane reported itself correctly licensed.
		var licenceGen uint64
		if config.VendorLicense != nil {
			licenceGen = config.VendorLicense.ConfigGeneration()
		}
		if assetStore != nil {
			ruleGen += assetStore.ConfigGeneration()
		}
		// The authorities each organization vouches for over its own private assets, for the fifth instance of
		// the reason written four times above: the bundle carries them, and an Edge applies a bundle only when
		// this number is newer. Measured on 2026-09-01 — an authority deleted on the control plane, every Edge
		// still trusting it, and the earlier ADD working only because a roll had restarted the fleet.
		if gen, ok := config.InternalCAs.(interface{ ConfigGeneration() uint64 }); ok && gen != nil {
			ruleGen += gen.ConfigGeneration()
		}
		// ★★★ AND THE TWO THIS BUNDLE LEARNED TO CARRY TODAY, for the SIXTH and SEVENTH instance of the
		// reason written five times above (2026-09-02, both measured failing).
		//
		// Registering an identity provider reached the Edges only because the roll that shipped the code
		// restarted them minutes later. And a grant reported to the authority sat there while every Edge
		// listed none — which would have made a revocation reach nobody, the one thing carrying grants exists
		// for.
		if reg := theIdPRegistry.Load(); reg != nil {
			ruleGen += reg.ConfigGeneration()
		}
		if grants := theGrantStore.Load(); grants != nil {
			ruleGen += grants.ConfigGeneration()
		}
		// ★ THE TENANT REGISTRY BELONGS IN THIS SUM (2026-08-15). The bundle carries it, and an Edge applies a
		// bundle only when this number is newer — so while the registry was absent from the sum, creating an
		// organization changed the bundle's CONTENTS without changing its VERSION, and no Edge ever re-pulled
		// for it. Measured: an organization created on the control plane was still missing from the Edge a
		// minute later, and an earlier one was present only because a restart had pulled unconditionally.
		var tenantGen uint64
		if tm, ok := tenantModelFleetCarrier(tenantModelStore); ok {
			tenantGen = tm.ConfigGeneration()
		}
		// ★ AND THE SITE CATALOG (2026-08-23). The same lesson as the tenant registry above, measured the same
		// way: the Site section was added to the bundle, published correctly, and never applied anywhere,
		// because creating a Site changed the bundle's CONTENTS and not its VERSION. A section that does not
		// contribute here is a section that does not travel.
		// ★ AND THE POSTURE'S GENERATION. Same lesson as the Site catalogue: a section that does not move this
		// number is published in every bundle and applied by nobody.
		// ★ AND THE REGISTRY'S GENERATION, for the same reason as every other section: without it, registering
		// a device CA changes the bundle's contents and not its version, and no Edge re-pulls.
		// ★ THE SERIAL IS THE GENERATION HERE. The distribution already carries a monotonic number devices
		// depend on, so folding it in costs nothing and means a new distribution moves the bundle's version.
		var transportTrustGen uint64
		if transportTrust != nil {
			if snap := transportTrust.Snapshot(); snap.Serial > 0 {
				transportTrustGen = uint64(snap.Serial)
			}
		}
		var deviceCAGen uint64
		if config.TenantCARegistry != nil {
			deviceCAGen = config.TenantCARegistry.ConfigGeneration()
		}
		// The section now also names managed organizations. A new managed
		// authority must move this bundle even when no imported CA changed.
		deviceCAGen += config.TenantDeviceAuthority.Generation()
		var postureGen uint64
		if config.InspectionPostureGeneration != nil {
			postureGen = config.InspectionPostureGeneration()
		}
		// ★ AND THE REGION MAP'S. Same rule as every section here: without it, changing the map changes the
		// bundle's contents and not its version, and no Edge re-pulls.
		regionGen := regionMap.ConfigGeneration()
		// Straight off the interface. It used to be a type assertion, and a backend that did not implement it
		// contributed 0 in silence — see adminSiteStore.ConfigGeneration.
		var siteGen uint64
		if config.SiteStore != nil {
			siteGen = config.SiteStore.ConfigGeneration()
		}
		return policyStore.ConfigGeneration() + edgeDNSResolver.ConfigGeneration() + config.EnrolledLedger.ConfigGeneration() +
			vlanBoundary.ConfigGeneration() + connectorGen + connectorRouteGov.ConfigGeneration() + nhiGen + delegatedGrantGen + ruleGen +
			tenantGen + directoryGen + siteGen + postureGen + deviceCAGen + transportTrustGen + regionGen + licenceGen + config.DLPDistribution.Generation(), configBundleEpoch
	}
	bundleGeneration = func() (uint64, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, catalogGeneration, _ := applicationState.read(ctx, config.ApplicationCatalogStore)
		base, epoch := baseBundleGeneration()
		return base + catalogGeneration, epoch
	}

	mux.HandleFunc("GET /admin/config-bundle", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ NOT FROM A STANDBY. See the_bundle_is_the_leaders_instruction.go: measured with two Edges of one
		// region applying generations 13 and 8 while both polled in the same second.
		if configBundleRefusedOnAStandby(w) {
			return
		}
		if !refreshInspectionPosture(w, config) {
			return
		}
		if !refreshAuthoredStores(w, ruleStore, assetStore) {
			return
		}
		if !refreshVLANStore(w, vlanBoundary) {
			return
		}
		if !refreshDLPStores(w, config.DLPDistribution) {
			return
		}
		if err := refreshManagedTenantRestrictions(policyStore); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("SaaS configuration cannot be refreshed: %w", err))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		tenantConfig := policyStore.SnapshotTenantConfig(tenantID)
		applications, catalogGeneration, err := applicationState.read(r.Context(), config.ApplicationCatalogStore)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("application catalog cannot be read: %w", err))
			return
		}
		applications = scopeApplicationBundle(applications, tenantID, adminCallerIsOperator(r) || configBundleFleetReader(r, config.OperatorTenantID))
		// The connector/region catalog folds into the bundle when the registry is the in-memory type the CP-pull
		// fleet uses (a DB-backed store distributes via its own replication, not the bundle).
		bundle := configBundlePayload{
			Applications: applications,
			DLP:          config.DLPDistribution.Snapshot(),
			// Aggregate generation across stores: policy.Store (policies + tenant-config) + the separate
			// DNS resolver + Enrolled Inventory ledger + VLAN boundary store + connector catalog. All counters
			// are monotonic, so the sum is monotonic and advances on ANY distributed-config change, triggering
			// an Edge re-pull.
			Generation:   generationOnly(baseBundleGeneration) + catalogGeneration,
			Epoch:        configBundleEpoch,
			Policies:     policyStore.Snapshot(tenantID),
			TenantConfig: &tenantConfig,
		}
		if !adminCallerIsOperator(r) && !configBundleFleetReader(r, config.OperatorTenantID) {
			bundle.DLP = bundle.DLP.ForTenant(tenantID)
		}
		// EVERY tenant's enforcement config, not just the puller's. The two fields above stay for an Edge that
		// predates this section; a current Edge reads this one and applies each tenant it names, leaving any
		// tenant it does NOT name alone — absence is not a instruction here either.
		if concrete, ok := policyStore.(*policystore.Store); ok && concrete != nil {
			for _, id := range concrete.Tenants() {
				cfg := concrete.SnapshotTenantConfig(id)
				bundle.TenantPolicies = append(bundle.TenantPolicies, tenantPolicySection{
					TenantID: id,
					Policies: concrete.Snapshot(id),
					Config:   &cfg,
				})
			}
		}
		if edgeDNSResolver != nil {
			dnsDTO := dnsresolver.PolicyToDTO(edgeDNSResolver.CurrentPolicy())
			bundle.DNSPolicy = &dnsDTO
		}
		if config.EnrolledLedger != nil {
			// Authoritative, not List: a removal has to reach the fleet, and it can only do that as an entry.
			bundle.Enrolled = &enrolledInventoryBundle{Entries: config.EnrolledLedger.Authoritative(), Groups: config.EnrolledLedger.ListGroups()}
		}
		// The tenant model, with the control plane as the authority. Served only when this node can actually
		// enumerate tenants — a narrow store would otherwise publish an empty set, which the receiving side
		// correctly refuses to act on but which is still a bundle claiming something it does not know.
		if adminStore, ok := tenantModelStore.(adminTenantModelAdminStore); ok {
			if tenants, err := adminStore.List(r.Context()); err == nil {
				section := &tenantModelBundle{Tenants: tenants}
				// Carry the deletions and the standing erasure orders. Without the deletions a delete on the
				// control plane reached no Edge at all, because the section UPSERTs and nothing in it can express
				// "this one is gone"; without the orders a node that has not yet erased a terminated tenant is
				// never told, since the order is the only thing that ever tells it.
				//
				// ★ ONE ASSERTION FOR BOTH, AND IT IS REPORTED WHEN IT FAILS (2026-08-18). These were two separate
				// anonymous-interface assertions, and the Postgres backend satisfied the second one never — so a
				// production control plane published a bundle whose erasure orders were silently always empty.
				if carrier, ok := tenantModelFleetCarrier(adminStore); ok {
					section.Deleted = carrier.DeletedTenants()
					section.PurgeOrders = carrier.PurgeOrders()
				}
				bundle.Tenants = section
			}
		}
		if vlanBoundary != nil {
			// Complete only when this node's own store is DURABLE: an in-memory control plane that has just
			// restarted is empty for a reason that is not "there are none", and saying otherwise would wipe
			// inter-VLAN enforcement off the fleet.
			bundle.VLAN = &vlanBoundaryBundle{
				Objects:  vlanBoundary.ListObjects(),
				Policies: vlanBoundary.ListPolicies(),
				Complete: vlanBoundary.Persisted(),
			}
		}
		if registry != nil {
			// Strip the runtime secret hash before distribution (publicConnectorRegistrations); the catalog
			// carries class-1 descriptors only (id/tenant/region/cluster/routes/private-base-url).
			//
			// ★★★ THIS ASKED FOR THE IN-MEMORY REGISTRY BY TYPE, AND STOPPED CARRYING ANYTHING THE MOMENT THE
			// CONTROL PLANE'S REGISTRY BECAME THE DEPLOYMENT'S DATABASE (2026-08-26, measured hours after
			// making that move). The assertion silently produced nil, the section was omitted, and every Edge
			// went on with whatever it had — which is only the connectors that registered with IT. A
			// destination fronted by a connector in another region then resolves to nothing, is dialled
			// directly, and fails; the mesh is never reached, because it is only consulted after a
			// destination resolves to a connector.
			//
			// Third time in one night that asking for a concrete store by type turned a working path off
			// without a word. The registry interface already has List(); that is what this needs.
			bundle.Connectors = &connectorCatalogBundle{Connectors: publicConnectorRegistrations(registry.List())}
		}
		// Fold the connector route-governance decisions into the bundle so a pull-model Edge converges on the
		// CP-configured bindings + hold/adopt state without a shared governance store (non-secret; nil when there
		// are no decisions, keeping the section lockout-safe). See docs/connector_network_route_advertisement_design.md.
		bundle.RouteGovernance = connectorRouteGov.Export()
		// /agent governance: distribute the Non-Human Identity registry + delegated-access grants so
		// agent governance authored on the control plane reaches enforcing Edges. Present-but-empty stays lockout-
		// safe on the Edge (apply keeps a non-empty local set). Guarded for nil stores.
		if nonHumanIdentities != nil {
			if identities, err := nonHumanIdentities.List(r.Context(), tenantID); err == nil {
				bundle.NHI = &nonHumanIdentityBundle{Identities: identities}
			}
		}
		// The people DIRECTORY, for the tenant this bundle is for. Measured absent before this existed: the
		// control plane held 90 identities for the lab tenant and both enforcing Edges held zero, so every
		// Edge-side answer about people was drawn from an empty list and none of them said so.
		// ★ SERVED FOR EVERY TENANT, not the requesting one (operator decision 2026-08-19). One Edge serves
		// several tenants, so a tenant-scoped directory section repeats the defect the rule section above
		// already warns about: correct for the tenant that happened to be asked, silently absent for the rest.
		// The operator's reasoning for accepting that every node holds every organization's people: a reader
		// can only ever see the organization their credential belongs to — the tenant of a read is taken from
		// the caller's identity and a tenant_id parameter is ignored — so distribution is not disclosure.
		if carrier, ok := humanIdentityDirectoryCarrier(humanIdentities); ok {
			section := &humanIdentityBundle{Identities: []model.HumanIdentity{}}
			for _, directoryTenant := range directoryBundleTenants(r.Context(), tenantModelStore, tenantID) {
				if identities, err := carrier.List(r.Context(), directoryTenant); err == nil {
					section.Identities = append(section.Identities, identities...)
				}
				if policies, err := carrier.ListSourcePolicies(r.Context(), directoryTenant); err == nil {
					section.SourcePolicies = append(section.SourcePolicies, policies...)
				}
			}
			bundle.HumanIdentities = section
		}
		if delegatedGrants != nil {
			bundle.DelegatedGrants = &delegatedGrantBundle{Grants: delegatedGrants.Snapshot()}
		}
		// The Site / Connector Group catalog. Measured absent before this existed: the control plane held one
		// Site and the enforcing Edge held three, two of which the control plane had never heard of, and a Site
		// deleted on the control plane was still on the Edge three minutes later. See config_bundle_sites.go —
		// and note it is load-bearing now that a connector proves itself with its Site's bootstrap secret.
		//
		// Every organization, for the same reason the directory above is: one Edge serves several, and a
		// connector belonging to any of them dials it.
		// The deployment's decrypt/bypass posture. It is enforcement, and it has differed between two Edges of
		// one fleet twice — see config_bundle_inspection_posture.go.
		// The device-CA registry: which organization a client certificate belongs to. Its authority was on the
		// enforcement side until this — the flag was on the Edges and not here.
		// What devices check before they will talk to an Edge at all. Published by whichever node HOLDS the
		// distribution — the control plane, once it has one; nil elsewhere, and a nil section changes nothing.
		if transportTrust != nil {
			if snap := transportTrust.Snapshot(); snap.Serial > 0 && strings.TrimSpace(snap.AnchorsPEM) != "" {
				bundle.TransportTrust = &transportTrustBundle{Distribution: snap}
			}
		}
		bundle.DeviceCAs = deviceCABundleSection(config.TenantCARegistry, config.TenantDeviceAuthority)
		if bundle.DeviceCAs != nil && (!bundle.DeviceCAs.Complete || !bundle.DeviceCAs.ManagedComplete) {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("device CA ownership could not be read; retry the configuration fetch"))
			return
		}
		bundle.InternalCAs = internalCABundleSection(config.InternalCAs)
		// ★★★ WHICH IDENTITY PROVIDER MAY SIGN A USER IN, for each organization. Registered through the
		// Console against the control plane, and — until this — carried nowhere: the Edge that redirects a
		// held flow to the step-up portal answered "no usable IdP for the tenant" about an organization
		// whose administrator had registered one, with a 200, minutes earlier. See
		// config_bundle_idp_connections.go.
		//
		// ★ PUBLISHED ONLY BY THE CONTROL PLANE, like the region endpoints above it. Every node holds one of
		// these registries; the one that is authoritative is the one authored against.
		if edgeIsControlPlane {
			bundle.IdPConnections = idpConnectionBundleSection(theIdPRegistry.Load())
			// What the fleet has already approved out of band. See config_bundle_grants.go.
			bundle.Grants = grantBundleSection(theGrantStore.Load())
		}
		bundle.RegionEndpoints = regionEndpointBundleSection(edgeIsControlPlane, regionMap.Catalog())
		bundle.InspectionPosture = inspectionPostureBundleSection(config.InspectionPosture)
		// The vendor's signed licence, carried so the Edges that ENFORCE it hold what the authority holds. Before
		// this it went no further than the node it was applied to, and an Edge given vendor keys refused every
		// enrolment in the deployment.
		bundle.Licence = licenceBundleSection(config.VendorLicense)
		bundle.Sites = siteBundleSection(r.Context(), config.SiteStore,
			directoryBundleTenants(r.Context(), tenantModelStore, tenantID))
		// ★ Served for EVERY tenant, not the requesting one. The rest of this bundle is tenant-scoped because
		// each Edge pulls on behalf of the tenant it enforces; rules are not, because the fleet requirement is
		// that all Edges hold the same authored configuration for all tenants. A tenant-scoped rule section
		// would have re-created the original defect one level down: correct for the tenant that happened to be
		// asked, silently absent for the rest.
		if ruleStore != nil {
			rules := ruleStore.Snapshot()
			section := &authoredRuleBundle{Rules: rules}
			if assetStore != nil {
				section.Endpoints, section.Groups, section.Services = assetStore.AuthoredSnapshot()
			}
			bundle.Rules = section
		}
		// SIGN the bundle with the shared agent-policy Ed25519 key so a PULLING Edge can verify it and reject a
		// tampered/forged config (a compromised CP or stolen bearer token must not push arbitrary policy). An Edge
		// that pins the key requires this signature (fail-closed). No signer configured = serve unsigned (lab).
		if config.AgentPolicySigner != nil {
			env, serr := config.AgentPolicySigner.Sign(bundle, time.Now())
			if serr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("sign config bundle: %w", serr))
				return
			}
			writeJSON(w, http.StatusOK, env)
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	}))
	mux.HandleFunc("GET /admin/policies/{policy_id}", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		policy, found, err := policyStore.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("policy_id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("policy %s is absent", r.PathValue("policy_id")))
			return
		}
		writeJSON(w, http.StatusOK, policy)
	}))
	// Enable/disable a single policy at runtime (incl. a built-in seeded one) without deleting it — the
	// "every rule/policy has an active/disabled toggle" of the unified policy model. Persisted (survives a
	// restart even though the policy re-seeds from config); a disabled policy is skipped at decision time.
	mux.HandleFunc("POST /admin/policies/{policy_id}/status", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "policy status") {
			return
		}
		var body struct {
			Status string `json:"status"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode status request: %w", err))
			return
		}
		status := strings.ToLower(strings.TrimSpace(body.Status))
		if status != "active" && status != "disabled" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("status must be active or disabled"))
			return
		}
		concrete, ok := policyStore.(*policystore.Store)
		if !ok {
			writeError(w, http.StatusConflict, fmt.Errorf("policy status toggle is not supported on this edge"))
			return
		}
		if !concrete.SetPolicyStatus(adminTenantIDFromRequest(r), r.PathValue("policy_id"), status) {
			writeError(w, http.StatusNotFound, fmt.Errorf("policy %s not found", r.PathValue("policy_id")))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"policy_id": r.PathValue("policy_id"), "status": status})
	}))
	mux.HandleFunc("POST /admin/policies", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "access policies") {
			return
		}
		var policy model.Policy
		if err := decodeLimitedJSONBody(w, r, &policy, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode policy: %w", err))
			return
		}
		now := time.Now()
		tenantID := adminTenantIDFromRequest(r)
		created, err := policyStore.Upsert(r.Context(), policy, tenantID, now)
		if err != nil {
			if errors.Is(err, policystore.ErrPolicyPersistence) {
				writeError(w, http.StatusInternalServerError, policystore.ErrPolicyPersistence)
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !publishAndAudit(w, r, created, "upsert", now) {
			return
		}
		writeJSON(w, http.StatusOK, created)
	}))
	// The missing half of POST: an authored policy could be created and disabled but never removed, so a
	// mistaken one sat in every listing forever with only a status override standing in for deletion.
	mux.HandleFunc("DELETE /admin/policies/{policy_id}", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "access policies") {
			return
		}
		now := time.Now()
		tenantID := adminTenantIDFromRequest(r)
		removed, existed, err := policyStore.Delete(r.Context(), tenantID, r.PathValue("policy_id"))
		if err != nil {
			// A bundle-sourced policy: it exists, but this API is not where it lives.
			writeError(w, http.StatusConflict, err)
			return
		}
		if !existed {
			writeError(w, http.StatusNotFound, fmt.Errorf("no admin-authored policy %s", r.PathValue("policy_id")))
			return
		}
		if !publishAndAudit(w, r, removed, "delete", now) {
			return
		}
		logInfof("admin_policy_deleted id=%q name=%q tenant=%q", removed.ID, removed.Name, tenantID)
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_policies.v1",
			"deleted":        removed.ID,
			"name":           removed.Name,
		})
	}))
	return bundleGeneration
}

// generationOnly drops the epoch from the shared generation function, for the one caller that only needs the
// number. Named rather than inlined so the shared function keeps a single call shape.
func generationOnly(f func() (uint64, string)) uint64 {
	g, _ := f()
	return g
}
