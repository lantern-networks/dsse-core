package main

import (
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"log"
	"maps"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// connector_route_governance.go — admin governance over connector reachable ROUTES. The corrected model is
// CP-CONFIGURED: the operator/CP configures which subnets a connector serves (admin-authored routes = the
// SOURCE), and a connector's self-reported subnets are non-authoritative DISCOVERY the operator ADOPTS
// (approve) to make routable. The operator can also HOLD a discovered subnet. The route layer
// (connectorForDestination) sees only the EFFECTIVE set. See docs/connector_network_route_advertisement_design.md.
//
// Two modes, selected by cpConfigured (flag -connector-routes-cp-configured):
//   - cpConfigured=false (legacy default, non-breaking): a connector's self-declared routes are grandfathered
//     (auto-approved) on first sight, then a NEWLY declared route is pending until approved.
//   - cpConfigured=true (corrected model): a self-reported (discovered) subnet is NEVER routable until the
//     operator adopts it (approve) — no grandfather. The connector never sources a routable route.
// In both modes admin-authored routes are always routable and a HELD route is always dropped.
//
// v1 keeps the model's single-namespace-per-connector: held/approved routes are keyed by CIDR within the
// connector's namespace; admin-authored routes are added in the connector's namespace (typed per-CIDR
// namespace is a later slice).

// authoredRoute is one admin-authored (CP-configured) binding. Exactly one of CIDR / FQDN / NetworkID is set:
//   - CIDR: a raw subnet binding.
//   - FQDN: a name binding (preferred route — unique across sites, no namespace).
//   - NetworkID: a REFERENCE to a Named Network (a VLANObject) — the subnet is defined ONCE there and reused for
//     connector routing, so the same range is not re-typed across surfaces (docs/unified_network_object_design.md).
type authoredRoute struct {
	CIDR        string `json:"cidr,omitempty"`
	FQDN        string `json:"fqdn,omitempty"`
	NetworkID   string `json:"network_id,omitempty"`
	Description string `json:"description,omitempty"`
}

// key is the dedupe/identity of an authored binding: its CIDR, its FQDN, or the referenced Named Network id.
func (r authoredRoute) key() string {
	if strings.TrimSpace(r.CIDR) != "" {
		return "cidr:" + strings.TrimSpace(r.CIDR)
	}
	if strings.TrimSpace(r.FQDN) != "" {
		return "fqdn:" + strings.ToLower(strings.TrimSpace(r.FQDN))
	}
	return "net:" + strings.TrimSpace(r.NetworkID)
}

type connectorRouteGovernance struct {
	writeMu     sync.Mutex
	sharedKnown bool
	mu          sync.RWMutex
	held        map[string]map[string]map[string]bool // tenant -> connectorID -> cidr -> held
	authored    map[string]map[string][]authoredRoute // tenant -> connectorID -> authored routes
	// approved gates the fail-safe: once a connector has been SEEN (SeeRoutes ran once — the grandfather), only
	// APPROVED self-declared CIDRs are routable. A route the connector advertises LATER is PENDING (not routable)
	// until an operator approves it — so a mis-declared or rogue connector cannot silently grab 0.0.0.0/0.
	approved map[string]map[string]map[string]bool // tenant -> connectorID -> cidr -> approved
	seen     map[string]map[string]bool            // tenant -> connectorID -> the grandfather has run
	// lastAdvertised records when the connector last advertised its route set (for the admin view).
	lastAdvertised map[string]map[string]time.Time
	// persistPath, when set, makes the admin DECISIONS (held/approved/authored/seen) durable + shared across the
	// HA fleet: every Edge that mounts the same path (the reference shares ./dataplane-ne across region-a/-b)
	// reads the same decisions, so route governance is consistent fleet-wide and survives a restart. Runtime
	// observations (lastAdvertised) are NOT persisted — each Edge times its own advertisements.
	persistPath string
	// persister, when set, is where these decisions actually live — the deployment's SHARED state.
	//
	// ★★★ THEY WERE IN MEMORY AND THE INSTALLER NEVER CONFIGURED OTHERWISE (2026-08-25, measured). A route
	// added to a Site answered 200 and read back correctly; a control-plane restart left the Site (it is in
	// the shared database) and took its ROUTES. Without them a connector fronts nothing, so no internal asset
	// is reachable by anybody — and the API said success.
	//
	// ★ AND THE FILE PATH IS NOT THE ANSWER. The flag that configures one describes itself as durable "on a
	// mount shared across the HA fleet". A shared mount is not a thing production deployments have; a file
	// per node would make each control plane serve a different set of routes after a failover, which is a
	// silent divergence rather than a fix. These decisions belong where the rest of the deployment's shared
	// state is, and the mechanism for that already exists.
	persister blobstore.Persister
	// cpConfigured selects the corrected CP-configured model: when true a connector's self-reported (discovered)
	// subnets are non-authoritative and NOT routable until the operator adopts (approves) them — no grandfather.
	// When false (legacy default) self-declared routes are grandfathered on first sight (non-breaking upgrade).
	cpConfigured bool
	// gen is a monotonic counter bumped on every DECISION change (held/approved/authored). It folds into the
	// config-bundle Generation so a pull-model Edge re-pulls when the governance decisions change. It is NOT
	// bumped on a discovery-only observation (SeeRoutes refreshing lastAdvertised), so a heartbeat never churns
	// the bundle. See docs/connector_network_route_advertisement_design.md.
	gen uint64
	// networkResolver expands a binding that REFERENCES a Named Network (VLANObject) to its name + CIDRs, so a
	// subnet defined once (in the Network Zones / vlan-objects surface) is reused for connector routing without
	// re-typing (docs/unified_network_object_design.md). Nil = network references resolve to nothing (safe).
	networkResolver func(tenant, networkID string) (name string, cidrs []string)
}

// governancePersistState is the on-disk shape of the shared governance decisions.
type governancePersistState struct {
	// Complete distinguishes an authoritative empty set from a legacy omitted section.
	Complete bool                                  `json:"complete,omitempty"`
	Held     map[string]map[string]map[string]bool `json:"held"`
	Approved map[string]map[string]map[string]bool `json:"approved"`
	Seen     map[string]map[string]bool            `json:"seen"`
	Authored map[string]map[string][]authoredRoute `json:"authored"`
}

func newConnectorRouteGovernance() *connectorRouteGovernance {
	return newConnectorRouteGovernanceWithPersistence("")
}

func newConnectorRouteGovernanceWithPersistence(persistPath string) *connectorRouteGovernance {
	return newConnectorRouteGovernanceWithOptions(persistPath, false)
}

// newConnectorRouteGovernanceWithOptions builds the governance store. cpConfigured selects the corrected
// CP-configured model (self-reported subnets are discovery, routable only after adoption); false keeps the
// legacy grandfather behavior for a non-breaking upgrade.
func newConnectorRouteGovernanceWithOptions(persistPath string, cpConfigured bool) *connectorRouteGovernance {
	return newConnectorRouteGovernanceWithPersister(persistPath, cpConfigured, nil)
}

// newConnectorRouteGovernanceWithPersister is the same, with the deployment's shared state supplied. A nil
// persister keeps the historical file behaviour, which is what the tests and single-process harnesses use.
func newConnectorRouteGovernanceWithPersister(persistPath string, cpConfigured bool,
	persister blobstore.Persister) *connectorRouteGovernance {
	g := &connectorRouteGovernance{
		persister:      persister,
		held:           map[string]map[string]map[string]bool{},
		authored:       map[string]map[string][]authoredRoute{},
		approved:       map[string]map[string]map[string]bool{},
		seen:           map[string]map[string]bool{},
		lastAdvertised: map[string]map[string]time.Time{},
		persistPath:    strings.TrimSpace(persistPath),
		cpConfigured:   cpConfigured,
	}
	if g.isShared() {
		if err := g.RefreshShared(); err != nil {
			log.Printf("connector route governance unavailable: %v", err)
		}
	} else {
		g.load()
	}
	return g
}

// SetNetworkResolver injects the Named-Network → (name, CIDRs) resolver (backed by the vlan-objects store), so a
// connector binding that references a Named Network expands to that network's CIDRs. Setter-style so tests and
// wiring stay non-breaking; nil-safe (unset = network references contribute no routes).
func (g *connectorRouteGovernance) SetNetworkResolver(fn func(tenant, networkID string) (string, []string)) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.networkResolver = fn
}

// resolveNetworkLocked expands a referenced Named Network to its CIDRs (caller holds g.mu). Empty when unresolved.
func (g *connectorRouteGovernance) resolveNetworkLocked(tenant, networkID string) (string, []string) {
	if g.networkResolver == nil || strings.TrimSpace(networkID) == "" {
		return "", nil
	}
	return g.networkResolver(tenant, networkID)
}

// load hydrates the decisions from the shared file (best-effort; absent/corrupt = start empty).
func (g *connectorRouteGovernance) load() {
	var raw []byte
	switch {
	case g.persister != nil:
		var err error
		if raw, err = g.persister.Load(); err != nil || len(raw) == 0 {
			return
		}
	case g.persistPath != "":
		var err error
		if raw, err = os.ReadFile(g.persistPath); err != nil {
			return
		}
	default:
		return
	}
	var st governancePersistState
	if err := json.Unmarshal(raw, &st); err != nil {
		log.Printf("connector_route_governance: ignoring corrupt persist file %s: %v", g.persistPath, err)
		return
	}
	if st.Held != nil {
		g.held = st.Held
	}
	if st.Approved != nil {
		g.approved = st.Approved
	}
	if st.Seen != nil {
		g.seen = st.Seen
	}
	if st.Authored != nil {
		g.authored = st.Authored
	}
	g.sharedKnown = true
	where := g.persistPath
	if g.persister != nil {
		where = "the deployment's shared state"
	}
	log.Printf("connector_route_governance: loaded shared decisions from %s", where)
}

// saveLocked retains best-effort persistence for discovery and imported decisions.
// Administrator binding mutations use persistStateLocked before publishing instead.
func (g *connectorRouteGovernance) saveLocked() {
	if err := g.persistStateLocked(governancePersistState{Held: g.held, Approved: g.approved, Seen: g.seen, Authored: g.authored}); err != nil {
		log.Printf("connector_route_governance: persist failed: %v", err)
	}
}

// persistStateLocked writes a candidate snapshot. The caller holds g.mu throughout
// saving and publication so another writer cannot overwrite it with an older state.
func (g *connectorRouteGovernance) persistStateLocked(st governancePersistState) error {
	if g.persister == nil && g.persistPath == "" {
		return nil
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode route decisions: %w", err)
	}
	if g.persister != nil {
		if err := g.persister.Save(raw); err != nil {
			return fmt.Errorf("save route decisions: %w", err)
		}
		return nil
	}
	tmp := g.persistPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write route decisions: %w", err)
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, g.persistPath); err != nil {
		return fmt.Errorf("replace route decisions: %w", err)
	}
	return nil
}

// SetHeld holds (block=true) or unholds a self-declared CIDR route for a connector.
func (g *connectorRouteGovernance) setHeldLocal(tenant, connectorID, cidr string, held bool) {
	tenant, connectorID, cidr = strings.TrimSpace(tenant), strings.TrimSpace(connectorID), strings.TrimSpace(cidr)
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.saveLocked()
	g.gen++
	if !held {
		if m := g.held[tenant]; m != nil {
			if c := m[connectorID]; c != nil {
				delete(c, cidr)
			}
		}
		return
	}
	if g.held[tenant] == nil {
		g.held[tenant] = map[string]map[string]bool{}
	}
	if g.held[tenant][connectorID] == nil {
		g.held[tenant][connectorID] = map[string]bool{}
	}
	g.held[tenant][connectorID][cidr] = true
}

// AddAuthored adds an admin-authored binding (idempotent by CIDR or FQDN).
func (g *connectorRouteGovernance) addAuthoredLocal(tenant, connectorID string, r authoredRoute) error {
	tenant, connectorID = strings.TrimSpace(tenant), strings.TrimSpace(connectorID)
	r.CIDR = strings.TrimSpace(r.CIDR)
	r.FQDN = strings.TrimSpace(r.FQDN)
	g.mu.Lock()
	defer g.mu.Unlock()
	list := append([]authoredRoute(nil), g.authored[tenant][connectorID]...)
	for i, existing := range list {
		if existing.key() == r.key() {
			list[i] = r
			return g.commitAuthoredLocked(tenant, connectorID, list)
		}
	}
	return g.commitAuthoredLocked(tenant, connectorID, append(list, r))
}

// RemoveAuthored deletes an admin-authored binding by its identity (a CIDR or an "fqdn:name" key equivalent).
// key is matched against each binding's key: pass a bare CIDR, or an authoredRoute-derived key.
func (g *connectorRouteGovernance) removeAuthoredLocal(tenant, connectorID, key string) error {
	tenant, connectorID, key = strings.TrimSpace(tenant), strings.TrimSpace(connectorID), strings.TrimSpace(key)
	g.mu.Lock()
	defer g.mu.Unlock()
	list := g.authored[tenant][connectorID]
	out := list[:0:0]
	for _, r := range list {
		// Match a bare CIDR (back-compat) or the typed key of either kind.
		if r.CIDR != key && r.key() != key && r.key() != "fqdn:"+strings.ToLower(key) {
			out = append(out, r)
		}
	}
	return g.commitAuthoredLocked(tenant, connectorID, out)
}

func (g *connectorRouteGovernance) commitAuthoredLocked(tenant, connectorID string, list []authoredRoute) error {
	next := maps.Clone(g.authored)
	if next == nil {
		next = map[string]map[string][]authoredRoute{}
	}
	if next[tenant] != nil || len(list) > 0 {
		bindings := maps.Clone(next[tenant])
		if bindings == nil {
			bindings = map[string][]authoredRoute{}
		}
		bindings[connectorID] = list
		next[tenant] = bindings
	}
	if err := g.persistStateLocked(governancePersistState{Held: g.held, Approved: g.approved, Seen: g.seen, Authored: next}); err != nil {
		return err
	}
	g.authored = next
	g.gen++
	return nil
}

func (g *connectorRouteGovernance) isHeld(tenant, connectorID, cidr string) bool {
	if m := g.held[tenant]; m != nil {
		if c := m[connectorID]; c != nil {
			return c[cidr]
		}
	}
	return false
}

// SeeRoutes records the connector's currently self-reported (discovered) CIDRs and the observation time. The
// grandfather (legacy mode) auto-approves the current set on FIRST sight so existing deployments keep working,
// then a NEWLY reported CIDR is PENDING until an operator approves it. In the corrected CP-configured mode there
// is NO grandfather: a discovered subnet is marked seen (so the operator sees it to adopt) but never
// auto-approved — the connector never sources a routable route (fail-safe against a rogue connector grabbing
// 0.0.0.0/0).
func (g *connectorRouteGovernance) seeRoutesLocal(tenant, connectorID string, cidrs []string, now time.Time) {
	tenant, connectorID = strings.TrimSpace(tenant), strings.TrimSpace(connectorID)
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.saveLocked()
	if g.lastAdvertised[tenant] == nil {
		g.lastAdvertised[tenant] = map[string]time.Time{}
	}
	g.lastAdvertised[tenant][connectorID] = now
	if g.seen[tenant] != nil && g.seen[tenant][connectorID] {
		return // already seen; new CIDRs stay pending/discovered until approved
	}
	if g.seen[tenant] == nil {
		g.seen[tenant] = map[string]bool{}
	}
	g.seen[tenant][connectorID] = true
	if g.cpConfigured {
		return // discovery only — never auto-approve; the operator adopts each subnet explicitly
	}
	for _, cidr := range cidrs {
		g.setApprovedLocked(tenant, connectorID, strings.TrimSpace(cidr), true)
	}
}

// SetApproved approves (or un-approves) a self-declared CIDR for routing (used on a pending route).
func (g *connectorRouteGovernance) setApprovedLocal(tenant, connectorID, cidr string, approved bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.saveLocked()
	g.setApprovedLocked(strings.TrimSpace(tenant), strings.TrimSpace(connectorID), strings.TrimSpace(cidr), approved)
}

func (g *connectorRouteGovernance) setApprovedLocked(tenant, connectorID, cidr string, approved bool) {
	g.gen++
	if !approved {
		if m := g.approved[tenant]; m != nil {
			if c := m[connectorID]; c != nil {
				delete(c, cidr)
			}
		}
		return
	}
	if g.approved[tenant] == nil {
		g.approved[tenant] = map[string]map[string]bool{}
	}
	if g.approved[tenant][connectorID] == nil {
		g.approved[tenant][connectorID] = map[string]bool{}
	}
	g.approved[tenant][connectorID][cidr] = true
}

func (g *connectorRouteGovernance) isApproved(tenant, connectorID, cidr string) bool {
	if m := g.approved[tenant]; m != nil {
		if c := m[connectorID]; c != nil {
			return c[cidr]
		}
	}
	return false
}

func (g *connectorRouteGovernance) isSeen(tenant, connectorID string) bool {
	if m := g.seen[tenant]; m != nil {
		return m[connectorID]
	}
	return false
}

// routableLocked decides whether a self-reported (discovered) CIDR enters the route layer: never when HELD.
// In the CP-configured model it is routable only when the operator has ADOPTED it (approved) — no grandfather.
// In the legacy model it is routable once grandfathered (seen) and approved, and routable before the grandfather.
func (g *connectorRouteGovernance) routableLocked(tenant, connectorID, cidr string) bool {
	if g.isHeld(tenant, connectorID, cidr) {
		return false
	}
	if g.cpConfigured {
		return g.isApproved(tenant, connectorID, cidr)
	}
	if g.isSeen(tenant, connectorID) {
		return g.isApproved(tenant, connectorID, cidr)
	}
	return true
}

// Apply returns a copy of the connectors with governance applied to the route layer. Admin-configured Networks
// are keyed by the SITE (connector group), so EVERY connector in a site serves the site's Networks — an
// active/standby pair is interchangeable (docs/site_private_access_design.md). Self-declared CIDRs still pass
// through the per-connector discovery gate (HELD dropped). Nil governance is the identity.
func (g *connectorRouteGovernance) Apply(tenant string, connectors []model.ConnectorRegistration) []model.ConnectorRegistration {
	if g == nil {
		return connectors
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]model.ConnectorRegistration, 0, len(connectors))
	for _, c := range connectors {
		cidrs := make([]string, 0, len(c.ReachableRoutes.CIDRs))
		for _, cidr := range c.ReachableRoutes.CIDRs {
			if g.routableLocked(tenant, c.ID, strings.TrimSpace(cidr)) {
				cidrs = append(cidrs, cidr)
			}
		}
		fqdns := append([]string(nil), c.ReachableRoutes.FQDNDomains...)
		// Authored bindings are keyed by the SITE (connector group) — every connector in a site serves the
		// site's Networks — AND by the connector's own id (a per-connector binding via
		// POST /admin/connectors/{id}/routes). Both must route: before 2026-07-16 the per-connector key was
		// write-only (the admin API accepted the binding and the Routes view showed it, but nothing routed).
		authoredKeys := []string{strings.TrimSpace(c.ConnectorGroupID)}
		if cidKey := strings.TrimSpace(c.ID); cidKey != "" && cidKey != authoredKeys[0] {
			authoredKeys = append(authoredKeys, cidKey)
		}
		seenAuthored := map[string]bool{}
		for _, key := range authoredKeys {
			for _, r := range g.authored[tenant][key] {
				if seenAuthored[r.key()] {
					continue
				}
				seenAuthored[r.key()] = true
				if strings.TrimSpace(r.CIDR) != "" {
					cidrs = append(cidrs, r.CIDR)
				}
				if strings.TrimSpace(r.FQDN) != "" {
					fqdns = append(fqdns, r.FQDN)
				}
				if strings.TrimSpace(r.NetworkID) != "" {
					// A binding that references a Named Network expands to that network's CIDRs (defined once).
					if _, netCIDRs := g.resolveNetworkLocked(tenant, r.NetworkID); len(netCIDRs) > 0 {
						cidrs = append(cidrs, netCIDRs...)
					}
				}
			}
		}
		c.ReachableRoutes.CIDRs = cidrs
		c.ReachableRoutes.FQDNDomains = fqdns
		out = append(out, c)
	}
	return out
}

// ConfigGeneration returns the monotonic decision counter, folded into the config-bundle Generation so a
// pull-model Edge re-pulls when the governance decisions change. Nil-safe (0).
func (g *connectorRouteGovernance) ConfigGeneration() uint64 {
	if g == nil {
		return 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.gen
}

// Export snapshots the governance DECISIONS (held/approved/seen/authored) so they can ride the signed
// config-bundle — the CP-configured model distributes the bindings as config, so a pull-model Edge converges
// without a shared governance store. Runtime observations (lastAdvertised) are per-Edge and NOT exported.
// Nil-safe (returns nil). Returns nil when there are no decisions (so an empty bundle section stays lockout-safe).
func (g *connectorRouteGovernance) Export() *governancePersistState {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	st := governancePersistState{Held: g.held, Approved: g.approved, Seen: g.seen, Authored: g.authored}
	if len(st.Held) == 0 && len(st.Approved) == 0 && len(st.Seen) == 0 && len(st.Authored) == 0 {
		return nil
	}
	return &st
}

// ImportShared adopts the governance decisions distributed in a config-bundle (the CP is the source of truth
// for connector bindings). Present-with-content REPLACES the local decisions; nil / all-empty is a no-op so an
// omitted or empty bundle section never wipes local decisions (lockout-safe, mirroring the connector catalog).
// Nil-safe.
func (g *connectorRouteGovernance) importSharedLocal(st *governancePersistState) {
	if g == nil || st == nil {
		return
	}
	if len(st.Held) == 0 && len(st.Approved) == 0 && len(st.Seen) == 0 && len(st.Authored) == 0 {
		return // empty section: keep local (lockout-safe)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.saveLocked()
	g.gen++
	if st.Held != nil {
		g.held = st.Held
	}
	if st.Approved != nil {
		g.approved = st.Approved
	}
	if st.Seen != nil {
		g.seen = st.Seen
	}
	if st.Authored != nil {
		g.authored = st.Authored
	}
}

// governedRoute is one route row for the admin API: a self-reported or admin-authored binding with its state.
// Exactly one of CIDR / FQDN is set. Kind ("cidr"|"fqdn") lets the UI label the row without inspecting fields.
type governedRoute struct {
	CIDR         string   `json:"cidr,omitempty"`
	FQDN         string   `json:"fqdn,omitempty"`
	NetworkID    string   `json:"network_id,omitempty"`    // set when the binding references a Named Network
	NetworkName  string   `json:"network_name,omitempty"`  // the referenced Named Network's name (display)
	NetworkCIDRs []string `json:"network_cidrs,omitempty"` // the CIDRs the reference expands to (display)
	Kind         string   `json:"kind"`                    // "cidr" | "fqdn" | "network"
	Source       string   `json:"source"`                  // "connector" (self-reported / discovered) | "admin" (authored / CP-configured)
	Held         bool     `json:"held"`                    // connector CIDR routes only: operator-blocked from the route layer
	Pending      bool     `json:"pending"`                 // connector CIDR routes only: discovered, awaiting adoption (not routable)
	Routable     bool     `json:"routable"`
	Description  string   `json:"description,omitempty"`
}

// Routes reports the governance view for a connector: each self-reported CIDR with its held/routable state, the
// self-reported FQDN (name) routes (informational — always routable, ungoverned today), then the admin-authored
// bindings (CIDR + FQDN). `declared` is the connector's self-reported CIDR list; `declaredFQDNs` its name routes.
func (g *connectorRouteGovernance) Routes(tenant, connectorID string, declared, declaredFQDNs []string) []governedRoute {
	g.mu.RLock()
	defer g.mu.RUnlock()
	rows := make([]governedRoute, 0, len(declared)+len(declaredFQDNs))
	seen := g.isSeen(tenant, connectorID)
	for _, cidr := range declared {
		cidr = strings.TrimSpace(cidr)
		held := g.isHeld(tenant, connectorID, cidr)
		pending := seen && !held && !g.isApproved(tenant, connectorID, cidr)
		rows = append(rows, governedRoute{CIDR: cidr, Kind: "cidr", Source: "connector", Held: held, Pending: pending, Routable: g.routableLocked(tenant, connectorID, cidr)})
	}
	for _, fqdn := range declaredFQDNs {
		fqdn = strings.TrimSpace(fqdn)
		if fqdn == "" {
			continue
		}
		// Self-reported name routes are not CIDR-governed today (names are globally unique); they route as-is.
		rows = append(rows, governedRoute{FQDN: fqdn, Kind: "fqdn", Source: "connector", Routable: true})
	}
	for _, r := range g.authored[tenant][connectorID] {
		switch {
		case strings.TrimSpace(r.NetworkID) != "":
			name, cidrs := g.resolveNetworkLocked(tenant, r.NetworkID)
			rows = append(rows, governedRoute{NetworkID: r.NetworkID, NetworkName: name, NetworkCIDRs: cidrs, Kind: "network", Source: "admin", Routable: true, Description: r.Description})
		case strings.TrimSpace(r.FQDN) != "":
			rows = append(rows, governedRoute{FQDN: r.FQDN, Kind: "fqdn", Source: "admin", Routable: true, Description: r.Description})
		default:
			rows = append(rows, governedRoute{CIDR: r.CIDR, Kind: "cidr", Source: "admin", Routable: true, Description: r.Description})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ki := rows[i].CIDR + rows[i].FQDN + rows[i].NetworkName + rows[i].NetworkID
		kj := rows[j].CIDR + rows[j].FQDN + rows[j].NetworkName + rows[j].NetworkID
		return ki < kj
	})
	return rows
}
