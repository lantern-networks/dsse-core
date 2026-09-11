package main

// fleet_config_status.go — "which Edges actually have this config?", answerable for the first time.
//
// ★ Why this exists (2026-08-10). An operator adopted a certificate-pin bypass, the Console confirmed it, and
// GET /admin/intercept/bypass-hosts — the endpoint whose only purpose is to show what is really not being
// decrypted — listed the host. The device kept receiving the interception certificate, because it was served
// by the OTHER Edge, which had never heard of the change. Every surface agreed with the administrator. The
// only party that disagreed was the endpoint, and the endpoint has no voice in the Console.
// (docs/authored_policy_reaches_one_edge_not_the_serving_one.md)
//
// Distributing authored rules fixed the mechanism. It did not fix the REPORTING, and the reporting is what
// made the incident un-diagnosable: an admin API answers for the node that was asked, and the Console asks
// exactly one. "Applied" meant "applied on whichever Edge the console front door proxies to" — a sentence
// nobody would knowingly ship, arrived at by never having a way to say anything else.
//
// The pieces already existed and were never joined:
//   - each Edge tracks the last CP generation it applied (configBundleSyncStatus), and its own doc comment
//     already describes it as "the fleet-health / staleness signal"
//   - each Edge knows who it is (-edge-region-id / -edge-cluster-id)
//   - the Edge already holds an authenticated channel to the control plane
// What was missing is one report and one place to read it.
//
// ★ REPORTED BY THE EDGE, not polled by the CP. The control plane cannot reach the Edges: in the reference
// deployment region-b's admin API is not published at all, and in production the Edges are the ones behind the
// boundary. A pull model would work in the lab and be undeployable, which is the worst kind of design to
// discover late. Push also gives the property that matters more: an Edge that has stopped reporting is
// VISIBLE, whereas an Edge the CP forgot to poll is invisible.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// fleetConfigReport is what one Edge says about itself.
type fleetConfigReport struct {
	RegionID  string `json:"region_id"`
	ClusterID string `json:"cluster_id"`
	// NodeID identifies the INSTANCE. A region is not one Edge: production fronts several behind a load
	// balancer, and they must each be visible.
	//
	// ★ Keying on region/cluster alone was this file's own defect, found by starting a second Edge in one
	// region (2026-08-10). Both reported, the later write replaced the earlier, and the view showed ONE row
	// carrying whichever instance spoke last — so an instance that was BEHIND became invisible the moment a
	// current sibling reported. That is one member answering for the group: the incident this file exists to
	// end, reproduced inside it, one level down.
	//
	// Defaults to the hostname, which is already unique per container/pod/host, so no deployment has to name
	// it for the view to be correct.
	NodeID string `json:"node_id"`
	// Machine and MachineAddress are the machine this node runs ON, as the operator declared it.
	//
	// ★★★ THE FLEET HAD NO ADDRESS (2026-09-03, found by adding a fourth machine and looking for it on a
	// screen). NodeID defaults to the container's hostname — a hex id that changes every time the container
	// is recreated — so the fleet an operator can be shown is a list of hex ids grouped by region, and
	// "which machine is behind?" is not answerable from anything on it. The plan already holds the name the
	// operator wrote and the name TLS verifies; the installer now carries both onto the machine, and this
	// reports them. Empty on a deployment that was not generated from a plan, which is why nothing here
	// depends on them being present.
	Machine        string `json:"machine,omitempty"`
	MachineAddress string `json:"machine_address,omitempty"`
	// Generation/Epoch are the control plane's, echoed back — the whole point is comparing them to the CP's
	// CURRENT values. An Edge reporting a generation it invented would be reporting about a different world.
	Generation  uint64 `json:"generation"`
	Epoch       string `json:"epoch"`
	HaveApplied bool   `json:"have_applied"`
	RuleCount   int    `json:"rule_count"`
	// RecoveryName is the name this node offers to an agent whose certificate has expired, and empty when it
	// offers none.
	//
	// ★★★ IT IS REPORTED BECAUSE OBSERVATION IS THE EDGE REPORTING, NOT THE CONSOLE ASKING AN EDGE
	// (2026-08-25). Devices meet EDGES; the control plane serves no agent plane, so asking the authority
	// whether a recovery name is offered answers about a node no device has ever dialled — structurally
	// empty, and reassuring. A node that offers none is the fact somebody needs before they change anything,
	// because every device it enrolled then has no way back.
	RecoveryName string `json:"recovery_name,omitempty"`
	// DevicesWithoutAWayBack is how many of this node's enrolled identities have NOT been measured onto that
	// name. Silence counts as not yet: a machine that is switched off is exactly the one this path exists for.
	DevicesWithoutAWayBack int `json:"devices_without_a_way_back"`
	// PolicySigningKey is the public half of the authority this node signs agent policy under, and verifies
	// config bundles against. A deployment has ONE; two distinct values here mean it has silently become two.
	// See agent_policy_authority_report.go for the deployment that had two and looked healthy in every view.
	PolicySigningKey string `json:"policy_signing_key,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	// Erasures is this node's answer for every standing tenant ERASURE order it has been told about: does this
	// node still hold anything for that tenant?
	//
	// ★ WHY IT TRAVELS WITH THE STATUS (2026-08-15). A tenant's logs live on the disk of every node that served
	// it, so "the tenant has been erased" is a claim about the whole fleet and no single node can make it. Each
	// node can only answer for itself — and it answers by COUNTING, freshly, with the same footprint code the
	// operator would run by hand. It is not a stored "I did it" flag: a node that erased and then somehow wrote
	// again would say so, where a flag would keep insisting the job was done.
	//
	// Without this an operator proving an erasure has to know every node's address and ask each one, which is
	// exactly the kind of manual sweep that gets skipped and then reported as complete.
	Erasures []fleetTenantErasure `json:"erasures,omitempty"`
}

// fleetTenantErasure is one node's answer about one erased tenant: is this node clean, and if not, how much is
// left. Remaining counts only what this node can see; the footprint route on that node says what it could not.
type fleetTenantErasure struct {
	TenantID  string `json:"tenant_id"`
	Clean     bool   `json:"clean"`
	Remaining int64  `json:"remaining"`
}

// fleetConfigEntry is a report plus what the control plane knows about it: when it arrived, and whether it is
// current. Staleness is judged HERE rather than by the reader, so two readers cannot disagree about it.
type fleetConfigEntry struct {
	fleetConfigReport
	ReportedAt time.Time `json:"reported_at"`
	// Status is one of: current | lagging | never_applied | error.
	//
	// ★ There is deliberately NO "gone" or "silent" state. A first version had one, and it modelled the wrong
	// world: it kept an instance after it stopped reporting and counted it as behind, so a routine scale-in
	// read as "4 Edges, 2 not responding". In a fleet where instances are created and destroyed continuously
	// that manufactures alarms out of normal operation, and it also implies an EXPECTED count the control
	// plane has no way to know. Membership is whatever is reporting now; status is only ever about CONFIG.
	Status string `json:"status"`
}

// fleetConfigEntryForTenant is what an administrator of ONE organization is told about one Edge: whether the
// configuration is in effect, and where. Not which node it is, not what else that node carries.
//
// The rule count is absent rather than zero. The number the store holds is the NODE's, across every tenant it
// serves, so showing it to one tenant would be a figure about other people's rules with this tenant's name on
// it — and a zero would read as "none of my rules are in effect", which is a different, alarming claim.
type fleetConfigEntryForTenant struct {
	RegionID    string    `json:"region_id"`
	HaveApplied bool      `json:"have_applied"`
	ReportedAt  time.Time `json:"reported_at"`
	Status      string    `json:"status"`
	// RecoveryName is the name this node offers to an agent whose certificate has expired. Empty means it
	// offers none, and then a device of ANY organization that enrolled there has no way back.
	//
	// ★★ THE NAME IS A CUSTOMER'S QUESTION; THE COUNT IS NOT. "Is there a way back where my devices are
	// served" is about this organization, and the answer is the same name every organization is told — it
	// discloses nothing about anybody else. How MANY devices have not taken it is the node's total across
	// every organization it serves, so it stays with the rule count, in the operator's view, for the reason
	// written above it.
	RecoveryName string               `json:"recovery_name,omitempty"`
	Erasures     []fleetTenantErasure `json:"erasures,omitempty"`
}

// fleetConfigEntriesForTenant reduces the fleet answer to one organization's view of it. Erasure rows survive
// only for the caller's own organization: whether THEIR data is gone is theirs to know, and whether anyone
// else exists is not.
func fleetConfigEntriesForTenant(entries []fleetConfigEntry, callerTenant string) []fleetConfigEntryForTenant {
	out := make([]fleetConfigEntryForTenant, 0, len(entries))
	for _, e := range entries {
		row := fleetConfigEntryForTenant{
			RegionID:    e.RegionID,
			HaveApplied: e.HaveApplied,
			ReportedAt:  e.ReportedAt,
			Status:      e.Status,
			// The name only. See the field's comment: the count is the node's, across every organization.
			RecoveryName: e.RecoveryName,
		}
		if callerTenant != "" {
			for _, er := range e.Erasures {
				if strings.EqualFold(strings.TrimSpace(er.TenantID), callerTenant) {
					row.Erasures = append(row.Erasures, er)
				}
			}
		}
		out = append(out, row)
	}
	return out
}

// fleetConfigStatusStore holds the last report from each Edge. Control-plane side only.
//
// restart-durability: ephemeral — every entry is re-reported by its Edge within one poll interval, so a
// control-plane restart costs one interval of blankness and nothing more. Deliberately NOT persisted: a view
// whose whole job is to say who is currently reachable must not answer from memory of a previous process. A
// remembered "region-b: current" surviving a restart would be the exact claim this store exists to stop being
// made without evidence.
//
// populated-by: assertion — each Edge POSTs its own status on EVERY config-bundle poll, applied or not, so the
// view re-converges on its own within one interval and an Edge that stops asserting simply leaves the fleet.
// Reporting only on change was considered and rejected: an Edge that reports nothing because nothing changed
// and one that reports nothing because it is gone would be indistinguishable, and membership is derived from
// exactly this stream.
//
// In-memory ON PURPOSE, and it is one of the few stores in this tree where that is right: every entry is
// re-reported within one poll interval, and a CP restart that showed a REMEMBERED fleet would be claiming
// knowledge it does not have. Losing it costs one interval of blankness, which is honest.
type fleetConfigStatusStore struct {
	mu      sync.RWMutex
	entries map[string]fleetConfigEntry // "region/cluster" -> latest
	// erasures remembers each node's LAST answer about each tenant erasure order, and is deliberately NOT
	// pruned by freshFor.
	//
	// ★ WHY IT OUTLIVES FLEET MEMBERSHIP (2026-08-15). Membership above is "whoever is reporting now", which
	// is right for configuration: instances come and go, and one that stopped reporting has overwhelmingly
	// been removed. It is WRONG for erasure. Measured on the lab: stopping region-b made it vanish from the
	// fleet within a poll, and the view answered in_sync=true — for erasure the same disappearance would have
	// read as "every node holds nothing", while a node that is merely powered off still has the customer's
	// logs on its disk and brings them back when it returns.
	//
	// So a node that once said "I still hold N" keeps saying it until it says otherwise. Absence is not
	// resolution, which is the same rule the config bundle applies to a missing tenant and the footprint
	// applies to a store it could not count.
	erasures map[string]map[string]fleetTenantErasureState // tenant_id -> node key -> last answer
	// authoritySince is when this process became the node reports arrive at. See cp_leader_election.go's
	// leaderSince: a store that has been listening for less than freshFor cannot tell a fleet of two from a
	// fleet of four whose other half has not had time to speak.
	//
	// Set once at construction for a node that is simply running (a single control plane has been the
	// authority for as long as it has existed), and moved forward on promotion.
	authoritySince time.Time
	// freshFor is how long a report keeps an instance in the fleet.
	//
	// ★ THE FLEET IS WHATEVER IS REPORTING NOW. Instances are created and destroyed continuously — autoscaling,
	// rolling deploys, a node draining — so an instance that stops reporting has, overwhelmingly, been REMOVED.
	// Keeping it and calling it a fault turns routine scale-in into an alarm, and stating "4 Edges, 2 behind"
	// asserts an expected count that nothing here knows.
	//
	// Generous enough that one missed poll never changes the picture (a blip must not make the number flicker),
	// short enough that the view is the CURRENT shape of the fleet rather than a memory of it.
	freshFor time.Duration
}

func newFleetConfigStatusStore(pollInterval time.Duration) *fleetConfigStatusStore {
	// Three missed reports: one is a network blip and must not change the count, three is gone.
	fresh := 3 * pollInterval
	if fresh < 30*time.Second {
		fresh = 30 * time.Second
	}
	return &fleetConfigStatusStore{
		entries:        map[string]fleetConfigEntry{},
		erasures:       map[string]map[string]fleetTenantErasureState{},
		freshFor:       fresh,
		authoritySince: time.Now().UTC(),
	}
}

// HasFormed reports whether this node has been receiving reports for long enough that the absence of a node
// means something.
//
// ★★★ THE ANSWER IS ABOUT THE DENOMINATOR, NOT THE NUMERATOR. Every reader of this view — is the fleet in
// sync, does the deployment sign under one authority, who depends on this deployment before I destroy it —
// divides by "the fleet". Fifteen seconds after a failover that denominator was two, on a fleet of four, and
// every one of those questions was answered confidently about the wrong set. Waiting freshFor is exactly the
// window the store already uses to decide that a silent node is gone; before it has elapsed, silence means
// nothing at all.
func (s *fleetConfigStatusStore) HasFormed(now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	since, fresh := s.authoritySince, s.freshFor
	s.mu.RUnlock()
	// ★ PROMOTION MOVES THE CLOCK, AND IT IS READ RATHER THAN PUSHED. A standby has been running for hours
	// while receiving nothing; its start time says it has been listening the whole time, which is exactly the
	// wrong answer the moment it takes over. Asking the elector means there is no second copy of this fact to
	// go stale, and no ordering requirement between two constructors in main.
	if promoted := cpLeaderElectorInstance.LeaderSince(); !promoted.IsZero() && promoted.After(since) {
		since = promoted.UTC()
	}
	return !now.UTC().Before(since.Add(fresh))
}

// fleetConfigKey identifies one INSTANCE. Every component matters: two Edges may share a region and a cluster
// and still be different processes that can hold different configuration.
func fleetConfigKey(region, cluster, node string) string {
	norm := func(v, fallback string) string {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			return fallback
		}
		return v
	}
	return norm(region, "unknown") + "/" + norm(cluster, "unknown") + "/" + norm(node, "unknown")
}

// Record stores one Edge's report.
func (s *fleetConfigStatusStore) Record(rep fleetConfigReport, now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fleetConfigKey(rep.RegionID, rep.ClusterID, rep.NodeID)
	s.entries[key] = fleetConfigEntry{
		fleetConfigReport: rep,
		ReportedAt:        now.UTC(),
	}
	for _, erasure := range rep.Erasures {
		tenantID := strings.TrimSpace(erasure.TenantID)
		if tenantID == "" {
			continue
		}
		if s.erasures[tenantID] == nil {
			s.erasures[tenantID] = map[string]fleetTenantErasureState{}
		}
		s.erasures[tenantID][key] = fleetTenantErasureState{
			NodeKey:    key,
			NodeID:     rep.NodeID,
			Clean:      erasure.Clean,
			Remaining:  erasure.Remaining,
			ReportedAt: now.UTC(),
		}
	}
}

// NodesInRegion counts the Edge nodes of one region that have reported WITHIN the freshness window.
//
// ★★★ THIS IS A DENOMINATOR, AND IT IS ONLY AS HONEST AS WHAT REPORTED. A node that has never spoken is not
// here at all — the count says "nodes that have reported recently", never "nodes that exist". A connector
// spreading over the fleet uses it to say how much of the fleet it covers, so an inflated or invented number
// would turn "you are only on half your fleet" into silence, which is the failure this count exists to make
// visible. Under-counting is safe (the connector simply stops looking sooner and says so); over-counting is
// not, so a node gone quiet drops out rather than being carried.
func (s *fleetConfigStatusStore) NodesInRegion(region string, now time.Time) int {
	if s == nil {
		return 0
	}
	region = strings.TrimSpace(region)
	if region == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	for _, entry := range s.entries {
		if !strings.EqualFold(strings.TrimSpace(entry.RegionID), region) {
			continue
		}
		if now.Sub(entry.ReportedAt) > s.freshFor {
			continue
		}
		node := strings.TrimSpace(entry.NodeID)
		if node == "" {
			continue
		}
		seen[node] = true
	}
	return len(seen)
}

// fleetTenantErasureState is one node's last answer about one erasure order, kept whether or not that node is
// still part of the fleet.
type fleetTenantErasureState struct {
	NodeKey    string    `json:"-"`
	NodeID     string    `json:"node_id"`
	Clean      bool      `json:"clean"`
	Remaining  int64     `json:"remaining"`
	ReportedAt time.Time `json:"reported_at"`
	// Stale reports that this node has not spoken within the fleet's freshness window. Its answer still counts
	// — a node that held data and went quiet has not stopped holding it.
	Stale bool `json:"stale"`
}

// TenantErasure returns every node's last answer for one tenant, and whether the erasure is COMPLETE across
// the fleet. Complete requires every node that has ever answered to say clean; a node that answered "not
// clean" and then went silent keeps the erasure incomplete, and says so with stale=true.
func (s *fleetConfigStatusStore) TenantErasure(tenantID string, now time.Time) ([]fleetTenantErasureState, bool) {
	out := []fleetTenantErasureState{}
	if s == nil {
		return out, false
	}
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, state := range s.erasures[tenantID] {
		state.Stale = now.Sub(state.ReportedAt) > s.freshFor
		out = append(out, state)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeKey < out[j].NodeKey })
	if len(out) == 0 {
		return out, false // nobody has answered: not evidence of anything, least of all completion
	}
	for _, state := range out {
		if !state.Clean {
			return out, false
		}
	}
	return out, true
}

// List returns every known Edge with its status judged against the control plane's CURRENT generation.
//
// Sorted by key so the Console renders a stable list — a table whose rows reorder on refresh is a table nobody
// reads carefully.
func (s *fleetConfigStatusStore) List(cpGeneration uint64, cpEpoch string, now time.Time) []fleetConfigEntry {
	if s == nil {
		return []fleetConfigEntry{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]fleetConfigEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if now.Sub(e.ReportedAt) > s.freshFor {
			continue // no longer part of the fleet — see freshFor
		}
		e.Status = fleetConfigEntryStatus(e, cpGeneration, cpEpoch)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return fleetConfigKey(out[i].RegionID, out[i].ClusterID, out[i].NodeID) <
			fleetConfigKey(out[j].RegionID, out[j].ClusterID, out[j].NodeID)
	})
	return out
}

// fleetConfigEntryStatus judges one entry that IS in the fleet. Only about configuration: whether the instance
// is still present is answered by whether it is in the list at all.
func fleetConfigEntryStatus(e fleetConfigEntry, cpGeneration uint64, cpEpoch string) string {
	if !e.HaveApplied {
		return "never_applied"
	}
	if strings.TrimSpace(e.LastError) != "" {
		return "error"
	}
	// A different epoch means the CP restarted since this report; the generation numbers are not comparable, so
	// claiming "current" would be a guess. Treated as lagging until the Edge reports against the new epoch.
	if cpEpoch != "" && e.Epoch != "" && e.Epoch != cpEpoch {
		return "lagging"
	}
	if e.Generation < cpGeneration {
		return "lagging"
	}
	return "current"
}

// fleetInSync answers "does the whole fleet hold the current configuration?".
//
// ★ ONE definition, called by the handler and asserted by the tests. It was written twice first — the handler
// computed it inline and the test re-implemented the same loop — and a mutation that made the empty fleet
// report in_sync passed, because the test never executed the handler's copy. A duplicated rule is an untested
// rule wearing a test's clothes.
//
// An EMPTY fleet is not agreement. "Nobody has reported" and "everybody agrees" render the same green banner
// unless the zero case is decided on purpose, and reading absence as success is the shape of this entire
// incident.
func fleetInSync(edges []fleetConfigEntry) bool {
	if len(edges) == 0 {
		return false
	}
	for _, e := range edges {
		if e.Status != "current" {
			return false
		}
	}
	return true
}

// registerFleetConfigStatusRoutes wires the CP-side ingest + read. Only meaningful on a control plane; an Edge
// with no store simply does not register them.
func registerFleetConfigStatusRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, store *fleetConfigStatusStore, currentGeneration func() (uint64, string)) {
	if store == nil {
		return
	}
	// The Edges POST here with the same bearer they already use to PULL the bundle. No new credential: an
	// identity that may read the fleet's entire configuration is not meaningfully constrained by also being
	// allowed to say which generation of it it holds.
	// control-plane-only: the fleet surface exists only where the fleet is aggregated (measured: an Edge answers 404)
	mux.HandleFunc("POST /admin/fleet/config-status", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		var rep fleetConfigReport
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&rep); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("malformed fleet config report: %w", err))
			return
		}
		if strings.TrimSpace(rep.RegionID) == "" && strings.TrimSpace(rep.ClusterID) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("a fleet config report must identify its edge (region_id / cluster_id)"))
			return
		}
		now := time.Now().UTC()
		store.Record(rep, now)
		// ★ ANSWER WITH THE REPORTER'S OWN DENOMINATOR. The Edges cannot see each other — they push here and
		// the aggregation lives here — so this reply is the only place a node can learn how many siblings its
		// region has. It is what a connector needs before it can say whether it covers the fleet or merely
		// sits on one member of it. Said as "have reported", because that is what is known.
		writeJSON(w, http.StatusOK, map[string]any{
			"region_id":    rep.RegionID,
			"region_nodes": store.NodesInRegion(rep.RegionID, now),
			"note": "region_nodes counts the Edge nodes of this region that have REPORTED within the fleet's " +
				"freshness window. A node that has never reported is not counted, so this is a floor, not a census.",
		})
	}))

	mux.HandleFunc("GET /admin/fleet/config-status", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		gen, epoch := uint64(0), ""
		if currentGeneration != nil {
			gen, epoch = currentGeneration()
		}
		now := time.Now().UTC()
		edges := store.List(gen, epoch, now)
		// ★ A VIEW THAT HAS NOT FORMED IS NOT A FLEET THAT AGREES. See HasFormed: within freshFor of becoming
		// the authority, the nodes that have not reported are indistinguishable from nodes that are gone.
		formed := store.HasFormed(now)
		inSync := formed && fleetInSync(edges)
		// ★ admin.policy.read IS HELD BY EVERY TENANT ADMINISTRATOR, AND THIS ANSWER IS THE DEPLOYMENT'S
		// (2026-08-16, found by signing in as a customer and reading the dashboard the customer sees). The
		// route beside this one is gated on admin.tenant.admin; this one was not, and it returned the whole
		// operator inventory: every node's id and cluster, the control plane's generation and epoch, each
		// node's total rule count across all tenants — and, worst, the erasure ledger, which NAMES EVERY
		// TENANT the deployment has ever been told to erase. Measured signed in as Northwind's administrator,
		// a principal with no cross-tenant permission at all: thirteen other organizations by id.
		//
		// A customer's question here is "is MY configuration in effect where I am served", so that is what a
		// customer is told. The node inventory is the operator's and stays the operator's.
		if tenant, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			writeJSON(w, http.StatusOK, map[string]any{
				"edges":   fleetConfigEntriesForTenant(edges, tenant),
				"in_sync": inSync,
				// Said to a customer too: "my configuration is in effect everywhere" must not be answered
				// from a list that is still assembling.
				"fleet_view_formed": formed,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"control_plane_generation": gen,
			"control_plane_epoch":      epoch,
			"edges":                    edges,
			"in_sync":                  inSync,
			// ★ THE DENOMINATOR, SAID OUT LOUD. Every reader that divides by "the fleet" has to be able to
			// tell "this is everybody" from "this is everybody who has reached me since I took over".
			"fleet_view_formed": formed,
		})
	}))

	// Is a tenant's erasure complete ACROSS THE FLEET? A tenant's logs sit on the disk of every node that
	// served it, so no single node can answer this and the fleet list above cannot either: membership there is
	// "whoever is reporting now", and a node that is merely powered off drops out. Measured on the lab —
	// stopping an Edge removed it from the fleet within one poll and in_sync went on saying true.
	//
	// So this reads the remembered answers instead: every node that has EVER answered about this tenant, with
	// its last answer, marked stale when it has gone quiet. complete=true needs all of them clean. A node that
	// said it still held data and then went silent keeps the erasure incomplete, because a machine that is off
	// has not stopped holding what is on its disk.
	mux.HandleFunc("GET /admin/fleet/tenant-erasure/{tenant_id}", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
		if tenantID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant_id is required"))
			return
		}
		// ★★★ Which nodes still hold an organization's data is that organization's business, or the
		// operator's. See an_organizations_life_is_not_a_customers_to_end.go.
		if !adminTenantPathReadAllowed(w, r, tenantID, "reading the erasure progress of") {
			return
		}
		nodes, complete := store.TenantErasure(tenantID, time.Now().UTC())
		stale := 0
		for _, n := range nodes {
			if n.Stale {
				stale++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": tenantID,
			"nodes":     nodes,
			"complete":  complete,
			// Said out loud rather than left to be inferred from an empty list, which is how "nobody answered"
			// gets read as "everybody is clean".
			"coverage": fmt.Sprintf("%d node(s) have answered about this tenant; %d of them have gone quiet and "+
				"their last answer still counts. A node that never answered is not represented here at all.",
				len(nodes), stale),
		})
	}))
}

// fleetConfigReporter is the Edge half: it tells the control plane what it is running.
type fleetConfigReporter struct {
	url       string
	token     string
	client    *http.Client
	regionID  string
	clusterID string
	nodeID    string
	machine   string
	address   string
}

// report ships one status. Best-effort by design — a fleet-visibility report must never be able to interfere
// with the config sync it is reporting on. The failure is logged at most once per interval by the caller.
func (f *fleetConfigReporter) report(ctx context.Context, rep fleetConfigReport) error {
	if f == nil || strings.TrimSpace(f.url) == "" {
		return nil
	}
	rep.RegionID, rep.ClusterID, rep.NodeID = f.regionID, f.clusterID, f.nodeID
	rep.Machine, rep.MachineAddress = f.machine, f.address
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	// ★★★ REPORTING FOLLOWS LEADERSHIP TOO (2026-08-25, measured while reproducing an admin lockout). The
	// config PULL was given the per-region selector today and moves when leadership does; this was left on
	// the fixed address, which is the region's own internal control-plane door. After a failover that door
	// has no healthy backend, so every Edge in the region that lost its control planes goes on serving
	// perfectly well and disappears from the fleet view — logging, once per poll, the very sentence the
	// message itself contains: "the fleet view will show it as silent".
	//
	//	config-bundle sync: applied generation 75 from the control plane      <- the pull moved
	//	could not report ... Post "https://dsse-control-plane:9443/..." EOF   <- the report did not
	//
	// A node that is healthy and invisible is the state this whole view exists to end.
	base := strings.TrimRight(f.url, "/")
	if current := controlChannelCurrentBaseURL(); current != "" {
		base = strings.TrimRight(current, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/admin/fleet/config-status", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("content-type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("control plane refused the fleet config report: HTTP %d", resp.StatusCode)
	}
	// The reply carries this region's node count — the one fact a node cannot work out for itself, since the
	// Edges never see each other. A control plane too old to send it leaves the count unknown, and everything
	// downstream must treat unknown as unknown rather than as zero.
	var answer struct {
		RegionNodes int `json:"region_nodes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 8<<10)).Decode(&answer); err == nil && answer.RegionNodes > 0 {
		setEdgeRegionNodeCount(answer.RegionNodes)
	}
	return nil
}

// edgeRegionNodeCount is how many Edge nodes of THIS region have reported to the control plane recently, as
// last told to this node. Zero means "not known yet" — never "none": this node is itself one of them.
var edgeRegionNodeCount atomic.Int64

func setEdgeRegionNodeCount(n int) { edgeRegionNodeCount.Store(int64(n)) }

// currentEdgeRegionNodeCount is the last count the control plane gave this node, or 0 for not known.
func currentEdgeRegionNodeCount() int { return int(edgeRegionNodeCount.Load()) }

// edgeNodeIdentity names THIS process among the Edges that share its region and cluster.
//
// ★ The hostname, because it is already unique per container, pod and host, and because requiring a flag would
// mean the view is only correct where somebody remembered to set one — which is the same as being wrong, since
// the deployments most likely to forget are the large ones this distinguishes. A deployment that wants a
// stable name across restarts can set -edge-cluster-id per instance; the pair is what keys the view.
func edgeNodeIdentity() string {
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSpace(h)
	}
	// No hostname is not an error worth failing a boot over, but it MUST NOT collide with a sibling: an
	// "unknown" shared by two instances is the collision this identity exists to remove.
	return fmt.Sprintf("pid-%d", os.Getpid())
}
