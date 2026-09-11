package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/seatallocation"
)

// The completion definition of "create an organization", answered for one organization in one call.
//
// ★ A REGISTRY ROW IS THE ENTRANCE, NOT THE FINISH (the provisioning design). An organization can exist
// in every list, be selectable in every menu, and enforce nothing — that is the state the whole review exists
// to end, and until now the only way to find out was to call twelve routes and know what each answer meant.
// Twelve routes also means twelve chances to answer the boundary question differently, which is the defect
// family this repository keeps paying for.
//
// ★ WHAT EACH ENTRY CARRIES, AND WHY. A checklist that only says done/not-done tells an operator that
// something is missing and not what they lose by leaving it, so it gets ignored in exactly the order that
// matters least. Each entry therefore says what the feature LETS YOU DO ("enables"), and names the route that
// sets it ("action") so a screen can offer the setting rather than describing it — a screen that can only
// describe is one somebody has to leave to get anything done.
type organizationSetupItem struct {
	Key string `json:"key"`
	// Label is in an operator's vocabulary, not the implementation's. "Device identity", not "tenant CA".
	Label string `json:"label"`
	// Enables is the capability this unlocks, stated plainly.
	Enables string `json:"enables"`
	// State is one of: done, missing, not_here.
	//
	// ★ not_here IS THE ONE THAT HAD TO EXIST (2026-08-16, found by asking both planes). The first version had
	// "unavailable", meaning the deployment does not offer this setting — and a node cannot know that. It only
	// knows whether IT holds the store. Asked on the control plane the answer said device identity was
	// unavailable AND blocking, while the Edge one desk away answered "1 certificate authority, expires in
	// 1812 days" for the same organization. Two planes, contradictory answers, and a screen built on either
	// would have been confidently wrong.
	//
	// So: not_here means THIS node cannot answer, Owner says which plane can, and it is never blocking —
	// a node must not report an organization as broken on the strength of a question it cannot see.
	State string `json:"state"`
	// Owner names the plane that holds this fact, so a screen knows where to ask rather than guessing from
	// whichever node it happened to reach.
	Owner string `json:"owner"`
	// Detail is the measured fact behind the state, short enough to sit in a row.
	Detail string `json:"detail"`
	// Blocking marks the items without which the organization does not actually work. The others are real
	// settings with real consequences; these are the ones that mean "created, and nothing happens".
	Blocking bool `json:"blocking"`
	// Action is what a screen calls to set this. Empty when the setting is not made through the admin API.
	Action *organizationSetupAction `json:"action,omitempty"`
	// Values are the measured numbers and names behind Detail, so a screen can compose the sentence in its
	// own language instead of printing this one.
	//
	// ★ Detail STAYS, AND IS ENGLISH ON PURPOSE. It is what a non-Console consumer reads, and a screen with no
	// template for a newly added item falls back to it — a checklist that silently omits an item the server
	// added is the failure this surface exists to prevent, and it would look identical to an organization with
	// nothing left to do.
	Values map[string]any `json:"values,omitempty"`
}

type organizationSetupAction struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// Verb is the button, in the operator's words.
	Verb string `json:"verb"`
}

const (
	organizationSetupDone    = "done"
	organizationSetupMissing = "missing"
	organizationSetupNotHere = "not_here"
)

// Which plane holds each fact. An organization's setup is a FLEET property assembled from both.
const (
	organizationSetupOwnerControlPlane = "control_plane"
	organizationSetupOwnerEdge         = "enforcement_edge"
	organizationSetupOwnerEither       = "either"
)

// organizationSetupSources is everything the answer is measured from. Passed as one struct so the route and
// its test look at the same surface, and so a source that is absent reads as absent rather than as a nil
// dereference at request time.
type organizationSetupSources struct {
	Tenant       adminTenantModel
	TenantExists bool
	Evaluator    decision.Evaluator
	Config       serverConfig
	IDPs         *idpregistry.Store
	Domains      *organizationDomainsStore
	Seats        *seatallocation.Store
	Entitlements organizationSetupEntitlements
	// EnforcementEdge is true when this node PULLS its configuration, which is what makes it an enforcement
	// Edge rather than the control plane.
	//
	// ★ HOLDING A STORE IS NOT OWNING THE FACT (2026-08-16). The Edge has a local admin-credential store, so
	// it answered "no administrator — every change has to go through the operator" for an organization with
	// twenty-three of them on the control plane. An empty store on the wrong plane reads exactly like an
	// organization that has not been set up, and the two answers together were contradictory rather than
	// complementary.
	EnforcementEdge bool
	// Policies answers per ORGANIZATION. Nil means this node cannot break the count down that way, which is
	// reported as none rather than as the node's own total.
	Policies policySnapshotReader
	Now      time.Time
}

// policySnapshotReader is the narrow read this needs: one organization's rules.
type policySnapshotReader interface {
	Snapshot(tenantID string) []model.Policy
}

// organizationSetupEntitlements is the narrow read this needs. Named for its caller rather than reusing the
// egress hook's entitlementReader, which asks a different question (is ONE feature entitled) — sharing a name
// for two shapes is how the wrong one gets passed.
type organizationSetupEntitlements interface {
	FeaturesForTenant(tenantID string) map[string]bool
}

// organizationSetupReport measures every item for one organization.
func organizationSetupReport(sources organizationSetupSources) []organizationSetupItem {
	tenant := sources.Tenant
	tenantID := strings.TrimSpace(tenant.TenantID)
	items := []organizationSetupItem{}
	// add records the item, and OVERRIDES it when this node is not the plane that owns the fact. A node
	// answers for what it is authoritative about; for the rest it says where to ask. That makes the two
	// planes' answers complementary — each covering the half it owns — instead of two partial pictures a
	// reader has to know not to trust.
	add := func(item organizationSetupItem) {
		thisPlane := organizationSetupOwnerControlPlane
		if sources.EnforcementEdge {
			thisPlane = organizationSetupOwnerEdge
		}
		if item.Owner != organizationSetupOwnerEither && item.Owner != thisPlane {
			item.State = organizationSetupNotHere
			item.Detail = "held on the " + strings.ReplaceAll(item.Owner, "_", " ")
			item.Action = nil
		}
		items = append(items, item)
	}

	state := func(done bool, whenDone, whenMissing string) (string, string) {
		if done {
			return organizationSetupDone, whenDone
		}
		return organizationSetupMissing, whenMissing
	}

	// 1. The registry row itself.
	s, d := state(sources.TenantExists, "registered on this control plane", "not registered")
	add(organizationSetupItem{Key: "registry", Owner: organizationSetupOwnerControlPlane, Label: "Organization record", State: s, Detail: d, Blocking: true,
		Enables: "everything else — until this exists there is nothing to configure",
		Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/tenants", Verb: "Create"}})

	// 2. Display name and timezone.
	named := strings.TrimSpace(tenant.DisplayName) != "" && !strings.EqualFold(tenant.DisplayName, tenantID)
	detail := "no name of its own — screens and reports show the identifier"
	if named {
		detail = tenant.DisplayName
		if zone := strings.TrimSpace(tenant.Timezone); zone != "" {
			detail += " (" + zone + ")"
		} else {
			detail += " (times shown in UTC)"
		}
	}
	s, _ = state(named, detail, detail)
	add(organizationSetupItem{Key: "identity", Owner: organizationSetupOwnerControlPlane, Label: "Name and time zone", State: s, Detail: detail,
		Values:  map[string]any{"name": tenant.DisplayName, "timezone": tenant.Timezone},
		Enables: "reports and log timestamps read in this organization's own working day",
		Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/tenant", Verb: "Set"}})

	// 3. Device identity — the CA their endpoints are admitted by.
	deviceCAs, soonestDays := 0, -1
	soonest := ""
	if sources.Config.TenantCARegistry != nil {
		for _, fact := range sources.Config.TenantCARegistry.Facts(sources.Now) {
			if !strings.EqualFold(fact.TenantID, tenantID) {
				continue
			}
			deviceCAs++
			// A NUMBER, not a phrase. The first version put "expires in N days" in Values, and a screen
			// composing its own sentence then had an English fragment inside it — half-translated is worse than
			// either, because it reads as a bug in the product rather than a gap in the wording.
			if soonestDays < 0 {
				soonestDays = fact.DaysLeft
				soonest = fmt.Sprintf("expires in %d days", fact.DaysLeft)
			}
		}
	}
	switch {
	case sources.Config.TenantCARegistry == nil:
		add(organizationSetupItem{Key: "device_identity", Owner: organizationSetupOwnerEdge, Label: "Device identity", State: organizationSetupNotHere,
			Detail: "not held on this node — ask an enforcement Edge", Blocking: true,
			Enables: "this organization's endpoints are admitted as theirs, and nobody else's"})
	default:
		s, d = state(deviceCAs > 0, fmt.Sprintf("%d certificate authority(ies), soonest %s", deviceCAs, soonest),
			"no certificate authority — this organization's devices cannot be admitted")
		add(organizationSetupItem{Key: "device_identity", Owner: organizationSetupOwnerEdge, Label: "Device identity", State: s, Detail: d, Blocking: true,
			Values:  map[string]any{"count": deviceCAs, "soonest": soonest},
			Enables: "this organization's endpoints are admitted as theirs, and nobody else's",
			Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/tenant-cas", Verb: "Register a CA"}})
	}

	// 4. Inspection authority — what signs their intercepted traffic.
	switch {
	case sources.Config.NetworkExtensionLabTLS == nil:
		// ★★★ NOT BLOCKING MEANT NOTHING TO ANSWER, AND SETUP SAID DONE (2026-08-26, reported by win-dev-1
		// in letter 105 from the deployment this installer generates). Device identity three cases above
		// marks its own not_here as blocking, so the summary counts it as UNSEEN and refuses to call the
		// organization operational on a question it cannot see. This one did not, so the item simply
		// evaporated: "done: 4/13, blocking: []" on a deployment where nothing has ever inspected anything.
		//
		// Blocking here does not assert that a deployment must inspect. It asserts that a node which cannot
		// see the answer must not supply one — the summary's third value exists precisely so "I cannot see
		// this" is neither "fine" nor "broken".
		add(organizationSetupItem{Key: "inspection_authority", Owner: organizationSetupOwnerEdge, Label: "Traffic inspection authority",
			State: organizationSetupNotHere, Detail: "not held on this node — ask an enforcement Edge", Blocking: true,
			Enables: "their traffic is inspected under an authority that is theirs, not the deployment's"})
	default:
		own := ""
		for _, issuer := range sources.Config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
			if strings.EqualFold(strings.TrimSpace(issuer.Tenant), tenantID) {
				own = issuer.RootCommonName
			}
		}
		if reason, revoked := sources.Config.NetworkExtensionLabTLS.TenantInterceptionRevoked(tenantID); revoked {
			add(organizationSetupItem{Key: "inspection_authority", Owner: organizationSetupOwnerEdge, Label: "Traffic inspection authority",
				State: organizationSetupMissing, Blocking: true,
				Detail:  "revoked here (" + reason + ") — their traffic is not being inspected at all",
				Enables: "their traffic is inspected under an authority that is theirs, not the deployment's",
				Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/interception-intermediate/{tenant}", Verb: "Load a replacement"}})
			break
		}
		// ★ THE SENTENCE WAS FIXED TEXT AND THE NODE HAD MOVED ON (2026-08-18, measured). It read "signed by
		// the deployment's own authority, not this organization's", which was true when one shared intermediate
		// signed everybody. Once ANY organization has its own offline issuer the node switches to
		// per_tenant_offline_intermediate, and from then on an organization WITHOUT one is REFUSED — its
		// traffic is not signed under somebody else's CA, it is not inspected at all.
		//
		// Those are different situations for the person reading. "Somebody else's authority signs your
		// traffic" is a privacy statement they may accept; "your traffic is not being inspected" is an
		// enforcement gap, and it BLOCKS.
		scope := sources.Config.NetworkExtensionLabTLS.InterceptionRootScope()
		refusedWithoutOwn := scope.PerTenantSigning && own == ""
		detailWithoutOwn := "signed by the deployment's own authority, not this organization's"
		blocking := false
		if refusedWithoutOwn {
			detailWithoutOwn = "no authority of their own, and this node signs per organization — their traffic is REFUSED rather than inspected"
			blocking = true
		}
		s, d = state(own != "", own, detailWithoutOwn)
		add(organizationSetupItem{Key: "inspection_authority", Owner: organizationSetupOwnerEdge, Label: "Traffic inspection authority",
			State: s, Detail: d, Blocking: blocking && own == "",
			Values:  map[string]any{"root": own, "signing_scope": scope.Effective},
			Enables: "their traffic is inspected under an authority that is theirs, not the deployment's",
			Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/interception-intermediate/{tenant}", Verb: "Load an issuing CA"}})
	}

	// 5. Policy — the rules that actually get enforced FOR THIS ORGANIZATION.
	//
	// ★ IT COUNTED THE NODE'S (2026-08-16, seen the moment the wizard created its first organization). The
	// first version walked evaluator.PolicyBundle.PolicyIDs, which is whatever the node is enforcing in
	// total — so a brand-new organization with no rules at all reported "9 rules distributed" and the
	// checklist ticked the one item that decides whether anything is enforced for them. A count that is
	// right for the deployment and wrong for the organization is worse than no count: it is a green tick on
	// the question being asked.
	//
	// ★★★ AND ONLY THE EDGE CAN ANSWER IT (2026-09-05, seen on a deployment stood up from the published tree,
	// with an organization created exactly as the wizard creates one). Owner was "either", so whichever plane
	// the screen happened to ask answered — and the CONTROL PLANE holds no evaluator for a customer
	// organization, because it decides nothing. It answered 0, and the checklist told the operator, in a
	// BLOCKING row:
	//
	//	Access rules   Not set   no rules — nothing is enforced for them
	//
	// while the organization's own Internet Access screen, two clicks away, showed the starting rule as
	// Active — and the EDGE, which is the thing that decides, held it as one effective policy. The
	// organization was working and read as permanently unfinished.
	//
	// The other facts the Edge holds — device identity, the inspection authority, the joining token — are
	// already marked as the Edge's, so the control plane says "held on the enforcement edge" and does not
	// score them. This is the same kind of fact and was the only one not marked.
	policies := 0
	if sources.Policies != nil {
		policies = len(sources.Policies.Snapshot(tenantID))
	}
	s, d = state(policies > 0, fmt.Sprintf("%d rule(s) distributed", policies), "no rules — nothing is enforced for them")
	add(organizationSetupItem{Key: "policy", Owner: organizationSetupOwnerEdge, Label: "Access rules", State: s, Detail: d, Blocking: true,
		Values:  map[string]any{"count": policies},
		Enables: "what this organization's people and devices may reach",
		Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/policies", Verb: "Add a rule"}})

	// 6. Their first administrator.
	admins := 0
	if sources.Config.LocalCredentials != nil {
		admins = len(sources.Config.LocalCredentials.List(tenantID))
	}
	s, d = state(admins > 0, fmt.Sprintf("%d administrator(s)", admins),
		"nobody in this organization can administer it — every change has to go through the operator")
	// ★★★ AND AN ORGANIZATION THE OPERATOR RUNS IS ADMINISTERED (2026-09-03, the operator's report that the
	// Console did not match reality). This was Blocking unconditionally, so an organization under a standing
	// delegation — which is how every organization in a managed deployment is run — was badged "not working
	// yet" for the whole of its life. The one measured this way had enrolled a device, was inspecting its
	// traffic under its own authority and had completed an out-of-band step-up that day. It was working.
	//
	// Having an administrator of their OWN is still the thing this item is for: it is what lets the
	// organization stop asking the operator for every change, which is why it stays on the list and says so.
	// It just does not decide whether anything works, when somebody is already running it.
	adminBlocks := true
	if tenant.OperatorManaged {
		adminBlocks = false
		if admins == 0 {
			d = "nobody inside this organization can administer it yet — the operator runs it under a " +
				"standing delegation, so it works; this is what would let them run it themselves"
		}
	}
	add(organizationSetupItem{Key: "administrator", Owner: organizationSetupOwnerControlPlane, Label: "Their administrator", State: s, Detail: d, Blocking: adminBlocks,
		Values:  map[string]any{"count": admins},
		Enables: "the organization runs itself instead of asking the operator for every change",
		Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/admins/invite", Verb: "Invite"}})

	// 7. Device allowance.
	//
	// ★★ OWNED BY THE PLANE THAT ENFORCES IT (2026-08-17, measured end to end on the lab). This item declared
	// the control plane as its owner, so an Edge answered "not here — held on the control plane" for a number
	// it holds, divides and enforces itself, and the control plane answered "no allowance" because nothing
	// ever writes allocations there. Result: 25 seats allocated through the Console, shown as 25 on the
	// licensing screen, and reported as MISSING on the organization's setup checklist forever — one screen
	// contradicting another about a change the operator had just made.
	//
	// The seat pool is the licence's, the licence is applied to the enforcing Edge, the allocations divide it
	// there, and POST /enroll consults that same store. Declaring another plane the owner of a fact it neither
	// holds nor enforces is how the two answers came apart. A plane with no pool at all still says so through
	// the nil branch below.
	//
	// If licensing ever moves to the control plane — pool held there, distributed like the config bundle — this
	// declaration moves with it, and the checklist will be the first thing to say so.
	switch {
	case sources.Seats == nil:
		add(organizationSetupItem{Key: "seats", Owner: organizationSetupOwnerEdge, Label: "Device allowance", State: organizationSetupNotHere,
			Detail:  "this deployment has no licence pool to allocate from",
			Enables: "a ceiling on how many devices this organization may enrol"})
	default:
		allocated := 0
		for _, allocation := range sources.Seats.List() {
			if strings.EqualFold(strings.TrimSpace(allocation.TenantID), tenantID) {
				allocated += allocation.Seats
			}
		}
		s, d = state(allocated > 0, fmt.Sprintf("%d device(s)", allocated), "no allowance — enrolment is ungated for them")
		add(organizationSetupItem{Key: "seats", Owner: organizationSetupOwnerEdge, Label: "Device allowance", State: s, Detail: d,
			Values:  map[string]any{"seats": allocated},
			Enables: "a ceiling on how many devices this organization may enrol",
			Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/seat-allocations", Verb: "Allocate"}})
	}

	// 8. Paid features.
	features := []string{}
	if sources.Entitlements != nil {
		for feature, granted := range sources.Entitlements.FeaturesForTenant(tenantID) {
			if granted {
				features = append(features, feature)
			}
		}
		sort.Strings(features)
	}
	s, d = state(len(features) > 0, strings.Join(features, ", "), "none granted")
	add(organizationSetupItem{Key: "features", Owner: organizationSetupOwnerEither, Label: "Paid features", State: s, Detail: d,
		Values:  map[string]any{"features": features},
		Enables: "the optional capabilities this organization has bought",
		Action:  &organizationSetupAction{Method: http.MethodPut, Path: "/admin/entitlements", Verb: "Grant"}})

	// 9. How their devices join.
	tokens := 0
	if sources.Config.EnrolmentTokens != nil {
		tokens = len(sources.Config.EnrolmentTokens.List(tenantID))
	}
	s, d = state(tokens > 0, fmt.Sprintf("%d outstanding", tokens), "none — no new device can join")
	add(organizationSetupItem{Key: "enrolment", Owner: organizationSetupOwnerEdge, Label: "Joining token", State: s, Detail: d,
		Values:  map[string]any{"count": tokens},
		Enables: "a new endpoint can enrol into this organization",
		Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/enrolment-tokens", Verb: "Issue"}})

	// 10. How their people sign in.
	idps := 0
	if sources.IDPs != nil {
		idps = len(sources.IDPs.List(tenantID))
	}
	s, d = state(idps > 0, fmt.Sprintf("%d identity provider(s)", idps),
		"none — their people have no way to sign in")
	add(organizationSetupItem{Key: "idp", Owner: organizationSetupOwnerEdge, Label: "Sign-in", State: s, Detail: d,
		Values:  map[string]any{"count": idps},
		Enables: "their people sign in with the accounts they already have",
		Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/idp-connections", Verb: "Connect"}})

	// 11. Which email domains are theirs.
	domains := []string{}
	if sources.Domains != nil {
		domains = sources.Domains.Domains(tenantID)
	}
	s, d = state(len(domains) > 0, strings.Join(domains, ", "), "none — sign-ins cannot be attributed by address")
	add(organizationSetupItem{Key: "domains", Owner: organizationSetupOwnerEdge, Label: "Their email domains", State: s, Detail: d,
		Values:  map[string]any{"domains": domains},
		Enables: "a person signing in is recognised as belonging to this organization",
		Action:  &organizationSetupAction{Method: http.MethodPut, Path: "/admin/organization-domains", Verb: "Set"}})

	// 12. Where their data may live.
	regions := strings.TrimSpace(strings.Join(tenant.AllowedRegions, ", "))
	home := strings.TrimSpace(tenant.HomeRegion)
	placed := regions != "" || home != ""
	d = "unpinned — they may be served from any region"
	if placed {
		d = strings.TrimSpace(home + " (" + regions + ")")
		if regions == "" {
			d = home
		}
	}
	// ★★ data_residency IS RECORDED AND ENFORCES NOTHING (2026-08-19, swept the tenant model for fields that
	// are stored and never read). It is accepted on the tenant record, normalised, persisted in its own
	// Postgres column and reported in the deletion footprint — and no code anywhere consults it. What actually
	// decides where an organization is served is home_region and allowed_regions, which the region-endpoint
	// route and the application router both read.
	//
	// A field that changes nothing is worse than a field that does not exist, and this one is worse still,
	// because its NAME is a compliance promise. Whether to reject writes to it is a contract decision; saying
	// so on the screen where somebody asks "where does my data live" is not, so that is what happens here.
	residency := strings.TrimSpace(tenant.DataResidency)
	s, _ = state(placed, d, d)
	values := map[string]any{"home": home, "allowed": tenant.AllowedRegions}
	if residency != "" {
		values["data_residency_recorded"] = residency
		values["data_residency_enforced"] = false
		d += " — data_residency is recorded as " + strconv.Quote(residency) + " and enforces nothing; the " +
			"regions above are what decides where they are served"
	}
	add(organizationSetupItem{Key: "regions", Owner: organizationSetupOwnerControlPlane, Label: "Where they are served", State: s, Detail: d,
		Values:  values,
		Enables: "their traffic and data stay inside the regions they agreed to",
		Action:  &organizationSetupAction{Method: http.MethodPost, Path: "/admin/tenants", Verb: "Set regions"}})

	// 13. Who runs it. Not in the original twelve because the answer did not exist until the envelope design.
	s, d = state(tenant.OperatorManaged, "the operator runs it under a standing delegation",
		"the organization runs itself — the operator cannot make changes inside it")
	add(organizationSetupItem{Key: "delegation", Owner: organizationSetupOwnerControlPlane, Label: "Who runs it", State: s, Detail: d,
		Enables: "the operator does this organization's day-to-day work on its behalf",
		Action:  &organizationSetupAction{Method: http.MethodPut, Path: "/admin/operator-delegation", Verb: "Change"}})

	return items
}

// registerOrganizationSetupRoute answers the completion definition for one organization.
func registerOrganizationSetupRoute(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	config serverConfig, evaluator decision.Evaluator, tenantModelStore adminTenantModelRuntimeStore,
	idps *idpregistry.Store, domains *organizationDomainsStore, seats *seatallocation.Store,
	entitlements organizationSetupEntitlements, policies policySnapshotReader) {

	mux.HandleFunc("GET /admin/organization-setup", adminEndpoint("admin.tenant.read|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		target := strings.TrimSpace(adminTenantIDFromRequest(r))
		if target == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this request names no organization"))
			return
		}
		if err := adminTenantPKITargetAllowed(r, target, "reading the setup state of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		tenant, exists := organizationSetupTenant(r.Context(), tenantModelStore, target)
		items := organizationSetupReport(organizationSetupSources{
			Tenant: tenant, TenantExists: exists, Evaluator: evaluator, Config: config,
			IDPs: idps, Domains: domains, Seats: seats, Entitlements: entitlements,
			EnforcementEdge: strings.TrimSpace(config.ConfigSourceURL) != "",
			Policies:        policies,
			Now:             time.Now(),
		})
		done, blocking, unseen := 0, []string{}, []string{}
		for _, item := range items {
			if item.State == organizationSetupDone {
				done++
			}
			if !item.Blocking {
				continue
			}
			switch item.State {
			case organizationSetupMissing:
				blocking = append(blocking, item.Label)
			case organizationSetupNotHere:
				// A node must not report an organization as broken on the strength of a question it cannot
				// see — nor as WORKING. Counted separately so the summary can say "unknown" rather than
				// pick one of the two wrong answers.
				unseen = append(unseen, item.Label)
			}
		}
		// ★ WHERE IT WAS MEASURED, ALWAYS. The two planes answered differently for the SAME organization —
		// device identity "done, expires in 1812 days" on the Edge and "not held here" on the control plane,
		// joining tokens 33 and 0 — because each holds a different half. An answer that does not say which
		// node produced it invites the reader to treat one half as the whole, and this codebase has spent
		// several days on exactly that mistake in other surfaces.
		//
		// ★★★ AND IT NAMES THE MACHINE THE OPERATOR KNOWS (2026-09-05, read on the Console of a deployment
		// whose one machine is called node-singapore, in a region called singapore). This said
		// "local/local-edge-001" — an Edge region and cluster id that a CONTROL PLANE does not have, so both
		// fell to their defaults. Neither string appears anywhere else in the deployment: not in the plan,
		// not on the machines list, not on any other screen. A provenance line exists to let a reader go and
		// ask that node, and one naming a node that does not appear anywhere cannot be acted on.
		//
		// The machine's own name and region are in its environment, put there by the installer for exactly
		// this — see plan_environment.go, DSSE_NODE_NAME. The Edge identity is still used when it is real.
		measuredOn := nodeProvenance(evaluator, edgeIsControlPlane)
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_organization_setup.v1",
			"tenant_id":      target,
			"measured_on":    measuredOn,
			"note": "Assembled from what THIS node holds. Items marked not_here live on the other plane — " +
				"ask it for those rather than reading their absence as a gap.",
			"items": items,
			"done":  done,
			"total": len(items),
			// operational is the answer the registry row cannot give: does anything actually happen for this
			// organization. Named separately from the count because eleven of thirteen with a blocking item
			// outstanding is not "nearly there".
			//
			// ★ THREE-VALUED, AND THAT WAS THE SECOND CORRECTION. As a boolean the control plane answered
			// TRUE at 5 of 13 — every blocking item it could see was fine, and the two it could not see were
			// the ones that decide whether traffic is inspected at all. "Nothing I can see is wrong" is not
			// "this works", and a screen showing a green tick for it would be the most expensive kind of
			// wrong this checklist exists to prevent.
			"operational": func() string {
				switch {
				case len(blocking) > 0:
					return "no"
				case len(unseen) > 0:
					return "unknown"
				default:
					return "yes"
				}
			}(),
			"blocking":         blocking,
			"not_visible_here": unseen,
		})
	}))
}

// organizationSetupTenant reads the registered row, and says whether there was one.
//
// The runtime read SYNTHESISES a row for an unknown id, so existence is only answerable against the list —
// the same trap the invite path and the operator delegation both had to work around.
func organizationSetupTenant(ctx context.Context, store adminTenantModelRuntimeStore, tenantID string) (adminTenantModel, bool) {
	if admin, ok := store.(adminTenantModelAdminStore); ok {
		if tenants, err := admin.List(ctx); err == nil {
			for _, tenant := range tenants {
				if strings.EqualFold(strings.TrimSpace(tenant.TenantID), tenantID) {
					return tenant, true
				}
			}
			return adminTenantModel{TenantID: tenantID}, false
		}
	}
	tenant, err := store.Get(ctx, tenantID)
	if err != nil {
		return adminTenantModel{TenantID: tenantID}, false
	}
	return tenant, strings.TrimSpace(tenant.TenantID) != ""
}

// policyCountForThisNode is how many rules this node enforces for the organization that asked — or nil when
// this node is not the one that enforces, because a count of zero from a node that never had any is a
// statement about the node dressed as a statement about the organization.
//
// ★ THE DISCRIMINATOR IS THE ROLE, NOT WHETHER THIS NODE PULLS. The first attempt asked whether a config
// source was set, which is true of an Edge in a deployment and false of one standing alone — and a standalone
// Edge enforces, so it would have said "unknown" about rules it was applying.
func policyCountForThisNode(policies []map[string]any, enforcementEdge bool) any {
	if !enforcementEdge {
		return nil
	}
	return len(policies)
}

// dataplaneCountForThisNode is the same rule for the two counts that only a dataplane produces: the access
// decisions it evaluated and the inspection events it recorded. Both live in bounded in-memory stores fed by
// traffic, and a control plane carries no traffic — so its zero is the shape of the node, not the activity of
// the organization. nil, which the tiles already render as "—", is the truthful answer from a node that never
// had the chance to see one.
//
// ★ THE SCREEN'S REAL SOURCE FOR DECISIONS IS THE HOT STORE now (access-trends, which reads the deployment's
// whole stream). This governs the fallback the tile uses when that read is unavailable — the moment a
// confident zero would do the most damage, because nothing else on the screen would contradict it.
func dataplaneCountForThisNode(count int, enforcementEdge bool) any {
	if !enforcementEdge {
		return nil
	}
	return count
}

// nodeProvenance names the machine answering, in the terms the operator knows it by — the region and machine
// name the installer wrote into this node's environment, and which of the two roles it is playing.
//
// ★★★ IT EXISTS BECAUSE A SCREEN LABELLED ONE NODE'S ANSWER WITH ANOTHER NODE'S NAME (2026-09-05, measured
// on the Console's certificate map). That screen asks two addresses, calls one "Enforcement Edge" and the
// other "Control plane", and on a deployment whose Console front door proxies both to the SAME node it
// received the control plane's certificates twice and labelled half of them as the Edge's. The Edge's own
// transport certificate, its transport anchors and the organization's interception root were not on the
// screen at all, and nothing said they were missing.
//
// A node that says who it is lets a screen label an answer by what answered, rather than by which URL it
// used to ask.
func nodeProvenance(evaluator decision.Evaluator, isControlPlane bool) string {
	role := "edge"
	if isControlPlane {
		role = "control plane"
	}
	node := strings.TrimSpace(os.Getenv("DSSE_NODE_NAME"))
	region := strings.TrimSpace(os.Getenv("DSSE_EDGE_REGION"))
	if region == "" {
		region = strings.TrimSpace(evaluator.EdgeRegionID)
	}
	if node == "" {
		return strings.TrimSpace(region + "/" + evaluator.EdgeClusterID)
	}
	return strings.TrimSpace(region + "/" + node + " (" + role + ")")
}
