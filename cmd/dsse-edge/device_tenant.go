package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"strings"
	"sync"
	"time"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/model"
)

func devicesForTenant(deviceStore deviceRuntimeStore, tenantID string) ([]model.Device, error) {
	if tenantReader, ok := deviceStore.(deviceTenantReader); ok {
		return tenantReader.ListByTenant(tenantID)
	}
	devices := []model.Device{}
	for _, dev := range deviceStore.List() {
		if dev.TenantID == tenantID {
			devices = append(devices, dev)
		}
	}
	return devices, nil
}

func deviceForTenant(deviceStore deviceRuntimeStore, tenantID, deviceID string) (model.Device, bool, error) {
	if tenantGetter, ok := deviceStore.(deviceTenantGetter); ok {
		return tenantGetter.GetByTenant(tenantID, deviceID)
	}
	dev, ok := deviceStore.Get(deviceID)
	if !ok || dev.TenantID != tenantID {
		return model.Device{}, false, nil
	}
	return dev, true, nil
}

// deviceGroupVisibleToTenant reports whether a device group (or a device assignment) carrying groupTenant is
// visible to — and mutable by — an admin operating as callerTenant.
//
// ★ AN OBJECT WITH NO TENANT WAS VISIBLE AND MUTABLE TO EVERY TENANT (2026-08-12, sixteenth review). The
// original rule treated an empty tenant on EITHER side as unscoped, for a reason that was real: on a
// single-tenant edge, where a legacy entry or a tenant-resolution quirk leaves the field blank, hiding those
// objects would hide the fleet from the only admin who owns it. But the two sides are not the same question.
//
//   - callerTenant empty is about the CALLER: an operator this deployment could not scope. Unchanged — it is
//     how a single-tenant edge with no tenant model works, and narrowing it would lock those admins out.
//   - groupTenant empty is about the OBJECT, and "belongs to nobody" was being read as "belongs to everybody".
//     That is one tenant's admin listing, renaming, disabling and DELETING another's devices — and it fails
//     open in the states nobody pictures: a tenant just added, a migration half-done, the last device of one
//     removed. The same shape was found and removed from the agent-update view one review earlier; this is
//     the path the Console actually reads first, so the boundary was still open where it mattered most.
//
// Nothing vanishes silently: the list endpoints report what they withheld as a count, so an unassigned fleet
// is a number an operator can see and act on rather than a set of devices that quietly stopped existing.
func deviceGroupVisibleToTenant(groupTenant, callerTenant string) bool {
	g := strings.TrimSpace(groupTenant)
	c := strings.TrimSpace(callerTenant)
	if c == "" {
		return true
	}
	return g != "" && strings.EqualFold(g, c)
}

// steerDeviceTenant answers WHOSE material this device is entitled to receive, on the routes an endpoint agent
// calls with a verified (T) transport identity.
//
// ★ EVERY ONE OF THOSE ROUTES USED THIS NODE'S OWN TENANT (found 2026-08-16). Five of them, all the same
// shape: /steer/agent-policy, /steer/agent-tuning, /steer/server-initiated-export, the agent report, and
// /steer/region-endpoints. On a single-tenant Edge the node's tenant and the device's tenant are the same
// value and nothing is visible. On the multi-tenant Edge this product now ships, a second organization's
// device was handed the FIRST organization's material — its steer exclusions (which apps bypass steering),
// its inbound firewall exceptions, its tuning, its allowed and home REGIONS (residency) — and filed its own
// reports under the wrong organization, which is also where the anchor-adoption measurement reads from.
//
// The certificate is the authority, exactly as it is on the data path: transportTenantFromRequest resolves
// the tenant from the Tenant CA that issued the device's client certificate. The enrolled ledger is the
// second source, for a node with no Tenant CA registry, and it is the same authority every admin read now
// uses. The node's own tenant remains the last resort, which is what a single-tenant deployment is.
func steerDeviceTenant(r *http.Request, config serverConfig, identity, nodeTenant string) string {
	if reg := config.TenantCARegistry; reg != nil {
		if tid, ok := transportTenantFromRequest(r, reg); ok && strings.TrimSpace(tid) != "" {
			return tid
		}
	}
	if config.EnrolledLedger != nil {
		if entry, ok := config.EnrolledLedger.EntryFor(identity); ok && strings.TrimSpace(entry.TenantID) != "" {
			return strings.TrimSpace(entry.TenantID)
		}
	}
	// ★★★ AND THERE IS NO THIRD ANSWER. The two questions above are the only ones that can be answered with
	// authority: which registered Tenant CA the device's certificate chains to, and which organization the
	// control plane recorded it into. When neither answers, this deployment does not know whose device this is.
	//
	// It used to return the NODE's tenant here — and the comment at the call site already said why that is
	// wrong: "Handing an organization the material of whichever organization happens to own the Edge is how a
	// second customer received the first one's enforcement." The fallback did exactly that, one line below the
	// sentence describing it. On a deployment made by dsse-install the node's tenant is tenant_default, which
	// is the OPERATOR's organization — so an unattributable device was served the enforcement configuration of
	// the organization that administers all the others, and every screen reported success.
	//
	// ★ SAID BEFORE IT IS REFUSED, so the day this fires is visible rather than inferred. The interception
	// engine closed the same hole this way and its counter stayed at zero: every flow resolved. If that stops
	// being true here, this line is how anyone finds out.
	unattributedDeviceTenant.note(identity, nodeTenant, time.Now())
	return ""
}

// unattributedDeviceTenant records the devices this node could not attribute to an organization. It is a
// counter and a first/last seen, not a list: the point is to answer "is this happening" without keeping a
// record of every device that ever failed.

var unattributedDeviceTenant = &unattributedTenantReports{seen: map[string]int{}}

// restart-durability: ephemeral — deliberately. Nothing an operator reads depends on this surviving: the
// refusal itself is what the device sees, the first sighting of each device is logged, and a device that still
// cannot be attributed asks again within a minute and is counted again. Persisting it would keep a list of the
// identities this deployment refused — a record with no reader and a privacy cost.
//
// populated-by: side_effect — of steerDeviceTenant refusing. Nothing fetches or asserts it: an entry exists
// only because a device asked THIS node a question it could not answer. Being empty off that path is not just
// acceptable, it is the state a healthy deployment stays in — every device resolves, so nothing is recorded.
type unattributedTenantReports struct {
	mu    sync.Mutex
	seen  map[string]int
	first time.Time
	last  time.Time
}

func (u *unattributedTenantReports) note(identity, wouldHaveBeen string, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.first.IsZero() {
		u.first = now
	}
	u.last = now
	u.seen[identity]++
	// Loud on the first sighting of each device, quiet afterwards: a device that cannot be attributed will ask
	// again every minute, and a line per minute per device buries the one that matters.
	if u.seen[identity] == 1 {
		log.Printf("device_tenant ★ REFUSED: device %q chains to no registered Tenant CA and is in no "+
			"organization's enrolled inventory, so this deployment does not know whose it is. It is NOT served "+
			"%q's configuration — that is the organization that happens to own this node, and handing it over "+
			"is how one customer receives another's enforcement. Enrol the device into its organization, or "+
			"register that organization's Tenant CA on this node.", identity, wouldHaveBeen)
	}
}

// Snapshot answers "is this happening", for the admin surface and for tests.
func (u *unattributedTenantReports) Snapshot() (devices, total int, first, last time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, n := range u.seen {
		total += n
	}
	return len(u.seen), total, u.first, u.last
}

// adminTenantPKITargetAllowed decides whether this caller may act on the PKI of the named tenant: yes for its
// own, or for an operator acting within the same selected tenant, no otherwise. It returns the refusal message so every
// PKI route says the same thing the same way.
//
// ★ THIS IS THE SHAPE THAT LET A CUSTOMER MINT ANOTHER CUSTOMER'S INTERCEPTION ROOT (2026-08-15). That route
// took the tenant from the URL and checked nothing, and the permission it required — admin.policy.write — is
// held by every ordinary tenant admin. The fix there was written inline; this is the same decision, extracted,
// because the routes that need it are multiplying as each PKI domain becomes tenant-manageable and the second
// copy of a boundary is where the two answers start to differ.
//
// The verb is passed in so the refusal names the ACT ("registering the device CA of X") rather than the route.
// An operator reading an audit trail of 403s needs to know what was attempted, not which handler said no.
// adminSelfTenantPathValue is what a caller writes in a {tenant} path segment to mean "the tenant I am".
//
// ★ THE ROUTES THAT PUT THE TENANT IN THE PATH HAVE NO WAY TO OMIT IT (2026-08-18). /admin/tenant-cas takes the
// tenant in the body, so a customer administrator simply leaves it out and the server answers for them. The
// interception-CA routes take it in the path, where there is no "leave it out" — an empty segment posts to a
// different route entirely (the node-wide, operator-only one). So the customer's own screen had to name the
// customer's own tenant id, which the Console does not reliably know and should not have to: the session
// already established who is calling.
const adminSelfTenantPathValue = "self"

// adminResolveTenantPathTarget turns a {tenant} path segment into the tenant it is about. "self" is the caller's
// own tenant; anything else is taken literally and still has to pass adminTenantPKITargetAllowed.
//
// An operator who has not entered a tenant has no "self" — refusing is the only honest answer, because the
// alternative is performing a tenant act against an empty tenant id and reporting success.
func adminResolveTenantPathTarget(r *http.Request, target string) (string, error) {
	target = strings.TrimSpace(target)
	if !strings.EqualFold(target, adminSelfTenantPathValue) {
		return target, nil
	}
	caller := strings.TrimSpace(adminTenantIDFromRequest(r))
	if caller == "" {
		return "", fmt.Errorf("%q means the tenant you are operating in, and this session is not operating in one; "+
			"enter a tenant first or name it explicitly", adminSelfTenantPathValue)
	}
	return caller, nil
}

func adminTenantPKITargetAllowed(r *http.Request, targetTenant, act string) error {
	target := strings.TrimSpace(targetTenant)
	caller := strings.TrimSpace(adminTenantIDFromRequest(r))
	if target == "" || strings.EqualFold(target, caller) {
		return nil
	}
	if adminCallerIsOperator(r) {
		return adminOperatorWriteTargetAllowed(r, target, act)
	}
	return fmt.Errorf("%s another organization (%q) requires cross-tenant operator rights; you are operating in %q",
		act, target, caller)
}

// A path/body target must agree with the tenant whose delegation and elevation
// the middleware checked. Operator authority alone is not customer consent.
// Reads, envelope controls, and explicitly tenantless/lab deployments retain
// their existing behavior; named production operators must select the target.
func adminOperatorWriteTargetAllowed(r *http.Request, target, act string) error {
	if r == nil || !adminMutatingMethod(r.Method) || operatorRouteIsEnvelopeControl(r.URL.Path) {
		return nil
	}
	identity, ok := adminIdentityFromRequest(r)
	if !ok || strings.EqualFold(identity.AuthMethod, adminLabBypassAuthMethod) ||
		(strings.TrimSpace(identity.TenantID) == "" && operatorTenantlessMode.Load()) {
		return nil
	}
	selected, _ := adminOperateTenant(r, identity)
	if target == "" || strings.EqualFold(strings.TrimSpace(target), strings.TrimSpace(selected)) {
		return nil
	}
	return fmt.Errorf("%s organization %q requires selecting that organization first; the request is operating in %q", act, target, selected)
}

// adminCallerIsOperator reports whether this request is being made by somebody who operates ACROSS tenants —
// an unscoped caller, or one holding admin.tenant.admin (super_admin / owner). It is the authority that makes
// an unassigned device assignable: a tenant admin cannot see one, so the only person who can adopt it is the
// person who can see all of them.
func adminCallerIsOperator(r *http.Request) bool {
	identity, ok := adminIdentityFromRequest(r)
	if !ok {
		// No resolved identity means an unscoped deployment (a single-tenant edge with no tenant model), which
		// is the same answer deviceGroupVisibleToTenant gives for an empty caller tenant.
		return true
	}
	if strings.TrimSpace(identity.TenantID) == "" {
		return true
	}
	// ★ AND THE ROLE ALONE IS NOT THE ANSWER (2026-08-21) — see
	// operator_is_an_organization_not_a_role.go. The caller must hold admin.tenant.admin AND belong to the
	// organization that operates this deployment.
	return adminIdentityMayActAcrossOrganizations(identity)
}
