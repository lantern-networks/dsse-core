package enrolledinventory

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/blobstore"
	"time"
)

// management ledger: the admin-managed Enrolled Inventory. The stage-0 admission gate originally
// read a STATIC signed JSON file (loadEnrolledInventory) — fine for PoC, but production needs the Admin
// Console to manage the device list at runtime: enroll a device, DISABLE it (the manual revocation path —
// the operator enables/disables entries by hand), re-enable, or remove it — all consulted live at the (T)
// handshake with no restart. The ledger SEEDS from the static file (back-compat) and is then authoritative.
//
// disable vs the W-2/W-7 admission-revocation overlay: disabling a ledger entry is the routine Console
// revocation (the device stays on the list, shown as disabled, re-enableable); the admission-revocation
// overlay is the emergency kill-switch / agent-dark auto-revocation. Both deny admission — complementary,
// not duplicative.
//
// NOTE: this ledger deliberately does NOT enforce certificate profiles (attribute/EKU/policy-OID checks) —
// that was explicitly out of scope (2026-06-18). Admission stays: CA-chain valid (TLS) + tenant binding +
// enrolled-and-enabled here + not-revoked overlay.

type Entry struct {
	Identity   string `json:"identity"`
	Enabled    bool   `json:"enabled"`
	TenantID   string `json:"tenant_id,omitempty"`
	Group      string `json:"group,omitempty"` // CP-assigned device group (M6 fleet view: filter/display by group)
	Note       string `json:"note,omitempty"`
	EnrolledAt string `json:"enrolled_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
	// DeviceEnrolledAt is when a DEVICE last completed POST /enroll for this identity and was issued a
	// certificate. Empty means the entry exists but no device has ever enrolled against it — an operator
	// pre-added the identity, or it was seeded.
	//
	// ★ IT IS WHAT SEPARATES A FIRST ENROLMENT FROM AN IMPERSONATION (2026-08-12, twentieth review). An
	// enrolment token is one-time but it is NOT bound to a device id — nothing in Token names one, and the
	// Console cannot know the id before the machine is set up. So a holder of any valid credential for a
	// tenant could name an EXISTING device in that same tenant and be issued a fresh certificate under its
	// name: not a cross-tenant move, which was already refused, but a takeover of a device identity inside
	// the tenant. Reissue for a device that already has a certificate is what /enroll/renew is for, and that
	// path is authenticated by the certificate being replaced.
	DeviceEnrolledAt string `json:"device_enrolled_at,omitempty"`
	// ReenrolmentNonce counts the times an administrator has permitted this identity to enrol again. It is
	// CP-authored state and travels in the config bundle, which is what makes the marker above survivable: a
	// bundle REPLACES this ledger, so an Edge keeps its local marker unless the incoming nonce is NEWER than
	// the one the marker was recorded under. See AllowReenrolment and MergeAuthoritative.
	ReenrolmentNonce int `json:"reenrolment_nonce,omitempty"`
	// DeviceEnrolledNonce is the nonce that was in force when the device enrolled. Local: it is how the Edge
	// decides whether an incoming CP entry represents a re-arm it has not yet honoured.
	DeviceEnrolledNonce int `json:"device_enrolled_nonce,omitempty"`
	// RemovedAt marks an identity an administrator took OUT of the inventory. The entry stays — holding
	// nothing but the refusal — instead of vanishing.
	//
	// ★★★ BECAUSE AN ABSENCE CANNOT TRAVEL (2026-08-24, measured on a two-Edge fleet). Deleting the entry made
	// a removed device indistinguishable, on every OTHER node, from a device that node had not been told about
	// yet — and a fleet learns about enrolments a poll after they happen, so "I have never heard of this" is
	// the ordinary state of a perfectly legitimate machine. A door that refused those refused every agent in
	// the seconds between enrolling and connecting. So removal was not enforceable at all: the machine went on
	// steering with the certificate it already held, and the operator had been told it was gone.
	//
	// A tombstone is a fact the fleet can carry. It is not listed anywhere an operator looks for devices — the
	// device IS gone — and it is what every admission door reads.
	RemovedAt string `json:"removed_at,omitempty"`
	// Kind says what this identity IS, and therefore what may be expected of it.
	//
	// ★ AN ENROLLED IDENTITY IS NOT NECESSARILY AN ENDPOINT (2026-08-15). A connector's transport
	// certificate is admitted from THIS ledger, and a connector never runs the endpoint agent, so it never
	// reports device-runtime state. The posture check read "enrolled, but no runtime row" as "UNKNOWN, which
	// is not OK" — exactly right for an endpoint, and simply what a connector looks like. The gate went red
	// for an identity doing nothing wrong, which is how a gate stops being read.
	//
	// It is DECLARED, never inferred from absence. Inferring "this one does not report, so it must not be an
	// endpoint" would let a real endpoint that VANISHED classify itself as exempt — the precise failure the
	// check exists to catch. Empty means KindEndpoint, so every entry that predates this field keeps the
	// strict reading, and only an operator saying otherwise relaxes it.
	Kind string `json:"kind,omitempty"`
	// MachineRef is a value the AGENT declares about the machine it runs on — stable across reinstalling the
	// agent, not across reinstalling the operating system.
	//
	// ★★★ WITHOUT IT A DEPLOYMENT CANNOT TELL A MACHINE FROM ITS NAMESAKE (the operator's point, 2026-08-25).
	// Since a device enrols under the name its own OS gives it, two machines called "laptop" are ordinary, and
	// a second enrolment of an existing identity has two causes that look identical: the same machine coming
	// back, and a different machine that happens to share a computer name. The first is a renewal; the second
	// must be refused and RENAMED. Refusing both with one sentence sends somebody to look at renewal on a
	// machine that has never enrolled, with the one-time token already spent.
	//
	// ★ IT IS EVIDENCE, NEVER AUTHENTICATION. The agent reports it, so anything can claim any value; it is used
	// only to tell those two cases apart and to recognise a machine that has been renamed. What authenticates a
	// device is the certificate it holds, and nothing here changes that.
	//
	// ★ AND IT CHANGES WHEN THE MACHINE IS REBUILT. A reinstalled OS looks like a different machine, which is
	// the correct reading and needs a way back — the same explicit act as AllowReenrolment, which clears it.
	MachineRef string `json:"machine_ref,omitempty"`
}

// The kinds an enrolled identity may declare.
const (
	// KindEndpoint is a managed device running the endpoint agent. It is expected to report device-runtime
	// state, and silence from one is a finding. This is the default for an entry that declares nothing.
	KindEndpoint = "endpoint"
	// KindService is an identity that authenticates to the transport but is not a managed device — a
	// connector, a site gateway, a service that holds a client certificate. It has no agent and no posture,
	// so no runtime report is expected and its absence from the runtime view says nothing either way.
	KindService = "service"
)

// IsEndpoint reports whether this identity is expected to report device-runtime state. An entry that
// declares nothing is an endpoint: the strict reading is the default, and relaxing it takes a decision.
func (e Entry) IsEndpoint() bool {
	switch strings.TrimSpace(strings.ToLower(e.Kind)) {
	case "", KindEndpoint:
		return true
	default:
		return false
	}
}

// ValidKind reports whether k is a kind this ledger understands. Empty is valid and means KindEndpoint.
func ValidKind(k string) bool {
	switch strings.TrimSpace(strings.ToLower(k)) {
	case "", KindEndpoint, KindService:
		return true
	default:
		return false
	}
}

type Ledger struct {
	mu      sync.Mutex
	entries map[string]Entry // key = normalized identity
	// groups: the first-class device-group REGISTRY (key = group id). Distinct from Entry.Group (the
	// per-device assignment string). The registry is the authoritative catalog of groups that EXIST, so the
	// Console can offer created groups for tab-select assignment instead of free-form typing. Persisted in the
	// same durable snapshot as entries. See groups.go.
	groups map[string]Group
	// persister: durable snapshot of admin runtime changes (enroll/disable/remove). nil = in-memory only
	// (runtime changes lost on restart). When set, the durable state is authoritative on boot, so an
	// admin's enroll/disable/remove survives a restart (W7) — and, on a shared persister, a CP failover.
	persister blobstore.Persister
	// generation is a monotonic counter bumped on every admin mutation (Enroll / SetEnabled / Remove /
	// ReplaceAll). Phase 1 config distribution folds the Enrolled Inventory into the config bundle; because it
	// is a SEPARATE store from policy.Store, the bundle's generation is the SUM of the per-store
	// generations, so any enroll/disable change advances the bundle generation and Edges re-pull.
	generation atomic.Uint64
	// claimer, when set, is where "this identity has already enrolled" is decided for every issuer at once.
	claimer IdentityClaimer
	// persistBlocked latches a failed LOAD: this process has not seen what is in the store, so it must not
	// write over it. Cleared only by a successful load.
	persistBlocked error
}

func NewLedger() *Ledger {
	return &Ledger{entries: map[string]Entry{}, groups: map[string]Group{}}
}

// ConfigGeneration returns the monotonic enrolled-inventory config version (bumped on each admin mutation).
func (l *Ledger) ConfigGeneration() uint64 {
	if l == nil {
		return 0
	}
	return l.generation.Load()
}

func NormalizeIdentity(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

// SeedFromStatic adds identities from the static inventory as enabled entries. It does NOT overwrite an
// existing managed entry (admin changes win over a re-seed).
func (l *Ledger) SeedFromStatic(ids map[string]struct{}, now string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id := range ids {
		k := NormalizeIdentity(id)
		if k == "" {
			continue
		}
		if _, exists := l.entries[k]; exists {
			continue
		}
		// ★ A SEEDED IDENTITY IS TREATED AS ALREADY ENROLLED (2026-08-12, twenty-first review, second pass).
		// The v2 migration covers entries that come from the DURABLE STORE, and this is the other way an
		// identity arrives without a marker: the static admission list, applied at boot before the store is
		// attached. Where there is no store configured — or on a first boot with an empty one — those entries
		// survive with an empty marker, and each is one same-tenant impersonation, which is precisely the
		// category the migration exists to close.
		//
		// The static list is an ADMISSION decision about names that already exist; it is not evidence that no
		// device has ever enrolled them. A device that genuinely needs to enrol against a seeded name is
		// re-armed by an administrator, one at a time, like every other exception.
		l.entries[k] = Entry{Identity: k, Enabled: true, EnrolledAt: now, UpdatedAt: now,
			Note: "seeded_from_static_inventory", DeviceEnrolledAt: seededDeviceEnrolmentSentinel}
	}
}

// IsAdmitted reports whether an identity is enrolled AND enabled (the admission membership test).
// isTombstone reports that this entry is the memory of a removal rather than a device.
func (e Entry) isTombstone() bool { return strings.TrimSpace(e.RemovedAt) != "" }

func (l *Ledger) IsAdmitted(id string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[NormalizeIdentity(id)]
	return ok && e.Enabled
}

// IsRefused reports that this ledger KNOWS the identity and does not admit it — a device an administrator has
// blocked.
//
// ★★★ IT IS NOT !IsAdmitted, AND THE DIFFERENCE IS AN OUTAGE (2026-08-24, measured on a two-Edge fleet). An
// identity absent from the ledger and one an administrator has disabled are the same answer to IsAdmitted and
// opposite facts. A device enrols on one Edge and its enrolment reaches the others through the control plane,
// which takes a poll — so for those seconds every other node has never heard of a device that is perfectly
// legitimate. Refusing on "not admitted" refused exactly that device: an agent that enrols and connects a
// second later, which is what every agent does.
//
// So a door that must not lock anybody out asks THIS instead: not "do I know this is allowed" but "do I know
// this is not". Blocking is the sanctioned way to stop a machine, and blocking is representable — the entry
// stays and says enabled=false. Removal is not, and that gap is named where the door uses this.
func (l *Ledger) IsRefused(id string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[NormalizeIdentity(id)]
	return ok && !e.Enabled
}

// CountAdmitted is how many of a tenant's devices currently occupy a seat: enrolled AND enabled.
//
// Disabled devices are deliberately NOT counted. Disabling is how an operator takes a machine out of service,
// and a seat that stays occupied by a device nobody may use would make the licence count measure history rather
// than reality — an operator who retires fifty laptops expects to be able to enrol fifty more.
//
// An empty tenant counts every entry, which is what a single-tenant deployment wants.
func (l *Ledger) CountAdmitted(tenantID string) int {
	if l == nil {
		return 0
	}
	want := strings.TrimSpace(tenantID)
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if !e.Enabled {
			continue
		}
		if want == "" || strings.EqualFold(strings.TrimSpace(e.TenantID), want) {
			n++
		}
	}
	return n
}

// Tenants lists every tenant that has at least one entry, sorted.
//
// The MSSP console needs it to answer "why can this customer not enrol", and the tenants worth asking about
// include the ones nobody allocated seats to — a tenant with devices and no allocation is precisely the case an
// operator gets called about, and it would be invisible to a view built only from the allocation table.
// CountUntenanted returns how many ENABLED entries carry no tenant at all.
//
// Seat usage is counted per tenant, so an entry with no tenant matches nothing and is counted nowhere. A
// deployment whose inventory was seeded rather than enrolled — every entry written before tenants were tagged —
// therefore reports zero seats in use while devices are admitted, and a licence that reports itself enforced
// can never refuse anything. Counting the untagged separately is what makes that state visible instead of
// looking like an empty fleet.
func (l *Ledger) CountUntenanted() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.entries {
		if e.isTombstone() {
			continue // a removal is not a device
		}
		if e.Enabled && strings.TrimSpace(e.TenantID) == "" {
			n++
		}
	}
	return n
}

func (l *Ledger) Tenants() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	seen := map[string]bool{}
	for _, e := range l.entries {
		if e.isTombstone() {
			continue // a removal is not a device
		}
		if t := strings.TrimSpace(e.TenantID); t != "" {
			seen[t] = true
		}
	}
	l.mu.Unlock()
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// GroupFor returns the CP-ASSIGNED device group for an identity (M6 Entry.Group) and whether the identity is
// present in the ledger. This is the AUTHORITATIVE group source for per-group policy/tuning resolution — it is
// set by the Control Plane at enrollment (EnrollGroup) / admin assignment (ReplaceAll), never by the device.
// Callers MUST prefer this over any device-reported metadata so a device cannot self-assert its group.
func (l *Ledger) GroupFor(id string) (string, bool) {
	if l == nil {
		return "", false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[NormalizeIdentity(id)]
	if !ok {
		return "", false
	}
	return e.Group, true
}

// EntryFor returns the full ledger entry for an identity and whether it is present. Used by the admin API to
// read an entry's TenantID for a tenant-isolation guard BEFORE mutating/deleting it (so a cross-tenant identity
// is treated as not-found rather than silently mutated).
func (l *Ledger) EntryFor(id string) (Entry, bool) {
	if l == nil {
		return Entry{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[NormalizeIdentity(id)]
	return e, ok
}

// Enroll adds or re-enables an identity.
func (l *Ledger) Enroll(id, tenantID, note, now string) (Entry, error) {
	return l.EnrollGroup(id, tenantID, "", note, now)
}

// EnrollGroup admits a device AND records its CP-assigned device group (M6 fleet view). An empty group is
// preserved on re-enroll (so an admin re-enable that carries no group does not clear the assignment). Same
// admission semantics as Enroll otherwise.
func (l *Ledger) EnrollGroup(id, tenantID, group, note, now string) (Entry, error) {
	return l.enrollGroup(id, tenantID, group, note, now, true)
}

// ErrIdentityDisabled is returned when enrolment is asked to write an identity an administrator has disabled.
var ErrIdentityDisabled = fmt.Errorf("identity is disabled by an administrator")

// ErrIdentityRemoved is returned when a write would land on an identity an administrator REMOVED.
//
// ★★★ THE ALTERNATIVE WAS 200 AND NOTHING CHANGING (2026-08-25, reported from win-dev-1). Creating the
// identity again wrote Enabled=true over the tombstone and left RemovedAt where it was — so the API answered
// success, the ledger still did not list the device, and /enroll still answered "not eligible". A removal
// that can be written over silently is a removal nobody can see; a removal that answers success and does
// nothing is worse. Lifting one is a named act, and the error says which.
var ErrIdentityRemoved = fmt.Errorf("identity was removed by an administrator; allow re-enrolment to lift it")

// EnrollGroupUnlessDisabled is EnrollGroup for the DEVICE-facing path (POST /enroll), where the caller is
// whoever holds an enrolment credential rather than an authenticated admin. It refuses an identity the operator
// has disabled instead of re-enabling it.
//
// EnrollGroup sets Enabled = true on whatever entry it finds under the same normalized identity, and disable
// writes that same field of that same entry — so a device that re-enrolled under its old name simply undid the
// operator's decision, silently, and overwrote the note explaining it. The console offers disable as revocation;
// it has to survive the device coming back and asking again.
//
// The admin route keeps EnrollGroup, because an admin re-adding a device they disabled IS the decision, made by
// someone entitled to make it. This split is the whole point: enrolment is not an admin action.
func (l *Ledger) EnrollGroupUnlessDisabled(id, tenantID, group, note, now string) (Entry, error) {
	return l.enrollGroup(id, tenantID, group, note, now, false)
}

// ErrIdentityOwnedByAnotherTenant is returned when an enrolment would take over an identity that already
// belongs to somebody else. The caller decides what to say — "not found" is usually the right answer, because
// whether a device exists in another tenant is not the asker's to learn.
var ErrIdentityOwnedByAnotherTenant = fmt.Errorf("identity belongs to another tenant")

// ErrIdentityUnassigned is returned when an enrolment would claim an identity that belongs to NO tenant. It is
// a different refusal from the one above: the device is genuinely unowned, and adopting it is a legitimate
// action — for an operator. A tenant admin cannot even see it.
var ErrIdentityUnassigned = fmt.Errorf("identity belongs to no tenant; assigning it is an operator action")

// ErrIdentityAlreadyEnrolled is returned when a DEVICE tries to enrol an identity that a device has already
// enrolled. Replacing that device's certificate is /enroll/renew's job, and it proves possession of the
// certificate being replaced.
// ★★★ AND THE MESSAGE HAS TO COVER THE OTHER CASE (2026-08-25). Since a device enrols under the name its
// OWN OPERATING SYSTEM gives it — rather than one somebody invented — this refusal now has two causes that
// look identical from here, and only one of them is "renew instead":
//
//	the same machine, again           → renewal, which proves possession of the certificate being replaced
//	a DIFFERENT machine, same name    → two machines share a computer name, and the second cannot enrol
//
// The deployment cannot tell them apart today: nothing machine-unique arrives with an enrolment, so the name
// is all there is. Saying only "reissue is a renewal" sends somebody to look at renewal on a machine that has
// never enrolled, and the one-time token is already spent by then. So the refusal names both, and what to do
// about the second — which is the one an operator cannot guess.
var ErrIdentityAlreadyEnrolled = fmt.Errorf(
	"this identity is already enrolled. If this is the SAME machine, replacing its certificate is a renewal " +
		"(/enroll/renew), which proves possession of the one being replaced. If this is a DIFFERENT machine " +
		"that happens to share a computer name, it cannot enrol under that name: rename it, or enrol it with " +
		"an explicit device identity")

// ★★★ AND NOW THE DEPLOYMENT CAN SAY WHICH (2026-08-25). Once an enrolment carries something machine-unique,
// the sentence above stops being the only thing that can be said: the two causes are distinguishable, and each
// has ONE way out rather than two an operator has to choose between.
var (
	// ErrSameMachineAlreadyEnrolled is this machine, coming back. It has a certificate; replacing it is a
	// renewal, which is authenticated by the certificate being replaced.
	ErrSameMachineAlreadyEnrolled = fmt.Errorf(
		"this machine is already enrolled under this name. Replacing its certificate is a renewal " +
			"(/enroll/renew), which proves possession of the one being replaced — enrolling again is not " +
			"needed and would not produce a second identity")

	// ErrDifferentMachineSameName is somebody else's namesake. Renewal is not open to it: it holds no
	// certificate to prove.
	ErrDifferentMachineSameName = fmt.Errorf(
		"a DIFFERENT machine is already enrolled under this computer name, so this one cannot enrol under it. " +
			"Rename this machine, or enrol it with an explicit device identity. Renewal is not the way in: " +
			"this machine holds no certificate for that name to replace")

	// ErrMachineEnrolledUnderAnotherName is the machine that has been RENAMED. Enrolling would give one
	// machine two identities, two certificates and two rows in every view, and nothing would ever join them.
	ErrMachineEnrolledUnderAnotherName = fmt.Errorf(
		"this machine is already enrolled in this deployment under a different name. Enrolling it again would " +
			"give one machine two identities. Keep using the name it is enrolled under, or have an " +
			"administrator permit it to enrol again — which releases the old name")
)

// MachineRefConflict describes what the ledger found when an enrolment was refused for a machine-reference
// reason, so the caller can say the OTHER name out loud rather than making an operator go looking.
type MachineRefConflict struct {
	// EnrolledAs is the identity this machine is already enrolled under. Empty unless the refusal is
	// ErrMachineEnrolledUnderAnotherName.
	EnrolledAs string
}

// EnrollDeviceForTenant is the DEVICE-facing enrolment (POST /enroll): it answers every question the device
// path has to answer — is this identity disabled, does it belong to somebody else, and has a device already
// enrolled it — inside one lock, and refuses rather than overwriting.
//
// ★ THE PUBLIC PATH WAS STILL A TAKEOVER AFTER THE ADMIN ONE WAS FIXED (2026-08-12, nineteenth review).
// EnrollGroupUnlessDisabled checks the disabled flag and then assigns TenantID unconditionally, so a caller
// holding a VALID enrolment credential for tenant B could name a device id belonging to tenant A: the ledger
// moved to B and B was handed a certificate for it. The admin route being atomic did not help — this is a
// different door into the same room.
//
// An entry belonging to NO tenant is assignable here, unlike on the admin route. The difference is the
// evidence: this caller holds a one-time credential an administrator issued FOR that tenant and proves
// possession of a key, where an admin POST is a person naming a string. A seeded ledger entry with no tenant
// is the ordinary shape of a device enrolling for the first time.
func (l *Ledger) EnrollDeviceForTenant(id, tenantID, group, note, now string) (Entry, error) {
	e, _, err := l.EnrollDeviceForTenantWithMachine(id, tenantID, group, note, now, "")
	return e, err
}

// EnrollDeviceForTenantWithMachine is EnrollDeviceForTenant with what the agent said about the machine.
//
// ★★★ THE MACHINE REFERENCE DECIDES NOTHING AN OPERATOR HAS NOT ALREADY DECIDED. It never grants an
// enrolment — a request that carries one is admitted on exactly the evidence a request without one is. All it
// does is narrow a refusal from "one of two things happened" to the one that did, and recognise a machine that
// has been renamed rather than letting it become a second device.
//
// The conflict it returns names the OTHER identity when there is one, because "you are already enrolled
// somewhere else" without saying where is a refusal an operator cannot act on.
// WouldRefuseEnrolment answers the local refusals WITHOUT writing anything, so a caller can ask before it
// spends something it cannot get back.
//
// ★★★ A REFUSED ENROLMENT WAS SPENDING THE ADMINISTRATOR'S ONE-TIME TOKEN (2026-08-29, measured on Windows by
// the session that walked the install lane there, and confirmed twice in its ledger). The endpoint spends the
// token in Assign and only reaches these checks in Record, so a device refused for "this identity is already
// enrolled" burned the approval on the way to being turned away. The comment on ErrIdentityAlreadyEnrolled
// already said "and the one-time token is already spent by then" — it was describing the defect, not a
// constraint.
//
// What made it expensive is the SECOND attempt: with the token gone, the same device is refused with "invalid
// or missing eligibility token", which names a different problem entirely. An operator issues another token,
// watches it vanish, issues another — and never reaches the thing that would actually fix it, which is the
// administrator's re-enrolment grant. The first refusal is the true one and it is only ever seen once.
//
// This is the same shape as refuseIfDisabled and the seat check, which already run before the spend for
// exactly this reason. It is deliberately the LOCAL checks only: the shared identity claim is a write, and
// asking a remote claimer "would you" before asking it "do" is two answers that can disagree.
func (l *Ledger) WouldRefuseEnrolment(id, tenantID, machineRef string) error {
	k := NormalizeIdentity(id)
	if k == "" {
		return fmt.Errorf("identity is required")
	}
	machineRef = NormalizeMachineRef(machineRef)
	l.mu.Lock()
	defer l.mu.Unlock()
	if machineRef != "" {
		if _, found := l.identityForMachineLocked(machineRef, k); found {
			return ErrMachineEnrolledUnderAnotherName
		}
	}
	e, exists := l.entries[k]
	if !exists {
		return nil
	}
	if !e.Enabled {
		return ErrIdentityDisabled
	}
	owner := strings.TrimSpace(e.TenantID)
	if owner != "" && strings.TrimSpace(tenantID) != "" && !strings.EqualFold(owner, strings.TrimSpace(tenantID)) {
		return ErrIdentityOwnedByAnotherTenant
	}
	if strings.TrimSpace(e.DeviceEnrolledAt) != "" {
		return l.alreadyEnrolledReasonLocked(e, machineRef)
	}
	return nil
}

func (l *Ledger) EnrollDeviceForTenantWithMachine(id, tenantID, group, note, now, machineRef string) (Entry, MachineRefConflict, error) {
	k := NormalizeIdentity(id)
	if k == "" {
		return Entry{}, MachineRefConflict{}, fmt.Errorf("identity is required")
	}
	machineRef = NormalizeMachineRef(machineRef)
	l.mu.Lock()
	defer l.mu.Unlock()
	// ★ THE RENAMED MACHINE IS CHECKED BEFORE THE NAME IS. A machine that has been renamed arrives under a name
	// nothing knows, so every check below would pass and it would be issued a SECOND identity — two
	// certificates, two rows in every view, and one machine counted twice for ever. Only the machine reference
	// can see it, and only before the new name is taken.
	if machineRef != "" {
		if other, found := l.identityForMachineLocked(machineRef, k); found {
			return Entry{}, MachineRefConflict{EnrolledAs: other}, ErrMachineEnrolledUnderAnotherName
		}
	}
	if e, exists := l.entries[k]; exists {
		if !e.Enabled {
			return Entry{}, MachineRefConflict{}, ErrIdentityDisabled
		}
		owner := strings.TrimSpace(e.TenantID)
		if owner != "" && strings.TrimSpace(tenantID) != "" && !strings.EqualFold(owner, strings.TrimSpace(tenantID)) {
			return Entry{}, MachineRefConflict{}, ErrIdentityOwnedByAnotherTenant
		}
		// ★ AND THE SAME-TENANT CASE IS THE ONE THAT WAS LEFT (2026-08-12, twentieth review). Refusing only
		// the cross-tenant move still let any holder of a valid credential for THIS tenant name an existing
		// machine and be issued a certificate under its name. A device that already has one renews.
		if strings.TrimSpace(e.DeviceEnrolledAt) != "" {
			return Entry{}, MachineRefConflict{}, l.alreadyEnrolledReasonLocked(e, machineRef)
		}
	}
	// ★ THE SHARED CLAIM IS TAKEN BEFORE THE LOCAL RECORD IS WRITTEN (2026-08-13, twenty-fourth review). The
	// local checks above are this node's; they cannot see another issuer. When a claimer is configured, the
	// decision that matters is made where every issuer can see it, and only then is it written here — so a
	// device whose identity was consumed elsewhere is refused rather than issued a second certificate.
	//
	// Taken under the grant this entry carries, which is the administrator's re-enrolment permission: a claim
	// only moves to a NEWER grant, so a re-arm still works and two issuers racing under one grant produce one
	// winner. A claimer that errors refuses the enrolment — an unknown answer is not a yes.
	claimTaken, claimHonoured := false, false
	grant := 0
	if l.claimer != nil {
		if e, ok := l.entries[k]; ok {
			grant = e.ReenrolmentNonce
		}
		claimed, cerr := l.claimer.ClaimIdentity(context.Background(), tenantID, k, grant)
		if cerr != nil {
			return Entry{}, MachineRefConflict{}, fmt.Errorf("the identity claim could not be taken, so no certificate is issued: %w", cerr)
		}
		if !claimed {
			return Entry{}, MachineRefConflict{}, ErrIdentityClaimedElsewhere
		}
		// If the local record cannot be written, the claim this node just took must go back — otherwise the
		// device gets no certificate AND cannot retry, with its one-time token already spent, until an
		// administrator re-arms it. Fail-closed either way; this is the difference between safe and stuck.
		defer func() {
			if claimTaken && !claimHonoured {
				if rerr := l.claimer.ReleaseIdentity(context.Background(), tenantID, k, grant); rerr != nil {
					log.Printf("enrolled_inventory: %q was claimed for an enrolment that then failed locally, and "+
						"the claim could NOT be released (%v) — an administrator's re-enrolment permission is the "+
						"way back for that device", k, rerr)
				}
			}
		}()
		claimTaken = true
	}
	before, hadBefore := l.entries[k]
	// ★ THE MARKER IS PART OF THE ENTRY BEING WRITTEN, NOT A SECOND WRITE AFTER IT (2026-08-12, twenty-first
	// review). The first version persisted the entry WITHOUT the marker, set it in memory, and persisted
	// again — so a crash between the two, or a failed second save, left a device holding a certificate and a
	// store saying nobody had ever enrolled that identity. And persistLocked only logged, so the endpoint
	// answered 200 either way. The write that records a security decision has to be one write, and its
	// failure has to reach the caller.
	entry, err := l.enrollGroupMutateLocked(k, tenantID, group, note, now, false, false, func(e *Entry) {
		e.DeviceEnrolledAt = now
		e.DeviceEnrolledNonce = e.ReenrolmentNonce
		// Recorded only when there is something to record. An agent that reports nothing must not ERASE what a
		// previous enrolment of the same identity established — the deployment would then be back to not being
		// able to tell a machine from its namesake, silently, on the first old agent that came through.
		if machineRef != "" {
			e.MachineRef = machineRef
		}
	})
	if err != nil {
		return Entry{}, MachineRefConflict{}, err
	}
	if perr := l.persistCheckedLocked(); perr != nil {
		// Put memory back where the store is. A marker this process believes and the store does not is the
		// same disagreement one restart later, and the caller is about to be told there is no certificate.
		if hadBefore {
			l.entries[k] = before
		} else {
			delete(l.entries, k)
		}
		return Entry{}, MachineRefConflict{}, fmt.Errorf("enrolment could not be recorded durably, so no certificate is issued: %w", perr)
	}
	claimHonoured = true
	return entry, MachineRefConflict{}, nil
}

// RecordEnrolmentDecidedElsewhere writes an enrolment that has ALREADY happened, on another node of this
// deployment, into this ledger.
//
// ★★★ IT DOES NOT TAKE THE IDENTITY CLAIM, AND THAT IS THE WHOLE DIFFERENCE (2026-08-24, measured on a
// generated deployment). An Edge issues a certificate only after asking the control plane whether the identity
// may be enrolled — the claim is taken THERE, at issuance. The Edge then reports where it happened, and the
// receiving path used EnrollDeviceForTenant, which takes the claim again. A claim is refused when it is
// already held at the same grant, deliberately, because that is what makes two issuers racing produce one
// winner. So every report was answered 409:
//
//	★ enrolment_report_refused identity=... status=409 — this device holds a valid certificate issued HERE
//	  but the control plane will not name it, so the next config bundle WILL drop it from admission
//
// A report is not an issuing decision. Asking "may I issue this?" about something already issued has exactly
// one correct answer, and it is no.
//
// ★★ WHAT IT STILL REFUSES. A disabled identity, and one that belongs to another organization — those are
// this ledger's own facts and a report must not move a machine between fleets. Only the claim step is
// skipped, because it was taken by the node that issued the certificate this report is about.
func (l *Ledger) RecordEnrolmentDecidedElsewhere(id, tenantID, group, note, now string) (Entry, error) {
	k := NormalizeIdentity(id)
	if k == "" {
		return Entry{}, fmt.Errorf("identity is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[k]; ok {
		if !e.Enabled {
			return Entry{}, ErrIdentityDisabled
		}
		if owner := strings.TrimSpace(e.TenantID); owner != "" && !strings.EqualFold(owner, strings.TrimSpace(tenantID)) {
			return Entry{}, ErrIdentityOwnedByAnotherTenant
		}
	}
	before, hadBefore := l.entries[k]
	entry, err := l.enrollGroupMutateLocked(k, tenantID, group, note, now, false, false, func(e *Entry) {
		e.DeviceEnrolledAt = now
		e.DeviceEnrolledNonce = e.ReenrolmentNonce
	})
	if err != nil {
		return Entry{}, err
	}
	if perr := l.persistCheckedLocked(); perr != nil {
		// Put memory back where the store is, the same way the issuing path does: a record this process
		// believes and the store does not is the same disagreement one restart later.
		if hadBefore {
			l.entries[k] = before
		} else {
			delete(l.entries, k)
		}
		return Entry{}, fmt.Errorf("the enrolment could not be recorded durably: %w", perr)
	}
	return entry, nil
}

// EnrollGroupForTenant is EnrollGroup with the ownership question answered INSIDE the lock.
//
// ★ CHECKING FIRST AND WRITING SECOND IS NOT A CHECK (2026-08-12, eighteenth review). The admin route read the
// entry with EntryFor, decided the caller was entitled to it, and then called EnrollGroup — two separate
// acquisitions of this mutex. Two tenants POSTing the same UNREGISTERED identity at once BOTH see "does not
// exist", both proceed, and the later write owns the device; the same race lands between a new device's first
// enrolment and an attacker's POST. Every test of that check was sequential, so nothing could see the window:
// a TOCTOU is invisible to a caller that never overlaps with another.
//
//   - claimant is the tenant the entry must already belong to. Empty means the deployment has no tenant model
//     (a single-tenant edge), which is unscoped and may write — the same lockout-safe reading used everywhere
//     else for an empty CALLER.
//   - adoptUnassigned lets a caller claim an entry that belongs to NO tenant. That is an operator action: a
//     tenant admin cannot see such a device, and the Console tells the operator it is theirs to assign.
//   - An entry owned by ANOTHER tenant is refused whoever is asking, operator included. Moving a device
//     between tenants is a decision, and it must not be reachable as a side effect of enrolling one.
//
// A shared database behind several Edges would need the same decision expressed as a conditional UPDATE; this
// mutex is the authority for a single process, and the ledger is that today.
func (l *Ledger) EnrollGroupForTenant(id, claimant, assignTo, group, note, now string, adoptUnassigned bool) (Entry, error) {
	k := NormalizeIdentity(id)
	if k == "" {
		return Entry{}, fmt.Errorf("identity is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, exists := l.entries[k]; exists && strings.TrimSpace(claimant) != "" {
		owner := strings.TrimSpace(e.TenantID)
		switch {
		case owner == "" && !adoptUnassigned:
			return Entry{}, ErrIdentityUnassigned
		case owner != "" && !strings.EqualFold(owner, strings.TrimSpace(claimant)):
			return Entry{}, ErrIdentityOwnedByAnotherTenant
		}
	}
	entry, err := l.enrollGroupLocked(k, assignTo, group, note, now, true)
	if err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// AllowReenrolment is the administrator's decision that a device may enrol again.
//
// ★ IT IS ITS OWN OPERATION, NOT A SIDE EFFECT OF ADDING A DEVICE (2026-08-12, twenty-first review). The
// first version cleared the marker inside the ordinary admin enrol, so re-adding a device for any reason —
// fixing a note, assigning a group — silently re-opened enrolment for it, and the audit trail recorded the
// same "enroll" action either way. An operator cannot review a decision that leaves no trace of having been
// made, and nobody would have known this one was being made at all.
//
// ★ AND IT ADVANCES A NONCE, WHICH IS WHAT SURVIVES CP AUTHORITY. The Edge's config bundle REPLACES this
// ledger with the control plane's copy, so a marker that only exists locally is erased on the next unrelated
// config change and every enrolled device becomes enrollable again. The nonce travels IN the entry, so the
// CP's copy carries the fact that a re-arm happened; the Edge keeps its local marker unless the incoming
// nonce is newer than the one the marker was recorded under. Merging on a counter, rather than on
// "local wins" or "CP wins", is the only version of this that lets both facts propagate.
// ★ IT RETURNS BOTH SIDES, BECAUSE THE AUDIT NEEDS THE PAIR (2026-08-12, twenty-third review). The route used
// to read the entry with EntryFor and then call this — two critical sections — and record the FIRST read as
// "the enrolment this grant superseded". A concurrent enrolment or re-arm between them made that field name a
// state this grant did not replace, in the one record whose job is saying what it replaced. The before-image
// comes from the same lock as the write or it is a guess.
func (l *Ledger) AllowReenrolment(id, callerTenant, now string) (Entry, Entry, error) {
	k := NormalizeIdentity(id)
	if k == "" {
		return Entry{}, Entry{}, fmt.Errorf("identity is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[k]
	if !ok {
		return Entry{}, Entry{}, ErrIdentityNotFound
	}
	if strings.TrimSpace(callerTenant) != "" {
		owner := strings.TrimSpace(e.TenantID)
		if owner == "" || !strings.EqualFold(owner, strings.TrimSpace(callerTenant)) {
			return Entry{}, Entry{}, ErrIdentityOwnedByAnotherTenant
		}
	}
	before := e
	// ★★★ AND THIS IS THE ONE ACT THAT LIFTS A REMOVAL (2026-08-25, reported from win-dev-1 after it removed
	// a device and could never bring it back).
	//
	// Removal leaves a tombstone so the fleet keeps refusing the identity and a stale Edge cannot resurrect
	// it. Nothing anywhere cleared RemovedAt — not this route, not re-creating the entry, not enrolling
	// again. Every other mutator treats a tombstone as "not a device to edit" and answers 404, and creating
	// the identity again answered 200 while the tombstone stayed, so the ledger never showed it and /enroll
	// answered "not eligible". The identity was gone for good, and the API said success the whole way.
	//
	// "Let this identity enrol again" is exactly what a removal has to be undoable BY, so it is undone here
	// and nowhere else: one named act, attributable, rather than a removal that quietly means never.
	e.RemovedAt = ""
	e.Enabled = true
	e.ReenrolmentNonce++
	e.DeviceEnrolledAt = ""
	// ★★★ AND IT RELEASES THE MACHINE THIS NAME WAS BOUND TO (2026-08-25). Two cases need it, and both are
	// ordinary: a machine that was REBUILT reports a new reference and would otherwise be refused for ever as
	// "a different machine with the same name", and a machine that was RENAMED holds this name hostage — its
	// reference points here, so it cannot enrol under its new name either. This act is the operator saying
	// "let this name be enrolled again", and a binding that survived it would make that untrue.
	//
	// ★ IT DOES NOT CANCEL THE DISTINCTION. The next enrolment records whatever the machine reports, so the
	// deployment can tell the cases apart again from that moment on. What is released is one name's claim, by
	// a named act, not the mechanism.
	e.MachineRef = ""
	e.UpdatedAt = now
	l.entries[k] = e
	l.generation.Add(1)
	if perr := l.persistCheckedLocked(); perr != nil {
		// ★ THE ROLLBACK PUT THE MUTATED ENTRY BACK (2026-08-12, twenty-second review). `l.entries[k] = e`
		// restores the value that was just written, not the one before it — so a re-arm whose durable write
		// FAILED still cleared the marker in this process. The API answers 500 and the very next /enroll from
		// anyone holding a credential for that tenant succeeds. A permission that could not be recorded is a
		// permission that was not granted, and memory has to say the same thing the disk does.
		l.entries[k] = before
		l.generation.Add(1) // the state changed twice; let the bundle re-pull rather than look unchanged
		return Entry{}, Entry{}, fmt.Errorf("the re-enrolment permission could not be recorded durably: %w", perr)
	}
	return e, before, nil
}

// IdentityClaimer takes the one-time claim on a device identity somewhere every issuer can see it.
//
// ★ THE LEDGER CANNOT BE THAT PLACE (2026-08-13, twenty-fourth review). It answers from memory and saves as a
// blob, so two processes holding a device CA each decide alone — and giving each its own file removes even the
// chance of noticing. grant is the administrator's re-enrolment permission counter: a claim may be taken only
// under a grant NEWER than the standing one, which is the same rule MergeAuthoritative applies, so an operator
// re-arming a re-imaged machine still works and two racing issuers under one grant produce one winner.
//
// nil means no claimer is configured, and the ledger then decides locally — correct for a deployment with a
// single issuer, and the startup gate is what makes that true rather than assumed.
type IdentityClaimer interface {
	ClaimIdentity(ctx context.Context, tenantID, identity string, grant int) (bool, error)
	// ReleaseIdentity gives back a claim this node took but could not honour. Best-effort by construction —
	// if it fails, the identity stays claimed and an administrator's re-arm is the way back, which is safe
	// and inconvenient rather than the other way round.
	ReleaseIdentity(ctx context.Context, tenantID, identity string, grant int) error
	// BackfillClaims records identities that were ALREADY enrolled before the shared claim existed.
	//
	// ★ AN EMPTY CLAIM TABLE HANDS THE EXISTING FLEET AWAY (2026-08-13, twenty-fifth review). Creating the
	// table does not populate it, so every identity enrolled before the upgrade has no claim — and a NEW
	// issuer, which has no local marker for them either, takes the empty claim and issues a certificate for
	// a name already in use. The original issuer still refuses from its own marker, which is what makes this
	// look fine from wherever you happen to be standing.
	BackfillClaims(ctx context.Context, claims []IdentityClaim) (int, error)
}

// IdentityClaim is one already-consumed identity, as an existing ledger knows it.
type IdentityClaim struct {
	TenantID string
	Identity string
	Grant    int
}

// BackfillIdentityClaims hands the shared claim every identity this node already knows to be enrolled.
//
// Called at startup, after the durable ledger has loaded and before any enrolment is served. Conservative by
// construction: it claims what is already spent, so the worst case is an identity that needs an
// administrator's re-arm — not one that can be enrolled twice.
// It returns how many identities this node KNOWS are already enrolled — not how many rows the store happened
// to insert.
//
// ★ THOSE TWO ARE NOT THE SAME NUMBER, AND CONFUSING THEM BRICKS A NORMAL UPGRADE (2026-08-13, twenty-seventh
// review). The migration barrier asks "did this node hold part of the fleet", and it was answered with the
// backfill's rows-affected. A deployment whose previous release already created claim rows re-claims the same
// rows, matches nothing, inserts zero — and the only issuer is then refused startup with "start the Edge that
// HAS the enrolments first", which is the Edge being refused. The escape hatch says "this deployment has never
// enrolled anything", which would be a lie. What the barrier needs is the evidence, and the evidence is what
// this node knows.
func (l *Ledger) BackfillIdentityClaims(ctx context.Context) (known int, err error) {
	if l == nil || l.claimer == nil {
		return 0, nil
	}
	l.mu.Lock()
	claims := make([]IdentityClaim, 0, len(l.entries))
	for k, e := range l.entries {
		if e.isTombstone() {
			continue // a removal has no claim to backfill
		}
		if strings.TrimSpace(e.DeviceEnrolledAt) == "" {
			continue // never enrolled: an operator pre-added it, and it is legitimately still available
		}
		claims = append(claims, IdentityClaim{TenantID: e.TenantID, Identity: k, Grant: e.ReenrolmentNonce})
	}
	l.mu.Unlock()
	if len(claims) == 0 {
		return 0, nil
	}
	inserted, berr := l.claimer.BackfillClaims(ctx, claims)
	if berr != nil {
		return 0, berr
	}
	if inserted != len(claims) {
		// Ordinary on a re-run or a second node: the rows were already there. Said out loud because the
		// difference between the two numbers is exactly what the barrier used to get wrong.
		log.Printf("enrolled_inventory: offered %d already-enrolled identity(ies) to the shared claim; %d were "+
			"new (the rest were already claimed, which is the normal state after the first run)", len(claims), inserted)
	}
	return len(claims), nil
}

// IdentityClaimer returns the claim this ledger takes identities in, or nil when it has none.
//
// Exposed so the node that HOLDS the authority can answer the fleet's claim requests with the same object it
// decides its own with. Two paths to one claim would be two places to take a one-time decision, which is the
// thing the claim exists to prevent.
func (l *Ledger) IdentityClaimer() IdentityClaimer {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.claimer
}

// SetIdentityClaimer installs the shared claim. Called at startup, before any enrolment is served.
func (l *Ledger) SetIdentityClaimer(c IdentityClaimer) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.claimer = c
}

// ErrIdentityClaimedElsewhere is returned when another issuer already consumed this identity under the same
// permission. It is a refusal, not a failure: the device asking is either a second copy or an impersonation,
// and both answers are the same one.
var ErrIdentityClaimedElsewhere = fmt.Errorf("this identity has already been enrolled by another issuer")

// ErrIdentityNotFound is returned when an operation names an identity the ledger does not hold.
var ErrIdentityNotFound = fmt.Errorf("identity is not in the enrolled inventory")

// IsExplicitlyDisabled reports whether an identity is PRESENT and disabled. It deliberately distinguishes that
// from absent: an unknown identity is a device that has never enrolled, which is the normal Day-0 case, while a
// disabled one is a device an operator decided to keep out.
func (l *Ledger) IsExplicitlyDisabled(id string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[NormalizeIdentity(id)]
	return ok && !e.Enabled
}

func (l *Ledger) enrollGroup(id, tenantID, group, note, now string, mayReEnable bool) (Entry, error) {
	k := NormalizeIdentity(id)
	if k == "" {
		return Entry{}, fmt.Errorf("identity is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enrollGroupLocked(k, tenantID, group, note, now, mayReEnable)
}

// enrollGroupLocked is the write itself. The caller holds the lock, so an ownership check made just above it
// cannot be overtaken between the two.
func (l *Ledger) enrollGroupLocked(k, tenantID, group, note, now string, mayReEnable bool,
	complete ...func(*Entry)) (Entry, error) {
	return l.enrollGroupMutateLocked(k, tenantID, group, note, now, mayReEnable, true, complete...)
}

// enrollGroupMutateLocked is the write, with the save under the caller's control.
//
// ★ THE MARKER WAS STILL SAVED TWICE (2026-08-12, twenty-second review). The comment above claimed one write
// and there were two: this function persisted, and the device path then persisted again to check the error.
// If the first succeeded and the second failed, the disk said ENROLLED, memory was rolled back, and the API
// returned a failure — with the one-time token already spent, so a legitimate device was locked out of a
// state it had actually reached, and only an administrator's re-arm could free it. The caller that needs to
// know whether the write landed does the saving, once.
func (l *Ledger) enrollGroupMutateLocked(k, tenantID, group, note, now string, mayReEnable, persist bool,
	complete ...func(*Entry)) (Entry, error) {
	e, exists := l.entries[k]
	switch {
	case !exists:
		e = Entry{Identity: k, EnrolledAt: now}
	case e.isTombstone():
		// See ErrIdentityRemoved. Writing over a tombstone is how a removal became permanent AND invisible.
		return Entry{}, ErrIdentityRemoved
	case !e.Enabled && !mayReEnable:
		return Entry{}, ErrIdentityDisabled
	}
	e.Enabled = true
	e.TenantID = strings.TrimSpace(tenantID)
	if g := strings.TrimSpace(group); g != "" {
		e.Group = g
	}
	if strings.TrimSpace(note) != "" {
		e.Note = strings.TrimSpace(note)
	}
	e.UpdatedAt = now
	// Finish the entry BEFORE it is stored and persisted, so there is one write and no window where the
	// record on disk is missing a field the caller is about to act on.
	for _, f := range complete {
		if f != nil {
			f(&e)
		}
	}
	l.entries[k] = e
	l.generation.Add(1) // distributed via the config bundle (Phase 1): advance so Edges re-pull
	if persist {
		return e, l.persistCheckedLocked()
	}
	return e, nil
}

// SetGroup EXPLICITLY sets an existing device's CP-assigned group (admin re-assignment from the console). Unlike
// EnrollGroup — which preserves an existing group when passed an empty value — SetGroup sets exactly what is
// given, so an empty group CLEARS the assignment (the device falls back to tenant-scope resolution). Returns
// false if the identity is not in the ledger. Bumps the generation so the change distributes via the bundle.
// ★★ IT REPORTS WHETHER THE ASSIGNMENT LASTED (2026-08-13, thirty-first review #8). This is the WAVE GROUP: it
// decides which ring a device updates in. On the best-effort seam an administrator moving a device from pilot
// to rest was told it worked, the durable save failed silently, and the next control-plane restart put the
// device back in pilot — taking the release on wave 0, which is the ring that exists to catch a bad build
// before the fleet does.
func (l *Ledger) SetGroup(id, group, now string) (Entry, bool, error) {
	k := NormalizeIdentity(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[k]
	if !ok || e.isTombstone() { // a removal is not a device to edit
		return Entry{}, false, nil
	}
	e.Group = strings.TrimSpace(group)
	e.UpdatedAt = now
	l.entries[k] = e
	l.generation.Add(1)
	return e, true, l.persistCheckedLocked()
}

// SetKind declares what an identity IS. Returns false if the identity is not in the ledger, and an error if
// the kind is one this ledger does not understand — a typo must not silently become "not an endpoint".
//
// ★ ITS OWN OPERATION, like SetGroup and AllowReenrolment above, and for the same reason. Folding it into the
// ordinary admin enrol would mean an operator fixing a note could also, invisibly, stop a device being
// checked for posture — and the audit line would say "enroll" either way. What this changes is whether
// silence from this identity is a finding, so it is worth being able to find the moment it was decided.
func (l *Ledger) SetKind(id, kind, now string) (Entry, bool, error) {
	if !ValidKind(kind) {
		return Entry{}, false, fmt.Errorf("unknown identity kind %q (want %q or %q)", kind, KindEndpoint, KindService)
	}
	k := NormalizeIdentity(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[k]
	if !ok || e.isTombstone() { // a removal is not a device to edit
		return Entry{}, false, nil
	}
	e.Kind = strings.TrimSpace(strings.ToLower(kind))
	if e.Kind == KindEndpoint {
		e.Kind = "" // the default reading, stored as absence so it cannot drift from it
	}
	e.UpdatedAt = now
	l.entries[k] = e
	l.generation.Add(1)
	return e, true, l.persistCheckedLocked()
}

// Endpoints returns the identities expected to report device-runtime state. Callers that ask "is every
// enrolled device accounted for?" mean this set, not every entry: a connector has no agent and its silence
// is not evidence of anything.
func (l *Ledger) Endpoints() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		if e.isTombstone() {
			continue // a removal is not a device
		}
		if e.IsEndpoint() {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// SetEnabled toggles a device's enabled state (disable = the manual revocation path). Returns false if the
// identity is not in the ledger.
func (l *Ledger) SetEnabled(id string, enabled bool, now string) (Entry, bool) {
	e, ok, _ := l.setEnabled(id, enabled, now)
	return e, ok
}

// setEnabled is the write, returning WHY it refused rather than leaving that on the receiver for somebody to
// read later under a different lock.
func (l *Ledger) setEnabled(id string, enabled bool, now string) (Entry, bool, error) {
	k := NormalizeIdentity(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[k]
	// ★ A TOMBSTONE IS NOT A DEVICE TO RE-ENABLE. Removal is deliberate, and the way back is enrolling again
	// — which is its own decision, with its own credential and its own record. Letting "enable" resurrect a
	// removal would make the tombstone a suggestion.
	if !ok || e.isTombstone() {
		return Entry{}, false, nil
	}
	before := e
	e.Enabled = enabled
	e.UpdatedAt = now
	l.entries[k] = e
	l.generation.Add(1) // distributed via the config bundle (Phase 1): advance so Edges re-pull
	// ★ DISABLE IS THE MANUAL REVOCATION PATH, SO ITS WRITE IS THE DECISION (2026-08-13, twenty-seventh
	// review). persistLocked swallowed the save error, so an operator revoking a compromised device got 200
	// and a success audit record whether or not it was recorded — and the next restart made the durable store
	// authoritative, readmitting the stolen machine with an audit trail claiming it had been revoked. The
	// checked seam already existed in this file, described as "where the write is the security decision"; this
	// call site was the one still on the best-effort path.
	if perr := l.persistCheckedLocked(); perr != nil {
		l.entries[k] = before
		l.generation.Add(1)
		return Entry{}, false, perr
	}
	return e, true, nil
}

// SetEnabledChecked is SetEnabled with the two failures told apart: an identity that is not here, and one
// whose new state could not be recorded. The route needs the difference — answering "not in the inventory"
// for a disk error would send an operator revoking a stolen device looking for the wrong problem.
// ★ THE REASON COMES BACK FROM THE SAME LOCK AS THE ATTEMPT (2026-08-13, twenty-ninth review). The first
// version stashed it on the ledger and read it in a SECOND critical section, so a concurrent SetEnabled on a
// different identity — succeeding, and clearing the field — turned a disk failure here into
// ErrIdentityNotFound. That is exactly the misattribution this method exists to prevent, reintroduced by the
// way it was plumbed.
func (l *Ledger) SetEnabledChecked(id string, enabled bool, now string) (Entry, error) {
	e, ok, perr := l.setEnabled(id, enabled, now)
	switch {
	case ok:
		return e, nil
	case perr != nil:
		return Entry{}, fmt.Errorf("%q could not be recorded, so it is NOT in force: %w", id, perr)
	default:
		return Entry{}, ErrIdentityNotFound
	}
}

// Remove deletes an identity from the ledger entirely.
func (l *Ledger) Remove(id, now string) bool {
	k := NormalizeIdentity(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	removed, ok := l.entries[k]
	if !ok || removed.isTombstone() {
		return false
	}
	// ★★★ THE ENTRY STAYS AS A TOMBSTONE. Deleting it made the removal unenforceable on every other node —
	// see Entry.RemovedAt. Enabled goes false in the same write, so every reader that already asks "is this
	// admitted" gets the right answer without knowing tombstones exist.
	tomb := Entry{
		Identity:  removed.Identity,
		TenantID:  removed.TenantID,
		Enabled:   false,
		RemovedAt: now,
		UpdatedAt: now,
		// The group, the note and the enrolment markers are deliberately dropped: a tombstone is a refusal,
		// not a device, and keeping its description would put a removed machine's details in the one place
		// that outlives it.
	}
	l.entries[k] = tomb
	l.purgeExpiredTombstonesLocked(now)
	l.generation.Add(1) // distributed via the config bundle (Phase 1): advance so Edges re-pull
	// ★ REMOVING A DEVICE IS A REVOCATION, SO ITS WRITE IS THE DECISION (2026-08-13, twenty-eighth review).
	// persistLocked discards the save error, so an operator removing a compromised machine got success in
	// memory and in the API while the durable store still held it — and the next restart put it back. The
	// checked seam already existed in this file for SetEnabled and enrolment; this call site was not on it.
	if perr := l.persistCheckedLocked(); perr != nil {
		l.entries[k] = removed
		l.generation.Add(1)
		return false
	}
	return true
}

// tombstoneLifetime is how long a removal is carried before the entry is dropped for good.
//
// ★ IT HAS TO BE LONGER THAN THE CERTIFICATE IT REFUSES. A tombstone exists to stop a machine that still
// holds a certificate this deployment issued; once that certificate cannot be valid, the tombstone is
// answering a question nobody can ask. Ninety days is comfortably past the enrolment certificate's life, and
// an entry that is a name and a timestamp costs nothing to keep meanwhile — which is the right way round,
// because dropping one early re-admits a machine somebody removed.
const tombstoneLifetime = 90 * 24 * time.Hour

// purgeExpiredTombstonesLocked drops tombstones whose certificate can no longer be valid. Called on write
// rather than on a timer: this ledger has no goroutine of its own, and a set that is only bounded while
// something is happening to it is bounded exactly when it grows.
func (l *Ledger) purgeExpiredTombstonesLocked(now string) {
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(now))
	if err != nil {
		return // an unparseable clock is not a reason to drop refusals
	}
	for k, e := range l.entries {
		if !e.isTombstone() {
			continue
		}
		removedAt, perr := time.Parse(time.RFC3339, strings.TrimSpace(e.RemovedAt))
		if perr != nil {
			continue
		}
		if at.Sub(removedAt) > tombstoneLifetime {
			delete(l.entries, k)
		}
	}
}

// RemoveTenant deletes every identity belonging to a tenant and returns the identities it removed.
//
// This is the ledger half of deleting an organization. It is a deliberate, named act — the same reason the
// config bundle carries deletions rather than inferring them from an absence: an inventory that drops whatever
// it cannot see is one bad payload away from de-admitting a fleet.
//
// The shared identity claims are RELEASED, each under the grant its own entry carried. Without that the
// identities stay spent in a store the tenant no longer has any row in, so re-using that hardware for another
// customer would need an administrator's re-arm for every machine — a deleted tenant would quietly poison its
// devices. Release is best-effort by construction (an unreleased claim is safe and inconvenient, the other way
// round is not), so a failure is logged with the identity in it rather than swallowed.
func (l *Ledger) RemoveTenant(tenantID string) []string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}
	l.mu.Lock()
	removed := map[string]Entry{}
	for k, entry := range l.entries {
		if strings.EqualFold(strings.TrimSpace(entry.TenantID), tenantID) {
			removed[k] = entry
		}
	}
	if len(removed) == 0 {
		l.mu.Unlock()
		return nil
	}
	for k := range removed {
		delete(l.entries, k)
	}
	l.generation.Add(1) // distributed via the config bundle: advance so Edges re-pull
	if perr := l.persistCheckedLocked(); perr != nil {
		// Same rule as Remove: a de-admission that only happened in memory comes back on the next restart, so
		// it did not happen at all. Put them back and report nothing removed.
		for k, entry := range removed {
			l.entries[k] = entry
		}
		l.generation.Add(1)
		l.mu.Unlock()
		log.Printf("enrolled_inventory: removing tenant %q was NOT durable (%v) — nothing was removed", tenantID, perr)
		return nil
	}
	claimer := l.claimer
	l.mu.Unlock()

	out := make([]string, 0, len(removed))
	for k := range removed {
		out = append(out, k)
	}
	sort.Strings(out)
	if claimer != nil {
		// Outside the lock: releasing a claim talks to a shared store, and holding the ledger's mutex across
		// that would stall every admission decision on this node for the duration.
		for _, k := range out {
			if rerr := claimer.ReleaseIdentity(context.Background(), tenantID, k, removed[k].ReenrolmentNonce); rerr != nil {
				log.Printf("enrolled_inventory: tenant %q was deleted and %q was removed from the ledger, but its "+
					"shared identity claim could NOT be released (%v) — that identity will need an administrator's "+
					"re-enrolment permission before it can enrol again", tenantID, k, rerr)
			}
		}
	}
	return out
}

// ReplaceAll atomically replaces the WHOLE ledger with the given entries (Phase 1 config distribution: a
// config-pulling Edge swaps in the control plane's authoritative Enrolled Inventory). Identities are
// re-normalized; an empty slice empties the ledger (deny everyone). Bumps the generation + persists.
// MergeAuthoritative applies the control plane's copy of the inventory while KEEPING what only this Edge
// knows: which identities have actually completed an enrolment here.
//
// ★ ReplaceAll ERASED THE ENROLMENT MARKER, WHICH RE-OPENED EVERY DEVICE (2026-08-12, twenty-first review).
// The config bundle carries the enrolled inventory and applies it wholesale, and the CP's entries carry no
// marker because enrolment happens at the EDGE. So: a device enrols and gets its marker, somebody changes
// anything at all on the control plane, the bundle lands, and that identity is enrollable again — by anyone
// holding a credential for its tenant. In the reference topology the same Edge has both -config-source-url
// and a device CA signer, so this is the supported configuration, not a corner.
//
// "Keep the local marker" alone is not the fix either: an administrator's decision to PERMIT a re-enrolment
// is authored on the control plane, and a local marker that always wins would swallow it. The nonce is what
// makes both directions expressible — the CP's entry says how many times a re-arm has been granted, the local
// marker remembers which grant it was recorded under, and the marker survives unless the CP's count is newer.
func (l *Ledger) MergeAuthoritative(entries []Entry, now string) error {
	dropped, err := l.mergeAuthoritative(entries, now)
	if len(dropped) > 0 {
		// ★ AN ERASED ENROLMENT MUST NOT BE SILENT (2026-08-14). The merge rebuilds this ledger from the control
		// plane's list, so an identity the CP does not name is gone — and POST /enroll tells the CP nothing, so
		// a device that enrolled HERE is never named. The twenty-first review fixed the neighbouring half (an
		// enrolled device becoming enrollable again); this half is still open, and until enrolment reaches the
		// control plane the least that can be true is that it says so.
		//
		// Both consequences point away from the config bundle. The device holds a valid certificate and is
		// refused at transport, which reads as a transport or PKI fault; and the Operator Quota that decision 4
		// builds on counts this ledger, so the count silently goes short and admits devices past the operator's
		// own limit. One line here is what connects either symptom to its cause.
		log.Printf("★ enrolled_inventory: the control plane's inventory did not name %d identity(ies) that had "+
			"ENROLLED on this node, and they have been dropped from admission: %s — POST /enroll does not report "+
			"to the control plane, so a device enrolled here is invisible to it. Those devices hold valid "+
			"certificates and will now be refused, and any seat count taken from this ledger is short by that "+
			"many", len(dropped), strings.Join(dropped, ", "))
	}
	return err
}

// MergeAuthoritativeDropped is MergeAuthoritative for callers that want the list rather than the log line —
// tests, and any future path that reports this to an operator instead of to a file.
func (l *Ledger) MergeAuthoritativeDropped(entries []Entry, now string) []string {
	dropped, _ := l.mergeAuthoritative(entries, now)
	return dropped
}

func (l *Ledger) mergeAuthoritative(entries []Entry, now string) ([]string, error) {
	if l == nil {
		return nil, nil
	}
	// ★ THE SNAPSHOT AND THE SWAP HELD THE LOCK SEPARATELY (2026-08-12, twenty-second review). The first
	// version copied local state, released the mutex, decided, and then called ReplaceAll — which took the
	// lock again. An /enroll completing in that gap wrote a marker the merge had already decided not to
	// carry, and the swap put the stale answer back: the identity became enrollable again, from a config
	// bundle that had nothing to do with it. Reading state and acting on it are one critical section here.
	l.mu.Lock()
	defer l.mu.Unlock()
	fresh := make(map[string]Entry, len(entries))
	for _, e := range entries {
		k := NormalizeIdentity(e.Identity)
		if k == "" {
			continue
		}
		e.Identity = k
		if strings.TrimSpace(e.UpdatedAt) == "" {
			e.UpdatedAt = now
		}
		if prev, ok := l.entries[k]; ok && strings.TrimSpace(prev.DeviceEnrolledAt) != "" {
			if e.ReenrolmentNonce <= prev.DeviceEnrolledNonce {
				// No permission newer than the one this marker was recorded under: the device is still
				// enrolled, whatever else the bundle changed about it.
				e.DeviceEnrolledAt = prev.DeviceEnrolledAt
				e.DeviceEnrolledNonce = prev.DeviceEnrolledNonce
				// ★★ AND WHICH MACHINE IT IS, FOR THE SAME REASON (2026-08-25). The bundle REPLACES this
				// ledger, so a control plane that has not yet been told about a machine — the poll after an
				// enrolment, or a deployment upgraded mid-flight — would silently erase the one thing that
				// tells a machine from its namesake. The deployment would go back to the ambiguous refusal
				// with nothing anywhere saying it had.
				//
				// Kept only when the incoming entry says nothing. Once the authority holds a value it is the
				// authority's, exactly like every other field here.
				if strings.TrimSpace(e.MachineRef) == "" {
					e.MachineRef = prev.MachineRef
				}
			} else {
				log.Printf("enrolled_inventory: %q may enrol again — the control plane has granted "+
					"re-enrolment %d time(s) and this device's enrolment was recorded under grant %d",
					k, e.ReenrolmentNonce, prev.DeviceEnrolledNonce)
			}
		}
		fresh[k] = e
	}
	// ★ WHICH LOCAL ENROLMENTS THIS LIST DOES NOT CARRY. Only those a DEVICE actually enrolled against: an
	// identity an operator pre-added and no device ever used costs nobody their access when it goes, and
	// reporting those would bury the ones that do.
	var dropped []string
	for k, prev := range l.entries {
		if strings.TrimSpace(prev.DeviceEnrolledAt) == "" {
			continue
		}
		if _, still := fresh[k]; !still {
			dropped = append(dropped, k)
		}
	}
	sort.Strings(dropped)
	// ★ REPLACING MEMORY BEFORE KNOWING THE WRITE LANDED UNDID THE GUARD BELOW IT (2026-08-12, twenty-fourth
	// review). The persister refuses to overwrite another process's change — and this swapped `l.entries`
	// first and then discarded the error, so the marker survived on DISK and vanished from THIS process. An
	// issuing node would then hand out a certificate for an identity the file says is spent, which is the
	// failure the refusal exists to prevent, arriving one layer above it.
	previous := l.entries
	l.entries = fresh
	l.generation.Add(1)
	if err := l.persistCheckedLocked(); err != nil {
		l.entries = previous
		l.generation.Add(1)
		// Nothing was dropped: the state was put back. Reporting a loss that did not happen would send an
		// operator hunting for devices that are still admitted.
		return nil, fmt.Errorf("the control plane's inventory was NOT applied (%w): this node keeps the state it "+
			"had, because a merge it cannot record is a merge another process would overwrite it back out of", err)
	}
	return dropped, nil
}

// ReplaceAll overwrites the inventory wholesale. Callers applying a CONTROL PLANE copy want
// MergeAuthoritative instead — see the note there about what this erases.
func (l *Ledger) ReplaceAll(entries []Entry, now string) {
	if l == nil {
		return
	}
	fresh := make(map[string]Entry, len(entries))
	for _, e := range entries {
		k := NormalizeIdentity(e.Identity)
		if k == "" {
			continue
		}
		e.Identity = k
		if strings.TrimSpace(e.UpdatedAt) == "" {
			e.UpdatedAt = now
		}
		fresh[k] = e
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = fresh
	l.generation.Add(1)
	l.persistLocked()
}

// List returns the ledger entries sorted by identity (stable response).
func (l *Ledger) List() []Entry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		// ★★★ TOMBSTONES ARE NOT DEVICES. This feeds every screen and every readiness sweep that asks "which
		// machines does this deployment have"; a removed one appearing there would undo the removal in the
		// only place an operator looks. What carries them is Authoritative, and only the config bundle calls
		// it.
		if e.isTombstone() {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// Authoritative is List plus the removals, and it is what the control plane puts in the config bundle.
//
// ★★★ AN ABSENCE CANNOT TRAVEL. The bundle REPLACES an Edge's ledger, and a receiving Edge treats an entry
// that is simply missing as "the control plane has not told me about this yet" — deliberately, because
// wiping admission from a short list is how a fleet locks itself out. So a removal has to arrive as
// something, and this is that something.
func (l *Ledger) Authoritative() []Entry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// NormalizeMachineRef trims and lower-cases a declared machine reference. Nothing else: the value is opaque to
// this deployment — a Windows MachineGuid, a hardware UUID, whatever the platform can produce stably — and
// rewriting it further would make two agents reporting the same machine disagree.
func NormalizeMachineRef(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// identityForMachineLocked finds the identity this machine is already enrolled under, other than `except`.
// Only enrolled entries count: an identity an operator pre-added has no machine behind it, and a tombstone is
// a machine that was removed — neither is a name this one is "already using".
func (l *Ledger) identityForMachineLocked(machineRef, except string) (string, bool) {
	if machineRef == "" {
		return "", false
	}
	for id, e := range l.entries {
		if id == except || strings.TrimSpace(e.RemovedAt) != "" {
			continue
		}
		if strings.TrimSpace(e.DeviceEnrolledAt) == "" {
			continue
		}
		if NormalizeMachineRef(e.MachineRef) == machineRef {
			return id, true
		}
	}
	return "", false
}

// alreadyEnrolledReasonLocked says WHICH of the two identical-looking cases this is.
//
// ★ SILENCE ON EITHER SIDE MEANS THE DEPLOYMENT STILL CANNOT TELL. An agent too old to report a machine
// reference, or an entry enrolled before this existed, leaves exactly the ambiguity the combined sentence was
// written for — so that sentence stays, and is used precisely when it is true.
func (l *Ledger) alreadyEnrolledReasonLocked(e Entry, machineRef string) error {
	known := NormalizeMachineRef(e.MachineRef)
	if machineRef == "" || known == "" {
		return ErrIdentityAlreadyEnrolled
	}
	if known == machineRef {
		return ErrSameMachineAlreadyEnrolled
	}
	return ErrDifferentMachineSameName
}

// RecordReportedMachine records what an ISSUING node said about the machine behind an identity. It is the
// authority's copy of Entry.MachineRef.
//
// ★★★ A REPORTED FIELD WITH NO READER IS A FIELD THAT VANISHES. The Edge that issues a certificate learns the
// machine reference and reports it; the control plane rebuilds every Edge's ledger from ITS copy, so a control
// plane that did not store it would erase the value at the next bundle — and the deployment would go back to
// not being able to tell a machine from its namesake, with nothing anywhere saying so. This deployment has
// found that shape twice in two days; the reader is written with the writer.
//
// It never creates an identity and never enables one: it fills in a fact about an identity the caller has
// already been allowed to record, and only when the fact is not already known. An issuing node cannot use this
// to rewrite which machine a name belongs to.
func (l *Ledger) RecordReportedMachine(id, machineRef, now string) error {
	k := NormalizeIdentity(id)
	ref := NormalizeMachineRef(machineRef)
	if k == "" || ref == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[k]
	if !ok || strings.TrimSpace(e.RemovedAt) != "" {
		return nil
	}
	if NormalizeMachineRef(e.MachineRef) != "" {
		// Already known. Two issuers reporting different machines for one name is a real disagreement and the
		// FIRST answer stands: the alternative is a later report quietly rewriting which machine owns a name.
		if NormalizeMachineRef(e.MachineRef) != ref {
			log.Printf("enrolled_inventory: %q was reported for a different machine than the one recorded — "+
				"keeping the recorded one; an administrator permitting re-enrolment is what releases a name", k)
		}
		return nil
	}
	before := e
	e.MachineRef = ref
	e.UpdatedAt = now
	l.entries[k] = e
	l.generation.Add(1)
	if perr := l.persistCheckedLocked(); perr != nil {
		l.entries[k] = before
		l.generation.Add(1)
		return fmt.Errorf("the reported machine reference could not be recorded durably: %w", perr)
	}
	return nil
}
