package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tenant_transport_material_fetch.go — an Edge assembles its per-organization transport identity from the
// control plane instead of from files somebody placed on the host.
//
// ★★★ THIS IS WHAT LETS THE FLEET GROW (decided 2026-08-20). Before it, every organization's transport
// certificate was a file: measured on this repository's own scale-out definition, a node added under load
// carried none of them, refused to join, and — until the guard landed — rewrote what the fleet had promised
// devices on its way past.
//
// ★ WHAT ARRIVES IS SHORT-LIVED, SO THIS RUNS AGAIN. Material is refreshed well before it expires; a node
// that cannot reach the control plane keeps serving what it has until then and says so, rather than falling
// back to a certificate that is not the organization's.
//
// restart-durability: ephemeral — held/expiry/installedAt/generation are this process's record of what it is
// currently serving and when that runs out. A restart drops them all, and the start-up fetch runs with
// known_generation=0, so the control plane sends everything and they are rebuilt from the certificates that
// arrive. Until that first fetch succeeds the deadline is simply unknown, which the loop already treats as
// "ask at the ordinary one-minute cadence" rather than as "nothing expires". Nothing an operator reads is
// served from here; the certificates themselves are held by transportTenantCertificates, which declares its
// own durability.
//
// populated-by: hydrated — every entry comes from a /tenant-edge-material response and is refreshed on each
// poll, so a node that starts with nothing converges on the next fetch without an operator doing anything.
// The one thing that does NOT re-hydrate on its own is an entry for material that is still being served but
// failed to install: it is kept from the previous round on purpose (see recordHeld), because the certificate
// under it is still the one on the wire.
type tenantTransportMaterialFetcher struct {
	trustDistributions *tenantTrustDistributionCache
	// installedTenants is how many organizations the LAST fetch actually carried. It exists because a control
	// plane that is still assembling answers 200 with an empty set, which is indistinguishable from "this
	// deployment has no organizations" unless somebody counts.
	installedTenants atomic.Int64
	// lastAnswer is the set of organizations the control plane's last SUCCESSFUL, non-empty answer named —
	// what it handed over plus what it refused by name. nil until one arrives, and never replaced by an empty
	// one, because "the answer carried nothing" is not "the deployment has no organizations".
	//
	// ★★★ THE NODE HAD THIS IN ITS HANDS AND KILLED ITSELF ANYWAY (2026-09-07). The start-up promise guard
	// refuses over a name whose organization it holds no certificate for, because it cannot tell "the name is
	// gone" from "I am behind". A successful answer that does not mention the organization AT ALL settles
	// exactly that question, and it had already been logged one line above the refusal:
	//
	//	tenant_edge_material installed: transport for 20 organization(s) …
	//	REFUSING TO JOIN THIS FLEET: … 18 promise(s) …
	//
	// all eighteen of them organizations the operator had deleted. See fleetPromisesThisNodeCannotKeep.
	lastAnswer atomic.Pointer[map[string]bool]

	endpoint string
	// dataURL is where the authority currently is on the DATA plane, per region, or "" on a deployment that
	// has only one. Consulted on EVERY fetch — see currentEndpoint.
	dataURL func() string
	token   string
	client  *http.Client
	tenants func() []string
	log     func(string, ...any)
	// loadDeviceIdentity installs one organization's device-issuing authority, so POST /enroll can answer for
	// it. nil on a node that does not enrol.
	loadDeviceIdentity func(tenantDeviceMaterial) error
	// fatal ends this process. Separated so the expiry behaviour can be exercised in a test without taking
	// the test binary with it.
	fatal  func(string, ...any)
	expiry time.Time
	// held records, per (purpose, organization), when the material this node is SERVING runs out. See
	// recordHeld: the aggregate deadline comes from here and not from whatever arrived last.
	heldMu sync.Mutex
	held   map[string]time.Time
	// wake is how an install tells the expiry watcher that the deadline it is sleeping against has moved.
	wakeMu sync.Mutex
	wake   chan struct{}
	// installedAt is when the material this node holds was installed, so its remaining life can be read as a
	// fraction rather than assumed. See renewalDue.
	installedAt time.Time
	// announced reads what this fleet currently promises devices, so a retirement can wait for the promise to
	// be withdrawn before the certificate is dropped. Injected rather than reached for, so the ordering can be
	// exercised in a test without a trust store.
	announced func() string
	// generation is what the control plane last said its set of authorities was. Sent back on every fetch so a
	// poll costs a comparison instead of a signature per organization — see the note on the route.
	generation uint64
	// loadInterception hands the per-Edge interception tier to the engine. Nil on a node that does not
	// intercept, which is a legitimate deployment and not an error.
	loadInterception func(tenantInterceptionMaterial) error
	// afterInstall runs once material has landed, so anything DERIVED from it can be rebuilt. The agent
	// configuration is the measured case — see the note where this is called.
	afterInstall func(transport, interception, deviceIdentity int)
}

func newTenantTransportMaterialFetcher(endpoint, token string, tlsConfig *tls.Config,
	tenants func() []string) *tenantTransportMaterialFetcher {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.TrimSpace(token) == "" {
		return nil
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	// ★ THE FLAG IT RIDES ON IS A FULL URL, NOT A BASE. -audit-ingest-url names the audit endpoint itself, so
	// appending here produced …/audit-ingest/tenant-transport-material and a 404 that read like a missing
	// route rather than a mis-built URL. Take the base back off it.
	base := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	base = strings.TrimSuffix(base, "/audit-ingest")
	return &tenantTransportMaterialFetcher{
		endpoint: base + "/tenant-edge-material",
		dataURL:  controlChannelCurrentDataURL,
		token:    strings.TrimSpace(token),
		client:   &http.Client{Timeout: 20 * time.Second, Transport: transport},
		tenants:  tenants,
		log:      log.Printf,
		// What the fleet currently promises. A retirement waits for this to stop naming the organization
		// before the certificate is dropped — see the note in FetchOnce.
		announced: func() string {
			if transportTrust == nil {
				return ""
			}
			return transportTrust.Announced()
		},
		fatal: log.Fatalf,
	}
}

// FetchOnce asks for material for every organization this node must serve and installs what comes back.
// Returns the soonest expiry so the caller knows when to come again.
// FetchOnce returns the soonest expiry and the error. installedTenants records how many organizations the
// control plane actually answered with, because "answered" and "answered with something" are different facts
// and a caller that cannot tell them apart accepts an empty answer as authority — see the retry in main.go.
func (f *tenantTransportMaterialFetcher) FetchOnce() (time.Time, error) {
	if f == nil {
		return time.Time{}, nil
	}
	// Empty asks for every organization this control plane holds an authority for — see the route. A node
	// that has just appeared cannot know the list, and the control plane can.
	want := f.tenants()
	// ★ THE CHEAP QUESTION IS ONLY CHEAP WHILE WHAT THIS NODE HOLDS IS STILL GOOD. Past two thirds of the
	// material's life the generation is dropped, which takes the control plane's "unchanged" path out of
	// reach and gets material minted — see renewalDue for what conflating the two cost.
	generation := f.generation
	if f.renewalDue(time.Now()) {
		generation = 0
	}
	body, err := json.Marshal(map[string]any{"tenants": want, "known_generation": generation})
	if err != nil {
		return time.Time{}, err
	}
	req, err := http.NewRequest(http.MethodPost, f.currentEndpoint(), bytes.NewReader(body))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := f.client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
	var out struct {
		TrustBundles   map[string]tenantTrustDistribution `json:"trust_bundles"`
		Materials      []tenantTransportMaterial          `json:"materials"`
		Interception   []tenantInterceptionMaterial       `json:"interception"`
		DeviceIdentity []tenantDeviceMaterial             `json:"device_identity"`
		Refused        []string                           `json:"refused"`
		Generation     uint64                             `json:"generation"`
		Unchanged      bool                               `json:"unchanged"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return time.Time{}, err
	}
	// ★ NOTHING CHANGED IS THE ORDINARY ANSWER, and it must be cheap on both sides: no material was minted,
	// nothing is installed, and this node keeps what it holds — including its expiry, which is why the
	// previous one is returned rather than a zero time (a zero would read as "no expiry known" and change how
	// often this asks).
	if f.trustDistributions != nil {
		if err := f.trustDistributions.Validate(out.TrustBundles); err != nil {
			return time.Time{}, err
		}
	}
	if out.Unchanged {
		if f.trustDistributions != nil {
			if err := f.trustDistributions.Adopt(out.TrustBundles); err != nil {
				return f.expiry, err
			}
		}
		f.generation = out.Generation
		return f.expiry, nil
	}
	// ★★★ THE GENERATION IS A CHECKPOINT, NOT A RECEIPT (2026-09-08, found by review).
	//
	// It was stored HERE, before a single material had been installed and before the refusal below was
	// judged. So a fetch that came back 200 / generation 7 / "refused: I could not find out" — no material at
	// all — recorded 7 as what this node holds. The retry then asked with known_generation=7, the control
	// plane truthfully answered "unchanged", and the retry returned SUCCESS with a zero expiry. The node had
	// nothing, believed it was current, and the start-up retry loop that exists for exactly this had been
	// answered.
	//
	// A generation means "I hold everything this generation names". It is therefore written on the success
	// path only, at the bottom of this function, and every early return below leaves the previous one in
	// place so the next ask is a full fetch.
	adoptGeneration := out.Generation
	// ★ A REFUSAL IS NOT A DETAIL. An organization this node was told to serve and cannot get material for is
	// an organization whose devices will be refused here — the fleet guard reads the same fact and stops this
	// node from joining, so the reason has to be in the log next to it.
	notEvidence := ""
	for _, reason := range out.Refused {
		f.log("tenant_transport_material REFUSED by the control plane: %s", reason)
		if notEvidence == "" && transportAuthorityRefusalIsNotEvidence(reason) {
			notEvidence = reason
		}
	}
	soonest := time.Time{}
	installed := 0
	unresolved := 0
	// Which authorities this response carried for each organization, so an authority it NO LONGER carries can
	// be recognised as withdrawn rather than merely absent from a partial answer. See the withdrawal below.
	carried := map[string]map[string]bool{}
	for _, mat := range out.Materials {
		tenant := strings.ToLower(strings.TrimSpace(mat.TenantID))
		if carried[tenant] == nil {
			carried[tenant] = map[string]bool{}
		}
		carried[tenant][strings.TrimSpace(mat.AnchorPEM)] = true
	}
	for _, mat := range out.Materials {
		// ★★★ WHICH SLOT THIS MATERIAL LANDS IN IS DECIDED BEFORE IT IS INSTALLED (2026-09-08, found by
		// review). Material for an authority this node does not yet serve is ANNOUNCED and not served — a
		// rotation's overlap — so it is a different thing with a different life from the certificate on the
		// wire. Booked under one key, a healthy pending material silently replaced the deadline of the
		// active one it does not replace: an organization whose active certificate died in an hour was
		// scheduled twelve hours out, and renewalDue was false at the moment it died.
		slot := "active"
		if existing := strings.TrimSpace(anchorOfTenant(mat.TenantID)); existing != "" &&
			existing != strings.TrimSpace(mat.AnchorPEM) {
			slot = "pending"
		}
		if err := installTenantTransportMaterial(mat); err != nil {
			f.log("tenant_transport_material for %q could not be installed (%v) — this node cannot serve that "+
				"organization's name", mat.TenantID, err)
			unresolved++
			continue
		}
		installed++
		// ★ NOTHING IS BOOKED HERE FOR TRANSPORT. The install folds the lease into the effective deadline it
		// records beside the certificate, so the deadline moves when the certificate moves — through a
		// promotion, a withdrawal, or a replacement — instead of being a second copy that a transition can
		// leave behind. See transportTenantCerts.put.
		if slot == "active" {
			// ★ AND A REFUSAL LIFTS ITSELF when usable material arrives. A door taken out of service by the
			// expiry judge has to come back without anybody restarting anything — the control plane being
			// unreachable for a while is an ordinary event, not an incident requiring an operator.
			transportTenantCertificates.Allow(mat.TenantID)
		}
	}
	// ★★★ AN AUTHORITY THE CONTROL PLANE HAS STOPPED SENDING HAS BEEN WITHDRAWN (2026-09-08, found by review).
	//
	// A rotation the operator abandons leaves this node announcing an authority nobody will ever sign under:
	// the certificate stays in the pending index, its fingerprint stays in the announcement devices adopt by,
	// and its deadline stays in the expiry judgement — where, before the deadline was derived from the
	// certificate being served, it went on refusing a door that had been refreshed since.
	//
	// ★ ONLY FROM A COMPLETE ANSWER. A refusal this node could not interpret, or a round where something
	// failed to install, is not evidence that anything was withdrawn — reading an incomplete answer as a
	// withdrawal is how a deployment tears down material that is still in force. So this runs only when the
	// response carried material for that organization and nothing in the round was left unresolved.
	f.withdrawAuthoritiesTheControlPlaneNoLongerSends(out.Materials, unresolved, notEvidence)

	// ★ THE INTERCEPTION TIER, AND IT NEVER TOUCHES THIS NODE'S DISK. It is short-lived and re-fetched; writing
	// it down would leave an organization's signing material on a machine that may be gone in an hour, which is
	// the thing this whole shape exists to avoid. LoadOfflineTenantIntermediate takes PEMs and persists nothing.
	intercepted := 0
	for _, mat := range out.Interception {
		if f.loadInterception == nil {
			break
		}
		if err := f.loadInterception(mat); err != nil {
			f.log("tenant_interception_material for %q could not be loaded (%v) — this node cannot intercept "+
				"for that organization, and its traffic will not be inspected here", mat.TenantID, err)
			unresolved++
			continue
		}
		intercepted++
		f.recordHeld("interception", mat.TenantID, f.deadlineOf(mat.ChainPEM, mat.NotAfter))
	}
	// ★ THE AUTHORITY THIS NODE ENROLS AN ORGANIZATION'S DEVICES UNDER (2026-08-21). Same rule as the
	// interception tier: it is short-lived, re-fetched, and never written to this node's disk. An Edge that
	// disappears under load takes nothing with it.
	enrolling := 0
	for _, mat := range out.DeviceIdentity {
		if f.loadDeviceIdentity == nil {
			break
		}
		if err := f.loadDeviceIdentity(mat); err != nil {
			f.log("tenant_device_material for %q could not be loaded (%v) — this node cannot enrol a device for "+
				"that organization, and an enrolment token its administrator issued will be refused here",
				mat.TenantID, err)
			unresolved++
			continue
		}
		enrolling++
		f.recordHeld("device", mat.TenantID, f.deadlineOf(mat.CACertPEM, mat.NotAfter))
	}
	// ★★★ AN ORGANIZATION THE CONTROL PLANE NO LONGER KNOWS IS RETIRED IN TWO PHASES (2026-08-21, after doing
	// it in one took the deployment down).
	//
	// The problem is real: an organization was deleted and purged, the control plane holds no authority for it
	// and mints nothing further, and every Edge went on presenting its name until the material it already held
	// expired — twelve hours in which an SNI probe for a customer that no longer exists is answered with a
	// valid certificate.
	//
	// ★ BUT A NAME THIS FLEET HAS ANNOUNCED IS A PROMISE. Dropping the certificate here, in one step, made
	// every Edge stop serving the purged name while the shared announcement went on promising it — and the
	// fleet-promise guard refuses to let a node join when it cannot keep a promise the fleet has made. The
	// node killed itself for failing a promise it was one line away from withdrawing.
	//
	// So: mark it retiring (it LEAVES THE ANNOUNCEMENT and keeps being served), and drop it only once the
	// announcement no longer names it. Same order as every other withdrawal here: retract, let the serial
	// carry it, then stop.
	//
	// ★ ABSENT IS NOT THE SAME AS REFUSED. A refusal means the control plane KNOWS this organization and could
	// not hand over material this time — transient, and keeping what we hold is exactly right. Absent from
	// BOTH lists means it has no idea who that is. Only that starts a retirement. And an answer carrying no
	// material at all starts nothing: a fetch that came back empty is not evidence that the fleet is empty.
	if len(out.Materials) > 0 {
		known := map[string]bool{}
		for _, mat := range out.Materials {
			known[strings.ToLower(strings.TrimSpace(mat.TenantID))] = true
		}
		for _, reason := range out.Refused {
			for _, field := range strings.Fields(reason) {
				field = strings.Trim(strings.ToLower(field), ":\"")
				if strings.HasPrefix(field, "tenant_") {
					known[field] = true
				}
			}
		}
		// Remembered for the start-up promise guard, which asks the same question this loop asks — is this
		// organization still one of the deployment's? — about names rather than about certificates.
		f.lastAnswer.Store(&known)
		for _, served := range transportTenantCertificates.ServedTenants() {
			if known[served] {
				continue
			}
			if transportTenantCertificates.BeginRetiring(served) {
				f.log("tenant_edge_material: the control plane no longer knows %q — retracting the fleet's "+
					"promise of its name first; this node keeps serving it until the announcement has moved",
					served)
			}
		}
		// Phase two: the announcement has moved on, so the certificate may go.
		announced := ""
		if f.announced != nil {
			announced = f.announced()
		}
		for _, retiring := range transportTenantCertificates.Retiring() {
			if announced == "" || strings.Contains(announced, retiring) {
				continue
			}
			f.forgetHeld(retiring)
			if dropped := transportTenantCertificates.StopServing(retiring); dropped > 0 {
				f.log("tenant_edge_material: stopped serving %d name(s) for %q — the fleet no longer promises "+
					"them, so this node may stop answering to them", dropped, retiring)
			}
		}
	}

	// The deadline is the soonest end among everything this node is SERVING — including material it failed to
	// replace this round and is therefore still serving under the old certificate. See recordHeld.
	soonest = f.heldDeadline()
	f.noteDeadlineChanged()
	f.installedTenants.Store(int64(installed))
	f.log("tenant_edge_material installed: transport for %d organization(s), interception for %d, device "+
		"identity for %d; soonest expiry %s", installed, intercepted, enrolling, soonestString(soonest))
	// ★★★ AND WHATEVER WAS WRITTEN BEFORE THIS ARRIVED IS NOW WRONG (2026-08-22, measured to the second).
	//
	// The agent configuration an installer hands a device names the organization's transport and enrolment
	// server names, and those come from the certificates installed just above. The file is published at
	// start-up — measured, both at 21:37:02, with the publish FIRST — so it was written before any of this
	// existed and named an organization with no name. Nothing rewrote it: the only other trigger is an
	// administrator saving a policy.
	//
	// Same shape as the recovery-name announcement computed once at boot, and the same fix: republish when the
	// thing it describes arrives. Best effort and never fatal — a configuration file that is one poll stale is
	// a smaller problem than a node that will not serve because it could not write one.
	if f.afterInstall != nil {
		f.afterInstall(installed, intercepted, enrolling)
	}
	if installed == 0 && len(out.Materials) > 0 {
		return soonest, fmt.Errorf("material arrived for %d organization(s) and none could be installed", len(out.Materials))
	}
	// ★★★ A 200 CARRYING A REFUSAL IS NOT A SUCCESSFUL FETCH (2026-08-28, measured: it took two Edges down and
	// they stayed down).
	//
	// The caller already retries a first fetch for a bounded window, because a node that starts before its
	// control plane must still be able to join. That retry is driven by the ERROR this returns — and a refusal
	// arrives inside a perfectly good 200, so the loop never engaged. The node went straight to the fleet
	// guard, which correctly refused to serve a name it had no certificate for, and exited. Both Edges of a
	// region, for a leadership move that lasted seconds.
	//
	// Reported AFTER everything that did arrive is installed: holding back material this node was given, over
	// an organization it could not be told about, would turn one unanswered question into a second outage.
	//
	// Only a refusal that is NOT EVIDENCE becomes an error. "This organization has no authority" is a fact and
	// must not be retried into a different answer; "I could not find out" is the one worth waiting on, and
	// waiting is exactly what the caller's window already does.
	if notEvidence != "" {
		return soonest, fmt.Errorf("the control plane could not say what this node may serve: %s", notEvidence)
	}
	// ★★ THE EXPIRY IS RECORDED HERE, NOT ONLY BY THE CALLER (2026-08-21, measured on the reference lab).
	// Start() stored it, and the START-UP fetch — which runs in its own retry loop before Start() — did not.
	// So the loop's very first answer was "unchanged", which returns f.expiry, which was still zero, which
	// selects the one-hour branch below. Measured: a new organization's transport material sat on the control
	// plane for the better part of an hour while the node that needed it slept, on a node whose own comment
	// says it asks every minute. One assignment, in the one place that knows the answer.
	if !soonest.IsZero() {
		f.expiry = soonest
		// ★★★ WHEN, AS WELL AS UNTIL. The expiry alone cannot say how much of this material's life is left as
		// a FRACTION, and the renewal rule is a fraction — see renewalDue. Without this the node would have to
		// assume a lifetime, and a node that assumes twelve hours renews far too late on material issued for
		// one and far too often on material issued for a week.
		f.installedAt = time.Now()
	}
	// ★★★ A PARTIAL SUCCESS IS NOT A CHECKPOINT (2026-09-08, found by review). Moving the generation to the
	// success path was not enough, because a round in which ONE organization's material fails still reaches
	// that path: the other nineteen installed, so nothing returns early, and the generation was adopted with
	// a material missing. The next ask carried that generation, the control plane truthfully answered
	// "unchanged", and the organization that failed was never sent again — for as long as nothing else
	// changed at the authority.
	//
	// So the checkpoint is only taken when everything this round carried is actually in place. Otherwise the
	// node forgets the generation and asks fully next time, which costs one full response a minute and buys
	// back the only property the generation was ever for.
	if unresolved > 0 {
		f.log("tenant_edge_material: %d material(s) in this response could not be put in place, so this node "+
			"is NOT recording generation %d as held — the next ask is a full fetch, not the cheap question",
			unresolved, adoptGeneration)
		f.generation = 0
	} else {
		if f.trustDistributions != nil {
			if err := f.trustDistributions.Adopt(out.TrustBundles); err != nil {
				return soonest, err
			}
		}
		f.generation = adoptGeneration
	}
	return soonest, nil
}

// deadlineOf is when material stops being usable: the earliest end in the CHAIN it carries, and the lease the
// response states beside it, whichever comes first.
//
// ★ THE CHAIN, NOT ITS FIRST CERTIFICATE. A path fails on whichever layer runs out, and on this deployment
// the tier above the signer is the short-lived one — so reading the leaf alone lets the scheduler believe
// there is time left after the engine has already started refusing to sign.
// ★ AND THE LEASE IS A SEPARATE FACT. The control plane may hand material for less time than the certificate
// itself allows; the shorter of the two is the one this node must act on, and an unparseable lease is never
// read as "no deadline".
func (f *tenantTransportMaterialFetcher) deadlineOf(pemText, statedLease string) time.Time {
	soonest := time.Time{}
	for _, c := range parseAllCerts([]byte(pemText)) {
		if c == nil {
			continue
		}
		if soonest.IsZero() || c.NotAfter.Before(soonest) {
			soonest = c.NotAfter.UTC()
		}
	}
	if lease, err := time.Parse(time.RFC3339, statedLease); err == nil {
		if soonest.IsZero() || lease.UTC().Before(soonest) {
			soonest = lease.UTC()
		}
	}
	return soonest
}

// recordHeld notes when the material this node is now SERVING for one organization and purpose runs out, and
// forgetHeld drops it when the node stops serving it. heldDeadline is the soonest of them.
//
// ★★★ A PARTIAL UPDATE USED TO ERASE THE DEADLINE OF WHAT IT DID NOT UPDATE (2026-09-08, found by review).
//
// The soonest expiry was computed over the materials that arrived and installed IN THIS ROUND. Reproduced:
// two organizations an hour from the end, A refreshed to twelve hours, B's replacement key unusable so B goes
// on being served under the certificate that expires in an hour — and the fetcher's deadline became A's,
// twelve hours out. At the moment B's certificate died, renewalDue was false. The node had recorded the
// health of the material it managed to replace as the health of the node.
//
// So the deadline is kept per (purpose, organization) and covers what is HELD, not what arrived: a failed
// install leaves the previous entry standing, because the previous certificate is what is still being served.
func (f *tenantTransportMaterialFetcher) recordHeld(purpose, tenant string, until time.Time) {
	if f == nil || until.IsZero() {
		return
	}
	f.heldMu.Lock()
	defer f.heldMu.Unlock()
	if f.held == nil {
		f.held = map[string]time.Time{}
	}
	f.held[purpose+"|"+strings.ToLower(strings.TrimSpace(tenant))] = until
}

func (f *tenantTransportMaterialFetcher) forgetHeld(tenant string) {
	if f == nil {
		return
	}
	suffix := "|" + strings.ToLower(strings.TrimSpace(tenant))
	f.heldMu.Lock()
	defer f.heldMu.Unlock()
	for k := range f.held {
		if strings.HasSuffix(k, suffix) {
			delete(f.held, k)
		}
	}
}

// withdrawAuthoritiesTheControlPlaneNoLongerSends stops announcing an authority an organization was moving
// to, once a COMPLETE answer from the control plane no longer carries it.
//
// ★★★ A ROTATION THE OPERATOR ABANDONS USED TO LIVE ON HERE (2026-09-08, found by review). The certificate
// stayed in the pending index, its fingerprint stayed in the announcement devices adopt by, and its deadline
// stayed in the expiry judgement — where, before the deadline was derived from the certificate being served,
// it went on refusing a door that had been refreshed since.
//
// ★ ONLY FROM A COMPLETE ANSWER. A refusal this node could not interpret, or a round where something failed
// to install, is not evidence that anything was withdrawn — reading an incomplete answer as a withdrawal is
// how a deployment tears down material that is still in force.
func (f *tenantTransportMaterialFetcher) withdrawAuthoritiesTheControlPlaneNoLongerSends(materials []tenantTransportMaterial, unresolved int, notEvidence string) {
	if f == nil || unresolved != 0 || strings.TrimSpace(notEvidence) != "" {
		return
	}
	carried := map[string]map[string]bool{}
	for _, mat := range materials {
		tenant := strings.ToLower(strings.TrimSpace(mat.TenantID))
		if carried[tenant] == nil {
			carried[tenant] = map[string]bool{}
		}
		carried[tenant][strings.TrimSpace(mat.AnchorPEM)] = true
	}
	for tenant, pendingAnchor := range transportTenantCertificates.pendingAnchorsByTenant() {
		anchors, sent := carried[tenant]
		if !sent || anchors[strings.TrimSpace(pendingAnchor)] {
			continue
		}
		if transportTenantCertificates.DropPending(tenant) {
			invalidateTrustBundlesAfterTransportMaterialChange(tenant, "an announced authority was withdrawn")
			f.log("tenant_transport_material: the authority %q was moving to is no longer sent by the control "+
				"plane — the rotation was abandoned, so this node stops announcing it. The authority in force "+
				"is unchanged.", tenant)
		}
	}
}

func (f *tenantTransportMaterialFetcher) forgetHeldKey(key string) {
	if f == nil {
		return
	}
	f.heldMu.Lock()
	defer f.heldMu.Unlock()
	delete(f.held, key)
}

func (f *tenantTransportMaterialFetcher) heldDeadline() time.Time {
	if f == nil {
		return time.Time{}
	}
	soonest := time.Time{}
	fold := func(at time.Time) {
		if at.IsZero() {
			return
		}
		if soonest.IsZero() || at.Before(soonest) {
			soonest = at
		}
	}
	f.heldMu.Lock()
	for _, at := range f.held {
		fold(at)
	}
	f.heldMu.Unlock()
	// The certificates actually being served, which is where a promotion or a withdrawal shows up.
	for _, at := range transportTenantCertificates.ActiveDeadlines() {
		fold(at)
	}
	return soonest
}

// activeDoorDeadlines is when each organization's door stops working: the certificate being served, or the
// lease the control plane put on it, whichever ends first.
func (f *tenantTransportMaterialFetcher) activeDoorDeadlines() map[string]time.Time {
	out := transportTenantCertificates.ActiveDeadlines()
	if f == nil {
		return out
	}
	f.heldMu.Lock()
	defer f.heldMu.Unlock()
	for key, at := range f.held {
		// ★ THE CERTIFICATE WINS WHERE THERE IS ONE. The book is the only evidence for an organization this
		// node was given transport material for and is NOT serving a certificate for — which is a dead door
		// and has to be counted as one, not as an organization that does not exist.
		for _, prefix := range []string{"transport|", "transport/active|"} {
			if tenant, ok := strings.CutPrefix(key, prefix); ok {
				if _, served := out[tenant]; !served {
					out[tenant] = at
				}
			}
		}
	}
	return out
}

// notAfterOfFirstCertificate reads the end of the FIRST certificate in a PEM, falling back to the value the
// response stated beside it only when there is no certificate to read.
//
// ★★★ A FIELD BESIDE A CERTIFICATE IS NOT THE CERTIFICATE'S VALIDITY (2026-09-08, found by review). The scheduler
// read mat.NotAfter — a JSON string — so a response whose leaf had already expired, carrying a not_after
// twelve hours out, set this node's renewal deadline twelve hours out while it served the dead certificate.
// The two normally agree, which is exactly why nobody would notice the day they did not.
func notAfterOfFirstCertificate(pemText, stated string) time.Time {
	if c, err := parseFirstCertificatePEM([]byte(pemText)); err == nil && c != nil {
		return c.NotAfter.UTC()
	}
	if at, err := time.Parse(time.RFC3339, stated); err == nil {
		return at.UTC()
	}
	return time.Time{}
}

// renewalDue answers whether this node should stop asking the cheap question and ask for material outright.
//
// ★★★ THE GENERATION SAYS THE AUTHORITY HAS NOT CHANGED. IT CANNOT SAY WHAT THIS NODE HOLDS IS STILL VALID
// (2026-09-08, measured on a three-region lab twelve hours after it was built, with every organization down).
//
// The two questions were conflated on 2026-08-20, when refreshing at two thirds of the material's life was
// replaced by asking every minute whether anything had changed. That made rotations arrive in a minute
// instead of eight hours, which was the point — and it silently removed the renewal it was replacing. The
// control plane's own comment beside the comparison still describes the behaviour that was taken away:
// "Edges refresh material at two thirds of a twelve-hour life."
//
// What it cost, measured to the second on every node of one deployment:
//
//	05:15:28  tenant_edge_material installed … soonest expiry 2026-09-07T17:15:28Z   (installs=1, and only 1)
//	17:15:28  every device of every organization begins failing the handshake
//
// The Edge asked its cheap question about seven hundred times in between and was told "unchanged" every time,
// which was TRUE and was not the question that mattered. It went on serving an expired certificate for hours;
// devices and connectors pin their own organization's authority and refused it, correctly, and had no way
// back until a person restarted something.
//
// So: while the material is comfortably fresh the cheap question stands. Past two thirds of its life this
// node asks for material outright, which costs one mint per organization per lifetime and leaves the last
// third as the window in which a control plane that is briefly away is survivable rather than fatal.
func (f *tenantTransportMaterialFetcher) renewalDue(now time.Time) bool {
	if f == nil || f.expiry.IsZero() || f.installedAt.IsZero() {
		// Nothing held, or held from before this node recorded when — the ordinary path already asks every
		// minute, and asking outright with nothing to compare would mint on every poll.
		return false
	}
	life := f.expiry.Sub(f.installedAt)
	if life <= 0 {
		return true // already expired when it arrived; asking again is the only useful thing left
	}
	return now.After(f.installedAt.Add(life * 2 / 3))
}

// Start fetches now and keeps the material fresh. Refreshes at two thirds of the remaining life, which is the
// same rule the device certificates use — early enough that one failed attempt is not an outage.
//
// ★★★ AND IT DECIDES WHAT HAPPENS IF THE MATERIAL RUNS OUT (2026-08-20). Short-lived material is what makes
// handing key material to a disposable node acceptable; the other half of that bargain is that the node
// stops when the material does. A node serving an expired certificate is refused by every device that
// reaches it, and it goes on being routed traffic — the same shape as a node that cannot keep the fleet's
// promises, and the same answer: be absent instead. A load balancer routes around a node that is gone.
//
// The window is generous on purpose: refresh begins at a third of the life remaining, so the control plane
// has to be unreachable for hours before this fires, and every one of those hours says so.
func (f *tenantTransportMaterialFetcher) Start() {
	if f == nil {
		return
	}
	// The expiry judgement runs on its own clock — see judgeMaterialExpiry. A fetch that hangs, or one that
	// succeeds while carrying nothing, must not be able to silence it.
	//
	// ★ AND EVERY CHANGE TO WHAT THIS NODE SERVES WAKES IT, not only a fetch: a promotion moves the deadline
	// with no material arriving at all.
	transportDeadlinesChanged = f.noteDeadlineChanged
	f.watchMaterialExpiry()
	go func() {
		for {
			expiry, err := f.FetchOnce()
			if err == nil && !expiry.IsZero() {
				f.expiry = expiry
			}
			// ★ ASK OFTEN, PAY RARELY (2026-08-20). This used to sleep two thirds of the material's life —
			// eight hours on a twelve-hour lifetime — which is also how long a rotation performed on the
			// control plane took to reach this node. It now asks every minute and is told "unchanged" almost
			// every time; material is minted only when the answer is different.
			wait := time.Minute
			switch {
			case err != nil:
				wait = f.backoffAfterFailure(time.Now(), 10*time.Minute)
				f.reportFetchFailure(err, wait)
			}
			// ★★★ AND HOLDING NOTHING IS NOT A REASON TO WAIT (2026-08-28, measured while setting a deployment
			// up). This used to sleep an HOUR when no material had a stated expiry, reasoning that a
			// deployment issuing none need not be asked often. An Edge cannot tell "this deployment issues
			// none" from "nobody has set an organization up YET" — and the second is the normal state of a
			// deployment being installed, which is exactly when organizations are created.
			//
			// Walked: the Edge fetched at 00:56 and was handed nothing, the operator created an
			// organization's PKI in the Console at 01:02, and the Edge had already decided to look again at
			// 01:56. Nothing on any screen said why the customer's own root was not being used.
			//
			// The cheap question is what makes asking often safe: known_generation is compared first and an
			// unchanged answer mints nothing. There was never a cost to pay here.
			time.Sleep(wait)
		}
	}()
}

// judgeMaterialExpiry decides what this node's material being at or past its end means, on a clock of its
// own. It returns the organizations it found expired, and whether it decided this node must leave.
//
// ★★★ THE DECISION ABOUT EXPIRY MUST NOT LIVE INSIDE THE THING THAT REFRESHES IT (2026-09-08, found by review).
//
// The expiry branches were reached only from a FAILED fetch. So the judgement stopped whenever the refresh
// stopped in any way that did not look like a failure: a fetch hanging inside its twenty-second timeout, a
// 200 carrying nothing, a refusal classified as evidence. In each case the material could pass its end with
// nothing anywhere deciding anything — which is the shape of the outage this file was already corrected for
// twice today, one level up.
//
// ★★ AND IT DOES NOT KILL A NODE FOR ONE ORGANIZATION. On a deployment
// of three regions of one machine each, exiting because ONE customer's material lapsed takes the other
// nineteen customers down with it — a strictly worse outcome than refusing that one customer's traffic. So
// an expired organization is named, loudly and repeatedly; leaving the fleet is reserved for a node that
// holds nothing usable at all, which is the case the exit was written for.
func (f *tenantTransportMaterialFetcher) judgeMaterialExpiry(now time.Time) (expired []string, leaving bool) {
	if f == nil {
		return nil, false
	}
	// ★★★ A DECISION IS APPLIED ONLY IF THE MATERIAL IT WAS TAKEN ABOUT IS STILL THE MATERIAL BEING SERVED
	// (2026-09-08, found by review). Reading the certificate and its deadline under one lock stopped them
	// disagreeing with each other; it did not stop a decision taken about both of them from being applied
	// after they had been replaced. Measured: a judge observed a one-minute certificate, a promotion put
	// twelve valid hours in its place, and the judge then refused the organization and killed the node on
	// what it had seen before.
	//
	// Bounded: material that keeps changing means this node is healthy and busy, and the next tick judges it.
	for attempt := 0; attempt < 4; attempt++ {
		read := transportTenantCertificates.Generation()
		expired, leaving = f.judgeOneGeneration(now, read)
		if transportTenantCertificates.Generation() == read {
			return expired, leaving
		}
	}
	f.log("tenant_edge_material: the material changed under every attempt to judge its expiry — nothing is " +
		"refused on this pass, and the next one judges what is in place then")
	return nil, false
}

// judgeOneGeneration is the judgement itself, about the material of one generation. It refuses and exits only
// while that generation is still the one being served; the caller re-reads and discards otherwise.
func (f *tenantTransportMaterialFetcher) judgeOneGeneration(now time.Time, read uint64) (expired []string, leaving bool) {
	// ★★★ ONE SNAPSHOT DECIDES WHAT IS SERVED AND WHAT IS AVAILABLE. Doors come from the certificates on the
	// wire; the other two lanes from what was installed. Judging a door from a book kept beside the store let
	// a promotion, a withdrawal and an expired pending each refuse a door that was working.
	doors := f.activeDoorDeadlines()
	liveDoors := 0
	refusals := map[string]string{}
	allowed := []string{}
	for tenant, at := range doors {
		if now.Before(at) {
			liveDoors++
			allowed = append(allowed, tenant)
			continue
		}
		expired = append(expired, "transport|"+tenant)
		refusals[tenant] = "its certificate expired at " + at.UTC().Format(time.RFC3339) +
			" and could not be refreshed"
	}
	// ★★★ NOTHING IS ACTED ON UNTIL THE MATERIAL IS CONFIRMED TO BE THE MATERIAL THAT WAS JUDGED. Deciding
	// and refusing in the same loop meant a promotion landing halfway through it had one organization
	// refused on the certificate it no longer serves.
	if transportTenantCertificates.Generation() != read {
		return nil, false
	}
	for _, tenant := range allowed {
		// A door that works is a door this node serves: lift any refusal left from before it did.
		transportTenantCertificates.Allow(tenant)
	}
	for tenant, why := range refusals {
		transportTenantCertificates.Refuse(tenant, why)
	}
	// The other two lanes: they stop inspection and enrolment for an organization, never its door.
	f.heldMu.Lock()
	otherHeld := 0
	for key, at := range f.held {
		if !strings.HasPrefix(key, "interception|") && !strings.HasPrefix(key, "device|") {
			continue
		}
		otherHeld++
		if !now.Before(at) {
			expired = append(expired, key)
		}
	}
	f.heldMu.Unlock()
	// ★★ AN EXPIRED PENDING AUTHORITY STOPS A PROMOTION, NOT A DOOR. It is announced and not served, and the
	// whole point of the overlap is that the organization keeps working on the authority it already has while
	// its devices adopt the next one. Refusing the active door because the material queued BEHIND it went
	// stale is the opposite of what the overlap is for.
	for tenant := range doors {
		if at, ok := transportTenantCertificates.PendingDeadlineFor(tenant); ok && !now.Before(at) {
			f.log("★ tenant_edge_material: the authority %q is moving TO expired at %s before its devices "+
				"adopted it — this node will NOT promote it, and goes on serving the authority in force",
				tenant, at.UTC().Format(time.RFC3339))
		}
	}
	sort.Strings(expired)
	if len(doors) == 0 && otherHeld == 0 {
		// Nothing held: this node runs on files or has not been given anything yet, and the fleet guard is
		// what judges that. Never an exit from here.
		return nil, false
	}
	if len(expired) == 0 {
		return nil, false
	}
	if len(doors) == 0 || liveDoors > 0 {
		f.log("★ tenant_edge_material EXPIRED: %s — the affected organizations are REFUSED at the TLS "+
			"selector rather than presented certificates their devices reject, and this node goes on serving "+
			"the other %d door(s). Nothing renews on its own past this point; the control plane has not "+
			"answered in time.", strings.Join(expired, ", "), liveDoors)
		return expired, false
	}
	if transportTenantCertificates.Generation() != read {
		return nil, false
	}
	f.fatal("tenant_edge_material EXPIRED for every door this node serves (%s) and could not be refreshed: "+
		"this node would present certificates every device refuses, so it is leaving the fleet instead. A "+
		"load balancer routes around a node that is gone; it does not route around one that is answering "+
		"wrongly.", strings.Join(expired, ", "))
	return expired, true
}

// watchMaterialExpiry runs judgeMaterialExpiry on its own timer, independent of the fetch loop.
//
// ★ THE INTERVAL IS DERIVED, NOT A CONSTANT — the rule this file was corrected by twice today. It looks
// often enough that the decision cannot be more than a small fraction of the material's life late, and it
// never sleeps past the deadline it is watching.
func (f *tenantTransportMaterialFetcher) watchMaterialExpiry() {
	if f == nil {
		return
	}
	go func() {
		for {
			now := time.Now()
			f.judgeMaterialExpiry(now)
			// ★★★ THE NEXT DEADLINE IS THE NEXT ONE STILL AHEAD (2026-09-08, found by review). Deriving the
			// interval from the SOONEST deadline meant that once one organization was past its end — which
			// is the state this loop exists to be in — the interval fell back to a flat minute, and the next
			// organization's deadline could pass unwatched inside it. And the floor could outlive what it
			// was watching: five seconds is longer than one second remaining.
			//
			// ★★★ AND THE SLEEP IS WAITED ON, NOT TAKEN (2026-09-08, found by review — twice: the first time
			// I wrote that this had been done, and it had not). time.Sleep computes an interval from what is
			// known now and then ignores everything that happens during it, so material installed a second
			// later with one minute of life is watched on an interval chosen for twelve hours. Every change
			// to what this node holds signals the channel, and the loop re-derives from scratch on waking.
			select {
			case <-time.After(f.watchInterval(now)):
			case <-f.deadlineChanged():
			}
		}
	}()
}

// watchInterval is how long the expiry watcher may sleep: a fraction of the time left before the next
// deadline still AHEAD of now, never past that deadline, and never longer than the ordinary minute.
// deadlineChanged is signalled whenever material is installed, so the watcher re-derives its interval
// instead of finishing a sleep chosen before that material existed.
func (f *tenantTransportMaterialFetcher) deadlineChanged() <-chan struct{} {
	f.wakeMu.Lock()
	defer f.wakeMu.Unlock()
	if f.wake == nil {
		f.wake = make(chan struct{}, 1)
	}
	return f.wake
}

func (f *tenantTransportMaterialFetcher) noteDeadlineChanged() {
	if f == nil {
		return
	}
	f.wakeMu.Lock()
	if f.wake == nil {
		f.wake = make(chan struct{}, 1)
	}
	ch := f.wake
	f.wakeMu.Unlock()
	select {
	case ch <- struct{}{}:
	default: // one pending wake-up is as good as many
	}
}

func (f *tenantTransportMaterialFetcher) watchInterval(now time.Time) time.Duration {
	wait := time.Minute
	next := time.Time{}
	consider := func(at time.Time) {
		if !at.After(now) {
			return
		}
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	f.heldMu.Lock()
	for _, at := range f.held {
		consider(at)
	}
	f.heldMu.Unlock()
	// ★ THE TIMER LOOKS AT WHAT THE JUDGEMENT LOOKS AT (2026-09-08, found by review). The deadline moved to
	// the certificate store and the timer went on scanning only the book, so material installed with a
	// shorter life than anything booked was watched at the ordinary cadence — the interval and the decision
	// disagreeing about when this node stops working.
	for _, at := range transportTenantCertificates.ActiveDeadlines() {
		consider(at)
	}
	if next.IsZero() {
		return wait
	}
	remaining := next.Sub(now)
	if w := remaining / 8; w < wait {
		wait = w
	}
	if wait < 100*time.Millisecond {
		wait = 100 * time.Millisecond
	}
	if wait > remaining {
		wait = remaining
	}
	return wait
}

func soonestString(t time.Time) string {
	if t.IsZero() {
		return "(none stated)"
	}
	return t.UTC().Format(time.RFC3339)
}

// auditShipTLSConfig builds the client TLS the Edge already uses to reach its control plane: the pinned CA and
// the Edge's OWN certificate.
//
// ★ THE CERTIFICATE IS NOT OPTIONAL HERE. The route on the other side hands out an organization's server
// identity and refuses a caller it cannot attribute to an Edge; sending no certificate would mean the shared
// bearer was the only control, which is the exact defect the audit path was corrected for on 2026-08-12.
func auditShipTLSConfig(caPEMFile, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p := strings.TrimSpace(caPEMFile); p != "" {
		pemBytes, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read the control plane's CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("the control plane's CA file contained no usable certificates")
		}
		cfg.RootCAs = pool
	}
	cert, key := strings.TrimSpace(clientCertFile), strings.TrimSpace(clientKeyFile)
	if cert == "" || key == "" {
		return nil, fmt.Errorf("this node has no client certificate for the control plane, and the route that "+
			"issues per-organization transport material refuses a caller it cannot attribute to an Edge "+
			"(cert=%q key=%q)", cert, key)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("read this node's control-plane client certificate: %w", err)
	}
	// ★★★ READ AT HANDSHAKE TIME, NOT ONCE AT START-UP (2026-08-20, found by running on this side the sweep the
	// Windows side ran on theirs — they found a health probe judging a region with start-up anchors and a
	// provisioning-time identity, and asked whether we had the same shape).
	//
	// This identity is what the control plane binds every record to, and it is also what this node presents to
	// FETCH ITS MATERIAL — so a rotation rides on it. Captured once, replacing the file needs a restart, and its
	// expiry is a scheduled outage of the whole control-plane channel: audit shipping, material refresh
	// (rotations included) and revocation sync all stop while the node goes on serving.
	//
	// A handshake is not a request — connections are pooled — so this is a file read per new connection.
	var lastIdentityWarning atomic.Int64
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		fresh, ferr := tls.LoadX509KeyPair(cert, key)
		if ferr != nil {
			// Keep the one that worked rather than presenting nothing: a half-written file during a replacement
			// must not take the channel down.
			log.Printf("★ this node's control-plane client certificate could not be re-read (%v) — presenting "+
				"the one loaded at start-up", ferr)
			warnIfNodeIdentityIsEnding(&pair, &lastIdentityWarning, time.Now(), log.Printf)
			return &pair, nil
		}
		warnIfNodeIdentityIsEnding(&fresh, &lastIdentityWarning, time.Now(), log.Printf)
		return &fresh, nil
	}
	warnIfNodeIdentityIsEnding(&pair, &lastIdentityWarning, time.Now(), log.Printf)
	return cfg, nil
}

// warnIfNodeIdentityIsEnding says, at most once an hour, that the certificate this node presents to the
// control plane is close to its end.
//
// ★★★ THE WARNING USED TO BE EVALUATED ONCE, WHEN THE TLS CONFIG WAS BUILT (2026-09-08, found by measuring
// the lifetimes the installer mints). It fires inside the last fourteen days — and this certificate's life
// is ONE YEAR (cmd/dsse-install/main.go mints it with NotAfter a year out, and nothing in the tree renews
// it). A node that has been up for a year therefore reached its own end having said nothing at all: the
// fourteen days it was supposed to warn in were fourteen days it never looked.
//
// The node that most needs to say something was the one that said least. It is checked at handshake time
// now, beside the re-read that was already happening there, so a long-running node says it while there is
// still time to act — and throttled to an hour, because this runs per new connection and a pooled channel
// makes plenty of those.
func warnIfNodeIdentityIsEnding(pair *tls.Certificate, lastWarned *atomic.Int64, now time.Time, warn func(string, ...any)) bool {
	if pair == nil || len(pair.Certificate) == 0 || lastWarned == nil || warn == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	left := leaf.NotAfter.Sub(now)
	if left >= 14*24*time.Hour {
		return false
	}
	previous := lastWarned.Load()
	if previous != 0 && now.Sub(time.Unix(0, previous)) < time.Hour {
		return false
	}
	if !lastWarned.CompareAndSwap(previous, now.UnixNano()) {
		// Another handshake said it in the same instant; one line is the point.
		return false
	}
	warn("★ the certificate this node presents to the control plane expires in %s (%s). "+
		"Everything that rides that channel stops when it does: audit shipping, per-organization "+
		"material refresh — rotations included — and revocation sync. NOTHING IN THIS DEPLOYMENT RENEWS "+
		"IT: it is minted once, by the installer, for a year.",
		left.Round(time.Hour), leaf.NotAfter.UTC().Format(time.RFC3339))
	return true
}

// backoffAfterFailure is how long to wait after a refresh failed. It is the ordinary back-off, EXCEPT that it
// never outlives the material this node is holding.
//
// ★★★ A BACK-OFF LONGER THAN WHAT THE NODE HOLDS IS AN OUTAGE THIS NODE SCHEDULED FOR ITSELF (2026-09-08,
// measured on a three-region deployment while compressing the material lifetime to six minutes to walk a
// rotation).
//
// One region's Edge failed a single fetch four seconds after start-up — the peer authority EOF'd because the
// fleet was mid-roll, which is as ordinary as a failure gets. It logged, correctly and in these words:
//
//	tenant_transport_material expires in 6m0s and the control plane is not answering — this node will
//	STOP rather than serve a certificate devices refuse
//
// and then slept TEN MINUTES on six minutes of material. It did not stop, because the branch that stops is
// reached by the NEXT attempt, and the next attempt was four minutes after the end. For those four minutes
// the door served an expired certificate and every connector that reached it was refused — 72 tunnels ended
// with "x509: certificate has expired" — while the node considered itself healthy and the load balancer went
// on routing to it. The promise in that log line was not kept by the code under it.
//
// ★ THE RULE, WHICH IS THE SAME ONE renewalDue IS: A NODE'S SCHEDULE IS DERIVED FROM THE LIFE OF WHAT IT
// HOLDS, NEVER FROM A CONSTANT. Ten minutes is nothing against twelve-hour material and fatal against six
// minutes of it; the constant cannot know which it is in. Waiting at most a quarter of the remaining life
// leaves at least three more attempts before the end in every case, and the floor keeps a nearly-expired
// node from spinning. If those attempts all fail the material really is gone, and reportFetchFailure's
// expiry branch does what it says: leave, so the door routes around this node instead of into it.
func (f *tenantTransportMaterialFetcher) backoffAfterFailure(now time.Time, ordinary time.Duration) time.Duration {
	if f == nil || f.expiry.IsZero() {
		// Holding nothing has no life to be shorter than; the fleet guard is what judges such a node.
		return ordinary
	}
	remaining := f.expiry.Sub(now)
	if remaining <= 0 {
		// Already past the end: reportFetchFailure is leaving the fleet, and this interval is moot.
		return ordinary
	}
	capped := remaining / 4
	if capped >= ordinary {
		return ordinary
	}
	// A floor, so a node with seconds left does not spin — and then the rule again, because the floor is a
	// constant too and the whole defect was a constant outliving the material. Half of what is left is the
	// last interval that still leaves an attempt inside it.
	if capped < 5*time.Second {
		capped = 5 * time.Second
	}
	if capped >= remaining {
		capped = remaining / 2
	}
	return capped
}

// reportFetchFailure is the decision that follows a failed refresh: keep going, warn, or leave. Separated
// from the loop so each branch can be exercised.
func (f *tenantTransportMaterialFetcher) reportFetchFailure(err error, wait time.Duration) {
	// ★ AND THE INTERVAL SAYS WHY IT WAS CHOSEN (win-dev-1's letter 65, agreed). "Retrying shortly" is not a
	// number; a reader cannot tell a ten-minute back-off from a one-minute poll, which is exactly how the
	// hourly branch above went unnoticed. Every branch that picks a non-default interval now names it.
	//
	// ★★★ AND IT NAMES THE INTERVAL IT ACTUALLY CHOSE (2026-09-08, measured). It used to say "backing off
	// to 10m" whatever it did, which was true until backoffAfterFailure started shortening it — and a line
	// that states a constant instead of the decision is how the ten minutes went unread for a fortnight.
	f.log("tenant_transport_material fetch failed (%v) — keeping what this node already has; backing off to "+
		"%s (the ordinary poll is 1m) because the control plane is not answering", err, wait.Round(time.Second))
	if f.expiry.IsZero() {
		// Never held any: this node is running on files or on nothing, and the fleet guard is what judges it.
		return
	}
	remaining := time.Until(f.expiry)
	switch {
	case remaining <= 0:
		// ★ ONE JUDGE. This branch used to decide the exit by itself, from the soonest deadline alone, so a
		// single organization's lapse ended the process for all of them. judgeMaterialExpiry makes the same
		// decision with the whole picture — which organizations are past their end, and whether ANY usable
		// material is left — and it also runs when no fetch failed at all.
		f.judgeMaterialExpiry(time.Now())
	case remaining < time.Hour:
		f.log("tenant_transport_material expires in %s and the control plane is not answering — this node "+
			"will STOP rather than serve a certificate devices refuse", remaining.Round(time.Minute))
	}
}

func sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

// currentEndpoint is where to ask for material: the DATA-plane address of the region leadership is currently
// in, and the configured door only when there is no such list.
//
// ★★★ THE CONFIGURED DOOR CARRIES NO NAME ACROSS A REGION BOUNDARY (2026-09-01, measured on a three-region
// deployment, with a control experiment that changed nothing but the SNI).
//
// -audit-ingest-url names this machine's own control-plane door — "https://dsse-control-plane:8443" — and
// that door forwards to the other regions when the local control planes are not leading. It forwards in TCP
// passthrough, because the request carries a CLIENT CERTIFICATE and terminating the TLS would throw it away.
// So the name that arrives at the far region is the one the Edge dialled: dsse-control-plane. No region
// doorway serves that name, so the flow lands on the default backend there — the EDGE fleet — which requires
// a certificate from a device CA and answers the Edge's fleet identity with
//
//	remote error: tls: unknown certificate authority
//
// Two of three regions therefore never assembled their customers' organizations and signed every flow under
// the deployment's ONE shared root, while their customers' roots sat registered, listed, trusted by devices,
// and signing nothing.
//
// ★ AND THE DOOR REPORTED THE PEER HEALTHY THROUGHOUT. Its check dials the peer with check-sni
// admin.<region>, a name that region does serve; the traffic beside it carries no name at all. A check that
// uses a different name from the traffic it is checking is not measuring that traffic. The `sni str(...)`
// written on those server lines is inert without `ssl`, which cannot be set here for the reason above — so
// the door is the wrong place to fix this, and the address the node dials is the right one.
//
// The per-region list is already in hand: it follows the same leadership decision as the read path, and it
// names each region's authority door, which does serve /tenant-edge-material.
func (f *tenantTransportMaterialFetcher) currentEndpoint() string {
	if f == nil {
		return ""
	}
	if f.dataURL != nil {
		if base := strings.TrimRight(strings.TrimSpace(f.dataURL()), "/"); base != "" {
			return base + "/tenant-edge-material"
		}
	}
	return f.endpoint
}

// OrganizationIsGone answers whether the control plane's last successful answer did not mention this
// organization at all. False when no such answer has arrived — absence of an answer is not a withdrawal, the
// rule this repository has now applied to a device ledger, a tenant store, a revocation list, a trust bundle
// and an announcement.
func (f *tenantTransportMaterialFetcher) OrganizationIsGone(tenant string) bool {
	if f == nil {
		return false
	}
	answer := f.lastAnswer.Load()
	if answer == nil || len(*answer) == 0 {
		return false
	}
	return !(*answer)[strings.ToLower(strings.TrimSpace(tenant))]
}
