package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// verify.go — the installer checking that the deployment it described actually works.
//
// ★★★ WHY THE INSTALLER DOES THIS (2026-08-23). An installer has to stand a deployment up on its own, with
// nobody looking over its shoulder — so the checking that would otherwise be done by whoever happens to be
// watching belongs in the tool. Every finding in this file was found by hand, once, by walking the procedure;
// a finding that is only ever found by hand is found again by the next person, on their deployment.
//
// So this is not a smoke test. It asserts the things the architecture calls invariants, in the order they can
// fail, and it says which one failed rather than "the deployment is unhealthy":
//
//	1. the control plane answers at all
//	2. it can be ADMINISTERED — a new deployment where nothing can authenticate is the failure mode that does
//	   not announce itself
//	3. the Edge answers
//	4. the Edge has APPLIED configuration from the control plane. Not "reached it": a refused pull leaves the
//	   Edge running on what it booted with, healthy on every screen, enforcing something nobody authored
//	5. a device can enrol, end to end, and the same token cannot be used twice — which is the one-time
//	   property, and it is decided by the control plane rather than by the Edge
//
// ★ IT REFUSES TO GUESS. Every check names what it looked at and what it got. A check that cannot run says so
// and fails; "could not tell" is never reported as a pass, because a deployment that cannot be checked is
// exactly the one nobody checks again.

type verifyResult struct {
	name string
	ok   bool
	note string
	// ★★★ A THIRD STATE, BECAUSE THE OTHER TWO BOTH LIE HERE (2026-09-04). A fresh deployment has no CUSTOMER
	// organization yet — populate creates those — and approving a device for the OPERATOR's own organization is
	// exactly what the product refuses, so the enrolment path cannot be exercised at install time. Counting that
	// as a failure makes -verify unpassable on every new deployment; counting it as a pass is a green that
	// measured nothing, which is the failure this repository keeps recording. So it is neither: printed as
	// "n/a", excluded from the failure count, and named in the summary so the operator knows what was NOT
	// answered and where it gets answered.
	skipped bool
}

// verifyDeployment runs the checks against a running deployment and returns them in order. cpAdmin and
// edgeTransport are the URLs the operator started; dir is where the installer's material lives.
func verifyDeployment(dir, cpAdmin string, edgeAdmins []string, edgeTransport, adminToken string, cpPeers []string, noWait bool) []verifyResult {
	// The first Edge is the one the single-node questions are asked of; the whole list matters wherever a
	// front door may pick any of them.
	edgeAdmin := ""
	if len(edgeAdmins) > 0 {
		edgeAdmin = strings.TrimRight(strings.TrimSpace(edgeAdmins[0]), "/")
	}
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) bool {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
		return ok
	}

	client, err := deploymentClient(dir)
	if err != nil {
		add("the deployment's anchor is readable", false, "%v", err)
		return out
	}
	add("the deployment's anchor is readable", true, "%s", filepath.Join(dir, "deployment-anchor.pem"))

	// ★★★ ADMINISTER WHERE LEADERSHIP IS. See verify_writes_go_to_the_leader.go: a block accepted by a standby
	// never reaches the fleet, and this walk is told a URL and believes it.
	leader, preferredLeads := leaderAmong(client, cpAdmin, cpPeers)
	out = append(out, verifyAdministrationReachesTheLeader(cpAdmin, leader, preferredLeads)...)
	cpAdmin = leader

	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		add("deployment.env is readable", false, "%v", err)
		return out
	}
	token := strings.TrimSpace(env["ADMIN_TOKEN"])
	if !add("deployment.env carries the admin credential", token != "", "ADMIN_TOKEN") {
		return out
	}

	// 1. The control plane answers.
	// ★★★ A DEPLOYMENT THAT WAS STARTED SECONDS AGO IS NOT A DEPLOYMENT THAT IS DOWN (2026-08-26, found by
	// following the printed order: start it, then check it). The front door needs its backends to pass a
	// health check before it will accept anything, so checking immediately got an EOF and this walk stopped
	// on its first question — reporting a deployment that was fine forty seconds later as one whose control
	// plane does not answer. Every check after it was skipped, so the operator saw one failure and no walk.
	//
	// Waited for, bounded. Still not answering after that is reported exactly as before, with the same
	// reasoning about where leadership might be.
	code, _, err := waitForTheControlPlaneToAnswer(client, cpAdmin, initialReadinessWait(120*time.Second, noWait))
	if err != nil || code != 200 {
		// ★ AND THE MOST LIKELY REASON IT DOES NOT, ON A DEPLOYMENT THAT SPANS REGIONS (2026-08-25, measured
		// by moving leadership). A region's door fronts ITS OWN control planes and routes to whichever is the
		// leader — so when leadership is in another region, this door has no healthy backend and the
		// connection is simply refused. Nothing is down. Reading "connection refused" as "the deployment is
		// down" after a failover is the wrong conclusion at the worst moment, so the possibility is named.
		add("the control plane answers", false,
			"%s/healthz -> %d %v. If this deployment spans regions, leadership may be in ANOTHER one: a "+
				"region's door fronts only its own control planes, and routes to the leader among them. Ask "+
				"the region that currently answers GET /leader with 200",
			cpAdmin, code, err)
		return out
	}
	add("the control plane answers", true, "%s/healthz", cpAdmin)

	// 2. It can be administered — and WHAT THAT MEANS DEPENDS ON WHERE THE DEPLOYMENT IS.
	//
	// ★★★ THE CHECK MUST NOT DEPEND ON THE CREDENTIAL THAT IS SUPPOSED TO GO AWAY (2026-08-23, found by
	// closing the circle and watching this fail). Before there is a named administrator, the break-glass
	// credential is the only thing that can authenticate and the deployment is unusable without it. After
	// there is one, that same credential MUST be refused — and a check that reads success as "break-glass
	// works" would fail exactly when the deployment became correct, teaching whoever runs it to ignore the
	// result or to re-arm.
	//
	// So the assertion flips with the marker, because the requirement does.
	_, markerErr := os.Stat(runtimePath(dir, adminBootstrappedMarker))
	bootstrapped := markerErr == nil
	code, _, err = get(client, cpAdmin+"/admin/config-bundle", token)
	if bootstrapped {
		if code == 200 {
			add("the break-glass credential is no longer accepted", false,
				"this deployment has a named administrator (%s) and -admin-token STILL authenticates: the "+
					"control plane is running with it armed, so every act is attributed to a synthetic owner "+
					"rather than to a person. Restart it — the start script no longer arms anything",
				adminBootstrappedMarker)
			return out
		}
		add("the break-glass credential is no longer accepted", true,
			"answered %d, and this deployment has a named administrator", code)
	} else {
		if err != nil || code != 200 {
			add("the control plane can be administered", false,
				"GET /admin/config-bundle -> %d. A NEW deployment has no named principals and no API tokens, "+
					"so nothing can authenticate — not an administrator, and not an Edge pulling its "+
					"configuration. start-control-plane.sh arms the break-glass credential while %s is absent",
				code, adminBootstrappedMarker)
			return out
		}
		add("the control plane can be administered", true,
			"with the break-glass credential, which is what a deployment with no administrator has")
	}

	// ★★★ AND IT IS NOT STILL BEING ADMINISTERED BY NOBODY. A deployment whose break-glass credential is armed
	// is administrable — that is the point of it — but every act is attributed to a synthetic principal rather
	// than to a person, and the credential authorises as owner. It exists to break the circle a new deployment
	// starts in, not to be the way the deployment runs.
	//
	// Checked HERE rather than left to a note, because a deployment is handed over once and this is the moment
	// somebody is looking. The marker is what the start script reads, so this asks the same question it does.
	if !bootstrapped {
		add("the deployment has a named administrator", false,
			"%s is absent, so start-control-plane.sh is still arming the break-glass credential: this "+
				"deployment is administered by a synthetic owner and every act is attributed to nobody. Run "+
				"dsse-install -bootstrap-admin, then restart the control plane",
			runtimePath(dir, adminBootstrappedMarker))
	} else {
		add("the deployment has a named administrator", true, "%s", runtimePath(dir, adminBootstrappedMarker))
	}

	// 3. The Edge answers.
	if code, _, err := get(client, edgeAdmin+"/healthz", ""); err != nil || code != 200 {
		add("the Edge answers", false, "%s/healthz -> %d %v", edgeAdmin, code, err)
		return out
	}
	add("the Edge answers", true, "%s/healthz", edgeAdmin)

	// ★★★ THE INVARIANTS, MEASURED DIRECTLY (2026-08-23). Everything else here checks BEHAVIOUR — that the
	// deployment did something correctly today. Behaviour is a consequence of the architecture rather than the
	// architecture itself, and a handover decision needs to know the deployment is the right SHAPE.
	//
	// These are asked of the running nodes, not read off a compose file, because the file is not what is
	// running and is not available to whoever is checking a deployment somebody else stood up.

	// Invariant: the control plane holds the deployment's durable shared state; an enforcement Edge holds none.
	// An Edge with a database will grow answers the control plane does not have — which is the invariant below
	// it, one step earlier.
	if role, holdsDB, ok := nodeShape(client, cpAdmin); !ok {
		add("the control plane reports what it is", false, "%s/healthz did not say", cpAdmin)
	} else if role != "control-plane" {
		add("the control plane is a control plane", false,
			"%s reports role=%q — an Edge is standing where the authority should be", cpAdmin, role)
	} else if !holdsDB {
		add("the control plane holds the deployment's database", false,
			"it reports holding none. The durable shared state has to live somewhere, and every node that is "+
				"not the control plane is a node that comes and goes")
	} else {
		add("the control plane holds the deployment's database", true, "role=control-plane")
	}

	if role, holdsDB, ok := nodeShape(client, edgeAdmin); !ok {
		add("the Edge reports what it is", false, "%s/healthz did not say", edgeAdmin)
	} else if role == "control-plane" {
		add("the Edge is an Edge", false, "%s reports role=control-plane", edgeAdmin)
	} else if holdsDB {
		add("the Edge holds no database", false,
			"it reports holding one. An Edge comes and goes, so state that lives only there is lost with it — "+
				"and a node with a database grows answers the control plane does not have")
	} else {
		add("the Edge holds no database", true, "it reports none, and takes its configuration from the control plane")
	}

	// 4. The Edge has APPLIED configuration from the control plane.
	//
	// ★ APPLIED, NOT REACHED. A refused pull is logged and the Edge keeps running on what it booted with — it
	// stays healthy on every screen while enforcing configuration nobody authored. Walking this by hand, the
	// Edge sat in exactly that state for several minutes and looked fine.
	// ★★★ A DEPLOYMENT THAT WAS STARTED A MOMENT AGO IS NOT A BROKEN ONE (2026-08-26, found by following the
	// printed procedure: start it, then check it). An Edge's first pull is a poll away, so checking
	// immediately reported "the Edge is up and has applied NOTHING from the control plane" — a finding whose
	// wording tells the reader their Edge is enforcing what nobody authored, on a deployment that was fine
	// forty seconds later.
	//
	// Waited for, not assumed: still false after the wait is still a failure, and it now means what it says.
	// The bound is short enough that a genuinely refused pull is not sat through.
	if !add("the Edge has applied the control plane's configuration",
		becomesTrueWithin(func() bool { return edgeAppliedConfig(client, edgeAdmin) }, initialReadinessWait(90*time.Second, noWait)),
		"healthz reports an applied generation") {
		out[len(out)-1].note = "the Edge is up and has applied NOTHING from the control plane. A refused pull " +
			"leaves it enforcing what it booted with, and it stays healthy while doing so"
		return out
	}

	// Invariant: an Edge holds no answer the control plane does not have. Measured as the version it is
	// serving against the version the control plane is publishing.
	//
	// ★ A GENERATION AND ITS EPOCH ARE ONLY COMPARABLE TOGETHER. A control plane recomputes its generation
	// from its stores on restart, so the number can come back LOWER than what it last published — the epoch is
	// what says "these two numbers are about the same run". Comparing the numbers alone reports a fleet as
	// behind when it is simply looking at a control plane that restarted, which is a false alarm this
	// deployment has raised before.
	// ★★★ A CHECK THAT CANNOT RUN MUST STILL SAY SO (2026-08-23, found by verifying a CLOSED deployment).
	// Both this and the authority probe below used to emit NOTHING when the credential could not read or
	// write. The summary then counted ten checks instead of fifteen and said the deployment was fine apart
	// from one — and the three that were never measured left no trace at all.
	//
	// The direction is what makes it bad: the credential stops working exactly when the deployment is CLOSED,
	// which is the state it is handed over in. So the moment a deployment became finished, it quietly stopped
	// being checked, and the output looked cleaner for it.
	cpGen, cpEpoch, cpGenOK := controlPlaneGeneration(client, cpAdmin, token, adminToken, bootstrapped)
	if !cpGenOK {
		add("the Edge holds the control plane's current configuration", false,
			"could not be checked: the control plane would not tell this credential which generation it is "+
				"publishing. Pass -admin-token with a named API token, or run this before -bootstrap-admin")
	}
	if cpGenOK {
		// ★ BEHIND FOR ONE POLL IS NOT MISCONFIGURED (2026-08-23, found by running this twice). Configuration
		// travels on a poll, so an Edge is briefly behind after ANY change — including a change this check
		// itself made a moment ago by issuing an enrolment token. Reporting that as a failure would make the
		// second run of a passing check fail, which is how a check gets ignored.
		//
		// So it waits, bounded. Staying behind is the real defect and it still fails; catching up is what the
		// deployment is supposed to do and it is given the time to.
		edgeGen, edgeEpoch := edgeAppliedGeneration(client, edgeAdmin)
		for waited := 0; edgeGen < cpGen && waited < generationCatchUpWait; waited += 5 {
			time.Sleep(5 * time.Second)
			edgeGen, edgeEpoch = edgeAppliedGeneration(client, edgeAdmin)
		}
		switch {
		case edgeEpoch != "" && cpEpoch != "" && edgeEpoch != cpEpoch:
			add("the Edge holds the control plane's current configuration", true,
				"not comparable yet: the control plane has restarted since this Edge last applied, and it "+
					"re-baselines on the next poll")
		case edgeGen >= cpGen:
			add("the Edge holds the control plane's current configuration", true,
				"generation %d", edgeGen)
		default:
			add("the Edge holds the control plane's current configuration", false,
				"the control plane is publishing generation %d and this Edge is still serving %d after %ds. "+
					"Until it catches up, what a device is told depends on which node it reached",
				cpGen, edgeGen, generationCatchUpWait)
		}
	}

	// 5. A device can enrol, and the same token cannot be spent twice.
	//
	// ★★★ THIS NEEDS A CREDENTIAL THAT OUTLIVES THE CLOSING (2026-08-23, found by closing the circle). Issuing
	// an enrolment token is a WRITE, and after the first administrator exists the break-glass credential is
	// refused — correctly. The fleet token minted for the Edges is read-scoped on purpose, so it cannot do this
	// either.
	//
	// The answer is the ORDER, not another permanent credential: verify while the deployment is still being
	// installed, then close it. That is also when somebody is looking. Afterwards a named token can be passed,
	// and with neither this reports that it could not check rather than passing — a deployment whose enrolment
	// path nobody has exercised is exactly the one where it does not work.
	// Invariant: the authority is the control plane's. An Edge that pulls its configuration must REFUSE to
	// author what the bundle replaces — a write accepted there diverges from the fleet and does not correct
	// itself, because an Edge's own divergence moves nobody's generation.
	//
	// ★ ASKED WITH A WRITE THAT WOULD FAIL ANYWAY, and read only for WHICH refusal. 409 is the guard saying
	// "the control plane authors this"; 400 or 422 would mean the guard let it through and something further
	// in objected, which is the case this exists to catch.
	writeCredential := verifyWriteCredential(adminToken, token, bootstrapped)
	if writeCredential == "" {
		add("the Edge refuses to author what the control plane owns", false,
			"could not be checked: this deployment has a named administrator, so the break-glass credential "+
				"is refused and the fleet token is read-scoped. Pass -admin-token with a named API token, or "+
				"run this before -bootstrap-admin")
	}
	if writeCredential != "" {
		probe, _ := json.Marshal(map[string]any{"site_id": "dsse-install-verification", "name": "verification"})
		code, body, err := post(client, edgeAdmin+"/admin/sites", writeCredential, probe)
		switch {
		case err != nil:
			add("the Edge refuses to author what the control plane owns", false, "could not ask: %v", err)
		case code == 409:
			add("the Edge refuses to author what the control plane owns", true,
				"a Site write answered 409 — the authority is the control plane's")
		case code == 401:
			add("the Edge refuses to author what the control plane owns", false,
				"the probe was refused for AUTHENTICATION (401), so the authority guard was never reached and "+
					"this says nothing about it. An Edge needs -admin-session-authority-url to resolve a "+
					"credential the control plane issued")
		case code == 403:
			// ★ 403 IS ABOUT THE CREDENTIAL, NOT ABOUT THE DEPLOYMENT (2026-08-23). The fleet token is
			// read-scoped on purpose, so it is refused here for exactly the right reason — and reporting that
			// as a failure of the guard would be reporting a correct deployment as broken. Said as what it is:
			// the check could not run.
			add("the Edge refuses to author what the control plane owns", false,
				"not checked: the credential given may not author here (403). Pass a token with "+
					"admin.connectors.write, or run this before -bootstrap-admin, when the break-glass "+
					"credential is still the deployment's only one")
		default:
			add("the Edge refuses to author what the control plane owns", false,
				"a Site write to the Edge answered %d (%s). Accepted there, it diverges from the fleet and does "+
					"NOT correct itself: an Edge's own divergence moves nobody's generation, so nothing "+
					"re-applies until something unrelated happens to", code, first(body, 120))
		}
	}

	writeToken := strings.TrimSpace(adminToken)
	if writeToken == "" && !bootstrapped {
		writeToken = token
	}
	if writeToken == "" {
		add("the enrolment path was checked", false,
			"skipped: this deployment has a named administrator, so the break-glass credential no longer works "+
				"and the fleet token is read-scoped. Pass -admin-token with a named API token, or run this "+
				"check BEFORE dsse-install -bootstrap-admin, which is when the deployment is still being installed")
		return out
	}
	if r := verifyEnrolment(client, dir, cpAdmin, edgeAdmins, edgeTransport, writeToken); len(r) > 0 {
		out = append(out, r...)
	}
	// ★ THE SIXTH STEP OF THE INSTALL ORDER, and it needs everything above it to have worked: a Site authored
	// on the control plane, carried to an Edge, and an Edge holding the organization's device authority.
	// The log path, from both ends: the node says whether what it records is leaving, and the authority says whether
	// it is landing. Placed here because it needs the credential this function resolved.
	out = append(out, verifyLogPath(client, edgeAdmin, cpAdmin, writeToken)...)
	if r := verifyConnector(client, dir, cpAdmin, edgeTransport, edgeAdmin, writeToken, ""); len(r) > 0 {
		out = append(out, r...)
	}
	return out
}

// edgeAppliedConfig asks the Edge's own health for whether it has applied a generation.
func edgeAppliedConfig(client *http.Client, edgeAdmin string) bool {
	code, body, err := get(client, edgeAdmin+"/healthz", "")
	if err != nil || code != 200 {
		return false
	}
	var health struct {
		ConfigSync struct {
			HaveApplied bool `json:"have_applied"`
		} `json:"config_sync"`
	}
	if json.Unmarshal(body, &health) != nil {
		return false
	}
	return health.ConfigSync.HaveApplied
}

// verifyEnrolment issues a one-time token on the control plane, enrols a device against the EDGE, and checks
// the same token is refused the second time.
//
// ★ THE SECOND USE IS THE POINT. Issuing a certificate proves the path exists; refusing the second use proves
// the decision is made in ONE place. Without it a deployment can look complete and hand the same installer
// config a certificate on every Edge it happens to reach.
func verifyEnrolment(client *http.Client, dir, cpAdmin string, edgeAdmins []string, edgeTransport, token string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}
	skip := func(name string, format string, args ...any) {
		out = append(out, verifyResult{name: name, skipped: true, note: fmt.Sprintf(format, args...)})
	}

	body, _ := json.Marshal(map[string]any{"label": "installer verification", "group": "default", "expires_in_hours": 1})
	code, raw, err := post(client, cpAdmin+"/admin/enrolment-tokens", token, body)
	if err != nil || code != 200 {
		// ★★★ THIS CHECK USED TO DO THE THING THE PRODUCT NOW REFUSES (2026-09-04, found when the refusal
		// landed and the installer's own readiness check turned red on every fresh deployment).
		//
		// It approves a device to prove the enrolment path works, and with no organization named that approval
		// lands in the OPERATOR's own — the organization that administers the customers and has no devices.
		// The Edge refuses it now, correctly. So this cannot be answered at install time at all: the
		// organizations a device can belong to are created afterwards.
		//
		// Not a failure, because nothing is wrong. Not a pass, because nothing was measured.
		if code == 409 && strings.Contains(string(raw), "OPERATOR organization") {
			skip("the enrolment path was checked",
				"n/a here: a device is approved for a CUSTOMER organization, and this deployment has none yet — "+
					"they are created after it is installed. The enrolment path is proven when the first "+
					"organization's device is enrolled, not here")
			return out
		}
		if code == 403 {
			add("the enrolment path was checked", false,
				"not checked: the credential given may not issue enrolment tokens (403). Pass a token with "+
					"admin.enrollment.write, or run this before -bootstrap-admin")
			return out
		}
		add("an enrolment token can be issued", false, "POST /admin/enrolment-tokens -> %d %v", code, err)
		return out
	}
	var issued struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal(raw, &issued) != nil || strings.TrimSpace(issued.Secret) == "" {
		add("an enrolment token can be issued", false, "the control plane returned no secret")
		return out
	}
	add("an enrolment token can be issued", true, "on the control plane")

	// ★★★ A DIFFERENT IDENTITY EVERY RUN, AND IT IS CLEANED UP (2026-08-23, found by verifying twice). The
	// identity claim is a ONE-TIME decision held by the control plane — which is the property being checked —
	// so a fixed name works once and is refused for ever after with "this identity has already been enrolled
	// by another issuer". A check that only passes the first time is a check people stop running.
	deviceID := "dsse-install-verification-" + strings.ToLower(randomSecret()[:10])
	keyPEM, csrPEM, err := generateVerificationCSR(deviceID)
	if err != nil {
		add("a device can enrol", false, "could not build a request: %v", err)
		return out
	}
	enrol, _ := json.Marshal(map[string]any{
		"device_id":   deviceID,
		"eligibility": map[string]string{"mode": "token", "token": issued.Secret},
		"csr_pem":     string(csrPEM),
	})
	// ★★★ A ONE-TIME TOKEN MUST NOT BE RETRIED, AND RETRYING IT IS WHAT THE FIRST ATTEMPT AT THIS DID
	// (2026-08-26). The Edge answers 403 "invalid or missing eligibility token" until the bundle carrying the
	// token reaches it, so the obvious repair is to try again — and the first try SPENDS the token. Every
	// retry then failed for a different reason, and the Edge said so plainly in a line nobody was reading:
	//
	//	enroll_not_recorded … the identity claim could not be taken … HTTP 409
	//	— the one-time token is SPENT and cannot be reused
	//
	// So the wait happens BEFORE the token is spent, and it waits for the thing that actually has to happen:
	// the Edge applying a configuration at least as new as the one carrying this token. Both sides already
	// publish that generation, so it is a comparison rather than a guess, and the token is used exactly once,
	// at a moment when it can work.
	// ★★★ EVERY EDGE, NOT THE FIRST ONE (2026-08-26, measured: two Edges of one region reported applied
	// generations 8 and 9 at the same instant). The token is spent through the region's FRONT DOOR, which
	// picks any Edge behind it — so waiting on one and enrolling through the door lands the one-time
	// credential on whichever node happens to answer, and a node that is one poll behind refuses it. There is
	// no second attempt: the token is spent either way.
	waitForEveryEdgeToCatchUp(client, edgeAdmins, cpAdmin, token, 90*time.Second)
	// ★★★ ONE REFUSAL MAY BE RETRIED AND EXACTLY ONE: the one where the Edge says it could not ASK. An Edge
	// holds no token store; it asks the control plane through a front door, and for a few seconds after
	// leadership settles that ask reaches a node which refuses because it does not lead. The Edge now says so
	// in those words — and what it means is that the token was never judged, so it was never spent, so trying
	// again is not the mistake that retrying a verdict would be.
	//
	// Anything else is a verdict and is reported on the first reading: a spent token, an expired one, one
	// belonging to another organization. Retrying THOSE is how a one-time credential gets burned and the
	// second failure hides the first.
	deadline := time.Now().Add(90 * time.Second)
	for {
		code, raw, err = post(client, strings.TrimRight(edgeTransport, "/")+"/enroll", "", enrol)
		if err == nil && code == 200 {
			break
		}
		if !enrolmentAuthorityWasNotAsked(raw) || time.Now().After(deadline) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil || code != 200 {
		add("a device can enrol through the Edge", false, "POST /enroll -> %d %v (%s)", code, err, first(raw, 160))
		return out
	}
	add("a device can enrol through the Edge", true, "a certificate was issued")

	// ★★★ AND THEN IT USES IT. The key was generated and discarded on the line above for as long as this
	// check existed, so what was established was that the deployment can MINT an identity — never that a
	// device holding one can carry a byte.
	issuedCert := enrolledCertificatePEM(raw)
	if issuedCert == "" {
		add("the enrolled device can open the steer transport", false,
			"the enrolment answered 200 with no certificate in it: %s", first(raw, 160))
	} else {
		out = append(out, verifyDeviceCanSteer(dir, strings.TrimRight(edgeTransport, "/"), deviceID,
			[]byte(issuedCert), keyPEM))
		// ★★★ AND THEN IT CARRIES ONE. Opening the transport establishes that this identity is let in; it
		// says nothing about whether what it carries is inspected. See verify_the_deployment_decrypts.go:
		// every interception check beside this one passed on a deployment that had decrypted nothing.
		decrypted, deviceMustHold := verifyTheDeploymentDecryptsAFlow(dir, strings.TrimRight(edgeTransport, "/"),
			verifyDecryptDestination, []byte(issuedCert), keyPEM)
		out = append(out, decrypted...)
		// ★★★ AND THE DEVICE HAS TO BE TOLD WHICH ROOT THAT WAS. Inspecting under an authority a device was
		// never told to hold breaks every site on the machine at once, and both halves report healthy about
		// themselves. See verify_the_announced_root_is_the_signing_one.go.
		out = append(out, verifyTheAnnouncedRootIsTheSigningOne(dir, strings.TrimRight(edgeTransport, "/"),
			deviceMustHold, []byte(issuedCert), keyPEM)...)
		// ★★★ AND ONE TO A DESTINATION THAT ONLY EXISTS IN IPv6. Asking the Edges what they can egress is
		// what every check did until 2026-08-30, and on that day they answered ipv6=true while refusing to
		// use it for a single flow. See a_flow_to_an_ipv6_only_origin.go.
		out = append(out, verifyAFlowReachesAnIPv6OnlyOrigin(dir, strings.TrimRight(edgeTransport, "/"),
			[]byte(issuedCert), keyPEM, edgesDeclareIPv6Egress(client, edgeAdmins))...)
	}

	// The same token, again. It must be refused, and refused by the AUTHORITY rather than by this node's memory.
	code, _, _ = post(client, strings.TrimRight(edgeTransport, "/")+"/enroll", "", enrol)
	add("the same enrolment token cannot be used twice", code != 200,
		"the second use answered %d — one-time is decided in one place, or it means once per Edge", code)

	// ★★★ AND THE ONE ACT AN OPERATOR PERFORMS TO STOP A MACHINE IS PERFORMED, AGAINST THE MACHINE. A screen
	// that says "blocked" and a device that goes on steering are the same screen.
	if issuedCert != "" {
		out = append(out, verifyBlockingStopsTheDevice(dir, strings.TrimRight(edgeTransport, "/"), deviceID,
			[]byte(issuedCert), keyPEM, func() (int, error) {
				code, _, err := post(client, cpAdmin+"/admin/enrolled-devices/"+deviceID+"/disable", token, nil)
				return code, err
			}))
	}

	// And put back, which is both a property worth checking and what makes the removal check below able to
	// fail: a device still blocked from the check above is refused whatever removal does.
	if issuedCert != "" {
		out = append(out, verifyUnblockingRestoresTheDevice(dir, strings.TrimRight(edgeTransport, "/"), deviceID,
			[]byte(issuedCert), keyPEM, func() (int, error) {
				code, _, err := post(client, cpAdmin+"/admin/enrolled-devices/"+deviceID+"/enable", token, nil)
				return code, err
			}))
	}

	// ★ AND THE VERIFICATION DEVICE IS TAKEN BACK OUT. A check that leaves something behind every time it runs
	// teaches an operator to distrust the inventory, and the identity claim is permanent — so the litter is not
	// only untidy, it is a name nobody can use again. Reported rather than swallowed: a device this installer
	// created and could not remove is one somebody has to know about.
	// ★★★ 404 IS NOT "ALREADY GONE" ON A NODE THAT NEVER KNEW IT (2026-08-26, measured). The roster is
	// authored by whoever holds leadership and a standby re-reads it every fifteen seconds, so a device
	// enrolled moments ago is genuinely unknown there — and this walk is routinely pointed at whichever
	// control plane an operator named, which is a standby half the time. Accepting that 404 as a removal made
	// the NEXT check measure a device that had never been removed, and report "REMOVED and still admitted":
	// the most alarming sentence this walk can produce, for a reason that was not the product.
	//
	// So the delete is retried until the node accepts it, and a 404 that persists is reported as what it is.
	code, err = acceptedWithin(func() (int, error) {
		c, _, e := deleteAt(client, cpAdmin+"/admin/enrolled-devices/"+deviceID, token)
		return c, e
	}, 60*time.Second)
	if err != nil || (code != 200 && code != 204) {
		add("the verification device was removed", false,
			"DELETE /admin/enrolled-devices/%s -> %d %v, for a minute. It is enrolled in this deployment and "+
				"its identity cannot be reused; remove it before handing the deployment over. A 404 here means "+
				"this control plane never learned of the device — ask the one that holds leadership",
			deviceID, code, err)
	} else {
		add("the verification device was removed", true, "%s", deviceID)
		// ★★★ AND THE REMOVAL IS CHECKED AGAINST THE MACHINE, NOT AGAINST THE SCREEN. Blocking was walked
		// above; this is the other half, and it is the half that used to be unenforceable.
		if issuedCert != "" {
			out = append(out, verifyRemovalStopsTheDevice(dir, strings.TrimRight(edgeTransport, "/"), deviceID,
				[]byte(issuedCert), keyPEM))
		}
	}
	return out
}

// enrolledCertificatePEM pulls the issued certificate out of an enrolment answer. The field name is the one
// the Edge writes; anything else means the answer is not an enrolment and saying so beats a confusing
// handshake error two checks later.
func enrolledCertificatePEM(raw []byte) string {
	var body struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	return strings.TrimSpace(body.CertPEM)
}

func deleteAt(client *http.Client, url, bearer string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

// deploymentClient trusts only this deployment's own anchor.
func deploymentClient(dir string) (*http.Client, error) {
	pem, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		return nil, fmt.Errorf("read the deployment anchor: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("the deployment anchor contains no certificate")
	}
	// ★★★ AND IT UNDERSTANDS name@address EVERYWHERE, NOT ONLY AT THE FRONT DOOR (2026-08-28).
	//
	// Every mouth of this deployment is 443 and the planes are separated by NAME, so a node is reached at a
	// NAME — and a walk is often run from a machine whose resolver does not yet know that name, or from one
	// that must reach a specific node behind a name that answers from several. Written NAME@ADDRESS, this
	// dials the address and verifies the name, which is what a client whose DNS already knew would do.
	//
	// It lives in the CLIENT rather than in one check because every per-node question needs it: the front
	// door, the Edge admin surfaces, the individual control planes. Teaching one of them left the others
	// unable to reach a deployment that was answering.
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	transport.DialContext = dialWithOverrides
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}

// dialWithOverrides is the dialler every client the walk builds shares: it sends the connection to the
// address a NAME@ADDRESS argument gave, and lets TLS go on verifying the name.
func dialWithOverrides(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
	}
	if to, ok := dialOverrides[strings.ToLower(host)]; ok {
		addr = net.JoinHostPort(to, port)
	}
	return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
}

// dialOverrides is name -> address, filled from every NAME@ADDRESS argument before the checks run. TLS still
// verifies the NAME; only where the connection goes is changed.
var dialOverrides = map[string]string{}

// resolveDoorArguments strips NAME@ADDRESS out of a comma-separated list, recording the override and
// returning the plain names — so every check downstream sees ordinary URLs and needs to know nothing.
func resolveDoorArguments(list string) string {
	out := []string{}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		scheme, rest := "", entry
		if i := strings.Index(entry, "://"); i >= 0 {
			scheme, rest = entry[:i+3], entry[i+3:]
		}
		name, address, found := strings.Cut(rest, "@")
		if !found {
			out = append(out, entry)
			continue
		}
		host := name
		if h, _, err := net.SplitHostPort(name); err == nil {
			host = h
		}
		dialOverrides[strings.ToLower(host)] = address
		out = append(out, scheme+name)
	}
	return strings.Join(out, ",")
}

func get(client *http.Client, url, bearer string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

func post(client *http.Client, url, bearer string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

func readEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			// ★★★ THE FILE IS SOURCED BY A SHELL, SO ITS VALUES ARE QUOTED — and this reader trimmed only
			// double quotes (2026-08-23, found the moment the writer started quoting). The installer changed
			// the format and its OWN reader did not follow: every credential came back wrapped in apostrophes,
			// the control plane answered 401 to a token that was correct, and the check reported the
			// deployment as unadministrable. The two halves live in one tool and still drifted in one commit.
			out[strings.TrimSpace(k)] = unquoteEnvValue(strings.TrimSpace(v))
		}
	}
	return out, nil
}

// unquoteEnvValue undoes shellQuote: a single- or double-quoted value loses its wrapper, and a bare one is
// returned as it stands. It is deliberately the inverse of the writer and lives next to the reader that needs
// it, because these two drifting is what produced a correct credential being refused.
func unquoteEnvValue(v string) string {
	for _, q := range []string{"'", `"`} {
		if len(v) >= 2 && strings.HasPrefix(v, q) && strings.HasSuffix(v, q) {
			return strings.ReplaceAll(v[1:len(v)-1], `'"'"'`, "'")
		}
	}
	return v
}

func first(b []byte, n int) string {
	s := strings.ReplaceAll(string(b), "\n", " ")
	if len(s) > n {
		return s[:n]
	}
	return s
}

// generateVerificationCSR builds the request the verification device enrols with.
//
// A real key and a real CSR, because the enrolment path parses and signs one — a stub would prove the endpoint
// answers rather than that it issues. The key is discarded: nothing here keeps a credential, and the identity
// it enrols under names itself so an operator finding it in the inventory knows where it came from.
func generateVerificationCSR(deviceID string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: deviceID}}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// runVerify checks a running deployment and reports every result, passing or not.
//
// initialReadinessWait controls only startup retries. A zero wait still performs the
// probe and reports its actual result; it never turns an unanswered check into a pass.
func initialReadinessWait(normal time.Duration, noWait bool) time.Duration {
	if noWait {
		return 0
	}
	return normal
}

// ★ EVERY RESULT, NOT JUST THE FAILURES. An operator reading this is deciding whether to hand the deployment
// to somebody; a list of what was actually established is the thing that decision needs. And the exit status
// is what a script reads, so the two cannot disagree.
func runVerify(dir, cpAdmin, edgeAdmin, edgeTransport, adminToken, consoleURL, cpPeers string, noWait bool) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("-dir is required: the checks read this deployment's own anchor and credentials")
	}
	for name, v := range map[string]string{"-control-plane": cpAdmin, "-edge-admin": edgeAdmin, "-edge": edgeTransport} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required with -verify", name)
		}
	}
	// ★ -edge-admin TAKES A LIST, because one of the checks is about the FLEET (see verify_region.go). The
	// first entry is the one the single-Edge checks use; every entry is asked whether it hands devices the
	// same region map.
	// ★ NAME@ADDRESS IS RESOLVED ONCE, HERE, so every check below sees ordinary URLs. See
	// resolveDoorArguments: the connection goes to the address, TLS still verifies the name.
	edgeAdmin = resolveDoorArguments(edgeAdmin)
	edgeTransport = resolveDoorArguments(edgeTransport)
	cpPeers = resolveDoorArguments(cpPeers)
	cpAdmin = resolveDoorArguments(cpAdmin)
	consoleURL = resolveDoorArguments(consoleURL)
	edgeAdmins := []string{}
	for _, u := range strings.Split(edgeAdmin, ",") {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			edgeAdmins = append(edgeAdmins, u)
		}
	}
	if len(edgeAdmins) == 0 {
		return fmt.Errorf("-edge-admin is required with -verify")
	}
	// ★ -edge TAKES A LIST FOR THE SAME REASON -edge-admin DOES: whether the region's doorway survives losing
	// a front door is a property of the PAIR and cannot be asked of one door. The first entry is the one the
	// enrolment checks walk through.
	edgeDoors := []string{}
	for _, u := range strings.Split(edgeTransport, ",") {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			edgeDoors = append(edgeDoors, u)
		}
	}
	if len(edgeDoors) == 0 {
		return fmt.Errorf("-edge is required with -verify")
	}
	results := verifyDeployment(dir, strings.TrimRight(cpAdmin, "/"), edgeAdmins,
		edgeDoors[0], adminToken, strings.Split(cpPeers, ","), noWait)
	// The credential every check below uses: the operator's named token when they gave one, and otherwise
	// this deployment's own break-glass token — which is the only credential a deployment has before
	// -bootstrap-admin runs, and is exactly when this walk is meant to be run.
	peerToken := strings.TrimSpace(adminToken)
	if peerToken == "" {
		if env, eerr := readEnvFile(filepath.Join(dir, "deployment.env")); eerr == nil {
			peerToken = strings.TrimSpace(env["ADMIN_TOKEN"])
		}
	}
	if client, cerr := deploymentClient(dir); cerr == nil {
		results = append(results, verifyRegionAgreement(client, edgeAdmins)...)
		// ★★★ AND WHETHER EACH ONE IS STILL BEING CONFIGURED. Asked of the node, not of the fleet view: an
		// Edge refused its pulls cannot report that it is being refused. See
		// every_edge_is_still_being_configured.go — this deployment answered 68/68 while every Edge was 401.
		results = append(results, verifyEveryEdgeIsStillBeingConfigured(client, edgeAdmins)...)
		// ★ WALKED THE WAY A DEVICE WALKS IT. Announcing a region's address is a promise to present a
		// certificate for that name there, and it was kept in the region the operator was standing in and
		// nowhere else. See verify_every_region_presents_the_name_it_announces.go.
		results = append(results, verifyEveryRegionPresentsTheNameItAnnounces(dir)...)
		// ★★★ AND THE FIFTH NAME, WHICH NOTHING ELSE HERE ASKS ABOUT. Every check in this walk is performed
		// by a client that already holds a valid certificate, so none of them ever sends the recovery name —
		// and neither does any healthy device in the fleet. See
		// verify_the_way_back_reaches_the_agent_plane.go.
		results = append(results, verifyTheWayBackReachesTheAgentPlane(dir, edgeDoors)...)
		// ★★★ ONE WAIT, HERE, FOR THE THINGS A FRESH DEPLOYMENT REACHES BY ITSELF (2026-08-26). The checks
		// below ask the AUTHORITY about the fleet — which Edges have reported, what they sign under, whether
		// the database has a replica streaming. None of that is true in the first seconds, and reporting it
		// as a finding tells an operator following the printed procedure that their new deployment is broken.
		//
		// Waited for once rather than inside each check, because they all depend on the same thing: the nodes
		// having reported at least once. Still not formed after the wait is reported exactly as before.
		waitForTheFleetViewToForm(client, strings.TrimRight(cpAdmin, "/"), peerToken, initialReadinessWait(90*time.Second, noWait))
		// ★ THE THIRD TIER, ASKED OF EVERY EDGE. A fleet where each node invented its own interception root
		// looks perfectly healthy from any single node. See verify_the_deployment_inspects.go.
		// ★★★ THE CREDENTIAL IS RESOLVED ONCE, FOR EVERY CHECK (2026-08-26, found by generating a deployment
		// and following the installer's own instruction to check BEFORE closing the break-glass). Three
		// checks took the -admin-token FLAG, which at that moment is empty by definition — the operator has
		// no named token yet, which is the whole reason the break-glass exists — so they were sent
		// unauthenticated, got 401, and reported:
		//
		//	FAIL the deployment inspects — no Edge reports an interception authority, so nothing is being
		//	     decrypted anywhere in this deployment
		//
		// on a deployment that was inspecting perfectly. The same curl with the deployment's own token
		// answered 200. An instruction the product prints, that then fails, is worse than no instruction:
		// the reader believes the finding.
		results = append(results, verifyTheDeploymentInspects(client, dir, edgeAdmins, peerToken)...)
		// ★★★ AND THE OTHER HALF OF THAT QUESTION, which the check above is the opposite of: every Edge using
		// the SAME authority is fleet consistency, and every ORGANIZATION using the same one is the thing an
		// organization must never have. See verify_an_organization_can_have_its_own_tree.go.
		results = append(results, verifyAnOrganizationCanHaveItsOwnTree(client, strings.TrimRight(cpAdmin, "/"), peerToken)...)
		// ★★★ AND THE THIRD, WHICH IS THE ONLY ONE ASKED OF THE NODE THAT SIGNS. The two above are both
		// answered by nodes that AUTHOR: one by the control plane, one by every Edge about its DEFAULT
		// authority. Neither notices a deployment that holds a customer's own root, shows it on the screen,
		// hands it to their devices — and mints every leaf under the shared CA anyway, which is what this
		// deployment was doing when both of them said ok. See verify_the_edges_enforce_what_was_authored.go.
		results = append(results, verifyTheEdgesEnforceWhatWasAuthored(client, strings.TrimRight(cpAdmin, "/"),
			edgeAdmins, peerToken)...)
		// ★★★ AND WHETHER ANY DEVICE CAN JOIN THIS DEPLOYMENT AT ALL. Asked here because the answer is in the
		// deployment's own files: the endpoint installer refuses a configuration missing either of two values,
		// and a deployment that cannot supply them is healthy, green, and unjoinable. See
		// verify_an_endpoint_can_be_installed.go.
		results = append(results, verifyAnEndpointCanBeInstalled(dir)...)
		// the multi-region install order's data-plane mesh step. Not "is there a mesh" — whether the deployment can say which of the two it is.
		results = append(results, verifyMesh(client, edgeAdmins)...)
		results = append(results, verifyEgressAddressFamily(client, edgeAdmins)...)
		// the multi-region install order's control-plane failover step. Same shape as the mesh check: not "does it fail over" but "can it say which it is".
		results = append(results, verifyControlChannel(client, edgeAdmins)...)
		// ★ ASKED OF THE AUTHORITY, BECAUSE IT IS THE ONLY PLACE EVERY REGION'S EDGES ARE VISIBLE. The Edges
		// of another region are not reachable from this host, and a deployment that has silently become two
		// signing authorities is exactly a difference BETWEEN regions.
		results = append(results, verifyOneSigningAuthority(client, strings.TrimRight(cpAdmin, "/"), peerToken)...)
		results = append(results, verifyConsole(client, consoleURL)...)
		// ★★★ A DEPLOYMENT OF ONE MACHINE IS NOT ASKED WHETHER IT IS REDUNDANT (2026-09-03) — see
		// a_shape_cannot_fail_for_being_the_shape.go. It has one control plane, one copy of its state and one
		// door because that is the shape it was installed in, and reporting that as a failure teaches an
		// operator that a red -verify is normal.
		if deploymentIsASingleMachine(dir) {
			results = append(results,
				verifyResult{name: "more than one control-plane process is running", ok: true,
					note: singleMachineNote("control plane")},
				verifyResult{name: "the authority's durable state is redundant", ok: true,
					note: singleMachineNote("copy of its state")})
		} else {
			results = append(results, verifyAuthorityIsNotASinglePoint(client, strings.TrimRight(cpAdmin, "/"),
				strings.Split(cpPeers, ","))...)
			results = append(results, verifyAuthorityStateIsRedundant(client, strings.TrimRight(cpAdmin, "/"))...)
		}
		// The peers are asked with the same credential the rest of the walk resolved: the flag when one was
		// given, otherwise the deployment's own break-glass token, which is what a deployment that has not
		// been handed over yet still has.

		results = append(results, verifyAuthorityPeersAgree(client, strings.Split(cpPeers, ","), peerToken)...)
		// Asked of every control plane the operator named, plus the one they pointed at: a registry held in
		// each node's memory answers differently depending on which one the front door picked.
		results = append(results, verifyConnectorRegistryIsShared(client,
			append([]string{strings.TrimRight(cpAdmin, "/")}, strings.Split(cpPeers, ",")...), peerToken)...)
		// The same question about what this deployment has PUBLISHED — the store next door to the registry,
		// and the same failure. See verify_published_releases_are_shared.go.
		results = append(results, verifyPublishedReleasesAreShared(client,
			append([]string{strings.TrimRight(cpAdmin, "/")}, strings.Split(cpPeers, ",")...), peerToken)...)
		// And the other half: the authority holding them all says nothing about whether the Edges that must
		// ROUTE to them have heard of them. See verify_connectors_reach_the_edges.go.
		results = append(results, verifyConnectorsReachTheEdges(client, strings.TrimRight(cpAdmin, "/"),
			edgeAdmins, peerToken)...)
		// ★ FIRST AMONG THE FLEET CHECKS IN IMPORTANCE, IF NOT IN ORDER. A node on a different build makes
		// every other answer here unreliable, and its symptoms read as defects. See verify_one_build.go.
		// The architecture's canonical log: the original, on disk, on the node. See
		// verify_canonical_log_is_durable.go.
		results = append(results, verifyCanonicalLogIsDurable(client,
			append(append([]string{strings.TrimRight(cpAdmin, "/")}, strings.Split(cpPeers, ",")...), edgeAdmins...))...)
		results = append(results, verifyOneBuild(client,
			append(append([]string{strings.TrimRight(cpAdmin, "/")}, strings.Split(cpPeers, ",")...), edgeAdmins...))...)
		// A deployment of one machine has one door, for the same reason it has one control plane.
		if deploymentIsASingleMachine(dir) {
			results = append(results, verifyResult{name: "the region's doorway is not a single point", ok: true,
				note: singleMachineNote("doorway")})
		} else {
			results = append(results, verifyFrontDoorPair(client, edgeDoors)...)
		}
		// ★★★ AND WHERE THE ANSWERS ABOVE CAME FROM. Half of this walk is about NODES, and a deployment
		// presents no name that reaches one. See the_fleet_has_no_address.go.
		results = append(results, verifyTheFleetWasAskedWhereProductionAnswers(edgeAdmins, cpPeers)...)
		// ★★★ AND WHETHER THE AUTHORITY CAN SURVIVE LOSING A PLACE. Everything above is about what answers
		// now; this is the only question about what happens when one of them stops. See
		// verify_the_store_can_lose_a_place.go — two voting members is a working deployment that cannot lose
		// one, and it looks exactly like three from every other angle.
		if storeEnv, eerr := readEnvFile(filepath.Join(dir, "deployment.env")); eerr == nil {
			results = append(results, verifyTheStoreCanLoseAPlace(dir, storeEnv)...)
		}
	}

	failed, skipped := 0, 0
	fmt.Printf("dsse-install -verify: %s\n\n", dir)
	for _, r := range results {
		mark := "ok  "
		switch {
		case r.skipped:
			mark, skipped = "n/a ", skipped+1
		case !r.ok:
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("  %s  %-52s %s\n", mark, r.name, r.note)
	}
	fmt.Println()
	if skipped > 0 {
		fmt.Printf("dsse-install -verify: %d check(s) could not be answered here and are marked n/a above — "+
			"read them, because a deployment that is 'ready' with an unanswered check is ready only for the "+
			"things that were asked.\n", skipped)
	}
	if failed > 0 {
		fmt.Printf("dsse-install -verify: %d of %d checks failed — this deployment is NOT ready to be handed over.\n",
			failed, len(results))
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Printf("dsse-install -verify: %d checks passed — the control plane holds the authority, the Edge is "+
		"applying it, and a device can enrol exactly once.\n", len(results))
	return nil
}

// nodeShape asks a node what it is. Unauthenticated on purpose — these are structural facts, and a check that
// needed a credential could not run at the moment a deployment is being handed over with its break-glass
// credential already closed.
func nodeShape(client *http.Client, adminURL string) (role string, holdsDatabase bool, ok bool) {
	code, body, err := get(client, strings.TrimRight(adminURL, "/")+"/healthz", "")
	if err != nil || code != 200 {
		return "", false, false
	}
	var health struct {
		Role          string `json:"role"`
		HoldsDatabase bool   `json:"holds_database"`
	}
	if json.Unmarshal(body, &health) != nil || strings.TrimSpace(health.Role) == "" {
		// A node that does not report its shape is not a node that reports "no database". Said as "did not
		// say" rather than assumed either way — this is the distinction the whole file is built on.
		return "", false, false
	}
	return health.Role, health.HoldsDatabase, true
}

// verifyWriteCredential picks the credential the write-shaped checks can use, or "" when there is none.
//
// Before the bootstrap the break-glass credential is the deployment's only one and is meant to work. After it,
// that credential is refused and only a named token supplied by the operator can be used — which is why the
// natural order is to verify before closing.
func verifyWriteCredential(supplied, breakGlass string, bootstrapped bool) string {
	if s := strings.TrimSpace(supplied); s != "" {
		return s
	}
	if !bootstrapped {
		return strings.TrimSpace(breakGlass)
	}
	return ""
}

// controlPlaneGeneration reads the version the control plane is publishing.
func controlPlaneGeneration(client *http.Client, cpAdmin, breakGlass, supplied string, bootstrapped bool) (uint64, string, bool) {
	credential := verifyWriteCredential(supplied, breakGlass, bootstrapped)
	if credential == "" {
		return 0, "", false
	}
	code, body, err := get(client, cpAdmin+"/admin/config-bundle", credential)
	if err != nil || code != 200 {
		return 0, "", false
	}
	var envelope struct {
		PayloadB64 string `json:"payload_b64"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return 0, "", false
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.PayloadB64)
	if err != nil {
		return 0, "", false
	}
	var payload struct {
		Generation uint64 `json:"generation"`
		Epoch      string `json:"epoch"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return 0, "", false
	}
	return payload.Generation, payload.Epoch, true
}

// edgeAppliedGeneration reads what the Edge is actually serving.
func edgeAppliedGeneration(client *http.Client, edgeAdmin string) (uint64, string) {
	code, body, err := get(client, strings.TrimRight(edgeAdmin, "/")+"/healthz", "")
	if err != nil || code != 200 {
		return 0, ""
	}
	var health struct {
		ConfigSync struct {
			Generation uint64 `json:"last_applied_generation"`
			Epoch      string `json:"last_applied_epoch"`
		} `json:"config_sync"`
	}
	if json.Unmarshal(body, &health) != nil {
		return 0, ""
	}
	return health.ConfigSync.Generation, health.ConfigSync.Epoch
}

// generationCatchUpWait is how long an Edge is given to apply a change before being reported as behind. Longer
// than a default poll, short enough that a deployment which is genuinely stuck is still reported while somebody
// is looking.
const generationCatchUpWait = 60

// becomesTrueWithin waits for a condition a freshly started deployment reaches on its own — a first poll, a
// first report — and returns what it finds at the deadline.
//
// ★ IT IS FOR THINGS THAT ARRIVE, NOT THINGS THAT MIGHT. Used on a question whose false answer is
// indistinguishable between "not yet" and "never", so that the walk reports the second and not the first.
// Anything that would still be false after a minute and a half is reported false, unchanged.
func becomesTrueWithin(cond func() bool, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(3 * time.Second)
	}
}

// waitForTheFleetViewToForm blocks until the authority has heard from the fleet, or the deadline passes.
//
// ★ IT IS NOT A HEALTH CHECK AND IT REPORTS NOTHING. Its only job is to stop the checks that follow from
// measuring a deployment mid-start and calling the result a defect. Every one of them still says exactly what
// it finds; this only decides WHEN they look.
func waitForTheFleetViewToForm(client *http.Client, cpAdmin, token string, within time.Duration) {
	deadline := time.Now().Add(within)
	for {
		code, body, err := get(client, cpAdmin+"/admin/fleet/config-status", token)
		if err == nil && code == 200 {
			var fleet struct {
				Formed *bool `json:"formed"`
				Nodes  []any `json:"nodes"`
			}
			if json.Unmarshal(body, &fleet) == nil {
				if (fleet.Formed == nil || *fleet.Formed) && len(fleet.Nodes) > 0 {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// waitForTheControlPlaneToAnswer gives a deployment that has just been started the time it takes to accept a
// connection, and returns what it finds at the deadline.
//
// ★ IT WAITS FOR AN ANSWER, NOT FOR HEALTH. A control plane that answers anything other than 200 is reported
// on the first reading it gives: the wait is for the socket, not for the verdict.
func waitForTheControlPlaneToAnswer(client *http.Client, cpAdmin string, within time.Duration) (int, []byte, error) {
	deadline := time.Now().Add(within)
	for {
		code, body, err := get(client, cpAdmin+"/healthz", "")
		if err == nil {
			return code, body, nil
		}
		if time.Now().After(deadline) {
			return code, body, err
		}
		time.Sleep(3 * time.Second)
	}
}

// waitForTheEdgeToCatchUp blocks until the Edge has applied a configuration at least as new as what the
// control plane is publishing now, or the deadline passes.
//
// ★ IT REPORTS NOTHING AND DECIDES NOTHING. Its only job is to make sure a ONE-TIME credential is spent at a
// moment when it can work: a token authored on the authority admits on the Edge, and the two are a poll
// apart. Whether the enrolment then succeeds is the caller's question, asked once.
func waitForEveryEdgeToCatchUp(client *http.Client, edgeAdmins []string, cpAdmin, token string, within time.Duration) {
	want, _, ok := controlPlaneGeneration(client, strings.TrimRight(cpAdmin, "/"), "", token, true)
	if !ok {
		return
	}
	deadline := time.Now().Add(within)
	for {
		behind := false
		for _, e := range edgeAdmins {
			if e = strings.TrimRight(strings.TrimSpace(e), "/"); e == "" {
				continue
			}
			if applied, _ := edgeAppliedGeneration(client, e); applied < want {
				behind = true
			}
		}
		if !behind || time.Now().After(deadline) {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// enrolmentAuthorityWasNotAsked reads the Edge's own answer for the one refusal that is not a verdict on the
// token: it could not reach the authority that decides, so nothing was judged and nothing was spent.
//
// ★ MATCHED ON THE EDGE'S SENTENCE, which is deliberate. The Edge is the only party that knows whether it
// asked; a status code cannot say it, and guessing from timing would retry real refusals.
func enrolmentAuthorityWasNotAsked(body []byte) bool {
	var answer struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &answer) != nil {
		return false
	}
	return strings.Contains(strings.ToLower(answer.Error), "could not reach the authority")
}
