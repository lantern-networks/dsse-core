package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enroll"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// enroll_endpoint.go — the device-facing enrollment endpoint (roadmap M4c-wire). An UNENROLLED agent POSTs a
// CSR + eligibility token here; the CP verifies eligibility, signs the CSR with the device CA into a client
// cert carrying the CP-AUTHORITATIVE identity (device id / assigned tenant / group — the CSR's own subject is
// ignored), records the admission in the enrolled ledger, and returns the cert + CA. This is only registered
// when a device CA (--device-ca-cert/--device-ca-key) is configured, so existing deployments are unaffected.
//
// The heavy lifting + security invariants live in oss/enroll + oss/deviceca (unit + client↔server E2E tested);
// this file is the thin Control-Plane wiring. Assign is intentionally MINIMAL here (one shared eligibility token
// → the edge's tenant + a default group).
//
// SECURITY / HARDENING (tracked for M5/M7): this reference uses a single SHARED, non-expiring token, so anyone
// who learns it can mint unlimited device certs, and the endpoint is public with NO rate limit / issuance cap.
// Production must move to ONE-TIME, short-lived, per-device enrollment tokens (issued by the Admin Console),
// per-source rate limiting, and an issuance cap. Do not ship the shared-token model to production.
// cpAuthoritativeGroup returns the Control-Plane-assigned device group for an mTLS-verified identity, read from
// the enrolled ledger (set at enrollment / admin assignment). It is the ONLY trustworthy group source for
// per-group policy/tuning resolution: unlike deviceStore.Metadata["device_group"] — which is merged verbatim
// from the device's own heartbeat and is therefore self-assertable — the ledger group is CP-authoritative. An
// unenrolled/absent identity or a device with no assigned group yields "" (tenant-scope only; never a device
// claim). Keep every group-scoped resolution path on this helper so a device cannot pick its own group.
func cpAuthoritativeGroup(ledger *enrolledinventory.Ledger, identity string) string {
	if ledger == nil {
		return ""
	}
	g, _ := ledger.GroupFor(identity)
	return strings.TrimSpace(g)
}

// Enrolment is a once-per-device event, so even a large kitting run is far below this. Chosen to bound the work
// an unauthenticated caller can cause, not to make a 256-bit secret harder to guess.
const (
	enrolRateLimitPerSecond = 5
	enrolRateLimitBurst     = 20
)

func registerEnrollEndpoint(mux *http.ServeMux, signer *deviceca.Signer, ledger *enrolledinventory.Ledger, eligibilityToken, tenant, defaultGroup string, certTTL time.Duration, logf func(string, ...interface{})) {
	registerEnrollEndpointWithIdP(mux, signer, ledger, nil, nil, eligibilityToken, tenant, defaultGroup, certTTL, nil, nil, nil, nil, logf)
}

// registerEnrollEndpointWithIdP is the same endpoint with the other eligibility sources available alongside the
// shared token.
//
// THREE modes coexist, and they are not equals. Admin-issued per-device tokens are the one to deploy: they prove
// a machine an administrator approved, they work once, they expire, and they record which admin authorised which
// device. The IdP proves a person, which is the wrong question at enrolment — an IT admin images a batch of
// laptops before knowing who gets them — so it stays available for the case where someone enrols their own
// machine, but it is not the default. The shared token proves nothing and is on its way out; it is already
// disabled everywhere, including the lab, and remains only so an existing deployment is not broken by the same
// commit that gives it a replacement.
//
// Checked in that order, so a deployment that has moved on is never silently still accepting something weaker.
func registerEnrollEndpointWithIdP(mux *http.ServeMux, signer *deviceca.Signer, ledger *enrolledinventory.Ledger,
	tokens enrolltoken.Authority, licensing EnrolmentLicensing,
	eligibilityToken, tenant, defaultGroup string, certTTL time.Duration, tenantLifecycle adminTenantModelRuntimeStore,
	idp *idpEnrollmentEligibility, cpReporter *enrolmentCPReporter, siteStore adminSiteStore,
	logf func(string, ...interface{})) {
	if idp != nil && strings.TrimSpace(idp.TenantID) == "" {
		// The tenant is known here and not where the checker is assembled; scoping the registry lookup to it
		// keeps one tenant's IdP from being usable to enrol into another.
		idp.TenantID = tenant
	}
	if ledger == nil && logf != nil {
		// Fail-visible: issuing without an inventory record means the device is invisible to /admin and not
		// revocable via the ledger. Currently unreachable (main always supplies a ledger), but warn if it changes.
		logf("enroll: WARNING device CA configured but enrolled ledger is nil — issued devices will not be recorded")
	}
	// An identity an administrator DISABLED does not get a fresh certificate by asking again. Disable is what
	// the console calls revocation, and it has to survive the device coming back and asking under the same name.
	//
	// This runs AFTER eligibility, deliberately: answering "that one is disabled" to a caller who has proved
	// nothing would turn a public endpoint into an oracle for which device names exist and which are revoked. A
	// caller who already holds a valid enrolment credential learns nothing new from an accurate answer, and a
	// legitimate operator gets a message that says what actually happened.
	//
	// It also has to run before the CSR is signed, which is why it is here and not in Record — refusing there
	// would still hand the device a usable certificate and merely decline to write it down.
	//
	// Being disabled is not the same as being unknown: an unknown identity is the ordinary Day-0 case and must
	// proceed. Only an entry that exists and was turned off is refused, and only an admin can turn one off
	// (SetEnabled's sole caller is the admin route), so this cannot lock out a device that merely went quiet —
	// the failure mode that bit the admission overlay before.
	refuseIfDisabled := func(deviceID string) (string, bool) {
		if ledger == nil || !ledger.IsExplicitlyDisabled(deviceID) {
			return "", false
		}
		if logf != nil {
			logf("enroll_refused device=%q reason=%q", deviceID, "identity is disabled by an administrator")
		}
		// Drop the attribution the IdP branch just stored: this enrolment is not happening, and leaving it
		// behind would misattribute whoever enrols this name next.
		lastEnrolmentAttribution.Delete(deviceID)
		return "identity is disabled by an administrator", true
	}
	// Licensing: is there a seat for one more device, and is the licence still admitting devices?
	//
	// Runs alongside refuseIfDisabled and for the same reason — AFTER eligibility, so a public endpoint cannot
	// be used to probe how close a tenant is to its limit, and BEFORE the CSR is signed, because refusing after
	// signing would hand out a certificate and merely decline to record it.
	//
	// Nothing here can stop a device that already works. Running out of seats, or running past the licence's
	// enrolment-stop, refuses GROWTH: a commercial shortfall is not a reason to take a customer's network down,
	// and the licence's own service-end is the only thing that ever stops traffic.
	//
	// An Edge with no licence configured is unlicensed by construction — a single-tenant deployment, the
	// reference lab — and is left entirely alone rather than defaulting to zero seats and refusing everything.
	refuseIfNoSeat := func(deviceID, tenant string) (string, bool) {
		if licensing == nil {
			return "", false
		}
		if why, refused := licensing.RefuseEnrolment(tenant); refused {
			if logf != nil {
				// The operator's reason, in the log. The caller gets the generic refusal below.
				logf("enroll_refused device=%q reason=%q", deviceID, why)
			}
			lastEnrolmentAttribution.Delete(deviceID)
			return "enrolment is not available for this tenant", true
		}
		return "", false
	}
	// Eligibility alone: may this caller enrol at all? Split out of Assign so the disabled-identity gate can
	// run strictly after it — see refuseIfDisabled.
	assignEligibility := func(req enroll.Request, pendingSpendOut *string) (t, g, reason string, ok bool) {
		pendingSpend := ""
		defer func() { *pendingSpendOut = pendingSpend }()
		// A connector proving itself with its Site's bootstrap secret. Checked FIRST because its mode is its
		// own word: nothing below can consume a connector's request, and a connector's secret must never be
		// tried as a device eligibility token. See connector_enrolment_identity.go for what it proves.
		if strings.TrimSpace(req.Eligibility.Mode) == connectorEligibilityMode {
			// A bounded context rather than the request's: enroll.Issuer's Assign callback is handed the
			// request BODY and no context, and widening that shared interface for one caller is worse than a
			// deadline here. Bounded rather than Background so a wedged Site store cannot pin an enrolment
			// goroutine open — the caller gets the ordinary refusal and retries.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			issuedFor, allowed := connectorEnrolmentEligibility(ctx, siteStore, tenant, req, logf)
			cancel()
			if !allowed {
				// The same sentence every refusal on this endpoint gives. /enroll is unauthenticated, and an
				// answer that distinguished "no such Site" from "wrong secret" would be an oracle.
				return "", "", "invalid or missing eligibility token", false
			}
			lastEnrolmentAttribution.Store(req.DeviceID,
				connectorEnrolmentAttribution(req.Eligibility.Site))
			return issuedFor, defaultGroup, "", true
		}
		// Admin-issued per-device token: the one credential here that authorises a MACHINE. Tried first, and it
		// SPENDS the token, so a config file that gets copied enrols one laptop rather than a fleet.
		//
		// Every refusal returns the same sentence. Which of "never existed", "already spent", "expired" and
		// "revoked" is true would let an unauthenticated caller probe a tenant's issuance state, so the specific
		// reason goes to the operator's log and the caller gets one answer.
		if tokens != nil && req.Eligibility.Mode == "token" && strings.TrimSpace(req.Eligibility.Token) != "" {
			// ★★★ THE ORGANIZATION COMES FROM THE TOKEN, NOT FROM THIS NODE (2026-08-21). Verifying against the
			// node's organization meant an administrator of any other one could mint an enrolment token (201)
			// that no device could ever use (403) — a screen minting credentials the product refuses. The
			// token's organization is AUTHORITATIVE and not client-claimed: the store bound it at issue and
			// refuses to be read as any other, exactly like a device's organization coming from the CA that
			// issued its certificate rather than from a field it sends.
			tok, err := tokens.Verify(req.Eligibility.Token, "", time.Now().UTC())
			if err == nil {
				// Verified, NOT yet spent. The endpoint still has to refuse identities an admin disabled, and a
				// token burned on an enrolment that is then refused leaves the admin re-issuing for a machine
				// that was never going to be admitted. Assign's caller spends it once the answer is yes.
				pendingSpend = tok.ID
				// Attribution becomes WHICH ADMIN APPROVED THIS MACHINE. Months later, that is the question an
				// operator has when they find a device somewhere it should not be — not who ran the installer.
				lastEnrolmentAttribution.Store(req.DeviceID, "enrolled with a token issued by "+tok.IssuedBy)
				if logf != nil {
					logf("enroll_eligibility_token device=%q token_id=%q issued_by=%q", req.DeviceID, tok.ID, tok.IssuedBy)
				}
				g := defaultGroup
				if tok.Group != "" {
					// The token carries the group its admin chose, so a machine lands in the right place without
					// the device asserting anything about itself.
					g = tok.Group
				}
				issuedFor := strings.TrimSpace(tok.TenantID)
				if issuedFor == "" {
					issuedFor = tenant
				}
				// ★ AND THIS NODE MUST BE ABLE TO ISSUE FOR THEM. A certificate signed by the wrong authority
				// identifies a customer's laptop as somebody else's fleet, which is worse than a refusal. An
				// organization that runs its own PKI has no authority here on purpose and its devices are
				// issued by the CA it holds — so the reason goes to the operator's log by name, while the
				// caller keeps the one sentence every refusal gives.
				if !strings.EqualFold(issuedFor, tenant) && tenantDeviceIdentity.For(issuedFor) == nil {
					if logf != nil {
						logf("enroll_refused mode=token device=%q tenant=%q reason=%q", req.DeviceID, issuedFor,
							"this node holds no device-identity authority for that organization: either the "+
								"control plane has not been given one, or the organization issues its own "+
								"certificates with a CA it registered")
					}
					return "", "", "invalid or missing eligibility token", false
				}
				return issuedFor, g, "", true
			}
			if !errors.Is(err, enrolltoken.ErrUnknownToken) {
				// A token that EXISTS but cannot be used is a real operational event — a spent config file doing
				// the rounds, a revoked one still in a kitting image. An unknown secret is just noise, and could
				// be an attacker filling the log.
				if logf != nil {
					logf("enroll_refused mode=token device=%q reason=%q", req.DeviceID, err.Error())
				}
				// ★★★ "YOUR TOKEN IS WRONG" IS THE WRONG ANSWER WHEN THE AUTHORITY COULD NOT BE ASKED
				// (2026-08-26, found by installing a fleet from nothing three times and having the third
				// refuse everything). An Edge holds no token store: it asks the control plane to verify and
				// spend. Behind a front door, during the seconds after leadership moves, that ask reaches a
				// node which refuses because it does not lead — and the caller was told, in every case, that
				// its token was invalid. The operator has a freshly minted token in their hand and a
				// deployment saying it is not one; the true reason was in a log they had no reason to open.
				//
				// The distinction is safe to make: it says nothing about the token. It says this Edge could
				// not reach the thing that decides.
				if enrolmentAuthorityWasUnreachable(err) {
					return "", "", "this Edge could not reach the authority that decides whether an enrolment " +
						"token may be spent, so it refused rather than guessing — the token itself was never " +
						"judged. Try again shortly; if it persists, the control plane behind this Edge is not " +
						"answering writes", false
				}
				return "", "", "invalid or missing eligibility token", false
			}
			// Fall through: an unrecognised secret may still be the shared token on a deployment mid-migration.
		}
		// IdP-backed eligibility: a per-person, short-lived, revocable proof instead of one shared secret
		// that lives forever on every machine and names nobody. Checked FIRST so a deployment that has
		// moved to it is not silently still accepting the token.
		if req.Eligibility.Mode == "idp" {
			if idp == nil {
				return "", "", "IdP-backed enrolment is not configured on this Edge", false
			}
			identity, err := idp.verify(req.Eligibility.Token)
			if err != nil {
				if logf != nil {
					// The reason, never the token.
					logf("enroll_refused mode=idp device=%q reason=%q", req.DeviceID, err.Error())
				}
				return "", "", "IdP eligibility rejected", false
			}
			lastEnrolmentAttribution.Store(req.DeviceID, enrolmentAttribution(identity))
			if logf != nil {
				logf("enroll_eligibility_idp device=%q %s", req.DeviceID, enrolmentAttribution(identity))
			}
			return tenant, defaultGroup, "", true
		}
		// Eligibility: a shared token must match (empty configured token = refuse everything). Constant-time
		// compare — it is a secret checked on an unauthenticated public endpoint. The CP is authoritative for
		// tenant/group — the device's requested values are ignored.
		if eligibilityToken != "" && req.Eligibility.Mode == "token" &&
			subtle.ConstantTimeCompare([]byte(req.Eligibility.Token), []byte(eligibilityToken)) == 1 {
			return tenant, defaultGroup, "", true
		}
		return "", "", "invalid or missing eligibility token", false
	}

	iss := enroll.Issuer{
		Signer: signer,
		// ★ THE AUTHORITY THAT ORGANIZATION'S DEVICES ARE ISSUED UNDER (2026-08-21). nil means this node holds
		// none for them, and enroll refuses rather than signing under the node's own — see Issuer.SignerFor.
		SignerFor:        tenantDeviceIdentity.For,
		CertTTL:          certTTL,
		Logf:             logf,
		NowPolicyVersion: 1,
		Assign: func(req enroll.Request) (t, g, reason string, ok bool) {
			var spendTokenID string
			t, g, reason, ok = assignEligibility(req, &spendTokenID)
			if !ok {
				return "", "", reason, false
			}
			if why, disabled := refuseIfDisabled(req.DeviceID); disabled {
				return "", "", why, false
			}
			// Checked before the token is spent, like the disabled gate: burning an admin's one-time token on an
			// enrolment there was never room for leaves them re-issuing for a device that could not have been
			// admitted anyway.
			if why, noSeat := refuseIfNoSeat(req.DeviceID, t); noSeat {
				return "", "", why, false
			}
			// ★★★ AND THE REFUSAL AN OPERATOR ACTUALLY MEETS, WHICH WAS ON THE OTHER SIDE OF THE SPEND
			// (2026-08-29, measured on Windows by the session walking the install lane there, confirmed twice
			// in its ledger). "This identity is already enrolled" is decided in Record — after the token is
			// spent — so a device refused for it burned the administrator's one-time approval on the way to
			// being turned away. The comment on ErrIdentityAlreadyEnrolled already said "and the one-time
			// token is already spent by then"; it was describing this, not accepting it.
			//
			// The cost is the SECOND attempt. With the token gone the same device is refused with "invalid or
			// missing eligibility token" — a different problem, named confidently. An operator issues another
			// token, watches it vanish, issues another, and never reaches the thing that fixes it, which is
			// the re-enrolment grant. The true refusal is only ever seen once, and it is seen first.
			//
			// Local checks only, deliberately: the shared identity claim is a write, and asking a remote
			// claimer "would you" before asking it "do" is two answers that can disagree.
			if ledger != nil {
				if err := ledger.WouldRefuseEnrolment(req.DeviceID, t, req.MachineRef); err != nil {
					if logf != nil {
						logf("enroll_refused device=%q reason=%q token_spent=false", req.DeviceID, err.Error())
					}
					lastEnrolmentAttribution.Delete(req.DeviceID)
					return "", "", err.Error(), false
				}
			}
			if spendTokenID != "" {
				// The enrolment is going ahead, so the token is spent now — atomically, re-checking everything,
				// because another machine holding a copy of the same config could have spent it since Verify.
				//
				// This is before the CSR is parsed, so a device with a valid token that sends a malformed CSR
				// burns it and the admin re-issues. The alternative — spending after signing — would let two
				// racing copies both receive a certificate, which is the thing one-time exists to prevent.
				if _, err := tokens.Spend(spendTokenID, t, req.DeviceID, time.Now().UTC()); err != nil {
					if logf != nil {
						logf("enroll_refused mode=token device=%q reason=%q", req.DeviceID, err.Error())
					}
					lastEnrolmentAttribution.Delete(req.DeviceID)
					return "", "", "invalid or missing eligibility token", false
				}
			}
			return t, g, "", true
		},
		RecordWithMachine: func(deviceID, t, g, machineRef string) error {
			if ledger != nil {
				now := time.Now().UTC().Format(time.RFC3339)
				// Record WHO enrolled it when that is known. Months later, "enrolled via POST /enroll" answers
				// nothing about a device found somewhere it should not be.
				note := "enrolled via POST /enroll"
				if attributed, ok := lastEnrolmentAttribution.LoadAndDelete(deviceID); ok {
					if s, ok := attributed.(string); ok && s != "" {
						note = s
					}
				}
				// ★ AND THIS IS WHERE THE ENROLMENT IS ALLOWED OR NOT (2026-08-12, nineteenth review). It used
				// to call EnrollGroupUnlessDisabled, which checks the disabled flag and then assigns TenantID
				// UNCONDITIONALLY — so a caller holding a valid enrolment credential for tenant B could name a
				// device id belonging to tenant A, move the ledger entry to B, and be handed a certificate for
				// it. Making the admin route atomic did nothing for this one: a different door into the same
				// room. Both questions — disabled, and already owned — are answered in one ledger lock now.
				//
				// The error is RETURNED, which is the other half: until RecordFunc could refuse, everything
				// added here could only be logged while the endpoint went on to answer 200 with a usable
				// identity.
				_, conflict, err := ledger.EnrollDeviceForTenantWithMachine(
					enrolledinventory.NormalizeIdentity(deviceID), t, g, note, now, machineRef)
				if err != nil {
					err = enrolmentRefusalForTheInstaller(err, conflict)
					if logf != nil {
						// ★ SAY WHAT STATE THE DEVICE IS IN (2026-08-13, twenty-sixth review). The one-time
						// token was spent above — deliberately, before signing, so two racing copies cannot
						// both be issued — and a shared identity claim taken here is released on this path.
						// The token is NOT: nothing gives it back, so this device cannot retry with the
						// credential it has. Fail-closed and recoverable only by an administrator, which the
						// operator should learn from the log rather than from the device never appearing.
						logf("enroll_not_recorded device=%q tenant=%q reason=%q — the one-time token is SPENT "+
							"and cannot be reused; this device needs a newly issued token (any shared identity "+
							"claim taken for it has been released)", deviceID, t, err.Error())
					}
					return err
				}
				// ★ AND THE CONTROL PLANE IS TOLD (2026-08-15). The ledger write above is local, and the
				// config bundle rebuilds this ledger from the CP's copy — so without this the device the
				// Edge just issued a certificate to is dropped from admission at the next bundle, still
				// holding that certificate, and refused at the transport handshake. Deliberately AFTER the
				// local write and deliberately unable to fail it: a control plane that is briefly away must
				// not strand machines an operator already approved. The obligation lives in a durable outbox.
				cpReporter.Report(enrolmentReport{Identity: enrolledinventory.NormalizeIdentity(deviceID),
					Group: g, Note: note, TenantID: t,
					MachineRef: enrolledinventory.NormalizeMachineRef(machineRef)})
			}
			return nil
		},
	}
	// Per-source rate limit on the bootstrap endpoint. ON by default, unlike the optional admin-surface limiter,
	// because /enroll is public, unauthenticated by construction, and parses attacker-supplied CSRs.
	//
	// It is NOT here to stop token guessing — the secret is 256 bits of randomness and guessing is not a threat
	// model. It bounds what an unauthenticated caller can make this endpoint DO: parse, hash, and log, on a port
	// facing the internet. So the limit is generous rather than tight, because the cost of being wrong in the
	// other direction is real: fifty laptops being kitted behind one office NAT all enrol from one source IP, and
	// a refusal there strands machines an operator has already approved.
	//
	// POST /enroll/renew is deliberately NOT rate-limited. It authenticates with the certificate being renewed,
	// so it is not an unauthenticated surface — and throttling it would turn a fleet-wide renewal window into a
	// fleet-wide expiry, which is an outage rather than a defence.
	enrolLimiter := newTokenBucketLimiter(enrolRateLimitPerSecond, enrolRateLimitBurst)
	enrolHandler := iss.Handler()
	mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
		// ★ A SUSPENDED ORGANIZATION TAKES NO NEW DEVICES (2026-08-18). Suspension freezes the administrative
		// plane and stops NEW admission; the devices already enrolled keep being enforced, because a billing
		// dispute must not take protection off a customer's laptops. Checked before the rate limiter so a frozen
		// organization's kitting run is answered rather than throttled into a mystery.
		if reason, refuse := adminTenantAdministrativelySuspended(r.Context(), tenantLifecycle, tenant); refuse {
			if logf != nil {
				logf("enroll_refused reason=tenant_suspended tenant=%q", tenant)
			}
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%s — it takes no new devices while suspended. The devices already enrolled are unaffected", reason))
			return
		}
		if !enrolLimiter.allow(clientIPForRateLimit(r)) {
			if logf != nil {
				// The source, never the token. A burst from one address is worth seeing; it is either an attack
				// or a kitting run that needs a higher limit, and both are the operator's call.
				logf("enroll_rate_limited source=%q", clientIPForRateLimit(r))
			}
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many enrolment attempts"))
			return
		}
		enrolHandler(w, r)
	})
	if logf != nil {
		// Say which eligibility modes are live. An operator moving a fleet off the shared token needs to see
		// that the IdP path is actually accepted — and, just as importantly, that the token still is.
		modes := make([]string, 0, 2)
		if strings.TrimSpace(eligibilityToken) != "" {
			modes = append(modes, "shared-token")
		}
		if idp != nil {
			modes = append(modes, "idp")
		}
		if len(modes) == 0 {
			modes = append(modes, "NONE — every enrolment will be refused")
		}
		logf("enroll endpoint registered: POST /enroll (tenant=%q default_group=%q ttl=%s eligibility=%s)",
			tenant, defaultGroup, certTTL, strings.Join(modes, "+"))
	}
}

// lastEnrolmentAttribution carries the enrolling identity from the eligibility check to the ledger write.
//
// A map rather than a field because enroll.Issuer splits the two into separate callbacks with no value passed
// between them, and widening that shared interface for one caller's benefit is worse than keying by the device
// id for the microseconds between the two. LoadAndDelete so an entry cannot outlive its enrolment.
var lastEnrolmentAttribution sync.Map

// enrolmentRefusalForTheInstaller decides which refusals the machine is TOLD, and names the other identity
// when there is one.
//
// ★★★ THE ONE-TIME TOKEN IS ALREADY SPENT BY THE TIME THIS IS DECIDED. Whoever is standing at the machine
// cannot try again without an administrator issuing a new approval, so a refusal they cannot act on costs a
// round trip through a person. Three of them are entirely about what the person should DO — renew instead,
// rename this machine, or keep the name it already has — and none of them discloses anything beyond "that name
// is taken", to a caller who already holds a credential an administrator issued for this organization.
//
// Every other refusal keeps the flat "not eligible": why a device was turned away is generally the
// deployment's business. "This identity belongs to another organization" tells a caller about an organization
// that is not theirs.
func enrolmentRefusalForTheInstaller(err error, conflict enrolledinventory.MachineRefConflict) error {
	switch {
	case errors.Is(err, enrolledinventory.ErrSameMachineAlreadyEnrolled),
		errors.Is(err, enrolledinventory.ErrDifferentMachineSameName),
		errors.Is(err, enrolledinventory.ErrIdentityAlreadyEnrolled):
		return enroll.Refusal{Reason: err.Error()}
	case errors.Is(err, enrolledinventory.ErrMachineEnrolledUnderAnotherName):
		reason := err.Error()
		if name := strings.TrimSpace(conflict.EnrolledAs); name != "" {
			// The name is the whole point: "you are enrolled somewhere else" without saying where leaves
			// somebody comparing lists by hand. Spliced into the sentence rather than prepended as a second
			// one — two sentences saying the same thing read like a bug, and this is what a person sees at the
			// machine with a spent token in their hand.
			reason = strings.Replace(reason, "under a different name", "as "+name, 1)
		}
		return enroll.Refusal{Reason: reason}
	}
	return err
}

// enrolmentAuthorityWasUnreachable says whether a token verification failed because the authority could not be
// ASKED, rather than because the token was judged and refused.
//
// ★ IT MATCHES ON WHAT THE AUTHORITY SAID ABOUT ITSELF, not on a status code, because the shape that caused
// this is a 4xx with a body explaining that the node does not hold leadership — an answer, from the wrong
// node. A transport error is the other half and is included for the same reason: neither of them is a verdict
// on the token.
func enrolmentAuthorityWasUnreachable(err error) bool {
	if err == nil {
		return false
	}
	e := strings.ToLower(err.Error())
	for _, marker := range []string{
		"does not hold leadership", // asked the wrong node behind a front door
		"connection refused",
		"no such host",
		"context deadline exceeded",
		"timeout",
		"eof",
	} {
		if strings.Contains(e, marker) {
			return true
		}
	}
	return false
}
