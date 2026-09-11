package main

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// admin_pki_readiness.go — one answer to "what is set up, and what is still missing?"
//
// WHY THIS COMES BEFORE A WIZARD. The Day-0 experience is not really a sequence of screens; it is an operator
// being able to tell, at any moment, which of the PKI preconditions are met and which are not. Today that
// answer is scattered across half a dozen endpoints and a log file, so the only people who can give it are the
// ones who already know the system — exactly the people who do not need a wizard.
//
// A wizard built without this would be a set of forms that cannot tell you whether they worked. So the fact
// comes first, and the screens can follow.
//
// WHAT IT IS NOT. It is not a health check: /healthz already answers "should this node take traffic". This
// answers "is this deployment finished, and if not, what is the next thing to do". A node can be perfectly
// healthy and still be missing every piece of a production PKI.
//
// EVERY ITEM SAYS WHAT BREAKS. "Not configured" tells an operator nothing about whether to care. Each item
// carries the consequence of leaving it as it is, because that is what decides the order they work in.

// pkiReadinessItem is one precondition and its current state.
type pkiReadinessItem struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // ok | attention | missing | unknown
	Detail string `json:"detail"`
	// Consequence states what happens if this is left as it is. Written for someone who does not already know
	// the system — the whole reason this exists.
	Consequence string `json:"consequence,omitempty"`
	// Remediation is the concrete next action that resolves this item — what to actually DO, in an operator's
	// terms. It is what turns the flat readiness list into a Day-0 wizard: a status view says "renewal is
	// missing", a wizard says "point the agent at the renewal endpoint and redeploy". Authored here, next to
	// the assessment, so the wizard renders rather than invents guidance (the same reason Consequence lives
	// here and not in the browser). Omitted for items already in the "ok" state — nothing to do.
	Remediation string `json:"remediation,omitempty"`
	// Concrete carries the deployment's ACTUAL values for whatever the remediation asks for — the endpoint an
	// agent should be pointed at, the address to enable, the socket to use. The remediation says what to do;
	// this says it with the numbers filled in.
	//
	// It exists because prose is where a setup guide stops being usable. "Point the agents at the renewal
	// endpoint" is correct and leaves an operator to work out which host, which port, which path — and this
	// assessment already knows all three, because it is running inside the deployment it is describing.
	Concrete []string `json:"concrete,omitempty"`
	// Value is WHAT THIS CHECK FOUND, as a code plus the numbers it needs — "in a token", "renews itself",
	// "nearest expiry is X in N days". The screen was built to hide everything healthy behind a toggle and
	// show only what was wrong, which left an operator unable to answer the question the page is named after:
	// what, exactly, is healthy? A state word alone cannot answer it; the finding can. The wording lives in
	// the Console so it can be said in the language being read.
	ValueCode   string   `json:"value_code,omitempty"`
	ValueParams []string `json:"value_params,omitempty"`
	// Action names a thing the Console can DO for this item, rather than describe. Empty when there is nothing
	// safe to perform from a screen.
	Action string `json:"action,omitempty"`
	// Blocking marks a precondition that makes production use unsafe rather than merely incomplete.
	Blocking bool `json:"blocking"`
}

type pkiReadinessReport struct {
	Items []pkiReadinessItem `json:"items"`
	// Summary counts, so a Console can show a single line without re-deriving it and getting a different
	// answer than the list.
	OK        int `json:"ok"`
	Attention int `json:"attention"`
	Missing   int `json:"missing"`
	// ProductionSafe is false while ANY blocking item is unresolved. Not a percentage: a deployment missing
	// one blocking piece is not "90% safe", it is unsafe.
	ProductionSafe bool `json:"production_safe"`
	// WithheldOtherOrganizations counts findings held back because they are about another organization's
	// machine. Stated rather than silently dropped: "nothing to do" and "nothing YOU can do" differ.
	WithheldOtherOrganizations int `json:"withheld_other_organizations,omitempty"`
}

// pkiReadinessItemNamesAnotherOrganization is true when a finding is about a machine the caller may not see.
// Only the parameters are consulted — they are the structured form of the same names the sentences carry, so
// judging on them keeps the decision out of prose.
func pkiReadinessItemNamesAnotherOrganization(item pkiReadinessItem, ledger *enrolledinventory.Ledger, r *http.Request) bool {
	for _, param := range item.ValueParams {
		if !looksLikeDeviceIdentity(param) {
			continue
		}
		if kept, _ := deviceIdentitiesForCaller([]string{param}, ledger, r); len(kept) == 0 {
			return true
		}
	}
	return false
}

// pkiReadinessInput is what the report is computed from. Passed in rather than read from globals so the
// assessment is testable without standing up an Edge.
type pkiReadinessInput struct {
	// InterceptionAnnouncementMismatch names the organizations whose devices are told to look for an
	// interception root that is not the one their traffic is signed under — one sentence per organization,
	// already written for a reader.
	//
	// ★★★ NOBODY ASKED THIS UNTIL 2026-08-19, and a machine lost every HTTPS request it made while the signal
	// built to prevent exactly that reported green. See interception_announced_vs_signing.go.
	InterceptionAnnouncementMismatch []string

	// The deployment's own addresses, so remediation can be stated with the real values rather than as prose an
	// operator has to translate.
	RenewalEndpointURL  string
	RecoveryEndpointURL string
	// HSMAgentSocket is the signing sidecar's socket, when one is configured. It is the single value an operator
	// needs in order to act on the key-custody item, and the assessment already knows it.
	HSMAgentSocket string
	// EnrolmentTokenStore / EnrolmentTokenMaxLifetime / EnrolmentTokenOutstanding describe the admin-issued
	// token regime as it is actually running, so the enrolment item can state the current settings instead of
	// asking an operator to go and look them up in a compose file.
	EnrolmentTokenStore       string
	EnrolmentTokenMaxLifetime time.Duration
	EnrolmentTokenOutstanding int

	// ControlPlane says this node IS the control plane. It terminates no user traffic, intercepts nothing and
	// issues no device certificates, so the interception and enrolment items below are not gaps on it — they
	// are questions about a role it does not have. Asserting them made the reference deployment read
	// "not ready for real traffic" permanently, on the strength of a node that is not in the traffic path,
	// and handed the operator three screens of guidance about configuring interception on a control plane.
	ControlPlane bool

	KeyCustody         string // "pkcs11" | "sealed-file" | "file" | ""
	KeyCustodyHealthy  bool
	KeyCustodyChecked  bool
	IntermediateActive bool
	// ReparentRestoreFailed is true when a persisted interception-root re-parent could not be restored at boot
	// — the Edge is serving the self-signed root instead of the intended MSSP-issued one. Surfaced so
	// readiness reads degraded, not green.
	ReparentRestoreFailed bool
	EnrollConfigured      bool
	EnrollSharedToken     bool
	EnrollIdPBacked       bool
	// EnrollAdminTokens is the admin-issued, one-time, per-device credential. It was added after this
	// assessment was first written, and leaving it out did not merely make the guide incomplete — it made it
	// WRONG: a deployment enrolling with admin tokens and no IdP was reported as running on a shared secret and
	// told to go and add an IdP it does not need. A setup guide that describes a mechanism the operator is not
	// using is worse than no guide, because it is followed.
	EnrollAdminTokens bool
	RenewalEndpoint   bool
	RecoveryListener  bool
	RecoveryWindow    time.Duration
	DevicesTotal      int
	DevicesRenewable  int // devices whose certificates come from /enroll rather than being hand-made
	// SoonestExpiry is the nearest expiry across everything this deployment depends on — the certificates
	// components serve, the trust anchors devices verify against, and the certificates devices hold. Named,
	// because "something expires in six days" is not actionable until you know what.
	//
	// The assessment had no expiry check at all, which meant a deployment could be reported ready for real
	// traffic with a certificate due to expire the following week. Every other item here asks whether a piece
	// is CONFIGURED; none asked whether it was about to stop working, and the second question is the one with
	// a deadline attached.
	SoonestExpiryWhat string
	SoonestExpiryIn   time.Duration
	// Kind and Who say the same thing structurally, so the screen can name it in its own language.
	SoonestExpiryKind string // "trust_anchor" | "device_certificate"
	SoonestExpiryWho  string
	SoonestExpiryHave bool
}

// concreteRenewal states the remediation with this deployment's actual endpoint. Empty when the Edge does not
// know its own address — better to say nothing than to print a placeholder somebody pastes verbatim.
func concreteRenewal(in pkiReadinessInput) []string {
	if strings.TrimSpace(in.RenewalEndpointURL) == "" {
		return nil
	}
	return []string{
		"This Edge renews at: " + in.RenewalEndpointURL,
		"macOS: the agent derives it from the transport URL already in its configuration — no extra setting.",
		"Windows: --enroll-url is only for first enrolment; renewal uses the (T) transport and needs no address.",
	}
}

// concreteRecovery does the same for the recovery listener, which an agent CANNOT derive: it exists precisely
// for devices whose certificate has expired, so it cannot be reached over the transport that certificate opens.
func concreteRecovery(in pkiReadinessInput) []string {
	if strings.TrimSpace(in.RecoveryEndpointURL) == "" {
		return []string{
			"Not enabled on this Edge. Set -enroll-renew-grace-listen to an address the fleet can reach.",
			"A device whose certificate expired while it was switched off cannot open the (T) transport, so it " +
				"cannot use the ordinary renewal path — this listener is the only way back without a human.",
		}
	}
	return []string{
		"This Edge accepts expired-certificate renewals at: " + in.RecoveryEndpointURL,
		"Agents resolve it from the transport URL they already hold, so no separate address has to be distributed.",
	}
}

// concreteKeyCustody names the sidecar this deployment is actually wired to, or says plainly that none is —
// which is the difference between "configure PKCS#11" as a slogan and as an instruction.
func concreteKeyCustody(in pkiReadinessInput) []string {
	if socket := strings.TrimSpace(in.HSMAgentSocket); socket != "" {
		return []string{
			"A signing sidecar is already configured at: " + socket,
			"Point the interception root at it with -interception-hsm-agent-socket so the key stops being a file this host can read.",
		}
	}
	return []string{
		"No signing sidecar is configured on this Edge (-interception-hsm-agent-socket is unset).",
		"The sidecar holds the key in a PKCS#11 token and signs on request, so the Edge process never has the key material — a host compromise then yields no CA.",
		"Until it is wired, the strength of this deployment's interception CA is the file permissions on this host.",
	}
}

// concreteIntermediate answers the question the prose leaves open: what does introducing one COST here. The
// answer is a number this assessment already has — how many endpoints would otherwise have to be re-provisioned.
func concreteIntermediate(in pkiReadinessInput) []string {
	out := []string{
		"Enable with -interception-use-intermediate (plus -interception-intermediate-cert / -interception-intermediate-key).",
		"Leaves then chain [leaf, intermediate, root], so the signing key can be replaced without touching what endpoints trust.",
	}
	if in.DevicesTotal > 0 {
		out = append(out, fmt.Sprintf(
			"Without it, rotating the signing key means re-provisioning the trust store on all %d enrolled device(s) — every one of them, before any of them can connect again.",
			in.DevicesTotal))
	}
	return out
}

// concreteEnrolment states the token regime as configured, because "issue per-device tokens instead" is advice
// an operator cannot act on without knowing where the tokens are stored and how long they live.
func concreteEnrolment(in pkiReadinessInput) []string {
	out := []string{"Issue tokens from the Console: Devices → Enrolment tokens. Each authorises one machine, once."}
	if store := strings.TrimSpace(in.EnrolmentTokenStore); store != "" {
		out = append(out, "Token store on this Edge: "+store+
			" — durability is a security property here, because the store is what remembers that a one-time token was SPENT.")
	}
	if in.EnrolmentTokenMaxLifetime > 0 {
		out = append(out, "Maximum token lifetime: "+in.EnrolmentTokenMaxLifetime.String()+" (-enrolment-token-max-lifetime).")
	}
	if in.EnrolmentTokenOutstanding > 0 {
		out = append(out, fmt.Sprintf("Cap on unspent tokens at any moment: %d (-enrolment-token-max-outstanding).", in.EnrolmentTokenOutstanding))
	}
	return out
}

// readinessValues states what each check FOUND, in one place rather than at each of the twenty-three sites
// that build an item. Derived from the same inputs the assessment judged, so the value and the state cannot
// tell different stories.
func readinessValues(items []pkiReadinessItem, in pkiReadinessInput) []pkiReadinessItem {
	for i := range items {
		it := &items[i]
		switch it.ID {
		case "role":
			it.ValueCode = "control_plane"
		case "key_custody":
			switch {
			case in.KeyCustody == "pkcs11":
				it.ValueCode = "in_token"
			case strings.Contains(in.KeyCustody, "sealed"):
				it.ValueCode = "sealed_file"
			case in.KeyCustody != "":
				it.ValueCode = "plain_file"
			default:
				it.ValueCode = "unknown"
			}
		case "key_custody_health":
			switch {
			case !in.KeyCustodyChecked:
				it.ValueCode = "not_checked"
			case in.KeyCustodyHealthy:
				it.ValueCode = "verified"
			default:
				it.ValueCode = "failed"
			}
		case "intermediate":
			switch {
			case in.ReparentRestoreFailed:
				// A persisted MSSP re-parent could not be restored: serving self-signed, which devices on the
				// MSSP root reject. Not green.
				it.ValueCode = "reparent_restore_failed"
			case in.IntermediateActive:
				it.ValueCode = "via_intermediate"
			default:
				it.ValueCode = "root_signs_directly"
			}
		case "enrolment":
			switch {
			case in.EnrollAdminTokens:
				it.ValueCode = "admin_tokens"
			case in.EnrollIdPBacked:
				it.ValueCode = "idp"
			case in.EnrollSharedToken:
				it.ValueCode = "shared_token"
			case in.EnrollConfigured:
				it.ValueCode = "configured"
			default:
				it.ValueCode = "none"
			}
		case "renewal":
			if in.RenewalEndpoint {
				it.ValueCode = "automatic"
				if in.DevicesTotal > 0 {
					it.ValueParams = []string{strconv.Itoa(in.DevicesRenewable), strconv.Itoa(in.DevicesTotal)}
				}
			} else {
				it.ValueCode = "by_hand"
			}
		case "recovery":
			if in.RecoveryListener && in.RecoveryWindow > 0 {
				it.ValueCode = "window_hours"
				it.ValueParams = []string{strconv.Itoa(int(in.RecoveryWindow.Hours()))}
			} else {
				it.ValueCode = "none"
			}
		case "expiry":
			if in.SoonestExpiryHave {
				it.ValueCode = "nearest_" + in.SoonestExpiryKind
				it.ValueParams = []string{in.SoonestExpiryWho, strconv.Itoa(int(in.SoonestExpiryIn.Hours() / 24))}
			} else {
				it.ValueCode = "nothing_dated"
			}
		}
	}
	return items
}

func assessPKIReadiness(in pkiReadinessInput) pkiReadinessReport {
	items := []pkiReadinessItem{}

	// A control plane is asked only what applies to a control plane. The design's own rule — items that do
	// not apply are omitted rather than reported as gaps, because a readiness view that invents work stops
	// being read — was not being followed for the one node where it matters most.
	if in.ControlPlane {
		return pkiReadinessReport{
			ProductionSafe: true,
			OK:             1,
			Items: readinessValues([]pkiReadinessItem{{
				ID: "role", Title: "Control plane", Status: "ok",
				Detail: "this node distributes configuration and does not carry user traffic; the interception and enrolment PKI belongs to the Edges",
			}}, in),
		}
	}

	// 0. Are an organization's devices told to look for the root that actually signs their traffic? Blocking,
	// and worded from what it cost: not one site failing, but every HTTPS request on every machine of that
	// organization, the moment steering is armed.
	if len(in.InterceptionAnnouncementMismatch) > 0 {
		items = append(items, pkiReadinessItem{
			ID: "interception_announced_root", Title: "The root devices are told to trust is the one that signs",
			Status: "missing",
			Detail: "not for " + strings.Join(in.InterceptionAnnouncementMismatch, "; "),
			Consequence: "every HTTPS request on those machines fails the moment steering is armed — browser, " +
				"command line and the platform's own TLS alike — because what is presented is signed by an " +
				"authority they were never told to hold. A device reporting that it holds the announced root is " +
				"not evidence of anything: it holds the wrong one.",
			Remediation: "Announce the root that signs. Distribute that root to those devices FIRST, confirm they " +
				"hold it, and only then sign under it — or move the organization back to the root its devices " +
				"already trust.",
			Blocking: true,
		})
	} else if in.IntermediateActive {
		items = append(items, pkiReadinessItem{
			ID: "interception_announced_root", Title: "The root devices are told to trust is the one that signs",
			Status: "ok",
			Detail: "every organization's devices are told to look for the root its own traffic is signed under",
		})
	}

	// 0b. What an intercepted certificate says about revocation. Stated because the answer is "nothing", and a
	// strict client refuses it for that reason alone — so an operator meets this as a broken tool rather than
	// as a policy unless the assessment says otherwise.
	if in.IntermediateActive {
		// ★★★ THE CONDITION THIS ITEM WAS WAITING FOR HAS HAPPENED, AND THE ANSWER IS STILL NO (2026-08-29).
		//
		// The remediation used to say "wait for the agent plane to fold onto one port and serve a signed, empty
		// CRL from it". The fold has landed — every Edge says so at start-up, `agent-facing ports: 1` — so that
		// text told an operator to wait for something already done, which is worse than saying nothing.
		//
		// The conclusion it was waiting to reach does not survive the real lifetimes:
		//
		//	leaf          30 days   minted per host by the Edge. The only party who could revoke it is the one
		//	                        who mints it, and it withdraws one by not minting it.
		//	per-Edge CA   12 hours  expiry IS the revocation, and it is faster than any CRL an endpoint polls.
		//	tenant CA      5 years  the one where revocation carries meaning — AND IT ALREADY EXISTS:
		//	                        POST /admin/interception-intermediate/{tenant}/revoke, refused by the Edges
		//	                        themselves, which is stronger than a CRL because it does not depend on the
		//	                        client bothering to check.
		//
		// So a CRL buys no security here. It would be served for one reason — to stop strict clients
		// hard-failing — which is COMPATIBILITY, priced at a new unauthenticated address, a fetch from every
		// endpoint, and the loop where a CRL fetched through the tunnel is itself intercepted. An empty
		// responder that can only ever say "good" is not revocation, and putting it on a screen under that word
		// would be the worse of the two outcomes: it teaches a reader this deployment has something it has not.
		//
		// The item stays "ok" and stops naming the fold at all: it is no longer part of the answer.
		revocationRemediation := "Allow the exception on the clients that require revocation checking, " +
			"deliberately. Nothing here is waiting to be built: the certificate where revocation carries " +
			"meaning is this organization's interception CA, and revoking it is already an act this deployment " +
			"performs — POST /admin/interception-intermediate/{tenant}/revoke, refused by the Edges themselves, " +
			"which holds whether or not a client checks. What a client would look up instead is a leaf the Edge " +
			"mints per host and withdraws by not minting, under a per-Edge CA that expires in hours. Serving a " +
			"CRL would satisfy the check without adding revocation, at the price of an address every endpoint " +
			"must reach WITHOUT being steered — a CRL fetched through the tunnel is itself intercepted, and a " +
			"certificate whose revocation check needs a certificate is a loop. Revisit only if a fleet's own " +
			"software cannot be excepted, and staple a response on the connection rather than opening an address."
		items = append(items, pkiReadinessItem{
			ID: "interception_leaf_revocation", Title: "Revocation information on intercepted certificates",
			// ★ ok, NOT attention: this is a DECISION with its reasons written down (the certificate-ownership design),
			// and a permanent attention item is noise that teaches an operator to skim the list. What the reader
			// needs is to recognise the failure when a strict client produces it — so the detail says what is
			// absent and the consequence says what it looks like, on an item that is not asking to be fixed.
			Status: "ok",
			Detail: "none, by decision — certificates minted for intercepted sites carry no CRL distribution " +
				"point and no OCSP responder, so a client that requires revocation checking needs an exception",
			Consequence: "a client that treats \"cannot check revocation\" as fatal refuses them — measured on " +
				"Windows: curl over schannel answers CRYPT_E_NO_REVOCATION_CHECK and the same request with " +
				"--ssl-no-revoke succeeds. The clients that fail are the strict ones, so this selects for the " +
				"most careful software on an endpoint.",
			Remediation: revocationRemediation,
		})
	}

	// 1. Where the interception root key lives. This is the one that cannot be undone after a leak.
	switch {
	case in.KeyCustody == "pkcs11":
		items = append(items, pkiReadinessItem{
			ID: "key_custody", Title: "Interception root key custody", Status: "ok",
			Detail: "held in a PKCS#11 token; the key cannot be copied off the host",
		})
	case strings.Contains(in.KeyCustody, "sealed"):
		items = append(items, pkiReadinessItem{
			ID: "key_custody", Title: "Interception root key custody", Status: "attention",
			Detail:      "sealed on disk with a key-encryption key",
			Consequence: "anyone who obtains both the sealed file and the KEK can mint a certificate any steered endpoint will trust. A PKCS#11 token removes that by making the key non-exportable.",
			Remediation: "Move the interception root key into a PKCS#11 token (or the HSM signing sidecar) and point the Edge at it, so the key becomes non-exportable.",
			Concrete:    concreteKeyCustody(in),
		})
	case in.KeyCustody == "":
		items = append(items, pkiReadinessItem{
			ID: "key_custody", Title: "Interception root key custody", Status: "unknown",
			Detail:      "could not be determined",
			Consequence: "if the key's location is unknown, so is who can copy it.",
			Remediation: "Configure the interception root key's custody explicitly — a PKCS#11 token or the HSM sidecar — so where it lives, and who can copy it, is known.",
			Concrete:    concreteKeyCustody(in),
			Blocking:    true,
		})
	default:
		items = append(items, pkiReadinessItem{
			ID: "key_custody", Title: "Interception root key custody", Status: "missing",
			Detail:      "the key is a plain file on this host",
			Consequence: "a host-level compromise yields a CA every steered endpoint trusts, for as long as that CA is trusted — which is far longer than the intrusion.",
			Remediation: "Move the interception root key into a PKCS#11 token or the HSM signing sidecar and stop using the plain file, so a host compromise no longer yields a trusted CA.",
			Concrete:    concreteKeyCustody(in),
			Blocking:    true,
		})
	}

	// 2. Is that key actually usable? Custody says where it lives, not that it works.
	switch {
	case !in.KeyCustodyChecked:
		items = append(items, pkiReadinessItem{
			ID: "key_custody_health", Title: "Signing works", Status: "unknown", Action: "check-signing",
			Detail:      "no functional check has completed yet",
			Consequence: "a key store that cannot sign looks fine until somebody visits a hostname that is not already cached.",
			Remediation: "Run a signing self-check (sign then verify) against the key store, so this is known-good before real traffic depends on it.",
		})
	case in.KeyCustodyHealthy:
		items = append(items, pkiReadinessItem{
			ID: "key_custody_health", Title: "Signing works", Status: "ok",
			Detail: "the key signs and the signature verifies",
		})
	default:
		items = append(items, pkiReadinessItem{
			ID: "key_custody_health", Title: "Signing works", Status: "missing", Action: "check-signing",
			Detail:      "the key store cannot produce a valid signature",
			Consequence: "already-cached sites keep working, so this stays invisible until somebody visits a new hostname. This node should not take new traffic.",
			Remediation: "Fix the key store so it can sign — check the token/HSM connection and credentials — and keep this node out of rotation until the sign-then-verify passes.",
			Concrete:    concreteKeyCustody(in),
			Blocking:    true,
		})
	}

	// 3. Intermediate. Without one, the root itself signs leaves and cannot be rotated without re-provisioning
	//    every endpoint.
	if in.IntermediateActive {
		items = append(items, pkiReadinessItem{
			ID: "intermediate", Title: "Issuing intermediate", Status: "ok",
			Detail: "leaves chain through a rotatable intermediate",
		})
	} else {
		items = append(items, pkiReadinessItem{
			ID: "intermediate", Title: "Issuing intermediate", Status: "attention",
			Detail:      "the root signs leaves directly",
			Consequence: "rotating the signing key means re-provisioning the trust store on every endpoint, because the thing they trust is the thing that signs.",
			Remediation: "Introduce an issuing intermediate under the root and have leaves chain through it, so the signing key can rotate without re-provisioning every endpoint's trust store.",
			Concrete:    concreteIntermediate(in),
		})
	}

	// 4. Enrolment, and what proves eligibility.
	//
	// Ordered by what the credential actually PROVES, which is the thing that matters at Day-0. An admin-issued
	// one-time token proves a MACHINE an administrator approved — the right question, because at install time
	// nobody knows who will use the laptop. An IdP login proves a PERSON, which is the right question later, at
	// access, and the wrong one here. A shared token proves nothing at all.
	switch {
	case !in.EnrollConfigured:
		items = append(items, pkiReadinessItem{
			ID: "enrolment", Title: "Device enrolment", Status: "missing",
			Detail:      "no device CA is configured, so devices cannot be issued certificates",
			Consequence: "every device identity has to be created and installed by hand.",
			Remediation: "Configure a device CA and the enrolment endpoint so devices can be issued certificates automatically instead of by hand.",
		})
	case in.EnrollSharedToken:
		// Whatever else is configured, a live shared token is the weakest thing accepted, and the weakest thing
		// accepted is what an attacker will use.
		items = append(items, pkiReadinessItem{
			ID: "enrolment", Title: "Device enrolment", Status: "attention", Blocking: true,
			Detail:      "a shared enrolment token is still accepted",
			Consequence: "one non-expiring secret has to sit on every machine that will ever enrol, it names nobody, and anyone who obtains it can add devices to the fleet without limit.",
			Remediation: "Turn off the shared token (-enroll-token=) and issue per-device enrolment tokens from the Console instead, so each one authorises one machine, once, and records which administrator approved it.",
			Concrete:    concreteEnrolment(in),
		})
	case in.EnrollAdminTokens:
		items = append(items, pkiReadinessItem{
			ID: "enrolment", Title: "Device enrolment", Status: "ok",
			Detail: "devices enrol with admin-issued, one-time tokens; each authorises one machine and records who approved it",
		})
	case in.EnrollIdPBacked:
		// A supported end state, not a lesser one. It fits people enrolling their own machines, and flagging it
		// for ever would be a nag nobody can resolve — which is how every other item on the page stops being
		// read. The detail says what the credential proves so an operator can tell whether it fits how their
		// devices are actually set up.
		items = append(items, pkiReadinessItem{
			ID: "enrolment", Title: "Device enrolment", Status: "ok",
			Detail: "eligibility is proved by an IdP login, which is attributable and revocable. It proves a PERSON — right for someone enrolling their own machine; for laptops an administrator prepares before knowing who gets them, issue per-device tokens from the Console instead.",
		})
	default:
		items = append(items, pkiReadinessItem{
			ID: "enrolment", Title: "Device enrolment", Status: "attention", Blocking: true,
			Detail:      "a device CA is configured but nothing proves eligibility to enrol",
			Consequence: "no device can enrol, so the fleet cannot grow.",
			Remediation: "Issue a per-device enrolment token from the Console (Enrolment Tokens) and put it in the machine's installer configuration.",
		})
	}

	// 5. Renewal. THE blocking one once short-lived certificates are issued.
	switch {
	case !in.EnrollConfigured:
		// Nothing is being issued, so nothing has to be renewed yet.
	case in.RenewalEndpoint:
		items = append(items, pkiReadinessItem{
			ID: "renewal", Title: "Certificate renewal", Status: "ok",
			Detail: "devices renew themselves before expiry",
		})
	default:
		items = append(items, pkiReadinessItem{
			ID: "renewal", Title: "Certificate renewal", Status: "missing",
			Detail:      "certificates are issued but nothing renews them",
			Consequence: "every device issued a certificate today fails authentication on the same day months from now, together.",
			Remediation: "Point the device agents at the renewal endpoint and redeploy, so certificates renew themselves before expiry.",
			Concrete:    concreteRenewal(in),
			Blocking:    true,
		})
	}

	// 6. Recovery for a device that was switched off across its own expiry.
	if in.EnrollConfigured && in.RenewalEndpoint {
		if in.RecoveryListener {
			items = append(items, pkiReadinessItem{
				ID: "recovery", Title: "Recovery after a long shutdown", Status: "ok",
				Detail: fmt.Sprintf("an expired device may renew for up to %s past expiry", in.RecoveryWindow),
			})
		} else {
			items = append(items, pkiReadinessItem{
				ID: "recovery", Title: "Recovery after a long shutdown", Status: "attention",
				Detail:      "a device that expires while switched off cannot renew",
				Consequence: "renewal authenticates with the certificate being renewed, so once it lapses the device cannot even ask. A laptop left off over a long holiday comes back needing manual re-enrolment.",
				Remediation: "Enable the renewal recovery listener and give the agents its address, so a device that expired while switched off can still renew on its own.",
				Concrete:    concreteRecovery(in),
			})
		}
	}

	// 7. Is anything about to stop working? Configuration and expiry are different questions, and only this one
	//    has a date on it.
	if in.SoonestExpiryHave {
		days := int(in.SoonestExpiryIn.Hours() / 24)
		switch {
		case in.SoonestExpiryIn <= 0:
			items = append(items, pkiReadinessItem{
				ID: "expiry", Title: "Nothing expired", Status: "missing", Blocking: true,
				Detail:      in.SoonestExpiryWhat + " has EXPIRED",
				Consequence: "whatever depended on it is already failing, and certificates give no warning before they do — this is the symptom, not the warning.",
				Remediation: "Replace or renew " + in.SoonestExpiryWhat + " now.",
			})
		case days <= 14:
			items = append(items, pkiReadinessItem{
				ID: "expiry", Title: "Nothing expiring soon", Status: "missing", Blocking: true,
				Detail:      fmt.Sprintf("%s expires in %d day(s)", in.SoonestExpiryWhat, days),
				Consequence: "nothing degrades first. It works exactly as well as it does today until the moment it stops, and then everything depending on it fails together.",
				Remediation: "Renew or replace " + in.SoonestExpiryWhat + " before it lapses.",
			})
		case days <= 45:
			items = append(items, pkiReadinessItem{
				ID: "expiry", Title: "Nothing expiring soon", Status: "attention",
				Detail:      fmt.Sprintf("%s expires in %d days", in.SoonestExpiryWhat, days),
				Consequence: "far enough away to plan, close enough that forgetting it becomes an outage rather than a task.",
				Remediation: "Schedule the renewal of " + in.SoonestExpiryWhat + " while it is still a choice.",
			})
		default:
			items = append(items, pkiReadinessItem{
				ID: "expiry", Title: "Nothing expiring soon", Status: "ok",
				Detail: fmt.Sprintf("the nearest expiry is %s, in %d days", in.SoonestExpiryWhat, days),
			})
		}
	}

	report := pkiReadinessReport{Items: readinessValues(items, in), ProductionSafe: true}
	for _, item := range items {
		switch item.Status {
		case "ok":
			report.OK++
		case "attention":
			report.Attention++
		case "missing", "unknown":
			report.Missing++
		}
		if item.Blocking && item.Status != "ok" {
			report.ProductionSafe = false
		}
	}
	return report
}

// registerAdminPKIReadinessEndpoint exposes the assessment.
func registerAdminPKIReadinessEndpoint(mux *http.ServeMux, assess func() pkiReadinessReport,
	checkSigning func() pkiReadinessReport, ledger *enrolledinventory.Ledger,
	wrap func(string, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /admin/pki/readiness", wrap("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		report := assess()
		// ★ A readiness finding can be ABOUT A MACHINE, and its detail, remediation and params carry that
		// machine's name. Measured as a customer administrator: "the certificate held by mac-dev-1 expires in
		// 45 days" — another organization's device, on this organization's readiness screen. A finding about
		// somebody else's machine is not this organization's work, so it is withheld rather than reworded.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			kept := make([]pkiReadinessItem, 0, len(report.Items))
			withheld := 0
			for _, item := range report.Items {
				if pkiReadinessItemNamesAnotherOrganization(item, ledger, r) {
					withheld++
					continue
				}
				kept = append(kept, item)
			}
			report.Items = kept
			report.WithheldOtherOrganizations = withheld
		}
		writeJSON(w, http.StatusOK, report)
	}))

	// Run the sign-then-verify NOW rather than waiting for the next scheduled one.
	//
	// The check itself already runs on a timer, so this is not new capability — it is the difference between an
	// operator who has just reconnected a token knowing within a second and finding out at the next interval.
	// That gap is where someone gives up and starts changing other things.
	//
	// Safe to expose: it signs a throwaway payload with the key already in use and verifies the result. It
	// changes nothing, and the worst outcome is learning sooner that the key cannot sign.
	mux.HandleFunc("POST /admin/pki/readiness/check-signing", wrap("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		if checkSigning == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("no interception key store is configured on this Edge"))
			return
		}
		writeJSON(w, http.StatusOK, checkSigning())
	}))
}
