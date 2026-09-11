// Package installprofile is the L1 "install seed": the signed, CP/tenant-authored configuration an endpoint
// agent applies at install time.
//
// It is delivered inside an agentpolicy.Envelope — the SAME Ed25519 signing/verification as the live
// steer-exclusion policy (L3) — so there is one trust mechanism. The agent VERIFIES the signature against a
// pinned public key; a tampered / unsigned / wrong-key / malformed profile is REJECTED and the agent falls
// back to SafeDefaults() (fail-closed, captive ON, no bypass, no transport → must enroll). That is what makes
// "operators cannot loosen posture by hand-editing the profile" structural rather than advisory.
//
// Pure, platform-neutral Go so it is unit-tested on any OS; the Windows config-store (registry) read/write
// that persists the resolved profile is a separate, Windows-only piece.
package installprofile

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// ProfileKind is the schema/type discriminator every install profile must carry. It is checked AFTER signature
// verification so a validly-signed envelope of a DIFFERENT type (e.g. an L3 steer-exclusion policy, which is
// signed with the SAME pinned key) is NOT mistaken for an install profile. Without it, a foreign-but-signed
// payload would unmarshal into InstallProfile (unknown fields dropped) and be reported verified=true.
const ProfileKind = "dsse_install_profile.v1"

// Posture / backend / start-mode / enroll-mode constants.
const (
	PostureFailClosed = "fail-closed"
	PostureFailOpen   = "fail-open"

	// ★★★ A VIRTUAL MACHINE ON THE DEVICE HAS ITS OWN NETWORK STACK, AND THIS AGENT DOES NOT SEE IT
	// (2026-09-01, measured on win-dev-1 with a real WSL2 distro while the agent reported steering).
	//
	// The Windows capture is connect-time classification of sockets on the HOST's TCP/IP stack. A WSL2
	// distro, and any Hyper-V guest, has its own stack and leaves through the virtual switch — so it never
	// reaches the classifier. Measured side by side on one box:
	//
	//	Windows itself   chain=ORG      egress 35.75.123.238   (the deployment's Edge)
	//	inside WSL       public CA      egress 116.82.46.71    (the site's own uplink)
	//
	// The macOS agent captures the same shape correctly — a VM there, with its own address, still egressed
	// through the deployment — so this is a gap in one capture layer, not a property of virtual machines.
	//
	// ★ AND IT NEEDS NO ADMINISTRATOR. That is what makes it a hole rather than a post-compromise detail:
	// this product's job is to make reaching administrator hard, and a standard user on a box where the
	// feature is already enabled must not be able to step around the whole steering layer.
	//
	// So a virtual machine's traffic is BLOCKED while steering is armed, unless the organization has said
	// otherwise — the same two-key shape as fail-open, and for the same reason: "we cannot inspect this" and
	// "we let it out anyway" are two decisions and the operator makes both.
	VMEgressBlocked = "blocked"
	VMEgressAllowed = "allowed"

	BackendWFP       = "wfp"
	BackendWinDivert = "windivert"

	StartAuto        = "auto"
	StartAutoDelayed = "auto-delayed"
	StartManual      = "manual"

	// Captive T_max clamp (bounded to 30s..3600s; default 180s).
	captiveTimeoutMin     = 30
	captiveTimeoutMax     = 3600
	captiveTimeoutDefault = 180
)

// InstallProfile is the signed L1 seed schema. Fields left unset are filled by resolveEffective().
type InstallProfile struct {
	Kind    string `json:"kind"` // must equal ProfileKind (checked after signature verification)
	Version int    `json:"version"`
	// IssuedAt is when the issuer signed this profile, RFC3339 — the anti-rollback ordering key.
	//
	// ★ WHY IT IS IN THE PAYLOAD AND NOT TAKEN FROM THE ENVELOPE (2026-08-17). agentpolicy.Envelope already
	// carries created_at, and reaching for it is the obvious shortcut. It is not signed: the signature covers
	// the payload bytes only (agentpolicy.SignTyped), so anyone replaying an old envelope can set created_at to
	// whatever passes. A freshness stamp an attacker can write is not a freshness stamp. Inside the payload it
	// is covered by the same signature as the transport URL it is there to protect.
	//
	// Empty on every profile issued before this field existed, which is not an error — see configstore.Apply:
	// two profiles are compared only when BOTH carry a stamp, and a stored stamp will not accept an unstamped
	// successor. Anything else would refuse the profiles already deployed.
	IssuedAt     string `json:"issued_at,omitempty"`
	TenantID     string `json:"tenant_id"`
	GroupID      string `json:"group_id,omitempty"` // optional; usually assigned by the CP at enrollment
	TransportURL string `json:"transport_url"`
	// TransportEndpoints are the OTHER addresses this device may start from, as "region=URL" — the same shape
	// the agent's -region-endpoints-seed already takes, and the same addresses the deployment publishes as
	// its regions.
	//
	// ★★★ ONE ADDRESS IS NOT ENOUGH TO START (2026-08-25, the operator's point). TransportURL is what a
	// device uses BEFORE it has the signed region list an Edge hands out — at first install, and again after
	// it has been away long enough to have nothing current. With one address, a deployment whose named region
	// is down can enrol nothing new and cannot take back a device that was off.
	//
	// ★ STEADY STATE IS STILL THE SIGNED LIST. These are a starting set, not a policy: the moment an Edge
	// answers, its list governs, and RegionPriority reorders only regions that list already permits. Nothing
	// here can move a device outside its residency boundary, because nothing here is trusted to add a region
	// the Edge has not allowed.
	TransportEndpoints []string   `json:"transport_endpoints,omitempty"`
	TransportAnchor    string     `json:"transport_anchor,omitempty"` // pinned CA fingerprint; else obtained at enroll
	Enroll             EnrollSpec `json:"enroll"`
	Posture            string     `json:"posture"`      // fail-closed (default) | fail-open (needs AckFailOpen too)
	AckFailOpen        bool       `json:"ack_failopen"` // fail-open requires BOTH this AND Posture==fail-open
	Backend            string     `json:"backend"`      // wfp (default) | windivert
	BypassApps         []string   `json:"bypass_apps"`
	BypassDests        []string   `json:"bypass_dests"`
	DNSListen          string     `json:"dns_listen"`
	BlockQUIC          *bool      `json:"block_quic"` // pointer: nil = unset → default true
	// VMEgress is what happens to traffic from virtual machines on the device — WSL distros and Hyper-V
	// guests — which have their own network stack and are not steered. blocked (default) | allowed.
	// Allowing requires BOTH this AND AckVMEgress, exactly like fail-open: see the note on VMEgressBlocked.
	VMEgress    string      `json:"virtual_machine_egress"`
	AckVMEgress bool        `json:"ack_virtual_machine_egress"`
	StartMode   string      `json:"start_mode"`
	Captive     CaptiveSpec `json:"captive"` // the feature is ALWAYS on; only timing is tunable
	// RegionPriority is the operator's preference among the regions the Edge allows this device to use:
	// region id -> rank, LOWER IS PREFERRED, 1 is the highest. It outranks measured latency; RTT then decides
	// only within one rank. Absent/empty = no preference, every region ties and nearest-RTT decides — which is
	// how every fleet behaves today, so an older profile keeps its current behaviour.
	//
	// ★ WHY THIS IS IN THE SIGNED PROFILE AND NOT AN INSTALLER PROPERTY. It was briefly the latter, on the
	// argument that preference is per-SITE while one signed profile reaches many devices. That argument was
	// about GRANULARITY and the conclusion did not follow: a profile is delivered per install too (bundled,
	// --config <path>, or MDM), so per-site profiles were always available — while an MSI property would have
	// been a SECOND install-time configuration channel beside this one, unsigned, for exactly one setting. Two
	// sources of install-time truth is the divergence class this system keeps getting bitten by, and the cost is
	// not theoretical: an operator would have had to know that every setting comes from the signed profile
	// EXCEPT this one. One channel, signed, is worth more than the convenience of setting it with msiexec.
	//
	// It stays SAFE for the same reason it was safe unsigned: it is applied by lookup onto the Edge's signed
	// allowed-region list (regionfailover.ApplyPriority) with no path to append, so it can only reorder regions
	// the Edge already permitted — it can never move a device outside its residency boundary.
	//
	// Values are NOT sanitized in resolveEffective: a rank of 0 would sanitize to "unspecified", which is the
	// silent inversion the authoring tools refuse (regionfailover.ValidatePriority). Dropping it here would
	// re-introduce that silence at the one place nobody is watching.
	RegionPriority map[string]int `json:"region_priority,omitempty"`
	// Organization names the device presents before it has been told anything. See OrganizationSpec — this is
	// the field that breaks the circle enrolment was stuck in.
	Organization OrganizationSpec `json:"organization,omitempty"`
	// Deployment is everything else the device must be TOLD, so that a profile and a one-time token are the
	// WHOLE of what a customer receives. See DeploymentSpec.
	Deployment DeploymentSpec `json:"deployment,omitempty"`
}

// DeploymentSpec is what a device needs to know about the deployment it is joining, and could not learn from
// the deployment because it has not joined it yet.
//
// ★★★ WHY IT EXISTS (2026-08-29, operator's decision, after putting an agent on a real Mac). The customer is
// given a package and a profile and a one-time token, and that has to be the whole of it. Until now it was
// not: the device also needed an agent_config.json carrying the anchor, the organization's device-CA pin, its
// interception root, the update pins and the steering rules — and nothing in the product produced that file.
// The lab had a script that wrote it by hand, which is a script no customer ever receives, and the product's
// stated answer was "MDM drops it", which makes MDM a requirement rather than a convenience. The gap was
// invisible because every walk of this lane had used the lab's script.
//
// So the profile carries the deployment's facts. They are not secrets: an anchor, two fingerprints, a public
// root and two public keys. What stays out is the ONE-TIME TOKEN, which is the only thing that says this
// device is this device, and which is why the token is still handed over separately.
//
// ★★ ON THE PIN THAT VERIFIES THIS PROFILE. A document cannot carry the key that proves it, and the package is
// deployment-independent so it cannot carry it either. The channel that closes the circle is the one the
// operator already uses: the profile is DOWNLOADED FROM THE CONSOLE over an authenticated session, together
// with the token. That download is the out-of-band step. AgentPolicySigningPublicKey is therefore stated here
// for a device that has none yet to adopt at install time, and — for a device that already has one — checked
// against it, so a second profile signed by a different authority is refused rather than adopted.
type DeploymentSpec struct {
	// AnchorPEM is the deployment's root, which the device verifies every Edge against. A file rather than the
	// system trust store: this authority is not a public CA and must not be reachable by anything that trusts
	// one.
	AnchorPEM string `json:"anchor_pem,omitempty"`
	// TransportAnchorsPEM are the authorities that sign the certificate served for THIS ORGANIZATION'S OWN
	// NAME, when it has one.
	//
	// ★★★ THE PROFILE TOLD A DEVICE TO PRESENT A NAME AND GAVE IT AN ANCHOR THAT CANNOT VERIFY IT (2026-08-29,
	// measured on a real Mac). An organization with its own address on the Edges is served a certificate from
	// its OWN transport CA — `CN=<name> Transport CA` — which the deployment root does not sign. The device
	// was told to dial that name and handed the deployment anchor, so the handshake failed with "unable to
	// get local issuer certificate" and enrolment reported a bare network error.
	//
	// A LIST because a rotation serves two, and a device must verify whichever one it is handed while the
	// fleet moves. Empty when this organization has no name of its own, which is a supported state: it is
	// served the deployment's shared certificate, and AnchorPEM verifies that.
	TransportAnchorsPEM []string `json:"transport_anchors_pem,omitempty"`

	// ★★★ WHETHER THE STEP-UP PORTAL IS SERVED ON A CERTIFICATE THE WORLD ALREADY TRUSTS (2026-09-03, the
	// operator's question: "the authority expansion is for WebView's sake — but is that not because it is
	// Keycloak? With Entra ID, would the device not display it perfectly well?").
	//
	// It settled the design. The step-up ceremony makes three navigations, and only the middle one is the
	// identity provider:
	//
	//	1. the DSSE portal          https://<portal>/clientless/auth/start
	//	2. the identity provider    Entra ID / Okta — publicly trusted; Keycloak in a lab — not
	//	3. the DSSE portal again    https://<portal>/clientless/auth/callback
	//
	// So moving from Keycloak to Entra ID fixes hop 2 and leaves 1 and 3 exactly where they were: on a
	// certificate this deployment issued itself. What fixes THOSE is the thing the operator had already
	// decided — the portal's certificate is theirs to provide — and once they have, nothing needs to be added
	// to any device's trust store at all.
	//
	// A device that is told this can therefore do the right thing in both worlds: trust nothing extra when
	// the portal is publicly trusted, and fall back to this organization's own anchor when it is not, which
	// is a lab. Without the field the device has to assume the worse case forever, and every machine ends up
	// permanently trusting an authority for the sake of a lab.
	StepUpPortalCertificateIsOperators bool `json:"step_up_portal_certificate_is_operators,omitempty"`
	// StepUpPortalAnchorPEM NAMES that authority, rather than leaving each platform to work it out.
	//
	// ★★★ TWO PLATFORMS, TWO WRONG ANSWERS (2026-09-03). Windows derived it from a NAME and trusted an
	// authority the portal never presents. macOS carried a hard-coded list of two hosts — 203.0.113.10 and
	// kc.dsse.lab, a lab that no longer exists — and accepted ANY certificate for them. Both were a device
	// guessing at something the deployment knows: whoever configures the portal knows what serves it.
	//
	// Empty when the operator supplied the portal's certificate, because then there is nothing to add.
	StepUpPortalAnchorPEM string `json:"step_up_portal_anchor_pem,omitempty"`
	// DeviceCAPinSHA256 is the authority that signs THIS ORGANIZATION's device identities. A device that
	// reaches the wrong enrol endpoint refuses the identity it is handed rather than adopting it.
	DeviceCAPinSHA256 string `json:"device_ca_pin_sha256,omitempty"`
	// InterceptionRootPEM is the organization's own inspection root. The device still has to put it where the
	// operating system looks — that is an OS act a profile cannot perform — but it no longer has to be carried
	// to the machine by hand.
	InterceptionRootPEM string `json:"interception_root_pem,omitempty"`
	// InterceptionRootIsOwn says whose root that is: this organization's, or the DEPLOYMENT's, which is what
	// inspects every organization that has not brought one. Both are roots a device must trust to see the
	// traffic it is served; they are not the same decision, and a reader that installs a shared root should
	// be able to tell that it did.
	InterceptionRootIsOwn bool `json:"interception_root_is_own"`
	// AgentPolicySigningPublicKey is the key this profile is signed under. See the note above.
	AgentPolicySigningPublicKey string `json:"agent_policy_signing_public_key,omitempty"`
	// UpdateSigningKeys and UpdatePublisherTeamID are what an endpoint refuses to install without: without
	// them this machine could never be updated, and nothing would say so.
	UpdateSigningKeys     []string `json:"update_signing_keys,omitempty"`
	UpdatePublisherTeamID string   `json:"update_publisher_team_id,omitempty"`
	// SteerExclusions are the signing identifiers this deployment has authored as never-steered. This product
	// ships ZERO built-in exclusions on purpose — an invisible app id inside a binary is not an authored,
	// revocable policy — so this list is the whole list, and it comes from the Console.
	SteerExclusions []string `json:"steer_exclusions,omitempty"`
	// PassthroughDomains are names left uninspected, authored the same way.
	PassthroughDomains []string `json:"passthrough_domains,omitempty"`
}

// OrganizationSpec carries the names this organization's agents put in a ClientHello, stated at INSTALL time.
//
// ★ WHY AT INSTALL TIME AND NOT LEARNED (operator's decision, 2026-08-22). The Edge selects an organization's
// certificate — and the routes that only exist for that organization — by SNI, before any client certificate is
// exchanged. The name was therefore announced in the trust bundle, which arrives AFTER enrolment. Enrolment was
// the thing that needed it. A device with no name to send is served the deployment's shared certificate, and on
// a folded port it also cannot select the enrolment route; if the address it was given is an IP literal it sends
// no SNI at all, because crypto/tls omits the extension for IP literals.
//
// So the tenant is stated when the device is installed, and the circle is cut. This is NOT a second authority:
// an announcement from a signed trust bundle still outranks it, precisely so that a name can be changed without
// reinstalling a fleet. It is the answer for the window before the first bundle, and the fallback if a
// deployment stops announcing.
//
// ★ AND ONLY NAMES THE SERVED CERTIFICATE ACTUALLY CARRIES BELONG HERE. A name the Edge does not serve turns
// every dial into a verification failure — the same shape this deployment has now paid for twice (the recovery
// name on 2026-08-19, the enrolment name on 2026-08-21). Absent is a supported and meaningful state: it means
// "the deployment's shared certificate", which is how every fleet behaved before this field existed.
type OrganizationSpec struct {
	// TenantID is stated for the operator reading the profile and for cross-checking against the profile's own
	// TenantID; the agent does not send it in a ClientHello.
	TenantID string `json:"tenant_id,omitempty"`
	// TransportServerName is the name presented on the (T) transport dial.
	TransportServerName string `json:"transport_server_name,omitempty"`
	// EnrolmentServerName is the name presented when enrolling, which on a folded port is what SELECTS the
	// enrolment route rather than merely labelling it.
	EnrolmentServerName string `json:"enrolment_server_name,omitempty"`
	// RenewalRecoveryServerName is the selector for the expired-certificate recovery path. Left empty on
	// deployments that announce it in the bundle instead, which is where it has lived until now.
	RenewalRecoveryServerName string `json:"renewal_recovery_server_name,omitempty"`
}

// EnrollSpec is how the device proves eligibility and establishes its identity at enrollment.
type EnrollSpec struct {
	Mode     string `json:"mode"` // mdm | token | interactive
	TokenRef string `json:"token_ref,omitempty"`
}

// CaptiveSpec tunes the always-on captive bootstrap window.
type CaptiveSpec struct {
	TimeoutSec int `json:"timeout_sec"`
}

// SafeDefaults is the fail-closed posture applied when no valid signed profile is present. Deliberately has NO
// transport and NO bypass: the box is secure (fail-closed) and unconfigured (must enroll) rather than open.
func SafeDefaults() InstallProfile {
	blockQUIC := true
	return InstallProfile{
		Posture:   PostureFailClosed,
		VMEgress:  VMEgressBlocked,
		Backend:   BackendWFP,
		DNSListen: "127.0.0.1:53",
		BlockQUIC: &blockQUIC,
		StartMode: StartAuto,
		Captive:   CaptiveSpec{TimeoutSec: captiveTimeoutDefault},
	}
}

// FailOpenEnabled reports whether fail-open is truly enabled: posture AND the explicit acknowledgement. Either
// alone leaves the box fail-closed (mirrors failopen_guard on the agent).
func (p InstallProfile) FailOpenEnabled() bool {
	return p.Posture == PostureFailOpen && p.AckFailOpen
}

// resolveEffective fills unset fields with safe defaults and ENFORCES the safety invariants: fail-open needs
// both signals, backend must be known, captive is clamped and never off. Applied to every profile (verified or
// the safe default) so the agent always gets a coherent, safe configuration.
func (p InstallProfile) resolveEffective() InstallProfile {
	d := SafeDefaults()
	out := p
	if out.Backend != BackendWFP && out.Backend != BackendWinDivert {
		out.Backend = d.Backend
	}
	if strings.TrimSpace(out.DNSListen) == "" {
		out.DNSListen = d.DNSListen
	}
	if out.BlockQUIC == nil {
		out.BlockQUIC = d.BlockQUIC
	}
	switch out.StartMode {
	case StartAuto, StartAutoDelayed, StartManual:
	default:
		out.StartMode = d.StartMode
	}
	// Posture: fail-open ONLY when both posture and ack are set; otherwise force fail-closed.
	if !(out.Posture == PostureFailOpen && out.AckFailOpen) {
		out.Posture = PostureFailClosed
		out.AckFailOpen = false
	}
	// A virtual machine's traffic is let out ONLY when both the setting and the acknowledgement say so. An
	// older profile carries neither and therefore blocks — which is the answer that keeps the promise this
	// agent makes about outbound traffic, and the one an organization can lift deliberately.
	if !(out.VMEgress == VMEgressAllowed && out.AckVMEgress) {
		out.VMEgress = VMEgressBlocked
		out.AckVMEgress = false
	}
	// Captive is always on; clamp the window to [min,max], default when unset/invalid.
	if out.Captive.TimeoutSec <= 0 {
		out.Captive.TimeoutSec = captiveTimeoutDefault
	}
	if out.Captive.TimeoutSec < captiveTimeoutMin {
		out.Captive.TimeoutSec = captiveTimeoutMin
	}
	if out.Captive.TimeoutSec > captiveTimeoutMax {
		out.Captive.TimeoutSec = captiveTimeoutMax
	}
	return out
}

// Load parses a signed Envelope JSON, verifies it against the pinned Ed25519 public key, and returns the
// EFFECTIVE profile. On ANY failure (no key, parse, bad/absent signature, wrong key, malformed profile) it
// returns (SafeDefaults resolved, verified=false, err): the agent applies the safe fail-closed defaults and
// NEVER the untrusted operator values. verified=true means the returned profile is the signed, trusted one.
// Sign is how a deployment issues an install profile: the same envelope and the same key as every other
// signed document on this surface, with the profile's own kind on the envelope so a reader can tell what it
// is holding before it opens it.
//
// ★★★ THE ONLY PRODUCER ANYWHERE WAS A DEV TOOL (2026-08-27). profilegen's own header says "in production the
// Control Plane signs profiles with the tenant key" — and nothing in the control plane did. So the one signed
// configuration contract this product has was issued, in every real deployment, by a person running a lab
// utility. This is the primitive the deployment issues with; who calls it is the next question, not this one.
func Sign(signer *agentpolicy.Signer, p InstallProfile, now time.Time) (agentpolicy.Envelope, error) {
	if signer == nil {
		return agentpolicy.Envelope{}, fmt.Errorf("installprofile: no signer")
	}
	if strings.TrimSpace(p.Kind) == "" {
		p.Kind = ProfileKind
	}
	if p.Kind != ProfileKind {
		return agentpolicy.Envelope{}, fmt.Errorf("installprofile: kind %q is not %q", p.Kind, ProfileKind)
	}
	if strings.TrimSpace(p.IssuedAt) == "" {
		p.IssuedAt = now.UTC().Format(time.RFC3339)
	}
	return signer.SignTyped(ProfileKind, p, now)
}

func Load(envelopeJSON []byte, pinnedPubKeyHex string) (profile InstallProfile, verified bool, err error) {
	safe := SafeDefaults().resolveEffective()
	if strings.TrimSpace(pinnedPubKeyHex) == "" {
		return safe, false, fmt.Errorf("installprofile: no pinned public key")
	}
	var env agentpolicy.Envelope
	if e := json.Unmarshal(envelopeJSON, &env); e != nil {
		return safe, false, fmt.Errorf("installprofile: parse envelope: %w", e)
	}
	// ★★★ AND THE ENVELOPE MUST SAY WHAT IT IS (2026-08-27, found while giving macOS this same document).
	// SignTyped's own note says a type nobody compares is "a substitution waiting to happen", and the install
	// profile was the case it describes: it was signed with the DEFAULT envelope type — the same one the live
	// steer policy uses — and told apart only by the payload's kind, checked below. One key legitimately signs
	// several documents on this surface, so the envelope has to carry the distinction too.
	//
	// ★ BOTH ARE ACCEPTED, because profiles issued before this exist on deployed Windows agents and refusing
	// them would strand a fleet to fix a labelling problem. The payload's kind is required either way, which
	// is what actually prevents the substitution; the type makes it visible on the wire.
	if t := strings.TrimSpace(env.Type); t != ProfileKind && t != agentpolicy.EnvelopeType {
		return safe, false, fmt.Errorf("installprofile: envelope type %q is neither %q nor the legacy %q",
			t, ProfileKind, agentpolicy.EnvelopeType)
	}
	// SINGLE KEY, DELIBERATELY — do not "fix" this to VerifyAny with an adopted key set. Every other signed
	// policy verifies against the pin plus keys adopted at runtime, because those have to survive a signing-key
	// rotation. This one must not: the L1 install profile is verified against an anchor baked into the signed
	// binary precisely so that nothing learned at runtime, from a store or a bundle, can decide what this agent
	// installs itself as (review S1). Accepting an adopted key here would let a value the profile itself is
	// supposed to establish trust for turn around and authorise the profile.
	payload, e := agentpolicy.Verify(env, pinnedPubKeyHex)
	if e != nil {
		return safe, false, fmt.Errorf("installprofile: verify: %w", e)
	}
	var p InstallProfile
	if e := json.Unmarshal(payload, &p); e != nil {
		return safe, false, fmt.Errorf("installprofile: parse profile: %w", e)
	}
	// Signed, but is it actually an install profile? Reject a validly-signed envelope of another kind (e.g. an
	// L3 policy signed with the same key) so it is never applied — or mislabeled — as a config profile.
	if p.Kind != ProfileKind {
		return safe, false, fmt.Errorf("installprofile: wrong kind %q (want %q)", p.Kind, ProfileKind)
	}
	return p.resolveEffective(), true, nil
}
