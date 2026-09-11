package agentupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// EnvelopeType marks an update manifest. It rides the SAME signed-envelope wire scheme as the steer policy
// (agentpolicy.Envelope: raw payload bytes signed, transmitted base64) so the Swift and Windows verifiers
// already written against that scheme are reused rather than re-implemented — but under its OWN type, its own
// key, and a type check Open performs before anything else. agentpolicy.Verify is pure crypto and does not
// look at the type; a valid signature over the wrong KIND of artefact must never be mistaken for this one.
const EnvelopeType = "dsse_agent_update_manifest.v1"

// SchemaVersion is the manifest payload schema. It is carried inside the signed payload, not alongside it, so
// it cannot be edited without breaking the signature.
const SchemaVersion = "1"

// Recognised platforms, architectures and artifact kinds. The set is closed: an agent must refuse a manifest
// naming a platform it does not know rather than guess, because "I do not recognise this" and "this is not
// for me" have to reach the operator as the same refusal and not as silence.
const (
	PlatformDarwin  = "darwin"
	PlatformWindows = "windows"

	ArchARM64 = "arm64"
	ArchAMD64 = "amd64"

	ArtifactKindMSI = "msi" // Windows installer, major upgrade
	ArtifactKindPKG = "pkg" // macOS installer package carrying the .app bundle
)

// Delivery says WHO fetches and executes the artifact. Both are supported deliberately: the product ships its
// own updater (DeliveryDSSE) because that is the only way the "when" is under DSSE's control, and fleets that
// already run Intune or Jamf must not be forced to run a second update channel (DeliveryMDM).
//
// The signed manifest is the authority in BOTH cases. Under DeliveryMDM the DSSE updater executes nothing and
// the manifest still names the authorised version and its digest.
//
// ★ WHAT THAT DOES AND DOES NOT ESTABLISH (corrected 2026-08-11, from a review). This comment used to say the
// agent could "report whether what arrived on the box is what was authorised". It cannot. Under MDM delivery
// the updater returns before staging, the digest is never used by either platform, and what the agent reports
// is the VERSION the running code claims about itself. A different build carrying the same version string is
// indistinguishable to everything DSSE has here.
//
// The digest stays REQUIRED because it is a published fact — the value an operator or a future check needs in
// order to establish anything at all, and the same manifest shape verifies under DSSE delivery — but the claim
// is now the true one: DSSE answers "is everyone running the version we approved", and under MDM it does not
// answer "are those the bytes we approved". Requiring a digest nobody checks is defensible; describing it as a
// check is not.
const (
	DeliveryDSSE = "dsse"
	DeliveryMDM  = "mdm"
)

// The refusal reasons. These are distinct sentinels rather than one error string because the acceptance
// condition for this step is that a tampered signature and a mismatched artifact are refused for DIFFERENT,
// individually asserted reasons — a negative check that cannot tell its failures apart passes just as happily
// when the code is refusing everything for the wrong reason.
var (
	ErrMalformed              = errors.New("update manifest is malformed")
	ErrWrongEnvelopeType      = errors.New("signed envelope is not an update manifest")
	ErrUntrusted              = errors.New("update manifest signature is not from a trusted key")
	ErrExpired                = errors.New("update manifest has expired")
	ErrPlatformMismatch       = errors.New("update manifest is for a different platform")
	ErrArchMismatch           = errors.New("update manifest is for a different architecture")
	ErrNotAnUpgrade           = errors.New("update manifest target is not newer than the running version")
	ErrMinFromNotMet          = errors.New("running version is older than the manifest's minimum upgrade-from version")
	ErrArtifactDigestMismatch = errors.New("artifact digest does not match the manifest")
	ErrArtifactSizeMismatch   = errors.New("artifact size does not match the manifest")
	ErrDirtyTarget            = errors.New("update manifest publishes a dirty build as a release target")
)

// Manifest is the signed statement "version V of the agent, for this platform, is these exact bytes".
//
// Note what is NOT here, and note that it is enforced rather than merely omitted: there is no field for
// service arguments, install flags, config paths, or anything else that could change how the agent is
// configured. The update channel MUST NOT be usable as a configuration channel — that is requirement R2.3
// (docs/productization_upgrade_continuity_and_agent_autoupdate.md), and it is why Open decodes strictly and
// refuses a payload carrying any field this schema does not define. Without that, a future manifest could
// smuggle a setting past an older agent that would simply ignore the field, and the fleet's configuration
// would be silently divergent from what the operator authored. See PreservedState for the other half.
type Manifest struct {
	Schema   string `json:"schema"`
	Version  string `json:"version"`  // the agent version this manifest publishes, e.g. "0.2.0"
	Platform string `json:"platform"` // PlatformDarwin | PlatformWindows
	Arch     string `json:"arch"`     // ArchARM64 | ArchAMD64
	Channel  string `json:"channel"`  // free-form release channel ("stable", "beta", …)
	Delivery string `json:"delivery"` // DeliveryDSSE | DeliveryMDM

	ArtifactKind string `json:"artifact_kind"`
	// ArtifactURL is where the DSSE updater fetches the artifact. Empty is only allowed under DeliveryMDM,
	// where the MDM already holds the payload and DSSE never downloads it.
	ArtifactURL    string `json:"artifact_url"`
	ArtifactSHA256 string `json:"artifact_sha256"` // lowercase hex; REQUIRED under both delivery modes
	ArtifactSize   int64  `json:"artifact_size"`   // exact byte count; a short read must not verify

	// MinFromVersion refuses the jump outright when the running build is older than the oldest version this
	// release knows how to migrate from. Fail-closed: the endpoint stays where it is and reports, rather than
	// attempting a migration whose starting state the release was never tested against.
	MinFromVersion string `json:"min_from_version"`

	ReleasedAt string `json:"released_at"` // RFC3339
	// NotAfter bounds how long this manifest may be acted on. It exists so a manifest captured today cannot be
	// replayed at an endpoint years later to pin it onto a build with a since-discovered flaw. Required.
	NotAfter string `json:"not_after"` // RFC3339
}

// PreservedState names the endpoint state an update MUST carry across untouched — requirement R2.3. It is
// exported so the platform updaters (which are the code that can actually violate it) and their tests refer
// to one list instead of each remembering their own.
//
// Regenerating the device identity is the expensive mistake here: the (T) transport client certificate is what
// every per-device grant, heartbeat and posture record is bound to, so an updater that "helpfully" re-enrols
// turns a routine version bump into a fleet-wide re-enrolment storm with a gap in enforcement in the middle.
func PreservedState() []string {
	return []string{
		"device transport identity (the (T) mTLS client certificate and its private key)",
		"the agent's baked service arguments / launchd or SCM configuration",
		"the pinned trust anchors and the agent-policy signing pin",
		"the cached signed steer-exclusion policy",
		"the enrolment record (tenant, device id) and any spent enrolment token state",
	}
}

// Sign validates a manifest and wraps it in the signed envelope. Validation happens BEFORE signing on purpose:
// signing an invalid manifest would produce a correctly-signed artefact that every endpoint refuses, which
// looks like a fleet-wide verification failure and sends the operator hunting for a key problem.
//
// The signer must be a key dedicated to updates — separate from the agent-policy and config-signing keys — so
// that compromise of a policy key cannot mint code the fleet will execute. This function cannot enforce that;
// the deployment does. It is stated here because it is the single most important property of this path.
func Sign(signer *agentpolicy.Signer, m Manifest, now time.Time) (agentpolicy.Envelope, error) {
	if signer == nil {
		return agentpolicy.Envelope{}, fmt.Errorf("%w: no update-manifest signing key", ErrMalformed)
	}
	m.Schema = SchemaVersion
	if err := m.Validate(); err != nil {
		return agentpolicy.Envelope{}, err
	}
	env, err := signer.SignTyped(EnvelopeType, m, now)
	if err != nil {
		return agentpolicy.Envelope{}, err
	}
	// ★ Re-label the key id, because the inherited one NAMES THE THING THIS DESIGN FORBIDS.
	//
	// agentpolicy derives every key id as "edge-agent-policy-<fingerprint>", which is right for the documents
	// that package was written for and actively misleading here: an update manifest signed by the update key
	// arrives at the endpoint announcing itself as agent-policy-signed. Observed on win-dev-1, 2026-08-10, in
	// the first manifest to reach a device — and the reader was right to distrust the label and run a control
	// rather than report it.
	//
	// The field is annotation, not authority: verification is against the PINNED key list, the signature covers
	// the payload bytes, and nothing in this tree matches on it (the Windows courier logs it and that is all).
	// So it can be corrected without touching a signature — and it is worth correcting, because a label nobody
	// verifies is a label someone eventually reads as evidence. One of them already nearly did.
	env.SigningKeyID = updateKeyID(signer.PublicKeyHex())
	return env, nil
}

// KeyIDFor is updateKeyID, exported.
//
// ★ THERE MUST BE ONE DERIVATION (2026-08-12, seventh review). The Edge's audit builder grew its own copy that
// hashed the hex CHARACTERS while this one hashes the decoded key bytes — so a correctly verified key produced
// an audit id that never matched the manifest's own, and every record looked like a mismatch. Two derivations
// of one identifier is a bug with a delay on it.
func KeyIDFor(pubHex string) string { return updateKeyID(pubHex) }

// updateKeyID names the signing key as what it is: an update key, not a policy key. Same derivation as
// agentpolicy's, so the two are comparable at a glance, with a prefix that tells the truth about which class
// of authority signed the document.
func updateKeyID(pubHex string) string {
	raw, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(raw) == 0 {
		return "agent-update-unknown"
	}
	sum := sha256.Sum256(raw)
	return "agent-update-" + hex.EncodeToString(sum[:8])
}

// Open is the whole verification gate: envelope type, signature against the pinned update keys, strict payload
// decode, field validation, and expiry. It returns a Manifest only when every one of those passed.
//
// Order matters. The type is checked before the signature so a valid signature over a different artefact kind
// is reported as the substitution it is, and the payload is only decoded after the signature verifies so no
// attacker-chosen bytes reach the JSON decoder on an unauthenticated path.
func Open(env agentpolicy.Envelope, trustedUpdateKeyHexes []string, now time.Time) (Manifest, error) {
	m, _, err := OpenWithKey(env, trustedUpdateKeyHexes, now)
	return m, err
}

// OpenWithKey is Open, and it also reports the public key (hex) that ACTUALLY verified the signature.
//
// For anything that records evidence: the envelope's own signing_key_id is an unsigned annotation and can be
// rewritten without breaking the signature, so an audit built from it is a claim rather than a finding.
func OpenWithKey(env agentpolicy.Envelope, trustedUpdateKeyHexes []string, now time.Time) (Manifest, string, error) {
	if env.Type != EnvelopeType {
		return Manifest{}, "", fmt.Errorf("%w: got type %q, want %q", ErrWrongEnvelopeType, env.Type, EnvelopeType)
	}
	payload, matchedKey, err := agentpolicy.VerifyAnyWithKey(env, trustedUpdateKeyHexes)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	m, err := decodeStrict(payload)
	if err != nil {
		return Manifest{}, "", err
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, "", err
	}
	notAfter, err := time.Parse(time.RFC3339, m.NotAfter)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("%w: not_after %q is not RFC3339", ErrMalformed, m.NotAfter)
	}
	if now.After(notAfter) {
		return Manifest{}, "", fmt.Errorf("%w: not_after %s, now %s", ErrExpired, m.NotAfter,
			now.UTC().Format(time.RFC3339))
	}
	return m, matchedKey, nil
}

// decodeStrict rejects any field the schema does not define — the enforcement half of R2.3 described on
// Manifest. json.Unmarshal would ignore an unknown field, and "ignored" is how an update channel quietly
// becomes a configuration channel.
func decodeStrict(payload []byte) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("%w: trailing content after the manifest object", ErrMalformed)
	}
	return m, nil
}

// Validate checks the manifest is internally coherent, independent of any particular endpoint.
func (m Manifest) Validate() error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("%w: schema %q, want %q", ErrMalformed, m.Schema, SchemaVersion)
	}
	target, err := ParseVersion(m.Version)
	if err != nil {
		return err
	}
	// A build made from a modified working tree corresponds to no commit, so nobody can later reproduce it or
	// say what is in it. That is exactly the artefact that must not become a fleet's target version.
	if target.Dirty() {
		return fmt.Errorf("%w: %s", ErrDirtyTarget, m.Version)
	}
	switch m.Platform {
	case PlatformDarwin, PlatformWindows:
	default:
		return fmt.Errorf("%w: unknown platform %q", ErrMalformed, m.Platform)
	}
	switch m.Arch {
	case ArchARM64, ArchAMD64:
	default:
		return fmt.Errorf("%w: unknown arch %q", ErrMalformed, m.Arch)
	}
	switch m.ArtifactKind {
	case ArtifactKindMSI, ArtifactKindPKG:
	default:
		return fmt.Errorf("%w: unknown artifact_kind %q", ErrMalformed, m.ArtifactKind)
	}
	if strings.TrimSpace(m.Channel) == "" {
		return fmt.Errorf("%w: channel is required", ErrMalformed)
	}
	switch m.Delivery {
	case DeliveryDSSE:
		if err := validateArtifactURL(m.ArtifactURL); err != nil {
			return err
		}
	case DeliveryMDM:
		// The MDM holds the payload; DSSE names the authorised version and digest so the authorised value is
		// published even though nothing on the endpoint compares it today (see the note above — the version is
		// what DSSE establishes under this mode). A URL here would be a second, unmanaged download path and is
		// refused rather than ignored.
		if strings.TrimSpace(m.ArtifactURL) != "" {
			return fmt.Errorf("%w: delivery=mdm must not carry an artifact_url (the MDM delivers the payload)", ErrMalformed)
		}
	default:
		return fmt.Errorf("%w: unknown delivery %q (want %q or %q)", ErrMalformed, m.Delivery, DeliveryDSSE, DeliveryMDM)
	}
	if !isSHA256Hex(m.ArtifactSHA256) {
		return fmt.Errorf("%w: artifact_sha256 must be 64 lowercase hex characters", ErrMalformed)
	}
	if m.ArtifactSize <= 0 {
		return fmt.Errorf("%w: artifact_size must be positive", ErrMalformed)
	}
	if strings.TrimSpace(m.MinFromVersion) != "" {
		minFrom, merr := ParseVersion(m.MinFromVersion)
		if merr != nil {
			return fmt.Errorf("%w (min_from_version)", merr)
		}
		if CompareVersions(minFrom, target) > 0 {
			return fmt.Errorf("%w: min_from_version %s is newer than the published version %s", ErrMalformed, m.MinFromVersion, m.Version)
		}
	}
	if _, perr := time.Parse(time.RFC3339, m.ReleasedAt); perr != nil {
		return fmt.Errorf("%w: released_at %q is not RFC3339", ErrMalformed, m.ReleasedAt)
	}
	if _, perr := time.Parse(time.RFC3339, m.NotAfter); perr != nil {
		return fmt.Errorf("%w: not_after %q is not RFC3339", ErrMalformed, m.NotAfter)
	}
	return nil
}

// validateArtifactURL requires https. An update artifact is privileged code; its digest is pinned by the
// signed manifest, so plain http would not let an attacker substitute the bytes — but it would let one
// enumerate which endpoint is fetching which build, and there is no reason to accept that.
func validateArtifactURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("%w: delivery=dsse requires an artifact_url", ErrMalformed)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%w: artifact_url is not a URL: %v", ErrMalformed, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: artifact_url must be https, got %q", ErrMalformed, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: artifact_url has no host", ErrMalformed)
	}
	return nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Applicable answers "may THIS endpoint act on this manifest", given what it is currently running. A nil
// return is the only thing that authorises an update; every refusal names its own reason so an operator
// looking at a stuck endpoint learns which condition held it back.
func (m Manifest) Applicable(currentVersion string, platform, arch string) error {
	if m.Platform != platform {
		return fmt.Errorf("%w: manifest is for %s, this endpoint is %s", ErrPlatformMismatch, m.Platform, platform)
	}
	if m.Arch != arch {
		return fmt.Errorf("%w: manifest is for %s, this endpoint is %s", ErrArchMismatch, m.Arch, arch)
	}
	current, err := ParseVersion(currentVersion)
	if err != nil {
		return fmt.Errorf("%w (running version)", err)
	}
	target, err := ParseVersion(m.Version)
	if err != nil {
		return err
	}
	// Downgrade is refused here, not merely discouraged: an attacker who can replay an old signed manifest
	// would otherwise be able to walk a fleet back onto a build with a known flaw, using nothing but material
	// that was once legitimately signed. Returning to the immediately-previous build is a separate, locally
	// initiated path (step 4's auto-rollback) and deliberately does not go through a manifest.
	//
	// Equality also refuses, and that is where the build-metadata limitation bites: 0.1.0+a and 0.1.0+b compare
	// equal, so a rollout between two builds of one version cannot be expressed. See Version.
	if CompareVersions(target, current) <= 0 {
		return fmt.Errorf("%w: running %s, manifest publishes %s", ErrNotAnUpgrade, current.Core(), target.Core())
	}
	if strings.TrimSpace(m.MinFromVersion) != "" {
		minFrom, merr := ParseVersion(m.MinFromVersion)
		if merr != nil {
			return fmt.Errorf("%w (min_from_version)", merr)
		}
		if CompareVersions(current, minFrom) < 0 {
			return fmt.Errorf("%w: running %s, this release migrates only from %s or newer", ErrMinFromNotMet, current.Core(), minFrom.Core())
		}
	}
	return nil
}

// VerifyArtifact streams the downloaded bytes and checks them against the manifest. It is the last gate before
// privileged execution, so it checks the SIZE as well as the digest and treats a short read as a failure:
// a truncated download that happened to be cut at a block boundary must not be able to reach the installer.
//
// It reads one byte past the declared size on purpose. A reader that yields MORE than the manifest declares is
// not the artifact that was signed, and stopping exactly at the limit would hash a prefix of it and pass.
func VerifyArtifact(r io.Reader, m Manifest) error {
	if !isSHA256Hex(m.ArtifactSHA256) || m.ArtifactSize <= 0 {
		return fmt.Errorf("%w: manifest carries no usable artifact digest/size", ErrMalformed)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, m.ArtifactSize+1))
	if err != nil {
		return fmt.Errorf("%w: read artifact: %v", ErrArtifactSizeMismatch, err)
	}
	if n != m.ArtifactSize {
		return fmt.Errorf("%w: read %d bytes, manifest declares %d", ErrArtifactSizeMismatch, n, m.ArtifactSize)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != m.ArtifactSHA256 {
		return fmt.Errorf("%w: got sha256:%s, manifest declares sha256:%s", ErrArtifactDigestMismatch, got, m.ArtifactSHA256)
	}
	return nil
}
