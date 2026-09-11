// update_courier.go — the agent as courier for the two signed documents the updater reads, and deliberately nothing more.
//
// The updater service holds no network identity: it reads a signed envelope from
// %ProgramData%\DSSE\update-manifest.json and verifies it against keys baked into its own binary. That design
// (updateplatform/source_file.go) rests on the signature being the trust boundary rather than the channel,
// which is what makes it safe for the file to be written by something else. This is that something else.
//
// THE AGENT IS THE OBVIOUS AUTHOR and not for convenience: it already holds the (T) mTLS transport, already
// runs signed-policy fetch loops of exactly this shape (steer_exclusion_sync.go), and is already the process
// the Edge identifies per device — which the manifest needs, because which release a device is offered is a
// per-device answer once rollout waves exist.
//
// ★ THE ENVELOPE IS WRITTEN UNOPENED. This file does not verify the signature, and that is a decision rather
// than an omission. The updater verifies it, and an agent that pre-approved the same bytes would be a second
// opinion the updater would then have to either trust (making the agent part of the trust boundary, for no
// gain) or ignore (making the check pointless). One verifier, at the point of use.
//
// What this file DOES check is that the body is an envelope of the right type at all — see writeIfPlausible.
// That is not a trust judgement; it is refusing to hand the updater something that would make it raise a
// security alarm about a proxy error page.
//
// Portable Go with no build tag, like steer_exclusion_sync.go: the decisions here — when to keep, when to
// clear, what counts as plausible — are the whole content, and they should not go untested because the host
// was the wrong OS. The atomic write is injected.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

// updateManifestPath is the Edge contract sibling of the agent-policy endpoint. Both endpoints key their
// answer to the cert-proven device identity from the (T) mTLS client certificate, so no device id is sent —
// the same rule the effective-exclusions report follows, and the reason a device cannot ask about another
// device.
const updateManifestPath = "/steer/agent-update-manifest"

// platform and arch are query parameters, both REQUIRED — the Edge answers 400 without them rather than
// guessing a default, which is right: a default here would silently hand a device the wrong build's manifest.
//
// They are device-declared, and that is safe for a reason worth writing down: they only select WHICH document
// is handed over. The manifest carries the platform it is for and the updater's Applicable refuses one that
// does not match the endpoint it is running on, so a device that lies receives something it then rejects
// itself. It cannot obtain a build for a platform it is not.
const manifestPlatform = "windows"

// manifestArch is the architecture this box actually runs.
//
// ★ IT WAS THE CONSTANT "amd64" (2026-08-13, twenty-ninth review). So an ARM64 Windows device asked for the
// amd64 release, refused it every tick because the manifest does not match the endpoint it is running on, and
// the fleet view — which reads the arch the REPORT lane sends, the real one — answered "no release is
// published for arm64". Two halves of the same device disagreeing about what it is, and neither of them
// wrong on its own.
func manifestArch() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROCESSOR_ARCHITECTURE")), "ARM64") {
		return "arm64"
	}
	// PROCESSOR_ARCHITECTURE reads x86 for a 32-bit process on 64-bit Windows; PROCESSOR_ARCHITEW6432 is what
	// the OS actually is in that case. Checked because mapping "not ARM64" to amd64 is how a device ends up
	// asking for a build it cannot run.
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROCESSOR_ARCHITEW6432")), "ARM64") {
		return "arm64"
	}
	return "amd64"
}

// updatePlanPath is the rollout plan: when this device may install, and whether the fleet is halted.
//
// A SECOND document rather than a field on the first, because they are signed by different keys on purpose —
// the plan by the agent-policy key, the manifest by the update key. An Edge may decide WHEN a fleet updates
// and must never be able to decide WHAT it runs, and merging them into one document would put both powers
// under whichever key signed it.
const updatePlanPath = "/steer/agent-update-plan"

// maxDocBytes bounds the body. An envelope is a few kilobytes; this is generous by three orders of
// magnitude and exists so a wrong endpoint returning something enormous cannot be written to disk on a
// machine whose network this product is responsible for.
const maxDocBytes = 1 << 20

// signedDocCourier fetches ONE signed envelope over the (T) transport and puts it where a second process
// reads it. Two of these run: the update manifest and the rollout plan.
//
// ★ ONE TYPE RATHER THAN TWO, and the reason is not brevity. The two couriers differ in exactly three things —
// which path, which envelope type, which file — and every other behaviour here is a property that BOTH must
// have: keep what is on disk when the answer is uncertain, never delete, refuse a body that is not an
// envelope, bound the read. Written twice, one copy eventually loses one of those quietly.
//
// The plan makes that concrete. Deletion lifting a freeze is already the residual gap the Mac side named; a
// plan courier that had grown its own delete path would have widened it, and nothing would have flagged the
// difference between the two files.
type signedDocCourier struct {
	// what varies
	name         string // for log lines: "update-manifest" / "update-plan"
	path         string // Edge path, with any query already attached
	envelopeType string // the agentpolicy.Envelope Type this endpoint must return
	// unsignedSchema, when set, accepts a body that carries NO envelope type — but ONLY if the body names
	// itself with this `schema_version`. Empty means the endpoint's document must always be a typed envelope.
	//
	// Only the plan sets it, and only because the Edge still serves that document unsigned — as a bare JSON
	// object — when it has no agent-policy signer. The distinction matters: "no type" is the unsigned form and
	// is legitimate, while "some other type" is a routing mistake, and on this document a routing mistake is
	// expensive. An exclusion policy served on the plan path would reach the updater, fail to verify as a plan,
	// and under the rule that an unverifiable plan is a FREEZE it would HALT THE FLEET.
	//
	// ★ IT USED TO BE A bool, AND THAT WAS THE HOLE (2026-08-13, found by the macOS side while fixing the same
	// defect in its own courier — review 30 #13). `json.Unmarshal` into a struct is lenient about missing
	// fields, so ANY JSON object decodes to an envelope with `Type == ""`: a proxy or captive portal answering
	// 200 with `{"error":"gateway timeout"}` was indistinguishable from the unsigned plan, and got written over
	// a verified one. Under signed operation the updater then refuses it as ErrPlanUnverifiable, which is a
	// FREEZE — one misrouted response stops that device updating.
	//
	// A schema name rather than a bool because the accept-path must not be expressible without saying what the
	// body has to call itself. The check goes no further than the name: judging the contents is the updater's
	// job, and a courier that starts verifying documents duplicates a layer that already exists.
	unsignedSchema string
	// write persists the envelope bytes atomically. Injected because the atomic-rename dance is OS-specific
	// and because the tests must not need %ProgramData%.
	//
	// There is deliberately no counterpart that deletes. Removing one of these is a fleet-affecting action and
	// this loop is not entitled to take it from a status code — see refreshOnce.
	write func([]byte) error

	// the rest
	client   *http.Client // wired to the (T) mTLS transport (transportHTTPClient)
	baseURL  string       // Edge base, e.g. https://<transport-host>
	interval time.Duration
	logf     func(string, ...any)
}

// errNotPublished is the Edge saying this device has nothing for this document. It is the normal answer for
// most devices and is returned so the caller can stay silent about it rather than logging a fault every tick.
var errNotPublished = errors.New("nothing published for this device")

// newManifestCourier configures c for the update manifest.
//
// The envelope type IS required here, unlike the plan: this endpoint always serves a signed envelope, and a
// steer policy arriving on the manifest path is a routing mistake worth naming at the courier rather than
// letting it reach the updater as ErrManifestRejected — which by design means "artefacts are being
// substituted, look tonight".
func newManifestCourier(c *signedDocCourier) *signedDocCourier {
	c.name = "update-manifest"
	c.path = updateManifestPath + "?platform=" + manifestPlatform + "&arch=" + manifestArch()
	c.envelopeType = agentupdate.EnvelopeType
	return c
}

// refreshOnce fetches the manifest once and reconciles the file on disk.
//
// ★ NOTHING HERE DELETES A MANIFEST, and the first version of this file was wrong about that.
//
// I had 404 clear the local copy, reasoning that otherwise an operator cannot un-publish and a release
// withdrawn after a bad batch keeps installing itself. The reasoning was right and the mechanism was not: on
// the Edge as built, a manifest is a file in a directory, so "withdrawn" and "never published" and "the
// operator pointed at the wrong directory" are all the same 404. Clearing on it means a single Edge
// misconfiguration silently disarms the update path across the fleet, and — worse — does so in the direction
// that looks healthy. Nothing reports "no devices are being offered anything".
//
// The withdrawal problem is real and belongs to a signed document rather than to a status code: the rollout
// plan's freeze says stop, it says so in bytes the device can verify, and it cannot be produced by a
// misdirected file path. That is the concrete reason I am taking the plan courier (option 1 of the two you
// offered) rather than leaving it — without it there is no way to stop a bad release on devices that already
// hold its manifest.
//
// So there are two outcomes, not three:
//
//   - a manifest arrives and is plausible -> written.
//   - anything else — 404, a 5xx, a transport error, a body that is not an envelope — KEEPS what is on disk.
//     A device may be mid-window with that manifest, and the updater re-reads it every pass.
func (s *signedDocCourier) refreshOnce(ctx context.Context) error {
	base := strings.TrimRight(strings.TrimSpace(s.baseURL), "/")
	if base == "" {
		return fmt.Errorf("%s courier: no Edge base URL", s.name)
	}
	url := base + s.path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%s courier: build request: %w", s.name, err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s courier: fetch: %w", s.name, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// The NORMAL state for most devices most of the time. Quiet, and explicitly not a reason to touch what
		// is on disk.
		return errNotPublished
	case resp.StatusCode == http.StatusBadRequest:
		// The Edge requires platform and arch and this agent always sends both, so a 400 means the contract
		// moved. Named rather than folded into the generic branch: it is a build-time mismatch between agent
		// and Edge, and it will not fix itself with retries.
		return fmt.Errorf("%s courier: the Edge rejected %s as malformed (HTTP 400) — the endpoint contract "+
			"has changed and this agent needs updating by another path", s.name, s.path)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s courier: Edge returned HTTP %d; keeping what is already on disk", s.name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes+1))
	if err != nil {
		return fmt.Errorf("%s courier: read body: %w", s.name, err)
	}
	if len(body) > maxDocBytes {
		return fmt.Errorf("%s courier: body exceeds %d bytes; refusing it", s.name, maxDocBytes)
	}
	return s.writeIfPlausible(body)
}

// writeIfPlausible writes the envelope only when the body is structurally an update-manifest envelope.
//
// NOT a signature check — the updater owns that. This exists because of what a bad body costs at the other
// end: the updater reports a body it cannot open as ErrManifestRejected, which by design means "either the
// release process is broken or something is substituting artefacts, and somebody should look tonight". A
// captive-portal HTML page or a truncated proxy response would raise that alarm. Refusing to write anything
// that is not even shaped like an envelope keeps a transport fault a transport fault.
//
// The type check is included for the same reason and no more: an envelope of the WRONG type is a real
// misconfiguration (a steer policy served on the update path), and it is cheaper to say so here than to have
// it arrive at the updater as a security event.
func (s *signedDocCourier) writeIfPlausible(body []byte) error {
	var env agentpolicy.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%s courier: the response is not a signed envelope (%w); keeping what is already on disk", s.name, err)
	}
	// An ABSENT type is accepted only where the endpoint legitimately produces one — the plan, which an Edge
	// without an agent-policy signer serves as a bare JSON object. A WRONG type is refused either way, and on
	// the plan that refusal is the expensive one to get right: an exclusion policy served on the plan path
	// would reach the updater, fail to verify as a plan, and under the rule that an unverifiable plan is a
	// FREEZE it would halt the fleet.
	//
	// The JSON parse above is NOT the guard it was once described as. It stops a captive-portal HTML page and a
	// truncated response; it does not stop a captive portal that answers in JSON, because every JSON object
	// decodes into this struct with the absent fields left empty. That is what namesItself covers.
	if s.envelopeType != "" && env.Type != s.envelopeType {
		if s.unsignedSchema == "" || env.Type != "" {
			return fmt.Errorf("%s courier: envelope type %q is not %q; keeping what is already on disk",
				s.name, env.Type, s.envelopeType)
		}
		if err := s.namesItself(body); err != nil {
			return err
		}
	}
	// Signature, payload and expiry are NOT examined. The updater does that with its own baked keys, and the
	// bytes are passed through byte-for-byte so what it verifies is what the Edge signed — re-serialising the
	// decoded struct here would risk changing them.
	if err := s.write(body); err != nil {
		return fmt.Errorf("%s courier: write: %w", s.name, err)
	}
	s.logf("%s courier: published for this device (%d bytes, signing key %s)", s.name, len(body), env.SigningKeyID)
	return nil
}

// namesItself refuses an untyped body that does not declare the schema this endpoint's unsigned form uses.
//
// The whole check is one string. It is deliberately not a decode of the document: the courier's job is to tell
// "a document of the expected kind" from "whatever the network handed us", and the moment it starts reading
// fields it becomes a second, weaker validator of a document the updater already validates with its own keys.
// A body that lies about its schema still gets refused downstream; a body that never claimed to be a plan
// should not have been written over one.
//
// Unknown fields are tolerated HERE on purpose, unlike DecodeRolloutPlan which refuses them. A newer Edge
// serving a plan with a field this build does not know is still a plan, and the courier writing it lets the
// updater produce the specific complaint. Refusing it here would turn a version skew into a document that
// never arrives, which on this document reads as "nothing published" — the silence that hides a stopped fleet.
func (s *signedDocCourier) namesItself(body []byte) error {
	var named struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(body, &named); err != nil {
		return fmt.Errorf("%s courier: the untyped response cannot be read as a %s document (%w); keeping what "+
			"is already on disk", s.name, s.unsignedSchema, err)
	}
	if named.SchemaVersion != s.unsignedSchema {
		return fmt.Errorf("%s courier: the response carries no envelope type and calls itself %q rather than "+
			"%q, so it is not this endpoint's unsigned form — a proxy or portal answering in JSON looks exactly "+
			"like this; keeping what is already on disk", s.name, named.SchemaVersion, s.unsignedSchema)
	}
	return nil
}

// run polls until the context is cancelled. The first pass happens immediately: a device that has just
// started is the one most likely to be behind, and waiting a full interval to find out delays every update by
// that much for no benefit.
func (s *signedDocCourier) run(ctx context.Context) {
	tick := func() {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := s.refreshOnce(c); err != nil {
			if errors.Is(err, errNotPublished) {
				return // the quiet, normal case: nothing published, nothing kept
			}
			s.logf("%v", err)
		}
	}
	tick()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
