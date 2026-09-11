package updateplatform

// source.go — where the two documents come from on this platform, and where the artifact waits.
//
// ★ NEITHER COURIER IS TRUSTED, and that is the design rather than a shortcut. A manifest's authority is its
// pinned signature and its own not_after, so the channel is a delivery mechanism and nothing more. That is
// what lets a root daemon read a file another process wrote without either of them having to trust the other —
// and it is why this file verifies unconditionally rather than because of where the bytes came from.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// ErrNoManifest is the quiet answer: nothing is published for this device. It is the normal state of most
// devices on most days and must never read as a fault.
var ErrNoManifest = errors.New("updateplatform: no manifest published for this device")

// ErrManifestRejected wraps every reason a manifest may not be believed.
//
// Distinct from "could not be read" because the caller that REPORTS has to tell them apart: a refused manifest
// is either a broken release or a substitution and needs a person tonight, while an unreadable file is an
// operational fault that may fix itself. By the time an error reaches a log line that distinction is gone
// unless it is carried.
var ErrManifestRejected = errors.New("the update manifest was refused")

// ManifestPath is where the NE courier writes the envelope.
func ManifestPath() string { return DataRoot + "/update-manifest.json" }

// PlanPath is where the NE courier writes the rollout plan.
func PlanPath() string { return DataRoot + "/update-plan.json" }

// FileManifestSource reads a signed manifest envelope from disk and verifies it.
type FileManifestSource struct {
	Path        string
	TrustedKeys []string
}

// Fetch reads, verifies and returns the manifest.
//
// An ABSENT file is ErrNoManifest: a device with nothing published is the ordinary state. Everything else is
// an error, deliberately — a malformed, wrongly-typed, untrusted or expired manifest is something an operator
// needs told about, and treating it as "nothing to do" would leave a fleet not updating with no visible cause.
func (s FileManifestSource) Fetch(_ context.Context, now time.Time) (agentupdate.Manifest, error) {
	if len(s.TrustedKeys) == 0 {
		// A verifier with no keys that accepts anything is worse than no verifier, because it looks like one.
		return agentupdate.Manifest{}, fmt.Errorf("%w: no trusted update-signing keys are configured, so this "+
			"device can never update; refusing to open a manifest that nothing can verify", ErrManifestRejected)
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return agentupdate.Manifest{}, ErrNoManifest
		}
		return agentupdate.Manifest{}, fmt.Errorf("updateplatform: read %s: %w", s.Path, err)
	}
	var env agentpolicy.Envelope
	if jerr := json.Unmarshal(raw, &env); jerr != nil {
		return agentupdate.Manifest{}, rejected(raw, "%w: %s is not a signed envelope: %w", ErrManifestRejected,
			s.Path, jerr)
	}
	m, oerr := agentupdate.Open(env, s.TrustedKeys, now)
	if oerr != nil {
		return agentupdate.Manifest{}, rejected(raw, "%w: %s did not verify: %w", ErrManifestRejected, s.Path, oerr)
	}
	return m, nil
}

// RejectedDocument carries the digest of the EXACT bytes that were refused.
//
// ★ RE-READING THE FILE WAS A TOCTOU (2026-08-12, tenth review). A refusal of an unverifiable manifest has no
// version to name it by, so the digest IS its identity — and hashing the path again afterwards let a courier
// replace the file in between, so the refusal identified bytes that were never rejected. A later substitution
// could then be suppressed as a repeat of it.
type RejectedDocument struct {
	Err    error
	Digest string
}

func (r *RejectedDocument) Error() string { return r.Err.Error() }
func (r *RejectedDocument) Unwrap() error { return r.Err }

// RejectedDigest is the digest of the refused bytes, or "" when this error is not about a document.
func RejectedDigest(err error) string {
	var doc *RejectedDocument
	if errors.As(err, &doc) {
		return doc.Digest
	}
	return ""
}

func rejected(raw []byte, format string, args ...any) error {
	sum := sha256.Sum256(raw)
	return &RejectedDocument{Err: fmt.Errorf(format, args...), Digest: hex.EncodeToString(sum[:])}
}

// LoadRollout reads the couriered plan. Thin on purpose: the DECISION — that an unverifiable plan is a FREEZE
// rather than a fallback — lives in agentupdate and is shared, because a second answer to it would be a
// platform on which damaging the plan lifts a halt.
func LoadRollout(path string, trustedKeys []string, now time.Time, exp agentupdate.RolloutExpectation) (agentupdate.Rollout, error) {
	return agentupdate.LoadRollout(path, trustedKeys, now, exp)
}

// stageTimeout bounds one download. Generous, because a .pkg is tens of megabytes and the device may be on a
// home link at 02:00 — bounded, because a stalled transfer must not hold the loop forever.
const stageTimeout = 30 * time.Minute

// Stage fetches the artifact, verifies it, and places it where Execute will look.
//
// ★ THE ORDERING IS THE SECURITY PROPERTY, and it is the same one the Windows side arrived at: the bytes are
// verified while still under a temporary name, so the path handed to `installer` only ever appears on a file
// that has already passed. Downloading straight to that path and checking afterwards leaves a window — a
// crash, a power loss — in which an unverified file sits exactly where a privileged install will look for it,
// and the next pass would find it "already staged".
func Stage(ctx context.Context, client *http.Client, m agentupdate.Manifest) (string, error) {
	if m.Delivery == agentupdate.DeliveryMDM {
		return "", errors.New("updateplatform: this manifest is delivered by MDM; DSSE does not fetch it")
	}
	if m.ArtifactURL == "" {
		return "", errors.New("updateplatform: manifest has no artifact URL")
	}
	if m.ArtifactSize <= 0 {
		return "", errors.New("updateplatform: manifest declares no artifact size; refusing an unbounded download")
	}
	dst, err := StagedPath(m.Version)
	if err != nil {
		return "", err
	}
	// Already holding the right bytes? Checked by DIGEST, not by the filename: a name is not a digest, and the
	// interval between staging and installing can be days.
	if _, verr := VerifyStaged(m); verr == nil {
		return dst, nil
	}
	if err := os.MkdirAll(StagedRoot(), 0o750); err != nil {
		return "", fmt.Errorf("updateplatform: create %s: %w", StagedRoot(), err)
	}
	tmp, err := os.CreateTemp(StagedRoot(), "staging-*.partial")
	if err != nil {
		return "", fmt.Errorf("updateplatform: create temp in %s: %w", StagedRoot(), err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if client == nil {
		client = &http.Client{}
	}
	ctx, cancel := context.WithTimeout(ctx, stageTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.ArtifactURL, nil)
	if err != nil {
		return "", fmt.Errorf("updateplatform: build request for %s: %w", m.ArtifactURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("updateplatform: fetch %s: %w", m.ArtifactURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// ★ THE BODY IS THE DIFFERENCE BETWEEN TWO 404s (2026-08-11, measured while breaking this on purpose).
		// An Edge that PREDATES the artifact route answers net/http's own "404 page not found"; an Edge that has
		// the route but lost the file answers "the published manifest's artifact is not on this edge". Identical
		// status, different repair — rebuild the Edge, or put the package where the manifest says it is. I read
		// the first as the second today, from this exact message.
		//
		// Same helper as the Windows side, deliberately: a device's account of why it could not update should not
		// depend on which platform is telling it.
		return "", fmt.Errorf("updateplatform: fetch %s: HTTP %d%s", m.ArtifactURL, resp.StatusCode,
			agentupdate.DescribeHTTPErrorBody(resp.Body))
	}
	// Bounded by the manifest's own declared size, plus one byte so an oversized body is DETECTED rather than
	// silently truncated into something that then fails a digest check for a misleading reason.
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, m.ArtifactSize+1))
	if err != nil {
		return "", fmt.Errorf("updateplatform: download %s: %w", m.ArtifactURL, err)
	}
	if written > m.ArtifactSize {
		return "", fmt.Errorf("updateplatform: %s served more than the declared %d bytes", m.ArtifactURL, m.ArtifactSize)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("updateplatform: sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	// Verified while it is still called *.partial and therefore still un-runnable.
	f, oerr := os.Open(tmpName)
	if oerr != nil {
		return "", oerr
	}
	verr := agentupdate.VerifyArtifact(f, m)
	f.Close()
	if verr != nil {
		// ★ A STALE MANIFEST IS NOT AN ATTACK, and must not be reported in an attack's words. The artifact URL
		// carries no version, so a device whose courier has not refreshed (every 15 minutes) downloads whatever
		// the Edge publishes NOW and checks it against the release it still holds. Measured on this Mac fifteen
		// minutes after a publication: "the downloaded artifact does not match the manifest" — which is exactly
		// what a substitution looks like, for the most ordinary reason there is.
		if served := strings.TrimSpace(resp.Header.Get(agentupdate.ArtifactVersionHeader)); served != "" &&
			!agentupdate.SameVersion(served, m.Version) {
			return "", fmt.Errorf("updateplatform: the downloaded artifact does not match the manifest: %w — this "+
				"edge is serving %s and this device holds a manifest for %s, so these are the wrong bytes rather "+
				"than tampered ones; the manifest refreshes on its own and the next attempt will match",
				verr, served, m.Version)
		}
		return "", fmt.Errorf("updateplatform: the downloaded artifact does not match the manifest: %w", verr)
	}
	// 0640 root:wheel by inheritance: this file is the input to a privileged install.
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return "", fmt.Errorf("updateplatform: place %s: %w", dst, err)
	}
	return dst, nil
}

// ClearStaged removes a staged package once it is installed or superseded: a staged artifact is a privileged
// install waiting to happen, and leaving supplanted ones on disk widens the window in which one could be run
// by something other than this updater.
func ClearStaged(version string) error {
	p, err := StagedPath(version)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("updateplatform: remove staged %s: %w", p, err)
	}
	return nil
}

// CurrentArch is what this BINARY is, in the manifest's vocabulary.
func CurrentArch() string { return currentArch }

// Plan is this endpoint's LOCAL configuration: the fallback window used before the device has heard from
// anyone, and MaxAttempts, which the fleet plan does not carry.
type Plan struct {
	LocalStart         string
	LocalEnd           string
	RequireIdleMinutes int
	RequireUnattended  bool
	RequireACPower     bool
	DeadlineDays       int
	MaxAttempts        int
}

// DefaultPlan is what a device uses before a rollout plan reaches it.
//
// ★ RequireIdleMinutes is set here and is 0 on Windows, and that difference is the point: HIDIdleTime is
// maintained on a Mac (measured at 45.7 s on a real one) while Windows reports zero for the console session.
// A default that a platform cannot satisfy would ship a fleet that only ever updates at its deadline.
func DefaultPlan() Plan {
	return Plan{
		LocalStart:         "02:00",
		LocalEnd:           "04:00",
		RequireIdleMinutes: 10,
		RequireUnattended:  true,
		RequireACPower:     true,
		DeadlineDays:       14,
		MaxAttempts:        agentupdate.DefaultMaxAttempts,
	}
}

// Apply folds the fleet plan's window over the local one. Fields the rollout does not carry keep the local
// value: a plan that only sets `frozen` must not silently rewrite every device's schedule to
// midnight-to-midnight.
func (p Plan) Apply(r agentupdate.Rollout) Plan {
	w := r.Plan.Window
	if w == nil {
		return p
	}
	// ★ THE RULE ITSELF LIVES IN agentupdate (2026-08-13, thirtieth review #22). It was written out here and in
	// the other platform's file, in the same words, after the twenty-ninth review found that a plan carrying
	// nothing but a window zeroed the safety gates. Two copies of a rule are two places for the next one to
	// land, and this lane's history is rules that shipped on one OS.
	merged := agentupdate.RaiseWindow(p.Window(), *w)
	out := p
	out.LocalStart = merged.LocalStart
	out.LocalEnd = merged.LocalEnd
	out.RequireIdleMinutes = merged.RequireIdleMinutes
	out.RequireUnattended = merged.RequireUnattended
	out.RequireACPower = merged.RequireACPower
	out.DeadlineDays = merged.DeadlineDays
	return out
}

// Window converts the plan into what the gate consumes.
func (p Plan) Window() agentupdate.MaintenanceWindow {
	return agentupdate.MaintenanceWindow{
		LocalStart:         p.LocalStart,
		LocalEnd:           p.LocalEnd,
		RequireIdleMinutes: p.RequireIdleMinutes,
		RequireUnattended:  p.RequireUnattended,
		RequireACPower:     p.RequireACPower,
		DeadlineDays:       p.DeadlineDays,
	}
}
