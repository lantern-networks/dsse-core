// source_file.go — where the manifest comes from, and why that turned out to be the smaller question.
//
// THE SIGNATURE IS THE TRUST BOUNDARY, NOT THE CHANNEL. agentupdate.Open verifies the envelope against keys
// baked into this binary, refuses any other envelope type, refuses unknown fields, and refuses a manifest
// past its not_after. A manifest that survives that is authoritative no matter how it arrived; one that does
// not is worthless no matter how carefully it was delivered.
//
// That collapses the transport question. The updater is a separate service from the agent and does not hold
// the agent's mTLS material, and the obvious answers were to give it a second TLS client stack with access to
// the device key, or to mint it a second identity. Both add a privileged network surface to the riskiest
// component we have, in order to protect a document that is already self-protecting.
//
// So this source reads a file. Whoever writes it — the agent, an MDM, an administrator during a controlled
// rollout — does not need to be trusted, which is the entire point of having signed it.
//
// WHAT THE FILE PATH STILL HAS TO DO. Replay is the one thing a signature alone does not stop: a valid
// manifest from six months ago is still validly signed. Two things already bound it, and both are in
// agentupdate rather than here — not_after expires a captured manifest, and Applicable refuses anything that
// is not an upgrade, so a downgrade cannot be replayed onto a device even with a genuine signature. The
// remaining exposure is a nuisance rather than a compromise, and the directory being SYSTEM/Administrators-
// writable is what closes it.
package updateplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

// ManifestFileName is the drop location under %ProgramData%\DSSE.
const ManifestFileName = "update-manifest.json"

// DefaultManifestPath is where the updater looks: %ProgramData%\DSSE\update-manifest.json.
//
// Under %ProgramData%\DSSE rather than beside the binaries, for the same reason the rollback store is: the
// install directory is what an upgrade rewrites and an uninstall removes, and a manifest that disappears
// during the install it describes is a manifest that cannot be reasoned about afterwards.
func DefaultManifestPath() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "DSSE", ManifestFileName)
	}
	return filepath.Join("DSSE", ManifestFileName)
}

// ErrManifestRejected wraps every reason a manifest may not be believed: a body that is not an envelope, the
// wrong envelope type, an untrusted signature, an unknown field, an expired not_after.
//
// It exists because the caller that REPORTS has to tell two failures apart, and by the time it sees an error
// the distinction is gone. "A manifest arrived and was refused" means either the release process is broken or
// something is substituting artefacts, and needs a person tonight; "the file could not be read" is an
// operational fault that may well fix itself. A refusal that reads like an outage is a silent security
// control, which is the failure class this tree keeps closing — so the sentinel is here, at the only place
// that still knows which happened.
var ErrManifestRejected = errors.New("the update manifest was refused")

// FileManifestSource reads a signed manifest envelope from disk and verifies it.
type FileManifestSource struct {
	// Path is the envelope file. Empty uses DefaultManifestPath.
	Path string
	// TrustedKeys are the update-signing public keys, hex. Empty is a configuration error and is reported as
	// one rather than treated as "trust everything" — a verifier with no keys that accepts anything is worse
	// than no verifier, because it looks like one.
	TrustedKeys []string
}

// Fetch reads, verifies and returns the manifest.
//
// An absent file is ErrNoManifest: a device with nothing published is the normal state and must not read as a
// fault. Every other failure is returned as an error, deliberately — a malformed, wrongly-typed, untrusted or
// expired manifest is something an operator needs told about, and quietly treating it as "nothing to do"
// would leave a fleet not updating with no visible reason.
func (s FileManifestSource) Fetch(ctx context.Context, now time.Time) (agentupdate.Manifest, error) {
	if len(s.TrustedKeys) == 0 {
		return agentupdate.Manifest{}, fmt.Errorf("%w: no trusted update-signing keys are configured, so this device "+
			"can never update; refusing to open a manifest that nothing can verify", ErrManifestRejected)
	}
	path := s.Path
	if path == "" {
		path = DefaultManifestPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return agentupdate.Manifest{}, ErrNoManifest
		}
		return agentupdate.Manifest{}, fmt.Errorf("updateplatform: read %s: %w", path, err)
	}
	var env agentpolicy.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return agentupdate.Manifest{}, rejected(raw, "%w: %s is not a signed envelope: %w", ErrManifestRejected,
			path, err)
	}
	m, err := agentupdate.Open(env, s.TrustedKeys, now)
	if err != nil {
		// The specific reason travels in the message; the sentinel says what to DO about it, which is the same
		// for all of them: refuse, install nothing, tell somebody.
		return agentupdate.Manifest{}, rejected(raw, "%w: %s did not verify: %w", ErrManifestRejected, path, err)
	}
	return m, nil
}

// RejectedDocument carries the digest of the EXACT bytes that were refused.
//
// ★ RE-READING THE FILE WAS A TOCTOU (2026-08-12, tenth review). The refusal used to be fingerprinted by
// hashing the path again afterwards, so a courier replacing the file between the verification and the hash made
// the refusal identify bytes that were never rejected — and a later substitution could then be suppressed as a
// repeat, or attributed to the wrong document. The digest now comes from the buffer verification was handed.
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
