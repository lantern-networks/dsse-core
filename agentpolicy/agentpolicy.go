// Package agentpolicy is the cross-platform core of the admin-managed, server-signed steer-exclusion
// policy. The Edge SIGNS a device's steer-exclusion set
// (Ed25519); each endpoint agent VERIFIES it against a pinned public key and applies it, ignoring any
// locally-edited app list (the tamper-resistance core).
//
// This package is platform-agnostic Go so BOTH the Edge (cmd/edge) and the Windows steering agent
// (cmd/windivert-steer) share one signing/verification implementation. The macOS NE has its own
// CryptoKit verifier; this package's cross-language test fixtures keep the two byte-compatible.
//
// CROSS-LANGUAGE scheme: the signature is over the RAW payload bytes, and the payload is transmitted
// base64-encoded — so no consumer must reproduce another's JSON serialization byte-for-byte. Verify =
// base64-decode payload, check sha256, Ed25519-verify the bytes, then parse.
package agentpolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/internal/posixperm"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"
)

const (
	// EnvelopeType is the schema marker for the signed steer-policy envelope.
	EnvelopeType = "dsse_agent_steer_policy.v1"
	// SignaturePrefix prefixes the base64url Ed25519 signature.
	SignaturePrefix = "ed25519:"
	// ECDSAP256SignaturePrefix prefixes a base64url ASN.1 ECDSA-P256-SHA256 signature. It exists because the
	// config-signing key cannot move into a PKCS#11 token as Ed25519 — no available crypto11 binding (checked
	// through v1.7.0-rc1) implements Ed25519 in a token — so HSM custody for this key requires ECDSA. The
	// verifier accepts BOTH; nothing signs ECDSA until the token key is put in service, so adding this is inert.
	ECDSAP256SignaturePrefix = "ecdsa-p256-sha256:"
)

// Envelope is the signed wrapper a consumer verifies. PayloadB64 holds the exact signed bytes.
type Envelope struct {
	Type          string `json:"type"`
	Version       string `json:"version"`
	SigningKeyID  string `json:"signing_key_id"`
	CreatedAt     string `json:"created_at"`
	PayloadSHA256 string `json:"payload_sha256"` // hex(sha256(payload bytes))
	PayloadB64    string `json:"payload_b64"`    // base64(std) of the payload JSON bytes (the signed bytes)
	Signature     string `json:"signature"`      // "ed25519:" + base64url(Ed25519.Sign(payload bytes))
}

// Signer signs steer-policy payloads with a stable key — Ed25519 (the provisioned default) or ECDSA-P256
// (the shape a PKCS#11 token can hold). It wraps a crypto.Signer so an in-process key and an HSM-backed one
// are the same to the caller; the algorithm is decided once, at construction, from the public key's type.
type Signer struct {
	signer  crypto.Signer
	isECDSA bool
	pubHex  string // Ed25519: 32-byte hex; ECDSA-P256: uncompressed-point hex (0x04||X||Y)
	keyID   string
}

// KeyIDFor derives a stable key id from an Ed25519 public key. Kept for existing callers; keyIDForBytes is the
// general form the ECDSA path uses.
func KeyIDFor(pub ed25519.PublicKey) string { return keyIDForBytes(pub) }

func keyIDForBytes(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "edge-agent-policy-" + hex.EncodeToString(sum[:8])
}

// LoadOrGenerateSigner loads the Ed25519 signing seed (32-byte hex) from path. When path is set but the
// file is absent, a seed is generated and persisted (the public key consumers pin stays stable across
// restarts). Empty path = dev-ephemeral; empty path with devMode=false = signing disabled (nil signer).
func LoadOrGenerateSigner(path string, devMode bool) (*Signer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		if !devMode {
			return nil, nil
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return newSigner(priv), nil
	}
	signer, rerr := loadSignerFile(path, devMode)
	if rerr == nil {
		return signer, nil
	}
	// Only a genuinely ABSENT file means "generate a new seed". Any OTHER read error (permission, transient
	// I/O) must fail loud — the old code treated every error as absent and OVERWROTE the seed, silently
	// rotating the signing identity and invalidating everything already signed under the old key (the NE
	// pins the public key, so a rotation locks out every enrolled endpoint until it re-pins) — review #34.
	if !errors.Is(rerr, fs.ErrNotExist) {
		return nil, rerr
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return nil, fmt.Errorf("persist agent-policy signing key %q: %w", path, err)
	}
	return newSigner(ed25519.NewKeyFromSeed(seed)), nil
}

// LoadSigner loads an existing signing key and NEVER creates one. A fallback path — "the HSM is unreachable,
// use the on-disk key" — needs load-or-fail, not load-or-mint: a freshly generated key is one no device has
// ever pinned or adopted, so the Edge would come up reporting healthy while signing policy the entire fleet
// rejects. That is review #34's failure mode arriving through the recovery path instead of the normal one.
//
// It exists because expressing that intent as os.Stat followed by LoadOrGenerateSigner does not actually
// guarantee it: between the two calls the file can disappear, and the call that runs next is the one whose job
// is to mint a key. A guarantee that depends on losing a race is not a guarantee.
//
// A missing file is reported as fs.ErrNotExist so callers can tell "no fallback configured" from "the fallback
// is broken" — the two deserve different messages, and only one of them is an emergency.
func LoadSigner(path string, devMode bool) (*Signer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("no agent-policy signing key path: %w", fs.ErrNotExist)
	}
	return loadSignerFile(path, devMode)
}

// loadSignerFile reads and validates an existing key file. Shared by LoadSigner and LoadOrGenerateSigner so the
// mode guard and the seed check cannot drift between "load" and "load or generate".
func loadSignerFile(path string, devMode bool) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err // reported verbatim so errors.Is(…, fs.ErrNotExist) holds for callers
		}
		return nil, fmt.Errorf("read agent-policy signing key %q: %w", path, err)
	}
	// A key this process WROTE is 0600; a key it merely reads has whatever mode it was given, and nothing
	// checked. This one signs the policy every agent applies and whose public half every agent PINS — anyone
	// who can read it can sign policy the entire fleet will accept as ours. Found at 0644 on the reference
	// deployment, readable by every account on the host, with nothing anywhere saying so.
	//
	// A production node refuses; development mode warns and continues, because a development stack that will
	// not start gets worked around rather than fixed. Same split as the weak-admin-token guard.
	if info, serr := os.Stat(path); serr == nil {
		switch verdict := signingKeyModeVerdict(info.Mode().Perm(), posixperm.Meaningful(), devMode); verdict {
		case keyModeRefuse:
			return nil, fmt.Errorf("agent-policy signing key %q is mode %04o: readable beyond its owner, and it signs the policy every agent applies — chmod 600 it (this is the key agents pin)", path, info.Mode().Perm())
		case keyModeWarn:
			log.Printf("WARNING: agent-policy signing key %s is mode %04o — readable beyond its owner. "+
				"Anyone who can read it can sign policy this fleet accepts as ours; chmod 600 it. "+
				"(development mode: continuing; a production node refuses to start)", path, info.Mode().Perm())
		case keyModeUnverifiable:
			// ★★★ SAY THAT IT WAS NOT CHECKED, RATHER THAN PASS OR REFUSE (2026-08-31, measured: the Edge
			// could not start on Windows at all). os.FileMode.Perm() reports a constant 0666 there whatever
			// the file actually permits, so this guard was reading a value carrying no information and
			// refusing on it — a refusal that says nothing about the key. Passing silently would be worse:
			// the operator would believe a guarantee nobody delivered. The honest third answer is to state
			// that this platform's control is an ACL and this check cannot see it.
			log.Print(unverifiableKeyModeNote(path))
		}
	}
	seed, derr := hex.DecodeString(strings.TrimSpace(string(data)))
	if derr != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("agent-policy signing key %q must be a %d-byte hex seed", path, ed25519.SeedSize)
	}
	return newSigner(ed25519.NewKeyFromSeed(seed)), nil
}

func newSigner(priv ed25519.PrivateKey) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{signer: priv, isECDSA: false, pubHex: hex.EncodeToString(pub), keyID: keyIDForBytes(pub)}
}

// NewSignerFromCrypto wraps any crypto.Signer — an in-process key or an HSM-backed one — as an agent-policy
// signer. Ed25519 and ECDSA-P256 are the two accepted key types; the algorithm and public-key encoding are
// fixed here so Sign and every verifier agree. This is how the config-signing key moves into a token: the
// token's ECDSA key is handed in here and nothing else in the signing path changes.
func NewSignerFromCrypto(signer crypto.Signer) (*Signer, error) {
	if signer == nil {
		return nil, fmt.Errorf("nil signer")
	}
	switch pub := signer.Public().(type) {
	case ed25519.PublicKey:
		return &Signer{signer: signer, isECDSA: false, pubHex: hex.EncodeToString(pub), keyID: keyIDForBytes(pub)}, nil
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("agent-policy ECDSA signing key must be P-256, got %s", pub.Curve.Params().Name)
		}
		raw := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
		return &Signer{signer: signer, isECDSA: true, pubHex: hex.EncodeToString(raw), keyID: keyIDForBytes(raw)}, nil
	default:
		return nil, fmt.Errorf("unsupported agent-policy signing key type %T (want Ed25519 or ECDSA-P256)", pub)
	}
}

// PublicKeyHex is the anchor a consumer pins to verify signatures.
func (s *Signer) PublicKeyHex() string { return s.pubHex }

// KeyID is the stable key identifier derived from the public key.
func (s *Signer) KeyID() string { return s.keyID }

// Sign wraps a steer-policy payload object in a signed envelope.
func (s *Signer) Sign(payloadObj any, now time.Time) (Envelope, error) {
	return s.SignTyped(EnvelopeType, payloadObj, now)
}

// SignTyped is Sign with the envelope type named by the caller, so a SECOND kind of signed artefact can reuse
// this exact wire scheme (and therefore the Swift and Windows verifiers already written against it) instead of
// growing a second, subtly-different copy of the same crypto. The agent update manifest is the first such
// consumer (oss/agentupdate).
//
// The type is not decoration. Verify deliberately does NOT check it — it is a pure crypto check — so every
// caller must compare env.Type against the type it asked for BEFORE trusting the payload. Two artefact kinds
// signed by one key and distinguished only by a field nobody reads is a substitution waiting to happen; that
// is why the update manifest is also specified to use a key of its own.
//
// Ed25519 signs the raw payload; ECDSA-P256 signs its SHA-256 (what every verifier here checks). The prefix
// names the algorithm so a verifier never has to guess it from the key.
func (s *Signer) SignTyped(envelopeType string, payloadObj any, now time.Time) (Envelope, error) {
	if strings.TrimSpace(envelopeType) == "" {
		return Envelope{}, fmt.Errorf("envelope type is required")
	}
	payload, err := json.Marshal(payloadObj)
	if err != nil {
		return Envelope{}, err
	}
	sum := sha256.Sum256(payload)
	env := Envelope{
		Type:          envelopeType,
		Version:       "1",
		SigningKeyID:  s.keyID,
		CreatedAt:     now.UTC().Format(time.RFC3339),
		PayloadSHA256: hex.EncodeToString(sum[:]),
		PayloadB64:    base64.StdEncoding.EncodeToString(payload),
	}
	if s.isECDSA {
		sig, serr := s.signer.Sign(rand.Reader, sum[:], crypto.SHA256)
		if serr != nil {
			return Envelope{}, fmt.Errorf("ecdsa sign: %w", serr)
		}
		env.Signature = ECDSAP256SignaturePrefix + base64.RawURLEncoding.EncodeToString(sig)
		return env, nil
	}
	// Ed25519 signs the whole message; crypto.Hash(0) selects the pure-EdDSA mode.
	sig, serr := s.signer.Sign(rand.Reader, payload, crypto.Hash(0))
	if serr != nil {
		return Envelope{}, fmt.Errorf("ed25519 sign: %w", serr)
	}
	env.Signature = SignaturePrefix + base64.RawURLEncoding.EncodeToString(sig)
	return env, nil
}

// VerifyAny accepts the envelope if ANY of the supplied keys verifies it, and is how a signing key is rotated
// without freezing a fleet: during the overlap a device holds both the key it was provisioned with and the one
// published in the signed trust bundle, so policy keeps arriving whichever key signed it.
//
// It is not a weakening. Every key in the set had to arrive inside a bundle signed by the key already in force,
// so the set's provenance is the same signature chain as everything else; a malformed entry is dropped rather
// than tried, because a key here is a key this device will accept instructions from. An empty set is an error,
// never a pass — "no keys" must not read as "no checking".
func VerifyAny(env Envelope, pubKeyHexes []string) ([]byte, error) {
	payload, _, err := VerifyAnyWithKey(env, pubKeyHexes)
	return payload, err
}

// VerifyAnyWithKey is VerifyAny, and it also reports WHICH key matched.
//
// ★ THE ENVELOPE'S OWN signing_key_id IS NOT EVIDENCE (2026-08-12, sixth review). It is an annotation OUTSIDE
// the signed payload: anyone able to hand over an envelope can rewrite it without invalidating anything, so an
// audit record built from it says "signed under key X" on the word of whoever supplied the document. That is
// precisely backwards for the one record that ties an installed build to the authority that authorised it.
//
// The matched key is a fact the verification already established and was throwing away. Callers that record
// evidence should derive the key id from THIS return value.
func VerifyAnyWithKey(env Envelope, pubKeyHexes []string) ([]byte, string, error) {
	var lastErr error
	tried := 0
	for _, k := range pubKeyHexes {
		if !isAcceptedPublicKeyHex(k) {
			continue // silently dropped: a malformed key is not something to attempt or to report as a near-miss
		}
		tried++
		payload, err := Verify(env, k)
		if err == nil {
			return payload, k, nil
		}
		lastErr = err
	}
	if tried == 0 {
		return nil, "", fmt.Errorf("no usable signing key to verify against")
	}
	return nil, "", fmt.Errorf("verify against %d accepted signing key(s): %w", tried, lastErr)
}

// isHexLower reports whether s is non-empty lowercase hex of the given byte length.
func isHexLower(s string, byteLen int) bool {
	if len(s) != byteLen*2 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isAcceptedPublicKeyHex reports whether s is a signing key this package can verify against: a hex Ed25519
// public key (32 bytes) or a hex ECDSA-P256 public key as an uncompressed point (65 bytes, 0x04||X||Y that
// actually lies on the curve). Used to drop malformed entries from a published key set before they are tried.
// The two are unambiguous by length, so the keyring needs no per-entry type tag.
func isAcceptedPublicKeyHex(s string) bool {
	k := strings.ToLower(strings.TrimSpace(s))
	if isHexLower(k, ed25519.PublicKeySize) {
		return true
	}
	return ecdsaP256FromHex(k) != nil
}

// AcceptedPublicKeyHex is the exported form, for callers that must decide whether a published key is usable
// BEFORE they have an envelope to try it against.
//
// ★ ONE definition, deliberately. The second definition of this rule was wrong: the macOS updater validated
// policy keys as "64 hex characters" — correct for Ed25519, and silently false for the ECDSA-P256 key the
// config-signing HSM switch put in force. The adopted key was dropped without a word, the rollout plan could
// not be verified, and the freeze that halts a bad release fell back to being only as strong as a file
// permission. A validator stricter than the verifier rejects what the system can handle, and does it quietly.
func AcceptedPublicKeyHex(s string) bool { return isAcceptedPublicKeyHex(s) }

// ecdsaP256FromHex parses an uncompressed-point hex ECDSA-P256 public key, or nil if it is not one / not on
// the curve. elliptic.Unmarshal returns a nil X for anything off the curve, so this cannot accept a point an
// attacker fabricated off-curve.
func ecdsaP256FromHex(k string) *ecdsa.PublicKey {
	if !isHexLower(k, 65) { // 0x04 || 32-byte X || 32-byte Y
		return nil
	}
	raw, err := hex.DecodeString(k)
	if err != nil {
		return nil
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil {
		return nil
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

// Verify base64-decodes the payload, checks its sha256, and verifies the signature against the pinned public
// key. The algorithm is chosen by the signature prefix, and the key must match it: Ed25519 (the provisioned
// default) or ECDSA-P256-SHA256 (the shape a PKCS#11 token can hold — see ECDSAP256SignaturePrefix).
// Fail-closed: any mismatch is an error and never returns bytes.
func Verify(env Envelope, pubKeyHex string) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != env.PayloadSHA256 {
		return nil, fmt.Errorf("payload checksum mismatch")
	}
	keyHex := strings.ToLower(strings.TrimSpace(pubKeyHex))

	switch {
	case strings.HasPrefix(env.Signature, ECDSAP256SignaturePrefix):
		pub := ecdsaP256FromHex(keyHex)
		if pub == nil {
			return nil, fmt.Errorf("signature is ECDSA-P256 but the pinned key is not an ECDSA-P256 public key")
		}
		sig, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env.Signature, ECDSAP256SignaturePrefix))
		if err != nil {
			return nil, fmt.Errorf("decode signature: %w", err)
		}
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return nil, signatureMismatch(env, keyHex, "ECDSA-P256-SHA256")
		}
		return payload, nil

	case strings.HasPrefix(env.Signature, SignaturePrefix):
		pub, derr := hex.DecodeString(keyHex)
		if derr != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signature is Ed25519 but the pinned key is not an Ed25519 public key")
		}
		sig, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env.Signature, SignaturePrefix))
		if err != nil {
			return nil, fmt.Errorf("decode signature: %w", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
			return nil, signatureMismatch(env, keyHex, "Ed25519")
		}
		return payload, nil

	default:
		return nil, fmt.Errorf("signature must use the %s or %s prefix", SignaturePrefix, ECDSAP256SignaturePrefix)
	}
}

// signingKeyModeVerdict decides what to do about the mode a signing key reports.
//
// Split out from the caller so all four answers are testable on any machine — including the one that only
// happens on Windows, which is the one that broke. The caller cannot be tested for it, because the platform
// is what decides.
type keyModeAnswer int

const (
	keyModeOK keyModeAnswer = iota
	keyModeRefuse
	keyModeWarn
	// keyModeUnverifiable: the mode bits carry no information on this OS, so neither refusing nor passing
	// silently is honest.
	keyModeUnverifiable
)

func signingKeyModeVerdict(mode fs.FileMode, modeBitsMeaningful, devMode bool) keyModeAnswer {
	if !modeBitsMeaningful {
		return keyModeUnverifiable
	}
	if mode&0o077 == 0 {
		return keyModeOK
	}
	if devMode {
		return keyModeWarn
	}
	return keyModeRefuse
}
