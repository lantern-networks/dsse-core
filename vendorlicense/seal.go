package vendorlicense

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Sealing: the signed licence, encrypted to one holder.
//
// This does NOT hide anything from the holder — their own software decrypts it, so any key the software has,
// they have. What it does is stop everyone who HANDLES the file in between from reading it: a mail server, a
// ticketing system, whoever forwards it. A plaintext licence naming seat counts and a customer is a commercial
// disclosure to all of them, and that is a real leak even though it is not the one people first imagine.
//
// Integrity is not this layer's job and never was. The signature underneath is what stops a holder inflating
// their own seat count, and it keeps working whether the file is sealed or not.
//
// Sign THEN seal, which has one known weakness: a recipient can re-encrypt the same signed licence to somebody
// else, and it would verify there too. The payload names its holder for exactly that reason — see Verify.

// SealedLicense is the file a vendor hands over. Opaque: reading it tells you nothing.
type SealedLicense struct {
	Type string `json:"type"`
	// EphemeralPublicKey is a fresh X25519 public key, one per licence. It is what makes a fixed nonce safe:
	// the encryption key is derived from a key agreement that never repeats, so no key is ever used twice.
	EphemeralPublicKey string `json:"ephemeral_public_key"` // base64(raw 32 bytes)
	Ciphertext         string `json:"ciphertext"`           // base64(ChaCha20-Poly1305 output)
	// RecipientKeyID is a hint so a holder with more than one key knows which to try. Non-secret, and NOT
	// trusted: it selects a key, it does not authorise anything.
	RecipientKeyID string `json:"recipient_key_id,omitempty"`
}

const (
	sealedType    = "dsse.vendor-license.sealed.v1"
	sealKDFInfo   = "dsse vendor licence seal v1"
	sealKeyLength = chacha20poly1305.KeySize
)

// Seal encrypts a signed envelope to one holder's X25519 public key.
func Seal(env Envelope, recipient *ecdh.PublicKey, recipientKeyID string) (SealedLicense, error) {
	if recipient == nil {
		return SealedLicense{}, fmt.Errorf("no recipient key")
	}
	plaintext, err := json.Marshal(env)
	if err != nil {
		return SealedLicense{}, fmt.Errorf("marshal licence envelope: %w", err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return SealedLicense{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return SealedLicense{}, fmt.Errorf("key agreement: %w", err)
	}
	key, err := sealKey(shared, ephemeral.PublicKey().Bytes(), recipient.Bytes())
	if err != nil {
		return SealedLicense{}, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return SealedLicense{}, fmt.Errorf("aead: %w", err)
	}
	// A zero nonce is correct HERE and would be a serious bug almost anywhere else: the key is derived from a
	// fresh ephemeral agreement for every licence, so it encrypts exactly one message and can never repeat.
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, plaintext, []byte(sealKDFInfo))
	return SealedLicense{
		Type:               sealedType,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Ciphertext:         base64.StdEncoding.EncodeToString(ct),
		RecipientKeyID:     strings.TrimSpace(recipientKeyID),
	}, nil
}

// Open decrypts a sealed licence. The signature is verified afterwards, by Verify — decryption proves only that
// this file was addressed to this holder, never that the vendor issued it.
func Open(sealed SealedLicense, recipient *ecdh.PrivateKey) (Envelope, error) {
	if recipient == nil {
		return Envelope{}, fmt.Errorf("no recipient key is configured; a sealed licence cannot be opened")
	}
	epkRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sealed.EphemeralPublicKey))
	if err != nil {
		return Envelope{}, fmt.Errorf("decode ephemeral key: %w", err)
	}
	epk, err := ecdh.X25519().NewPublicKey(epkRaw)
	if err != nil {
		return Envelope{}, fmt.Errorf("ephemeral key is not a valid X25519 point: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sealed.Ciphertext))
	if err != nil {
		return Envelope{}, fmt.Errorf("decode ciphertext: %w", err)
	}
	shared, err := recipient.ECDH(epk)
	if err != nil {
		return Envelope{}, fmt.Errorf("key agreement: %w", err)
	}
	key, err := sealKey(shared, epkRaw, recipient.PublicKey().Bytes())
	if err != nil {
		return Envelope{}, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return Envelope{}, fmt.Errorf("aead: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, ct, []byte(sealKDFInfo))
	if err != nil {
		// Wrong key, wrong recipient, or a tampered file — and they are indistinguishable on purpose. Reporting
		// which would tell whoever is probing whether they have the right key.
		return Envelope{}, fmt.Errorf("this licence is not readable with the configured key")
	}
	var env Envelope
	if err := json.Unmarshal(plaintext, &env); err != nil {
		return Envelope{}, fmt.Errorf("decode licence envelope: %w", err)
	}
	return env, nil
}

// sealKey derives the encryption key, binding BOTH public keys into the derivation. Without the recipient's key
// in there, a ciphertext could be re-targeted by an attacker who can replace the ephemeral key.
func sealKey(shared, ephemeralPub, recipientPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(sealKDFInfo)+len(ephemeralPub)+len(recipientPub))
	info = append(info, []byte(sealKDFInfo)...)
	info = append(info, ephemeralPub...)
	info = append(info, recipientPub...)
	key := make([]byte, sealKeyLength)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, info), key); err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

// RecipientKeyFingerprint identifies a key without naming its owner: the first eight bytes of SHA-256 over the
// public key, hex.
//
// The hint field exists so a holder with several keys knows which to try, and it travels in the clear. Putting
// anything identifying there — a customer name, a tenant id — would publish to everyone handling the file the
// one commercial fact sealing is meant to keep from them, which is a way to encrypt a licence and leak it
// anyway.
func RecipientKeyFingerprint(pub *ecdh.PublicKey) string {
	if pub == nil {
		return ""
	}
	sum := sha256.Sum256(pub.Bytes())
	return "k" + fmt.Sprintf("%x", sum[:8])
}

// ParseRecipientPrivateKeyPEM reads a holder's X25519 private key.
//
// This key protects confidentiality only. Losing it means somebody can read licences addressed to this holder;
// it does NOT let them mint one, because minting needs the vendor's signing key. That difference is why this one
// lives in a file and the vendor's lives in hardware.
func ParseRecipientPrivateKeyPEM(pemText string) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	ecdhKey, ok := key.(*ecdh.PrivateKey)
	if !ok || ecdhKey.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("licence recipient key must be X25519")
	}
	return ecdhKey, nil
}

// ParseRecipientPublicKeyPEM reads a holder's X25519 public key — what a vendor needs in order to seal to them.
func ParseRecipientPublicKeyPEM(pemText string) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := key.(*ecdh.PublicKey)
	if !ok || pub.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("licence recipient key must be X25519")
	}
	return pub, nil
}

// LooksSealed reports whether a file is a sealed licence rather than a bare signed envelope, so an import path
// can accept both. A deployment that has not yet been issued a recipient key still receives plain envelopes, and
// making the operator pick the right menu item would be a way to fail for no reason.
func LooksSealed(raw []byte) bool {
	var probe struct {
		Type       string `json:"type"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Type == sealedType || probe.Ciphertext != ""
}
