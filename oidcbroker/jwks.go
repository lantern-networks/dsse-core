package oidcbroker

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
)

// JWK is a JSON Web Key (RSA only, the OIDC default for ID tokens).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"` // base64url big-endian modulus
	E   string `json:"e"` // base64url big-endian exponent
}

// JWKS is a JSON Web Key Set (the IdP's jwks_uri document).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKS parses a jwks_uri document. The integration layer fetches it; parsing/validation is here so the
// security core stays unit-testable.
func ParseJWKS(data []byte) (JWKS, error) {
	var set JWKS
	if err := json.Unmarshal(data, &set); err != nil {
		return JWKS{}, fmt.Errorf("parse jwks: %w", err)
	}
	return set, nil
}

// keyByKID returns the RSA public key whose kid matches. When kid is empty and the set has exactly one RSA
// key, that key is used (some IdPs omit kid).
func (s JWKS) keyByKID(kid string) (*rsa.PublicKey, error) {
	var only *JWK
	count := 0
	for i := range s.Keys {
		k := &s.Keys[i]
		if k.Kty != "RSA" {
			continue
		}
		count++
		only = k
		if kid != "" && k.Kid == kid {
			return k.rsaPublicKey()
		}
	}
	if kid == "" && count == 1 {
		return only.rsaPublicKey()
	}
	return nil, fmt.Errorf("no RSA jwk matches kid %q", kid)
}

func (k *JWK) rsaPublicKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("jwk kty %q is not RSA", k.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("jwk n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jwk e: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, fmt.Errorf("jwk has empty modulus/exponent")
	}
	// Exponent: big-endian, left-pad to 8 bytes for uint64. A JWKS is network-fed, so an exponent LONGER
	// than 8 bytes must be rejected, not panicked on: `copy(padded[8-len(eBytes):], ...)` with len > 8 makes
	// a NEGATIVE slice index, a slice-bounds panic that crashes the process on a hostile/corrupt key
	// (review #23). A real RSA public exponent is tiny (65537 = 3 bytes); anything past 8 bytes is invalid.
	if len(eBytes) > 8 {
		return nil, fmt.Errorf("jwk exponent is too large (%d bytes)", len(eBytes))
	}
	padded := make([]byte, 8)
	copy(padded[8-len(eBytes):], eBytes)
	e := binary.BigEndian.Uint64(padded)
	if e == 0 {
		return nil, fmt.Errorf("jwk exponent is zero")
	}
	// E must fit in a positive int on this platform (rsa.PublicKey.E is int). No legitimate exponent
	// approaches this, but a crafted 8-byte value could overflow int to a negative — reject it.
	if e > math.MaxInt32 {
		return nil, fmt.Errorf("jwk exponent is out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}
