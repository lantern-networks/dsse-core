package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Allowlist suppresses findings for operator-declared KNOWN-SAFE values — a test card (4111 1111 1111 1111), a
// sample My Number used in docs, a specific benign email — the #1 source of DLP false positives. It is the
// false-positive-tuning primitive (slice F) and the hashing core a future EDM/exact-data-match (slice E) reuses.
//
// NON-SECRET discipline: the raw safe value is accepted only in transit (the admin enters it once) and NEVER
// stored — the Allowlist holds only salted SHA-256 hashes. A value is normalized before hashing so a card matches
// whether written grouped or contiguous, and an email regardless of case.
type Allowlist struct {
	salt   string
	hashes map[string]bool
}

// NewAllowlist builds an allowlist from raw known-safe values (transit only) under the given salt. The values are
// normalized + hashed immediately; the raw slice is not retained.
func NewAllowlist(salt string, values []string) *Allowlist {
	a := &Allowlist{salt: salt, hashes: map[string]bool{}}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		// Store under BOTH a type-agnostic normalization and the digits-only form, so a pasted "4111 1111 1111
		// 1111" allowlists the card whether the finding carries it grouped or contiguous.
		a.hashes[a.hash(normalizeAllowValue("", v))] = true
		if d := digitsOnly(v); d != "" && d != v {
			a.hashes[a.hash(d)] = true
		}
	}
	return a
}

// Empty reports whether the allowlist suppresses nothing.
func (a *Allowlist) Empty() bool { return a == nil || len(a.hashes) == 0 }

// Allowed reports whether a matched value (raw bytes, normalized per identifier type) is on the allowlist and its
// finding should be suppressed. The bytes are hashed here and discarded — never stored or returned.
func (a *Allowlist) Allowed(typ IdentifierType, raw []byte) bool {
	if a.Empty() {
		return false
	}
	return a.hashes[a.hash(normalizeAllowValue(typ, string(raw)))]
}

func (a *Allowlist) hash(normalized string) string {
	sum := sha256.Sum256([]byte(a.salt + "\x00" + normalized))
	return hex.EncodeToString(sum[:])
}

// normalizeAllowValue canonicalizes a value so equivalent renderings hash alike: numeric identifiers to digits
// only (grouping/separators dropped), email lowercased, everything else trimmed.
func normalizeAllowValue(typ IdentifierType, v string) string {
	v = strings.TrimSpace(v)
	switch typ {
	case MyNumber, CorporateNumber, CreditCard, Phone:
		// Phone joins the digits-only branch (review #19): a phone finding carries its separators
		// ("090-1234-5678"), so keeping them here meant the hash never matched the operator's allowlist
		// entry and a separated phone could NEVER be allowlisted. Digits-only canonicalizes both sides.
		return digitsOnly(v)
	case Email:
		return strings.ToLower(v)
	case "":
		// Unknown type (allowlist ingestion): if it is all-ish digits, prefer the digits-only form so a pasted
		// card/number matches the numeric finding path; otherwise lowercase (covers emails).
		if d := digitsOnly(v); d != "" && len(d) >= len(v)-len(v)/3 {
			return d
		}
		return strings.ToLower(v)
	default:
		return v
	}
}

// digitsOnly returns just the ASCII digits of s.
func digitsOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
