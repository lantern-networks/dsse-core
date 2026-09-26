package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

// Allowlist suppresses findings for operator-declared KNOWN-SAFE values — a test card (4111 1111 1111 1111), a
// sample My Number used in docs, a specific benign email — the #1 source of DLP false positives. It is the
// false-positive-tuning primitive (slice F) and the hashing core a future EDM/exact-data-match (slice E) reuses.
//
// This compiled scanner holds only salted SHA-256 hashes. The administration store
// and configuration bundle retain authored known-safe values for management.
// Numeric grouping and email case normalize; other values match exactly.
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
		// Keep literal, email and numeric matches separate. An identifier that
		// contains digits must not authorize an unrelated card or phone number.
		a.hashes[a.hash("literal\x00"+v)] = true
		a.hashes[a.hash("email\x00"+strings.ToLower(v))] = true
		if d, ok := formattedNumericAllowValue(v); ok {
			a.hashes[a.hash("numeric\x00"+d)] = true
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
	value := strings.TrimSpace(string(raw))
	switch typ {
	case MyNumber, CorporateNumber, CreditCard, Phone:
		digits, ok := formattedNumericAllowValue(value)
		return ok && a.hashes[a.hash("numeric\x00"+digits)]
	case Email:
		return a.hashes[a.hash("email\x00"+strings.ToLower(value))]
	default:
		return a.hashes[a.hash("literal\x00"+value)]
	}
}

func (a *Allowlist) hash(normalized string) string {
	sum := sha256.Sum256([]byte(a.salt + "\x00" + normalized))
	return hex.EncodeToString(sum[:])
}

// formattedNumericAllowValue accepts digits with conventional numeric grouping,
// never arbitrary text containing digits. Other values use exact literal matching.
func formattedNumericAllowValue(value string) (string, bool) {
	var digits strings.Builder
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case unicode.IsSpace(r) || r == '-' || r == '(' || r == ')' || r == '.':
		default:
			return "", false
		}
	}
	return digits.String(), digits.Len() > 0
}
