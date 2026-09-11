package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Exact-Data-Match (EDM, slice E). An operator fingerprints a SENSITIVE dataset — a column of customer record
// ids, employee numbers, account keys — and the scan raises a finding (under the dataset's own identifier name)
// whenever one of those exact values appears in egress. It reuses the allowlist's salted-hash primitive but
// INCLUDES (detects) instead of suppressing, and — unlike the allowlist or a keyword classifier — it stores ONLY
// salted hashes: the dataset is never kept in the clear, so the fingerprint is safe to persist on the edge and an
// operator cannot recover the source data from the config.
//
// Scope (MVP): SINGLE-TOKEN values (ids, account numbers, emails — no internal spaces), matched exactly after a
// light normalization (lowercase, drop '-'/'_'). Multi-token / proximity / cell-based matching is the follow-on.

const (
	// edmMinTokenLen ignores trivial short tokens so a large body does not fingerprint every 1–3 char word.
	edmMinTokenLen = 5
	// edmMaxTokenLen bounds a token so a pathological run is not hashed whole.
	edmMaxTokenLen = 128
)

// Fingerprint is one operator dataset's exact-match set: salted hashes of its values, emitting the dataset's
// identifier name on a match. The zero value / nil is an empty set.
type Fingerprint struct {
	name   IdentifierType
	salt   string
	hashes map[string]bool
}

// NewFingerprint fingerprints raw dataset values (transit only) under name+salt. The values are normalized +
// hashed immediately and NOT retained (only the hashes are).
func NewFingerprint(name, salt string, values []string) *Fingerprint {
	f := &Fingerprint{name: IdentifierType(name), salt: salt, hashes: map[string]bool{}}
	for _, v := range values {
		if n := edmNormalize(v); len(n) >= edmMinTokenLen {
			f.hashes[f.hash(n)] = true
		}
	}
	return f
}

// NewFingerprintFromHashes rehydrates a fingerprint from already-computed salted hashes (durable storage) — the
// salt must match the one the hashes were computed with so scan-time token hashing lines up.
func NewFingerprintFromHashes(name, salt string, hashes []string) *Fingerprint {
	f := &Fingerprint{name: IdentifierType(name), salt: salt, hashes: make(map[string]bool, len(hashes))}
	for _, h := range hashes {
		if h = strings.TrimSpace(h); h != "" {
			f.hashes[h] = true
		}
	}
	return f
}

// Name returns the identifier the fingerprint emits.
func (f *Fingerprint) Name() string { return string(f.name) }

// Count returns how many distinct values are fingerprinted.
func (f *Fingerprint) Count() int {
	if f == nil {
		return 0
	}
	return len(f.hashes)
}

// Empty reports whether the fingerprint matches nothing.
func (f *Fingerprint) Empty() bool { return f == nil || len(f.hashes) == 0 }

// Hashes returns the salted hashes (sorted) for durable, non-secret storage.
func (f *Fingerprint) Hashes() []string {
	if f == nil {
		return nil
	}
	out := make([]string, 0, len(f.hashes))
	for h := range f.hashes {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (f *Fingerprint) hash(normalized string) string {
	sum := sha256.Sum256([]byte(f.salt + "\x00" + string(f.name) + "\x00" + normalized))
	return hex.EncodeToString(sum[:])
}

// FingerprintSet is a tenant's collection of named EDM datasets, scanned together.
type FingerprintSet struct {
	fps []*Fingerprint
}

// NewFingerprintSet builds a set from compiled fingerprints (nil/empty entries dropped).
func NewFingerprintSet(fps []*Fingerprint) *FingerprintSet {
	set := &FingerprintSet{}
	for _, f := range fps {
		if !f.Empty() {
			set.fps = append(set.fps, f)
		}
	}
	return set
}

// Empty reports whether the set detects nothing.
func (s *FingerprintSet) Empty() bool { return s == nil || len(s.fps) == 0 }

// Names returns the dataset identifier names in the set (sorted).
func (s *FingerprintSet) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.fps))
	for _, f := range s.fps {
		out = append(out, string(f.name))
	}
	sort.Strings(out)
	return out
}

// Subset returns a new set containing only the datasets whose name is in names — so a rule's scan runs only the
// EDM datasets that rule selected (policy-scoped detection). nil/empty names → empty set.
func (s *FingerprintSet) Subset(names []string) *FingerprintSet {
	if s == nil || len(names) == 0 {
		return &FingerprintSet{}
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := &FingerprintSet{}
	for _, f := range s.fps {
		if want[string(f.name)] {
			out.fps = append(out.fps, f)
		}
	}
	return out
}

// scan tokenizes data and, for each candidate token that hashes to a fingerprint, appends a match under that
// dataset's identifier name. One linear tokenize pass; each token is hashed once per dataset.
func (s *FingerprintSet) scan(data []byte, out *[]match) {
	if s.Empty() {
		return
	}
	n := len(data)
	for i := 0; i < n; {
		if !edmTokenByte(data[i]) {
			i++
			continue
		}
		j := i
		for j < n && edmTokenByte(data[j]) {
			j++
		}
		if tokLen := j - i; tokLen >= edmMinTokenLen && tokLen <= edmMaxTokenLen {
			norm := edmNormalize(string(data[i:j]))
			if len(norm) >= edmMinTokenLen {
				for _, f := range s.fps {
					if f.hashes[f.hash(norm)] {
						*out = append(*out, match{f.name, i, j})
					}
				}
			}
		}
		i = j
	}
}

// edmTokenByte reports whether b can be part of an EDM token (id/account/email-like: alphanumerics + a few
// intra-token punctuation bytes). Spaces are NOT token bytes — MVP matches single tokens.
func edmTokenByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		b == '-' || b == '_' || b == '.' || b == '@' || b == '+'
}

// edmNormalize canonicalizes a value/token for matching: lowercase and drop '-' and '_' (so "EMP-004217" and
// "emp004217" match). '.'/'@'/'+' are kept (email-significant).
func edmNormalize(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' || c == '_' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}
