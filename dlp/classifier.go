package dlp

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Operator-defined custom classifiers (slice C). An operator can teach the engine tenant-specific identifiers —
// an employee-ID format, an internal project codename list, a contract-number shape — without a code change.
// Two kinds:
//
//   - regex:   an RE2 pattern (Go's regexp IS RE2 — linear time, no catastrophic backtracking, no backreferences).
//   - keyword: a literal dictionary; a match is a case-sensitive substring occurrence of any entry.
//
// Everything stays NON-SECRET: a custom classifier emits only its name + a count, exactly like a built-in — never
// the matched bytes. The hot path is protected by hard caps (count/length) and a cheap literal gate so benign
// uploads never pay for a classifier that cannot match. See docs/dlp_vision_and_roadmap.md slice C.

// ClassifierKind is how a custom classifier matches.
type ClassifierKind string

const (
	// ClassifierRegex matches an RE2 pattern.
	ClassifierRegex ClassifierKind = "regex"
	// ClassifierKeyword matches any literal in a dictionary (case-sensitive substring).
	ClassifierKeyword ClassifierKind = "keyword"
)

// Caps that keep operator input off the critical path and bounded. A custom match longer than the streaming
// carry-over window could be missed at a chunk boundary, so match length is bounded well under windowSize.
const (
	// MaxClassifiers is the per-tenant ceiling on custom classifiers.
	MaxClassifiers = 64
	// MaxPatternLen bounds a custom regex source (defense against pathological input; RE2 is linear regardless).
	MaxPatternLen = 512
	// MaxKeywords bounds a keyword dictionary's entry count.
	MaxKeywords = 256
	// MaxKeywordLen bounds a single keyword's length.
	MaxKeywordLen = 128
	// maxCustomMatchLen drops any custom match longer than this so a match can never straddle the streaming
	// window undetected (it is well under windowSize).
	maxCustomMatchLen = 512
	// minGateLiteral is the shortest literal prefix worth gating on (a 1-byte gate barely filters anything).
	minGateLiteral = 2
)

// nameRE constrains a custom classifier's emitted identifier name: lowercase snake, 2–40 chars. It shares the
// IdentifierType space with the built-ins but must not collide with a reserved one.
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,39}$`)

// reservedNames are the built-in identifier types a custom classifier may not shadow.
var reservedNames = map[string]bool{
	string(MyNumber): true, string(CorporateNumber): true, string(CreditCard): true,
	string(APIKey): true, string(Email): true, string(Phone): true,
}

// ValidIdentifierName reports whether name is a legal operator-defined identifier (for a custom classifier or an
// EDM dataset): lowercase snake_case, 2–40 chars, and not a reserved built-in.
func ValidIdentifierName(name string) bool {
	name = strings.TrimSpace(name)
	return nameRE.MatchString(name) && !reservedNames[name]
}

// ClassifierSpec is the operator-authored, JSON-serializable definition of a custom classifier. It is the shape
// stored durably and exchanged over the admin API. It carries no compiled state.
type ClassifierSpec struct {
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	Kind            ClassifierKind `json:"kind"`
	Pattern         string         `json:"pattern,omitempty"`          // regex only
	Keywords        []string       `json:"keywords,omitempty"`         // keyword only
	CaseInsensitive bool           `json:"case_insensitive,omitempty"` // regex only (adds (?i))
}

// compiledClassifier is the runtime form: the emitted type, a matcher, and a cheap literal gate.
type compiledClassifier struct {
	typ  IdentifierType
	kind ClassifierKind
	re   *regexp.Regexp // regex kind
	lits [][]byte       // keyword kind: the dictionary; regex kind: an optional single gate literal
}

// gate reports whether data could contain a match (cheap memchr pre-check). A regex with a literal prefix gates
// on it; a regex without one (lits empty) always runs. A keyword classifier gates on its dictionary.
func (c compiledClassifier) gate(data []byte) bool {
	if len(c.lits) == 0 {
		return true
	}
	return hasCandidate(data, c.lits)
}

// ClassifierSet is a compiled, immutable set of custom classifiers ready to scan with. The zero value / nil is a
// valid empty set (built-ins only).
type ClassifierSet struct {
	classifiers []compiledClassifier
}

// Empty reports whether the set contributes no custom classifiers.
func (s *ClassifierSet) Empty() bool { return s == nil || len(s.classifiers) == 0 }

// CompileClassifier validates + compiles one spec. It rejects a reserved/malformed name, an over-cap or
// un-compilable regex, a regex that matches the empty string (would match everywhere), and an empty/over-cap
// keyword dictionary. The returned compiledClassifier derives a literal gate automatically (regex: LiteralPrefix;
// keyword: the dictionary) so a benign body never pays for it.
func CompileClassifier(spec ClassifierSpec) (compiledClassifier, error) {
	name := strings.TrimSpace(spec.Name)
	if !nameRE.MatchString(name) {
		return compiledClassifier{}, fmt.Errorf("dlp: classifier name %q must be lowercase snake_case, 2–40 chars", spec.Name)
	}
	if reservedNames[name] {
		return compiledClassifier{}, fmt.Errorf("dlp: classifier name %q is a reserved built-in identifier", name)
	}
	switch spec.Kind {
	case ClassifierRegex:
		pat := spec.Pattern
		if strings.TrimSpace(pat) == "" {
			return compiledClassifier{}, fmt.Errorf("dlp: regex classifier %q has an empty pattern", name)
		}
		if len(pat) > MaxPatternLen {
			return compiledClassifier{}, fmt.Errorf("dlp: regex classifier %q pattern exceeds %d chars", name, MaxPatternLen)
		}
		if spec.CaseInsensitive {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat) // RE2: no backreferences, linear time
		if err != nil {
			return compiledClassifier{}, fmt.Errorf("dlp: regex classifier %q: %w", name, err)
		}
		if loc := re.FindStringIndex(""); loc != nil {
			return compiledClassifier{}, fmt.Errorf("dlp: regex classifier %q matches the empty string (too broad)", name)
		}
		c := compiledClassifier{typ: IdentifierType(name), kind: ClassifierRegex, re: re}
		if prefix, _ := re.LiteralPrefix(); len(prefix) >= minGateLiteral {
			c.lits = [][]byte{[]byte(prefix)}
		}
		return c, nil
	case ClassifierKeyword:
		seen := map[string]bool{}
		lits := make([][]byte, 0, len(spec.Keywords))
		for _, kw := range spec.Keywords {
			kw = strings.TrimSpace(kw)
			if kw == "" || seen[kw] {
				continue
			}
			if len(kw) > MaxKeywordLen {
				return compiledClassifier{}, fmt.Errorf("dlp: keyword %q in classifier %q exceeds %d chars", kw, name, MaxKeywordLen)
			}
			seen[kw] = true
			lits = append(lits, []byte(kw))
			if len(lits) > MaxKeywords {
				return compiledClassifier{}, fmt.Errorf("dlp: keyword classifier %q exceeds %d entries", name, MaxKeywords)
			}
		}
		if len(lits) == 0 {
			return compiledClassifier{}, fmt.Errorf("dlp: keyword classifier %q has no non-empty keywords", name)
		}
		return compiledClassifier{typ: IdentifierType(name), kind: ClassifierKeyword, lits: lits}, nil
	default:
		return compiledClassifier{}, fmt.Errorf("dlp: classifier %q has unknown kind %q (want regex|keyword)", name, spec.Kind)
	}
}

// NewClassifierSet compiles a batch of specs into a scan-ready set, enforcing the per-tenant cap and rejecting
// duplicate names. Invalid specs are skipped and returned as errors (so one bad classifier never disables the
// rest); the set contains every spec that compiled. A nil/empty input yields an empty set.
func NewClassifierSet(specs []ClassifierSpec) (*ClassifierSet, []error) {
	set := &ClassifierSet{}
	var errs []error
	seen := map[string]bool{}
	for _, spec := range specs {
		if len(set.classifiers) >= MaxClassifiers {
			errs = append(errs, fmt.Errorf("dlp: classifier %q dropped — over the %d-classifier cap", spec.Name, MaxClassifiers))
			continue
		}
		c, err := CompileClassifier(spec)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[string(c.typ)] {
			errs = append(errs, fmt.Errorf("dlp: duplicate classifier name %q ignored", c.typ))
			continue
		}
		seen[string(c.typ)] = true
		set.classifiers = append(set.classifiers, c)
	}
	return set, errs
}

// Names returns the emitted identifier names in the set (sorted), for admin/validation use.
func (s *ClassifierSet) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.classifiers))
	for _, c := range s.classifiers {
		out = append(out, string(c.typ))
	}
	sort.Strings(out)
	return out
}

// Subset returns a new set containing only the classifiers whose name is in names — so a rule's scan runs only the
// detectors that rule selected (policy-scoped detection). nil/empty names → empty set.
func (s *ClassifierSet) Subset(names []string) *ClassifierSet {
	if s == nil || len(names) == 0 {
		return &ClassifierSet{}
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := &ClassifierSet{}
	for _, c := range s.classifiers {
		if want[string(c.typ)] {
			out.classifiers = append(out.classifiers, c)
		}
	}
	return out
}

// Has reports whether the set defines a classifier with the given name.
func (s *ClassifierSet) Has(name string) bool {
	if s == nil {
		return false
	}
	for _, c := range s.classifiers {
		if string(c.typ) == name {
			return true
		}
	}
	return false
}

// scan appends every custom-classifier match in data to out. Each classifier is gated by its cheap literal
// pre-check first, so a body that cannot match pays nothing beyond the memchr. Regex matches longer than
// maxCustomMatchLen are dropped (keeps them under the streaming window).
func (s *ClassifierSet) scan(data []byte, out *[]match) {
	if s == nil {
		return
	}
	for _, c := range s.classifiers {
		if !c.gate(data) {
			continue
		}
		switch c.kind {
		case ClassifierRegex:
			for _, loc := range c.re.FindAllIndex(data, -1) {
				if loc[1]-loc[0] > maxCustomMatchLen {
					continue
				}
				*out = append(*out, match{c.typ, loc[0], loc[1]})
			}
		case ClassifierKeyword:
			for _, kw := range c.lits {
				for idx := 0; ; {
					rel := bytes.Index(data[idx:], kw)
					if rel < 0 {
						break
					}
					start := idx + rel
					*out = append(*out, match{c.typ, start, start + len(kw)})
					idx = start + len(kw)
				}
			}
		}
	}
}
