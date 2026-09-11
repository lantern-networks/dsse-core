package dlp

import (
	"bytes"
	"io"
	"mime"
	"sort"
	"strings"
)

// Finding is a NON-SECRET result: an identifier type and how many times it was found. The engine never
// includes the matched bytes, an offset, or any surrounding context — only type + count.
type Finding struct {
	Type  IdentifierType `json:"type"`
	Count int            `json:"count"`
}

const (
	// windowSize is the streaming carry-over/hold window. It must be ≥ the longest possible single match so a
	// boundary-straddling identifier is always fully present in the retained tail and never missed. All
	// anchors are bounded well under this (the longest, a JWT, is ~3 KB).
	windowSize = 4096
	// chunkSize is the streaming read granularity.
	chunkSize = 32 * 1024
)

// ShouldScan reports whether a body of the given Content-Type is worth scanning, and if not, a short reason
// for the dlp_scan_skipped audit. Only text-like types are scanned; binary/compressed content is skipped
// (the caller logs the reason). There is deliberately NO size ceiling — streaming inspects any size.
func ShouldScan(contentType string) (scan bool, reason string) {
	if contentType == "" {
		return true, ""
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	mt = strings.ToLower(mt)
	switch {
	// NOTE: multipart/* is deliberately NOT here — a multipart upload is routed to the buffered file path
	// (oss/fileextract), which parses the parts and extracts file contents; it is not raw-streamed as text.
	case strings.HasPrefix(mt, "text/"),
		mt == "application/json",
		strings.HasSuffix(mt, "+json"),
		mt == "application/x-www-form-urlencoded",
		mt == "application/xml",
		strings.HasSuffix(mt, "+xml"),
		mt == "application/csv",
		mt == "application/x-ndjson",
		mt == "application/graphql":
		return true, ""
	default:
		return false, "non_text_content_type"
	}
}

type match struct {
	typ        IdentifierType
	start, end int
}

// scan finds every identifier occurrence in data with its byte range. Numeric identifiers use a linear
// digit-run pass (fast); API keys use a prefix-gated regex. Matches are confirmed by a validator so false
// positives stay low.
func scan(data []byte) []match {
	var out []match
	scanDigitRuns(data, &out)
	scanSeparatedRuns(data, &out)
	if hasAPIKeyCandidate(data) {
		for _, loc := range apiKeyRE.FindAllIndex(data, -1) {
			out = append(out, match{APIKey, loc[0], loc[1]})
		}
	}
	// Email: gated on '@' so benign uploads never run the regex.
	if bytes.IndexByte(data, '@') >= 0 {
		for _, loc := range emailRE.FindAllIndex(data, -1) {
			out = append(out, match{Email, loc[0], loc[1]})
		}
	}
	// Japanese mobile phone: gated on the mobile-prefix literals.
	if hasCandidate(data, phoneJPLiterals) {
		for _, loc := range phoneJPRE.FindAllIndex(data, -1) {
			out = append(out, match{Phone, loc[0], loc[1]})
		}
	}
	return out
}

// Options carries the optional per-scan configuration shared by every detector: operator-defined custom
// classifiers (slice C), exact-data-match fingerprint datasets (slice E), and an allowlist of known-safe values
// to suppress (slice F). The zero value is "built-in identifiers, suppress nothing".
type Options struct {
	Classifiers  *ClassifierSet
	Fingerprints *FingerprintSet
	Allowlist    *Allowlist
}

// scanAll runs the built-in scan plus any operator-defined custom classifiers and EDM fingerprint datasets, then
// drops any match whose value is on the allowlist (known-safe). It is the single entry point every detector
// (Detect / Scanner / GuardReader) uses so custom identifiers, EDM, and allowlisting are honored uniformly on the
// buffered, streaming, and hold-before-release paths.
func scanAll(data []byte, opts Options) []match {
	out := scan(data)
	opts.Classifiers.scan(data, &out)
	opts.Fingerprints.scan(data, &out)
	if !opts.Allowlist.Empty() {
		kept := out[:0]
		for _, m := range out {
			if opts.Allowlist.Allowed(m.typ, data[m.start:m.end]) {
				continue // known-safe value (e.g. a test card) — suppress the finding
			}
			kept = append(kept, m)
		}
		out = kept
	}
	return out
}

// hasAPIKeyCandidate reports whether data contains any API-key prefix literal (fast memchr-based gate).
func hasAPIKeyCandidate(data []byte) bool { return hasCandidate(data, apiKeyLiterals) }

// hasCandidate reports whether data contains any of the given literal prefixes (fast memchr-based gate) — the
// cheap pre-check that keeps an expensive regex off the critical path for bodies that can't match.
func hasCandidate(data []byte, literals [][]byte) bool {
	for _, lit := range literals {
		if bytes.Contains(data, lit) {
			return true
		}
	}
	return false
}

// scanDigitRuns finds each maximal run of ASCII digits that is delimited by non-word boundaries (matching
// \b\d{n}\b) and, by length, validates it as a My Number (12, mod-11), Corporate Number (13, mod-9), and/or
// credit card (13–19, Luhn). One linear pass; no regex.
func scanDigitRuns(data []byte, out *[]match) {
	n := len(data)
	for i := 0; i < n; {
		if data[i] < '0' || data[i] > '9' {
			i++
			continue
		}
		j := i
		for j < n && data[j] >= '0' && data[j] <= '9' {
			j++
		}
		// Word-boundary check: the run must not be adjacent to a letter/underscore (a digit run inside an
		// alphanumeric token is not a delimited identifier).
		leftOK := i == 0 || !isWordByte(data[i-1])
		rightOK := j == n || !isWordByte(data[j])
		if leftOK && rightOK {
			run := data[i:j]
			switch length := j - i; {
			case length == 12:
				if validMyNumber(run) {
					*out = append(*out, match{MyNumber, i, j})
				}
			case length == 13:
				if validCorporateNumber(run) {
					*out = append(*out, match{CorporateNumber, i, j})
				}
				if luhnValid(run) {
					*out = append(*out, match{CreditCard, i, j})
				}
			case length >= 14 && length <= 19:
				if luhnValid(run) {
					*out = append(*out, match{CreditCard, i, j})
				}
			}
		}
		i = j
	}
}

// scanSeparatedRuns detects numeric identifiers written in the usual human grouping — digit groups joined by a
// single space or hyphen (e.g. "4111 1111 1111 1111", "1234 5678 9018", "9-2345-6789-0123"). scanDigitRuns only
// matches CONTIGUOUS runs, so a grouped identifier (a card in 4-digit groups, a My Number as 4-4-4, a Corporate
// Number as 1-4-4-4) slips through — yet grouped is how these are almost always pasted into an AI prompt, a form,
// or a document. The collected digits are classified by length with the SAME validators as scanDigitRuns: 12 →
// My Number (mod-11), 13 → Corporate Number (mod-9) and/or credit card (Luhn), 14–19 → credit card (Luhn). A
// token qualifies only when it is word-boundary delimited and contains at least one separator (a contiguous run
// is already handled by scanDigitRuns). One extra linear pass; the collected digits are bounded (≤19) so it stays
// cheap.
func scanSeparatedRuns(data []byte, out *[]match) {
	n := len(data)
	var digits [20]byte // scratch, bounded by the 19-digit cap
	for i := 0; i < n; {
		if data[i] < '0' || data[i] > '9' || (i > 0 && isWordByte(data[i-1])) {
			i++
			continue
		}
		// Parse a run of digit-groups separated by SINGLE space/hyphen (never a trailing/double separator).
		j := i
		ndig := 0
		seps := 0
		overflow := false
		for j < n {
			c := data[j]
			if c >= '0' && c <= '9' {
				if ndig >= len(digits) {
					overflow = true
					break
				}
				digits[ndig] = c
				ndig++
				j++
				continue
			}
			// A single separator is only consumed when the NEXT byte is a digit (so we never eat a trailing sep).
			if (c == ' ' || c == '-') && j+1 < n && data[j+1] >= '0' && data[j+1] <= '9' {
				seps++
				j++
				continue
			}
			break
		}
		// Only grouped tokens (≥1 separator, no overflow, right word-boundary) reach classification; contiguous
		// runs are scanDigitRuns' job. Dispatch by digit count exactly as the contiguous pass does so a grouped
		// identifier is classified identically to its unseparated form (13 digits can be both Corporate + card).
		if !overflow && seps >= 1 && (j == n || !isWordByte(data[j])) {
			run := digits[:ndig]
			switch {
			case ndig == 12:
				if validMyNumber(run) {
					*out = append(*out, match{MyNumber, i, j})
				}
			case ndig == 13:
				if validCorporateNumber(run) {
					*out = append(*out, match{CorporateNumber, i, j})
				}
				if luhnValid(run) {
					*out = append(*out, match{CreditCard, i, j})
				}
			case ndig >= 14 && ndig <= 19:
				if luhnValid(run) {
					*out = append(*out, match{CreditCard, i, j})
				}
			}
		}
		if j > i {
			i = j
		} else {
			i++
		}
	}
}

// findings converts a per-type count map into a stable, sorted slice.
func findings(counts map[IdentifierType]int) []Finding {
	if len(counts) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(counts))
	for t, c := range counts {
		out = append(out, Finding{Type: t, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// Detect scans a fully-buffered body and returns non-secret findings (built-in identifiers only). It honors the
// Content-Type gate. Use it when the whole body is already in memory; use DetectStream for arbitrary-size
// streaming bodies, or DetectWith to include operator-defined custom classifiers.
func Detect(data []byte, contentType string) []Finding { return DetectWith(data, contentType, nil) }

// DetectWith is Detect plus the given operator-defined custom classifiers (nil set = built-ins only).
func DetectWith(data []byte, contentType string, set *ClassifierSet) []Finding {
	return DetectWithOptions(data, contentType, Options{Classifiers: set})
}

// DetectWithOptions is Detect plus custom classifiers and/or an allowlist (Options).
func DetectWithOptions(data []byte, contentType string, opts Options) []Finding {
	if ok, _ := ShouldScan(contentType); !ok {
		return nil
	}
	counts := map[IdentifierType]int{}
	for _, m := range scanAll(data, opts) {
		counts[m.typ]++
	}
	return findings(counts)
}

// Scanner is a streaming, Writer-driven detector for a single body. Feed it bytes with Write (e.g. via
// io.TeeReader so it observes an upload without altering it), then call Findings once at the end. It keeps a
// windowSize-byte carry-over tail so an identifier straddling a Write boundary is never missed and never
// double-counted: a match is counted once, when it lies entirely before the retained tail (its bytes are then
// dropped), and the residual tail is counted by Findings. Memory is constant regardless of body size. Not
// safe for concurrent use.
type Scanner struct {
	counts map[IdentifierType]int
	buf    []byte
	done   bool
	opts   Options
}

// NewScanner returns a ready streaming Scanner (built-in identifiers only).
func NewScanner() *Scanner { return NewScannerWithOptions(Options{}) }

// NewScannerWith returns a streaming Scanner that also detects the given operator-defined custom classifiers.
func NewScannerWith(set *ClassifierSet) *Scanner {
	return NewScannerWithOptions(Options{Classifiers: set})
}

// NewScannerWithOptions returns a streaming Scanner honoring custom classifiers and/or an allowlist.
func NewScannerWithOptions(opts Options) *Scanner {
	return &Scanner{counts: map[IdentifierType]int{}, buf: make([]byte, 0, chunkSize+windowSize), opts: opts}
}

// windowCommit returns how far buf may be safely released/dropped in a streaming scan. The base boundary is
// windowSize bytes behind the end (so no future read can extend a match into the released prefix), lowered so
// it never cuts a currently-detected match that straddles it (which would drop part of the match and miss it
// after compaction). final=true releases everything (EOF). Matches ending at or before the returned dropTo
// are entirely within the released prefix and can be committed exactly once.
func windowCommit(buf []byte, matches []match, final bool) int {
	if final {
		return len(buf)
	}
	dropTo := len(buf) - windowSize
	if dropTo <= 0 {
		return 0
	}
	for changed := true; changed; {
		changed = false
		for _, m := range matches {
			if m.start < dropTo && m.end > dropTo {
				dropTo = m.start
				changed = true
			}
		}
	}
	if dropTo < 0 {
		return 0
	}
	return dropTo
}

// Write feeds bytes to the scanner. It never errors and always consumes all of p, so it is safe as an
// io.TeeReader sink on the critical forwarding path (it must not stall or fail the upload).
func (s *Scanner) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	matches := scanAll(s.buf, s.opts)
	dropTo := windowCommit(s.buf, matches, false)
	if dropTo > 0 {
		for _, m := range matches {
			if m.end <= dropTo {
				s.counts[m.typ]++
			}
		}
		// Drop the committed prefix; retain the remainder (>= the last windowSize bytes) so a match straddling
		// the boundary is preserved intact for the next Write.
		s.buf = append(s.buf[:0], s.buf[dropTo:]...)
	}
	return len(p), nil
}

// Findings finalizes the scan (counting the residual tail) and returns non-secret findings. Idempotent: the
// residual is counted only once even if called multiple times.
func (s *Scanner) Findings() []Finding {
	if !s.done {
		for _, m := range scanAll(s.buf, s.opts) {
			s.counts[m.typ]++
		}
		s.done = true
	}
	return findings(s.counts)
}

// DetectStream scans a body of any size at constant memory and returns non-secret findings. The caller is
// responsible for the Content-Type gate (ShouldScan) and for logging dlp_scan_skipped when it returns false;
// DetectStream itself scans whatever bytes it is given.
func DetectStream(r io.Reader) ([]Finding, error) { return DetectStreamWithOptions(r, Options{}) }

// DetectStreamWith is DetectStream plus the given operator-defined custom classifiers (nil set = built-ins only).
func DetectStreamWith(r io.Reader, set *ClassifierSet) ([]Finding, error) {
	return DetectStreamWithOptions(r, Options{Classifiers: set})
}

// DetectStreamWithOptions is DetectStream honoring custom classifiers and/or an allowlist (Options).
func DetectStreamWithOptions(r io.Reader, opts Options) ([]Finding, error) {
	s := NewScannerWithOptions(opts)
	if _, err := io.Copy(s, r); err != nil {
		return s.Findings(), err
	}
	return s.Findings(), nil
}
