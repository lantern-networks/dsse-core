// Package dlp is a pure, data-free content-inspection engine for minimal data-loss prevention. It detects a
// small, high-precision set of identifiers (Japanese My Number / Corporate Number, credit-card numbers, and
// common API keys/secrets) in decrypted egress bodies and reports only NON-SECRET findings: the identifier
// type and a count. It never returns, stores, or logs the raw matched value.
//
// The engine is anchor-based (a format match, then a validator: My Number mod-11, Corporate Number mod-9,
// credit-card Luhn, API-key prefix) so false positives stay low, and it is streaming (DetectStream, see
// detect.go) so a body of any size is inspectable at constant memory. It has no I/O and no real PII — every
// test vector is a synthetic, checksum-valid value that corresponds to no real person or entity — so it lives
// in the OSS-core (dsse-core) tree alongside oss/knownbypass. See docs/dlp_minimal_design.md.
package dlp

import "regexp"

// IdentifierType is the non-secret classification of a finding. It is the ONLY identifying information the
// engine emits about a match — never the matched bytes.
type IdentifierType string

const (
	// MyNumber is a Japanese individual number (個人番号): 12 digits with a mod-11 check digit.
	MyNumber IdentifierType = "my_number"
	// CorporateNumber is a Japanese corporate number (法人番号): 13 digits with a mod-9 check digit.
	CorporateNumber IdentifierType = "corporate_number"
	// CreditCard is a 13–19 digit payment card number that passes the Luhn check.
	CreditCard IdentifierType = "credit_card"
	// APIKey is a credential/secret matched by a known high-precision prefix or structure (AWS/GitHub/Google/
	// Slack/Stripe/Anthropic/OpenAI keys, PEM private-key headers, JWTs).
	APIKey IdentifierType = "api_key"
	// Email is an email address (PII). Gated on '@' so benign uploads pay nothing.
	Email IdentifierType = "email"
	// Phone is a Japanese mobile phone number (070/080/090, bare or hyphen/space-separated). Sovereign PII, gated
	// on the mobile prefix literals so the precise regex runs only when one is present.
	Phone IdentifierType = "phone"
)

// Numeric identifiers (My Number / Corporate Number / credit card) are detected by a hand-rolled linear
// digit-run scan (see scanDigitRuns in detect.go), not regex — RE2 is ~2 orders of magnitude slower here and
// this path runs on every scannable upload. API keys keep a regex, but it is gated behind a cheap literal
// prefix pre-check so the expensive alternation only runs when a credential prefix is actually present.
// apiKeyLiterals are the distinctive literal prefixes of every API-key shape. They gate the expensive
// apiKeyRE with bytes.Contains (SIMD/memchr-fast, ~orders faster than RE2): only when a body actually
// contains a credential prefix does the precise regex run. Benign uploads never pay for apiKeyRE.
var apiKeyLiterals = [][]byte{
	[]byte("AKIA"), []byte("AIza"),
	[]byte("ghp_"), []byte("gho_"), []byte("ghu_"), []byte("ghs_"), []byte("ghr_"),
	// "xox" (not "xox-"): real Slack tokens are xoxb-/xoxp-/xoxa-/xoxs-…, so a "xox-" literal never fires
	// and the whole Slack class would silently bypass the gate — the regex below requires xox[baprs]-.
	[]byte("xox"), []byte("sk_live_"), []byte("sk-ant-"), []byte("eyJ"), []byte("-----BEGIN "),
}

var (
	// apiKeyRE is an alternation of high-precision credential shapes. Every branch is length-bounded so a
	// single match can never exceed the streaming carry-over window (see windowSize in detect.go).
	apiKeyRE = regexp.MustCompile(
		`AKIA[0-9A-Z]{16}` + // AWS access key id
			`|gh[pousr]_[0-9A-Za-z]{36,251}` + // GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_)
			`|AIza[0-9A-Za-z_\-]{35}` + // Google API key
			`|xox[baprs]-[0-9A-Za-z\-]{10,240}` + // Slack tokens
			`|sk_live_[0-9A-Za-z]{16,240}` + // Stripe live secret key
			`|sk-ant-[0-9A-Za-z_\-]{16,240}` + // Anthropic key
			`|-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----` + // PEM private-key header
			`|eyJ[0-9A-Za-z_\-]{10,1000}\.eyJ[0-9A-Za-z_\-]{10,1000}\.[0-9A-Za-z_\-]{10,1000}`) // JWT

	// emailRE matches an email address. Gated behind a cheap '@' pre-check (hasEmailCandidate). The TLD is 2–24
	// letters so random "a@b" noise (no dotted TLD) does not match. Bounded well under windowSize.
	emailRE = regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}\.)+[A-Za-z]{2,24}`)

	// phoneJPRE matches a Japanese mobile number: 070/080/090 then 4+4 digits, optionally hyphen/space separated
	// (090-1234-5678, 09012345678, 090 1234 5678). Gated behind the mobile-prefix literals so the regex runs only
	// when a prefix is present; the distinctive 0[789]0 prefix + fixed 4+4 shape keeps precision high.
	phoneJPRE = regexp.MustCompile(`0[789]0[-\s]?[0-9]{4}[-\s]?[0-9]{4}`)
)

// phoneJPLiterals cheaply gate phoneJPRE: unless the body contains a Japanese mobile prefix, the regex never runs.
var phoneJPLiterals = [][]byte{[]byte("070"), []byte("080"), []byte("090")}

// KnownIdentifier reports whether t is an identifier type the engine supports (used to validate policy input).
func KnownIdentifier(t IdentifierType) bool {
	switch t {
	case MyNumber, CorporateNumber, CreditCard, APIKey, Email, Phone:
		return true
	default:
		return false
	}
}

// isWordByte reports whether b is a word character ([0-9A-Za-z_]), matching RE2's \b semantics used to keep
// numeric identifiers delimited (a digit run adjacent to a letter/underscore is NOT a boundary and is
// ignored, exactly as \b\d{n}\b would).
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}

// validMyNumber reports whether b (exactly 12 ASCII digits) is a valid Japanese individual number. The 12th
// digit is a check digit over the first 11: with P_n the n-th digit from the least-significant of those 11,
// Q_n = n+1 for 1..6 and n-5 for 7..11, r = (Σ P_n·Q_n) mod 11, and the check digit is 0 when r ≤ 1 else 11-r.
func validMyNumber(b []byte) bool {
	if len(b) != 12 {
		return false
	}
	sum := 0
	for i := 0; i < 11; i++ {
		p := int(b[10-i] - '0')
		n := i + 1
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	r := sum % 11
	check := 0
	if r > 1 {
		check = 11 - r
	}
	return check == int(b[11]-'0')
}

// validCorporateNumber reports whether b (exactly 13 ASCII digits) is a valid Japanese corporate number. The
// leading digit is a check digit over the trailing 12: with P_n the n-th digit from the least-significant of
// those 12 and Q_n = 1 (n odd) / 2 (n even), the check digit is 9 - ((Σ P_n·Q_n) mod 9).
func validCorporateNumber(b []byte) bool {
	if len(b) != 13 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		p := int(b[12-i] - '0')
		n := i + 1
		q := 1
		if n%2 == 0 {
			q = 2
		}
		sum += p * q
	}
	check := 9 - (sum % 9)
	return check == int(b[0]-'0')
}

// luhnValid reports whether b (ASCII digits) passes the Luhn checksum.
func luhnValid(b []byte) bool {
	sum := 0
	alt := false
	for i := len(b) - 1; i >= 0; i-- {
		d := int(b[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
