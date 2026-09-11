package dlp

import (
	"io"
	"strings"
	"testing"
)

// findingCount returns the count for a type, or 0.
func findingCount(fs []Finding, t IdentifierType) int {
	for _, f := range fs {
		if f.Type == t {
			return f.Count
		}
	}
	return 0
}

func TestDetectPositives(t *testing.T) {
	cases := []struct {
		name string
		body string
		typ  IdentifierType
	}{
		{"my_number", `{"my_number":"123456789018"}`, MyNumber},
		{"corporate_number", `法人番号 9234567890123 です`, CorporateNumber},
		{"credit_card", `card=4111111111111111`, CreditCard},
		{"aws_key", `AKIA=AKIAIOSFODNN7EXAMPLE`, APIKey},
		{"github_token", `token ghp_0123456789abcdefghijklmnopqrstuvwxyz done`, APIKey},
		// Real Slack tokens are xoxb-/xoxp-/… — this vector guards the gate literal ("xox"), which once
		// read "xox-" and silently bypassed the entire Slack credential class.
		{"slack_token", `slack: xoxb-0123456789-abcDEFghiJKLmno`, APIKey},
		{"jwt", `auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`, APIKey},
		{"pem", `-----BEGIN RSA PRIVATE KEY-----`, APIKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect([]byte(c.body), "text/plain")
			if findingCount(got, c.typ) < 1 {
				t.Errorf("Detect(%q) missing %s; got %+v", c.body, c.typ, got)
			}
		})
	}
}

func TestDetectEmailPhonePositives(t *testing.T) {
	cases := []struct {
		name string
		body string
		typ  IdentifierType
	}{
		{"email", `contact: alice.smith+dev@example.co.jp for access`, Email},
		{"email_json", `{"user":"bob@corp.example.com"}`, Email},
		{"phone_hyphen", `緊急連絡先 090-1234-5678`, Phone},
		{"phone_bare", `tel 08012345678 まで`, Phone},
		{"phone_space", `携帯 070 1234 5678`, Phone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect([]byte(c.body), "text/plain")
			if findingCount(got, c.typ) < 1 {
				t.Errorf("Detect(%q) missing %s; got %+v", c.body, c.typ, got)
			}
		})
	}
}

func TestDetectEmailPhoneFalsePositives(t *testing.T) {
	// None of these should produce an email/phone finding: no dotted-TLD email, and numbers that merely CONTAIN
	// a mobile prefix but are not phone-shaped (the cheap gate may run the regex, but precision comes from it).
	bodies := []string{
		"reach me @ the office",     // '@' but not an address
		"a@b no tld",                // no dotted TLD
		"invoice total 1090500 yen", // contains "090" but not 0X0+4+4
		"code 0901234 partial",      // 090 + only 4 digits, not 4+4
		"ref 08000 short",           // 080 + too short
	}
	for _, b := range bodies {
		got := Detect([]byte(b), "text/plain")
		if findingCount(got, Email) != 0 || findingCount(got, Phone) != 0 {
			t.Errorf("Detect(%q) = %+v, want no email/phone", b, got)
		}
	}
}

func TestDetectFalsePositives(t *testing.T) {
	bodies := []string{
		"hello world, order 42 shipped to dock 7",
		`{"my_number":"123456789012"}`,  // invalid My Number check digit
		"corp 1234567890123 invalid",    // invalid corporate check digit
		"card 4111111111111112 invalid", // invalid Luhn
		"just a very long word aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, b := range bodies {
		if got := Detect([]byte(b), "text/plain"); len(got) != 0 {
			t.Errorf("Detect(%q) = %+v, want no findings", b, got)
		}
	}
}

func TestDetectCounts(t *testing.T) {
	body := `a 123456789018 b 123456789018 c 4111111111111111`
	got := Detect([]byte(body), "application/json")
	if n := findingCount(got, MyNumber); n != 2 {
		t.Errorf("my_number count = %d, want 2", n)
	}
	if n := findingCount(got, CreditCard); n != 1 {
		t.Errorf("credit_card count = %d, want 1", n)
	}
}

func TestShouldScan(t *testing.T) {
	scan := []string{"", "text/plain", "text/html; charset=utf-8", "application/json",
		"application/vnd.api+json", "application/x-www-form-urlencoded"}
	for _, ct := range scan {
		if ok, _ := ShouldScan(ct); !ok {
			t.Errorf("ShouldScan(%q) = false, want true", ct)
		}
	}
	skip := []string{"image/png", "application/octet-stream", "application/zip", "video/mp4", "application/gzip"}
	for _, ct := range skip {
		if ok, reason := ShouldScan(ct); ok {
			t.Errorf("ShouldScan(%q) = true, want false", ct)
		} else if reason == "" {
			t.Errorf("ShouldScan(%q) skipped without a reason", ct)
		}
	}
}

func TestDetectContentTypeGate(t *testing.T) {
	body := []byte(`{"my_number":"123456789018"}`)
	if got := Detect(body, "image/png"); len(got) != 0 {
		t.Errorf("Detect on image/png = %+v, want skipped (nil)", got)
	}
}

// sliceReader returns its chunks one Read at a time, so tests can control exactly where reads split.
type sliceReader struct {
	chunks [][]byte
	i      int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.i >= len(s.chunks) {
		return 0, io.EOF
	}
	n := copy(p, s.chunks[s.i])
	s.i++
	return n, nil
}

func TestDetectStreamBoundaryStraddle(t *testing.T) {
	// The My Number "123456789018" is split across the chunk boundary ("12345" | "6789018"), and there is
	// >windowSize of padding before it so the streaming commit/drop path runs mid-stream. A credit card sits
	// near the end (found at EOF). Neither must be missed nor double-counted.
	chunkA := strings.Repeat("x", 5000) + " 12345"
	chunkB := "6789018 " + strings.Repeat("y", 5000) + " 4111111111111111 end"
	r := &sliceReader{chunks: [][]byte{[]byte(chunkA), []byte(chunkB)}}
	got, err := DetectStream(r)
	if err != nil {
		t.Fatalf("DetectStream error: %v", err)
	}
	if n := findingCount(got, MyNumber); n != 1 {
		t.Errorf("my_number count = %d, want 1 (boundary-straddling, no double count); got %+v", n, got)
	}
	if n := findingCount(got, CreditCard); n != 1 {
		t.Errorf("credit_card count = %d, want 1; got %+v", n, got)
	}
}

// Regression for windowCommit: a valid identifier that straddles the drop boundary (len-windowSize) must not
// be cut by compaction. The My Number is placed to span offset windowSize+k's drop point in a single Write.
func TestScannerBoundaryStraddleNotCut(t *testing.T) {
	const k = 100
	myNum := "123456789018"
	// Lay out: k-6 pad | My Number (12) | pad, total = windowSize + k, so dropTo starts at k and the My
	// Number (start k-6, end k+6) straddles it. Pad with spaces (non-word) so the digit run is delimited.
	body := strings.Repeat(" ", k-6) + myNum + strings.Repeat(" ", windowSize+k-(k-6)-len(myNum))
	s := NewScanner()
	if _, err := s.Write([]byte(body)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if n := findingCount(s.Findings(), MyNumber); n != 1 {
		t.Errorf("straddling My Number count = %d, want 1 (must not be cut at the drop boundary)", n)
	}
}

func TestDetectStreamMatchesBuffered(t *testing.T) {
	// Streaming over many small reads must agree with the buffered Detect.
	body := strings.Repeat("pad ", 3000) + " 123456789018 mid 4111111111111111 " + strings.Repeat("z", 6000)
	want := Detect([]byte(body), "text/plain")

	chunks := [][]byte{}
	for i := 0; i < len(body); i += 512 {
		end := i + 512
		if end > len(body) {
			end = len(body)
		}
		chunks = append(chunks, []byte(body[i:end]))
	}
	got, err := DetectStream(&sliceReader{chunks: chunks})
	if err != nil {
		t.Fatalf("DetectStream error: %v", err)
	}
	if findingCount(got, MyNumber) != findingCount(want, MyNumber) ||
		findingCount(got, CreditCard) != findingCount(want, CreditCard) {
		t.Errorf("stream %+v != buffered %+v", got, want)
	}
}
