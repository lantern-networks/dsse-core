package dlp

import (
	"strings"
	"testing"
)

func TestAllowlistSuppressesKnownSafe(t *testing.T) {
	// The Visa test card + a sample My Number are known-safe; real values still fire.
	allow := NewAllowlist("tenant-salt", []string{"4111 1111 1111 1111", "123456789018"})
	opts := Options{Allowlist: allow}

	// A body with ONLY the allowlisted test card + sample my_number → nothing fires.
	body := "test data card 4111-1111-1111-1111 and my number 123456789018 here"
	if got := DetectWithOptions([]byte(body), "text/plain", opts); len(got) != 0 {
		t.Fatalf("allowlisted-only body still produced findings: %v", got)
	}
	// Without the allowlist, the same body fires (proves it WOULD have without suppression).
	if got := Detect([]byte(body), "text/plain"); len(got) == 0 {
		t.Fatalf("control: expected findings without the allowlist")
	}

	// A DIFFERENT (real) card is NOT suppressed.
	real := "charge 4242 4242 4242 4242 now" // Luhn-valid, not allowlisted
	found := false
	for _, f := range DetectWithOptions([]byte(real), "text/plain", opts) {
		if f.Type == CreditCard {
			found = true
		}
	}
	if !found {
		t.Fatalf("a non-allowlisted card must still fire")
	}
}

func TestAllowlistNormalizationGroupingAndCase(t *testing.T) {
	// Allowlisting the grouped form suppresses the contiguous form and vice-versa (digits-only normalization).
	allow := NewAllowlist("s", []string{"4111111111111111"})
	if got := DetectWithOptions([]byte("card 4111 1111 1111 1111 x"), "text/plain", Options{Allowlist: allow}); len(got) != 0 {
		t.Errorf("grouped card should be suppressed by a contiguous allowlist entry: %v", got)
	}
	// Email case-insensitive.
	allowEmail := NewAllowlist("s", []string{"Tanaka@Acme.co.jp"})
	if got := DetectWithOptions([]byte("mail tanaka@acme.co.jp end"), "text/plain", Options{Allowlist: allowEmail}); len(got) != 0 {
		t.Errorf("email allowlist should be case-insensitive: %v", got)
	}
	// Review #19: a phone finding carries its separators, so a separated phone must be allowlistable. Before
	// the fix normalizeAllowValue kept the separators and the hash never matched — a separated phone could
	// never be suppressed. Allowlisting the contiguous form must suppress the separated finding and vice-versa.
	allowPhone := NewAllowlist("s", []string{"09012345678"})
	if got := DetectWithOptions([]byte("call 090-1234-5678 now"), "text/plain", Options{Allowlist: allowPhone}); len(got) != 0 {
		t.Errorf("separated phone should be suppressed by a contiguous allowlist entry: %v", got)
	}
	allowPhoneSep := NewAllowlist("s", []string{"090-1234-5678"})
	if got := DetectWithOptions([]byte("call 09012345678 now"), "text/plain", Options{Allowlist: allowPhoneSep}); len(got) != 0 {
		t.Errorf("contiguous phone should be suppressed by a separated allowlist entry: %v", got)
	}
}

func TestAllowlistEmpty(t *testing.T) {
	if !NewAllowlist("s", nil).Empty() {
		t.Error("nil values → Empty()")
	}
	if !(*Allowlist)(nil).Empty() {
		t.Error("nil allowlist → Empty()")
	}
	if NewAllowlist("s", []string{"x"}).Empty() {
		t.Error("non-empty allowlist reported Empty()")
	}
}

// The allowlist also stops a known-safe value from tripping a block (GuardReader).
func TestAllowlistGuardDoesNotBlock(t *testing.T) {
	allow := NewAllowlist("s", []string{"123456789018"}) // sample my_number
	body := "prefix my number 123456789018 suffix"
	g := NewGuardReaderWithOptions(strings.NewReader(body), map[IdentifierType]int{MyNumber: 1}, Options{Allowlist: allow})
	buf := make([]byte, 4096)
	for {
		_, err := g.Read(buf)
		if err != nil {
			break
		}
	}
	if g.Tripped() {
		t.Fatal("an allowlisted sample value must not trip a block")
	}
}
