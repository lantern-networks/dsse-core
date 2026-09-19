package dlp

import (
	"strings"
	"testing"
)

func TestFingerprintExactMatch(t *testing.T) {
	// Fingerprint a sensitive dataset of customer record ids under the identifier name "customer_record".
	fp := NewFingerprint("customer_record", "salt", []string{"CUST-100482", "ACME-7741-XZ", "kojima.h@acme.co.jp"})
	set := NewFingerprintSet([]*Fingerprint{fp})
	opts := Options{Fingerprints: set}

	cases := []struct {
		body string
		want int // customer_record count
	}{
		{"record for CUST-100482 attached", 1},
		{"lowercase cust-100482 also matches (normalized)", 1}, // case + separator normalization
		{"id ACME7741XZ without dashes", 1},                    // separators dropped in normalization
		{"contact kojima.h@acme.co.jp please", 1},
		{"CUST-100482 and ACME-7741-XZ both", 2},
		{"unrelated CUST-999999 not in the set", 0},
		{"benign text with no ids", 0},
	}
	for _, tc := range cases {
		got := 0
		for _, f := range DetectWithOptions([]byte(tc.body), "text/plain", opts) {
			if f.Type == "customer_record" {
				got = f.Count
			}
		}
		if got != tc.want {
			t.Errorf("Detect(%q) customer_record = %d, want %d (all: %v)", tc.body, got, tc.want, DetectWithOptions([]byte(tc.body), "text/plain", opts))
		}
	}
}

func TestFingerprintStoresHashesOnly(t *testing.T) {
	fp := NewFingerprint("secret_ds", "salt", []string{"TOPSECRETVALUE123"})
	// The serialized representation contains hashes rather than raw values.
	for _, h := range fp.Hashes() {
		if h == "TOPSECRETVALUE123" || len(h) != 64 {
			t.Fatalf("fingerprint leaked a raw value or wrong hash length: %q", h)
		}
	}
	if fp.Count() != 1 {
		t.Fatalf("count = %d, want 1", fp.Count())
	}
	// Rehydrate from hashes only (durable path) and confirm it still detects.
	fp2 := NewFingerprintFromHashes("secret_ds", "salt", fp.Hashes())
	set := NewFingerprintSet([]*Fingerprint{fp2})
	got := 0
	for _, f := range DetectWithOptions([]byte("leak TOPSECRETVALUE123 here"), "text/plain", Options{Fingerprints: set}) {
		if f.Type == "secret_ds" {
			got = f.Count
		}
	}
	if got != 1 {
		t.Fatalf("rehydrated-from-hashes fingerprint did not detect: %d", got)
	}
}

func TestFingerprintShortValuesIgnored(t *testing.T) {
	// Values below the min token length are not fingerprinted (avoids matching trivial tokens everywhere).
	fp := NewFingerprint("ds", "salt", []string{"AB", "1234"})
	if !fp.Empty() {
		t.Fatalf("short values should not be fingerprinted; count=%d", fp.Count())
	}
}

func TestFingerprintMultipleDatasets(t *testing.T) {
	a := NewFingerprint("employees", "salt", []string{"EMP-556677"})
	b := NewFingerprint("projects", "salt", []string{"PRJ-FALCON-9"})
	set := NewFingerprintSet([]*Fingerprint{a, b})
	if names := set.Names(); len(names) != 2 || names[0] != "employees" || names[1] != "projects" {
		t.Fatalf("names = %v, want [employees projects]", set.Names())
	}
	body := "EMP-556677 on PRJ-FALCON-9"
	types := map[IdentifierType]int{}
	for _, f := range DetectWithOptions([]byte(body), "text/plain", Options{Fingerprints: set}) {
		types[f.Type] = f.Count
	}
	if types["employees"] != 1 || types["projects"] != 1 {
		t.Fatalf("both datasets should fire: %v", types)
	}
}

// EDM matches also participate in block enforcement via the GuardReader.
func TestFingerprintGuardBlocks(t *testing.T) {
	fp := NewFingerprint("customer_record", "salt", []string{"CUST-100482"})
	set := NewFingerprintSet([]*Fingerprint{fp})
	body := "prefix record CUST-100482 suffix"
	g := NewGuardReaderWithOptions(strings.NewReader(body), map[IdentifierType]int{"customer_record": 1}, Options{Fingerprints: set})
	buf := make([]byte, 4096)
	blocked := false
	for {
		_, err := g.Read(buf)
		if err == ErrBlocked {
			blocked = true
			break
		}
		if err != nil {
			break
		}
	}
	if !blocked {
		t.Fatal("an EDM fingerprint match must be able to trip a block")
	}
}

func TestFingerprintSetSubset(t *testing.T) {
	a := NewFingerprint("employees", "s", []string{"EMP-556677"})
	b := NewFingerprint("projects", "s", []string{"PRJ-FALCON-9"})
	set := NewFingerprintSet([]*Fingerprint{a, b})
	sub := set.Subset([]string{"employees"})
	if names := sub.Names(); len(names) != 1 || names[0] != "employees" {
		t.Fatalf("Subset names = %v, want [employees]", sub.Names())
	}
	// projects must not fire through the subset.
	body := "EMP-556677 and PRJ-FALCON-9"
	types := map[IdentifierType]int{}
	for _, f := range DetectWithOptions([]byte(body), "text/plain", Options{Fingerprints: sub}) {
		types[f.Type] = f.Count
	}
	if types["employees"] != 1 || types["projects"] != 0 {
		t.Fatalf("subset should detect only employees: %v", types)
	}
	if !set.Subset(nil).Empty() {
		t.Fatal("Subset(nil) must be empty")
	}
}

func TestFingerprintInputValidationMatchesScannerTokens(t *testing.T) {
	for _, value := range []string{"CUST-100482", " cust100482 ", "user+tag@example.invalid", strings.Repeat("Z", 128)} {
		if err := ValidateFingerprintValues([]string{value}); err != nil {
			t.Fatal(err)
		}
		fp := NewFingerprint("record_id", "salt", []string{value})
		found := false
		for _, f := range DetectWithOptions([]byte(value), "text/plain", Options{Fingerprints: NewFingerprintSet([]*Fingerprint{fp})}) {
			if f.Type == "record_id" && f.Count == 1 {
				found = true
			}
		}
		if !found {
			t.Fatal("accepted value cannot be scanned")
		}
	}
	for _, value := range []string{"private two words", "private/slash", strings.Repeat("Z", 129), "private\tvalue", "café-value"} {
		err := ValidateFingerprintValues([]string{"CUST-100482", value})
		if err == nil || strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "value 2") {
			t.Fatalf("invalid input leaked or accepted: %v", err)
		}
	}
	if err := ValidateFingerprintValues([]string{"AB", "12-34"}); err != nil {
		t.Fatal("legacy short-value ignore changed")
	}
}
