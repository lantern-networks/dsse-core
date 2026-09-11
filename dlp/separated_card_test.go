package dlp

import "testing"

func TestSeparatedCreditCard(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int // expected credit_card count
	}{
		{"space grouped", "pay with 4111 1111 1111 1111 today", 1},
		{"hyphen grouped", "card 4111-1111-1111-1111 on file", 1},
		{"contiguous still works", "card 4111111111111111 ok", 1},
		{"amex 15 spaced", "amex 3782 822463 10005 here", 1}, // 3782822463 10005 -> 15 digits, Luhn valid
		{"in AI prompt json", `{"messages":[{"role":"user","content":"my card 4111 1111 1111 1111"}]}`, 1},
		{"jp phone not a card", "call 090-1234-5678 now", 0},       // 11 digits, not 13-19
		{"random spaced non-luhn", "ref 1234 5678 9012 3456 x", 0}, // 16 digits but not Luhn
		{"too many digits", "id 4111 1111 1111 1111 1111 end", 0},  // 20 digits -> not a card
		{"double separator breaks", "4111  1111 1111 1111", 0},     // double space is not a single-sep grouping
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := 0
			for _, f := range Detect([]byte(tc.body), "text/plain") {
				if f.Type == CreditCard {
					got = f.Count
				}
			}
			if got != tc.want {
				t.Errorf("Detect(%q) credit_card = %d, want %d (all: %v)", tc.body, got, tc.want, Detect([]byte(tc.body), "text/plain"))
			}
		})
	}
}

// A grouped My Number (12 digits, mod-11) or Corporate Number (13 digits, mod-9) written with human separators
// must be detected the same as its contiguous form — the separated scan dispatches by digit count just like the
// contiguous scan does. Values are SYNTHETIC with valid check digits (see identifiers_test.go).
func TestSeparatedMyNumberAndCorporate(t *testing.T) {
	cases := []struct {
		name string
		body string
		typ  IdentifierType
		want int
	}{
		{"my number space 4-4-4", "私の番号は 1234 5678 9018 です", MyNumber, 1}, // 123456789018 valid mod-11
		{"my number hyphen", "MyNumber: 1234-5678-9018 end", MyNumber, 1},
		{"invalid my number grouped", "num 1234 5678 9012 x", MyNumber, 0},            // check digit should be 8, not 2
		{"corporate 1-4-4-4 hyphen", "法人番号 9-2345-6789-0123 で登録", CorporateNumber, 1}, // 9234567890123 valid mod-9
		{"corporate space grouped", "corp 9234 5678 90123 ok", CorporateNumber, 1},
		{"invalid corporate grouped", "id 1234 5678 90123 x", CorporateNumber, 0}, // leading check should be 9, not 1
		{"jp phone stays clean", "call 090-1234-5678 now", MyNumber, 0},           // 11 digits: no identifier
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := 0
			for _, f := range Detect([]byte(tc.body), "text/plain") {
				if f.Type == tc.typ {
					got = f.Count
				}
			}
			if got != tc.want {
				t.Errorf("Detect(%q) %s = %d, want %d (all: %v)", tc.body, tc.typ, got, tc.want, Detect([]byte(tc.body), "text/plain"))
			}
		})
	}
}

// A grouped card must not be double-counted (the contiguous scan finds only 4-digit runs; the separated scan
// finds the whole once).
func TestSeparatedCardNoDoubleCount(t *testing.T) {
	got := 0
	for _, f := range Detect([]byte("4111 1111 1111 1111"), "text/plain") {
		if f.Type == CreditCard {
			got = f.Count
		}
	}
	if got != 1 {
		t.Fatalf("grouped card counted %d times, want exactly 1", got)
	}
}

// A grouped card straddling a streaming Write boundary is counted exactly once.
func TestSeparatedCardStreamingBoundary(t *testing.T) {
	full := "prefixdata " + "4111 1111 1111 1111" + " suffix"
	sc := NewScanner()
	// Split in the middle of the card.
	mid := len("prefixdata 4111 1111 ")
	sc.Write([]byte(full[:mid]))
	sc.Write([]byte(full[mid:]))
	got := 0
	for _, f := range sc.Findings() {
		if f.Type == CreditCard {
			got = f.Count
		}
	}
	if got != 1 {
		t.Fatalf("straddling grouped card counted %d, want 1", got)
	}
}
