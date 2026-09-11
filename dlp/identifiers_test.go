package dlp

import "testing"

// All vectors below are SYNTHETIC values with valid check digits that correspond to no real person or
// entity — the package must never carry real PII (OSS/no-real-data rule).

func TestValidMyNumber(t *testing.T) {
	valid := []string{"123456789018"} // synthetic, mod-11 check digit = 8
	for _, s := range valid {
		if !validMyNumber([]byte(s)) {
			t.Errorf("validMyNumber(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"123456789012",  // wrong check digit (should be 8)
		"12345678901",   // 11 digits
		"1234567890180", // 13 digits
		"12345678901a",  // non-digit
	}
	for _, s := range invalid {
		if validMyNumber([]byte(s)) {
			t.Errorf("validMyNumber(%q) = true, want false", s)
		}
	}
}

func TestValidCorporateNumber(t *testing.T) {
	if !validCorporateNumber([]byte("9234567890123")) { // synthetic, mod-9 leading check digit = 9
		t.Error("validCorporateNumber(9234567890123) = false, want true")
	}
	invalid := []string{
		"1234567890123",  // wrong leading check digit (should be 9)
		"234567890123",   // 12 digits
		"92345678901234", // 14 digits
	}
	for _, s := range invalid {
		if validCorporateNumber([]byte(s)) {
			t.Errorf("validCorporateNumber(%q) = true, want false", s)
		}
	}
}

func TestLuhn(t *testing.T) {
	if !luhnValid([]byte("4111111111111111")) { // standard Visa test PAN
		t.Error("luhnValid(4111111111111111) = false, want true")
	}
	if luhnValid([]byte("4111111111111112")) {
		t.Error("luhnValid(4111111111111112) = true, want false")
	}
}
