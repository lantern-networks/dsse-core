package dlp

import (
	"strings"
	"testing"
)

func TestAllowlistLiteralCannotAuthorizeEmbeddedDigits(t *testing.T) {
	value := "ORDER-4111111111111111"
	allow := NewAllowlist("s", []string{value})
	if !allow.Allowed(IdentifierType("order_id"), []byte(value)) {
		t.Error("explicit literal value is not allowlisted")
	}
	for _, f := range DetectWithOptions([]byte("card 4111 1111 1111 1111"), "text/plain", Options{Allowlist: allow}) {
		if f.Type == CreditCard {
			return
		}
	}
	t.Fatal("allowlisting an alphanumeric value suppressed an unrelated numeric match")
}
func TestAllowlistCustomAndEDMKeepExactValues(t *testing.T) {
	classifiers, errs := NewClassifierSet([]ClassifierSpec{{Name: "project_code", Kind: ClassifierKeyword, Keywords: []string{"BLUEFIN", "bluefin", "REDCEDAR"}}})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	fps := NewFingerprintSet([]*Fingerprint{NewFingerprint("customer_record", "fp", []string{"CUST-100482", "CUST-900001"})})
	opts := Options{Classifiers: classifiers, Fingerprints: fps, Allowlist: NewAllowlist("s", []string{"BLUEFIN", "CUST-100482"})}
	for _, body := range []string{"BLUEFIN", "CUST-100482"} {
		if got := DetectWithOptions([]byte(body), "text/plain", opts); len(got) != 0 {
			t.Fatalf("explicit value not suppressed: %v", got)
		}
	}
	for _, body := range []string{"bluefin", "REDCEDAR", "cust-100482", "CUST-900001"} {
		if got := DetectWithOptions([]byte(body), "text/plain", opts); len(got) == 0 {
			t.Fatal("an unlisted literal value was suppressed")
		}
	}
	streamed, err := DetectStreamWithOptions(strings.NewReader("BLUEFIN REDCEDAR CUST-100482 CUST-900001"), opts)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[IdentifierType]int{}
	for _, f := range streamed {
		counts[f.Type] = f.Count
	}
	if counts["project_code"] != 1 || counts["customer_record"] != 1 {
		t.Fatalf("stream controls: %v", counts)
	}
}
func TestAllowlistOnlyFoldsEmailAndNumericGrouping(t *testing.T) {
	allow := NewAllowlist("s", []string{"KEY-AbCdEF123456", "Person@Example.invalid", "090 1234 5678"})
	if !allow.Allowed(IdentifierType("api_key"), []byte("KEY-AbCdEF123456")) || allow.Allowed(IdentifierType("api_key"), []byte("KEY-abcdef123456")) {
		t.Fatal("case-sensitive secret exception broadened")
	}
	if !allow.Allowed(Email, []byte("person@example.invalid")) || !allow.Allowed(Phone, []byte("090-1234-5678")) {
		t.Fatal("supported canonical form lost")
	}
	if allow.Allowed(Phone, []byte("0123456")) {
		t.Fatal("embedded digits from literal became numeric exception")
	}
}
