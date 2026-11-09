package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// The enrolment record names the token's issuer by the label recorded at issuance (2026-11-06: the approval
// screen showed only "adm_7f15…").
func TestTheEnrolmentRecordNamesTheIssuerByTheirLabel(t *testing.T) {
	for _, c := range []struct{ id, label, want string }{
		{"adm_7f15", "admin@example.test", "admin@example.test (adm_7f15)"},
		{"adm_7f15", "", "adm_7f15"},
		{"adm_7f15", "adm_7f15", "adm_7f15"},
	} {
		if got := enrolmentIssuerText(enrolltoken.Token{IssuedBy: c.id, IssuedByLabel: c.label}); got != c.want {
			t.Errorf("issuer %q/%q reads %q, want %q", c.id, c.label, got, c.want)
		}
	}
}
