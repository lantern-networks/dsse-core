package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ AN ORGANIZATION'S ID MUST NOT BE ITS NAME (decided 2026-08-21, after the oracle was measured on the
// lab). The id becomes the name that organization's agents send, and the transport port confirms or denies
// that name to anyone who asks by SNI — with no credential at all. A derived id turns a dictionary of company
// names into the customer list of a multi-tenant deployment.
func TestAnOrganizationIDCannotBeGuessedFromItsName(t *testing.T) {
	seen := map[string]bool{}
	shape := regexp.MustCompile(`^tenant_[a-z2-7]{26}$`)
	for i := 0; i < 500; i++ {
		id, err := newOrganizationID()
		if err != nil {
			t.Fatalf("minting an organization id failed: %v", err)
		}
		if !shape.MatchString(id) {
			t.Fatalf("id %q is not the issued shape — every gate, probe and log query in this tree matches on "+
				"the tenant_ prefix, so the shape is part of the contract", id)
		}
		if seen[id] {
			t.Fatalf("two organizations were issued the same id (%q) in %d draws", id, i+1)
		}
		seen[id] = true
	}

	// ★ AND THE NAME MUST NOT LEAK THROUGH THE TRANSPORT NAME EITHER. A minted id protects nothing if the
	// name the agents send is still typed in by hand, because the oracle reads the NAME.
	got := organizationTransportServerName("tenant_u4j7ggffm5ki7xrhfgectfg6ya", "dsse.invalid")
	if got != "u4j7ggffm5ki7xrhfgectfg6ya.dsse.invalid" {
		t.Fatalf("transport name = %q, want it derived from the id", got)
	}
	if organizationTransportServerName("", "dsse.invalid") != "" ||
		organizationTransportServerName("tenant_x", "") != "" {
		t.Fatal("a half-known name must be empty rather than a fragment: a certificate carrying a partial " +
			"name is one no device can verify")
	}
}

// ★ AND NOTHING MAY GO BACK TO DERIVING ONE FROM THE DISPLAY NAME. The Console filled the field in for the
// person creating an organization, which is the friendliest possible way to produce a guessable id.
func TestNoScreenDerivesAnOrganizationIDFromItsDisplayName(t *testing.T) {
	body, err := os.ReadFile("../../console/organizationwizard.js")
	if err != nil {
		t.Skipf("console not present: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "slugToTenantId") {
		t.Fatal("the wizard derives an organization id from its display name again. The id is issued by " +
			"POST /admin/tenants; the form asks for the display name and reads tenant_id out of the answer.")
	}
	// The creation call specifically. Passing the ISSUED id around afterwards is how every later step names
	// the new organization, and is exactly right — what must not happen is naming one on the way in.
	if create := strings.Index(text, `apiFetch("POST", "/admin/tenants"`); create >= 0 {
		body := text[create:]
		if end := strings.Index(body, "});"); end > 0 {
			body = body[:end]
		}
		if strings.Contains(body, "tenant_id") {
			t.Fatalf("the wizard names an id when creating an organization. Creation refuses a caller-supplied "+
				"id — see organization_id_is_not_a_name.go — so this would create nothing and say so in a "+
				"toast. Body was:\n%s", body)
		}
	} else {
		t.Fatal("the wizard no longer creates organizations through POST /admin/tenants — this check is " +
			"guarding a call that is gone")
	}
	// The positive control: it must still READ the issued id, or every step after creation acts in the
	// operator's own organization instead of the new one.
	if !strings.Contains(text, "created.body && created.body.tenant_id") {
		t.Fatal("the wizard no longer reads the issued id out of the creation answer, so the steps after it " +
			"name no organization")
	}
}
