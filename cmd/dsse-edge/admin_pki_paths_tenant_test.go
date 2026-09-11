package main

import (
	"os"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// ★★★ ANOTHER CUSTOMER'S CERTIFICATE WAS SHOWN AS THIS CUSTOMER'S OWN INTERCEPTION PATH (2026-08-18, read
// through the admin API as Acme's own administrator, a credential with no cross-tenant rights).
//
//	{"id":"interception","from":"endpoints","to":"node",
//	 "server_cert_subject":"CN=Northwind Traders Interception Root 2028,O=Northwind Traders"}
//
// Two things at once. It names a different customer of the same provider on this customer's screen — a
// membership disclosure, and in an MSSP deployment those two may be competitors. And it is false: Acme has no
// interception authority, so its traffic is refused rather than signed by anybody's root.
//
// The filter that exists to prevent this decided ownership by looking for the substring "tenant_" inside the
// certificate's SUBJECT. "CN=Northwind Traders Interception Root 2028,O=Northwind Traders" contains no such
// substring, so it was not foreign and passed straight through. The same lesson the device-trust CAs taught
// two days earlier: ask the registry, not the certificate's name.
//
// It was latent until per-tenant interception roots started appearing in the inventory earlier the same day —
// before that there was one node-wide root and picking "the first" happened to be right. A fix that made the
// inventory honest made this endpoint wrong, which is the ordinary shape of a defect surfacing.
func TestAPathDoesNotShowOneTenantAnothersCertificate(t *testing.T) {
	inv := []pkiCertificateItem{
		{ID: "interception_root:aaaa", Role: "interception_root", TenantID: "tenant_northwind",
			Subject: "CN=Northwind Traders Interception Root 2028,O=Northwind Traders"},
		{ID: "interception_root:bbbb", Role: "interception_root", TenantID: "tenant_acme",
			Subject: "CN=Acme Interception Root,O=Acme Corp"},
	}
	// The report is built once for the deployment and picks the first item for the role.
	paths := []pkiPath{{
		ID: "interception", From: "endpoints", To: "node",
		ServerCertID: "interception_root:aaaa", ServerCertSubject: inv[0].Subject, ServerCertTenantID: "tenant_northwind",
	}}

	acme := pkiPathsForTenant(paths, "tenant_acme", inv)
	if len(acme) != 1 {
		t.Fatalf("the path itself was dropped: %+v", acme)
	}
	if strings.Contains(acme[0].ServerCertSubject, "Northwind") {
		t.Fatalf("Acme is shown %q as the certificate on its own interception path", acme[0].ServerCertSubject)
	}
	// ★ AND IT IS REPLACED, NOT MERELY BLANKED. Acme has a root of its own here; telling it that its
	// interception path has no certificate would be true of the blanking and false of the deployment.
	if acme[0].ServerCertID != "interception_root:bbbb" {
		t.Fatalf("Acme was not given its own root on its own path: %+v", acme[0])
	}

	// The owner still sees theirs.
	nw := pkiPathsForTenant(paths, "tenant_northwind", inv)
	if !strings.Contains(nw[0].ServerCertSubject, "Northwind") {
		t.Fatalf("Northwind lost its own certificate from its own path: %+v", nw[0])
	}

	// ★ THE CONTROL: a tenant with no root of its own gets the reference blanked and NOT substituted with
	// somebody else's. Without this, "replace with the caller's own" could degrade into "replace with the
	// first one found", which is the bug wearing a different hat.
	none := pkiPathsForTenant(paths, "tenant_probe", inv)
	if none[0].ServerCertSubject != "" || none[0].ServerCertID != "" {
		t.Fatalf("a tenant with no interception root was handed %+v", none[0])
	}

	// ★★ AND MATERIAL THIS NODE CANNOT PLACE IS NOT NAMED TO A CUSTOMER (2026-08-19, replacing the check that
	// this was caught by READING the tenant id out of the subject).
	//
	// The old rule scanned "CN=X Device Issuing CA (tenant_northwind)" for the text "tenant_" and blanked it
	// for Acme. That worked here and was wrong twice over: a subject is typed by whoever minted the
	// certificate, so it is an attribution anyone can claim, and on the reference lab it placed an
	// organization's own device CA in an organization that no longer exists. Attribution comes from the
	// signature now.
	//
	// What replaces it is the fail-closed half: on a deployment that attributes CAs per organization, a named
	// reference this node cannot place is not shown to a customer — "not established" is not "everybody's".
	named := []pkiPath{{ID: "device_transport", ClientAuthVerifiedBy: "CN=X Device Issuing CA (tenant_northwind)"}}
	if got := pkiPathsForTenant(named, "tenant_acme", inv); got[0].ClientAuthVerifiedBy != "" {
		t.Fatalf("Acme was shown a certificate this node cannot attribute: %q", got[0].ClientAuthVerifiedBy)
	}
	// ★ THE CONTROL, and it is the reason this is conditioned on the deployment rather than applied always: a
	// single-organization deployment attributes nothing, and there the node's device CA genuinely IS that
	// customer's to see. Blanking it everywhere would answer "what verifies my devices" with silence on every
	// single-tenant deployment there is.
	if got := pkiPathsForTenant(named, "tenant_acme", nil); got[0].ClientAuthVerifiedBy == "" {
		t.Fatalf("a deployment that attributes nothing withheld its only device CA from its only customer")
	}
}

// ★★ AND THE PROSE BESIDE THE SCOPED LISTS WAS NOT SCOPED (2026-08-18). The per-tenant root and issuer lists
// on /admin/interception-roots were scoped a month ago, because a root list is a membership list. The sentence
// next to them says `"tenant_reference_lab" keeps the node-wide intermediate its devices already trust` and
// went to every customer unchanged. The scoping reached the structured fields and stopped at the paragraph.
func TestTheSigningScopeNoteDoesNotNameAnotherTenantToACustomer(t *testing.T) {
	scope := edgeplane.InterceptionSigningScope{
		Configured: "shared", Effective: "per_tenant_offline_intermediate", PerTenantSigning: true,
		Note: `1 organization(s) sign under their own offline root; any other organization is REFUSED rather ` +
			`than signed under another's CA; "tenant_reference_lab" keeps the node-wide intermediate its devices already trust`,
	}

	customer := interceptionScopeForCaller(scope, false)
	if strings.Contains(customer.Note, "tenant_reference_lab") {
		t.Fatalf("a customer is told which other tenant owns the node-wide intermediate: %q", customer.Note)
	}
	// The half that is about the deployment survives — a customer whose traffic is refused needs to know that
	// per-tenant signing is why.
	if !strings.Contains(customer.Note, "REFUSED") {
		t.Fatalf("the customer lost the reason its own traffic is refused: %q", customer.Note)
	}
	if !customer.PerTenantSigning || customer.Effective != scope.Effective {
		t.Fatalf("the structured answer changed shape for a customer: %+v", customer)
	}

	// ★ THE CONTROL: the operator keeps the whole note. They are who moves an organization off the shared
	// intermediate, and they cannot do it without knowing which one is on it.
	if got := interceptionScopeForCaller(scope, true); got.Note != scope.Note {
		t.Fatalf("the operator lost the name too: %q", got.Note)
	}
}

// ★★ AND THE ROUTE MUST ACTUALLY CALL IT (2026-08-18). The test above passed against a build where
// interceptionScopeForCaller existed and nothing invoked it: an edit script asserted after mutating and
// exited before writing, so the helper landed and its use did not. Go compiles an unused package-level
// function without complaint, the unit test exercised the helper directly, and the leak was still live on the
// running Edge — found only by asking the API again as a customer.
//
// This is the same trap the "self" path gate was written against a few hours earlier: verifying a helper is
// not verifying the behaviour. Reading the source is crude and it is the thing that would have caught it.
func TestTheInterceptionRootsRouteScopesItsScopeNote(t *testing.T) {
	raw, err := os.ReadFile("admin_interception_pki_routes.go")
	if err != nil {
		t.Fatalf("read the routes: %v", err)
	}
	src := string(raw)
	if !strings.Contains(src, `"signing_scope": interceptionScopeForCaller(`) {
		t.Fatal("GET /admin/interception-roots emits signing_scope without passing it through " +
			"interceptionScopeForCaller — the note names the tenant that owns the node-wide intermediate, to " +
			"every customer that asks")
	}
	// The control: the raw accessor must not ALSO be serialised straight into the response somewhere else,
	// which would make the line above true and the leak live.
	if strings.Contains(src, `"signing_scope": config.NetworkExtensionLabTLS.InterceptionRootScope()`) {
		t.Fatal("an unscoped signing_scope is still emitted somewhere on this surface")
	}
}
