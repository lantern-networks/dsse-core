package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// ★★ A TENANT FIELD THAT IS STORED AND NEVER READ (2026-08-19, swept the whole model).
//
// data_residency is accepted on the tenant record, normalised on write, persisted in its own Postgres column
// and reported in the deletion footprint. Nothing consults it. What actually decides where an organization is
// served is home_region and allowed_regions, which the region-endpoint route and the application router read.
//
// A field that changes nothing is worse than a field that does not exist — this codebase has said so before,
// about the invite route's tenant_id, and made sending it an error. This one is worse still, because its NAME
// is a compliance promise: somebody reading a tenant record sees "data_residency: jp" and concludes something
// is being enforced.
//
// Rejecting writes is a contract decision and is not taken here. What this gate holds is the honesty: while
// the field is inert, the screen that answers "where does my data live" must say so.
func TestTheResidencyFieldSaysItEnforcesNothingWhileItDoes(t *testing.T) {
	src, err := os.ReadFile("admin_organization_setup.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	setup := string(src)
	if !strings.Contains(setup, "data_residency_enforced") {
		t.Fatal("the regions item no longer reports that data_residency enforces nothing")
	}
	// ★ AND THE ROUTE MUST STILL REFUSE TO SET IT. Allowing admin_tenant_routes.go above would otherwise let
	// the refusal be deleted silently — the exemption has to be paid for by the thing it exempts.
	routes, err := os.ReadFile("admin_tenant_routes.go")
	if err != nil {
		t.Fatalf("read the tenant routes: %v", err)
	}
	if !strings.Contains(string(routes), "adminTenantRefuseResidency") {
		t.Fatal("nothing refuses a write that sets data_residency any more")
	}

	// ★ AND THE CLAIM MUST STILL BE TRUE. The day somebody wires the field, this assertion fails and the
	// sentence above has to come out — which is the right way round: the screen cannot go on calling a live
	// control inert.
	//
	// "Read" means consulted by something that decides. Storage, normalisation, the footprint count and this
	// setup item are the four places that legitimately touch it.
	out, err := exec.Command("sh", "-c",
		`grep -rn '\.DataResidency\b' --include='*.go' . | grep -v '_test'`).Output()
	if err != nil && len(out) == 0 {
		t.Fatalf("could not scan for readers: %v", err)
	}
	// Storage, normalisation, the setup item that says it enforces nothing — and, since 2026-08-19, the route
	// that REFUSES to set it. A refusal is not a reader: it consults the field precisely in order to make sure
	// nothing ever depends on it. Anything else touching it means somebody wired it, and then the sentence on
	// the setup screen has to come out.
	allowed := regexp.MustCompile(`admin_tenant_model_postgres\.go|admin_tenant_model_store\.go|admin_organization_setup\.go|admin_tenant_routes\.go`)
	var readers []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || allowed.MatchString(line) {
			continue
		}
		readers = append(readers, line)
	}
	if len(readers) > 0 {
		t.Fatalf("data_residency is now read outside storage and the setup item, so it may no longer be inert — "+
			"check whether it decides anything and remove the 'enforces nothing' sentence if it does: %v", readers)
	}
}
