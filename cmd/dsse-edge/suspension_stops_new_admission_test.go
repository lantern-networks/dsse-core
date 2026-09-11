package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★ SUSPENSION STOPPED ONE ADMISSION DOOR OF THREE (2026-08-19).
//
// The decision recorded on adminTenantAdministrativelySuspended is explicit: suspension freezes the
// administrative plane and stops NEW admission, while enforcement for devices already enrolled continues —
// "a billing dispute must not become a security incident by taking protection off a customer's laptops".
//
// Only POST /enroll enforced it. Two other doors admit machines:
//
//	POST /admin/tenant-cas        registers a device CA. Every device holding a certificate from it is admitted
//	                              at the transport handshake from the moment it lands, without /enroll at all.
//	POST /admin/enrolment-tokens  mints an approval. The credential outlives the suspension and the device
//	                              walks in whenever it is used.
//
// It matters most for the operator acting under a delegation, which is the case suspension exists for: the
// provider should stop adding devices, not stop protecting the ones already there.
//
// This gate counts the doors from the source, so one added tomorrow is covered tomorrow.
func TestEveryAdmissionDoorChecksTheOrganizationIsRealAndNotSuspended(t *testing.T) {
	// A route admits new machines when it registers a device authority, mints an approval, or enrols.
	doors := map[string]string{
		"POST /admin/tenant-cas":       "admin_tenant_ca_routes.go",
		"POST /admin/enrolment-tokens": "admin_enrolment_tokens.go",
	}
	route := regexp.MustCompile(`mux\.HandleFunc\("((?:POST|PUT) /admin/[^"]+)"`)
	for want, file := range doors {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		lines := strings.Split(string(raw), "\n")
		found, guarded, exists := false, false, false
		for i, l := range lines {
			m := route.FindStringSubmatch(l)
			if m == nil || m[1] != want {
				continue
			}
			found = true
			// ★ COMMENTS DO NOT COUNT (2026-08-19, caught by the control). The first version scanned the raw
			// handler text, so the explanatory comment above the check satisfied it: deleting the actual call
			// left the gate green. Mentioning a guard is not calling one — the same mistake as verifying a
			// helper instead of its call site, which this repo made a day earlier.
			guarded = callsSuspensionCheck(lines[i:minInt(i+110, len(lines))])
			exists = callsExistenceCheck(lines[i:minInt(i+110, len(lines))])
			break
		}
		if !found {
			t.Fatalf("%s is no longer registered in %s — this gate is reading the wrong file", want, file)
		}
		if !guarded {
			t.Fatalf("%s admits new machines and does not consult the tenant's lifecycle state, so a suspended "+
				"organization goes on onboarding", want)
		}
		// ★★★ AND THE ORGANIZATION HAS TO EXIST (2026-08-19, measured live before the fix). Naming a tenant
		// that is not in the registry minted a real token — 200 with a usable secret, stored against an id
		// nobody runs. The credential outlives the absence: create or recreate that id and it is live, so a
		// purged organization's namespace can be re-armed before anybody reoccupies it.
		if !exists {
			t.Fatalf("%s admits new machines without checking that the organization is in the registry", want)
		}
	}

	// ★ AND THE ORIGINAL DOOR IS STILL GUARDED, or this passes while the one that always worked regressed.
	enrol, err := os.ReadFile("enroll_endpoint.go")
	if err != nil {
		t.Fatalf("read enroll_endpoint.go: %v", err)
	}
	if !strings.Contains(string(enrol), "adminTenantAdministrativelySuspended") {
		t.Fatal("POST /enroll no longer checks suspension")
	}

	// ★ THE CONTROL ON THE DECISION ITSELF: suspension must NOT be wired into the enforcement path. If a
	// suspended organization's devices stopped being protected, that would be the security incident the
	// decision exists to prevent, and this gate would otherwise be satisfied by exactly that.
	for _, enforcement := range []string{"secure_transport.go", "steer_agent_policy_routes.go"} {
		raw, err := os.ReadFile(enforcement)
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), "adminTenantAdministrativelySuspended") {
			t.Fatalf("%s consults suspension; enforcement for devices already enrolled must continue while an "+
				"organization is suspended", enforcement)
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// callsSuspensionCheck reports whether these lines CALL the suspension check, ignoring comments.
func callsSuspensionCheck(lines []string) bool {
	for _, l := range lines {
		code := l
		if i := strings.Index(code, "//"); i >= 0 {
			code = code[:i]
		}
		if strings.Contains(code, "adminTenantAdministrativelySuspended(") {
			return true
		}
	}
	return false
}

// callsExistenceCheck reports whether these lines CALL the registry-absence check, ignoring comments.
func callsExistenceCheck(lines []string) bool {
	for _, l := range lines {
		code := l
		if i := strings.Index(code, "//"); i >= 0 {
			code = code[:i]
		}
		if strings.Contains(code, "adminTenantIsGone(") {
			return true
		}
	}
	return false
}

// ★★★ A PULLED COPY CANNOT TESTIFY TO AN ABSENCE (2026-08-19, measured on the running lab).
//
// The control plane keeps the tenant registry in shared Postgres. The enforcement Edge is started with a
// LOCAL FILE — -tenant-model-store=/dataplane-ne/tenant_model.json — that nothing distributes to. Measured:
// suspending tenant_northwind on the control plane left :9444 reporting "suspended" and :9443 reporting
// "active", in the same second.
//
// That matters twice. The suspension checks added an hour earlier read the Edge's copy, so on an Edge they
// are only as current as a file nobody updates. And the ABSENCE check is worse than inert there: an
// organization created on the control plane is simply not in the Edge's file, so refusing on absence would
// refuse the first thing a new organization ever does — approve a device — on a node that has never heard of
// it. The fix would have been an outage.
//
// adminTenantIsGone already declines to testify when the store cannot ENUMERATE. This is the same asymmetry
// one step out: a node that pulls its configuration is not the register.
func TestAbsenceIsOnlyEvidenceOnTheRegister(t *testing.T) {
	if !adminTenantAbsenceIsAuthoritative("") {
		t.Fatal("a node with no config source IS the register; its registry must be able to testify to an absence")
	}
	if adminTenantAbsenceIsAuthoritative("https://controlplane:9443") {
		t.Fatal("a config-pulling Edge holds a copy nothing distributes to, so an organization missing from it " +
			"may simply be newer than the copy — refusing on that would refuse a new organization its first device")
	}
	// Whitespace is not a config source, so a node configured with one is still the register.
	if !adminTenantAbsenceIsAuthoritative("   ") {
		t.Fatal("whitespace was treated as a config source")
	}

	// And the admission doors must consult it, or the guard is back to refusing on a stale file.
	for _, f := range []string{"admin_enrolment_tokens.go", "admin_tenant_ca_routes.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if !strings.Contains(string(raw), "adminTenantAbsenceIsAuthoritative(") {
			t.Fatalf("%s refuses on absence without asking whether this node may testify to one", f)
		}
	}
}
