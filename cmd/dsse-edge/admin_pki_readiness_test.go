package main

import (
	"strings"
	"testing"
	"time"
)

// The Day-0 assessment. What it has to get right is not the wording but the JUDGEMENT: which gaps make a
// deployment merely incomplete, and which make it unsafe. An operator who cannot tell those apart works in the
// wrong order.

func TestAFileKeyAndNoRenewalIsNotProductionSafe(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{
		KeyCustody: "file", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		EnrollConfigured: true, EnrollSharedToken: true,
	})
	if report.ProductionSafe {
		t.Fatal("reported production-safe with the root key in a plain file and nothing renewing certificates")
	}
	// Both must be named, or an operator fixes one and believes they are done.
	var ids []string
	for _, item := range report.Items {
		if item.Blocking && item.Status != "ok" {
			ids = append(ids, item.ID)
		}
	}
	if len(ids) < 2 {
		t.Fatalf("only %v flagged as blocking; both the key custody and the missing renewal are", ids)
	}
}

// Issuing certificates with nothing to renew them is the specific failure this whole area exists to prevent:
// every device fails on the same day.
func TestIssuingWithoutRenewalIsBlocking(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{
		KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		IntermediateActive: true, EnrollConfigured: true, EnrollIdPBacked: true,
	})
	if report.ProductionSafe {
		t.Fatal("a deployment that issues certificates but renews none was called production-safe")
	}
	found := false
	for _, item := range report.Items {
		if item.ID == "renewal" {
			found = true
			if !item.Blocking || item.Status == "ok" {
				t.Fatalf("renewal item = %+v, want a blocking non-ok", item)
			}
			if !strings.Contains(item.Consequence, "same day") {
				t.Fatalf("the consequence does not say what actually happens: %q", item.Consequence)
			}
		}
	}
	if !found {
		t.Fatal("no renewal item at all")
	}
}

// Nothing is being issued yet, so renewal is not a gap. Reporting it would send an operator to configure
// something that has no purpose yet, and inventing work is how a readiness view stops being read.
func TestRenewalIsNotDemandedBeforeAnythingIsIssued(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{
		KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: true,
	})
	for _, item := range report.Items {
		if item.ID == "renewal" || item.ID == "recovery" {
			t.Fatalf("%s was raised before any certificate is issued", item.ID)
		}
	}
}

// A fully configured deployment must come out clean, or the view is noise.
func TestAFullyConfiguredDeploymentIsProductionSafe(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{
		KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		IntermediateActive: true, EnrollConfigured: true, EnrollIdPBacked: true,
		RenewalEndpoint: true, RecoveryListener: true, RecoveryWindow: 30 * 24 * time.Hour,
	})
	if !report.ProductionSafe {
		t.Fatalf("a fully configured deployment was not production-safe: %+v", report)
	}
	if report.Missing != 0 || report.Attention != 0 {
		t.Fatalf("clean deployment still reports attention=%d missing=%d", report.Attention, report.Missing)
	}
}

// "Signing has not been checked yet" must not read as "signing works". Unknown is not ok.
func TestUncheckedSigningIsNotReportedAsWorking(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{KeyCustody: "pkcs11"})
	for _, item := range report.Items {
		if item.ID == "key_custody_health" && item.Status == "ok" {
			t.Fatal("an unchecked key store was reported as working")
		}
	}
}

// Every non-ok item must say what breaks. "Not configured" alone does not tell an operator whether to care,
// and the consequence is what decides the order they work in.
func TestEveryProblemStatesItsConsequence(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{
		KeyCustody: "file", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		EnrollConfigured: true, EnrollSharedToken: true, RenewalEndpoint: true,
	})
	for _, item := range report.Items {
		if item.Status != "ok" && strings.TrimSpace(item.Consequence) == "" {
			t.Fatalf("%q is flagged as %q but does not say what happens if it is left alone", item.ID, item.Status)
		}
	}
}

// Every non-ok item must also say what to DO about it. This is what the Day-0 wizard renders as the next
// action; a step with no remediation is a dead end — it tells an operator something is wrong and then abandons
// them. (An "ok" item has nothing to do, so it carries no remediation.)
func TestEveryProblemStatesItsRemediation(t *testing.T) {
	// Exercise the missing/attention branches of every item: a file key, a shared-token-only enrolment, no
	// renewal, no recovery, no intermediate.
	report := assessPKIReadiness(pkiReadinessInput{
		KeyCustody: "file", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		EnrollConfigured: true, EnrollSharedToken: true,
	})
	seen := 0
	for _, item := range report.Items {
		if item.Status == "ok" {
			continue
		}
		seen++
		if strings.TrimSpace(item.Remediation) == "" {
			t.Fatalf("%q is flagged as %q but does not say what to do about it (the wizard has nothing to show)", item.ID, item.Status)
		}
	}
	if seen == 0 {
		t.Fatal("this input was supposed to produce unresolved items to check")
	}
}

// The enrolment assessment must know about every credential the endpoint actually accepts. When admin-issued
// tokens were added it did not, and the result was not an incomplete guide but a WRONG one: a deployment
// enrolling with per-device tokens and no IdP was reported as running on a shared secret and told to add an IdP
// it does not need. A guide is followed, so a guide that is wrong does damage a missing one does not.
func TestEnrolmentReadinessKnowsEveryCredentialTheEndpointAccepts(t *testing.T) {
	find := func(r pkiReadinessReport) pkiReadinessItem {
		for _, i := range r.Items {
			if i.ID == "enrolment" {
				return i
			}
		}
		t.Fatalf("no enrolment item")
		return pkiReadinessItem{}
	}

	// The shape this product recommends: per-device tokens, no shared secret.
	got := find(assessPKIReadiness(pkiReadinessInput{EnrollConfigured: true, EnrollAdminTokens: true}))
	if got.Status != "ok" {
		t.Fatalf("admin-issued tokens are the recommended state, got %q: %s", got.Status, got.Detail)
	}

	// A shared token outranks everything else, because the weakest credential accepted is the one an attacker
	// uses — being ALSO configured for something better does not help.
	got = find(assessPKIReadiness(pkiReadinessInput{
		EnrollConfigured: true, EnrollAdminTokens: true, EnrollIdPBacked: true, EnrollSharedToken: true}))
	if got.Status == "ok" || !got.Blocking {
		t.Fatalf("a live shared token must block however much else is configured: %+v", got)
	}

	// An IdP alone is a SUPPORTED end state — someone enrolling their own machine — so it must not be flagged.
	// A readiness item a legitimate deployment can never clear is a nag, and a nag is how the rest of the page
	// stops being read. What it must do is say what the credential proves, so an operator can tell whether it
	// fits the way their devices are set up.
	got = find(assessPKIReadiness(pkiReadinessInput{EnrollConfigured: true, EnrollIdPBacked: true}))
	if got.Status != "ok" {
		t.Fatalf("an IdP-only deployment is supported and must not be flagged: %+v", got)
	}
	if !strings.Contains(got.Detail, "PERSON") {
		t.Fatalf("it must say what the credential proves: %+v", got)
	}

	// A device CA with no way to prove eligibility cannot enrol anything, which is worth saying plainly rather
	// than describing as a shared-token problem it does not have.
	got = find(assessPKIReadiness(pkiReadinessInput{EnrollConfigured: true}))
	if !got.Blocking || strings.Contains(strings.ToLower(got.Detail), "shared") {
		t.Fatalf("no credential at all must be reported as exactly that: %+v", got)
	}
}

// A guide stops being usable at the point where it says "point the agents at the renewal endpoint" and leaves
// an operator to work out which host, which port, which path. The assessment runs INSIDE the deployment it is
// describing, so it already knows all three.
func TestRemediationCarriesTheDeploymentsRealValues(t *testing.T) {
	find := func(r pkiReadinessReport, id string) pkiReadinessItem {
		for _, i := range r.Items {
			if i.ID == id {
				return i
			}
		}
		t.Fatalf("no %s item", id)
		return pkiReadinessItem{}
	}

	report := assessPKIReadiness(pkiReadinessInput{
		KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		IntermediateActive: true, EnrollConfigured: true, EnrollAdminTokens: true,
		RenewalEndpoint:    false, // not configured: this is the case with something to say
		RenewalEndpointURL: "https://edge.example:18543",
	})
	renewal := find(report, "renewal")
	if len(renewal.Concrete) == 0 {
		t.Fatalf("an unmet step must carry the real values, not only prose: %+v", renewal)
	}
	if !strings.Contains(strings.Join(renewal.Concrete, " "), "edge.example:18543") {
		t.Fatalf("the deployment's actual endpoint must appear: %+v", renewal.Concrete)
	}

	// With no address known, say nothing rather than print a placeholder somebody pastes verbatim.
	report = assessPKIReadiness(pkiReadinessInput{
		EnrollConfigured: true, EnrollAdminTokens: true, RenewalEndpoint: false})
	if len(find(report, "renewal").Concrete) != 0 {
		t.Fatalf("an unknown address must produce nothing, not a placeholder")
	}
}

// The recovery listener is the one an agent CANNOT work out for itself — it exists for devices whose certificate
// has expired, so it cannot be reached over the transport that certificate opens. Not enabled is worth stating
// with that reason attached.
func TestRecoveryRemediationExplainsWhyItCannotBeDerived(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{
		EnrollConfigured: true, EnrollAdminTokens: true, RenewalEndpoint: true,
		RecoveryListener: false,
	})
	for _, i := range report.Items {
		if i.ID != "recovery" {
			continue
		}
		joined := strings.Join(i.Concrete, " ")
		if joined == "" {
			t.Fatalf("a missing recovery listener must say what to set: %+v", i)
		}
		if !strings.Contains(joined, "enroll-renew-grace-listen") {
			t.Fatalf("it must name the setting: %+v", i.Concrete)
		}
		return
	}
	t.Fatalf("no recovery item")
}

// The signing check is the one thing on this page a screen can DO. It is offered exactly when there is a reason
// to run it — an unknown or failing result — and not as decoration next to a healthy one.
func TestTheSigningCheckIsOfferedOnlyWhenItWouldTellYouSomething(t *testing.T) {
	offered := func(in pkiReadinessInput) bool {
		for _, i := range assessPKIReadiness(in).Items {
			if i.ID == "key_custody_health" {
				return i.Action == "check-signing"
			}
		}
		return false
	}
	if !offered(pkiReadinessInput{KeyCustody: "pkcs11"}) {
		t.Fatalf("an unchecked key store is exactly when an operator wants to run it")
	}
	if !offered(pkiReadinessInput{KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: false}) {
		t.Fatalf("a failing store is when somebody has just fixed something and wants to know")
	}
	if offered(pkiReadinessInput{KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: true}) {
		t.Fatalf("a healthy store needs no button; offering one everywhere is how buttons stop meaning anything")
	}
}
