package main

import "testing"

func root(fp, subject string) parsedRoot { return parsedRoot{SHA256: fp, Subject: subject} }

// ★ The defect: nothing ever removed what the installer installed, so every rebuild left one more CA trusted
// for every name on the internet, belonging to a deployment that no longer exists.
func TestTheRootThisPackageInstalledIsRemoved(t *testing.T) {
	existing := []parsedRoot{root("aaa", "CN=Other Org Interception Root"), root("bbb", "CN=Ours Interception Root")}
	plan := planRootRemoval(existing, []parsedRoot{root("bbb", "CN=Ours Interception Root")})
	if len(plan.Remove) != 1 || plan.Remove[0].SHA256 != "bbb" {
		t.Fatalf("wrong certificate chosen: %#v", plan.Remove)
	}
	if len(plan.Absent) != 0 {
		t.Fatalf("nothing should be absent: %#v", plan.Absent)
	}
}

// ★★★ THE ONE THAT MATTERS. Two deployments can legitimately share a subject — a rotation in flight, or a
// device moved between organizations. Removing "everything named Interception Root" is an outage for the
// other one, so the match is on the fingerprint and the subject is only what a human reads.
func TestAnotherDeploymentsRootWithTheSameNameIsLeftAlone(t *testing.T) {
	existing := []parsedRoot{
		root("theirs", "CN=Acme Interception Root"),
		root("ours", "CN=Acme Interception Root"),
	}
	plan := planRootRemoval(existing, []parsedRoot{root("ours", "CN=Acme Interception Root")})
	if len(plan.Remove) != 1 || plan.Remove[0].SHA256 != "ours" {
		t.Fatalf("a same-named root belonging to another deployment was taken: %#v", plan.Remove)
	}
}

// An uninstall runs when things are already partly gone. Removing what is not there is not an error.
func TestAlreadyRemovedIsNotAFailure(t *testing.T) {
	plan := planRootRemoval(nil, []parsedRoot{root("ours", "CN=Ours Interception Root")})
	if len(plan.Remove) != 0 || len(plan.Absent) != 1 {
		t.Fatalf("%#v", plan)
	}
}
