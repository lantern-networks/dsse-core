package main

import "testing"

// ★★★ THE RULE HAS TO COVER WRITES ADDED TOMORROW, so it reads the scope's own suffix rather than a list
// somebody has to remember to extend. A permission that names a change and is not recognised here is a change
// a standby accepts and discards.
func TestEveryChangingPermissionIsRecognisedAsAWrite(t *testing.T) {
	writes := []string{
		"admin.enrollment.write", "admin.policy.write", "admin.steering.write", "admin.connectors.write",
		"admin.certs.write", "admin.tenant.write", "admin.tenant.admin", "admin.export.cancel",
		"admin.export.create", "admin.dns.write", "admin.platform.write",
	}
	for _, p := range writes {
		if !adminPermissionWrites(p) {
			t.Fatalf("%q was not recognised as a change — a standby would accept it and discard it", p)
		}
	}
	// The guard: reads must stay readable on a standby, which is what a standby is for.
	reads := []string{
		"admin.state.read", "admin.policy.read", "admin.enrollment.read", "admin.logs.read",
		"admin.steering.read", "admin.connectors.read",
	}
	for _, p := range reads {
		if adminPermissionWrites(p) {
			t.Fatalf("%q was treated as a change — a standby would stop answering questions", p)
		}
	}
}
