package tenantca

import (
	"bytes"
	"encoding/json"
	"testing"
)

func sharedRegistryBytes(t *testing.T, entries ...TenantCAEntry) []byte {
	t.Helper()
	if entries == nil {
		entries = []TenantCAEntry{}
	}
	b, err := json.Marshal(TenantCARegistryFile{Tenants: entries})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAdoptRejectsEntireMalformedSharedSnapshot(t *testing.T) {
	old, oldPEM := selfSignedCAForTest(t, "existing")
	newCA, newPEM := selfSignedCAForTest(t, "new")
	for _, bad := range []TenantCAEntry{
		{TenantID: "", CAPEM: string(newPEM)},
		{TenantID: "other", CAPEM: "not a certificate"},
		{TenantID: "other", CAPEM: string(newPEM) + "\ntrailing garbage"},
		{TenantID: "other", CAFile: "/tmp/remote-ca.pem"},
	} {
		r := NewTenantCARegistry()
		if _, err := r.Register("existing", oldPEM); err != nil {
			t.Fatal(err)
		}
		before, _ := r.Snapshot()
		added, err := r.Adopt(sharedRegistryBytes(t,
			TenantCAEntry{TenantID: "new", CAPEM: string(newPEM)}, bad))
		if err == nil || added != 0 || resolves(r, old) != "existing" || resolves(r, newCA) != "" {
			t.Fatalf("partial adoption of invalid shared snapshot: added=%d err=%v", added, err)
		}
		after, _ := r.Snapshot()
		if !bytes.Equal(before, after) {
			t.Fatal("invalid shared snapshot changed registry")
		}
	}
}

func TestSaveToDoesNotPublishOrAdoptMalformedSharedRow(t *testing.T) {
	localCA, localPEM := selfSignedCAForTest(t, "local")
	remoteCA, remotePEM := selfSignedCAForTest(t, "remote")
	r := NewTenantCARegistry()
	if _, err := r.Register("local", localPEM); err != nil {
		t.Fatal(err)
	}
	p := &memPersister{data: sharedRegistryBytes(t,
		TenantCAEntry{TenantID: "remote", CAPEM: string(remotePEM)},
		TenantCAEntry{TenantID: "broken", CAPEM: "bad PEM"})}
	sharedBefore := append([]byte(nil), p.data...)
	localBefore, _ := r.Snapshot()
	if err := r.SaveTo(p); err == nil {
		t.Fatal("SaveTo published over a malformed shared snapshot")
	}
	localAfter, _ := r.Snapshot()
	if !bytes.Equal(localBefore, localAfter) || !bytes.Equal(sharedBefore, p.data) ||
		resolves(r, localCA) != "local" || resolves(r, remoteCA) != "" {
		t.Fatal("failed SaveTo changed local or shared admission anchors")
	}
}

func TestAdoptRejectsConflictingSharedCAOwnership(t *testing.T) {
	ca, caPEM := selfSignedCAForTest(t, "shared")
	for _, seedLocal := range []bool{false, true} {
		r := NewTenantCARegistry()
		if seedLocal {
			if _, err := r.Register("owner", caPEM); err != nil {
				t.Fatal(err)
			}
		}
		before, _ := r.Snapshot()
		entries := []TenantCAEntry{{TenantID: "owner", CAPEM: string(caPEM)}, {TenantID: "other", CAPEM: string(caPEM)}}
		if seedLocal {
			entries = entries[1:]
		}
		added, err := r.Adopt(sharedRegistryBytes(t, entries...))
		if err == nil || added != 0 {
			t.Fatalf("ambiguous shared CA accepted: local=%v added=%d err=%v", seedLocal, added, err)
		}
		after, _ := r.Snapshot()
		if !bytes.Equal(before, after) {
			t.Fatalf("ambiguous shared CA changed registry: local=%v", seedLocal)
		}
		if seedLocal && resolves(r, ca) != "owner" {
			t.Fatal("shared snapshot moved CA owner")
		}
	}
}

func TestReconcileRejectsPartialSharedSnapshotBeforeWithdrawal(t *testing.T) {
	keep, keepPEM := selfSignedCAForTest(t, "keep")
	add, addPEM := selfSignedCAForTest(t, "add")
	r := NewTenantCARegistry()
	if _, err := r.Register("keep", keepPEM); err != nil {
		t.Fatal(err)
	}
	before, _ := r.Snapshot()
	added, removed, err := r.Reconcile(sharedRegistryBytes(t,
		TenantCAEntry{TenantID: "add", CAPEM: string(addPEM)},
		TenantCAEntry{TenantID: "broken", CAPEM: "not a certificate"}))
	if err == nil || added != 0 || removed != 0 {
		t.Fatalf("partial shared snapshot reconciled: added=%d removed=%d err=%v", added, removed, err)
	}
	after, _ := r.Snapshot()
	if !bytes.Equal(before, after) || resolves(r, keep) != "keep" || resolves(r, add) != "" {
		t.Fatal("partial shared snapshot changed admission anchors")
	}
	// An explicitly empty view is still a no-op, not a wholesale withdrawal.
	if added, removed, err := r.Reconcile(sharedRegistryBytes(t)); err != nil || added != 0 || removed != 0 || resolves(r, keep) != "keep" {
		t.Fatalf("empty shared view no-op changed: added=%d removed=%d err=%v", added, removed, err)
	}
}

func TestReconcileRejectsConflictingCAOwnerBeforeWithdrawal(t *testing.T) {
	keep, keepPEM := selfSignedCAForTest(t, "keep")
	other, otherPEM := selfSignedCAForTest(t, "other")
	r := NewTenantCARegistry()
	if _, err := r.Register("keep", keepPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register("other", otherPEM); err != nil {
		t.Fatal(err)
	}
	before, _ := r.Snapshot()
	// The shared view claims the existing CA for a different tenant and omits
	// another live CA. Neither reassignment nor withdrawal may take effect.
	added, removed, err := r.Reconcile(sharedRegistryBytes(t,
		TenantCAEntry{TenantID: "wrong-owner", CAPEM: string(keepPEM)}))
	if err == nil || added != 0 || removed != 0 {
		t.Fatalf("conflicting owner reconciled: added=%d removed=%d err=%v", added, removed, err)
	}
	after, _ := r.Snapshot()
	if !bytes.Equal(before, after) || resolves(r, keep) != "keep" || resolves(r, other) != "other" {
		t.Fatal("conflicting shared snapshot changed admission anchors")
	}
}
