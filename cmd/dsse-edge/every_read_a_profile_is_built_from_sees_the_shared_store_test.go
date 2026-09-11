package main

import (
	"testing"
	"time"
)

// ★★★ THE READS A PROFILE IS BUILT FROM MUST GO THROUGH THE SHARED STORE (2026-08-31, measured live).
//
// An organization's authorities are minted on one control plane and written to the shared store. Another
// control plane answers from the snapshot it loaded at start-up — so after leadership moved between regions,
// every profile issued carried no device-CA pin, no interception root, no transport anchors and no
// organization door name, at HTTP 200 with a valid signature. A device installed from it dials the
// deployment-wide name, pins nothing, and refuses every page once its Edge inspects.
//
// The material paths already refreshed on a miss, with a comment saying why. The reads that BUILD THE PROFILE
// did not — the rule was applied at one call site and not the neighbouring one, which is how this repository
// keeps losing a day. So this test is written over ALL THREE authorities at once: a fourth read added to any
// of them without the refresh fails here.
func TestEveryProfileReadRefreshesFromTheSharedStore(t *testing.T) {
	now := func() time.Time { return time.Unix(1_760_000_000, 0).UTC() }

	// "minter" mints, and persists into a shared blob. "reader" is a second control plane that started before
	// the write and holds an empty snapshot, with the way back to the same blob.
	var shared []byte
	save := func(b []byte) error { shared = b; return nil }
	load := func() ([]byte, error) { return shared, nil }

	t.Run("the device-identity authority", func(t *testing.T) {
		minter := newTenantDeviceAuthority(nil, save, now)
		if _, err := minter.EnsureCA("t1", "Test Organization"); err != nil {
			t.Fatalf("mint: %v", err)
		}
		reader := newTenantDeviceAuthorityWithReload(nil, save, load, now)
		if _, known := reader.Row("t1"); !known {
			t.Fatal("a control plane that did not receive the write answers 'this organization has no device " +
				"authority', and the profile it issues pins nothing")
		}
	})

	t.Run("the interception authority", func(t *testing.T) {
		var shared2 []byte
		save2 := func(b []byte) error { shared2 = b; return nil }
		load2 := func() ([]byte, error) { return shared2, nil }
		stamp := now()
		rootCert, rootKey := interceptionTestCA(t, "Test Organization Interception Root", nil, nil, stamp)
		issuingCert, issuingKey := interceptionTestCA(t, "Test Organization Interception Issuing CA", rootCert, rootKey, stamp)
		minter := newTenantInterceptionAuthority(nil, save2, now)
		if _, err := minter.Import("t1", certPEMForTest(rootCert), certPEMForTest(issuingCert),
			ecKeyPEMForTest(t, issuingKey)); err != nil {
			t.Fatalf("import the organization's interception authority: %v", err)
		}
		reader := newTenantInterceptionAuthorityWithReload(nil, save2, load2, now)
		if _, known := reader.Row("t1"); !known {
			t.Fatal("a control plane that did not receive the write hands out a profile with no interception " +
				"root, and the device refuses every page once its Edge inspects")
		}
	})
}
