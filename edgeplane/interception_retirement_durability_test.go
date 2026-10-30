package edgeplane

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func retirementFixture(t *testing.T) (*NetworkExtensionLabTLSInterception, string, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	e, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	e.SetOfflineTenantIntermediateDir(dir)
	r, i, k, old := tenantOfflineBundle(t, "retirement-old", now)
	if _, err := e.LoadOfflineTenantIntermediate("tenant-a", r, i, k); err != nil {
		t.Fatal(err)
	}
	r, i, k, _ = tenantOfflineBundle(t, "retirement-new", now)
	if _, err := e.LoadOfflineTenantIntermediate("tenant-a", r, i, k); err != nil {
		t.Fatal(err)
	}
	return e, dir, old
}

func TestAnnouncedRootsRejectInvalidRecordsWithoutOverwriting(t *testing.T) {
	for _, invalid := range []string{"null", "{}", `{"current_sha256":"invalid"}`, `{"current_sha256":"a","current_sha256":"b"}`} {
		t.Run(invalid, func(t *testing.T) {
			dir := t.TempDir()
			p := announcedRootsPath(dir, "tenant-a")
			if err := os.WriteFile(p, []byte(invalid), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := recordAnnouncedRoot(dir, "tenant-a", strings.Repeat("a", 64)); err == nil {
				t.Fatal("invalid existing record accepted")
			}
			if err := forgetRetiringRoot(dir, "tenant-a", strings.Repeat("b", 64)); err == nil {
				t.Fatal("invalid existing record accepted for withdrawal")
			}
			got, err := os.ReadFile(p)
			if err != nil || string(got) != invalid {
				t.Fatal("invalid original overwritten")
			}
		})
	}
}

func TestAnnouncedRootsCreateNewDirectoryAndPermitExplicitReactivation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new", "issuer-store")
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := recordAnnouncedRoot(dir, "tenant-a", a); err != nil {
		t.Fatal(err)
	}
	if _, err := recordAnnouncedRoot(dir, "tenant-a", b); err != nil {
		t.Fatal(err)
	}
	if err := forgetRetiringRoot(dir, "tenant-a", a); err != nil {
		t.Fatal(err)
	}
	if _, err := recordAnnouncedRoot(dir, "tenant-a", a); err != nil {
		t.Fatal(err)
	}
	rec, err := readAnnouncedRoots(dir, "tenant-a")
	if err != nil || rec.CurrentSHA256 != a || len(rec.WithdrawnSHA256) != 0 {
		t.Fatalf("explicit current root must not stay withdrawn: %+v %v", rec, err)
	}
}

func TestRetiringRootWithdrawalRequiresDurableRecord(t *testing.T) {
	e, dir, old := retirementFixture(t)
	p := announcedRootsPath(dir, "tenant-a")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	removed, err := e.WithdrawRetiringTenantRoot("tenant-a", interceptionCertSHA256Hex(old))
	if err == nil || removed {
		t.Fatalf("unpersisted withdrawal reported success: removed=%v err=%v", removed, err)
	}
	if got := len(e.OfflineTenantAnnouncedRoots("tenant-a")); got != 2 {
		t.Fatalf("failed withdrawal changed live announcements: %d", got)
	}
}

func TestRetiringRootWithdrawalSurvivesStalePEMAtRestart(t *testing.T) {
	_, dir, old := retirementFixture(t)
	if err := forgetRetiringRoot(dir, "tenant-a", interceptionCertSHA256Hex(old)); err != nil {
		t.Fatal(err)
	}
	// A stale file may survive deletion failure or a previous writer's late
	// flush. The durable withdrawal decision must remain authoritative.
	if err := os.WriteFile(filepath.Join(dir, retiringRootFileName("tenant-a", old)), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: old.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	restarted := &NetworkExtensionLabTLSInterception{}
	restarted.restoreRetiringTenantRoots(dir, "tenant-a")
	if got := len(restarted.offlineTenantRetiringRoots["tenant-a"]); got != 0 {
		t.Fatalf("withdrawn root restored from stale PEM: %d", got)
	}
}

func TestCorruptAnnouncedRootsArePreservedAndRefuseReplacement(t *testing.T) {
	e, dir, _ := retirementFixture(t)
	p := announcedRootsPath(dir, "tenant-a")
	bad := []byte(`{"current_sha256":`)
	if err := os.WriteFile(p, bad, 0600); err != nil {
		t.Fatal(err)
	}
	r, i, k, _ := tenantOfflineBundle(t, "uncommitted-replacement", time.Now())
	before := e.OfflineTenantAnnouncedRoots("tenant-a")[0]
	if _, err := e.LoadOfflineTenantIntermediate("tenant-a", r, i, k); err == nil {
		t.Fatal("corrupt announcement record accepted")
	}
	after, err := os.ReadFile(p)
	if err != nil || string(after) != string(bad) {
		t.Fatal("corrupt original was overwritten")
	}
	if !before.Equal(e.OfflineTenantAnnouncedRoots("tenant-a")[0]) {
		t.Fatal("failed replacement changed the active root")
	}
}
