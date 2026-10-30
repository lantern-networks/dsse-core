package edgeplane

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// A restarted node can know an outgoing root only by fingerprint. Revoking
// the tenant's authority must withdraw that fingerprint from the actual
// device-facing list as well as from the issuer/certificate lists.
func TestRevocationWithdrawsFingerprintOnlyRetirementFromDistribution(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	first, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first.SetOfflineTenantIntermediateDir(dir)
	aRootPEM, aIntermediate, aKey, aRoot := tenantOfflineBundle(t, "outgoing", now)
	if _, err := first.LoadOfflineTenantIntermediate("tenant-a", aRootPEM, aIntermediate, aKey); err != nil {
		t.Fatal(err)
	}
	bRootPEM, bIntermediate, bKey, bRoot := tenantOfflineBundle(t, "current", now)
	if _, err := first.LoadOfflineTenantIntermediate("tenant-a", bRootPEM, bIntermediate, bKey); err != nil {
		t.Fatal(err)
	}
	// A normal file replacement/restart need not retain A's certificate. The
	// announced-roots record is still required to remember its fingerprint.
	if err := os.Remove(filepath.Join(dir, retiringRootFileName("tenant-a", aRoot))); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.LoadOfflineTenantIntermediatesFromDir(dir); err != nil {
		t.Fatal(err)
	}
	if got := len(restarted.offlineTenantRetiringRoots["tenant-a"]); got != 0 {
		t.Fatalf("expected fingerprint-only retirement, got %d certificates", got)
	}
	if got := restarted.OfflineTenantAnnouncedRootFingerprints("tenant-a"); !sameFingerprintSet(got, []string{interceptionCertSHA256Hex(aRoot), interceptionCertSHA256Hex(bRoot)}) {
		t.Fatalf("rotation control: expected both roots, got %v", got)
	}
	if _, err := restarted.RevokeTenantInterceptionAuthority("tenant-a", "key custody lost"); err != nil {
		t.Fatal(err)
	}
	if got := restarted.OfflineTenantAnnouncedRootFingerprints("tenant-a"); len(got) != 0 {
		t.Fatalf("revoked authority remains in device-facing fingerprints: %v", got)
	}
	for _, fp := range []string{interceptionCertSHA256Hex(aRoot), interceptionCertSHA256Hex(bRoot)} {
		if restarted.RevokedTenantInterceptionRoots()[fp] == "" {
			t.Fatalf("revocation omitted root %s", fp)
		}
	}
	cRootPEM, cIntermediate, cKey, cRoot := tenantOfflineBundle(t, "recovered", now)
	if _, err := restarted.LoadOfflineTenantIntermediate("tenant-a", cRootPEM, cIntermediate, cKey); err != nil {
		t.Fatal(err)
	}
	want := []string{interceptionCertSHA256Hex(cRoot)}
	if got := restarted.OfflineTenantAnnouncedRootFingerprints("tenant-a"); !sameFingerprintSet(got, want) {
		t.Fatalf("replacement still distributes a revoked root: %v", got)
	}
	third, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := third.LoadOfflineTenantIntermediatesFromDir(dir); err != nil {
		t.Fatal(err)
	}
	if got := third.OfflineTenantAnnouncedRootFingerprints("tenant-a"); !sameFingerprintSet(got, want) {
		t.Fatalf("restart restored a revoked root to distribution: %v", got)
	}
}

func TestRevokedInterceptionRootCannotBeAnnouncedAgain(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	e, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	e.SetOfflineTenantIntermediateDir(t.TempDir())
	rootPEM, intermediate, key, _ := tenantOfflineBundle(t, "compromised", now)
	if _, err := e.LoadOfflineTenantIntermediate("tenant-a", rootPEM, intermediate, key); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RevokeTenantInterceptionAuthority("tenant-a", "key custody lost"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AnnounceTenantInterceptionRoot("tenant-a", rootPEM); err == nil {
		t.Fatal("revoked root was accepted as an incoming announcement")
	}
	if roots := e.OfflineTenantAnnouncedRoots("tenant-a"); len(roots) != 0 {
		t.Fatalf("revoked certificate remains in the admin/readiness announcement: %d", len(roots))
	}
	if roots := e.OfflineTenantAnnouncedRootFingerprints("tenant-a"); len(roots) != 0 {
		t.Fatalf("revoked fingerprint remains in device distribution: %v", roots)
	}
	replacementPEM, _, _, replacement := tenantOfflineBundle(t, "recovery", now)
	if _, err := e.AnnounceTenantInterceptionRoot("tenant-a", replacementPEM); err != nil {
		t.Fatalf("a different recovery root was refused: %v", err)
	}
	if roots := e.OfflineTenantAnnouncedRoots("tenant-a"); len(roots) != 1 || !roots[0].Equal(replacement) {
		t.Fatalf("recovery root not announced: %d", len(roots))
	}
}

func TestAnnouncedFingerprintsCanBeReadDuringRetirementUpdates(t *testing.T) {
	e := &NetworkExtensionLabTLSInterception{
		offlineTenantRetiringFingerprints: map[string][]string{"tenant-a": {strings.Repeat("a", 64)}},
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10000; i++ {
			e.issuerMu.Lock()
			e.offlineTenantRetiringFingerprints["tenant-a"] = []string{strings.Repeat("b", 64)}
			e.issuerMu.Unlock()
			runtime.Gosched()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10000; i++ {
			_ = e.OfflineTenantAnnouncedRootFingerprints("tenant-a")
			runtime.Gosched()
		}
	}()
	close(start)
	wg.Wait()
}

func TestAnnouncedFingerprintsCanBeReadDuringIncomingRootUpdates(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	rootPEM, _, _, _ := tenantOfflineBundle(t, "incoming", now)
	e := &NetworkExtensionLabTLSInterception{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			if _, err := e.AnnounceTenantInterceptionRoot("tenant-a", rootPEM); err != nil {
				t.Errorf("announce: %v", err)
				return
			}
			e.WithdrawIncomingTenantRoot("tenant-a")
			runtime.Gosched()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			_ = e.OfflineTenantAnnouncedRootFingerprints("tenant-a")
			runtime.Gosched()
		}
	}()
	close(start)
	wg.Wait()
}
