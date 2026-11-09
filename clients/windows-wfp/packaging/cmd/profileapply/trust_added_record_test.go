package main

import (
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Found 2026-11-04: the uninstall removed the deployment anchor the administrator had trusted by hand, because
// the step-up portal is served under the same anchor and the removal took every certificate in its PEM.
func TestRemovalTakesBackOnlyWhatProvisioningAdded(t *testing.T) {
	dir := t.TempDir()
	pem := filepath.Join(dir, "step_up_portal_ca.pem")
	roots := []parsedRoot{{Subject: "admin anchor", SHA256: "AAA"}, {Subject: "added", SHA256: "bbb"}}

	// No record: an older package trusted these, and the older behaviour (take them all) stands.
	got, err := onlyWhatProvisioningAdded(pem, roots)
	if err != nil || len(got) != 2 {
		t.Fatalf("without a record = %v, %v; want both", got, err)
	}

	// Provisioning found AAA already trusted and added nothing: the record exists and is empty.
	if err := recordTrustAdded(pem, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ = onlyWhatProvisioningAdded(pem, roots); len(got) != 0 {
		t.Fatalf("nothing was added, but the removal would take %v", got)
	}

	// A later provisioning added bbb; the earlier record is kept, and only bbb is taken back.
	if err := recordTrustAdded(pem, []string{"BBB"}); err != nil {
		t.Fatal(err)
	}
	got, _ = onlyWhatProvisioningAdded(pem, roots)
	if len(got) != 1 || got[0].SHA256 != "bbb" {
		t.Fatalf("removal would take %v; want only the added root", got)
	}
	if _, err := os.Stat(trustAddedRecordPath(pem)); err != nil {
		t.Fatal(err)
	}
}

func writeRootsPEM(t *testing.T, path string, roots ...parsedRoot) {
	t.Helper()
	body := []byte{}
	for _, r := range roots {
		body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.DER})...)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Found 2026-11-04 by upgrading a device from 0.4.0 to 0.4.1 and uninstalling: 0.4.0 trusted the interception
// root and kept no record, 0.4.1 found it already trusted and recorded that it had added nothing, and the
// uninstall left the organization's interception root trusted.
func TestAnUpgradeKeepsWhatTheOlderPackageTrusted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "interception-root.pem")
	old := selfSigned(t, "Acceptance A Interception Root")
	writeRootsPEM(t, path, old) // left by 0.4.0, which kept no record

	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	// Provisioning rewrites the PEM (same root) and finds it already in the store.
	writeRootsPEM(t, path, old)
	inherited, err := inheritFromOlderPackage(path, []parsedRoot{old})
	if err != nil || len(inherited) != 1 {
		t.Fatalf("inherited = %v, %v; want the root 0.4.0 trusted", inherited, err)
	}
	if err := recordTrustAdded(path, inherited); err != nil {
		t.Fatal(err)
	}
	if err := forgetOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	got, err := onlyWhatProvisioningAdded(path, []parsedRoot{old})
	if err != nil || len(got) != 1 {
		t.Fatalf("the uninstall would take %v, %v; want the interception root back out", got, err)
	}
	if _, err := os.Stat(olderPackageTrustPath(path)); !os.IsNotExist(err) {
		t.Fatalf("the note outlived the record: %v", err)
	}
}

// A fresh install has no older PEM, so a certificate the administrator trusted by hand stays theirs.
func TestAFreshInstallInheritsNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "step_up_portal_ca.pem")
	adminAnchor := selfSigned(t, "Deployment Root CA")
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	writeRootsPEM(t, path, adminAnchor)
	inherited, err := inheritFromOlderPackage(path, []parsedRoot{adminAnchor})
	if err != nil || len(inherited) != 0 {
		t.Fatalf("a fresh install inherited %v, %v", inherited, err)
	}
}

// A fresh install that failed after writing its PEM and before its record, then retried, took
// its own PEM for the older package's, and a certificate the administrator had trusted by hand was recorded as
// provisioning's and taken out at uninstall.
func TestAFailedFreshInstallRetriedInheritsNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "step_up_portal_ca.pem")
	adminAnchor := selfSigned(t, "Deployment Root CA")

	// First attempt: nothing was there. Note it, write the PEM, then fail before the store install recorded.
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(olderPackageTrustPath(path)); err != nil {
		t.Fatalf("a fresh install left no note that nothing was there: %v", err)
	}
	writeRootsPEM(t, path, adminAnchor)

	// The retry: a PEM with no record. The first note stands.
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	inherited, err := inheritFromOlderPackage(path, []parsedRoot{adminAnchor})
	if err != nil || len(inherited) != 0 {
		t.Fatalf("the retry inherited %v, %v; the administrator's own anchor would be taken out", inherited, err)
	}
	if err := recordTrustAdded(path, inherited); err != nil {
		t.Fatal(err)
	}
	if err := forgetOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	if got, _ := onlyWhatProvisioningAdded(path, []parsedRoot{adminAnchor}); len(got) != 0 {
		t.Fatalf("the uninstall would take %v", got)
	}
}

// A PEM that already has a record belongs to a package that keeps one; nothing is noted, and a reinstall
// that finds a certificate already trusted does not start owning it.
func TestARecordedPEMIsNotReattributed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "step_up_portal_ca.pem")
	adminAnchor := selfSigned(t, "Deployment Root CA")
	writeRootsPEM(t, path, adminAnchor)
	if err := recordTrustAdded(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(olderPackageTrustPath(path)); !os.IsNotExist(err) {
		t.Fatalf("a recorded PEM was noted as an older package's: %v", err)
	}
}

// A provisioning that failed after rewriting the PEM must not replace the older package's note with its own PEM.
func TestTheFirstNoteStands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "interception-root.pem")
	old, next := selfSigned(t, "Old Root"), selfSigned(t, "New Root")
	writeRootsPEM(t, path, old)
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	writeRootsPEM(t, path, next) // rewritten, then the provisioning failed
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	inherited, _ := inheritFromOlderPackage(path, []parsedRoot{old, next})
	if len(inherited) != 1 || inherited[0] != strings.ToLower(old.SHA256) {
		t.Fatalf("inherited %v; want only the root the older package trusted", inherited)
	}
}

// The helpers above only help if provisioning notes the older PEM BEFORE rewriting it, and the store install
// hands its decisions to installTrustAnchor. Both callers are Windows-only, so they are checked by their source.
func TestProvisioningNotesTheOlderPackageBeforeRewriting(t *testing.T) {
	body, err := os.ReadFile("provision_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, v := range []string{"portalAnchorPath", "rootPath"} {
		note := strings.Index(src, "captureOlderPackageTrust("+v+")")
		write := strings.Index(src, "os.WriteFile("+v+",")
		if note < 0 || write < 0 || note > write {
			t.Errorf("%s: the older package's trust is not noted before the PEM is rewritten (note at %d, write at %d)", v, note, write)
		}
	}
	install, err := os.ReadFile("interception_root_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	// The store install hands every decision to installTrustAnchor, which the tests below run.
	if !strings.Contains(string(install), "return installTrustAnchor(path, what, list, func(der []byte) error { return addToStore(store, der) })") {
		t.Error("doInstallTrustAnchor does not hand its decisions to installTrustAnchor")
	}
	if strings.Count(string(install), "addToStore(") != 2 { // its definition, and the one call above
		t.Error("the Windows store is added to somewhere other than through installTrustAnchor")
	}
}

// A fresh install wrote its PEM, the store install refused it (a different authority already
// holds one of its names), and the device was then uninstalled. The removal read "no record" as an older
// package's PEM and took out the administrator's own CA, which provisioning had never added.
func TestAnUnfinishedFreshInstallTakesNothingOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interception-root.pem")
	admin := selfSigned(t, "Administrator Deployment CA")
	theirs, ours := selfSigned(t, "Shared Subject"), selfSigned(t, "Shared Subject")
	store := []parsedRoot{admin, theirs}

	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	writeRootsPEM(t, path, admin, ours)
	incoming, err := readInterceptionRoots(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planRootInstall(store, incoming); err == nil {
		t.Fatal("the same-name collision was not refused; this test needs the refusal")
	}

	removed := uninstallFrom(t, path, &store)
	if len(removed) != 0 {
		t.Fatalf("the uninstall took %v out; provisioning never added anything", removed)
	}
	if len(store) != 2 {
		t.Fatalf("store after the uninstall = %v", store)
	}
}

// The same unfinished provisioning on a device upgraded from a package that kept no record: what that package
// was trusting is still taken back, and nothing else.
func TestAnUnfinishedUpgradeTakesBackOnlyWhatTheOlderPackageTrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "step_up_portal_ca.pem")
	old, admin := selfSigned(t, "Old Deployment CA"), selfSigned(t, "Administrator CA")
	store := []parsedRoot{old, admin}

	writeRootsPEM(t, path, old) // left by the older package, which kept no record
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	writeRootsPEM(t, path, old, admin) // rewritten; the store install then never ran

	removed := uninstallFrom(t, path, &store)
	if len(removed) != 1 || removed[0] != old.SHA256 {
		t.Fatalf("the uninstall took %v; want only the root the older package trusted", removed)
	}
}

// A provisioning that added one certificate and failed on the next: the record names both (each is recorded
// before it goes in), the uninstall takes back the one that went in, and the administrator's CA stays.
func TestAPartlyFinishedInstallTakesBackWhatWentIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interception-root.pem")
	admin, first, second := selfSigned(t, "Administrator CA"), selfSigned(t, "Added First"), selfSigned(t, "Added Second")
	store := []parsedRoot{admin}

	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	writeRootsPEM(t, path, admin, first, second)
	// As doInstallTrustAnchor does: the inherited (none), then each certificate recorded before it is added.
	if err := recordTrustAdded(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := recordTrustAdded(path, []string{first.SHA256}); err != nil {
		t.Fatal(err)
	}
	store = append(store, first)
	if err := recordTrustAdded(path, []string{second.SHA256}); err != nil {
		t.Fatal(err)
	}
	// ...and the add of the second failed.

	removed := uninstallFrom(t, path, &store)
	if len(removed) != 1 || removed[0] != first.SHA256 {
		t.Fatalf("the uninstall took %v; want only the certificate that went in", removed)
	}
	if len(store) != 1 || store[0].SHA256 != admin.SHA256 {
		t.Fatalf("store after the uninstall = %v; want the administrator's CA alone", store)
	}
}

// uninstallFrom runs the removal's own selection and verified removal against an in-memory store.
func uninstallFrom(t *testing.T, path string, store *[]parsedRoot) []string {
	t.Helper()
	ours, err := readOurRoots(path)
	if err != nil {
		t.Fatal(err)
	}
	if ours, err = onlyWhatProvisioningAdded(path, ours); err != nil {
		t.Fatal(err)
	}
	removed := []string{}
	err = removeRootsVerified(ours, func() ([]parsedRoot, error) { return append([]parsedRoot{}, *store...), nil },
		func(r parsedRoot) error {
			removed = append(removed, r.SHA256)
			kept := []parsedRoot{}
			for _, x := range *store {
				if x.SHA256 != r.SHA256 {
					kept = append(kept, x)
				}
			}
			*store = kept
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return removed
}

// memoryStore stands in for LocalMachine\Root: the same list and add installTrustAnchor gets on Windows.
type memoryStore struct {
	roots  []parsedRoot
	refuse map[string]bool // fingerprints whose add fails
	onAdd  func(parsedRoot)
}

func (m *memoryStore) list() ([]parsedRoot, error) { return append([]parsedRoot{}, m.roots...), nil }

func (m *memoryStore) add(der []byte) error {
	r, err := parseRoot(der)
	if err != nil {
		return err
	}
	if m.onAdd != nil {
		m.onAdd(r)
	}
	if m.refuse[r.SHA256] {
		return errors.New("refused by the store")
	}
	m.roots = append(m.roots, r)
	return nil
}

func (m *memoryStore) has(r parsedRoot) bool {
	for _, x := range m.roots {
		if x.SHA256 == r.SHA256 {
			return true
		}
	}
	return false
}

// The add was refused, the certificate was left in the record, and the administrator then
// trusted it by hand. The uninstall took it out — with a retry in between or without one.
func TestARefusedAddIsNotProvisioningsToTakeBack(t *testing.T) {
	for _, retry := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "step_up_portal_ca.pem")
		anchor := selfSigned(t, "Deployment Root CA")
		store := &memoryStore{refuse: map[string]bool{anchor.SHA256: true}}
		if err := captureOlderPackageTrust(path); err != nil {
			t.Fatal(err)
		}
		writeRootsPEM(t, path, anchor)
		if err := installTrustAnchor(path, "anchor", store.list, store.add); err == nil {
			t.Fatal("the refused add was not reported")
		}
		store.roots = append(store.roots, anchor) // the administrator trusts it by hand
		if retry {
			if err := installTrustAnchor(path, "anchor", store.list, store.add); err != nil {
				t.Fatal(err)
			}
		}
		if removed := uninstallFrom(t, path, &store.roots); len(removed) != 0 {
			t.Fatalf("retry=%v: the uninstall took out %v, which provisioning never added", retry, removed)
		}
	}
}

// And the certificate is in the record while its add is under way, so an add that never returns (the custom
// action ended inside it) still leaves a record that names it.
func TestACertificateIsRecordedWhileItIsAdded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interception-root.pem")
	root := selfSigned(t, "Interception Root")
	named := false
	store := &memoryStore{onAdd: func(r parsedRoot) {
		added, ok, _ := readTrustAddedRecord(path)
		named = ok && added[r.SHA256]
	}}
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	writeRootsPEM(t, path, root)
	if err := installTrustAnchor(path, "interception root", store.list, store.add); err != nil {
		t.Fatal(err)
	}
	if !named {
		t.Fatal("the certificate was added before the record named it")
	}
	if removed := uninstallFrom(t, path, &store.roots); len(removed) != 1 || removed[0] != root.SHA256 {
		t.Fatalf("the uninstall took %v; want the root provisioning added", removed)
	}
}

// One added, the next refused: the record keeps the first and not the second.
func TestAPartlyRefusedInstallRecordsWhatWentIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interception-root.pem")
	admin, first, second := selfSigned(t, "Administrator CA"), selfSigned(t, "Added First"), selfSigned(t, "Added Second")
	store := &memoryStore{roots: []parsedRoot{admin}, refuse: map[string]bool{second.SHA256: true}}
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	writeRootsPEM(t, path, admin, first, second)
	if err := installTrustAnchor(path, "interception root", store.list, store.add); err == nil {
		t.Fatal("the refused add was not reported")
	}
	added, _, _ := readTrustAddedRecord(path)
	if !added[first.SHA256] || added[second.SHA256] || added[admin.SHA256] {
		t.Fatalf("record = %v; want the first only", added)
	}
	store.roots = append(store.roots, second) // trusted later by other means
	if removed := uninstallFrom(t, path, &store.roots); len(removed) != 1 || removed[0] != first.SHA256 {
		t.Fatalf("the uninstall took %v; want only the certificate that went in", removed)
	}
}

// A certificate an earlier provisioning added, since removed from the store by someone, whose re-add is refused:
// it was provisioning's before this attempt and stays in the record.
func TestARefusedReaddKeepsWhatWasProvisioningsBefore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interception-root.pem")
	root := selfSigned(t, "Interception Root")
	writeRootsPEM(t, path, root)
	if err := recordTrustAdded(path, []string{root.SHA256}); err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{refuse: map[string]bool{root.SHA256: true}}
	if err := installTrustAnchor(path, "interception root", store.list, store.add); err == nil {
		t.Fatal("the refused add was not reported")
	}
	if added, _, _ := readTrustAddedRecord(path); !added[root.SHA256] {
		t.Fatal("a certificate provisioning had added before was dropped from the record")
	}
}

// An upgrade from a package that kept no record: the root it trusted is found in the store and recorded as
// provisioning's, through the code that ships.
func TestAnUpgradeInheritsThroughTheInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interception-root.pem")
	old := selfSigned(t, "Old Interception Root")
	writeRootsPEM(t, path, old)
	store := &memoryStore{roots: []parsedRoot{old}}
	if err := captureOlderPackageTrust(path); err != nil {
		t.Fatal(err)
	}
	if err := installTrustAnchor(path, "interception root", store.list, store.add); err != nil {
		t.Fatal(err)
	}
	if removed := uninstallFrom(t, path, &store.roots); len(removed) != 1 || removed[0] != old.SHA256 {
		t.Fatalf("the uninstall took %v; want the root the older package trusted", removed)
	}
	if _, err := os.Stat(olderPackageTrustPath(path)); !os.IsNotExist(err) {
		t.Fatalf("the note outlived the record: %v", err)
	}
}
