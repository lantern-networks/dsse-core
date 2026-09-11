//go:build windows

package rollbackstore

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// These controls cover unsafe owners and access rights. The previous check looked at two control bits and never at an
// owner or a single ACE, so a protected DACL granting Everyone full control read as "protected" — a test that
// passes on the worst case it is meant to catch. Each case here must REFUSE, and for its own reason.
//
// icacls is used to set the ACLs rather than composing security descriptors in Go: the point is to prove the
// check refuses what a real machine can actually be put into, and icacls is how an administrator (or an
// attacker with a shell) would put it there.

func icacls(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("icacls", args...).CombinedOutput()
	if err != nil {
		t.Skipf("icacls %v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
}

// protectedDir makes a directory whose DACL is protected and SYSTEM/Administrators-only, which is what
// createProtected produces in production.
func protectedDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(testStoreRoot(t), "store")
	if _, err := createProtected(dir); err != nil {
		t.Fatalf("create the protected store: %v", err)
	}
	// createProtected sets the DACL; the OWNER of a directory made by a normal test process is that user, and
	// an owner holds WRITE_DAC implicitly. Production creates this as SYSTEM or an elevated installer, so the
	// owner is administrative there. Hand ownership over so the positive control tests the DACL rather than
	// the identity of whoever ran `go test`.
	icacls(t, dir, "/setowner", "*S-1-5-32-544")
	return dir
}

func TestAProperlyProtectedStoreIsAccepted(t *testing.T) {
	dir := protectedDir(t)
	if err := verifyStore(dir); err != nil {
		t.Fatalf("a SYSTEM/Administrators-only store should be accepted: %v", err)
	}
}

func TestAStoreEveryoneCanWriteIsRefused(t *testing.T) {
	dir := protectedDir(t)
	icacls(t, dir, "/grant", "*S-1-1-0:(F)") // Everyone: Full

	err := verifyStore(dir)
	if err == nil {
		t.Fatal("a store granting Everyone full control must be refused")
	}
	if !strings.Contains(err.Error(), "grants write access") {
		t.Fatalf("the refusal must name the principal: %v", err)
	}
}

// TestAStoreUsersCanDeleteChildrenFromIsRefused is the hole a file-by-file ACL cannot close: FILE_DELETE_CHILD
// on the directory lets a holder replace a package whose own ACL is perfect.
func TestAStoreUsersCanDeleteChildrenFromIsRefused(t *testing.T) {
	dir := protectedDir(t)
	icacls(t, dir, "/grant", "*S-1-5-32-545:(DC)") // Users: delete child

	if err := verifyStore(dir); err == nil {
		t.Fatal("a store whose children Users may delete must be refused")
	}
}

func TestAStoreOwnedByAStandardUserIsRefused(t *testing.T) {
	dir := protectedDir(t)
	// os/user reports the SID as Uid on Windows, which is what icacls wants. Shelling out to whoami made this
	// control SKIP rather than run, and a negative control that does not run is not a control.
	me, err := user.Current()
	if err != nil {
		t.Skipf("current user: %v", err)
	}
	icacls(t, dir, "/setowner", "*"+me.Uid)

	err = verifyStore(dir)
	if err == nil {
		t.Fatal("a store owned by a standard user must be refused — an owner can rewrite the DACL")
	}
	if !strings.Contains(err.Error(), "is owned by") {
		t.Fatalf("the refusal must name the owner: %v", err)
	}
}

// TestAWritablePackageInAProtectedStoreIsRefused is the case a directory-only check misses entirely.
func TestAWritablePackageInAProtectedStoreIsRefused(t *testing.T) {
	dir := protectedDir(t)
	pkg := filepath.Join(dir, "dsse-agent-0.1.0.msi")
	if err := os.WriteFile(pkg, []byte("not really an msi"), 0o644); err != nil {
		t.Fatalf("write the package: %v", err)
	}
	// In production the installer writes this as SYSTEM, so the owner is administrative. A test process owns
	// what it creates, so hand it over — otherwise this asserts who ran `go test` rather than the ACL.
	icacls(t, pkg, "/setowner", "*S-1-5-32-544")
	if err := VerifyStoreAndPackage(dir, pkg); err != nil {
		t.Fatalf("a package inheriting the protected store's ACL should be accepted: %v", err)
	}

	icacls(t, pkg, "/grant", "*S-1-5-32-545:(F)") // Users: Full, on the package alone

	err := VerifyStoreAndPackage(dir, pkg)
	if err == nil {
		t.Fatal("a package a standard user can rewrite must be refused even inside a protected store")
	}
	if !strings.Contains(err.Error(), "stored package is not protected") {
		t.Fatalf("the refusal must say it is the package: %v", err)
	}
}

// TestAReparsePointIsRefused covers the substitution that can be made between the check and the launch.
func TestAReparsePointIsRefused(t *testing.T) {
	base := testStoreRoot(t)
	real := filepath.Join(base, "real")
	if _, err := createProtected(real); err != nil {
		t.Fatalf("create: %v", err)
	}
	link := filepath.Join(base, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
		t.Skipf("mklink: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	if err := VerifyStoreAndPackage(link, ""); err == nil {
		t.Fatal("a junction must be refused: the name checked and the bytes installed need not be the same object")
	} else if !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("the refusal must name the reason: %v", err)
	}
}

// TestAnUnreadableACLIsRefused makes sure an answer that cannot be established refuses rather than passes.
func TestAnUnreadableACLIsRefused(t *testing.T) {
	if err := verifyStore(filepath.Join(testStoreRoot(t), "does-not-exist")); err == nil {
		t.Fatal("a path whose security cannot be read must be refused, not accepted")
	}
}

// ★ THESE CALL Stash ITSELF. Proving verifyStore refuses in isolation is
// not proving the STORE PATH refuses: the content-idempotent early return, the stale-marker removal and the
// copy each reported success without ever reaching the check when it sat further down.

func stashFixture(t *testing.T) (store *Store, src string) {
	t.Helper()
	root := filepath.Join(testStoreRoot(t), "store")
	src = filepath.Join(testStoreRoot(t), "candidate.msi")
	if err := os.WriteFile(src, []byte("installer bytes"), 0o644); err != nil {
		t.Fatalf("write the source: %v", err)
	}
	return New(root), src
}

func TestStashSucceedsIntoAProtectedStore(t *testing.T) {
	s, src := stashFixture(t)
	if _, err := s.Stash(src, "0.1.0"); err != nil {
		t.Fatalf("a store this process creates protected should accept a package: %v", err)
	}
	// And again with identical bytes — the content-idempotent path.
	if _, err := s.Stash(src, "0.1.0"); err != nil {
		t.Fatalf("re-stashing identical bytes should succeed: %v", err)
	}
}

// TestStashRefusesWhenTheStoreIsOpenedAfterwards is the early-return bypass: the package is already there with
// identical content, so the old code returned success without looking at the ACL at all.
func TestStashRefusesWhenTheStoreIsOpenedAfterwards(t *testing.T) {
	s, src := stashFixture(t)
	if _, err := s.Stash(src, "0.1.0"); err != nil {
		t.Fatalf("first stash: %v", err)
	}
	icacls(t, s.Root(), "/grant", "*S-1-1-0:(OI)(CI)F") // Everyone: Full

	if _, err := s.Stash(src, "0.1.0"); err == nil {
		t.Fatal("re-stashing IDENTICAL bytes into a now-open store must be refused, not returned early")
	}
}

// TestStashRefusesAParentThatCanBeSubstituted is point 3 from the store side: the store's own DACL is perfect
// and the directory above it can be deleted and replaced by a standard user.
func TestStashRefusesAParentThatCanBeSubstituted(t *testing.T) {
	parent := testStoreRoot(t)
	s := New(filepath.Join(parent, "store"))
	src := filepath.Join(parent, "candidate.msi")
	if err := os.WriteFile(src, []byte("installer bytes"), 0o644); err != nil {
		t.Fatalf("write the source: %v", err)
	}
	icacls(t, parent, "/grant", "*S-1-5-32-545:(OI)(CI)(DC)") // Users: delete child, on the PARENT

	if _, err := s.Stash(src, "0.1.0"); err == nil {
		t.Fatal("a store whose parent lets a standard user delete it must be refused")
	} else if !strings.Contains(err.Error(), "ancestor") {
		t.Fatalf("the refusal must name the ancestry: %v", err)
	}
}

// TestStashRefusesAJunction covers the substitution made by pointing the store name somewhere else.
func TestStashRefusesAJunction(t *testing.T) {
	base := testStoreRoot(t)
	real := filepath.Join(base, "real")
	if _, err := createProtected(real); err != nil {
		t.Fatalf("create: %v", err)
	}
	link := filepath.Join(base, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
		t.Skipf("mklink: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	src := filepath.Join(base, "candidate.msi")
	if err := os.WriteFile(src, []byte("installer bytes"), 0o644); err != nil {
		t.Fatalf("write the source: %v", err)
	}

	if _, err := New(link).Stash(src, "0.1.0"); err == nil {
		t.Fatal("stashing through a junction must be refused")
	} else if !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("the refusal must name the reason: %v", err)
	}
}

// A directory check alone cannot authorize reuse of a child with an explicit writable ACL.
func TestStashRefusesWritableIdenticalPackage(t *testing.T) {
	base := testStoreRoot(t)
	src := filepath.Join(base, "source.msi")
	if err := os.WriteFile(src, []byte("same installer bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(filepath.Join(base, "store"))
	pkg, err := store.Stash(src, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	icacls(t, pkg, "/grant", "*S-1-5-32-545:(F)")
	if _, err := store.Stash(src, "0.1.0"); err == nil {
		t.Fatal("identical bytes must not authorize reuse of a writable package")
	} else if !strings.Contains(err.Error(), "stored package is not protected") {
		t.Fatal(err)
	}
}

// A fresh default installation has no DSSE parent yet; preparation must precede ancestry verification.
func TestStashCreatesMissingDefaultParent(t *testing.T) {
	base := testStoreRoot(t)
	t.Setenv("ProgramData", base)
	src := filepath.Join(base, "source.msi")
	if err := os.WriteFile(src, []byte("installer bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(DefaultRoot())
	pkg, err := store.Stash(src, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStoreAndPackage(store.Root(), pkg); err != nil {
		t.Fatal(err)
	}
}
