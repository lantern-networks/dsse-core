//go:build windows

package durablefile

import (
	"os"
	"path/filepath"
	"testing"
)

// This platform has no permission bits, so the Unix assertion could not hold here: Go reports every writable
// file as 0666, and `Write(p, x, 0o600)` produced -rw-rw-rw- on win-dev-1. What Windows DOES have is a single
// read-only attribute, which Go sets from `perm&0200 == 0` — so that is what is pinned.
func TestTheReadOnlyAttributeIsInForceTheMomentTheFileAppears(t *testing.T) {
	p := filepath.Join(t.TempDir(), "frozen.json")
	if err := Write(p, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o200 != 0 {
		t.Fatalf("mode is %v: the read-only attribute was not in force when the file appeared", st.Mode().Perm())
	}

	// And an ordinary mode leaves the file writable. Asserting the exact bits would fail on this platform for
	// a reason that says nothing about this package.
	q := filepath.Join(filepath.Dir(p), "normal.json")
	if err := Write(q, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(q)
	if st.Mode().Perm()&0o200 == 0 {
		t.Fatalf("mode is %v: a writable mode produced a read-only file", st.Mode().Perm())
	}
}

// ★ THE REGRESSION THIS EXISTS FOR (2026-08-13, measured here before it was fixed). MoveFileEx will not
// replace a file carrying FILE_ATTRIBUTE_READONLY, so a store written with a read-only mode took its first
// value and then failed EVERY update, forever, on Windows only:
//
//	durablefile: durably replace "...\b.json": Access is denied.
//
// On Unix the identical sequence succeeds, because rename depends on the directory's permissions rather than
// the file's. A shared durable write whose second call fails on one platform is not one durable write, so
// durableReplace clears the attribute first — and this test is what stops it coming back.
func TestAReadOnlyFileCanStillBeReplaced(t *testing.T) {
	p := filepath.Join(t.TempDir(), "floor.json")
	if err := Write(p, []byte("first"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte("second"), 0o444); err != nil {
		t.Fatalf("the second write failed (%v) — a read-only mode made this file write-once, which on a signing "+
			"floor means the value can never rise again", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("the replacement did not land: %q", got)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm()&0o200 != 0 {
		t.Fatalf("mode is %v: clearing the attribute to replace the file must not leave it writable afterwards",
			st.Mode().Perm())
	}
}

// ★ A FAILED WRITE MUST NOT LEAVE THE FILE WRITABLE (2026-08-13, mac side, after the write-once fix landed).
//
// The fix clears FILE_ATTRIBUTE_READONLY so the replacement can happen. That clear is a means to an end, and
// when the end does not happen it has to be undone — otherwise a caller who asked for a read-only file, and was
// told the write FAILED, is left holding a writable one. A failure that quietly relaxes a protection is worse
// than a failure, because nothing about the error mentions it.
//
// The failure is injected through the moveFileEx seam: the interesting branch only happens when the OS says no,
// which a test cannot otherwise arrange without leaving a locked handle behind.
func TestAFailedReplaceRestoresTheReadOnlyAttribute(t *testing.T) {
	p := filepath.Join(t.TempDir(), "frozen.json")
	if err := Write(p, []byte("first"), 0o444); err != nil {
		t.Fatal(err)
	}

	original := moveFileEx
	moveFileEx = func(from, to *uint16, flags uint32) error { return os.ErrPermission }
	defer func() { moveFileEx = original }()

	if err := Write(p, []byte("second"), 0o444); err == nil {
		t.Fatal("the injected failure was reported as success")
	}

	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o200 != 0 {
		t.Fatalf("mode is %v: the failed replacement left the file WRITABLE, so a write that changed nothing "+
			"still weakened it", st.Mode().Perm())
	}
	// And the contents are the ones that were there before the failed write.
	got, _ := os.ReadFile(p)
	if string(got) != "first" {
		t.Fatalf("the failed write changed the contents to %q", got)
	}
}
