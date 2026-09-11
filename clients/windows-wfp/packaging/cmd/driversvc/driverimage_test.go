package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileDigestChangesWithContentAndNotWithPath(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "dsse-wfp.sys")
	if err := os.WriteFile(a, []byte("driver-v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	d1, err := FileDigest(a)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	// ★ The upgrade case the old code could not see: SAME path, new bytes.
	if err := os.WriteFile(a, []byte("driver-v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	d2, err := FileDigest(a)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if d1 == d2 {
		t.Fatal("the digest must change when the bytes change at the same path — that is the whole point")
	}
	if _, err := FileDigest(filepath.Join(dir, "absent.sys")); err == nil {
		t.Fatal("a missing .sys must be an error, never an empty digest that compares equal to another failure")
	}
}

// The old name (sameDriverImage) read as "same image" while comparing only paths, and it was used as though
// it meant the former. The rename is part of the fix; these are the path semantics it legitimately has.
func TestSameDriverImagePathIsAboutPathsOnly(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{`\??\C:\Program Files\DSSE\dsse-wfp.sys`, `C:\Program Files\DSSE\dsse-wfp.sys`, true},
		{`C:\PROGRAM FILES\DSSE\DSSE-WFP.SYS`, `C:\Program Files\DSSE\dsse-wfp.sys`, true},
		{`C:\Program Files\DSSE\.\dsse-wfp.sys`, `C:\Program Files\DSSE\dsse-wfp.sys`, true},
		{`C:\Program Files\DSSE\old.sys`, `C:\Program Files\DSSE\dsse-wfp.sys`, false},
	} {
		if got := SameDriverImagePath(tc.a, tc.b); got != tc.want {
			t.Errorf("SameDriverImagePath(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestPendingRebootStatus(t *testing.T) {
	note := PendingReboot{Digest: "aaaa", SetAtBootID: 100}

	// Same boot: nothing has had a chance to load it.
	if pending, _ := PendingRebootStatus(note, 100, "aaaa"); !pending {
		t.Fatal("within the same boot the note must stand")
	}
	// Rebooted, and the on-disk image is still the one that was pending: the kernel loaded it at boot.
	pending, why := PendingRebootStatus(note, 101, "aaaa")
	if pending {
		t.Fatalf("after a reboot the pending image is loaded; note must clear (%s)", why)
	}
	if !strings.Contains(why, "rebooted") {
		t.Fatalf("the reason must say why it cleared, got %q", why)
	}
	// Rebooted, but the file changed AGAIN since. Nothing can be concluded, so the note must NOT clear —
	// clearing would under-report a driver that really is stale, and that direction is the unsafe one.
	pending, why = PendingRebootStatus(note, 101, "bbbb")
	if !pending {
		t.Fatal("a changed on-disk image after a reboot is unresolved, not resolved")
	}
	if !strings.Contains(why, "cannot be determined") {
		t.Fatalf("the reason must admit the uncertainty, got %q", why)
	}
	// No note at all.
	if pending, _ := PendingRebootStatus(PendingReboot{}, 101, "aaaa"); pending {
		t.Fatal("no note means nothing pending")
	}
	// A note with no boot id (written by an older build) must stand rather than silently clear.
	if pending, _ := PendingRebootStatus(PendingReboot{Digest: "aaaa"}, 101, "aaaa"); !pending {
		t.Fatal("a note without a boot id must be kept, not assumed resolved")
	}
}

// ★ The sentence that was wrong. "installed + started" was printed for a box whose kernel still held the
// previous driver; anything reading as success must mean the new code is running.
func TestTheOutcomeSentenceDistinguishesLoadedFromPending(t *testing.T) {
	digest := strings.Repeat("a", 64)

	fresh := DescribeInstallOutcome("DsseWfp", digest, false, nil)
	if !strings.Contains(fresh, "installed + started") {
		t.Fatalf("a clean install should read as one: %q", fresh)
	}

	reloaded := DescribeInstallOutcome("DsseWfp", digest, true, nil)
	if !strings.Contains(reloaded, "reloaded") || !strings.Contains(reloaded, "kernel is running") {
		t.Fatalf("a replacement must say the previous image was unloaded: %q", reloaded)
	}

	stale := DescribeInstallOutcome("DsseWfp", digest, true, &PendingReboot{Digest: digest})
	if strings.Contains(stale, "installed + started") {
		t.Fatalf("a pending reboot must NOT read as a successful install: %q", stale)
	}
	for _, must := range []string{"REBOOT REQUIRED", "NOT in effect"} {
		if !strings.Contains(stale, must) {
			t.Errorf("the pending sentence must contain %q, got %q", must, stale)
		}
	}
}
