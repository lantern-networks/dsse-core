package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// driverimage.go — telling "the driver service points at the right file" apart from "the right code is
// running".
//
// THE DEFECT THIS EXISTS FOR. doInstall used to decide idempotence from the .sys PATH alone: if a service by
// this name already pointed at the same path, it just (re)started it and reported "installed + started",
// exit 0. Across an upgrade the path never changes — it is always
// C:\Program Files\DSSE\dsse-wfp.sys — so the new bytes were laid down on disk and the OLD image stayed
// loaded in the kernel, while the installer, the InstalledVersion marker and the user-mode agent all said the
// upgrade had succeeded. A security fix to the callout could ship to a whole fleet and take effect on none of
// it, silently. The existing comment in doInstall reasoned about a service pointing at a DIFFERENT image; the
// ordinary upgrade case, same path with new content, was the one it did not cover.
//
// WHY THERE IS NO "IS THE LOADED IMAGE THE SAME AS THE FILE" CHECK. There cannot be. Once a kernel driver is
// loaded its image lives in kernel memory; nothing in user mode can hash what is actually running. So the
// honest options are to REPLACE unconditionally, or to track what was loaded in persistent state and reason
// about it. This file takes the first for the decision and the second only for REPORTING, because the reason
// this code needs fixing at all is that it optimised a decision it could not actually make.
//
// Nothing here touches Windows APIs, so the reasoning is tested on any host — which matters, because the
// plumbing around it cannot be.

// pendingImageValueName / pendingBootValueName are where a not-yet-loaded image is recorded, under the
// driver service's own Parameters key.
const (
	pendingImageValueName = "PendingImageSHA256"
	pendingBootValueName  = "PendingSetAtBootUnix"
)

// FileDigest returns the lowercase hex SHA-256 of a file. Used to say WHICH image was laid down and which one
// is waiting for a reboot — never to decide whether a reload is needed, since the loaded image cannot be
// hashed.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SameDriverImagePath reports whether a service's stored ImagePath refers to the same FILE as want. It is
// tolerant of the \??\ NT prefix SCM adds for drivers and of Windows' case-insensitive paths.
//
// Renamed from sameDriverImage on purpose. The old name read as "same image" and was used as though it meant
// it; it only ever compared paths, and the gap between those two readings is the entire defect. A name that
// overstates what a function checks is how a wrong check survives review.
// It deliberately does NOT use filepath.Clean. These are always Windows paths, and filepath is host-dependent:
// on the Linux CI runner and on this Mac it treats a backslash as an ordinary character, so `..\.\x.sys` is
// left untouched while Windows would collapse it. A comparison that behaves one way where it is tested and
// another way where it runs is not tested at all. Separators are normalised explicitly and path.Clean (the
// slash-only one) does the rest, so the answer is the same everywhere.
func SameDriverImagePath(current, want string) bool {
	norm := func(p string) string {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, `\??\`)
		p = strings.ReplaceAll(p, `\`, "/")
		return strings.ToLower(path.Clean(p))
	}
	return norm(current) == norm(want)
}

// PendingReboot describes an image that is on disk but not in the kernel: the driver could not be stopped, so
// the bytes were replaced while the old code kept running.
type PendingReboot struct {
	Digest      string // the on-disk image waiting to be loaded
	SetAtBootID int64  // the boot this was recorded during
}

// PendingRebootStatus decides what a recorded pending-reboot note means NOW.
//
// The note is written when a driver cannot be swapped live. If the machine has since rebooted, the kernel
// loaded whatever was on disk at boot — which is the pending image — so the note is spent and must stop being
// reported. Keeping it would produce a permanent "reboot required" that operators learn to ignore, and an
// alert nobody believes is worse than no alert.
//
// Being wrong here is cosmetic in one direction only: a note left too long over-reports, while clearing it
// early would under-report a driver that really is stale. So it is cleared only when the boot id has actually
// changed AND the on-disk image still matches what was pending — if the file changed again in the meantime,
// nothing can be concluded and the note stands.
func PendingRebootStatus(note PendingReboot, currentBootID int64, onDiskDigest string) (stillPending bool, reason string) {
	if note.Digest == "" {
		return false, ""
	}
	if note.SetAtBootID != 0 && currentBootID != 0 && currentBootID != note.SetAtBootID {
		if onDiskDigest != "" && onDiskDigest == note.Digest {
			return false, "the machine has rebooted since; the pending image is the one the kernel loaded at boot"
		}
		return true, "the machine has rebooted, but the .sys on disk is no longer the image that was pending — " +
			"what is loaded cannot be determined from here"
	}
	return true, "the driver could not be swapped live and the machine has not rebooted since"
}

// DescribeInstallOutcome is the line driversvc prints when it finishes, and it is deliberately not the same
// sentence in both cases.
//
// The bug being fixed printed "installed + started" for a box whose kernel was still running the previous
// driver. Anything that reads like success has to mean the new code is running; anything else has to say what
// is actually true, and say it in a way that survives being skimmed.
func DescribeInstallOutcome(name, digest string, reloaded bool, pending *PendingReboot) string {
	short := digest
	if len(short) > 12 {
		short = short[:12]
	}
	if pending != nil {
		p := pending.Digest
		if len(p) > 12 {
			p = p[:12]
		}
		return fmt.Sprintf("driversvc: %s REBOOT REQUIRED — the new driver image (sha256:%s…) is on disk but the "+
			"running kernel still has the previous one; it could not be unloaded. The update is NOT in effect "+
			"until this machine restarts.", name, p)
	}
	if reloaded {
		return fmt.Sprintf("driversvc: %s reloaded and started with image sha256:%s… (the previous image was "+
			"unloaded first, so this build is what the kernel is running)", name, short)
	}
	return fmt.Sprintf("driversvc: %s installed + started with image sha256:%s…", name, short)
}
