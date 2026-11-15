package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Upgrade A had no archive alert publisher. Adding its configured webhook while
// upgrading generates a real new entrypoint. A resumed rollback must retain the
// mode captured at the start of this attempt, not look it up in A's older backup.
func TestAResumedPutBackKeepsANewEntrypointExecutable(t *testing.T) {
	dir := t.TempDir()
	var setup bytes.Buffer
	if err := captureProcessStdout(&setup, func() error {
		installFromPlan(t, "../../docs/plans/single-region.json", dir)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(dir, "start-archive-alert-publisher.sh")
	// An installation predating this optional publisher has no such script. It
	// is not mounted by this fixture's old Compose file, so removing only this
	// unused file represents that older generated state without breaking A.
	oldCompose, err := os.ReadFile(filepath.Join(dir, composeFileName()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(oldCompose, []byte("start-archive-alert-publisher.sh")) {
		t.Fatal("old fixture already uses the publisher")
	}
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "deployment.env"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(f, "\nDSSE_ARCHIVE_WEBHOOK_URL='https://alerts.example.test/dsse'\n")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	in := upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}
	for attempt, rec := range []*recordedUpgrade{{failUp: true}, {failPull: true}} {
		deps := rec.deps("")
		deps.derived = upgradeDerivedFiles
		var out, errOut bytes.Buffer
		if code := runUpgrade(in, deps, &out, &errOut); code == 0 {
			t.Fatalf("failure not injected on attempt %d", attempt+1)
		}
		info, err := os.Stat(entry)
		if err != nil {
			t.Fatal(err)
		}
		marker, exists := readUpgradeUnfinished(dir)
		t.Logf("attempt=%d entry mode=%#o unfinished=%t kept=%s", attempt+1, info.Mode().Perm(), exists, marker.Kept)
		if attempt == 0 && info.Mode().Perm()&0111 == 0 {
			t.Fatal("first upgrade did not create an executable entrypoint")
		}
		if attempt == 1 && info.Mode().Perm()&0111 == 0 {
			t.Error("resumed pull rollback stripped execute permission from the new entrypoint")
		}
	}
	if err := captureProcessStdout(&setup, func() error { return upgradeDerivedFiles(dir) }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(entry)
	if err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(filepath.Join(dir, composeFileName()))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("after another real regeneration: mode=%#o used as entrypoint=%t", info.Mode().Perm(), bytes.Contains(compose, []byte(`entrypoint: ["/deployment/start-archive-alert-publisher.sh"]`)))
	if info.Mode().Perm()&0111 == 0 {
		// The missing execute bits prevent the kernel from starting the script,
		// so none of its configuration/service behavior can run here.
		execErr := exec.Command(entry).Run()
		t.Logf("direct entrypoint exec: %v", execErr)
		if !errors.Is(execErr, os.ErrPermission) {
			t.Fatalf("expected kernel permission denial, got %v", execErr)
		}
		t.Error("normal regeneration leaves the entrypoint non-executable, so the next Compose start cannot execute it")
	}
}
