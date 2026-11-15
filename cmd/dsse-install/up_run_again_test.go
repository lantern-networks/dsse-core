package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The actual CP's /leader checks its three voters, and the admin doorway
// routes only to a /leader=200 backend. Closing the bootstrap marker seals
// the founder-only exception. Model that public readiness contract here;
// the store promotions below are the only operations that can restore it.
func TestUpJoinsThreeVotersBeforeWaitingForAControlPlaneTheClosedBootstrapFences(t *testing.T) {
	for _, name := range []string{"one-region-three-independent-entries.json", "three-regions-multi-edge.json"} {
		t.Run(name, func(t *testing.T) {
			plan := samplePlans(t)[name]
			if plan == nil || !threeVoterProfile(plan.Profile) {
				t.Fatal("missing three-voter sample")
			}
			dir := t.TempDir()
			steps, err := upSteps(plan, dir, dir+".plan.json", "Example", "admin@example.test")
			if err != nil {
				t.Fatal(err)
			}
			closed, promotions, healthCalls := false, 0, 0
			r := upRunner{
				run: func(_ context.Context, _, shell string, _ io.Writer) error {
					if strings.Contains(shell, "-bootstrap-admin") {
						closed = true
					}
					if strings.Contains(shell, " member promote ") {
						promotions++
					}
					return nil
				},
				waitCP: func(context.Context, string, string) error {
					healthCalls++
					if closed && promotions != 2 {
						return errors.New("CP /leader is unavailable until all three planned voters join")
					}
					return nil
				},
				confirm: func(string) bool { return true },
				sleep:   func(context.Context, time.Duration) {},
				exists:  func(string) bool { return false },
			}
			var log, out bytes.Buffer
			stopped, err := executeUp(context.Background(), steps, upInput{SSH: true}, dir, dir, "", loadUpProgress(filepath.Join(dir, "progress.json")), r, &log, &out)
			if err != nil {
				t.Fatalf("-up stopped at step %d before store joins; promotions=%d health calls=%d: %v\n%s", stopped+1, promotions, healthCalls, err, out.String())
			}
		})
	}
}

// bootstrap.go explicitly prints the once-only credentials before attempting
// to save the operator token. A save/sync failure returns an error with the
// marker already present and says to retain the captured output. Repeat that
// documented boundary through executeUp's real file capture implementation.
func TestUpKeepsWhatAFailedFirstAdministratorStepPrintedWhenRunAgain(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "runtime"), 0700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(dir, "admin-credentials.txt")
	st := upStep{Kind: upFirstAdmin, Machine: "node-a", Shell: "dsse-install -bootstrap-admin -control-plane https://admin.example.test", Capture: capture}
	const onceOnly = "password generated-password\nsecond factor secret-totp\nrecovery codes code-a code-b\napi token recovery-api-token\n"
	runs := 0
	r := upRunner{
		run: func(_ context.Context, _, _ string, out io.Writer) error {
			runs++
			if runs == 1 {
				if err := os.WriteFile(runtimePath(dir, adminBootstrappedMarker), []byte("closed"), 0600); err != nil {
					return err
				}
				fmt.Fprint(out, onceOnly)
				return errors.New("administrator exists but operator token file could not be saved; retain the captured credentials")
			}
			// This uses the production bootstrap entry point. Its closed marker
			// refusal happens before any network operation or credential output.
			err := runBootstrapAdminWithTokenFile(dir, "https://admin.example.test", "admin@example.test", "", "")
			fmt.Fprintln(out, err)
			return err
		},
		waitCP: func(context.Context, string, string) error { return nil },
		exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
		sleep:  func(context.Context, time.Duration) {},
	}
	var log, out bytes.Buffer
	progress := filepath.Join(dir, "progress.json")
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(progress), r, &log, &out); err == nil {
			t.Fatal("expected partial-bootstrap failure")
		}
	}
	got, err := os.ReadFile(capture + ".pending")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), onceOnly) {
		t.Fatalf("retry destroyed once-only credentials; pending capture now contains only: %s", got)
	}
}

// Reproduce a real partial mint using the same local filesystem failure as
// partial_install_test.go. The normal installer deliberately refuses to
// pretend that the presence of one certificate makes this complete.
func TestUpDoesNotCallAMintCompleteBecauseItsAnchorExists(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "schemas")
	if err := os.WriteFile(blocker, []byte("block schemas directory"), 0600); err != nil {
		t.Fatal(err)
	}
	st := upStep{Kind: upMint, Machine: "node-a", Shell: "dsse-install -plan plan.json -organization Example"}
	r := upRunner{
		run: func(context.Context, string, string, io.Writer) error {
			return run(dir, "dsse.example.test", "Example", 1, false)
		},
		exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
	}
	progress := filepath.Join(t.TempDir(), "progress.json")
	var log, out bytes.Buffer
	if _, err := executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(progress), r, &log, &out); err == nil {
		t.Fatal("initial local mint must fail")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "deployment.env")); !os.IsNotExist(err) {
		t.Fatalf("expected missing deployment.env in real partial mint, got %v", err)
	}
	_, err := executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(progress), r, &log, &out)
	if err == nil && loadUpProgress(progress).done(0, st) {
		t.Fatal("-up marked the failed mint complete on retry even though deployment.env does not exist; the next step starts this incomplete directory")
	}
}

// The first step creates the authorities and then applies the plan to this machine. Stopped between the two,
// the directory holds every file a created deployment has, and none of what the plan decides.
func TestUpAppliesThePlanAgainWhenTheFirstStepStoppedBeforeApplyingIt(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example.test", "Example", 1, false); err != nil {
		t.Fatal(err)
	}
	real := upRunner{exists: func(p string) bool { _, err := os.Stat(p); return err == nil }}
	for _, name := range []string{agentPolicySigningKeyFile, "deployment.env", composeFileName()} {
		if !real.exists(filepath.Join(dir, name)) {
			t.Fatalf("the created deployment has no %s — this test would prove nothing", name)
		}
	}
	st := upStep{Kind: upMint, Machine: "node-a", Shell: "dsse-install -plan plan.json -organization Example"}
	ran := 0
	r := upRunner{
		run: func(context.Context, string, string, io.Writer) error {
			ran++
			return os.WriteFile(filepath.Join(dir, installPlanFile), []byte("{}\n"), 0o600)
		},
		exists: real.exists,
	}
	progress := filepath.Join(t.TempDir(), "progress.json")
	var log, out bytes.Buffer
	if _, err := executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(progress), r, &log, &out); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Fatalf("the first step ran %d time(s) on a deployment the plan was never applied to, want 1", ran)
	}
	// And once the plan is saved, the step is not run again.
	if _, err := executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(filepath.Join(t.TempDir(), "p.json")), r, &log, &out); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Fatalf("the first step ran again (%d) on a finished directory", ran)
	}
}

// Review finding (2026-11-14): the last store member was given its vote, the wait for the control plane after
// it timed out, and nothing remembered the vote. Run again, the step promoted a member that was no longer a
// learner — which the store refuses — sixty-one times, and never got past it.
func TestUpDoesNotGiveAStoreMemberItsVoteTwiceWhenOnlyTheWaitFailed(t *testing.T) {
	dir := t.TempDir()
	st := upStep{Machine: "node-a", Shell: "etcdctl member promote 1234", AfterRemote: true, CPAnswersNow: true}
	promoted, cpUp := 0, false
	r := upRunner{
		run: func(context.Context, string, string, io.Writer) error {
			promoted++
			if promoted > 1 {
				return errors.New("etcdserver: can only promote a learner member")
			}
			return nil
		},
		waitCP: func(context.Context, string, string) error {
			if !cpUp {
				return errors.New("the control plane did not answer in time")
			}
			return nil
		},
		sleep:  func(context.Context, time.Duration) {},
		exists: func(string) bool { return true },
	}
	progress := filepath.Join(dir, "progress.json")
	var log, out bytes.Buffer
	if _, err := executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(progress), r, &log, &out); err == nil {
		t.Fatal("the wait failed and the step was reported done")
	}
	if loadUpProgress(progress).done(0, st) {
		t.Fatal("a step whose wait failed is recorded as finished")
	}
	cpUp = true // the operator restored the control plane's reachability
	if _, err := executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(progress), r, &log, &out); err != nil {
		t.Fatalf("run again after the control plane answers: %v (the member was promoted %d times)", err, promoted)
	}
	if promoted != 1 {
		t.Fatalf("the member was given its vote %d times, want once", promoted)
	}
	if !loadUpProgress(progress).done(0, st) {
		t.Fatal("the step is not recorded as finished after its wait succeeded")
	}
}

// Review finding (2026-11-14): the three-Region order's command changes into the deployment's directory before
// it starts the services, and the removal appended to it looked for the package there. It removed nothing and
// succeeded; the archive with the machine's identity and the fleet credential stayed where scp had put it.
func TestThePackageIsRemovedWhereItWasCopiedWhateverTheCommandDoes(t *testing.T) {
	login := t.TempDir() // the directory an SSH session starts in, where scp puts the package
	pkg := filepath.Join(login, "node-b.tar.gz")
	if err := os.WriteFile(pkg, []byte("identity and credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	deployment := filepath.Join(login, "opt", "dsse", "region-b")
	command := "mkdir -p " + shellQuote(deployment) + " && cd " + shellQuote(deployment) + " && true"
	cmd := exec.Command("/bin/sh", "-c", remoteCommandThatRemovesItsPackage(command, "node-b.tar.gz"))
	cmd.Dir = login
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if _, err := os.Stat(pkg); !os.IsNotExist(err) {
		t.Fatal("the package is still where it was copied")
	}
	// A command that fails leaves the package: the machine has not started from it yet.
	if err := os.WriteFile(pkg, []byte("identity and credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("/bin/sh", "-c", remoteCommandThatRemovesItsPackage("cd "+shellQuote(deployment)+" && false", "node-b.tar.gz"))
	cmd.Dir = login
	if err := cmd.Run(); err == nil {
		t.Fatal("a failed start was reported as success")
	}
	if _, err := os.Stat(pkg); err != nil {
		t.Fatal("the package was removed although the machine did not start")
	}
}
