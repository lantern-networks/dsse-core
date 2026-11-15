package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	oldService = "ghcr.io/example/dsse-service@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest  = "2222222222222222222222222222222222222222222222222222222222222222"
)

func upgradeManifest(t *testing.T, dir string, postgresMajor int) string {
	t.Helper()
	body := `{"container_images":{"image_revision_label":"source-newrevision000000","postgres_major":` + fmt.Sprint(postgresMajor) + `,"images":{
 "service_image":"ghcr.io/example/dsse-service@sha256:` + newDigest + `",
 "console_image":"ghcr.io/example/dsse-console@sha256:` + newDigest + `",
 "data_layer.etcd_image":"ghcr.io/example/dsse-etcd@sha256:` + newDigest + `",
 "data_layer.postgres_image":"ghcr.io/example/dsse-postgres@sha256:` + newDigest + `",
 "data_layer.postgres_tools_image":"ghcr.io/example/dsse-postgres-tools@sha256:` + newDigest + `"}}}`
	path := filepath.Join(dir, "release-manifest.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// installedMachine is a deployment directory as an older release left it: settings with a secret beside the
// images, and a generated compose file.
func installedMachine(t *testing.T, withDatabase bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "region-a")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := "# the images this machine runs\nDSSE_IMAGE='" + oldService + "'\nDSSE_CONSOLE_IMAGE='old-console'\nDSSE_IMAGE_REVISION='source-oldrevision000000'\nADMIN_TOKEN='keep-this-secret'\n"
	if withDatabase {
		env += "DSSE_ETCD_IMAGE='old-etcd'\nDSSE_POSTGRES_IMAGE='old-postgres'\nDSSE_PSQL_IMAGE='old-psql'\nDSSE_POSTGRES_MAJOR='18'\n"
	}
	for name, body := range map[string]string{"deployment.env": env, composeFileName(): "services:\n  old: {}\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type recordedUpgrade struct {
	// failDerived makes the regeneration of this deployment's files fail, as a full disk would.
	failDerived bool
	composed    []string
	envAtPull   string
	failPull    bool
	failUp      bool
	derivedRan  int
	// verifyFailures is how many times the closing check fails before it passes.
	verifyFailures, verified, waitedForControlPlane int
}

func (r *recordedUpgrade) deps(newCompose string) upgradeDeps {
	return upgradeDeps{
		compose: func(_ context.Context, dir string, _ io.Writer, args ...string) error {
			r.composed = append(r.composed, strings.Join(args, " "))
			if slices.Contains(args, "pull") {
				body, _ := os.ReadFile(filepath.Join(dir, "deployment.env"))
				r.envAtPull = string(body)
				if r.failPull {
					return errors.New("registry unreachable")
				}
			}
			if r.failUp && strings.Contains(strings.Join(args, " "), " up -d") {
				return errors.New("a container did not start")
			}
			return nil
		},
		project: func(context.Context, string) (string, error) { return "dsse", nil },
		derived: func(dir string) error {
			r.derivedRan++
			if r.failDerived {
				return errors.New("no space left on device")
			}
			if newCompose == "" {
				return nil
			}
			return os.WriteFile(filepath.Join(dir, composeFileName()), []byte(newCompose), 0o600)
		},
		settled: func(context.Context, string, string) error { return nil },
		verify: func(context.Context, string, string) (string, error) {
			r.verified++
			if r.verified <= r.verifyFailures {
				return "4 checks failed", errors.New("exit status 1")
			}
			return "dsse-install -verify: 50 checks passed; 1 not checked.", nil
		},
		answering: func(context.Context, string, string) error { r.waitedForControlPlane++; return nil },
		pause:     func(context.Context, time.Duration) {},
		now:       func() time.Time { return time.Date(2026, 11, 13, 4, 0, 0, 0, time.UTC) },
	}
}

func TestUpgradeMovesTheImagesAndKeepsEverythingElse(t *testing.T) {
	dir := installedMachine(t, true)
	rec := &recordedUpgrade{}
	var out, errOut bytes.Buffer
	code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute},
		rec.deps("services:\n  new: {}\n"), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	env, _ := readEnvFile(filepath.Join(dir, "deployment.env"))
	for _, key := range []string{"DSSE_IMAGE", "DSSE_CONSOLE_IMAGE", "DSSE_ETCD_IMAGE", "DSSE_POSTGRES_IMAGE", "DSSE_PSQL_IMAGE"} {
		if !strings.HasSuffix(env[key], "@sha256:"+newDigest) {
			t.Errorf("%s was not moved to the release: %q", key, env[key])
		}
	}
	if env["DSSE_IMAGE_REVISION"] != "source-newrevision000000" || env["ADMIN_TOKEN"] != "keep-this-secret" {
		t.Errorf("revision %q, secret %q", env["DSSE_IMAGE_REVISION"], env["ADMIN_TOKEN"])
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if !strings.Contains(string(raw), "# the images this machine runs") {
		t.Error("the comments of deployment.env were lost")
	}
	// Pull comes before up, and it already reads the new settings.
	if len(rec.composed) != 2 || !strings.HasSuffix(rec.composed[0], "pull --policy missing --quiet") || !strings.Contains(rec.composed[1], "up -d") {
		t.Fatalf("compose ran: %q", rec.composed)
	}
	if !strings.Contains(rec.envAtPull, newDigest) {
		t.Error("the images were fetched before the new settings were written")
	}
	keptEnv, err := os.ReadFile(filepath.Join(dir, "upgrade-kept", "20261113T040000Z-from-oldrevision0", "deployment.env"))
	if err != nil || !strings.Contains(string(keptEnv), oldService) {
		t.Errorf("the previous settings were not kept: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, "upgrade-kept", "20261113T040000Z-from-oldrevision0")); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the kept copy holds secrets and must be private: %v", err)
	}
}

func TestUpgradeGivesAMachineWithoutADatabaseNoDatabaseImage(t *testing.T) {
	dir := installedMachine(t, false)
	rec := &recordedUpgrade{}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, rec.deps(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	env, _ := readEnvFile(filepath.Join(dir, "deployment.env"))
	if _, has := env["DSSE_POSTGRES_IMAGE"]; has {
		t.Error("a machine that named no database image was given one")
	}
}

func TestUpgradeToTheReleaseAlreadyRunningRestartsNothing(t *testing.T) {
	dir := installedMachine(t, true)
	manifest := upgradeManifest(t, t.TempDir(), 18)
	first := &recordedUpgrade{}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}, first.deps(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	second := &recordedUpgrade{}
	out.Reset()
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}, second.deps(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if len(second.composed) != 0 {
		t.Fatalf("a machine already on the release was touched: %q", second.composed)
	}
	if !strings.Contains(out.String(), "nothing was restarted") {
		t.Errorf("it did not say so: %s", out.String())
	}
	if kept, _ := filepath.Glob(filepath.Join(dir, "upgrade-kept", "*")); len(kept) != 1 {
		t.Errorf("the second run left a kept copy of nothing: %v", kept)
	}
}

func TestUpgradeThatCannotFetchPutsTheFilesBack(t *testing.T) {
	dir := installedMachine(t, true)
	before, _ := os.ReadFile(filepath.Join(dir, "deployment.env"))
	composeBefore, _ := os.ReadFile(filepath.Join(dir, composeFileName()))
	rec := &recordedUpgrade{failPull: true}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, rec.deps("services:\n  new: {}\n"), &out, &errOut); code == 0 {
		t.Fatal("a failed fetch was reported as an upgrade")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "deployment.env"))
	composeAfter, _ := os.ReadFile(filepath.Join(dir, composeFileName()))
	if !bytes.Equal(before, after) || !bytes.Equal(composeBefore, composeAfter) {
		t.Error("the previous files were not put back")
	}
	if len(rec.composed) != 1 {
		t.Errorf("the services were replaced without their images: %q", rec.composed)
	}
	if !strings.Contains(errOut.String(), "nothing that is running was changed") {
		t.Errorf("it did not say so: %s", errOut.String())
	}
}

func TestUpgradeRefusesAnotherPostgresMajor(t *testing.T) {
	dir := installedMachine(t, true)
	before, _ := os.ReadFile(filepath.Join(dir, "deployment.env"))
	rec := &recordedUpgrade{}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 19), Timeout: time.Minute}, rec.deps(""), &out, &errOut); code == 0 {
		t.Fatal("a change of PostgreSQL major was treated as a change of image")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if !bytes.Equal(before, after) || len(rec.composed) != 0 || rec.derivedRan != 0 {
		t.Error("something was changed before the refusal")
	}
}

func TestUpgradeRefusesADirectoryThatHoldsNoDeployment(t *testing.T) {
	rec := &recordedUpgrade{}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: t.TempDir(), Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, rec.deps(""), &out, &errOut); code == 0 {
		t.Fatal("an empty directory was upgraded")
	}
	if !strings.Contains(errOut.String(), "-up installs one") {
		t.Errorf("it did not point at -up: %s", errOut.String())
	}
}

func TestUpgradeRecordsTheReleaseInThePlans(t *testing.T) {
	dir := installedMachine(t, true)
	plan := `{"deployment":"example.test","service_image":"` + oldService + `","data_layer":{"etcd_image":"old","postgres_major":18}}`
	for _, p := range []string{filepath.Join(dir, installPlanFile), dir + ".plan.json"} {
		if err := os.WriteFile(p, []byte(plan), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := &recordedUpgrade{}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, rec.deps(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, p := range []string{filepath.Join(dir, installPlanFile), dir + ".plan.json"} {
		raw, _ := os.ReadFile(p)
		if strings.Contains(string(raw), oldService) || strings.Count(string(raw), newDigest) != 5 || !strings.Contains(string(raw), `"deployment": "example.test"`) {
			t.Errorf("%s does not record the release beside what it already said: %s", p, raw)
		}
	}
}

func TestComposeProjectIsTheOneRunningFromThisDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, composeFileName())
	if err := os.WriteFile(path, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listing := `[{"Name":"other","Status":"running(2)","ConfigFiles":"/somewhere/else/docker-compose.yml"},{"Name":"dsse-region-b","Status":"running(8)","ConfigFiles":"` + path + `"}]`
	got, err := composeProjectFor([]byte(listing), path)
	if err != nil || got != "dsse-region-b" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := composeProjectFor([]byte(`[]`), path); err != nil || got != "" {
		t.Fatalf("nothing running: got %q, %v", got, err)
	}
}

func TestAServiceThatRanOnceAndFailedIsNotSettled(t *testing.T) {
	if waiting, _, err := composeServicesNotRunning([]byte(`[{"Service":"init","State":"exited","ExitCode":1}]`)); err != nil || len(waiting) != 1 {
		t.Errorf("a failed one-time service was read as finished: %v %v", waiting, err)
	}
}

func TestComposeServicesNotRunningReadsBothForms(t *testing.T) {
	array := `[{"Service":"a","State":"running","Health":""},{"Service":"b","State":"restarting","Health":""},{"Service":"init","State":"exited","Health":"","ExitCode":0}]`
	lines := "{\"Service\":\"a\",\"State\":\"running\",\"Health\":\"healthy\"}\n{\"Service\":\"c\",\"State\":\"running\",\"Health\":\"starting\"}\n"
	if waiting, total, err := composeServicesNotRunning([]byte(array)); err != nil || total != 3 || len(waiting) != 1 || !strings.HasPrefix(waiting[0], "b ") {
		t.Errorf("array form: %v %d %v", waiting, total, err)
	}
	if waiting, total, err := composeServicesNotRunning([]byte(lines)); err != nil || total != 2 || len(waiting) != 1 || !strings.HasPrefix(waiting[0], "c ") {
		t.Errorf("line form: %v %d %v", waiting, total, err)
	}
}

// oneMachineDeployment is an installed machine that also holds its plan: one machine, which is its own last.
func oneMachineDeployment(t *testing.T) string {
	t.Helper()
	dir := installedMachine(t, true)
	raw, err := os.ReadFile("../../docs/plans/single-region.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, installPlanFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := LoadPlan(filepath.Join(dir, installPlanFile))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "deployment.env"))
	env = append(env, []byte("DSSE_NODE_NAME='"+plan.foundingRegion().controlPlane().Name+"'\n")...)
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), env, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestUpgradeOfOneMachineChecksTheDeploymentOnceItAnswers(t *testing.T) {
	dir := oneMachineDeployment(t)
	rec := &recordedUpgrade{verifyFailures: 1} // the first check lands while the deployment is still coming up
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, rec.deps(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	if _, err := LoadPlan(filepath.Join(dir, installPlanFile)); err != nil {
		t.Fatalf("the plan no longer loads after the upgrade: %v", err)
	}
	if local, err := localInstallMachine(dir); err != nil || local == "" {
		t.Fatalf("local machine %q %v", local, err)
	}
	if rec.waitedForControlPlane != 1 || rec.verified != 2 {
		t.Errorf("waited for the control plane %d time(s), checked %d time(s)", rec.waitedForControlPlane, rec.verified)
	}
	if !strings.Contains(out.String(), "50 checks passed") {
		t.Errorf("the result of the check was not shown: %s", out.String())
	}
}

func TestUpgradeWhoseCheckKeepsFailingFails(t *testing.T) {
	dir := oneMachineDeployment(t)
	rec := &recordedUpgrade{verifyFailures: 99}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, rec.deps(""), &out, &errOut); code == 0 {
		t.Fatal("a deployment whose check never passed was reported as upgraded and checked")
	}
	if rec.verified != upgradeVerifyAttempts {
		t.Errorf("checked %d time(s)", rec.verified)
	}
}

// Review finding (2026-11-14): an upgrade failed while replacing the services, the same command again failed
// while fetching, and that second failure removed the record of the unfinished upgrade. The third run found
// the new release's files and healthy (old) services, and said the machine already ran the new release.
func TestAnUpgradeThatFailsTwiceIsStillUnfinished(t *testing.T) {
	dir := installedMachine(t, true)
	manifest := upgradeManifest(t, t.TempDir(), 18)
	run := func(rec *recordedUpgrade) (int, string) {
		var out, errOut bytes.Buffer
		code := runUpgrade(upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}, rec.deps("services:\n  new: {}\n"), &out, &errOut)
		return code, out.String() + errOut.String()
	}
	unfinished := func() bool { _, err := os.Stat(filepath.Join(dir, upgradeUnfinishedFile)); return err == nil }

	if code, _ := run(&recordedUpgrade{failUp: true}); code == 0 || !unfinished() {
		t.Fatalf("first run: exit %d, unfinished record present %t", code, unfinished())
	}
	code, said := run(&recordedUpgrade{failPull: true})
	if code == 0 {
		t.Fatal("second run: a failed fetch was reported as an upgrade")
	}
	if !unfinished() {
		t.Fatal("second run: the record of the unfinished upgrade was removed although nothing was finished or restored")
	}
	if strings.Contains(said, "previous files were put back") || !strings.Contains(said, "still unfinished") {
		t.Fatalf("second run said: %s", said)
	}
	third := &recordedUpgrade{}
	code, said = run(third)
	if code != 0 {
		t.Fatalf("third run: exit %d: %s", code, said)
	}
	replaced := false
	for _, c := range third.composed {
		if strings.Contains(c, " up -d") {
			replaced = true
		}
	}
	// (This machine holds no plan, so the closing check is printed for the operator rather than run here.)
	if !replaced || strings.Contains(said, "already runs release") {
		t.Fatalf("third run reported success without replacing the services: %q\n%s", third.composed, said)
	}
	if unfinished() {
		t.Fatal("the record outlived a completed upgrade")
	}
}

// Second review (2026-11-14): the first fix kept the record only when the second failure was the fetch. A
// second run that fails earlier — while regenerating the files — still removed it, and the third run reported
// the release as running without replacing a service.
func TestAnUpgradeThatFailsAgainAtAnyStepIsStillUnfinished(t *testing.T) {
	for name, second := range map[string]*recordedUpgrade{
		"regenerating the files": {failDerived: true},
		"fetching the images":    {failPull: true},
		"replacing the services": {failUp: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := installedMachine(t, true)
			manifest := upgradeManifest(t, t.TempDir(), 18)
			run := func(rec *recordedUpgrade) (int, string) {
				var out, errOut bytes.Buffer
				code := runUpgrade(upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}, rec.deps("services:\n  new: {}\n"), &out, &errOut)
				return code, out.String() + errOut.String()
			}
			unfinished := func() bool { _, err := os.Stat(filepath.Join(dir, upgradeUnfinishedFile)); return err == nil }
			if code, _ := run(&recordedUpgrade{failUp: true}); code == 0 || !unfinished() {
				t.Fatalf("first run: exit %d, unfinished record present %t", code, unfinished())
			}
			recordBefore, _ := os.ReadFile(filepath.Join(dir, upgradeUnfinishedFile))
			code, said := run(second)
			if code == 0 {
				t.Fatalf("second run reported success: %s", said)
			}
			if !unfinished() {
				t.Fatalf("second run removed the record of the unfinished upgrade: %s", said)
			}
			if recordAfter, _ := os.ReadFile(filepath.Join(dir, upgradeUnfinishedFile)); !bytes.Equal(recordBefore, recordAfter) {
				t.Fatalf("the record no longer says what the first run kept:\n%s\n%s", recordBefore, recordAfter)
			}
			if strings.Contains(said, "previous files were put back") {
				t.Fatalf("second run claimed the previous release's files were put back: %s", said)
			}
			third := &recordedUpgrade{}
			code, said = run(third)
			replaced := false
			for _, c := range third.composed {
				if strings.Contains(c, " up -d") {
					replaced = true
				}
			}
			if code != 0 || !replaced || strings.Contains(said, "already runs release") {
				t.Fatalf("third run: exit %d, services replaced %t: %s", code, replaced, said)
			}
			if unfinished() {
				t.Fatal("the record outlived a completed upgrade")
			}
		})
	}
}
