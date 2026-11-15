package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// -upgrade moves the machine it runs on to another release, and nothing else.
//
// What a release changes on a machine is small and known: which images run, and the files this installer derives
// (the compose file, the launch scripts, the door configurations). The deployment's authorities, certificates,
// secrets and data are not part of it and are not touched. The same command is the upgrade on every machine of
// every layout; a deployment of several machines runs it on one machine at a time.
//
// It changes nothing that is running until the new images are on the machine, it keeps a copy of every file it
// replaces, and when the machine already runs the release it restarts nothing.

type upgradeInput struct {
	Dir, Manifest, Project string
	Timeout                time.Duration
}

type upgradeDeps struct {
	// compose runs `docker compose <args>` for this deployment directory, with the directory's own settings.
	compose func(ctx context.Context, dir string, out io.Writer, args ...string) error
	// project names the compose project already running from this directory, or "" when none is.
	project func(ctx context.Context, dir string) (string, error)
	// derived rewrites the files this installer derives from the deployment's own values.
	derived func(dir string) error
	// settled returns once every container of the project is running.
	settled func(ctx context.Context, dir, project string) error
	// verify runs the deployment-wide check the install order ends with. It returns the check's last lines.
	verify func(ctx context.Context, dir, shell string) (string, error)
	// answering returns once the control plane at url answers; running is not answering.
	answering func(ctx context.Context, url, anchorFile string) error
	pause     func(ctx context.Context, d time.Duration)
	now       func() time.Time
}

// upgradeUnfinishedFile records, in the deployment directory, an upgrade whose files are written and whose
// remaining steps have not all passed. It is written when the files change and removed when the last step
// passes or the files are put back, so its presence is what distinguishes "the files are this release's" from
// "this machine runs this release".
const upgradeUnfinishedFile = "upgrade-unfinished.json"

// upgradeAlreadyRunsCheck is how long a second run with nothing to write waits for the services to be seen
// running before it stops calling the machine upgraded.
const upgradeAlreadyRunsCheck = 30 * time.Second

type upgradeUnfinished struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kept string `json:"kept"`
}

func readUpgradeUnfinished(dir string) (upgradeUnfinished, bool) {
	var u upgradeUnfinished
	raw, err := os.ReadFile(filepath.Join(dir, upgradeUnfinishedFile))
	if os.IsNotExist(err) {
		return u, false
	}
	// A record that is there and cannot be read still says an upgrade began.
	if err == nil {
		_ = json.Unmarshal(raw, &u)
	}
	return u, true
}

func writeUpgradeUnfinished(dir string, u upgradeUnfinished) error {
	raw, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return publishInstallerFile(filepath.Join(dir, upgradeUnfinishedFile), append(raw, '\n'), 0o600)
}

// writeThroughTheSameFile puts body into the file that is already at path, instead of putting a new file in its
// place. A generated file mounted alone into a running container — the door's configuration, a launch script —
// is held there by the file itself, not by its name: replace the file and the container keeps the old one, so
// what the host shows as put back is not what a reload inside the container reads.
func writeThroughTheSameFile(path string, body []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// A machine's services are waited for upgradeSettleBeforeAskingAgain at a time, and Compose is asked to bring
// them up again between waits, upgradeSettleAttempts waits in all; the last wait has no limit of its own.
const (
	upgradeSettleBeforeAskingAgain = 45 * time.Second
	upgradeSettleAttempts          = 4
)

// upgradeVerifyAttempts is how many times the closing check is asked while a replaced deployment comes up.
const upgradeVerifyAttempts = 3

// upgradeImageSettings are the settings of deployment.env that say which images a machine runs.
func upgradeImageSettings(rel *releaseImages) [][2]string {
	return [][2]string{
		{"DSSE_IMAGE", rel.Service}, {"DSSE_CONSOLE_IMAGE", rel.Console}, {"DSSE_IMAGE_REVISION", rel.ImageRevision},
		{"DSSE_ETCD_IMAGE", rel.Etcd}, {"DSSE_POSTGRES_IMAGE", rel.Postgres}, {"DSSE_PSQL_IMAGE", rel.PostgresTools},
	}
}

// upgradeKeptFiles are the files an upgrade may replace, as paths under the deployment directory.
func upgradeKeptFiles(dir string) []string {
	names := []string{"deployment.env", composeFileName(), installPlanFile, "haproxy-resource-entrypoint.sh"}
	for _, pattern := range []string{"start-*.sh", "haproxy*.cfg"} {
		found, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, f := range found {
			names = append(names, filepath.Base(f))
		}
	}
	sort.Strings(names)
	out := names[:0]
	for i, n := range names {
		if i == 0 || n != names[i-1] {
			out = append(out, n)
		}
	}
	return out
}

func shortRevision(rev string) string {
	rev = strings.TrimPrefix(strings.Trim(strings.TrimSpace(rev), `'"`), "source-")
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		return "unknown"
	}
	return rev
}

func unquotedEnv(v string) string { return strings.Trim(strings.TrimSpace(v), `'"`) }

// planDocumentWithRelease rewrites the images of a plan document to the release's. Unlike withReleaseImages it
// replaces images that are already pinned: moving them is what an upgrade is.
func planDocumentWithRelease(raw []byte, rel *releaseImages) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	doc["image_revision"], doc["service_image"], doc["console_image"] = rel.ImageRevision, rel.Service, rel.Console
	layer, _ := doc["data_layer"].(map[string]any)
	if layer == nil {
		layer = map[string]any{}
		doc["data_layer"] = layer
	}
	layer["etcd_image"], layer["postgres_image"], layer["postgres_tools_image"] = rel.Etcd, rel.Postgres, rel.PostgresTools
	// The images and the major they hold are kept together; a plan that named neither is given both.
	if _, has := layer["postgres_major"]; !has && rel.PostgresMajor != 0 {
		layer["postgres_major"] = rel.PostgresMajor
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func runUpgrade(in upgradeInput, deps upgradeDeps, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "dsse-install: "+format+"\n", a...)
		return 1
	}
	if strings.TrimSpace(in.Dir) == "" || strings.TrimSpace(in.Manifest) == "" {
		return fail("-upgrade needs -dir (this machine's deployment directory) and -release-manifest (the release-manifest.json published beside this installer)")
	}
	dir, err := filepath.Abs(in.Dir)
	if err != nil {
		return fail("%v", err)
	}
	envPath := filepath.Join(dir, "deployment.env")
	for _, name := range []string{"deployment.env", composeFileName()} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || !info.Mode().IsRegular() {
			return fail("%s holds no deployment to upgrade: %s is missing. -upgrade moves an installed machine to another release; -up installs one", dir, name)
		}
	}
	rel, err := readReleaseManifest(in.Manifest)
	if err != nil {
		return fail("%v", err)
	}
	env, err := readEnvFile(envPath)
	if err != nil {
		return fail("%v", err)
	}
	// A different PostgreSQL major is a migration of the data itself. Replacing the image is not that migration.
	if have := unquotedEnv(env["DSSE_POSTGRES_MAJOR"]); have != "" && rel.PostgresMajor != 0 && have != fmt.Sprint(rel.PostgresMajor) {
		return fail("this release runs PostgreSQL %d and this deployment's data is PostgreSQL %s. That is a migration of the data, which -upgrade does not perform. Nothing was changed", rel.PostgresMajor, have)
	}
	from := shortRevision(env["DSSE_IMAGE_REVISION"])
	to := shortRevision(rel.ImageRevision)
	ctx, cancel := context.WithTimeout(context.Background(), in.Timeout)
	defer cancel()
	project := strings.TrimSpace(in.Project)
	if project == "" {
		if project, err = deps.project(ctx, dir); err != nil {
			return fail("%v", err)
		}
	}
	if project == "" {
		return fail("no compose project is running from %s, so there is nothing here to move to another release. If this machine's services are stopped on purpose, name their project with -project", dir)
	}

	// Keep what is about to be replaced, before anything is.
	keepDir := filepath.Join(dir, "upgrade-kept", deps.now().UTC().Format("20060102T150405Z")+"-from-"+from)
	if err := os.MkdirAll(keepDir, 0o700); err != nil {
		return fail("%v", err)
	}
	kept := map[string][]byte{}
	// The mode is kept with the bytes, from the same moment. Putting a file back with the mode of whatever
	// copy keepDir points at went wrong when a resumed run switched keepDir to the earlier attempt's copy: a
	// start script that attempt had generated was not in it, and came back 0600 — not executable, and the
	// regeneration that follows does not change an existing file's mode.
	keptMode := map[string]os.FileMode{}
	for _, name := range upgradeKeptFiles(dir) {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		kept[name] = body
		mode := os.FileMode(0o600)
		if info, serr := os.Stat(filepath.Join(dir, name)); serr == nil {
			mode = info.Mode().Perm()
		}
		keptMode[name] = mode
		if err := os.WriteFile(filepath.Join(keepDir, name), body, mode); err != nil {
			return fail("keep a copy of %s: %v", name, err)
		}
	}
	outsidePlan := dir + ".plan.json"
	outsidePlanBefore, outsidePlanErr := os.ReadFile(outsidePlan)
	// ★ THE RECORD OF AN UNFINISHED UPGRADE IS READ BEFORE THIS RUN CHANGES ANYTHING, and whatever this run
	// does, it never removes a record it did not write. An earlier run that replaced the files and did not
	// finish left the new release's files beside the old services, and its record is the only thing that says
	// so. This run "puts back" what it found — those same new files — and used to delete the record with
	// them: on a failed fetch (review of 2026-11-14) and, because the state was noticed only after the files
	// had been regenerated, on every failure before that point too (second review, same day). The next run
	// then read the new files and healthy old services and reported the upgrade complete.
	recordAtStart, unfinishedAtStart := readUpgradeUnfinished(dir)
	resuming := unfinishedAtStart
	putBack := func() error {
		for name, body := range kept {
			if err := writeThroughTheSameFile(filepath.Join(dir, name), body, keptMode[name]); err != nil {
				return err
			}
		}
		// A file this attempt generated and the machine did not have before is not part of what was running.
		for _, name := range upgradeKeptFiles(dir) {
			if _, was := kept[name]; !was {
				if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
		if unfinishedAtStart {
			// The files are back to what this run found, and what it found was an unfinished upgrade.
			if err := writeUpgradeUnfinished(dir, recordAtStart); err != nil {
				return err
			}
		} else {
			_ = os.Remove(filepath.Join(dir, upgradeUnfinishedFile))
		}
		if outsidePlanErr == nil {
			return publishInstallerFile(outsidePlan, outsidePlanBefore, 0o600)
		}
		return nil
	}
	// What a failure before the services are touched says. "Put back" means back to what this run found.
	putBackNote := "The previous files were put back"
	if unfinishedAtStart {
		putBackNote = "This machine's files are as this run found them, and the upgrade begun earlier is still unfinished: run the same command again"
	}

	fmt.Fprintf(stdout, "%s: release %s -> %s (compose project %s)\n", dir, from, to, project)
	fmt.Fprintf(stdout, "[1/4] write this release's settings and generated files ... ")
	for _, kv := range upgradeImageSettings(rel) {
		// A machine that holds no database names no database image; it is not given one.
		if _, has := env[kv[0]]; !has && kv[0] != "DSSE_IMAGE" && kv[0] != "DSSE_IMAGE_REVISION" {
			continue
		}
		if err := replaceEnvValue(envPath, kv[0], shellQuoted(kv[1])); err != nil {
			_ = putBack()
			return fail("write %s: %v. %s", kv[0], err, putBackNote)
		}
	}
	for _, planPath := range []string{filepath.Join(dir, installPlanFile), outsidePlan} {
		raw, rerr := os.ReadFile(planPath)
		if rerr != nil {
			continue // a machine prepared from a package need not hold the plan
		}
		next, perr := planDocumentWithRelease(raw, rel)
		if perr == nil {
			perr = publishInstallerFile(planPath, next, 0o600)
		}
		if perr != nil {
			_ = putBack()
			return fail("record the release in %s: %v. %s", planPath, perr, putBackNote)
		}
	}
	var derivedOut bytes.Buffer
	if err := captureProcessStdout(&derivedOut, func() error { return deps.derived(dir) }); err != nil {
		_ = putBack()
		return fail("regenerate this deployment's files: %v. %s", err, putBackNote)
	}
	// A compose file this installer does not recognise is left as it is. The images still move; whatever this
	// release changed in the generated compose file does not, and the operator must be told.
	composeLeftAlone := strings.Contains(derivedOut.String(), "LEFT ALONE")
	changed := []string{}
	for _, name := range upgradeKeptFiles(dir) {
		now, _ := os.ReadFile(filepath.Join(dir, name))
		if !bytes.Equal(now, kept[name]) {
			changed = append(changed, name)
		}
	}
	if len(changed) == 0 {
		dropNewCopy := func() {
			_ = os.RemoveAll(keepDir)
			_ = os.Remove(filepath.Dir(keepDir)) // only when empty
		}
		// The files being this release's is not the machine running it. An upgrade that wrote them and then
		// failed leaves them exactly so, and its record says which upgrade that was; without a record, the
		// services themselves are asked. Only files, record and services together are "already runs".
		unfinished, wasUnfinished := readUpgradeUnfinished(dir)
		if !wasUnfinished {
			brief, stop := context.WithTimeout(ctx, upgradeAlreadyRunsCheck)
			serr := deps.settled(brief, dir, project)
			stop()
			if serr == nil {
				dropNewCopy()
				fmt.Fprintf(stdout, "nothing to write\n\nThis machine already runs release %s: its files are this release's and its services are all running. Nothing was changed and nothing was restarted.\n", to)
				return 0
			}
			fmt.Fprintf(stdout, "nothing to write; the files are release %s and the services are not all running (%v), so the remaining steps are run\n", to, serr)
		} else {
			// What that upgrade replaced is what it kept; the copy just made is of the new files.
			if info, kerr := os.Stat(unfinished.Kept); unfinished.Kept != "" && kerr == nil && info.IsDir() {
				dropNewCopy()
				keepDir = unfinished.Kept
			}
			fmt.Fprintf(stdout, "nothing to write; an earlier upgrade to release %s wrote them and did not finish, so its remaining steps are run\n", to)
		}
	} else {
		fmt.Fprintf(stdout, "done (%s)\n", strings.Join(changed, ", "))
		// From here until the last step passes, this machine's files say one release and nothing has yet shown
		// that it runs it. The record is what a second run reads.
		if err := writeUpgradeUnfinished(dir, upgradeUnfinished{From: from, To: to, Kept: keepDir}); err != nil {
			_ = putBack()
			return fail("record that this upgrade has begun: %v. %s", err, putBackNote)
		}
	}
	if composeLeftAlone {
		fmt.Fprintf(stdout, "      %s names services this installer does not recognise, so it was left as it is: this machine takes the release's images and not its changes to that file.\n", composeFileName())
	}

	var log bytes.Buffer
	fmt.Fprintf(stdout, "[2/4] fetch this release's images (what is running is not touched) ... ")
	began := deps.now()
	// Only what this machine does not already hold. Every release image is pinned by digest, so an image that is
	// present is the image; asking the registry again failed on a machine whose images were carried in rather than
	// pulled — a machine without access to the registry could not be upgraded at all.
	if err := deps.compose(ctx, dir, &log, "compose", "-p", project, "--env-file", "deployment.env", "pull", "--policy", "missing", "--quiet"); err != nil {
		perr := putBack()
		fmt.Fprintf(stdout, "failed\n")
		fmt.Fprintf(stderr, "%s\n", lastLines(log.String(), 12))
		if perr != nil {
			return fail("the images could not be fetched (%v), and the previous files could not be put back (%v); they are in %s", err, perr, keepDir)
		}
		if resuming {
			return fail("the images could not be fetched (%v). The upgrade to release %s begun earlier is still unfinished: this machine's files are that release's and its services have not all been replaced. Run the same command again", err, to)
		}
		return fail("the images could not be fetched (%v). The previous files were put back; nothing that is running was changed", err)
	}
	fmt.Fprintf(stdout, "done in %s\n", deps.now().Sub(began).Truncate(time.Second))

	fmt.Fprintf(stdout, "[3/4] replace this machine's services (they are interrupted now) ... ")
	began = deps.now()
	log.Reset()
	if err := deps.compose(ctx, dir, &log, "compose", "-p", project, "--env-file", "deployment.env", "up", "-d", "--remove-orphans"); err != nil {
		fmt.Fprintf(stdout, "failed\n")
		fmt.Fprintf(stderr, "%s\n", lastLines(log.String(), 20))
		return fail("the services were not all replaced (%v). The files of release %s are in place and the previous ones are kept in %s. Correct the cause and run the same command again; to go back, copy the kept files over the ones in %s and run `docker compose -p %s --env-file deployment.env up -d` there", err, to, keepDir, dir, project)
	}
	// Compose can return without having started everything: a replacement that was cut short earlier leaves a
	// container created and not started, and the next `up` has been seen to pass it by. Asking again is harmless
	// — it restarts nothing that already runs as configured — so a service that has not come up is asked for
	// again before it is waited for to the end.
	settleErr := error(nil)
	for attempt := 1; ; attempt++ {
		if attempt == upgradeSettleAttempts {
			settleErr = deps.settled(ctx, dir, project) // the last wait is for as long as the command was given
			break
		}
		brief, stop := context.WithTimeout(ctx, upgradeSettleBeforeAskingAgain)
		settleErr = deps.settled(brief, dir, project)
		stop()
		if settleErr == nil || ctx.Err() != nil {
			break
		}
		log.Reset()
		if err := deps.compose(ctx, dir, &log, "compose", "-p", project, "--env-file", "deployment.env", "up", "-d", "--remove-orphans"); err != nil {
			settleErr = err
			break
		}
	}
	if err := settleErr; err != nil {
		fmt.Fprintf(stdout, "failed\n")
		return fail("the services were replaced and did not all come up (%v). Look at `docker compose -p %s --env-file deployment.env ps` in %s. The previous files are kept in %s", err, project, dir, keepDir)
	}
	fmt.Fprintf(stdout, "done in %s\n", deps.now().Sub(began).Truncate(time.Second))

	// The deployment-wide check belongs after the LAST machine. One machine holding everything is its own last.
	verifyShell, machines := "", 0
	if plan, perr := LoadPlan(filepath.Join(dir, installPlanFile)); perr == nil {
		for _, r := range plan.Regions {
			machines += len(r.Machines)
		}
		if local, lerr := localInstallMachine(dir); lerr == nil && local == plan.foundingRegion().controlPlane().Name {
			for _, s := range plan.InstallOrder(dir, filepath.Join(dir, installPlanFile)) {
				if strings.HasPrefix(s.Do, "dsse-install -verify ") {
					verifyShell = s.Do
				}
			}
		}
	}
	switch {
	case verifyShell != "" && machines == 1:
		fmt.Fprintf(stdout, "[4/4] check the whole deployment ... ")
		began = deps.now()
		// A deployment that has just been replaced is still coming up: its control plane answers after its
		// containers run, and its Edges take their configuration after that. A check that fails while that is
		// happening says nothing yet, so it is asked again — a deployment that is broken fails every time.
		if m := controlPlaneURL.FindStringSubmatch(verifyShell); m != nil {
			if err := deps.answering(ctx, m[1], filepath.Join(dir, "deployment-anchor.pem")); err != nil {
				fmt.Fprintf(stdout, "failed\n")
				return fail("this machine's services were replaced with release %s, and its control plane does not answer (%v). The previous files are kept in %s", to, err, keepDir)
			}
		}
		var tail string
		var err error
		for attempt := 1; attempt <= upgradeVerifyAttempts; attempt++ {
			if tail, err = deps.verify(ctx, dir, verifyShell); err == nil || ctx.Err() != nil {
				break
			}
			if attempt < upgradeVerifyAttempts {
				deps.pause(ctx, 20*time.Second)
			}
		}
		if err != nil {
			fmt.Fprintf(stdout, "failed\n")
			fmt.Fprintf(stderr, "%s\n", tail)
			return fail("this machine runs release %s, and the check of the deployment did not pass (%v). The previous files are kept in %s", to, err, keepDir)
		}
		fmt.Fprintf(stdout, "done in %s\n", deps.now().Sub(began).Truncate(time.Second))
		for _, line := range strings.Split(tail, "\n") {
			if strings.Contains(line, "checks passed") {
				fmt.Fprintf(stdout, "      %s\n", strings.TrimSpace(line))
			}
		}
	default:
		fmt.Fprintf(stdout, "[4/4] check the whole deployment ... not run here: it belongs after the last machine\n")
	}
	if err := os.Remove(filepath.Join(dir, upgradeUnfinishedFile)); err != nil && !os.IsNotExist(err) {
		return fail("this machine runs release %s, and the record of the unfinished upgrade could not be removed (%v); remove %s", to, err, filepath.Join(dir, upgradeUnfinishedFile))
	}
	fmt.Fprintf(stdout, "\nThis machine runs release %s.\n", to)
	fmt.Fprintf(stdout, "  The files it replaced are kept in %s (deployment.env there holds secrets; it is private).\n", keepDir)
	if machines != 1 {
		fmt.Fprintf(stdout, "  Run the same command on each other machine of this deployment, one machine at a time, and let each come back before the next.\n")
		if verifyShell != "" {
			fmt.Fprintf(stdout, "  When every machine runs this release, check the deployment from this machine:\n    %s\n", verifyShell)
		} else {
			fmt.Fprintf(stdout, "  When every machine runs this release, run the -verify step of the install order on the founding machine.\n")
		}
	}
	return 0
}

// upgradeDerivedFiles brings this machine's generated files to what this installer generates, and changes
// nothing else: regenerating with the installer that wrote them leaves every file as it was.
//
// Two things make that true. The machine's shape is taken from the stored plan when the machine holds one — the
// plan knows that a region joined a deployment, which a compose file read back does not say. And a generated
// file that was not here before, and that nothing in this machine's compose file reads, is not left behind: a
// machine prepared from a package holds only what it runs.
// carryPlanSettingsThisReleaseReads writes into deployment.env the plan's own values that this release's
// start scripts read and an earlier release's installation never wrote. A fresh installation gets them when
// the plan is applied; a machine being upgraded keeps its deployment.env, so without this the new start
// script reads a variable that is not there.
//
// DSSE_DEPLOYMENT_CRL_ORIGINS is the case: the plan has always held deployment_crl_origins, and the control
// plane now reads them to name revocation lists in an inspection authority it makes for an organization. An
// upgraded deployment that publishes lists made such authorities with no address in them (review, 2026-11-14).
// Only values the plan holds, only when the setting is absent, and nothing secret.
func carryPlanSettingsThisReleaseReads(dir string, plan *Plan) error {
	if plan == nil || len(plan.DeploymentCRLOrigins) == 0 {
		return nil
	}
	path := filepath.Join(dir, "deployment.env")
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	env, err := readEnvFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(env["DSSE_DEPLOYMENT_CRL_ORIGINS"]) != "" {
		return nil
	}
	mode := os.FileMode(0o600)
	if info, serr := os.Stat(path); serr == nil {
		mode = info.Mode().Perm()
	}
	next := PlanEnvironmentFor(string(body), map[string]string{"DSSE_DEPLOYMENT_CRL_ORIGINS": strings.Join(plan.DeploymentCRLOrigins, ",")})
	return writeThroughTheSameFile(path, []byte(next), mode)
}

func upgradeDerivedFiles(dir string) error {
	if plan, err := LoadPlan(filepath.Join(dir, installPlanFile)); err == nil {
		if err := carryPlanSettingsThisReleaseReads(dir, plan); err != nil {
			return err
		}
		if local, lerr := localInstallMachine(dir); lerr == nil {
			if region, machine, ok := plan.find(local); ok {
				shape := plan.shapeOf(region, machine)
				saved := shapeOverride
				shapeOverride = &shape
				defer func() { shapeOverride = saved }()
			}
		}
	}
	// What each generated file held before, so that one nothing reads can be put back as it was.
	before := map[string][]byte{}
	for _, name := range generatedFileNames {
		if body, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			before[name] = body
		}
	}
	var err error
	if _, kerr := os.Stat(filepath.Join(dir, agentPolicySigningKeyFile)); kerr == nil {
		err = repairDerivedFiles(dir)
	} else {
		regeneratingDerivedFiles = true
		derivedFileOutcomes = nil
		err = rewriteGeneratedFiles(dir)
		regeneratingDerivedFiles = false
	}
	if err != nil {
		return err
	}
	compose, _ := os.ReadFile(filepath.Join(dir, composeFileName()))
	for _, name := range generatedFileNames {
		// The compose file names what it reads as "./<file>:<path in the container>". A file it does not name
		// is read by nothing on this machine; rewriting or creating it would be a change with no effect that
		// the operator is then shown as one.
		if bytes.Contains(compose, []byte("\"./"+name+":")) {
			continue
		}
		path := filepath.Join(dir, name)
		if body, had := before[name]; had {
			if now, rerr := os.ReadFile(path); rerr != nil || !bytes.Equal(now, body) {
				mode := os.FileMode(0o644)
				if info, serr := os.Stat(path); serr == nil {
					mode = info.Mode().Perm()
				}
				if werr := os.WriteFile(path, body, mode); werr != nil {
					return werr
				}
			}
		} else if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
	}
	return nil
}

// generatedFileNames are the files beside the compose file that this installer derives.
var generatedFileNames = []string{"haproxy.cfg", "haproxy-edge.cfg", "haproxy-postgres.cfg", "haproxy-resource-entrypoint.sh",
	"start-control-plane.sh", "start-edge.sh", "start-archive-alert-publisher.sh"}

func lastLines(text string, n int) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// captureProcessStdout runs fn with the process's standard output collected into buf. The acts that regenerate a
// deployment's files report through fmt.Printf; an upgrade says its own four lines and keeps that report for a
// failure.
func captureProcessStdout(buf *bytes.Buffer, fn func() error) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fn()
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan struct{})
	go func() { _, _ = io.Copy(buf, r); close(done) }()
	ferr := fn()
	os.Stdout = saved
	w.Close()
	<-done
	r.Close()
	return ferr
}

// runningComposeProject asks Docker which project was started from this directory's compose file. What is
// running is the authority on its own name: a project name guessed from a plan can be right and still not be
// the one an operator started.
func runningComposeProject(ctx context.Context, dir string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "compose", "ls", "--all", "--format", "json").Output()
	if err != nil {
		return "", fmt.Errorf("Docker with Compose v2 is needed on this machine, and `docker compose ls` failed: %v", err)
	}
	return composeProjectFor(out, filepath.Join(dir, composeFileName()))
}

func composeProjectFor(listing []byte, composePath string) (string, error) {
	var rows []struct {
		Name        string `json:"Name"`
		ConfigFiles string `json:"ConfigFiles"`
	}
	if err := json.Unmarshal(listing, &rows); err != nil {
		return "", fmt.Errorf("`docker compose ls` did not answer in the form this installer reads: %v", err)
	}
	want := composePath
	if real, err := filepath.EvalSymlinks(composePath); err == nil {
		want = real
	}
	found := []string{}
	for _, row := range rows {
		for _, f := range strings.Split(row.ConfigFiles, ",") {
			f = strings.TrimSpace(f)
			if real, err := filepath.EvalSymlinks(f); err == nil {
				f = real
			}
			if f == want {
				found = append(found, row.Name)
			}
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("more than one compose project runs from %s (%s); name the one to upgrade with -project", composePath, strings.Join(found, ", "))
}

// composeServicesNotRunning reads `docker compose ps --all --format json` — one JSON array, or one object a line,
// depending on the Compose version — and names what is neither running nor finished cleanly.
func composeServicesNotRunning(listing []byte) ([]string, int, error) {
	type row struct {
		Service, State, Health string
		ExitCode               int
	}
	var rows []row
	trimmed := bytes.TrimSpace(listing)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, 0, err
		}
	} else {
		for _, line := range bytes.Split(trimmed, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var r row
			if err := json.Unmarshal(line, &r); err != nil {
				return nil, 0, err
			}
			rows = append(rows, r)
		}
	}
	waiting := []string{}
	for _, r := range rows {
		// A service that ran once and ended cleanly — the database's initialisation, its certificate
		// preparation — has done what it is for. Waiting for it to be "running" waits for ever.
		if r.State == "exited" && r.ExitCode == 0 {
			continue
		}
		if r.State != "running" || r.Health == "starting" || r.Health == "unhealthy" {
			waiting = append(waiting, r.Service+" ("+strings.TrimSpace(r.State+" "+r.Health)+")")
		}
	}
	sort.Strings(waiting)
	return waiting, len(rows), nil
}

func composeSettled(ctx context.Context, dir, project string) error {
	waiting := []string{"nothing listed"}
	for {
		cmd, err := installerComposeCommand(ctx, dir, "compose", "-p", project, "--env-file", "deployment.env", "ps", "--all", "--format", "json")
		if err != nil {
			return err
		}
		if out, err := cmd.Output(); err == nil {
			var total int
			if waiting, total, err = composeServicesNotRunning(out); err == nil && total > 0 && len(waiting) == 0 {
				return nil
			}
			if total == 0 {
				waiting = []string{"nothing listed"}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("not running when the time allowed ran out: %s", strings.Join(waiting, ", "))
		case <-time.After(2 * time.Second):
		}
	}
}

func realUpgradeDeps() upgradeDeps {
	return upgradeDeps{
		compose: func(ctx context.Context, dir string, out io.Writer, args ...string) error {
			cmd, err := installerComposeCommand(ctx, dir, args...)
			if err != nil {
				return err
			}
			cmd.Stdout, cmd.Stderr = out, out
			return cmd.Run()
		},
		project: runningComposeProject,
		derived: upgradeDerivedFiles,
		settled: composeSettled,
		verify: func(ctx context.Context, dir, shell string) (string, error) {
			self, err := os.Executable()
			if err != nil {
				return "", err
			}
			// The step calls `dsse-install` by name, as the printed order does. Make that name this binary.
			binDir, err := os.MkdirTemp("", "dsse-install-self-")
			if err != nil {
				return "", err
			}
			defer os.RemoveAll(binDir)
			if err := os.Symlink(self, filepath.Join(binDir, "dsse-install")); err != nil {
				return "", err
			}
			var out bytes.Buffer
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", shell)
			cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &out, &out
			cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			err = cmd.Run()
			return lastLines(out.String(), 25), err
		},
		answering: waitForControlPlane,
		pause: func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		},
		now: time.Now,
	}
}
