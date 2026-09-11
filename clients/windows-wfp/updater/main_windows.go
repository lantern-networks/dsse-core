//go:build windows

// main_windows.go — the Windows service around the sequencing.
//
//	dsse-updater --once                    one tick, print what it decided, and exit
//	dsse-updater --once --dry-run          one tick that verifies, STAGES and evaluates every gate, then stops
//	                                       immediately before the installer — nothing is disarmed, launched or recorded
//	dsse-updater --service-install         register DsseUpdater (LocalSystem, auto-start)
//	dsse-updater --service-uninstall
//	dsse-updater --service-run             run under the SCM
//	dsse-updater --status                  print what this device would do, and why, without doing it
//
// ★ WHY THIS IS NOT PART OF DsseWatchdog, restated where someone would be tempted to merge them. The watchdog
// is the safety net and this is the riskiest component in the tree; a net sharing a process with the thing it
// catches is not a net. The sharper reason is what runstate made explicit: this process reads a value the
// agent writes, and the watchdog exists precisely for when the agent is writing nothing. Two opposite
// assumptions about one process do not belong in one process.
//
// Everything policy-shaped lives in tick.go / stage.go / source.go and is tested off-Windows. What is here is
// the wiring, the flags, and the service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/authenticode"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/datadir"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/runstate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/updateplatform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "DsseUpdater"

var (
	buildVersion = "0.0.0-dev"
	buildCommit  = "unknown"
)

// stateRoot is where this process keeps the journal and the plan: %ProgramData%\DSSE\update.
//
// ProgramData rather than the install directory, for the same reason the rollback store lives there — the
// install directory is what an upgrade rewrites, and a journal that disappears during the install it is
// recording is a journal that cannot report an interrupted install.
func stateRoot() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "DSSE", "update")
	}
	return filepath.Join("DSSE", "update")
}

func main() {
	serviceInstall := flag.Bool("service-install", false, "register DsseUpdater (LocalSystem, auto-start)")
	serviceUninstall := flag.Bool("service-uninstall", false, "stop + remove DsseUpdater")
	serviceRun := flag.Bool("service-run", false, "run under the Windows service control manager")
	once := flag.Bool("once", false, "evaluate once, print the decision, and exit")
	// ★ ROLLBACK IS AN OPERATOR ACTION AND NEVER THE SERVICE'S. The DsseUpdater service runs --service-run and
	// cannot reach these: an unattended process that decides on its own to walk a fleet backwards is a worse
	// failure than whatever it would be fixing. A person types this, on a box, elevated.
	//
	// Added 2026-08-11 after a review pointed out that Platform.ExecuteRollback, the MSI's DSSEROLLBACK launch
	// condition and the stored-package marker were all implemented and UNREACHABLE — agentupdate.Rollback had
	// no Windows caller at all, so the whole recovery path existed and could not be invoked.
	rollback := flag.Bool("rollback", false, "put the previous version back: install the MSI this box stored for the version it was running before its last update, refuse the version being left, and record it. Operator action; the service never does this.")
	rollbackTo := flag.String("rollback-to", "", "roll back to this exact version instead of the one the journal names. It must be a version this box HOLDS an MSI for — the store bounds what this flag can do — and --status lists them.")
	status := flag.Bool("status", false, "print what this device would do and why, touching nothing")
	// ★ THE RESCUE WAS ADDED TO macOS AND THE DEVICE IT WAS FOR IS THIS ONE (2026-08-13, twenty-ninth review).
	// A journal from a build that predates the outcome counter is read as already reported — right for a build
	// that HAD a reporter, wrong for one whose outbox drain did not exist yet, and win-dev-1 is exactly that
	// case. The command existed on the platform that did not need it.
	reportAgain := flag.Bool("report-outcome-again", false, "clear an ASSUMED report marker so this device's last terminal outcome is queued for the fleet again. Refuses to touch a marker earned by a report that actually reached the outbox — clearing one of those would send the same outcome twice.")
	// Precise about what it does and does not do. Staging still happens: updateplatform.Tick owns it, it is
	// idempotent and non-destructive, and suppressing it would make the dry run exercise a different path from
	// the real one — which is the opposite of what a rehearsal is for. What is suppressed is the two things
	// that change the machine: taking steering down, and launching an installer.
	dryRun := flag.Bool("dry-run", false, "with --once: go through the whole tick — fetch, verify, stage, check the digest, evaluate the freeze/wave/window — and stop immediately before the installer. Steering stays up, the journal is not written, and no attempt is counted against this version.")
	interval := flag.Duration("interval", 30*time.Minute, "how often to evaluate")

	manifestURL := flag.String("manifest-url", "", "reserved: fetching the manifest over https is not implemented, and this flag exists only so a deployment that sets it is told rather than silently ignored")
	manifestFile := flag.String("manifest-file", "", "path to the signed update manifest envelope placed by the agent, an MDM, or an administrator (default: <ProgramData>\\DSSE\\update-manifest.json)")
	updatePins := flag.String("update-pin", "", "comma-separated public keys (hex) the update manifest is verified against: each a 64-char Ed25519 key or a 130-char uncompressed ECDSA-P256 point starting 04 (a PKCS#11 token holds the second kind, and the control plane signs with one). Comma-separated is how a rotation is carried out — pin old AND new, wait for the fleet to hold both, then switch signing keys; the reverse order strands devices, and no update can rescue them because the new pin travels in an MSI that the refusing lane must deliver. MUST be separate from the agent-policy and config-signing keys; empty means this device can never update")
	planFile := flag.String("plan-file", "", "path to the LOCAL fallback plan JSON (default: <ProgramData>\\DSSE\\update\\plan.json). Used before this device has been sent a rollout plan, and for MaxAttempts, which the fleet plan does not carry.")
	rolloutFile := flag.String("rollout-plan-file", "", "path to the signed rollout plan the agent couriers (default: <ProgramData>\\DSSE\\update-plan.json). Carries the FREEZE and this device's wave start.")
	planPin := flag.String("plan-pin", "", "public key (hex) the rollout plan is verified against, in either accepted shape (64-char Ed25519, or 130-char uncompressed ECDSA-P256 starting 04 — the reference Edge prints the latter at startup) — the agent-policy key, NOT the update key: this document says WHEN, and the one that says WHAT to run is signed by a key no edge holds. Empty accepts the plan unverified and says so, which means the freeze is only as strong as the file's permissions.")
	updatePublisher := flag.String("update-publisher", "", "who must have BUILT a package before it is installed as SYSTEM, as `subject:<Authenticode Subject O=>` (durable across certificate renewals — the macOS Team-ID analog) or `thumbprint:<leaf certificate SHA-256>` (exact, and invalidated by a renewal). This is a DIFFERENT authority from --update-pin: that key says which VERSION may run, this says who built the bytes, and an attacker holding the first can then only choose a version this publisher really built. Empty means no check, which installs on the manifest signature alone and says so on every pass.")
	steerExe := flag.String("steer-exe", "", "the agent binary used to take steering down before an install (default: beside this executable)")
	failOpen := flag.Bool("fail-open", false, "posture: this endpoint may be disarmed before the installer runs. Must match the install-time posture the driver's owner handle uses")
	flag.Parse()

	switch {
	case *reportAgain:
		os.Exit(agentupdate.ForgetAssumedOutcomeCommand(filepath.Join(stateRoot(), "journal.json"), os.Stdout, os.Stderr))
	case *serviceInstall:
		if err := installService(serviceRunArgs(serviceRunFlags{
			updatePins: *updatePins, planPin: *planPin, failOpen: *failOpen,
			manifestFile: *manifestFile, planFile: *planFile, rolloutFile: *rolloutFile,
			steerExe: *steerExe, interval: *interval,
		})); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-updater: install: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("dsse-updater: %s installed (LocalSystem, auto-start)\n", serviceName)
		return
	case *serviceUninstall:
		if err := uninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-updater: uninstall: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("dsse-updater: %s removed\n", serviceName)
		return
	}

	u, err := build(buildOpts{
		manifestURL: *manifestURL, manifestFile: *manifestFile, updatePins: *updatePins,
		planFile: *planFile, rolloutFile: *rolloutFile, planPin: *planPin,
		steerExe: *steerExe, failOpen: *failOpen, dryRun: *dryRun, publisher: *updatePublisher,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: %v\n", err)
		os.Exit(2)
	}

	switch {
	case *status:
		printStatus(u)
	case *serviceRun:
		if p := redirectServiceLogs(); p != "" {
			fmt.Printf("===== dsse-updater service start version=%s+%s log=%s =====\n", buildVersion, buildCommit, p)
		}
		// ★ THE PUBLISHER REQUIREMENT IS STATED AT START, because its ABSENCE is invisible in every other way: a
		// device that checks nobody's signature updates exactly as happily as one that does. The macOS daemon has
		// printed this since the check existed there, and the line is here for the same reason and in the same
		// place — once per start rather than once per pass, since a line that repeats every thirty minutes is a
		// line people filter out. That is the documented history of "no update-signing key is pinned".
		fmt.Printf("dsse-updater: package publisher: %s\n", u.publisher.Describe())
		if err := svc.Run(serviceName, &updaterService{interval: *interval, u: u}); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-updater: service: %v\n", err)
			os.Exit(1)
		}
	case *rollback || *rollbackTo != "":
		if !runRollback(u, *rollbackTo) {
			os.Exit(1)
		}
	case *once:
		evt := openEventLog()
		defer evt.close()
		tick(u, evt, newReportThrottle())
	default:
		fmt.Fprintln(os.Stderr, "dsse-updater: one of --once / --status / --rollback / --service-install / --service-uninstall / --service-run is required")
		os.Exit(2)
	}
}

// updater is one device's configured loop: what updateplatform.Tick needs, plus what the reporting needs.
type updater struct {
	deps   updateplatform.TickDeps
	source string
	// store is the SAME instance the Platform was given, so --status reports the inventory the rollback would
	// actually draw from rather than a second store built from the same default and assumed to match.
	store *rollbackstore.Store
	// publisher is what this device requires of a package's BUILDER, kept here so --status can report both the
	// requirement and its verdict on every stored package — the two facts an operator needs BEFORE arming it,
	// and before an incident makes the rollback path's answer urgent.
	publisher updateplatform.PublisherRequirement
	// rolloutPath / planPins / localPlan are re-read on EVERY pass rather than captured at startup. A freeze an
	// operator sets has to reach a running service, and a halt that needs a service restart is not a halt.
	rolloutPath string
	planPins    []string
	localPlan   Plan
}

// acceptedPlanFloor is the newest rollout plan this device has accepted, from the journal — the ratchet that
// makes replaying an older signed plan useless. An unreadable journal answers zero, which accepts the next
// plan and starts the ratchet again: failing closed here would mean a damaged journal permanently refuses
// every plan, including the halt.
func (u *updater) acceptedPlanFloor() time.Time {
	j, err := agentupdate.LoadJournal(u.deps.JournalPath)
	if err != nil {
		return time.Time{}
	}
	return j.AcceptedPlanFloor()
}

// applyRollout re-reads the couriered plan and folds it into this pass's config.
//
// Errors are NOT returned: LoadRollout answers a damaged plan with a FREEZE, and that answer is the one that
// must reach the gate. Returning the error instead would abort the pass — leaving the device unfrozen and the
// halt unapplied, which is the exact inversion this whole path exists to prevent.
func (u *updater) applyRollout(exp agentupdate.RolloutExpectation) agentupdate.Rollout {
	r, err := agentupdate.LoadRollout(u.rolloutPath, u.planPins, time.Now(), exp)
	if err != nil {
		fmt.Printf("dsse-updater: %v\n", err)
	}
	u.deps.Config.Window = u.localPlan.Apply(r).Window()
	u.deps.Config.Frozen = r.Frozen
	// ★ The hold is a value the gate reads. Clearing the wave start alone withheld nothing: Run replaces a zero
	// start with the attempt's own, by design, so a device with no schedule is not stuck forever.
	u.deps.Config.PlanHold = r.WaveWithheld
	u.deps.Config.EligibleSince = r.EligibleSince
	return r
}

// buildOpts is the flag set, named so the wiring below reads as configuration rather than as nine positional
// strings whose order nobody can check.
type buildOpts struct {
	manifestURL, manifestFile, updatePins string
	planFile, rolloutFile, planPin        string
	steerExe, publisher                   string
	failOpen, dryRun                      bool
}

// build wires the platform-specific pieces into the pass that updateplatform owns.
func build(o buildOpts) (*updater, error) {
	manifestURL, manifestFile, pins := o.manifestURL, o.manifestFile, o.updatePins
	planFile, steerExe, failOpen, dryRun := o.planFile, o.steerExe, o.failOpen, o.dryRun
	if manifestURL != "" {
		// Not silently ignored. The manifest is a FILE another component places — see
		// updateplatform.FileManifestSource for why the signature rather than the channel is the trust
		// boundary — and accepting a URL here while never fetching it would leave an operator believing this
		// device is subscribed to something.
		return nil, fmt.Errorf("--manifest-url is not implemented: this updater reads a signed manifest from a " +
			"file that the agent, an MDM, or an administrator places. Point --manifest-file at it")
	}
	if manifestFile == "" {
		manifestFile = updateplatform.DefaultManifestPath()
	}
	plan := planFile
	if plan == "" {
		plan = filepath.Join(stateRoot(), "plan.json")
	}
	// ★ A BROKEN LOCAL PLAN MUST NOT BLOCK AN EMERGENCY ROLLBACK (2026-08-11, second review). This file carries
	// MaxAttempts and the fallback maintenance window — neither of which a rollback consults: a rollback runs
	// when the fleet published something bad or an agent is too broken to assess, which is exactly when the
	// device's other files are least trustworthy. Refusing to build the updater over an unrelated typo would
	// take the recovery path away at the moment it exists for.
	//
	// So a plan that cannot be read is reported and the DEFAULT is used. An update still evaluates the gate,
	// with the default window, and says loudly which plan it is using.
	p, err := LoadPlan(plan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: ★ the local plan %s could not be read (%v); using the built-in "+
			"defaults. A rollback does not consult it at all; an update will use the DEFAULT maintenance window "+
			"until this file is corrected\n", plan, err)
		p = DefaultPlan()
	}

	store := rollbackstore.New(rollbackstore.DefaultRoot())
	// ★ PARSED ONCE, HERE, so that a defect is reported at start-up rather than discovered by an install. A
	// requirement that cannot be used does NOT stop this device updating — see ParsePublisherRequirement for
	// why refusing would make the only repair path the one being refused — so the report is the whole of the
	// protection against a typo, and it has to happen where somebody reads it.
	publisher := updateplatform.ParsePublisherRequirement(o.publisher)
	if publisher.Defect != "" {
		log.Printf("%s", publisher.Describe())
	}
	var platform agentupdate.Platform = &updateplatform.Platform{
		SteerExe:  steerExe,
		FailOpen:  failOpen,
		Store:     store,
		Publisher: publisher,
	}
	// ★ The rehearsal is Config.DryRun, NOT a Platform whose destructive methods refuse (2026-08-11).
	//
	// The refusing-Platform form was structurally appealing — nothing downstream has to remember a flag — and it
	// had a consequence nobody had hit: Run treats a Disarm or Execute error as a FAILED ATTEMPT. It records the
	// failure, counts it against MaxAttempts (3), and on the third one marks the version POISONED — "versions
	// this device will no longer attempt".
	//
	// So three rehearsals of a release made the device refuse that release for good. And because the disarm is
	// only reached once the gate is OPEN, it happened precisely when someone tested during the maintenance
	// window — the case worth testing. The safest thing an operator can do was the thing that blocked the
	// rollout, silently, three tries in.
	//
	// Config.DryRun stops inside the sequencing, after the gate and after restore material, before anything
	// mutates: no disarm, no execute, no journal write, no attempt counted.

	rollout := o.rolloutFile
	if rollout == "" {
		rollout = filepath.Join(datadir.Root(), "update-plan.json")
	}

	// ★★ THE SEPARATION IS ENFORCED HERE, AND THIS PLATFORM NEVER ENFORCED IT AT ALL (2026-08-13, thirty-first
	// review #9). The rule — the key that authorises RUNNING CODE must not also authorise the rollout plan —
	// lived in one lane of the macOS agent, and `--update-pin X --plan-pin X` was expressible on both. The plan
	// carries the FREEZE, so one key for both means the party a halt exists to stop is the party who signs the
	// halt: a compromised release key could publish a bad build and lift the stop that would have caught it.
	//
	// The PLAN key is dropped rather than the update key. Refusing the update key would leave the device unable
	// to update at all, which is the state this product spent weeks escaping; dropping the plan key leaves it
	// unable to verify a plan, which LoadRollout already has an answer for.
	planPins, refusedPlanPins := agentupdate.SeparatePlanKeys(splitPins(pins), splitPins(o.planPin))
	if len(refusedPlanPins) > 0 {
		log.Printf("★ REFUSED %d plan-signing key(s) that are also this device's UPDATE-signing key: one key "+
			"signing both the release and the halt means a compromised release key can also unfreeze the fleet",
			len(refusedPlanPins))
	}

	return &updater{
		source:      manifestFile,
		store:       store,
		publisher:   publisher,
		rolloutPath: rollout,
		planPins:    planPins,
		localPlan:   p,
		deps: updateplatform.TickDeps{
			Source:   updateplatform.FileManifestSource{Path: manifestFile, TrustedKeys: splitPins(pins)},
			Platform: platform,
			Config: agentupdate.Config{
				Window:      p.Window(),
				MaxAttempts: p.MaxAttempts,
				Platform:    agentupdate.PlatformWindows,
				Arch:        runtimeArch(),
				DryRun:      dryRun,
				// The WFP redirect lives in the kernel and outlives this process, which is why an interrupted
				// attempt here means the network must be checked before anything else is tried on the box.
				SteeringSurvivesAgent: true,
			},
			JournalPath:  filepath.Join(stateRoot(), "journal.json"),
			ManifestPath: manifestFile,
		},
	}, nil
}

func splitPins(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runtimeArch maps this build to the manifest's vocabulary. A closed set: an architecture nobody named must
// not silently match a manifest written for another one.
// ★ EVERYTHING THAT IS NOT ARM64 WAS AMD64 (2026-08-13, twenty-ninth review). A 32-bit process on 64-bit
// Windows reads x86 here, and an absent variable read as amd64 too — so a box could be handed an MSI for an
// architecture it cannot run. PROCESSOR_ARCHITEW6432 is what the OS actually is when this process is the
// 32-bit one, and an answer this device cannot establish is reported rather than guessed.
func runtimeArch() string {
	native := strings.TrimSpace(os.Getenv("PROCESSOR_ARCHITEW6432"))
	if native == "" {
		native = strings.TrimSpace(os.Getenv("PROCESSOR_ARCHITECTURE"))
	}
	switch strings.ToUpper(native) {
	case "ARM64":
		return agentupdate.ArchARM64
	case "AMD64":
		return agentupdate.ArchAMD64
	default:
		// Not something this build knows how to ask for. Returning amd64 would let msiexec be handed a package
		// for another architecture; an empty arch makes the endpoint answer "nothing published for it", which
		// is the true statement.
		return ""
	}
}

// describeRollback answers, in one line, what --rollback would install and whether it could.
//
// ★ EVERY branch ends with the INVENTORY, and that is not decoration — it is the only thing that makes the
// refusing branches actionable. Measured on win-dev-1 2026-08-11: a box holding 0.1.0 and 0.2.0, upgraded by
// an operator running msiexec rather than by the service, printed "nothing — this box has never recorded a
// version to come back from" and stopped there. True, and read as "there is no material here" — while
// `--rollback-to 0.1.0+37949d7d.dirty` would have worked. The journal answers what the DEVICE did; the store
// answers what it HOLDS, and only the second one bounds --rollback-to. The flag's own help already told the
// operator that --status lists the held versions; it did not.
//
// The macOS line has said this since it was written. This one had drifted, in the direction that reads as an
// empty store — see describeRollback in clients/macos/updater/main_darwin.go, whose wording this now mirrors.
func describeRollback(u *updater, j *agentupdate.Journal) string {
	inventory := "none stored"
	held, herr := u.store.List()
	switch {
	case herr != nil:
		// Reported rather than swallowed: an unreadable store and an empty one are the same sentence to a
		// reader and opposite facts to whoever has to fix it.
		inventory = fmt.Sprintf("the store could not be listed (%v)", herr)
	case len(held) > 0:
		names := make([]string, 0, len(held))
		for _, e := range held {
			names = append(names, e.Version)
		}
		inventory = "held: " + strings.Join(names, ", ")
	}

	target := strings.TrimSpace(j.FromVersion)
	if j.IsRollback() {
		return fmt.Sprintf("★ nothing automatically — the last attempt was itself a rollback to %s, so from_version "+
			"(%s) is the build already abandoned. Name a version with --rollback-to. (%s)",
			j.TargetVersion, j.FromVersion, inventory)
	}
	if target == "" {
		return fmt.Sprintf("★ nothing automatically — this box has never recorded a version to come back from, so "+
			"--rollback has no target. Name one with --rollback-to. (%s)", inventory)
	}
	if _, err := u.deps.Platform.RestoreMaterialFor(target); err != nil {
		// The reason is QUOTED, not summarised: "holds no package" and "holds one that predates the mechanism"
		// need different repairs and only the callee knows which this is.
		return fmt.Sprintf("★ NOTHING — it would go to %s and cannot: %v (%s)", target, err, inventory)
	}
	return fmt.Sprintf("install %s, and refuse the version it leaves on this box. (%s)", target, inventory)
}

// printPublisherVerdicts answers, for every package this box holds, what the publisher gate WOULD say about it.
//
// ★★ IT RUNS EVEN WITH NO REQUIREMENT SET, AND THAT IS THE WHOLE VALUE. A new gate on a privileged install path
// has one dangerous failure — it is armed, it is wrong, and the fleet stops updating with a message about
// signatures — and the only honest way to avoid it is to let an operator SEE the verdict on real packages
// before anything depends on it. With nothing configured this reads the signature and reports what it found,
// so `-UpdatePublisher subject:...` can be chosen from what these bytes actually say rather than from what
// somebody believes the build signs with.
//
// It also answers the rollback question before the incident: ExecuteRollback asks the same gate, so a stored
// MSI that would be refused is a recovery path that is not there — and that is a fact to learn on a quiet
// afternoon.
func printPublisherVerdicts(u *updater) {
	held, err := u.store.List()
	if err != nil {
		fmt.Printf("  ★ stored pkgs   : the store could not be listed (%v), so no verdict can be given for the "+
			"packages a rollback would use\n", err)
		return
	}
	if len(held) == 0 {
		return
	}
	for _, e := range held {
		path, perr := u.store.Path(e.Version)
		if perr != nil {
			fmt.Printf("  stored %-14s : the path could not be resolved (%v)\n", e.Version, perr)
			continue
		}
		// The observed identity is printed alongside the verdict, not instead of it: "refused" tells an operator
		// the gate is unhappy, and only the identity tells them whether the requirement or the package is wrong.
		sig := authenticode.Signature(path)
		switch verdict := u.publisher.Check(sig); {
		case !u.publisher.Configured():
			fmt.Printf("  stored %-14s : signed=%t subject_o=%q thumbprint=%s (no requirement set, so nothing is "+
				"refused)\n", e.Version, sig.Valid, sig.Org, orNone(sig.Thumbprint))
		case verdict != nil:
			fmt.Printf("  ★ stored %-12s : WOULD BE REFUSED — %v\n", e.Version, verdict)
		default:
			fmt.Printf("  stored %-14s : publisher OK (subject_o=%q)\n", e.Version, sig.Org)
		}
	}
}

func orNone(s string) string {
	if s == "" {
		return "unreadable"
	}
	return s
}

// runRollback is the operator's recovery path: put back the version this box came from. It reports whether the
// command did what was asked.
//
// ★ NO MANIFEST, NO PLAN, NO GATE — deliberately, and identically to the macOS side. A rollback runs when the
// control plane published something bad or when an agent is too broken to be assessed; requiring a verified
// manifest would make recovery depend on the publishing that caused the incident, and requiring a maintenance
// window would make a broken box wait until 02:00. What bounds it instead is the STORE: only an MSI this box
// already holds, and only one whose own launch condition can honour the authorisation.
// installedVersion is what the MSI recorded when it last installed here
// (HKLM\SOFTWARE\DSSE\Agent\InstalledVersion, the same value the MDM detection rule reads).
//
// ★ IT IS NOT AND MUST NOT BECOME A FALLBACK FOR RunningVersion. Those answer different questions, and they
// differ on precisely the box that matters — the one holding new bytes and running old code. This value is
// used for ONE thing: naming the build a rollback is escaping, so it can be refused afterwards. Measured on
// win-dev-1 (2026-08-11): a rollback landed on a box whose agent could not start, and the journal came back
// with poisoned=[] — the version just escaped was free to come back on the next tick. "Do not install this
// package here again" is a statement about the installed package, so this is the right source for it.
//
// Best-effort and unreported: an empty answer means Rollback says, in full, that nothing was refused.
func installedVersion() string {
	be, err := configstore.ProductionRegistryBackend()
	if err != nil {
		return ""
	}
	v, ok, err := be.Get(configstore.ValueInstalledVersion)
	if err != nil || !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

func runRollback(u *updater, to string) bool {
	// ★ THE LOCK COMES FIRST, then the journal. Reading it before taking the lock meant a concurrent tick could
	// write a transition between the read and this rollback's own write, and the later writer would erase it.
	lock, lerr := agentupdate.LockDevice(updateplatform.LockPath(u.deps.JournalPath))
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: not rolling back: %v. The DsseUpdater service evaluates on a timer "+
			"and an install may be starting; try again in a moment\n", lerr)
		return false
	}
	defer lock.Release()

	j, err := agentupdate.LoadJournal(u.deps.JournalPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: not rolling back: %v. Until this file is readable or removed by hand, "+
			"this box cannot be told apart from one whose previous update stopped half way\n", err)
		return false
	}

	out, rerr := agentupdate.Rollback(j, agentupdate.RollbackRequest{ToVersion: to, LeavingVersion: installedVersion()},
		u.deps.Config, u.deps.Platform,
		func(jj *agentupdate.Journal) error { return jj.Save(u.deps.JournalPath) }, time.Now())
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: the rollback was abandoned because its record could not be kept: %v\n", rerr)
		return false
	}
	fmt.Printf("dsse-updater: version=%s+%s action=%s reason=%q\n", buildVersion, buildCommit, out.Action, out.Reason)
	if out.Action == agentupdate.ActionRollingBack {
		// "Handed to msiexec" is not "running the old version again", the same distinction the install path had
		// to learn: a receipt and the running code are different facts.
		fmt.Println("  msiexec is running. Confirm it LANDED — do not assume it from this line:")
		fmt.Printf("    %s --status     # running version, and journal phase=%s once confirmed\n",
			os.Args[0], agentupdate.PhaseRolledBack)
		fmt.Println("  The service has to restart before it reports its version, so give it a moment.")
	}
	return out.Action != agentupdate.ActionRefused
}

// tick performs one pass and reports it to both sinks.
func tick(u *updater, evt *eventWriter, thr *reportThrottle) Result {
	// ★ ONE MANIFEST, ONE LOCK. This used to fetch the manifest to judge the plan and then call Tick, which
	// fetched it again — a courier replacing the file in between meant a wave opened for the first release
	// authorised the install of the second. Tick now reads it once, inside the device lock, and hands it here.
	// The journal's plan ratchet moves in there too, where the journal is already being read and written.
	deps := u.deps
	deps.ResolveRollout = func(m agentupdate.Manifest) agentupdate.Rollout {
		// ★ Who this box proved itself to be, as the RUNNING agent recorded it (runstate). Without it a validly
		// signed plan for a machine in an earlier wave opens this one's. Empty until the agent records it —
		// which is reported rather than treated as a match, exactly as on macOS.
		device, tenant := runstate.Addressing()
		return u.applyRollout(agentupdate.RolloutExpectation{
			Version:        m.Version,
			NotBefore:      u.acceptedPlanFloor(),
			MaxAge:         agentupdate.DefaultPlanMaxAge,
			DeviceIdentity: device,
			TenantID:       tenant,
		})
	}
	deps.ResolveWindow = func(r agentupdate.Rollout) agentupdate.MaintenanceWindow {
		return u.localPlan.Apply(r).Window()
	}
	res, err := updateplatform.Tick(context.Background(), deps, time.Now())
	// ★ THE OUTCOME LEAVES THIS DEVICE, and until 2026-08-12 it did not. Every mechanism in this lane worked
	// and the control plane's fleet view read `total: 0`, because nothing ever called the ingest route. The
	// updater cannot send it (no network identity, deliberately), so it QUEUES and DsseSteer — which holds the
	// device certificate and already beats on a timer — drains it.
	//
	// Best-effort by contract: a device that cannot write a report has still performed the update. The failure
	// is printed rather than swallowed, because "the fleet view is empty" and "nothing happened" must not read
	// the same from here either.
	// ★ THE REPORTS ARE ALREADY QUEUED. Tick writes them inside the device lock — the check, the append and the
	// suppression marker are one operation, and doing it out here (after the lock is released) let the service
	// and a hand-run --once both decide a refusal was unreported and both store it.
	//
	// What is left is the addressing, which only this process can resolve, and it is stamped by the SENDER
	// anyway from the certificate it holds. So this loop reports rather than writes.
	if len(res.Reports) > 0 {
		fmt.Printf("dsse-updater: %d outcome(s) queued for the fleet view\n", len(res.Reports))
	}
	r := Classify(res, err, u.source)

	line := fmt.Sprintf("dsse-updater: version=%s+%s action=%s reconciled=%t reason=%q",
		buildVersion, buildCommit, r.Action, res.Reconciled, r.Reason)
	fmt.Println(line)
	for _, n := range res.Notes {
		fmt.Printf("dsse-updater: %s\n", n)
	}

	if !r.Reportable {
		// The quiet passes still go to the FILE. "Running and nothing published" has to be distinguishable
		// from "not running at all", and only a file that records every pass can tell those apart.
		if cleared := thr.clear(); cleared != "" {
			evt.info(evtCleared, fmt.Sprintf("dsse-updater: the condition previously reported has CLEARED (was: %s). "+
				"Current state: %s", cleared, r.Reason))
		}
		return r
	}
	if !thr.should(r.Action + "|" + r.Reason) {
		return r
	}
	switch r.Action {
	case ActionUnverified:
		evt.err(evtRefusedManifest, line)
	case ActionBlocked:
		evt.err(evtBlocked, line)
	case agentupdate.ActionNone:
		// Only reaches here when a pass closed out a completed attempt, which Classify marks reportable: it is
		// the one moment a finished update is knowable, because the installer replaced the process that
		// started it.
		evt.info(evtProgress, line)
	case agentupdate.ActionExecuting:
		evt.warn(evtExecuting, line)
	case agentupdate.ActionResumed:
		evt.err(evtInterrupted, line)
	case agentupdate.ActionRefused:
		evt.warn(evtRefused, line)
	default:
		evt.info(evtProgress, line)
	}
	return r
}

// printStatus answers "what would this device do, and why" without doing any of it. The question an operator
// asks about a device that has not updated is never "what is the code" — it is "what is this box waiting for".
func printStatus(u *updater) {
	fmt.Printf("dsse-updater %s+%s\n", buildVersion, buildCommit)
	w := u.deps.Config.Window
	fmt.Printf("  manifest source : %s\n", u.source)
	if src, ok := u.deps.Source.(updateplatform.FileManifestSource); ok {
		fmt.Printf("  pinned keys     : %d\n", len(src.TrustedKeys))
		if len(src.TrustedKeys) == 0 {
			fmt.Println("  ★ WARNING no update-signing key is pinned, so this device can NEVER update.")
		}
	}
	fmt.Printf("  window          : %s-%s unattended=%t ac=%t idle_minutes=%d deadline_days=%d\n",
		w.LocalStart, w.LocalEnd, w.RequireUnattended, w.RequireACPower, w.RequireIdleMinutes, w.DeadlineDays)
	if v, err := u.deps.Platform.RunningVersion(); err == nil {
		fmt.Printf("  running version : %s\n", v)
	} else {
		fmt.Printf("  running version : UNKNOWN — %v\n", err)
	}
	c := u.deps.Platform.Conditions(time.Now())
	fmt.Printf("  conditions      : in_use=%t (known=%t) idle=%s (known=%t) ac=%t (known=%t)\n",
		c.InUse, c.InUseKnown, c.IdleFor.Round(time.Second), c.IdleKnown, c.OnACPower, c.PowerKnown)
	// The manifest FIRST, and through the same source the tick uses, so --status cannot report a state the
	// next pass would disagree with.
	m, merr := u.deps.Source.Fetch(context.Background(), time.Now())
	fmt.Printf("  manifest        : %s\n", DescribeManifest(m, merr, u.source))

	sdevice, stenant := runstate.Addressing()
	statusExp := agentupdate.RolloutExpectation{NotBefore: u.acceptedPlanFloor(), MaxAge: agentupdate.DefaultPlanMaxAge,
		DeviceIdentity: sdevice, TenantID: stenant}
	if merr == nil {
		statusExp.Version = m.Version
	}
	r := u.applyRollout(statusExp)
	fmt.Printf("  rollout plan    : %s\n", r.Source)
	if r.Frozen {
		fmt.Printf("  ★ FROZEN        : %s\n", r.FrozenReason)
	}
	if r.WaveWithheld != "" {
		fmt.Printf("  ★ WAVE WITHHELD : %s\n", r.WaveWithheld)
	}
	// ★ WHAT A ROLLBACK WOULD DO, on a good day. "Can this box go back" has to be answerable before the
	// incident: during one, the answer arrives too late to change anything, and a box with no stored MSI has to
	// be recovered by hand.
	fmt.Printf("  publisher       : %s\n", u.publisher.Describe())
	printPublisherVerdicts(u)
	if j, jerr := agentupdate.LoadJournal(u.deps.JournalPath); jerr == nil {
		fmt.Printf("  rollback would  : %s\n", describeRollback(u, j))
		if j.LastFailureReason != "" {
			fmt.Printf("  last failure    : %s\n", j.LastFailureReason)
		}
	}
	if !r.EligibleSince.IsZero() {
		fmt.Printf("  wave opens      : %s (%s)\n", r.EligibleSince.Format(time.RFC3339), r.Plan.WaveReason)
	}
	if j, err := agentupdate.LoadJournal(u.deps.JournalPath); err == nil {
		fmt.Printf("  journal         : phase=%s target=%q poisoned=%v\n", j.Phase, j.TargetVersion, j.PoisonedVersions())
	} else {
		fmt.Printf("  journal         : UNREADABLE — %v\n", err)
	}
}

// --- the service --------------------------------------------------------------------------------------------

type updaterService struct {
	interval time.Duration
	u        *updater
}

func (s *updaterService) Execute(_ []string, r <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	st <- svc.Status{State: svc.StartPending}
	st <- svc.Status{State: svc.Running, Accepts: accepted}

	evt := openEventLog()
	defer evt.close()
	evt.info(evtStarted, fmt.Sprintf("dsse-updater started version=%s+%s interval=%s source=%s log=%s",
		buildVersion, buildCommit, s.interval, s.u.source, logFilePath()))
	thr := newReportThrottle()

	t := time.NewTicker(s.interval)
	defer t.Stop()
	tick(s.u, evt, thr)
	for {
		select {
		case <-t.C:
			tick(s.u, evt, thr)
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Stopping this service must never change the box. It is the one component here that performs a
				// destructive act, and its exit is not one of them: an install already handed to msiexec is
				// detached and continues, which is what Execute's Release() is for.
				st <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

// serviceRunArgs is the command line the SCM will start this service with.
//
// ★ --service-install USED TO REGISTER ["--service-run"] AND NOTHING ELSE (2026-08-13, twenty-eighth review).
// Every pin and posture flag given on the install command line was silently dropped, and --service-run reads
// its keys from flags alone — there is no config to recover them from. So the registered service ran with NO
// update key (the device can never update, and says so as a REFUSED-manifest event every tick, reporting a
// misconfiguration as an attack), no plan pin, and fail-open=false whatever the box was provisioned as. The
// "shipped keyless, permanently unable to update" defect, arriving through the installer instead of the
// package.
// serviceRunFlags is everything the SCM-started service needs that --service-run reads from flags alone.
//
// ★ THE FIRST FIX CARRIED THREE OF THEM (2026-08-13, twenty-ninth review). Adding the pins and the posture
// left --manifest-file, --plan-file, --rollout-plan-file, --steer-exe and --interval still discarded, so a
// deployment that puts those documents anywhere but the default path registered a service that reads paths
// nobody writes — and evaluates on a schedule nobody chose. A partial fix to "the install line is thrown
// away" reads as a fixed one.
type serviceRunFlags struct {
	updatePins   string
	planPin      string
	publisher    string
	failOpen     bool
	manifestFile string
	planFile     string
	rolloutFile  string
	steerExe     string
	interval     time.Duration
}

func serviceRunArgs(f serviceRunFlags) []string {
	args := []string{"--service-run"}
	for _, kv := range []struct {
		flag  string
		value string
	}{
		{"--update-pin", f.updatePins},
		{"--plan-pin", f.planPin},
		{"--update-publisher", f.publisher},
		{"--manifest-file", f.manifestFile},
		{"--plan-file", f.planFile},
		{"--rollout-plan-file", f.rolloutFile},
		{"--steer-exe", f.steerExe},
	} {
		if v := strings.TrimSpace(kv.value); v != "" {
			args = append(args, kv.flag, v)
		}
	}
	if f.failOpen {
		args = append(args, "--fail-open")
	}
	// Only when it differs from the default, so an ordinary install registers the ordinary command line.
	if f.interval > 0 && f.interval != 30*time.Minute {
		args = append(args, "--interval", f.interval.String())
	}
	return args
}

func installService(runArgs []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("%s already exists (use --service-uninstall first)", serviceName)
	}
	// No ServiceDependency on DsseSteer, and this one is worth spelling out because the reasoning is the
	// opposite of the watchdog's. The watchdog must not depend on the agent because it watches for its absence.
	// This process must not depend on it either, but for a different reason: an installer is about to stop and
	// replace that service, and a dependency would make the SCM stop this process in the middle of the update
	// it is running.
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "Lantern DSSE Agent Updater",
		Description:  "Installs signed DSSE agent releases inside the maintenance window this device was given.",
		StartType:    mgr.StartAutomatic,
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		ErrorControl: mgr.ErrorNormal,
	}, runArgs...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
	}, 86400); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	if err := installEventSource(); err != nil {
		fmt.Printf("dsse-updater: WARNING could not register the %q event source (%v) — updates will be recorded in "+
			"%s but NOT in the Windows event log\n", eventSource, err, logFilePath())
	}
	return s.Start()
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, qerr := s.Query(); qerr == nil && st.State != svc.Stopped {
		if _, cerr := s.Control(svc.Stop); cerr != nil {
			return fmt.Errorf("stop: %w", cerr)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if st, qerr := s.Query(); qerr == nil && st.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	removeEventSource()
	return s.Delete()
}
