//go:build windows

// profileapply verifies a signed L1 install profile and persists it to the config store at install time. The MSI
// invokes it from a deferred SYSTEM custom action with the profile that was passed via the CONFIG= property (or
// bundled). On success it can flip DsseSteer to auto-start — the service is installed Start=demand precisely so
// it does NOT come up fail-closed before a transport-bearing profile exists; only AFTER a verified profile is
// persisted is it safe to let it auto-start.
//
//	profileapply --apply --config <profile.json> [--pin <hex>] [--set-start-auto]
//	profileapply --reconcile-start-type [--pin <hex>]
//	profileapply --status [--pin <hex>]
//
// TRUST ANCHOR (review S1): the profile is verified against a pin that MUST NOT come from the mutable store.
// The pin is baked into this binary at build time (-ldflags "-X main.trustAnchorPin=<hex>"); --pin overrides it
// for dev/lab/MDM. The runtime agent (DsseSteer --service-run, M8.3b-2) likewise verifies the stored envelope
// against its OWN baked anchor, never a store value.
//
// Exit: 0 ok, 1 failure (the MSI custom action treats a bad/absent profile as non-fatal → the agent falls back
// to fail-closed SafeDefaults), 2 usage.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// trustAnchorPin is set at build time: -ldflags "-X main.trustAnchorPin=<64-hex>". Empty in dev builds.
var trustAnchorPin string

func main() {
	apply := flag.Bool("apply", false, "verify + persist the signed install profile to the config store")
	clear := flag.Bool("clear", false, "remove the persisted profile from the config store (uninstall)")
	status := flag.Bool("status", false, "print the config-store profile state")
	harden := flag.Bool("harden", false, "set the SYSTEM/Admin-write, Users-read DACL on the config-store key (defense-in-depth)")
	configPath := flag.String("config", "", "path to the signed install-profile envelope JSON (for --apply)")
	pinOverride := flag.String("pin", "", "trust-anchor public key hex (overrides the baked-in anchor; dev/MDM)")
	setStartAuto := flag.Bool("set-start-auto", false, "after a successful --apply, set the DsseSteer service to auto-start")
	reconcileConfigPin := flag.Bool("reconcile-config-pin", false, "restore DsseSteer's pins from the PROTECTED verifier store when the service names NO verifier, and record the in-force key into that store when it does — the state a major upgrade leaves, because it recreates the service from the package and drops the key provisioning wrote there. Safe to run on every install and upgrade: it acts ONLY when the arguments name nothing, and reports without changing anything in every other case.")
	captureBeforeUpgrade := flag.Bool("capture-before-upgrade", false, "save the authorities DsseSteer currently names (--config-pin, --agent-policy-pin, --update-pin) into the protected verifier store, BEFORE a major upgrade deletes the service that holds them. Run as an IMMEDIATE custom action sequenced before RemoveExistingProducts, which is where the old product still exists — every deferred action of the new package runs after it is already gone. Exits non-zero when it had something to save and could not, so the install stops with the existing product intact.")
	reconcileStart := flag.Bool("reconcile-start-type", false, "derive DsseSteer's start type from the persisted profile and the enrolment on disk, apply it, AND START the service. Safe to run on every install and upgrade: it acts ONLY on a box that is already enrolled with a transport-bearing profile, and changes nothing otherwise. The start matters because a major upgrade STOPS DsseSteer and never restarts it (its ServiceControl has no Start, unlike the watchdog and updater), and the start type alone only decides the next boot.")
	restoreProfile := flag.Bool("restore-profile", false, "if the config store holds no usable profile, restore the escrowed copy from %ProgramData%\\DSSE (written there by every successful --apply, outside MSI component tracking so uninstall cannot reach it). Safe to run on every install and upgrade: it changes NOTHING on a box that already holds a verified profile, and the restored envelope is re-verified against the baked-in anchor and the anti-rollback floor like any other apply. Without it, uninstall+reinstall leaves a device that cannot steer until the control plane re-issues a profile — measured, 2026-08-21.")
	stashRollbackMSI := flag.String("stash-rollback-msi", "", "copy this installer package into the rollback store (%ProgramData%\\DSSE\\rollback), keyed by the version the just-installed agent reports. The MSI passes [OriginalDatabase]. Without this the updater has no restore material and refuses every update.")
	rollbackKeep := flag.Int("rollback-keep", 3, "how many packages to retain in the rollback store after --stash-rollback-msi (the version just installed is always kept)")
	clearRollback := flag.Bool("clear-rollback-store", false, "remove every stored rollback package (uninstall). The store is written outside MSI component tracking, so RemoveFiles never reaches it.")
	provision := flag.Bool("provision", false, "provision this device from the two artefacts a customer receives: --config <the profile downloaded from the Console> and --token <the file holding the one-time enrolment token>. Derives and installs everything else from the profile deployment block: the transport anchors, this organization interception root (into the machine Root store), and the enrolment seed the agent enrols itself with on first start. Then persists the profile. This is what makes a package deployment-generic: nothing about the organization is baked into it.")
	fromInstallerFolder := flag.String("from-installer-folder", "", "provision from the three artefacts sitting beside the installer named by this path (the MSI's own path, or the folder holding it) — which is what the Console's README tells a person the installer does. Absent artefacts are not an error here: nobody typed a path, so there is nothing to have got wrong. --config keeps its own meaning, which is 'exactly this file, and fail if it is not there'.")
	pinFile := flag.String("pin-file", "", "--provision: path to the file holding the key the profile is verified against — the fourth artefact the Console issues, placed by the operator beside the token. A profile cannot carry the key that proves it, and adopting one on first sight would approve an authority without an explicit act; see signing_key_artefact.go. An explicit --pin or a key baked into this binary still wins.")
	tokenPath := flag.String("token", "", "--provision: path to the one-time enrolment token file. Optional: a fleet enrolled by MDM, or a device that already holds an identity, has none to spend.")
	removeTrusted := flag.Bool("remove-what-provisioning-trusted", false,
		"uninstall: take back every anchor this machine was given at provisioning time — the organization's "+
			"interception root and, where this deployment's step-up portal is on a certificate it issued "+
			"itself, that authority. Matched BY FINGERPRINT against the artefacts provisioning wrote, so a "+
			"root another deployment put there is never touched. Never fails an uninstall.")
	removeRoot := flag.String("remove-interception-root", "", "uninstall: remove the interception root THIS package installed, named by the same artifact the install read, matched BY FINGERPRINT. Never by subject — another deployment can hold a root with the same name (a rotation in flight, a device moved between organizations) and taking that one is an outage. It never fails the uninstall: an uninstall that refuses leaves the machine holding both the agent and the root.")
	installRoot := flag.String("install-interception-root", "", "install the organization's interception root (a PEM, possibly carrying a rotation's old+new pair) into LocalMachine\\Root. Embedded in the package so the FIRST trust decision does not have to be learned from the network. Adding a certificate already present is a no-op; adding a DIFFERENT certificate under a subject already in the store is REFUSED, because a trust store shows only the name and two authorities sharing one has taken this product down twice.")
	flag.Parse()

	pin := trustAnchorPin
	if *pinOverride != "" {
		pin = *pinOverride
	}

	// Rollback material is handled BEFORE the config store is opened, because it has nothing to do with it.
	// Sequencing it inside the switch would make a config-store failure decide whether an installer package
	// gets kept — two unrelated things sharing one fate, and the one that would be lost is the one the box
	// needs months later when it wants to go back.
	if *stashRollbackMSI != "" {
		if err := doStashRollbackMSI(*stashRollbackMSI, *rollbackKeep); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: stash rollback msi: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *clearRollback {
		if err := doClearRollbackStore(); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: clear rollback store: %v\n", err)
			os.Exit(1)
		}
		return
	}
	// Before the config store, for the same reason the rollback material is: it has nothing to do with it, and
	// sequencing it inside the switch would let a config-store failure decide whether a machine ends up able to
	// verify intercepted TLS at all.
	if *installRoot != "" {
		if err := doInstallInterceptionRoot(*installRoot); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: install interception root: %v\n", err)
			os.Exit(1)
		}
		return
	}
	// ★ The counterpart the installer never had. It returns nil on everything it cannot do — an uninstall
	// that refuses leaves the machine holding the agent AND a CA trusted for every name on the internet,
	// which is strictly worse than either. See interception_root_removal.go.
	if *removeTrusted {
		// ★ THE UNINSTALL PATH THAT THE SHIPPED LANE ACTUALLY HAS. See
		// everything_provisioning_trusted_comes_back_out.go: -remove-interception-root only exists in a
		// package built WITH a root, and the lane this product ships installs it from a signed profile.
		doRemoveEverythingProvisioningTrusted(escrowDir())
		return
	}
	if *removeRoot != "" {
		_ = doRemoveInterceptionRoot(*removeRoot)
		return
	}

	// ★ DISPATCHED BEFORE THE CONFIG STORE IS OPENED, deliberately. This one runs as an IMMEDIATE custom
	// action in the installing user's context, and ProductionRegistryBackend CREATES HKLM\SOFTWARE\DSSE\Agent,
	// which needs administrative rights. Opening it first would make the capture fail for a reason that has
	// nothing to do with the capture, and the diagnosis would point at the config store.
	if *captureBeforeUpgrade {
		if err := doCaptureBeforeUpgrade(); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: %v\n", err)
			os.Exit(1)
		}
		return
	}

	be, err := configstore.ProductionRegistryBackend()
	if err != nil {
		fmt.Fprintf(os.Stderr, "profileapply: open config store: %v\n", err)
		os.Exit(1)
	}

	switch {
	case *restoreProfile:
		// Deliberately BEFORE reconcile-start-type in the install sequence: the start type is derived from the
		// persisted profile, so restoring one first is what lets the same install both recover the configuration
		// and bring the service back. Running it on a healthy box is a no-op that still prints what is in force.
		// A generic build resolves its verifier from protected device state.
		// This branch used to receive only the baked or --pin value, which a deployment-independent package does
		// not have. The exact case this action exists for — an empty config store with a good escrow beside it —
		// then could not re-verify the escrowed envelope even though the right key was sitting in the protected
		// store, so the restore reported "does not verify against this binary's anchor" on a box holding both
		// halves. Resolved from the same protected sources as the start-type step, and NEVER from
		// profile_signing_key.txt. The signature and anti-rollback checks inside restoreProfileFromEscrow are
		// unchanged: this supplies the key they check against, it does not bypass them.
		if pin == "" {
			resolved, from, rerr := resolveConfigVerifier("DsseSteer")
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "profileapply: the protected verifier store cannot be trusted, so the "+
					"escrowed profile cannot be re-verified: %v\n", rerr)
				os.Exit(1)
			}
			if resolved != "" {
				pin = resolved
				fmt.Println("profileapply: this build bakes no trust anchor — re-verifying the escrowed " +
					"profile against the config key " + from + " names (" + short(pin) + ")")
			}
		}
		restored, line, err := restoreProfileFromEscrow(be, pin, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("profileapply: " + line)
		_ = restored
	case *reconcileConfigPin:
		// Deliberately BEFORE reconcile-start-type in the install sequence, for the same reason restore-profile
		// is: the start type is derived from a profile the agent must be able to VERIFY, and the service is
		// started at the end of that step. Restoring the verifier after the start would leave the box holding a
		// service that has already failed to come up.
		if err := doReconcileConfigPin(); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: %v\n", err)
			os.Exit(1)
		}
	case *reconcileStart:
		if err := doReconcileStartType(be, pin); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: %v\n", err)
			os.Exit(1)
		}
	case strings.TrimSpace(*fromInstallerFolder) != "":
		// The README's promise, kept. See provision_from_the_installers_own_folder.go: absent means do
		// nothing and SAY so; present means provision, and present-but-bad still fails the install.
		cfg, tok, pinPath, found := installerFolderArtefacts(*fromInstallerFolder)
		if !found {
			fmt.Println(describeInstallerFolder(*fromInstallerFolder, cfg))
			return
		}
		if err := doProvision(be, cfg, tok, pinPath, pin); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: %v\n", err)
			os.Exit(1)
		}
	case *provision:
		if err := doProvision(be, *configPath, *tokenPath, *pinFile, pin); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: %v\n", err)
			os.Exit(1)
		}
	case *apply:
		if err := doApply(be, *configPath, pin, *setStartAuto); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: %v\n", err)
			os.Exit(1)
		}
	case *harden:
		// Opening the production backend above already created the key, so the DACL can be set now. Defense-in-
		// depth only (the real tamper guard is verify-on-read), so the MSI custom action treats a failure as
		// non-fatal (Return=ignore) — a hardening hiccup must never roll an install back, which is exactly why
		// the earlier util:PermissionEx/SecureObjects approach was replaced by this code-based step.
		if err := configstore.HardenProductionKeyACL(); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: harden: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("profileapply: config-store key ACL hardened (SYSTEM/Admin write, Users read)")
		// ★ AND THE BINARIES THEMSELVES (2026-09-09, the operator's requirement: nothing in this product may be
		// run by an account without administrative privilege). %ProgramFiles% grants BUILTIN\Users
		// ReadAndExecute and every installed file inherits it, so this is not the default and cannot be — it has
		// to be set, and set PROTECTED, on every install and every upgrade. Non-fatal like the rest of --harden,
		// but the failure is named: a partially hardened install is one where the requirement is believed to
		// hold and does not.
		if dir, derr := agentBinaryDir(); derr != nil {
			fmt.Fprintf(os.Stderr, "profileapply: harden binaries: %v\n", derr)
		} else {
			lines, herr := hardenAgentBinaries(dir)
			for _, l := range lines {
				fmt.Println("profileapply:   " + l)
			}
			if herr != nil {
				fmt.Fprintf(os.Stderr, "profileapply: ★ harden binaries: %v\n", herr)
			} else {
				fmt.Println("profileapply: the agent binaries are executable by administrators and SYSTEM only")
			}
		}
		// The same binaries exist a second time inside the stored installer packages, in a directory the
		// Windows default makes user-writable. See harden_agent_binaries_windows.go.
		dirLines, derr2 := hardenStateDirectories()
		for _, l := range dirLines {
			fmt.Println("profileapply:   " + l)
		}
		if derr2 != nil {
			fmt.Fprintf(os.Stderr, "profileapply: ★ harden state directories: %v\n", derr2)
		}
	case *clear:
		// The persisted profile is written OUTSIDE MSI component tracking (configstore.Apply), so uninstall must
		// scrub it explicitly, or the envelope would linger after removal.
		if err := configstore.Clear(be); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: clear: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("profileapply: config-store profile cleared")
		// ★ AND THE ADOPTED VERIFIER, for the same reason and with a sharper consequence. The verifier store is
		// deliberately outside MSI component tracking — that is what lets it survive the upgrade it exists for —
		// so an uninstall reaches it only if something says so here. Left behind, it is a record of an authority
		// on a machine that no longer runs the product, and a LATER install would have --reconcile-config-pin
		// restore a previous deployment's key with nobody having placed it. That defeats the rule the whole
		// artefact exists to keep: adopting an authority is an explicit act (signing_key_artefact.go).
		//
		// This branch is reached on genuine uninstall only — ClearProfile is conditioned REMOVE="ALL" AND NOT
		// UPGRADINGPRODUCTCODE — so a MajorUpgrade's RemoveExistingProducts never gets here.
		if err := clearAdoptedVerifier(); err != nil {
			// Non-fatal, like everything else on this path: an uninstall that refuses leaves the machine holding
			// the product AND the record. Loud, because a silently retained authority is the failure above.
			fmt.Fprintf(os.Stderr, "profileapply: WARNING - the adopted verifier could NOT be removed (%v). "+
				"This machine still records which authority it verified configuration against.\n", err)
		} else {
			fmt.Println("profileapply: the adopted verifier record was removed")
		}
		// ★★★ AND SAY WHAT IS BEING LEFT (2026-09-07, found on both platforms on the same day). Clearing the
		// store stops this machine acting on a profile. It does not collect the artefacts on disk that NAME
		// the deployment it belonged to, and the next thing to read one adopts that deployment — measured on
		// a box whose uninstall could not run at all, which came back bound to a deployment destroyed the day
		// before. Whether removal should destroy a device's identity is a decision; leaving it in silence is
		// not one. Fail loud, which is this tree's recorded rule for exactly this shape.
		reportWhatUninstallLeaves(os.Stdout)
	case *status:
		prof, meta, err := configstore.Load(be, pin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: status: %v\n", err)
			os.Exit(1)
		}
		// issued_at is printed even when empty, and says so: an operator comparing two boxes needs to see that
		// one of them is running a profile from before profiles were stamped, not an absent field.
		issued := meta.IssuedAt
		if issued == "" {
			issued = "(unstamped — predates issued_at; re-issue to arm the rollback floor)"
		}
		fmt.Printf("present=%v verified=%v version=%d tenant=%q source=%q posture=%q transport=%q issued_at=%s applied_at=%q\n",
			meta.Present, meta.Verified, meta.Version, meta.TenantID, meta.Source, prof.Posture, prof.TransportURL, issued, meta.AppliedAt)
		// Which authority this box verifies its configuration against, and whether the copy a person reads
		// still says the same thing. See pin_agreement.go.
		fmt.Println("signing key: " + reportPinAgreement(filepath.Dir(enrolmentDir()), "DsseSteer").Note)
	default:
		fmt.Fprintln(os.Stderr, "profileapply: one of --apply / --status is required")
		os.Exit(2)
	}
}

func doApply(be configstore.Backend, configPath, pin string, setStartAuto bool) error {
	if configPath == "" {
		return fmt.Errorf("--config is required for --apply")
	}
	if pin == "" {
		return fmt.Errorf("no trust anchor pin (build with -ldflags -X main.trustAnchorPin=<hex>, or pass --pin)")
	}
	// A relative --config resolves against this exe's own dir, so the MSI custom action can pass a bare
	// "profile.json" (the bundled profile and profileapply.exe co-install in INSTALLDIR) without threading the
	// absolute INSTALLDIR through deferred-custom-action CustomActionData.
	if !filepath.IsAbs(configPath) {
		if exe, e := os.Executable(); e == nil {
			configPath = filepath.Join(filepath.Dir(exe), configPath)
		}
	}
	env, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read profile %q: %w", configPath, err)
	}
	prof, err := configstore.Apply(be, env, pin, "path", time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("apply profile: %w", err) // unverified/rollback => store left untouched => runtime SafeDefaults
	}
	fmt.Printf("profileapply: applied version=%d tenant=%q posture=%q transport=%q\n",
		prof.Version, prof.TenantID, prof.Posture, prof.TransportURL)

	// Keep a copy where an uninstall cannot reach it. Reported but NOT fatal: the profile is in force either
	// way, and failing an install over a copy that only matters on a recovery nobody has needed yet would trade
	// a real outage for a hypothetical one. See profile_escrow.go for what this copy is and is not.
	if err := escrowProfile(env); err != nil {
		fmt.Fprintf(os.Stderr, "profileapply: WARNING — the profile is applied, but the escrow copy could not be "+
			"written (%v). This device is fine now and will steer, but an uninstall/reinstall on it will need a "+
			"re-issued profile from the control plane\n", err)
	}

	// S4: only NOW (a verified, transport-bearing profile is persisted) is it safe to let DsseSteer auto-start.
	// A fail-open profile without a transport would still be unsafe, so require a transport before flipping.
	if setStartAuto {
		if prof.TransportURL == "" {
			fmt.Println("profileapply: profile has no transport_url — leaving DsseSteer on demand-start")
			return nil
		}
		if err := setServiceAutoStart("DsseSteer"); err != nil {
			return fmt.Errorf("set DsseSteer auto-start: %w", err)
		}
		fmt.Println("profileapply: DsseSteer set to auto-start")
	}
	return nil
}

// setServiceAutoStart flips only the start type of a service to SERVICE_AUTO_START, via ChangeServiceConfig with
// SERVICE_NO_CHANGE for every other field — so the (space-containing, correctly-formatted) ImagePath and all
// other config are left exactly as installed.
func setServiceAutoStart(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	return windows.ChangeServiceConfig(s.Handle,
		windows.SERVICE_NO_CHANGE,  // service type
		windows.SERVICE_AUTO_START, // start type -> auto
		windows.SERVICE_NO_CHANGE,  // error control
		nil, nil, nil, nil, nil, nil, nil)
}

// enrolmentDir is where `dsse-steer --mode enroll` persists the device identity. Must match
// defaultEnrollDir() in steer/enroll_windows.go.
func enrolmentDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "DSSE", "enroll")
}

// deviceIsEnrolled reports whether this box holds a device identity. The certificate is the discriminator:
// the DPAPI-wrapped key is unreadable from here by design, and `enrolled.json` alone would be satisfied by a
// half-finished enrolment.
func deviceIsEnrolled() bool {
	_, err := os.Stat(filepath.Join(enrolmentDir(), "device.crt"))
	return err == nil
}

// doReconcileStartType sets DsseSteer's start type to what this box's OWN state says it should be.
//
// WHY THIS EXISTS. The MSI installs DsseSteer as demand-start, correctly: before enrolment the agent cannot
// build a transport, so auto-starting it would black-hole the box on first boot. Raising it to auto once the
// box is enrolled was left to `--set-start-auto`, and NOTHING in the tree ever passed that flag — so in
// practice an operator did it by hand.
//
// Hand-made state is exactly what an upgrade destroys. A major upgrade deletes the service and recreates it
// from the MSI's ServiceInstall, which says demand-start, so every upgrade silently undid the operator's
// change. Nothing broke at the time — the running agent kept steering — and the box simply failed to steer
// after its NEXT reboot, far enough away that the upgrade was not the obvious suspect.
//
// The fix is to stop preserving hand-made state and start DERIVING it. The conditions for auto-start are
// observable on the box: a verified, transport-bearing profile in the config store, and a device identity on
// disk. Reading them is cheap and unambiguous, so an upgrade can reach the right answer without having to
// remember what someone typed months ago.
//
// It only ever raises demand -> auto. It never lowers auto -> demand: an operator who deliberately parked a
// service is making a decision this has no business overruling, and "the installer turned my agent off" is a
// worse failure than a stale auto-start.
func doReconcileStartType(be configstore.Backend, pin string) error {
	// ★ A GENERIC PACKAGE HAS NO BAKED PIN, AND THIS STEP IS A SEPARATE PROCESS (2026-09-09, review point 2).
	// ReconcileSteerStartType is its own custom action receiving only --reconcile-start-type, so fixing the
	// SCM arguments in the step before does nothing for THIS process's pin. On a deployment-independent build
	// trustAnchorPin is empty by design, and refusing here meant the start type was never derived and the
	// service was never started — the generic package's whole point, defeated by a check written when every
	// package was deployment-specific.
	//
	// Resolved from the same protected sources the restore uses, in the same order: the service arguments
	// (what the agent itself will verify against), then the verifier store. Never profile_signing_key.txt —
	// see reconcile_config_pin_windows.go for the measurement that rules it out.
	if pin == "" {
		resolved, from, rerr := resolveConfigVerifier("DsseSteer")
		if rerr != nil {
			return fmt.Errorf("this build bakes no trust anchor and the protected verifier store cannot be "+
				"trusted: %w", rerr)
		}
		if resolved != "" {
			pin = resolved
			fmt.Println("profileapply: this build bakes no trust anchor — verifying against the config key " +
				from + " names (" + short(pin) + ")")
		}
	}
	if pin == "" {
		return fmt.Errorf("no trust anchor pin: this build bakes none, DsseSteer's arguments name none, and " +
			"the protected verifier store holds none (build with -ldflags -X main.trustAnchorPin=<hex>, pass " +
			"--pin, or provision with PIN=)")
	}
	prof, _, err := configstore.Load(be, pin)
	if err != nil {
		// No verified profile: the box is pre-enrolment or the store is unreadable. Demand-start is correct
		// in both cases, and this is a no-op rather than an error so it can sit in the install sequence
		// unconditionally.
		fmt.Printf("profileapply: no verified profile in the config store (%v) — leaving DsseSteer's start type unchanged\n", err)
		return nil
	}
	if prof.TransportURL == "" {
		fmt.Println("profileapply: profile has no transport_url — leaving DsseSteer's start type unchanged")
		return nil
	}
	if !deviceIsEnrolled() {
		fmt.Printf("profileapply: no device identity at %s — this box is not enrolled yet, leaving DsseSteer on demand-start\n", enrolmentDir())
		return nil
	}
	current, err := serviceStartType("DsseSteer")
	if err != nil {
		return fmt.Errorf("read DsseSteer start type: %w", err)
	}
	if current != windows.SERVICE_AUTO_START {
		if err := setServiceAutoStart("DsseSteer"); err != nil {
			return fmt.Errorf("set DsseSteer auto-start: %w", err)
		}
		// Say what changed and why, because this runs unattended inside an installer: an operator who later
		// wonders why the start type moved needs the reason in the same place as the fact.
		fmt.Printf("profileapply: DsseSteer start type RESTORED to auto (was %d). This box is enrolled and holds a "+
			"transport-bearing profile, so auto-start is correct; a major upgrade recreates the service as "+
			"demand-start and would otherwise have left it that way until the next reboot stopped steering\n", current)
	} else {
		fmt.Println("profileapply: DsseSteer is already auto-start")
	}

	// ★ AND START IT. Setting the start type only decides what happens at the NEXT BOOT, and an upgrade is not
	// a boot (found 2026-08-11, on the code rather than on a box, because the MSI path is still gated on
	// signing — so this is reasoned from the package and the services, and is UNVERIFIED against a real install).
	//
	// The chain after a major upgrade of an enrolled, steering box: the MSI stops DsseSteer (ServiceControl
	// Stop="both") and never starts it, because that ServiceControl deliberately has no Start — unlike
	// DsseWatchdog and DsseUpdater, which both carry Start="install". DsseWatchdog does not cover the gap: it
	// guards the DRIVER service (DsseWfp), not the agent. So the box finished a successful upgrade and did not
	// steer again until somebody rebooted it.
	//
	// This is the right place for the start, and the MSI's ServiceControl is not, for the reason DsseSteer is
	// demand-start in the first place (review finding S4): an agent with no verified transport-bearing profile
	// comes up fail-closed with nowhere to send traffic. A Start="install" would do that on every FRESH install.
	// The condition for "may this run" was already computed above — verified profile, transport URL, enrolled —
	// and every early return above leaves the service alone. Starting only where all three hold means a box that
	// was steering before the upgrade is steering after it, and a box that was not is untouched.
	//
	// A failure to start is REPORTED, not fatal: the MSI custom action is Return="ignore" and rolling back a
	// completed upgrade over this would be worse than an agent an operator can start. It is loud because the
	// alternative is a silently unprotected box.
	if err := startServiceIfStopped("DsseSteer"); err != nil {
		fmt.Fprintf(os.Stderr, "profileapply: WARNING DsseSteer is enrolled and configured but could NOT be "+
			"started (%v). THIS BOX IS NOT STEERING until it is started or rebooted — the upgrade stopped the "+
			"agent and nothing brought it back\n", err)
		return nil
	}
	return nil
}

// startServiceIfStopped starts a service unless it is already running or already on its way up. Idempotent
// because it runs on every install and upgrade, and StartService on a running service is an error rather than
// a no-op — one this must not report as a failure to steer.
func startServiceIfStopped(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query %s: %w", name, err)
	}
	switch st.State {
	case windows.SERVICE_RUNNING:
		fmt.Printf("profileapply: %s is already running\n", name)
		return nil
	case windows.SERVICE_START_PENDING:
		fmt.Printf("profileapply: %s is already starting\n", name)
		return nil
	}
	if err := s.Start(); err != nil {
		return err
	}
	fmt.Printf("profileapply: %s STARTED — the upgrade stopped it and setting the start type alone would not "+
		"have brought it back until the next reboot\n", name)
	return nil
}

// serviceStartType reads a service's configured start type.
func serviceStartType(name string) (uint32, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return 0, err
	}
	return cfg.StartType, nil
}
