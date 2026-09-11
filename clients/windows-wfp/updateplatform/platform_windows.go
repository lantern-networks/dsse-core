//go:build windows

// platform_windows.go — the five methods, and the source each one trusts.
package updateplatform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/runstate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/wfpstate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// recoverTimeout bounds the disarm child. The updater is not inside an msiexec transaction the way the
// installer's custom actions are, but a disarm that never returns is worse here than there: Run is holding an
// endpoint at the point where it has decided to update and has not yet handed over, and the posture during
// that window is the whole reason disarming is deliberate.
const recoverTimeout = 90 * time.Second

// rearmTimeout bounds putting steering back. Shorter than recoverTimeout on purpose: this runs after a failed
// launch, when the endpoint is already unprotected, and a restoration that hangs is indistinguishable from one
// that failed — except that nobody is being told.
const rearmTimeout = 60 * time.Second

// systemBinary resolves an executable that ships WITH Windows, without consulting %PATH%.
//
// ★ THIS IS A MEASURED FAILURE, not a precaution. win-dev-1's journal, 2026-08-11T21:45:52Z, recorded
// exec.LookPath("msiexec.exe") returning "executable file not found in %PATH%" inside the running updater —
// and because the sequencing takes steering DOWN before the installer on a fail-open endpoint, the box was
// left unsteered and the Rearm behind it failed too. One unresolvable string decided whether this endpoint was
// protected. See package winbin for the whole finding; it is shared because the steering agent resolves sc,
// netsh and powershell the same way, on the paths that stop services and change the firewall.
func systemBinary(name string) (string, error) { return winbin.System(name) }

// Platform implements agentupdate.Platform for a Windows endpoint.
type Platform struct {
	// SteerExe is the agent binary, used ONLY to perform the disarm (never to ask a version — that would be
	// the on-disk answer to a question about running code). Empty means "beside this executable".
	SteerExe string
	// FailOpen is the endpoint's install-time posture, the same choice the driver's owner-handle uses.
	FailOpen bool
	// Store is where restore material lives. Nil means the production default.
	Store *rollbackstore.Store
	// Publisher is who this endpoint requires to have BUILT a package, asked immediately before msiexec is
	// launched as SYSTEM. The zero value means no requirement, which installs and says so — see
	// ParsePublisherRequirement.
	Publisher PublisherRequirement

	// armedBeforeDisarm is what the driver reported at the moment Disarm ran, and it exists so that Rearm can
	// judge a RESTORATION against what was actually taken down.
	//
	// ★ MEASURED ON win-dev-1, 2026-08-12. The disarm and the rearm read the same absence and reasoned in
	// opposite directions: confirmDisarmed treats "no control device" as a definite, safe answer — no driver,
	// therefore no redirect, therefore nothing to take down — while Rearm required `Present && Known && Armed`
	// before it would call the restoration done. On a box with no WFP driver loaded the first ALWAYS succeeds
	// and the second can NEVER succeed.
	//
	// What that produced, from this box's own records: the update journal at 06:45:52 carried "★ steering could
	// NOT be restored afterwards ... this endpoint is NOT steering", and the agent log shows DsseSteer starting
	// two seconds later and standing aside because the device is not enrolled. Everything worked as designed and
	// the endpoint was told it had lost a protection it never had — the sentence Run escalates hardest on, and
	// the one that says "needs a person now".
	//
	// Restoring means putting back what was there. Asserting an armed redirect on a box that had none is
	// asserting something that was never true, and an alarm that fires on a healthy stand-aside box is how
	// people learn to ignore the one that matters.
	armedBeforeDisarm bool
	// disarmObserved distinguishes "the disarm looked and found nothing armed" from "no disarm has run in this
	// process", so a Rearm reached without one keeps the strict assertion. The safe default is the strict one.
	disarmObserved bool
}

// Ensure the interface is satisfied at compile time rather than at the first update on a real box.
var _ agentupdate.Platform = (*Platform)(nil)

func (p *Platform) store() *rollbackstore.Store {
	if p.Store != nil {
		return p.Store
	}
	return rollbackstore.New(rollbackstore.DefaultRoot())
}

// RunningVersion is the version the LIVE agent recorded, paired with the SCM's view of that service.
//
// It is a single call into runstate because the rule — a value counts only alongside an independent liveness
// signal — belongs there, next to the writer, and not restated here. This method deliberately has no fallback
// to the on-disk binary: a fallback would answer on exactly the boxes where the two differ, which are the
// boxes the distinction exists for.
func (p *Platform) RunningVersion() (string, error) {
	return runstate.Resolve(runstate.Read(), runstate.Live())
}

// Conditions reports what this device can observe about itself.
//
// The idle answer does NOT come from GetLastInputInfo, which cannot work here: it reports input for the
// calling session and this runs in session 0, so it would say "idle forever" no matter who is typing. It comes
// from the terminal-services API, which answers about a session from outside it. See session_windows.go.
//
// ★ What that produces on a real box, measured rather than assumed (win-dev-1): the LOCK state reads
// correctly, and LastInputTime comes back ZERO for the console session — the documented "not maintained on
// every configuration" case. So IdleKnown is still false there, and a plan carrying RequireIdleMinutes is
// still unsatisfiable, while the machine can say perfectly well whether anyone is at it. That is why InUse is
// reported alongside: the predicate is measurable where the duration is not.
func (p *Platform) Conditions(now time.Time) agentupdate.DeviceConditions {
	c := agentupdate.DeviceConditions{LocalNow: now}
	// One reading answers both: two enumerations would describe two different moments, and a session that
	// locks between them would produce a pair that never existed together.
	idle, idleKnown, inUse, inUseKnown := observeDevice()
	if idleKnown {
		c.IdleFor = idle
		c.IdleKnown = true
	}
	if inUseKnown {
		c.InUse = inUse
		c.InUseKnown = true
	}
	if onAC, known := onACPower(); known {
		c.OnACPower = onAC
		c.PowerKnown = true
	}
	return c
}

// CaptureRestoreMaterial secures what a rollback would need: the installer package for the version currently
// running.
//
// An error here stops the update, and the common error is not a fault. A box installed before the installer
// began stashing has nothing to roll back to, and refusing is the designed answer — an update that cannot be
// undone is the same as having no rollback. The message says which version was looked for, because the
// operator's next question is always that.
func (p *Platform) CaptureRestoreMaterial(m agentupdate.Manifest) ([]string, error) {
	running, err := p.RunningVersion()
	if err != nil {
		return nil, fmt.Errorf("cannot secure restore material without knowing what is running: %w", err)
	}
	pkg, err := p.store().Lookup(running)
	if err != nil {
		if errors.Is(err, rollbackstore.ErrNoMaterial) {
			return nil, fmt.Errorf("%w — this device holds no installer package for the version it is running "+
				"(%s), so an update to %s could not be undone. It will keep refusing until an install leaves one "+
				"behind", err, running, m.Version)
		}
		return nil, err
	}
	return []string{pkg}, nil
}

// DisarmBeforeUpdate reports whether this endpoint's posture permits taking steering down first.
//
// False on a fail-closed endpoint: disarming there would break the posture the operator chose, so such a box
// takes the outage risk during the install window instead. That trade is stated, not hidden.
func (p *Platform) DisarmBeforeUpdate() bool { return p.FailOpen }

// Disarm takes steering down and CONFIRMS it.
//
// Performed by running the agent binary, which is the precedent the watchdog already set for a second process
// needing the network back: the IOCTL that clears the redirect is issued by dsse-steer and nothing else, and
// duplicating that here would be a second implementation of the one operation whose failure is a black hole.
// The recover-keep-services flag is the same one the MSI uses — this must undo the network mutations without
// touching service lifecycle, which the installer owns.
//
// The exit code is NOT the verdict. A clear that returns success while the driver is still redirecting is
// precisely the failure this confirmation exists for, so the driver is asked afterwards and its answer
// decides. An unreadable driver is a refusal, not a pass: Run must not hand an installer a box whose redirect
// might still be armed.
func (p *Platform) Disarm() error {
	// BEFORE anything is cleared: what Rearm will have to put back. See armedBeforeDisarm.
	p.noteArmedBeforeDisarm()
	exe, err := p.steerExe()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "--mode", "recover", "--recover-keep-services")
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s to disarm: %w", filepath.Base(exe), err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case runErr := <-done:
		// Recorded and deliberately not returned on its own: the driver's answer below is what decides.
		if runErr != nil {
			runErr = fmt.Errorf("recover exited with %w", runErr)
		}
		return p.confirmDisarmed(runErr)
	case <-time.After(recoverTimeout):
		_ = cmd.Process.Kill()
		// ★ ASK THE DRIVER, BECAUSE THE HELPER MAY HAVE FINISHED THE WORK BEFORE IT HUNG (2026-08-13,
		// twenty-eighth review). This returned "the redirect state is unknown" without ever looking, and the
		// caller reads a Disarm error as "steering was never taken down" — so it skips Rearm entirely
		// (`if !disarmed || launched { return }`). A recover that cleared the kernel redirect and THEN hung
		// left the box unsteered on its native network, with a refusal that says the opposite of what happened,
		// and three of those poison the target version as well.
		//
		// confirmDisarmed reads the driver. If the redirect is gone, this WAS a disarm and the caller must
		// restore it; if it is still there, the old answer stands and nothing was touched.
		return p.confirmDisarmed(fmt.Errorf("recover did not finish within %s", recoverTimeout))
	}
}

// noteArmedBeforeDisarm records what the driver reported BEFORE the redirect was cleared, for Rearm.
//
// Read at the top of Disarm rather than derived afterwards: after the clear, every box looks like a box that
// was never armed, which is exactly the question being asked.
func (p *Platform) noteArmedBeforeDisarm() {
	r := wfpstate.Read()
	p.disarmObserved = true
	p.armedBeforeDisarm = r.Present && r.Known && r.State.Armed
}

// restorationIsTheServiceComingBack reports whether Rearm is done once DsseSteer is running again, because the
// disarm looked first and found nothing armed to put back.
//
// Its own function so the rule can be stated once and tested without a driver: the two facts it reads are set
// by a single call at the top of Disarm, and everything about being wrong here is asymmetric. Answering true
// when something WAS armed would report a restored endpoint that is unprotected — so an unobserved disarm
// keeps the strict path, which is the only default that fails in the survivable direction.
func (p *Platform) restorationIsTheServiceComingBack() bool {
	return p.disarmObserved && !p.armedBeforeDisarm
}

// confirmDisarmed asks the driver whether the redirect is actually gone.
func (p *Platform) confirmDisarmed(runErr error) error {
	r := wfpstate.Read()
	if !r.Present {
		// No control device means no loaded driver and therefore no redirect. A definite answer, and the safe
		// one: a driver with no filters passes traffic rather than black-holing it.
		return nil
	}
	var readErr error
	if !r.Known {
		readErr = errors.New("the driver is loaded but would not report its state")
	}
	v := wfpstate.VerifyDisarmed(r.State, readErr)
	if v.Verified {
		return nil
	}
	if runErr != nil {
		return fmt.Errorf("disarm not verified: %s (%w)", v.Reason, runErr)
	}
	return fmt.Errorf("disarm not verified: %s", v.Reason)
}

// Execute launches the installer DETACHED and returns immediately.
//
// It must not wait. The package it starts replaces dsse-steer.exe and may replace this updater's own binary,
// so anything that waits is waiting to be killed — and a Wait that dies with the process would be reported as
// a failed install of an update that in fact succeeded.
//
// Release() rather than a discarded handle: without it the child is a zombie until this process exits, and
// this process is a long-running service.
func (p *Platform) Execute(m agentupdate.Manifest) error {
	// Re-verified here, not merely checked for existence: staging and execution are separated by the whole
	// maintenance window by design, and a present, non-empty file at a predictable path is not evidence that it
	// is still the package that was verified. See VerifyStaged.
	staged, err := VerifyStaged(m)
	if err != nil {
		return err
	}

	// ★ WHO BUILT THESE BYTES, asked after VerifyStaged has proved they are the bytes the manifest named and
	// immediately before SYSTEM is handed them. Those are different questions and only this one survives a
	// compromised manifest signer, which can name the digest of anything it likes. See publisher.go.
	//
	// The note is discarded here and printed by --status and at service start instead: this package is a
	// library, and writing to stdout from inside an install path is how a message ends up somewhere nobody
	// looks — the documented history of the "no update-signing key is pinned" warning.
	if _, perr := VerifyPublisher(staged, p.Publisher); perr != nil {
		return fmt.Errorf("refusing to install %s: %w", m.Version, perr)
	}

	msiexec, err := systemBinary("msiexec.exe")
	if err != nil {
		return err
	}
	// ★ /norestart, BECAUSE /qn LETS msiexec DECIDE (2026-08-13, twenty-ninth review). Under a quiet install
	// the file-in-use handler can conclude a reboot is needed and take it — immediately, with no prompt, on a
	// machine somebody is working on. Worse for this product specifically: a reboot landing inside the
	// disarm→execute window makes the NEXT pass find an interrupted attempt and raise an alarm about a restart
	// the updater itself caused. A reboot is an operator's decision; the exit code says one is pending and
	// that is the honest place for it.
	cmd := exec.Command(msiexec, "/i", staged, "/qn", "/norestart")
	// A detached process group, so the installer is not taken down with the updater it is about to replace.
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch installer for %s: %w", m.Version, err)
	}
	_ = cmd.Process.Release()
	return nil
}

// Rearm puts steering back after an install that never happened, and CONFIRMS it.
//
// ★ WHY A SERVICE RESTART AND NOT AN "ARM" COMMAND. There is no `--mode arm`: the agent applies the redirect
// when it starts, and `--mode recover --recover-keep-services` deliberately clears the kernel policy while
// leaving the service running. That combination is what makes the disarm safe (the agent stays alive to be
// asked questions) and it is exactly what makes restoring it impossible from outside — the running process
// still believes it is armed, so nothing re-applies. Restarting the service is the one path that ends with the
// driver holding a policy the agent knows about.
//
// The exit code is NOT the verdict, the same rule as the disarm: the driver is asked afterwards, and an
// unreadable driver is a failure rather than a pass. A caller that is told "restored" while the redirect is
// absent is worse off than one told nothing.
//
// ★ UNVERIFIED ON HARDWARE. Written from the macOS session; no Windows box has run it. The failure it guards
// against — a fail-open endpoint left unprotected after a failed launch — is real either way, so shipping the
// guard unexercised is better than shipping the gap, and the handoff says exactly this.
func (p *Platform) Rearm() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open the service manager to restore steering: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(runstate.ServiceName)
	if err != nil {
		return fmt.Errorf("open %s to restore steering: %w", runstate.ServiceName, err)
	}
	defer s.Close()

	// Stop, wait for it to actually stop, then start. A start issued while the previous instance is still
	// shutting down is refused, and a "restore" that returned that error would leave the box unprotected with a
	// message about service state.
	// ★ THE ERROR IS COMPARED AS A CODE, NOT AS ENGLISH (2026-08-13, twenty-eighth review). This matched
	// "has not been started", which is the message an ENGLISH Windows returns. FormatMessage localises it, so
	// on the Japanese Windows this fleet actually runs the match failed, Rearm returned before reaching
	// Start(), and the recovery path built to restore steering left it down. A recovery routine that works
	// only in one locale is a recovery routine for one locale.
	if st, serr := s.Control(svc.Stop); serr != nil && !errors.Is(serr, windows.ERROR_SERVICE_NOT_ACTIVE) {
		_ = st
		return fmt.Errorf("stop %s to restore steering: %w", runstate.ServiceName, serr)
	}
	deadline := time.Now().Add(rearmTimeout)
	for {
		st, qerr := s.Query()
		if qerr != nil {
			return fmt.Errorf("query %s while restoring steering: %w", runstate.ServiceName, qerr)
		}
		if st.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not stop within %s, so steering could not be restored", runstate.ServiceName, rearmTimeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if serr := s.Start(); serr != nil {
		return fmt.Errorf("start %s to restore steering: %w", runstate.ServiceName, serr)
	}

	// ★ RESTORING MEANS PUTTING BACK WHAT WAS THERE, and on this box that was nothing. The disarm found no
	// armed redirect — an unenrolled device whose agent deliberately stands aside, a box with no WFP driver
	// loaded, an endpoint in observe mode — so the service being up again IS the restoration, and demanding an
	// armed redirect would demand a state that never existed. See armedBeforeDisarm for what this cost when it
	// was absolute: a healthy stand-aside box was told it had lost a protection it never had, in the sentence
	// Run escalates hardest on.
	//
	// The service was started above and that call's failure is already returned; there is nothing further to
	// confirm here that would not be confirming the agent's own posture decision, which is not this method's to
	// second-guess.
	if p.restorationIsTheServiceComingBack() {
		return nil
	}

	// Otherwise: something WAS armed, this took it down, and only the driver can say it is back. Confirm
	// against the DRIVER, not against the service being "running" — the process can be up while the policy is
	// not yet applied, and the whole point of this method is the state of the redirect. Also the path taken
	// when no disarm was observed in this process, which is the safe default.
	// ★ THE CONFIRMATION GETS ITS OWN CLOCK (2026-08-13, twenty-ninth review). It shared the deadline with the
	// stop-wait above, so a service that took 55 of the 60 seconds to stop left 5 for the driver to come back —
	// and a healthy box that arms in 6 recorded the loudest message this file has, "this endpoint is NOT
	// steering", three of which poison a target version that was never at fault. The two waits are different
	// questions and the second one starts when it starts.
	confirmDeadline := time.Now().Add(rearmTimeout)
	for {
		r := wfpstate.Read()
		if r.Present && r.Known && r.State.Armed {
			return nil
		}
		if time.Now().After(confirmDeadline) {
			return fmt.Errorf("%s was restarted but the driver does not report an armed redirect within %s; "+
				"this endpoint is NOT steering", runstate.ServiceName, rearmTimeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// RestoreMaterialFor is the read half of the same store: the package this box holds for one specific version.
// The error names what IS held, because that is the operator's next question and only SYSTEM can list the
// directory to answer it.
func (p *Platform) RestoreMaterialFor(version string) (string, error) {
	pkg, err := p.store().Lookup(version)
	if err == nil {
		return pkg, nil
	}
	if !errors.Is(err, rollbackstore.ErrNoMaterial) {
		return "", err
	}
	held, lerr := p.store().List()
	switch {
	case lerr != nil:
		return "", fmt.Errorf("%w — and %s could not be listed (%v)", err, p.store().Root(), lerr)
	case len(held) == 0:
		return "", fmt.Errorf("%w — this box holds NO installer packages at all (%s is empty). Nothing can be rolled "+
			"back to until an install leaves one behind", err, p.store().Root())
	}
	names := make([]string, 0, len(held))
	for _, e := range held {
		names = append(names, e.Version)
	}
	return "", fmt.Errorf("%w — this box holds packages for: %s", err, strings.Join(names, ", "))
}

// RollbackProperty is what the MSI must look at to tell a deliberate downgrade from an accidental one. Public
// (uppercase, no underscore) so msiexec passes it through to the install session.
//
// Aliased rather than re-declared: rollbackstore names it too (its marker text refers to it) and the WiX launch
// condition is pinned against THAT constant. Three spellings of one string is how a launch condition quietly
// stops matching, so there is one and the other two point at it.
const RollbackProperty = rollbackstore.RollbackIntentProperty

// ★ THE GUARD MOVED FROM A GLOBAL CONSTANT TO THE STORED PACKAGE, and the reason is a correction.
//
// This was `const msiHonoursRollbackProperty = false` — a declaration about "the installer this Go code is
// paired with", to be flipped in the same commit as the WiX change. DsseAgent.wxs now carries the launch
// condition (`NOT WIX_DOWNGRADE_DETECTED OR DSSEROLLBACK = "1"`), so the flip is due. But a constant is the
// wrong shape for the fact, and this is the fact:
//
//   A rollback installs the STORED, OLDER package over the current one. The launch condition that runs is the
//   one inside THAT package — not the one in the MSI currently installed, and not the one in the source tree
//   this binary was built from.
//
// So the question is never "does this build's WiX honour the property", it is "does the specific package on
// this disk honour it" — and on any box that has been through more than one release the answer differs per
// stored version. A constant compiled into the updater would answer for all of them at once, and would answer
// TRUE for exactly the packages stashed before the mechanism existed, which is the bootstrap case it was
// supposed to protect.
//
// The marker beside the stored package (rollbackstore.MarkAcceptsRollbackIntent, written by the profileapply
// that ships INSIDE a package carrying the condition) answers per package, from evidence. Same purpose as the
// macOS `<pkg>.accepts-rollback-intent` marker, and same reason: refuse before launching anything, so the
// operator hears it while asking rather than from a journal that says a rollback is running on a machine
// nothing has touched.

// ExecuteRollback installs a package this box already holds, declaring the downgrade deliberate.
func (p *Platform) ExecuteRollback(pkg, toVersion string) error {
	ok, merr := p.store().AcceptsRollbackIntent(toVersion)
	if merr != nil {
		return fmt.Errorf("cannot establish whether the stored package for %s admits a declared rollback: %w",
			toVersion, merr)
	}
	if !ok {
		return fmt.Errorf("the package stored for %s predates the rollback mechanism: it is an MSI whose "+
			"MajorUpgrade refuses every downgrade unconditionally, so launching it would fail in seconds while "+
			"the journal said a rollback was running on a box nothing had touched. The package IS here (%s) and "+
			"is not damaged — it simply cannot be installed over a newer build. The first version this box can "+
			"roll back TO is the first one installed from a package carrying %s=1 (marker: %s)",
			toVersion, pkg, RollbackProperty, rollbackstore.IntentMarkerPath(pkg))
	}
	st, err := os.Stat(pkg)
	if err != nil {
		return fmt.Errorf("the stored package for %s cannot be read: %w", toVersion, err)
	}
	if st.Size() == 0 {
		return fmt.Errorf("the stored package for %s is empty (%s) — a torn copy is not restore material", toVersion, pkg)
	}
	// ★★ ASKED ON THE WAY BACK TOO, which is not obvious and is the same call macOS made (thirtieth review
	// #19). This package is not being fetched from anywhere — it is the one an installer stored on this disk,
	// under a SYSTEM-only directory — so its DIGEST is deliberately not re-checked here: there may be no
	// manifest left for a version the fleet has withdrawn. But "where did it come from" and "who built it" are
	// separate questions, and the second is answerable offline from the bytes themselves.
	//
	// The cost is real and is accepted: if the operator changes the requirement to something the stored package
	// does not satisfy, the recovery path refuses at the moment it is needed. That is the correct direction —
	// a stored MSI that no longer matches what this device will accept as SYSTEM is not restore material — and
	// it is why --status prints this verdict for every stored package, so the answer is known before the
	// incident rather than during it.
	// ★★★ AND THE DIRECTORY'S CLAIM IS CHECKED, NOT ASSUMED. The comment
	// above declines to re-check the digest ON THE GROUNDS that this package sits "under a SYSTEM-only
	// directory". Measured on win-dev-1, %ProgramData%\DSSE\rollback granted BUILTIN\Users Read AND Write —
	// so the premise was false and the conclusion was being applied anyway, on the path that hands msiexec
	// bytes to install as SYSTEM.
	//
	// VerifyPublisher below is NOT a substitute: it returns nil when the device names no --update-publisher,
	// which is exactly the deployment that would need this most. So the store and the package are verified
	// here, immediately before the launch — owner, protection, every ACE, the package's own ACL, and neither
	// being a reparse point — and an answer that cannot be established refuses rather than proceeds.
	if verr := rollbackstore.VerifyStoreAndPackage(p.store().Root(), pkg); verr != nil {
		return fmt.Errorf("refusing to roll back to %s: the stored package cannot be shown to be material only "+
			"an administrator could have placed (%w). Treat it as unusable and re-fetch the version from a "+
			"verified source rather than installing it as SYSTEM", toVersion, verr)
	}
	if _, perr := VerifyPublisher(pkg, p.Publisher); perr != nil {
		return fmt.Errorf("refusing to roll back to %s: %w", toVersion, perr)
	}
	msiexec, err := systemBinary("msiexec.exe")
	if err != nil {
		return err
	}
	// Same rule on the way back: a rollback is already an incident, and rebooting a machine in the middle of
	// one without asking is not part of the recovery.
	cmd := exec.Command(msiexec, "/i", pkg, "/qn", "/norestart", RollbackProperty+"=1")
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch the installer for %s: %w", toVersion, err)
	}
	_ = cmd.Process.Release()
	return nil
}

// steerExe resolves the agent binary: the configured path, or the one beside this executable.
func (p *Platform) steerExe() (string, error) {
	if p.SteerExe != "" {
		if _, err := os.Stat(p.SteerExe); err != nil {
			return "", fmt.Errorf("configured agent binary %s: %w", p.SteerExe, err)
		}
		return p.SteerExe, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this executable: %w", err)
	}
	cand := filepath.Join(filepath.Dir(self), "dsse-steer.exe")
	if _, err := os.Stat(cand); err != nil {
		return "", fmt.Errorf("agent binary %s: %w", cand, err)
	}
	return cand, nil
}

// --- power ------------------------------------------------------------------------------------------------

// systemPowerStatus mirrors SYSTEM_POWER_STATUS.
type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemPowerStat = kernel32.NewProc("GetSystemPowerStatus")
)

// onACPower reports (onAC, known). Unlike idle, this IS readable from session 0.
//
// ACLineStatus 255 means the API itself does not know — a desktop with no battery subsystem reports 1, so 255
// is a genuine unknown and is passed through as one. The gate refuses to update on an unknown power state for
// the same reason it refuses on unknown idle, so inventing "probably plugged in" here would defeat a check
// somebody deliberately turned on.
func onACPower() (bool, bool) {
	var s systemPowerStatus
	r, _, _ := procGetSystemPowerStat.Call(uintptr(unsafe.Pointer(&s)))
	if r == 0 {
		return false, false
	}
	switch s.ACLineStatus {
	case 0:
		return false, true
	case 1:
		return true, true
	default:
		return false, false
	}
}
