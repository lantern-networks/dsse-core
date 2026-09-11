//go:build darwin

// platform_darwin.go — the five methods, and the source each one trusts.
package updateplatform

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// Platform implements agentupdate.Platform for a macOS endpoint.
type Platform struct {
	// Store is where restore material lives. Nil means the production default.
	Store *rollbackstore.Store
	// Now is injected for tests.
	Now func() time.Time
	// ConfigPath is the agent configuration the publisher requirement is read from. Empty means the production
	// default.
	//
	// ★ IT USED TO BE FIXED WHILE --status WAS NOT (2026-08-13, thirtieth review #17). The updater takes
	// --agent-config and reports the publisher requirement from THAT file, and the install gate read the default
	// path regardless. So --status could say "notarized Developer ID Installer, team …" about one file while the
	// gate consulted another: unreadable there means every install is refused, and a missing field there means
	// the install proceeds with no publisher check at all — while the screen claims one. An operator using the
	// flag to test a configuration was being told about a file that would not be used.
	ConfigPath string
}

var _ agentupdate.Platform = (*Platform)(nil)

// configPath is the agent configuration this platform reads its publisher requirement from.
func (p *Platform) configPath() string {
	if p != nil && strings.TrimSpace(p.ConfigPath) != "" {
		return p.ConfigPath
	}
	return AgentConfigPath()
}

func (p *Platform) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Platform) store() *rollbackstore.Store {
	if p.Store != nil {
		return p.Store
	}
	// rollbackstore's root is a parameter, so the Windows package is reused whole rather than copied. What is
	// Windows-specific about it is DefaultRoot and nothing else — the naming rules, the torn-copy refusal and
	// the content-idempotency all apply here unchanged, and a second implementation of them is a second place
	// for a rollback to silently hold the wrong bytes.
	// Through DefaultRollbackStore, never rollbackstore.New: the macOS installer writes a .pkg and New looks
	// for a .msi. That mismatch is invisible — Lookup returns ErrNoMaterial, every device refuses every update,
	// and it presents as "nobody implemented stashing" while the postinstall runs correctly on every box.
	return DefaultRollbackStore()
}

// RunningVersion is the version the LIVE system extension recorded, paired with its own refreshed heartbeat.
//
// See runtimeMarker in observe.go for why a self-refreshed timestamp satisfies the independent-liveness rule
// where the Windows registry value did not. This method deliberately has no fallback to the installed bundle's
// version: that would answer on exactly the boxes where the two differ, which is the case the distinction was
// drawn for — a system extension whose replacement completes on the next restart.
func (p *Platform) RunningVersion() (string, error) {
	raw, err := os.ReadFile(RuntimeMarkerPath())
	if err != nil {
		if os.IsNotExist(err) {
			return resolveRunningVersion(runtimeMarker{}, false, p.now())
		}
		return "", fmt.Errorf("read the runtime marker %s: %w", RuntimeMarkerPath(), err)
	}
	var m runtimeMarker
	if jerr := json.Unmarshal(raw, &m); jerr != nil {
		return "", fmt.Errorf("%w: the runtime marker at %s is unreadable (%v)", errAgentNotRunning,
			RuntimeMarkerPath(), jerr)
	}
	return resolveRunningVersion(m, true, p.now())
}

// Addressing is who this device is, as the running extension read it off its verified (T) client certificate.
// Both are empty when the extension is not running, or is a build that did not record them — which the caller
// must report rather than treat as a match.
func (p *Platform) Addressing() (deviceIdentity, tenantID string) {
	raw, err := os.ReadFile(RuntimeMarkerPath())
	if err != nil {
		return "", ""
	}
	var m runtimeMarker
	if json.Unmarshal(raw, &m) != nil {
		return "", ""
	}
	return strings.TrimSpace(m.DeviceIdentity), strings.TrimSpace(m.TenantID)
}

// Conditions reports what this device can observe about itself.
//
// ★ Unlike Windows, BOTH halves are answerable here: HIDIdleTime is maintained (measured at 45.7 s on a real
// Mac) and the console session's lock state is readable. So a plan written in RequireIdleMinutes is
// satisfiable on macOS and is not on Windows, and that asymmetry is the operator's to know rather than
// something either platform should paper over by inventing a number.
func (p *Platform) Conditions(now time.Time) agentupdate.DeviceConditions {
	c := agentupdate.DeviceConditions{LocalNow: now}

	lockOut, lockOK := run("ioreg", "-n", "Root", "-d1", "-k", "CGSSessionScreenIsLocked")
	// ★ A FAILED OBSERVATION IS NOT "NOBODY IS LOGGED IN" (2026-08-13, twenty-ninth review). The error was
	// discarded, so a stat that failed produced an empty string, which parseScreenLocked folds into
	// lockNoConsoleUser — and an unattended-only gate then opened while somebody was at the machine. The
	// family this whole thread keeps finding: a value that means "nothing" and "could not tell" at once.
	consoleUser, consoleOK := run("stat", "-f%Su", "/dev/console")
	if !consoleOK {
		// Unknown, and it stays unknown: InUseKnown is left false, and a plan requiring an unattended box
		// holds rather than proceeding on an answer this device did not get.
		consoleUser = ""
		lockOK = false
	}
	if used, known := inUse(parseScreenLocked(lockOut, lockOK, consoleUser)); known {
		c.InUse = used
		c.InUseKnown = true
	}

	if idleOut, ok := run("ioreg", "-c", "IOHIDSystem"); ok {
		if idle, known := parseHIDIdle(idleOut, true); known {
			c.IdleFor = idle
			c.IdleKnown = true
		}
	}

	if pmOut, ok := run("pmset", "-g", "batt"); ok {
		if ac, known := parseACPower(pmOut, true); known {
			c.OnACPower = ac
			c.PowerKnown = true
		}
	}
	return c
}

// CaptureRestoreMaterial secures the installer package for the version currently running.
//
// Identical in shape and in consequence to the Windows one, including the refusal that matters: a device
// installed before the installer began stashing has nothing to roll back to, and an update that cannot be
// undone is the same as having no rollback. It will keep refusing until an install leaves one behind.
func (p *Platform) CaptureRestoreMaterial(m agentupdate.Manifest) ([]string, error) {
	running, err := p.RunningVersion()
	if err != nil {
		return nil, fmt.Errorf("cannot secure restore material without knowing what is running: %w", err)
	}
	pkg, err := p.store().Lookup(running)
	if err != nil {
		if errors.Is(err, rollbackstore.ErrNoMaterial) {
			return nil, fmt.Errorf("%w — this device holds no installer package for the version it is running "+
				"(%s), so an update to %s could not be undone", err, running, m.Version)
		}
		return nil, err
	}
	return []string{pkg}, nil
}

// RestoreMaterialFor is the read half of the same store: the package this device holds for one specific
// version.
//
// The error names what IS held, because the question asked immediately after "there is no package for 0.2.0"
// is "then what is there", and an operator asking it during an incident should not have to know the naming
// rules of a directory only root can list.
func (p *Platform) RestoreMaterialFor(version string) (string, error) {
	pkg, err := p.store().Lookup(version)
	if err == nil {
		// ★ Holding the package is not the same as being able to install it. The script that reads a rollback
		// authorisation is the preinstall INSIDE this package, so one built before that existed refuses the
		// downgrade whatever the updater writes — and the place to find that out is here, not from an opaque
		// installer failure during an incident.
		if aerr := PackageAcceptsIntent(pkg); aerr != nil {
			return "", fmt.Errorf("this device holds a package for %s and cannot install it: %w", version, aerr)
		}
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
		return "", fmt.Errorf("%w — this device holds NO installer packages at all (%s is empty). Nothing can be "+
			"rolled back to until an install leaves a package behind", err, p.store().Root())
	}
	var names []string
	for _, e := range held {
		names = append(names, e.Version)
	}
	return "", fmt.Errorf("%w — this device holds packages for: %s", err, strings.Join(names, ", "))
}

// DisarmBeforeUpdate is FALSE on macOS, and this is a finding rather than a stub.
//
// ★ THE BLACK HOLE IS A WINDOWS PROPERTY, NOT AN UPDATE PROPERTY. On Windows the WFP callout driver holds the
// redirect in the kernel and only dsse-steer can clear it, so an agent that dies mid-install leaves every
// connection refused — which is why Run disarms first on endpoints entitled to fail open, and why that step
// is one of the two orderings the whole design rests on.
//
// macOS has no such residue. An NEAppProxyProvider that stops is a provider the system stops handing flows to;
// there is no kernel object left holding the interception, and this deployment does not take over DNS either
// (the Mac's resolver is untouched, which is a separate known limitation and here is the one place it helps).
// So there is nothing for a disarm to undo.
//
// Returning false is therefore the honest answer, and implementing a Disarm anyway would be worse than not
// having one: a no-op wearing the costume of a safety step is exactly the kind of thing a later reader treats
// as evidence that the box was protected.
func (p *Platform) DisarmBeforeUpdate() bool { return false }

// Disarm is unreachable while DisarmBeforeUpdate is false, and refuses loudly rather than silently succeeding
// if that ever changes without someone reading the note above.
func (p *Platform) Disarm() error {
	return errors.New("macOS has no armed redirect to clear: an app-proxy provider that stops is one the system " +
		"stops routing to, and no kernel object survives it. If this is being called, DisarmBeforeUpdate has been " +
		"changed without deciding what it would disarm")
}

// Rearm is unreachable while DisarmBeforeUpdate is false, and refuses loudly for the same reason Disarm does.
//
// ★ Returning nil here would be the worse answer, and it is the tempting one: it would make the sequencing's
// restore step "succeed" on every Mac and report that steering had been put back, on a platform where it was
// never taken down. A restoration that cannot fail is a restoration nobody can trust on the platform where it
// matters.
func (p *Platform) Rearm() error {
	return errors.New("macOS never takes steering down for an install (DisarmBeforeUpdate is false), so there is " +
		"nothing to put back. If this is being called, the disarm decision changed without deciding what would " +
		"restore it")
}

// Execute launches the installer and returns immediately.
//
// `installer -pkg … -target /` requires root, which is why this component's home is a root LaunchDaemon rather
// than the user's app. It does not wait: the package replaces the app bundle and the system extension, so
// anything that waits is waiting to be killed — and a wait that dies with the process would be reported as a
// failed install of an update that in fact succeeded.
func (p *Platform) Execute(m agentupdate.Manifest) error {
	staged, err := VerifyStaged(m)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing %s needs root (installer -pkg -target /) and this process is uid %d; the "+
			"updater belongs in a root LaunchDaemon", m.Version, os.Geteuid())
	}
	// ★ WHO BUILT THESE BYTES, asked immediately before root is handed them and after VerifyStaged has proved
	// they are the bytes the manifest named. Those are different questions and only this one survives a
	// compromised signing key: a manifest signer can name any digest it likes, and until this check existed the
	// signed manifest was the only thing between a fetched file and `installer -target /` as root. See
	// publisher.go — this is the device-side half of the decision not to require two-person publishing approval.
	// The note is discarded HERE and printed by --status and at daemon start instead: this package is a library
	// and writing to stdout from inside an install path is how a message ends up somewhere nobody looks — which
	// is the documented history of the "no update-signing key is pinned" warning.
	if _, perr := VerifyPublisherFromConfig(p.configPath(), staged); perr != nil {
		return fmt.Errorf("refusing to install %s: %w", m.Version, perr)
	}
	cmd := exec.Command("/usr/sbin/installer", "-pkg", staged, "-target", "/")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch the installer for %s: %w", m.Version, err)
	}
	// Released rather than waited on, and rather than left as a zombie in a long-running daemon.
	go func() { _ = cmd.Wait() }()
	return nil
}

// ExecuteRollback installs a package this device already holds, having first written down that the downgrade
// is deliberate.
//
// THE ORDER IS THE POINT. The intent is written and FLUSHED before the installer is launched, because the
// preinstall reads it within seconds and a rollback whose authorisation had not landed yet would be refused by
// its own product's downgrade guard — the exact failure this path exists to end.
//
// No staging and no digest check here, unlike Execute, and deliberately: this package is not being fetched
// from anywhere. It is the one the installer stored on this disk, under a root-only directory, at the moment
// it installed the version now being returned to. Re-verifying it against a manifest would mean requiring a
// manifest for a version the fleet may have withdrawn, which is precisely the situation a rollback is for.
func (p *Platform) ExecuteRollback(pkg, toVersion string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("rolling back to %s needs root (installer -pkg -target /, and an authorisation only root "+
			"may write) and this process is uid %d", toVersion, os.Geteuid())
	}
	st, err := os.Stat(pkg)
	if err != nil {
		return fmt.Errorf("the stored package for %s cannot be read: %w", toVersion, err)
	}
	if st.Size() == 0 {
		return fmt.Errorf("the stored package for %s is empty (%s) — a torn copy is not restore material", toVersion, pkg)
	}
	// ★★ WHO BUILT THESE BYTES IS ASKED HERE TOO (2026-08-13, thirtieth review #19). The paragraph above explains
	// why the DIGEST is not re-checked on this path, and that argument is sound: it would require a manifest for
	// a version the fleet may have withdrawn, which is the situation a rollback is for. It does not extend to the
	// publisher check, which needs no manifest at all — the answer is in the package. Leaving it out meant the
	// control that describes itself as "the gate between bytes and a privileged installer" had a second door,
	// and anything that could write to the rollback directory could be installed as root by triggering a
	// rollback.
	//
	// A device with no publisher configured still rolls back, exactly as it still updates — the requirement's
	// absence is a stated gap, not a refusal. What is refused is a package this publisher did not build, and the
	// consequence is worth naming: restore material captured while notarization was unavailable will not
	// install. That is the same trade the forward path already makes, and the recovery it costs is a recovery
	// into bytes we cannot vouch for.
	if _, perr := VerifyPublisherFromConfig(p.configPath(), pkg); perr != nil {
		return fmt.Errorf("refusing to roll back to %s: %w", toVersion, perr)
	}
	intent := NewIntent(toVersion, "", pkg, p.now())
	if err := WriteIntent(IntentPath(), intent); err != nil {
		return fmt.Errorf("authorise the downgrade to %s: %w — without this the package's own preinstall refuses "+
			"it, and refusing an unintended downgrade is correct", toVersion, err)
	}
	cmd := exec.Command("/usr/sbin/installer", "-pkg", pkg, "-target", "/")
	if err := cmd.Start(); err != nil {
		// The authorisation outlives nothing it should: remove it rather than leave a live override on a device
		// where no installer is running.
		_ = os.Remove(IntentPath())
		return fmt.Errorf("launch the installer for %s: %w", toVersion, err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// DescribeSessions is a human-readable snapshot for --status: who is at this machine, and why it counts as
// busy or not.
//
// Exported because "the rollout is stalled" is diagnosed from the endpoint, and a boolean with no explanation
// sends people to the wrong place. The Windows side has the same function for the same reason.
func DescribeSessions() string {
	lockOut, lockOK := run("ioreg", "-n", "Root", "-d1", "-k", "CGSSessionScreenIsLocked")
	consoleUser, _ := run("stat", "-f%Su", "/dev/console")
	user := strings.TrimSpace(consoleUser)
	switch parseScreenLocked(lockOut, lockOK, user) {
	case lockNoConsoleUser:
		return "session: nobody is logged in at the display — nobody to interrupt"
	case lockLocked:
		return fmt.Sprintf("session: %s is logged in and the screen is LOCKED — not in use", user)
	case lockUnlocked:
		return fmt.Sprintf("session: %s is logged in and the screen is unlocked — in use", user)
	default:
		return "session: the console lock state could not be read, so whether anyone is here is unknown"
	}
}

// run executes a read-only observation command and reports whether it succeeded. A failure is an unknown, never
// a value: every caller above turns !ok into "could not tell", and the gate refuses on an unknown.
func run(name string, args ...string) (string, bool) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}
