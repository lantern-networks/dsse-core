//go:build windows

// ncsi_probe_policy_windows.go — manage Windows' NCSI *active* connectivity test for the steered lifetime.
//
// Under steer-all every outbound flow is redirected to the local terminator. That is a genuine, truthful
// interception, and NCSI (NlaSvc) is *designed* to detect interception: its active probe resolves
// dns.msftncsi.com (expecting 131.107.255.255) and GETs msftconnecttest.com/connecttest.txt (expecting
// "Microsoft Connect Test"). We answer BOTH locally + byte-correct (see ncsi_answer.go), yet the NCSI event
// log still records `ChangeReason: SuspectDnsProbeFailed` and downgrades the link to "No Internet" — because
// the answer being right does not matter once the *behaviour* (all traffic terminating ~1 hop away, a
// locally-served web probe) looks intercepted. The active probe is therefore structurally unsatisfiable under
// a local redirect; no DNS/web answer can make NCSI trust it.
//
// So for the steered lifetime we disable NCSI's active test via the supported policy value
// (HKLM\SOFTWARE\Policies\...\NetworkConnectivityStatusIndicator\NoActiveProbe = 1) and let NCSI's PASSIVE
// detector + the IPv6 connectivity aggregate drive the OS label truthfully (traffic really does reach the
// internet, so passive/aggregate report "connected"). We snapshot the prior value and restore it on clean
// stop — exactly like the DNS takeover (dns_resolver_windows.go) — and --mode recover undoes it after an
// unclean exit. Residual limit: on an IPv4-only network with no IPv6, the passive IPv4 signal is also "Local"
// (loopback redirect) and nothing carries the aggregate, so the label can still read "No Internet"; that is
// inherent to steer-all's local-redirect design and is cosmetic (traffic flows regardless).
//
// Best-effort throughout: NCSI labeling is cosmetic, so every failure is logged, never fatal.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ncsiPolicyPath is the HKLM-relative policy key (registry API form; the old code used the "HKLM:\..." PowerShell
// provider path). Set NoActiveProbe=1 here to disable NCSI's active connectivity probe for the steered lifetime.
const ncsiPolicyPath = `SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator`

// ncsiReadNoActiveProbe returns the current NoActiveProbe DWORD as a decimal string, or ("",false) if the key or
// value is absent. In-process registry read (no child process — session-0 safe).
func ncsiReadNoActiveProbe() (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ncsiPolicyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("NoActiveProbe")
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(v, 10), true
}

// ncsiWriteNoActiveProbe sets NoActiveProbe to val (creating the key if needed).
func ncsiWriteNoActiveProbe(val uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ncsiPolicyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue("NoActiveProbe", val)
}

// ncsiDeleteNoActiveProbe removes the value (restores NCSI's default: active probe on). No-op if already absent.
func ncsiDeleteNoActiveProbe() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ncsiPolicyPath, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if err := k.DeleteValue("NoActiveProbe"); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

// restartService stops then starts a service via the SCM API (no child process — session-0 safe). Bounded wait
// for STOPPED before Start. Best-effort: NlaSvc always ends up running (Start on a still-running service errors
// harmlessly), so a stuck NlaSvc is not left behind.
func restartService(name string) error {
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
	stopped := false
	if _, err := s.Control(svc.Stop); err == nil {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			q, qerr := s.Query()
			if qerr != nil || q.State == svc.Stopped {
				stopped = true
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if err := s.Start(); err != nil && stopped {
		// We stopped it but couldn't start — retry once so NlaSvc is never left down.
		time.Sleep(500 * time.Millisecond)
		return s.Start()
	}
	return nil
}

// ncsiProbeBackupPath stores the pre-steer NoActiveProbe value next to the binary so a clean stop (or
// --mode recover) after a service restart can still restore it. Holds either "absent" or the prior DWORD.
func ncsiProbeBackupPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "dsse_ncsi_probe_backup.txt"
	}
	return filepath.Join(filepath.Dir(exe), "dsse_ncsi_probe_backup.txt")
}

// isAllDigits reports whether s is a non-empty run of ASCII digits — the only shape we ever write back into
// the registry value, so a corrupted/garbage backup can never be injected into the restore PowerShell.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// suppressNCSIActiveProbe snapshots the current NoActiveProbe value (or "absent") to the backup file, sets
// NoActiveProbe=1, and restarts NlaSvc so the change takes effect promptly (the initial arm has no network
// change to trigger a re-probe on its own).
func suppressNCSIActiveProbe() {
	backup := ncsiProbeBackupPath()
	// Snapshot the PRE-steer value exactly once. If a snapshot already exists we are RE-arming — a supervisor
	// restart, or an UNCLEAN exit that skipped the restore defer and left NoActiveProbe=1 — so keep it: it holds
	// the true pre-steer value. Re-capturing here would snapshot our OWN "=1" and leave NCSI's active test stuck
	// off after the next clean stop. Mirrors resolverManager.start(), which loads the persisted DNS backup rather
	// than re-capturing the (already-taken-over) live config.
	prior := ""
	if b, err := os.ReadFile(backup); err == nil {
		prior = strings.TrimSpace(string(b))
	}
	if prior == "" {
		prior = "absent"
		if v, ok := ncsiReadNoActiveProbe(); ok {
			prior = v
		}
		if err := os.WriteFile(backup, []byte(prior), 0o600); err != nil {
			fmt.Printf("ncsi_probe: WARNING could not persist NoActiveProbe backup: %v\n", err)
		}
	}
	if err := ncsiWriteNoActiveProbe(1); err != nil {
		fmt.Printf("ncsi_probe: WARNING could not disable NCSI active test: %v\n", err)
		return
	}
	if err := restartService("NlaSvc"); err != nil {
		fmt.Printf("ncsi_probe: WARNING NoActiveProbe=1 set but NlaSvc restart failed (applies on next network event): %v\n", err)
	}
	fmt.Printf("ncsi_probe: NCSI active connectivity test DISABLED (NoActiveProbe=1, prior=%s) — under steer-all the active probe is intercepted/unsatisfiable; passive detection + IPv6 aggregate now drive the OS connectivity label. Restored on clean stop.\n", prior)
}

// restoreNCSIActiveProbe puts NoActiveProbe back to its pre-steer value (removing the value if it was absent)
// and restarts NlaSvc. Reads the persisted snapshot so it works even across a service restart. Idempotent:
// running it twice (e.g. clean stop after --mode recover already ran) is a harmless no-op.
func restoreNCSIActiveProbe() {
	prior := "absent"
	if b, err := os.ReadFile(ncsiProbeBackupPath()); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			prior = s
		}
	}
	var err error
	if isAllDigits(prior) {
		v, _ := strconv.ParseUint(prior, 10, 32)
		err = ncsiWriteNoActiveProbe(uint32(v))
	} else {
		// "absent" or anything unexpected -> remove the value so NCSI returns to its default (active test on).
		prior = "absent"
		err = ncsiDeleteNoActiveProbe()
	}
	if err != nil {
		fmt.Printf("ncsi_probe: WARNING could not restore NCSI active test: %v\n", err)
	} else {
		if rerr := restartService("NlaSvc"); rerr != nil {
			fmt.Printf("ncsi_probe: WARNING NoActiveProbe restored but NlaSvc restart failed: %v\n", rerr)
		}
		fmt.Printf("ncsi_probe: NCSI active connectivity test restored (NoActiveProbe -> %s)\n", prior)
	}
	_ = os.Remove(ncsiProbeBackupPath())
}
