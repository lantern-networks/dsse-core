//go:build windows

// driversvc installs/removes the DsseWfp kernel WFP callout driver as a kernel-mode service (roadmap M8.4).
//
// A WFP callout is NOT a PnP device, so it is installed as a kernel SERVICE (SERVICE_KERNEL_DRIVER), which the
// Windows Installer ServiceInstall table cannot express (it only supports user-mode ownProcess/shareProcess).
// So the MSI copies the .sys and invokes this helper from a DEFERRED, no-impersonate (SYSTEM) custom action to
// create + start it on install, and to stop + delete it on uninstall. It is also the manual dev path (a typed,
// idempotent replacement for `sc create DsseWfp type= kernel …`).
//
//	driversvc --install   --name DsseWfp --sys "C:\Program Files\DSSE\dsse-wfp.sys"
//	driversvc --uninstall --name DsseWfp
//	driversvc --status    --name DsseWfp
//
// Exit: 0 ok, 1 failure, 2 usage.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func main() {
	install := flag.Bool("install", false, "create + start the kernel driver service")
	uninstall := flag.Bool("uninstall", false, "stop + delete the kernel driver service")
	status := flag.Bool("status", false, "print the service state")
	name := flag.String("name", "DsseWfp", "driver service name")
	sysPath := flag.String("sys", "", "path to the driver .sys (required for --install)")
	flag.Parse()

	n := strings.TrimSpace(*name)
	if n == "" {
		fmt.Fprintln(os.Stderr, "driversvc: --name is required")
		os.Exit(2)
	}
	m, err := mgr.Connect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "driversvc: connect SCM: %v\n", err)
		os.Exit(1)
	}
	defer m.Disconnect()

	switch {
	case *install:
		if err := doInstall(m, n, *sysPath); err != nil {
			fmt.Fprintf(os.Stderr, "driversvc: install %s: %v\n", n, err)
			os.Exit(1)
		}
		// doInstall prints the outcome itself: "installed + started" and "the new image is on disk but the
		// kernel still has the old one" are different results and must not share a sentence.
	case *uninstall:
		if err := doUninstall(m, n); err != nil {
			fmt.Fprintf(os.Stderr, "driversvc: uninstall %s: %v\n", n, err)
			os.Exit(1)
		}
		fmt.Printf("driversvc: %s stopped + deleted\n", n)
	case *status:
		st, err := doStatus(m, n, *sysPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "driversvc: status %s: %v\n", n, err)
			os.Exit(1)
		}
		fmt.Println(st)
	default:
		fmt.Fprintln(os.Stderr, "driversvc: one of --install / --uninstall / --status is required")
		os.Exit(2)
	}
}

func doInstall(m *mgr.Mgr, name, sysPath string) error {
	if strings.TrimSpace(sysPath) == "" {
		return fmt.Errorf("--sys is required")
	}
	// A relative --sys resolves against this exe's own directory, so the MSI custom action can pass a bare
	// "dsse-wfp.sys" (driversvc.exe and the .sys are co-installed in INSTALLDIR) without threading the absolute
	// INSTALLDIR through deferred-custom-action CustomActionData. The kernel service needs an ABSOLUTE binPath.
	if !filepath.IsAbs(sysPath) {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve exe dir for relative --sys: %w", err)
		}
		sysPath = filepath.Join(filepath.Dir(exe), sysPath)
	}
	if _, err := os.Stat(sysPath); err != nil {
		return fmt.Errorf("driver .sys not found: %w", err)
	}
	// What image is being installed. Used for REPORTING, never to decide whether a reload is needed: a loaded
	// kernel driver cannot be hashed from user mode, so any decision based on comparing it would be a guess.
	digest, derr := FileDigest(sysPath)
	if derr != nil {
		return fmt.Errorf("hash driver .sys: %w", derr)
	}

	// If a service by this name exists, REPLACE it — stop, delete, recreate — whether or not it points at the
	// same path.
	//
	// This used to short-circuit when the path matched, and across an upgrade the path ALWAYS matches: the
	// .sys lives at a fixed location, so new bytes were written to disk while the previously loaded image kept
	// running, and this printed "installed + started" and exited 0. The whole fleet could be told it had a
	// security-fixed callout and be running the old one.
	//
	// The replacement is unconditional rather than conditional on a content check, because the content check
	// that matters — "is the running kernel image the same as this file" — is not answerable. An unnecessary
	// reload costs a moment with no WFP filters, during an install, when the agent is stopped anyway; and a
	// driver with no filters passes traffic rather than black-holing it. Paying that reliably beats deciding
	// with information we do not have.
	reloaded := false
	if s, err := m.OpenService(name); err == nil {
		reloaded = true
		if cfg, cerr := s.Config(); cerr == nil && !SameDriverImagePath(cfg.BinaryPathName, sysPath) {
			fmt.Printf("driversvc: %s currently points at %q; replacing it with %q\n", name, cfg.BinaryPathName, sysPath)
		}
		stopServiceIfRunning(s)
		// A driver still running here could not be unloaded — something holds it open, or it does not support
		// dynamic unload. The new bytes are on disk and the OLD code is in the kernel: a pending reboot, not a
		// success. Record it and say so; do NOT delete/recreate, which would fail anyway and leave the box
		// without a driver service.
		if st, qerr := s.Query(); qerr == nil && st.State != svc.Stopped {
			s.Close()
			recordPendingReboot(name, digest)
			fmt.Println(DescribeInstallOutcome(name, digest, true, &PendingReboot{Digest: digest}))
			return nil
		}
		if derr := s.Delete(); derr != nil {
			s.Close()
			return fmt.Errorf("replace driver service: delete: %w", derr)
		}
		s.Close()
	}
	s, err := createKernelDriverService(m, name, sysPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	if err := startDriver(s); err != nil {
		return err
	}
	// The kernel loaded this file, so any earlier "reboot required" note is spent.
	clearPendingReboot(name)
	fmt.Println(DescribeInstallOutcome(name, digest, reloaded, nil))
	return nil
}

// createKernelDriverService creates the DsseWfp service via the raw Win32 CreateService with the .sys path as a
// LITERAL, UNQUOTED ImagePath. mgr.CreateService is not used because it always windows.EscapeArg()s the path —
// correct for a user-mode service's command line, but for a kernel driver the ImagePath is a plain path, so a
// space-containing path (e.g. C:\Program Files\DSSE\dsse-wfp.sys) would be wrongly quoted and StartService would
// fail with ERROR_INVALID_NAME. SCM normalizes a plain path to the \??\ NT form for drivers on its own.
func createKernelDriverService(m *mgr.Mgr, name, sysPath string) (*mgr.Service, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	dispPtr, err := windows.UTF16PtrFromString("Lantern DSSE WFP Callout Driver")
	if err != nil {
		return nil, err
	}
	pathPtr, err := windows.UTF16PtrFromString(sysPath) // plain, unquoted
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateService(m.Handle, namePtr, dispPtr,
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_KERNEL_DRIVER,
		windows.SERVICE_DEMAND_START,
		windows.SERVICE_ERROR_NORMAL,
		pathPtr, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

func startDriver(s *mgr.Service) error {
	st, err := s.Query()
	if err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		// ERROR_SERVICE_ALREADY_RUNNING is fine.
		if err == windows.ERROR_SERVICE_ALREADY_RUNNING {
			return nil
		}
		return fmt.Errorf("start: %w", err)
	}
	return waitState(s, svc.Running, 15*time.Second)
}

func doUninstall(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return nil // already absent — uninstall is idempotent
	}
	defer s.Close()
	stopServiceIfRunning(s)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}

// stopServiceIfRunning best-effort stops a service and waits for it to reach Stopped (bounded). Used before a
// delete/replace so the driver image is unloaded first.
func stopServiceIfRunning(s *mgr.Service) {
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, cerr := s.Control(svc.Stop); cerr == nil || cerr == windows.ERROR_SERVICE_NOT_ACTIVE {
			_ = waitState(s, svc.Stopped, 15*time.Second)
		}
	}
}

// sameDriverImage compares a service's current ImagePath (as SCM stores it, e.g. "\??\C:\Program Files\...") to
// the desired .sys path, tolerant of the \??\ NT prefix and Windows' case-insensitive paths.
func sameDriverImage(current, want string) bool {
	norm := func(p string) string {
		p = strings.TrimPrefix(p, `\??\`)
		return strings.ToLower(filepath.Clean(strings.TrimSpace(p)))
	}
	return norm(current) == norm(want)
}

// doStatus reports the service state AND whether the loaded image is the one on disk.
//
// The second half is why the pending note is persisted at all. "state=4" (running) was previously the whole
// answer, and a box running the PREVIOUS driver after an upgrade looks exactly like a healthy one by that
// measure — which is how a fleet can be told it is patched and not be. A status command that cannot express
// "running, but not the code you installed" is a status command that hides the failure it should surface.
func doStatus(m *mgr.Mgr, name, sysPath string) (string, error) {
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Sprintf("%s: absent", name), nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", err
	}
	line := fmt.Sprintf("%s: state=%d", name, st.State)

	onDisk := ""
	if p := strings.TrimSpace(sysPath); p != "" {
		if !filepath.IsAbs(p) {
			if exe, eerr := os.Executable(); eerr == nil {
				p = filepath.Join(filepath.Dir(exe), p)
			}
		}
		if d, derr := FileDigest(p); derr == nil {
			onDisk = d
			line += fmt.Sprintf(" on_disk_image=sha256:%s…", d[:12])
		}
	}
	if pending, why := PendingRebootStatus(readPendingReboot(name), bootID(), onDisk); pending {
		line += fmt.Sprintf(" PENDING_REBOOT=yes (%s) — the kernel is NOT running the installed image", why)
	}
	return line, nil
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for state %d (now %d)", want, st.State)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
