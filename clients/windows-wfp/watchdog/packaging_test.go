package main

import (
	"os"
	"strings"
	"testing"
)

// This repo has already paid for this guard once. dsse-stepup-window.exe was implemented, wired in, and never
// added to the installer; because the lookup falls back silently when the file is absent, the feature simply
// never ran on an installed agent and nothing said so (see steer/companions.go).
//
// The watchdog is a worse candidate for that failure than the step-up window was. It does nothing at all in
// normal operation, so an unpackaged watchdog looks exactly like a working one — right up to the incident it
// was supposed to handle, where its absence is indistinguishable from it having decided not to act.

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestWatchdogIsBuiltAndInstalled(t *testing.T) {
	build := read(t, "../packaging/build-msi.ps1")
	if !strings.Contains(build, "./clients/windows-wfp/watchdog") {
		t.Error("build-msi.ps1 does not build the watchdog: it would be absent from the MSI staging dir")
	}
	if !strings.Contains(build, "dsse-watchdog.exe") {
		t.Error("build-msi.ps1 does not produce dsse-watchdog.exe")
	}

	wxs := read(t, "../packaging/DsseAgent.wxs")
	if !strings.Contains(wxs, `Source="dsse-watchdog.exe"`) {
		t.Error("DsseAgent.wxs does not install dsse-watchdog.exe")
	}
	if !strings.Contains(wxs, `<ComponentRef Id="WatchdogExe" />`) {
		t.Error("the WatchdogExe component is defined but not referenced by the Feature — WiX would omit it")
	}
	if !strings.Contains(wxs, `Name="DsseWatchdog"`) {
		t.Error("DsseAgent.wxs installs the exe but does not register the DsseWatchdog service; " +
			"an executable nobody runs is not a watchdog")
	}
}

// The watchdog is useless if it starts only when the thing it watches is healthy, and it is useless if it is
// not running at boot. Both are one attribute each, and both are easy to "tidy" into wrongness later.
func TestWatchdogServiceStartsOnItsOwn(t *testing.T) {
	wxs := read(t, "../packaging/DsseAgent.wxs")
	i := strings.Index(wxs, `Id="DsseWatchdogSvc"`)
	if i < 0 {
		t.Fatal("DsseWatchdogSvc ServiceInstall not found")
	}
	end := strings.Index(wxs[i:], "/>")
	if end < 0 {
		t.Fatal("malformed DsseWatchdogSvc element")
	}
	elem := wxs[i : i+end]

	if !strings.Contains(elem, `Start="auto"`) {
		t.Errorf("DsseWatchdog must be auto-start; a watchdog that needs starting by hand is not watching. Got:\n%s", elem)
	}
	if !strings.Contains(elem, `Account="LocalSystem"`) {
		t.Errorf("DsseWatchdog must run as LocalSystem: reading the driver and running recovery both need it. Got:\n%s", elem)
	}

	// A dependency on DsseSteer or DsseWfp would keep the watchdog stopped in precisely the situation it
	// exists for — one of them being gone.
	if strings.Contains(elem, "ServiceDependency") {
		t.Errorf("DsseWatchdog must NOT depend on another service; the absence of one is what it watches for. Got:\n%s", elem)
	}
	depBlock := wxs[i : i+end+len("/>")+200]
	if strings.Contains(depBlock, `<ServiceDependency Id="DsseSteer"`) || strings.Contains(depBlock, `<ServiceDependency Id="DsseWfp"`) {
		t.Error("DsseWatchdog must not declare a dependency on DsseSteer or DsseWfp")
	}
}

// On an MSI-installed box the watchdog finds the agent beside itself. That is now a FALLBACK — the DsseSteer
// service's own ImagePath is asked first (see resolveSteerExe), because assuming the name is what made the
// watchdog detect a black hole on win-dev-1 and then fail to act on it. The fallback still has to work, since
// it is what covers a box whose service has been removed while the driver is left armed — and that box is
// worth recovering precisely because nothing else will.
func TestTheRecoveryBinaryTheWatchdogInvokesIsInstalledBesideIt(t *testing.T) {
	wxs := read(t, "../packaging/DsseAgent.wxs")
	if !strings.Contains(wxs, `Source="`+steerExeNameForTest+`"`) {
		t.Fatalf("the watchdog falls back to running %q for recovery, but DsseAgent.wxs does not install a file by that name",
			steerExeNameForTest)
	}
	// Both live in INSTALLDIR, which is what makes "beside itself" resolution valid.
	if !strings.Contains(wxs, `<Directory Id="INSTALLDIR" Name="DSSE">`) {
		t.Error("INSTALLDIR layout changed; the watchdog resolves its fallback binary relative to its own directory")
	}
}

// steerExeNameForTest mirrors the first entry of the Windows-only steerExeFallbackNames so this test compiles
// on any host. Keeping the literal in one place per build tag is the trade for having the guard run
// off-Windows at all — and the guard existing everywhere matters more, since the CI runner is not Windows.
const steerExeNameForTest = "dsse-steer.exe"

// The watchdog looks for the agent's DNS-takeover backup by name. The agent writes it under a name of its
// own, in a different package, in a file this one never compiles against — so nothing but a test keeps the two
// equal. A rename on the agent side would not break any build; it would make the watchdog conclude "the
// resolver was restored" on every box, forever, and the only symptom would be fail-open machines quietly
// losing name resolution after their agent dies. That is the exact regression this residue check was added to
// close, re-created by a rename.
func TestTheDNSResidueFilenameMatchesWhatTheAgentWrites(t *testing.T) {
	agent := read(t, "../steer/dns_resolver_windows.go")
	if !strings.Contains(agent, `"`+dnsResidueFileNameForTest+`"`) {
		t.Fatalf("the watchdog looks for %q, but steer/dns_resolver_windows.go does not write a file by that name",
			dnsResidueFileNameForTest)
	}
	// And it must be written beside the agent binary, which is what makes resolving it from the agent's path
	// correct. If it moved to ProgramData the lookup would find nothing and report "restored".
	if !strings.Contains(agent, `filepath.Join(filepath.Dir(exe), "`+dnsResidueFileNameForTest+`")`) {
		t.Error("the DNS backup is no longer written beside the agent binary; the watchdog resolves it from " +
			"the agent's directory and would silently stop finding it")
	}
	// The residue is only meaningful because it is CONSUMED on restore. If the agent stopped deleting it, the
	// watchdog would see residue forever and recover healthy boxes.
	if !strings.Contains(agent, "os.Remove(backup)") {
		t.Error("restoreResolverFromBackup no longer deletes the backup; its presence would stop meaning " +
			"'DNS was taken over and not restored', and the watchdog would act on healthy boxes")
	}
}

// dnsResidueFileNameForTest mirrors the Windows-only constant so the guard runs off-Windows, where CI is.
const dnsResidueFileNameForTest = "dsse_dns_resolver_backup.json"
