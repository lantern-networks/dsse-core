//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func runInstalledHelper(dir, name string, args ...string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("installed helper directory must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(dir, name), args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// Disable before stopping, including watchdog/updater, so another service or a
// reboot cannot restart a partially removed deployment. A rollback action runs
// this again AFTER MSI has restored its service rows. Missing services are the
// ordinary retry case; access denial is never treated as absence.
func holdInstallerServices() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	var steps []cleanupStep
	for _, name := range []string{"DsseUpdater", "DsseWatchdog", "DsseSteer"} {
		steps = append(steps, cleanupStep{name, func() error { return disableAndStop(m, name) }})
	}
	return runCleanup(steps...)
}

func disableAndStop(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.StartType = windows.SERVICE_DISABLED
	// Still try stopping if changing the start type failed, but keep both errors.
	return runCleanup(cleanupStep{"disable", func() error {
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
		actual, err := s.Config()
		if err != nil {
			return err
		}
		if actual.StartType != windows.SERVICE_DISABLED {
			return fmt.Errorf("service is not disabled after configuration update")
		}
		return nil
	}},
		cleanupStep{"confirm stopped", func() error {
			deadline := time.Now().Add(2 * time.Minute)
			for {
				st, err := s.Query()
				if err != nil {
					return err
				}
				if st.State == svc.Stopped {
					return nil
				}
				if st.State != svc.StopPending {
					if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
						return err
					}
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("timeout waiting for observed stopped state")
				}
				time.Sleep(100 * time.Millisecond)
			}
		}})
}

func doUninstallMachine(dir string) error {
	return uninstallMachine(uninstallSteps{
		stop: holdInstallerServices,
		recover: func() error {
			return runInstalledHelper(dir, "dsse-steer.exe", "--mode", "recover", "--recover-keep-services")
		},
		anchors: func() error { return doRemoveEverythingProvisioningTrusted(escrowDir()) },
		profile: func() error {
			be, err := configstore.ProductionRegistryBackend()
			if err != nil {
				return err
			}
			return configstore.Clear(be)
		},
		verifier:      clearAdoptedVerifier,
		driver:        func() error { return runInstalledHelper(dir, "driversvc.exe", "--uninstall", "--name", "DsseWfp") },
		rollbackStore: doClearRollbackStore,
	})
}

// Rollback cannot restore custom-action trust mutations safely. Hold the
// product inert and recover through the installed executable at this rollback stage. Never
// recreate a trust anchor, read a mutable key artifact, or start steering here.
func doHoldIncompleteUninstall(dir string) error {
	fmt.Fprintln(os.Stderr, "profileapply: MSI removal/rollback is INCOMPLETE; holding services disabled. Retry uninstall or explicitly reprovision; rollback does not restore removed trust.")
	return prepareDriverReplacement(dir)
}

func prepareDriverReplacement(dir string) error {
	return recoverInstallerNetwork(holdInstallerServices, func() error {
		return runInstalledHelper(dir, "dsse-steer.exe", "--mode", "recover", "--recover-keep-services")
	})
}

func doRollbackFreshMachine(dir string) error {
	return rollbackFreshMachine(holdInstallerServices, func() error {
		return runInstalledHelper(dir, "dsse-steer.exe", "--mode", "recover", "--recover-keep-services")
	}, func() error { return runInstalledHelper(dir, "driversvc.exe", "--uninstall", "--name", "DsseWfp") })
}
