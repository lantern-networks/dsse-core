package main

import (
	"errors"
	"fmt"
)

type cleanupStep struct {
	name string
	run  func() error
}

// runCleanup attempts every independent step and preserves every failure. Callers
// keep dependent phases separate: a failed recovery must never unload the driver,
// and a failed removal must never discard the packages needed to repair it.
func runCleanup(steps ...cleanupStep) error {
	var problems []error
	for _, step := range steps {
		if err := step.run(); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", step.name, err))
		}
	}
	return errors.Join(problems...)
}

type uninstallSteps struct {
	stop, recover, anchors, profile, verifier, driver, rollbackStore func() error
}

// uninstallMachine does not promise to undo irreversible trust removal. On any
// error MSI must report failure; its rollback finalizer holds services stopped
// and disabled. PEM evidence and reinstall escrow remain available for an
// idempotent retry. No rollback path re-trusts a removed CA or adopts an old pin.
func uninstallMachine(s uninstallSteps) error {
	if err := recoverInstallerNetwork(s.stop, s.recover); err != nil {
		return err
	}
	if err := runCleanup(cleanupStep{"remove anchors", s.anchors},
		cleanupStep{"clear profile", s.profile}, cleanupStep{"clear verifier", s.verifier}); err != nil {
		return err
	}
	if err := runCleanup(cleanupStep{"remove driver", s.driver}); err != nil {
		return err
	}
	return runCleanup(cleanupStep{"clear rollback store", s.rollbackStore})
}

func recoverInstallerNetwork(stop, recover func() error) error {
	if err := runCleanup(cleanupStep{"stop services", stop}); err != nil {
		return err
	}
	return runCleanup(cleanupStep{"recover network", recover})
}

func rollbackFreshMachine(stop, recover, driver func() error) error {
	if err := recoverInstallerNetwork(stop, recover); err != nil {
		return err
	}
	return runCleanup(cleanupStep{"remove fresh-install driver", driver})
}
