//go:build windows

package main

// capture_before_upgrade_windows.go — saving the verification conditions while they still exist.
//
// ★★★ THE COUNTER-EXAMPLE THAT MADE THIS NECESSARY. The previous fix
// recorded the conditions from the service arguments inside --reconcile-config-pin, and that step runs too
// late to ever see them on the one box it was written for.
//
// RemoveExistingProducts now runs after InstallInitialize, before any action that
// generates execution script. The old service is still removed before the new
// package's deferred actions, so its authorities must be captured immediately,
// before removal. Transactional MSI file restoration does not reconstruct these
// custom service arguments by itself.
//
// ★ SO THIS IS AN IMMEDIATE CUSTOM ACTION, with two consequences worth stating plainly.
//
//   - It runs from the Binary table, not from INSTALLDIR, because InstallFiles has not happened yet.
//   - It runs in the installing user's context, not as SYSTEM. Reading a service's configuration needs only
//     SERVICE_QUERY_CONFIG, which is why serviceArgsFor asks for exactly that; WRITING the protected store
//     needs administrative rights. An unelevated attempt therefore FAILS HERE — before anything has been
//     removed — rather than half-way through an upgrade.
//
// ★★★ AND EVERY SERVICE IS READ, AND VALIDATED, BEFORE ANYTHING IS WRITTEN.
// The conditions live on two services — DsseSteer carries the config and policy pins, DsseUpdater the update
// pin, plan pin and publisher — and a capture that read one, wrote it, then failed on the other would leave a
// store that looks populated and is half a device. Read all, validate all, then write once.

import (
	"fmt"
	"strings"
)

// doCaptureBeforeUpgrade records the conditions the currently-installed services name, before the upgrade
// deletes them.
//
// Returning an error is the signal to halt: the caller exits non-zero and the MSI's Return="check" stops the
// transaction with the old product still in place, so nothing has been lost and the operator can retry.
func doCaptureBeforeUpgrade() error {
	captured := pinSet{}
	anyServiceFound := false

	for _, service := range servicesWithPurposes() {
		args, found, err := serviceArgsFor(service)
		if err != nil {
			// ★ THE FAILURE THIS EXISTS TO CATCH. Access denied, no SCM, an unreadable or malformed ImagePath —
			// none of these mean "this device holds nothing". Treating them as an absence is what let the old
			// capture exit 0 and hand RemoveExistingProducts a device whose only copy it was about to destroy.
			return fmt.Errorf("the configuration of %s could not be READ, which is not the same as it holding "+
				"nothing: %w", service, err)
		}
		if !found {
			continue
		}
		anyServiceFound = true
		servicePins := pinsInArgs(service, args)
		if service == "DsseUpdater" {
			if publisher, ok := legacyPublisherForCapture(args); ok {
				servicePins["Updater_Publisher"] = publisher
			}
		}
		for name, value := range servicePins {
			captured[name] = value
		}
	}

	if !anyServiceFound {
		// No DsseSteer and no DsseUpdater: this is not really an upgrade of a provisioned box, and there is
		// nothing to carry. Not an error — refusing here would refuse to install because the machine was not
		// already configured.
		fmt.Println("profileapply: pre-upgrade capture: none of the agent services are installed, so there is " +
			"nothing to carry across")
		return nil
	}

	// Validated BEFORE the first write, so a malformed value on the second service cannot leave the first one
	// already committed. A value the product would refuse is not restore material, and storing it would only
	// move the failure to the moment the service is asked to start.
	var named []string
	for _, purpose := range pinPurposes {
		v := captured.get(purpose.ValueName)
		if v == "" {
			continue
		}
		if err := purpose.Validate(v); err != nil {
			return fmt.Errorf("%s names a %s this device could not use after the upgrade (%w). Nothing was "+
				"saved and the install is stopped, because storing it would move the failure to the moment "+
				"the service is asked to start", purpose.Service, purpose.Flag, err)
		}
		named = append(named, purpose.Service+" "+purpose.Flag+"="+short(v))
	}

	if len(named) == 0 {
		fmt.Println("profileapply: pre-upgrade capture: the installed services name no verification condition, " +
			"so there is nothing to carry across the upgrade")
		return nil
	}
	fmt.Println("profileapply: pre-upgrade capture: " + strings.Join(named, ", "))

	// ★ THE STORE IS NOT OVERWRITTEN WHOLESALE. recordCapturedPins leaves a purpose absent from `captured`
	// exactly as it was, so an upgrade of a box that names four conditions does not erase a fifth the store
	// already holds from an earlier generation.
	changed, err := recordCapturedPins(captured)
	if err != nil {
		return fmt.Errorf("the conditions this device verifies against could NOT be saved before the upgrade "+
			"removes them (%w). The install is stopped here, with the existing product still in place, because "+
			"continuing would delete the only copy. Re-run the installer elevated; if it still fails, the "+
			"protected store has been tampered with and the message above names how", err)
	}
	if len(changed) == 0 {
		fmt.Println("profileapply: pre-upgrade capture: the protected store already recorded these")
		return nil
	}
	fmt.Println("profileapply: pre-upgrade capture: saved " + strings.Join(changed, " and ") +
		" — the upgrade may now recreate the services")
	return nil
}
