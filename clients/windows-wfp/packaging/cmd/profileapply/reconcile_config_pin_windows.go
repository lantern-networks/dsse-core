//go:build windows

package main

// reconcile_config_pin_windows.go — putting back the verification conditions a major upgrade took away.
//
// ★★★ WHAT THIS FIXES, MEASURED ON win-dev-1 2026-09-09. A deployment-independent package carries no baked
// anchor, so provisioning writes the adopted keys into the services' ARGUMENTS — the third option
// service_args_windows.go describes, and the one that makes a generic package work at all. A MAJOR UPGRADE
// then recreates the services from the MSI's own ServiceInstall, and those arguments are gone. Nothing puts
// them back: ProvisionFromConsole runs only when CONFIG= was passed, and on an upgrade nobody passes it.
//
// The device is then in a state where every part is individually correct and the whole does not work: the
// profile is present and intact, the enrolled identity is untouched — and DsseSteer cannot verify anything,
// falls back to SAFE fail-closed defaults, finds no steering target in them, and EXITS ON A USAGE ERROR. The
// service does not start. That is worse than the box being unsteered: it is a machine whose agent will not run
// after an ordinary upgrade.
//
// ★★★ WHERE THE VALUES COME BACK FROM (review point 1 — the first version of this file got it wrong). NOT
// from %ProgramData%\DSSE\profile_signing_key.txt. Measured on this box, that file's parent directory granted
// BUILTIN\Users Write, so a standard user could create it before an upgrade read it and hand the device an
// authority of their choosing. signing_key_artefact.go already said that file is the operator's delivery and
// not what is in force; restoring from it contradicted the design it was implementing.
//
// The sources are the SERVICE ARGUMENTS, when they still name something, and the VERIFIER STORE — a registry
// key created protected and re-checked before every read (verifier_store_windows.go), filled by the immediate
// custom action that runs before RemoveExistingProducts (capture_before_upgrade_windows.go).
//
// ★★★ AND THE RECONCILE IS PER (SERVICE, FLAG). Five conditions across two services, each decided on its own
// evidence. An earlier version asked one question of the whole device, so a box whose arguments still named a
// config pin took the "already in force" branch and never restored the POLICY pin the same upgrade had
// deleted — and it put --update-pin on DsseSteer, which has no such flag.

import (
	"fmt"
	"strings"
)

// doReconcileConfigPin restores each service's absent conditions from the protected verifier store, and
// records the in-force ones that the store does not yet know.
//
// Safe to run on every install and upgrade: on a healthy box it changes no service configuration and only
// makes sure the box will survive its NEXT upgrade.
func doReconcileConfigPin() error {
	stored, storeErr := readCapturedPins()
	if storeErr != nil {
		// An untrusted store is not an absent one and must never be treated as one. Reported and non-fatal:
		// the custom action is Return="ignore", and failing the install here would turn "this box cannot
		// restore its verifier" into "this box has no agent". What it must never do is fall back to the file.
		fmt.Println("profileapply: ★ the protected verifier store cannot be trusted, so nothing is restored " +
			"from it: " + storeErr.Error())
		return nil
	}

	inForce := pinSet{}
	for _, service := range servicesWithPurposes() {
		// ★ RESTORE FIRST, RECORD SECOND, and the order matters. Recording what is in force before restoring
		// would write the post-upgrade emptiness over a good record, on exactly the box this exists for.
		if r, err := restoreMissingPinsInServiceArgs(service, stored); err != nil {
			// Reported, not fatal, and NOT silently skipped: a service whose conditions could not be put back
			// is a service that may not start, and the operator needs that in the install log.
			fmt.Println("profileapply: ★ " + service + ": the verification conditions could not be restored (" +
				err.Error() + "). This service may refuse to start.")
		} else if r.Changed() {
			fmt.Println("profileapply: ★ an upgrade recreates the services from the package and drops what " +
				"provisioning put there. " + r.Note)
		} else {
			fmt.Println("profileapply: " + r.Note)
		}

		args, found, err := serviceArgsFor(service)
		if err != nil {
			fmt.Println("profileapply: ★ " + service + " could not be read back, so what it now verifies " +
				"against is unknown: " + err.Error())
			continue
		}
		if !found {
			continue
		}
		for name, value := range pinsInArgs(service, args) {
			inForce[name] = value
		}
	}

	// ★★★ RECORD ONLY WHAT THE STORE DOES NOT ALREADY KNOW. The previous
	// version called recordCapturedPins(inForce) unconditionally and THEN printed "nothing is changed" for
	// each disagreement — so the log said one thing and the store had already been overwritten with the other.
	// A disagreement between two protected records is a fact for a person to resolve; capture and explicit
	// provisioning are where a value is adopted, and this step is neither.
	toRecord := pinSet{}
	for _, purpose := range pinPurposes {
		have, want := inForce.get(purpose.ValueName), stored.get(purpose.ValueName)
		switch {
		case have == "":
			// Nothing in force to record. Either restored above (and then have != "") or genuinely absent.
		case want == "":
			toRecord[purpose.ValueName] = have
		case have != want:
			fmt.Println("profileapply: ★ " + purpose.Service + " " + purpose.Flag + " is " + short(have) +
				" but the protected store records " + short(want) + " (" + purpose.What + "). NOTHING is " +
				"changed, in the service or in the store: which of the two is correct is not a thing this can " +
				"decide")
		}
	}
	if len(toRecord) == 0 {
		return nil
	}
	changed, err := recordCapturedPins(toRecord)
	if err != nil {
		fmt.Println("profileapply: ★ the conditions in force could NOT be recorded in the protected store (" +
			err.Error() + "). This box works now and will lose them at the next major upgrade.")
		return nil
	}
	if len(changed) > 0 {
		fmt.Println("profileapply: recorded " + strings.Join(changed, " and ") + " in the protected store, so " +
			"a major upgrade can put them back")
	}
	return nil
}
