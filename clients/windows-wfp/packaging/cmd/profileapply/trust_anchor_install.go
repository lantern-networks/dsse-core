package main

import (
	"errors"
	"fmt"
	"strings"
)

// trust_anchor_install.go — what provisioning adds to the machine trust store, and what it records having added.
//
// doInstallTrustAnchor (interception_root_windows.go) is only the store: list reads it, add puts one certificate
// in. Every decision is here, where it runs on any platform and can be tested as the code that ships.

// installTrustAnchor lays the certificates in the PEM at path into the store and records which it added.
func installTrustAnchor(path, what string, list func() ([]parsedRoot, error), add func(der []byte) error) error {
	incoming, err := readInterceptionRoots(path)
	if err != nil {
		return err
	}
	existing, err := list()
	if err != nil {
		return err
	}
	plan, err := planRootInstall(existing, incoming)
	if err != nil {
		return err
	}
	for _, r := range plan.AlreadyPresent {
		fmt.Printf("profileapply: interception root already trusted, nothing to do: %s (%s)\n", r.Subject, r.SHA256)
	}
	// See trust_added_record.go: what a package that kept no record was trusting from this PEM is still that
	// package's, and its removal would have taken it back.
	inherited, err := inheritFromOlderPackage(path, plan.AlreadyPresent)
	if err != nil {
		return fmt.Errorf("read what the previous package trusted from %s: %w", path, err)
	}
	for _, fp := range inherited {
		fmt.Printf("profileapply: %s %s was trusted by the package this one replaced; it is taken back at uninstall, as that package would have done\n", what, fp)
	}
	// What the record named before this provisioning began: those were provisioning's already.
	owned, _, err := readTrustAddedRecord(path)
	if err != nil {
		return fmt.Errorf("read which %s certificates provisioning added: %w", what, err)
	}
	added := append([]string{}, inherited...)
	// See trust_added_record.go: a removal takes back only these, never a certificate that was already trusted.
	//
	// ★★ AND EACH IS RECORDED BEFORE IT GOES IN (2026-11-05). A removal that finds the note and no
	// record takes back only what the note names, so a certificate in the store that the record does not name
	// stays trusted. Recorded after the add, a failure between the two — the record's write, the custom action
	// ended — would leave exactly that.
	if err := recordTrustAdded(path, added); err != nil {
		return fmt.Errorf("record which %s certificates provisioning added: %w", what, err)
	}
	for _, r := range plan.Add {
		fp := strings.ToLower(strings.TrimSpace(r.SHA256))
		if err := recordTrustAdded(path, []string{fp}); err != nil {
			return fmt.Errorf("record %s (%s) before trusting it: %w", r.Subject, r.SHA256, err)
		}
		if aerr := add(r.DER); aerr != nil {
			failed := fmt.Errorf("%s (%s): %w", r.Subject, r.SHA256, aerr)
			// ★★ A REFUSED ADD IS NOT PROVISIONING'S (2026-11-06). Recorded first and left in the
			// record after the store refused it, the certificate became provisioning's although it never went
			// in: if the administrator then trusted it by hand — or another program had just added it, which is
			// what makes an add of a new certificate fail as a duplicate — the uninstall took it out, retry or
			// not, since a retry finds it already trusted and the record keeps what it named. So the entry this
			// attempt made is taken back out. One the record held before this provisioning began stays: that
			// one was provisioning's already. Only an add whose outcome is unknown — the process ended inside
			// it — leaves the entry, which is what the entry is there for.
			if !owned[fp] {
				if uerr := forgetTrustAdded(path, fp); uerr != nil {
					return errors.Join(failed, fmt.Errorf("and the record of what provisioning added still names "+
						"it, so an uninstall would take it out if it is trusted later by other means: %w", uerr))
				}
			}
			return failed
		}
		fmt.Printf("profileapply: %s INSTALLED into LocalMachine\\Root: %s (%s)\n", what, r.Subject, r.SHA256)
	}
	if err := forgetOlderPackageTrust(path); err != nil {
		fmt.Printf("profileapply: WARNING: %s is recorded, but the note of what the previous package trusted could not be removed: %v\n", what, err)
	}
	return nil
}
