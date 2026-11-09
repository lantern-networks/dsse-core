package main

// trust_added_record.go — an uninstall takes back only the trust provisioning ADDED.
//
// ★★★ THE ADMINISTRATOR'S OWN ANCHOR WAS TAKEN OUT (2026-11-04, found by installing and removing the published
// 0.4.0 MSI against a fresh deployment). The administrator had trusted the deployment's anchor by hand to use the
// Console. The deployment's step-up portal is served under that same anchor, so provisioning found it already
// trusted and added nothing — and the uninstall, which removes every certificate in step_up_portal_ca.pem by
// fingerprint, removed it anyway. windows-agent.md tells the reader the opposite: certificates the administrator
// installed independently, including a Console anchor, are kept.
//
// So provisioning records, beside each PEM it trusts, the fingerprints it actually added, and the removal takes
// back only those. The record is written even when nothing was added: its presence is what tells a removal that
// the accounting exists. A PEM with no record and no note (below) was trusted by an older package, and keeps the
// older behaviour.

import (
	"os"
	"sort"
	"strings"
)

func trustAddedRecordPath(pemPath string) string { return pemPath + ".added-by-provisioning" }

// readTrustAddedRecord returns the fingerprints provisioning added for pemPath, and whether a record exists.
func readTrustAddedRecord(pemPath string) (map[string]bool, bool, error) {
	return readFingerprintList(trustAddedRecordPath(pemPath))
}

// readFingerprintList reads one fingerprint per line, and whether the file exists. An empty file exists.
func readFingerprintList(path string) (map[string]bool, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if fp := strings.ToLower(strings.TrimSpace(line)); fp != "" {
			out[fp] = true
		}
	}
	return out, true, nil
}

// recordTrustAdded adds fingerprints to the record for pemPath, keeping what an earlier provisioning added.
func recordTrustAdded(pemPath string, added []string) error {
	prev, _, err := readTrustAddedRecord(pemPath)
	if err != nil {
		return err
	}
	all := map[string]bool{}
	for fp := range prev {
		all[fp] = true
	}
	for _, fp := range added {
		if fp = strings.ToLower(strings.TrimSpace(fp)); fp != "" {
			all[fp] = true
		}
	}
	return writeTrustAddedRecord(pemPath, all)
}

// forgetTrustAdded takes one fingerprint back out of the record for pemPath, keeping the rest.
func forgetTrustAdded(pemPath, fingerprint string) error {
	prev, ok, err := readTrustAddedRecord(pemPath)
	if err != nil || !ok {
		return err
	}
	delete(prev, strings.ToLower(strings.TrimSpace(fingerprint)))
	return writeTrustAddedRecord(pemPath, prev)
}

func writeTrustAddedRecord(pemPath string, fingerprints map[string]bool) error {
	list := make([]string, 0, len(fingerprints))
	for fp := range fingerprints {
		list = append(list, fp)
	}
	sort.Strings(list)
	body := strings.Join(list, "\n")
	if body != "" {
		body += "\n"
	}
	return os.WriteFile(trustAddedRecordPath(pemPath), []byte(body), 0o644)
}

// onlyWhatProvisioningAdded narrows the roots a removal may take to the ones the record says provisioning added.
// Without a record or a note (an older package trusted them, and nothing since has touched them) every root in
// the PEM is returned, as before.
//
// ★★ A NOTE WITHOUT A RECORD IS A PROVISIONING THAT NEVER FINISHED (2026-11-05). The note below
// is written before the PEM is rewritten and removed only once the record exists, so a PEM with a note and no
// record may already be THIS package's — written, and then the store install refused (a different authority
// holds one of its names) or never ran. The removal read "no record" as "an older package's PEM" and took every
// certificate in it: a fresh install that failed and was then uninstalled took out a certificate the
// administrator had trusted by hand, which provisioning had never added. What provisioning answers for there is
// what the note says the older package was trusting — nothing, after a fresh install.
func onlyWhatProvisioningAdded(pemPath string, roots []parsedRoot) ([]parsedRoot, error) {
	added, ok, err := readTrustAddedRecord(pemPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		noted, hasNote, err := readFingerprintList(olderPackageTrustPath(pemPath))
		if err != nil {
			return nil, err
		}
		if !hasNote {
			return roots, nil
		}
		added = noted
	}
	out := []parsedRoot{}
	for _, r := range roots {
		if added[strings.ToLower(strings.TrimSpace(r.SHA256))] {
			out = append(out, r)
		}
	}
	return out, nil
}

// ★★★ AND A PACKAGE THAT KEPT NO RECORD STILL OWNS WHAT IT TRUSTED (2026-11-04, found by upgrading a device from
// the 0.4.0 MSI to 0.4.1 and uninstalling). 0.4.0 trusted the organization's interception root and kept no record.
// The 0.4.1 provisioning found that root already trusted, recorded that it had added nothing, and so the
// uninstall left an interception root trusted on a device that no longer belonged to anything — a root that
// signs any name, held by a deployment that may already be gone. The empty record had erased the only thing
// that said who put it there: that the PEM existed with no record beside it.
//
// So, before provisioning rewrites a PEM that has no record, it notes the fingerprints the older package was
// trusting from it. Of those, the ones the store still holds are recorded as provisioning's own, which is what
// the older package's removal would have taken back. A certificate the administrator ALSO imported by hand is
// among them and cannot be told apart; on a device upgraded from a package that kept no record it is taken back
// at uninstall, as that package would have done.

func olderPackageTrustPath(pemPath string) string { return pemPath + ".trusted-by-older-package" }

// captureOlderPackageTrust runs before provisioning rewrites pemPath. With no record, it notes the fingerprints
// the PEM there holds — none, when there is no PEM. The first note stands, so a provisioning that failed after
// rewriting the PEM does not replace what the older package trusted with what this one wrote.
//
// ★★ "NOTHING WAS THERE" IS NOTED TOO (2026-11-05). The note used to be written only when a PEM
// was present, so a FRESH install left none. If that install then failed after writing its PEM and before the
// record, the retry found a PEM with no record and no note, and noted this package's own PEM as the older
// package's — and a certificate the administrator had already trusted by hand (the deployment anchor, under
// which the step-up portal is served) was recorded as provisioning's and taken out at uninstall. An empty note
// says the older package trusted nothing from this path, and it stands like any other first note.
func captureOlderPackageTrust(pemPath string) error {
	if _, ok, err := readTrustAddedRecord(pemPath); err != nil || ok {
		return err
	}
	if _, err := os.Stat(olderPackageTrustPath(pemPath)); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	roots, err := readOurRoots(pemPath)
	if err != nil {
		return err
	}
	list := make([]string, 0, len(roots))
	for _, r := range roots {
		if fp := strings.ToLower(strings.TrimSpace(r.SHA256)); fp != "" {
			list = append(list, fp)
		}
	}
	sort.Strings(list)
	body := strings.Join(list, "\n")
	if body != "" {
		body += "\n"
	}
	return os.WriteFile(olderPackageTrustPath(pemPath), []byte(body), 0o644)
}

// inheritFromOlderPackage is, of the roots already trusted, the ones the older package was trusting from pemPath.
func inheritFromOlderPackage(pemPath string, alreadyPresent []parsedRoot) ([]string, error) {
	noted, _, err := readFingerprintList(olderPackageTrustPath(pemPath))
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, r := range alreadyPresent {
		if fp := strings.ToLower(strings.TrimSpace(r.SHA256)); noted[fp] {
			out = append(out, fp)
		}
	}
	return out, nil
}

// forgetOlderPackageTrust removes the note once the record holds what it said.
func forgetOlderPackageTrust(pemPath string) error {
	if err := os.Remove(olderPackageTrustPath(pemPath)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
