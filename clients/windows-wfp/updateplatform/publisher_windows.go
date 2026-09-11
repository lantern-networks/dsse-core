//go:build windows

package updateplatform

// publisher_windows.go — asking the operating system the question publisher.go judges. This file only runs the
// verifier and refuses to guess when it cannot.

import (
	"fmt"
	"os"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/authenticode"
)

// VerifyPublisher is the gate between a verified download and a privileged installer.
//
// It returns a note when the requirement is absent or unusable — see ParsePublisherRequirement for why those
// two install rather than refuse — and an error wrapping ErrPublisherUntrusted in every other direction that
// is not a clear pass, including "the file cannot be opened". The cost of refusing wrongly is that a device
// stays on the version it is already running, which is a state it was in a second ago and can be diagnosed
// from a report; the cost of passing wrongly is arbitrary code as SYSTEM.
func VerifyPublisher(pkgPath string, req PublisherRequirement) (note string, err error) {
	if req.Defect != "" || !req.Configured() {
		return req.Describe(), nil
	}
	// Stat first, so "there is no such file" is not reported as "this file is not signed by Lantern". The two
	// send an operator to different places, and the second one implicates a release that is fine.
	if _, serr := os.Stat(pkgPath); serr != nil {
		return "", fmt.Errorf("%w: %s could not be opened to check who signed it (%v), and a check that cannot run "+
			"must not pass", ErrPublisherUntrusted, pkgPath, serr)
	}
	if cerr := req.Check(authenticode.Signature(pkgPath)); cerr != nil {
		return "", cerr
	}
	return "publisher verified: " + req.Describe(), nil
}
