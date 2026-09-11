//go:build windows

package main

import (
	"path/filepath"
	"strings"
)

// transportPinPath is where this device's PROVISIONED transport anchor lives, given whatever the operator
// passed on the command line.
//
// ★ IT EXISTS BECAUSE THE INSTALLED SERVICE PASSES NOTHING (2026-08-12, measured on win-dev-1). The MSI's
// service line is `--service-run --config-store` — no --transport-pinned-ca — and every version of the trust
// selection so far has been keyed on that flag. An enrolled box therefore resolved to no anchor at all: first
// silently falling back to the enrolled device-issuing CA, then (correctly) to an empty root set. Both are the
// same practical state, a machine that cannot complete one (T) handshake, and neither is a trust decision
// anybody made.
//
// The anchors were on disk the whole time, in %ProgramData%\DSSE. Returning the well-known path rather than
// reading it here is deliberate: the caller's selection is keyed on the pin's DIRECTORY, so naming the file is
// enough to bring the adopted-bundle lookup, the REPLACE-not-union rule and the serial along unchanged.
//
// Beside the enrolled material rather than inside it, because the anchors outlive any one enrolment — a device
// that re-enrols must not lose what it verifies the Edge with.
func transportPinPath(flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	return filepath.Join(filepath.Dir(defaultEnrollDir()), provisionedTransportCAFile)
}
