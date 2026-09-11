//go:build !windows

package main

import "crypto/x509"

// On non-Windows builds there is no Windows trust store to scan; the interception-root report is a Windows
// concern (the macOS NE has its own SecTrustSettings implementation). The stub keeps the portable report logic
// compiling and unit-testable on Linux CI — it simply finds nothing, which the report treats as "omit".
func interceptionRootsPresent([]string) []string { return nil }

// deviceRootPool returns the roots this device would verify an intercepted chain against. On non-Windows builds
// there is no store to walk, so nil is returned — and nil means "use the platform pool" to crypto/x509, which is
// the right answer everywhere except the platform this client actually runs on.
func deviceRootPool() *x509.CertPool { return nil }
