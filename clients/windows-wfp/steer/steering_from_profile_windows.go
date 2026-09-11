//go:build windows

// steering_from_profile_windows.go — the two small rules that decide what a config-store box does when it
// starts: whether an operator actually asked for a flag, and whether a mode is one that takes over the
// machine's network path.
//
// Both were found the same way on win-dev-1 (2026-08-11): the MSI installs DsseSteer as
// `--service-run --config-store`, that is the entire argument list, and everything else has to be derived
// from the signed profile or defaulted. Neither rule was here, and the two consequences were an agent that
// enforced nothing and a service that could not start at all.
package main

import (
	"flag"
	"strings"
)

// flagWasSet reports whether the operator actually passed this flag, rather than it holding its default.
//
// flag.Visit is the only thing that can tell: it visits the flags that were SET. Comparing a value against
// its default cannot distinguish `--mode observe` — a deliberate diagnostic run on a profiled box — from a
// box that said nothing at all, and a derivation that silently overrode the first would be worse than not
// deriving anything.
func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// modeTakesTheNetworkPath reports whether this mode would apply filters, take over DNS, or build a transport
// to enforce with — the modes for which "no approved identity" must mean stand aside and idle.
//
// ★ IT REPLACED `*mode == "redirect"`, and the difference is a service that starts. The stand-aside branch
// says in its own comment that the service stays up so the SCM does not restart-loop it; it was reached only
// in redirect mode, and the MSI's service line names no mode at all. So an unenrolled MSI box fell through to
// the transport build, exited with `transport ... requires --transport-pinned-ca`, and the SCM reported that
// DsseSteer could not be started — the exact crash the branch exists to prevent, on the exact configuration
// the product ships.
//
// Written as a list of what must KEEP WORKING without an identity rather than a list of what enforces: those
// modes diagnose or repair the box, and a `print-config` that idled, or a `recover` that refused to give a
// machine its network back because nobody had approved it, would be worse than useless. A new enforcing mode
// added later is covered by default, which is the safe direction for this list to be wrong in.
func modeTakesTheNetworkPath(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "print-config", "recover", "watchdog", "bypass-observe", "enroll":
		return false
	}
	return true
}
