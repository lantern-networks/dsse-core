//go:build windows

package main

// service_args_windows.go — putting the operator's key where the running agent reads it.
//
// The agent verifies its install profile against a pin it is GIVEN, never one it reads from beside the
// envelope: a pin stored next to the document it verifies can be replaced by whoever replaced the document,
// and the check becomes circular (review S1). Baking it into the binary satisfies that and costs one signed
// installer per deployment. Service arguments are the third option: set once by an elevated installer, as
// protected as the binary they name, and not the store the envelope lives in.

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// putPinsInServiceArgs rewrites the named service's command line so both pins carry key, and returns a line
// naming what is now in force.
//
// ★ IT READS THE ARGUMENTS BACK RATHER THAN COMPOSING THEM. The service was registered by the MSI with the
// site facts that package was built with — a bypass destination, an update publisher — and composing a fresh
// command line here would silently drop them. The bypass destination is this box's management path; losing it
// puts the route to the machine inside the thing that machine is steering.
func putPinsInServiceArgs(service, key string) (string, error) {
	if !isProfileSigningKey(key) {
		return "", fmt.Errorf("refusing to put a value that is not a key into %s's arguments", service)
	}
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("open the service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(service)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", service, err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return "", fmt.Errorf("read %s configuration: %w", service, err)
	}

	exe, args, derr := decomposeImagePath(cfg.BinaryPathName)
	if derr != nil {
		return "", fmt.Errorf("%s: %w", service, derr)
	}
	updated := pinArgs(args, key)
	rebuilt := composeImagePath(exe, updated)
	if rebuilt == strings.TrimSpace(cfg.BinaryPathName) {
		return service + " already verifies profiles against this key", nil
	}
	cfg.BinaryPathName = rebuilt
	if err := s.UpdateConfig(cfg); err != nil {
		return "", fmt.Errorf("update %s configuration: %w", service, err)
	}
	return service + " now verifies profiles against the operator's key (sha256 of the key is not it — the key " +
		"itself is " + key[:16] + "…)", nil
}

// decomposeImagePath separates an ImagePath into the executable and its arguments, using Windows' OWN parsing
// rules rather than an approximation of them.
//
// ★★★ THE APPROXIMATION WAS WRONG IN BOTH DIRECTIONS. strings.Fields split
// --update-publisher "subject:Aoba Networks" into two arguments. A hand-written quote toggler fixed that case
// and still got the rest wrong: Windows gives backslashes a meaning before a quote (\" is a literal quote,
// \\" is a backslash then a delimiter), an empty argument must survive as "" rather than vanishing, and a
// trailing backslash inside a quoted path has to be doubled when the line is rebuilt. Each of those produces
// a service command line that parses into something other than what was read — silently, and only visible
// when the service refuses to start.
//
// So the round trip is DecomposeCommandLine and ComposeCommandLine. They are the rules CommandLineToArgvW and
// CreateProcess actually use, which is the only definition that matters here.
//
// ★ AN UNPARSEABLE ImagePath IS AN ERROR, NOT AN EMPTY SERVICE. Returning "no arguments" for a malformed line
// is what let the pre-upgrade capture decide there was nothing to save and allow RemoveExistingProducts to
// proceed.
func decomposeImagePath(imagePath string) (exe string, args []string, err error) {
	p := strings.TrimSpace(imagePath)
	if p == "" {
		return "", nil, fmt.Errorf("the ImagePath is empty")
	}
	parts, err := windows.DecomposeCommandLine(p)
	if err != nil {
		return "", nil, fmt.Errorf("parse the ImagePath %q: %w", imagePath, err)
	}
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "", nil, fmt.Errorf("the ImagePath %q names no executable", imagePath)
	}
	return parts[0], parts[1:], nil
}

// composeImagePath rebuilds a service command line from an executable and its arguments, quoting and escaping
// each one the way CreateProcess expects to read it back.
func composeImagePath(exe string, args []string) string {
	return windows.ComposeCommandLine(append([]string{exe}, args...))
}

// splitServiceCommand is the diagnostic form, for callers that report rather than decide. It returns an empty
// executable where decomposeImagePath returns an error, and every caller that acts on the result — the
// capture, the restore, the adoption — uses decomposeImagePath instead so a parse failure cannot read as an
// absence.
func splitServiceCommand(imagePath string) (exe string, args []string) {
	exe, args, err := decomposeImagePath(imagePath)
	if err != nil {
		return "", nil
	}
	return exe, args
}
