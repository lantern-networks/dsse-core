package main

// signing_key_artefact.go — the fourth thing a customer receives.
//
// ★★★ THE DECISION (2026-08-29, the operator's, relayed by the Mac session; this is the Windows half).
//
// A profile cannot carry the key that proves it — a document that certifies itself certifies anything, and the
// macOS installer was doing exactly that until today: it decoded payload_b64 WITHOUT verifying and took
// agent_policy_signing_public_key out of the thing it was about to verify.
//
// Two ways out were considered and both rejected:
//
//   - TRUST ON FIRST USE. The device adopts whatever key the first profile names, and refuses any later one
//     that differs. It fails the operator's standing rule — no authority is approved without an explicit act —
//     and the strictness is illusory: a device handed the wrong key on day one defends the wrong authority
//     perfectly for ever.
//   - BAKED INTO THE PACKAGE at build time. Correct, and it costs the thing that makes the installer worth
//     having: one signed installer per deployment, re-signed and re-notarised per customer, so it can no
//     longer be the single download the Console offers.
//
// So the key travels as an artefact, placed by the operator, exactly like the one-time token — and for the same
// reason: placing it IS the explicit act. The customer receives four things: the installer, the profile, the
// token, and this.
//
//	msiexec /i DsseAgent.msi CONFIG=<profile> TOKEN=<token file> PIN=<key file>
//
// It lands at %ProgramData%\DSSE\profile_signing_key.txt, the same name macOS uses, so one runbook line covers
// both platforms.
//
// ★ AND THE RUNNING AGENT DOES NOT READ THAT FILE. It reads the pin from its own service arguments, which
// profileapply writes here. The file is the operator's delivery; the service configuration is what is in force.
// The distinction is review S1's: the profile envelope lives in the config store, so a pin read from beside it
// could be replaced by whoever replaced the envelope, and the verification would be circular. Service
// arguments are not that store — they are set once by an elevated installer and are as protected as the binary
// they name.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// signingKeyFileName is the name on both platforms. Changing it here without changing it there gives one
// product two runbooks.
const signingKeyFileName = "profile_signing_key.txt"

// readSigningKeyFile reads the operator-placed key and checks it is one.
//
// ★ IT VALIDATES THE SHAPE, because the failure it prevents is silent. A key with a stray character verifies
// nothing, every profile is refused, and the device falls to SAFE fail-closed defaults — which is the same
// state as a device that was never given a profile at all. Saying "this file does not hold a key" at install
// costs one line and saves that.
func readSigningKeyFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the profile signing key %q: %w", path, err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("the profile signing key file %q is empty — without it nothing can verify the "+
			"profile, and this device would install and then refuse every configuration it is given", path)
	}
	if !isProfileSigningKey(key) {
		show := key
		if len(show) > 24 {
			show = show[:24] + "…"
		}
		return "", fmt.Errorf("the profile signing key file %q does not hold a key: expected 64 lower-case hex "+
			"characters (an Ed25519 public key), got %d character(s) starting %q", path, len(key), show)
	}
	return strings.ToLower(key), nil
}

var hex64 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func isProfileSigningKey(s string) bool { return hex64.MatchString(strings.TrimSpace(s)) }

// installSigningKey writes the key where an operator will look for it later, and reports whether it changed.
//
// It is written even though the agent reads the service arguments instead: an operator asking "which authority
// is this box verifying its configuration against" needs somewhere to look that is not a service's command
// line, and a support conversation that begins with "run sc qc" begins badly.
func installSigningKey(dataDir, key string) (string, error) {
	if strings.TrimSpace(key) == "" {
		return "", nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", dataDir, err)
	}
	path := filepath.Join(dataDir, signingKeyFileName)
	if prev, err := os.ReadFile(path); err == nil && strings.EqualFold(strings.TrimSpace(string(prev)), key) {
		return "the profile signing key is unchanged -> " + path, nil
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return "the operator's profile signing key -> " + path, nil
}

// pinArgs rewrites a service's argument list so both pins carry the given key, replacing any that were there
// and adding them when they were not.
//
// ★ REPLACING RATHER THAN APPENDING. A second --config-pin on the same command line is decided by flag
// package ordering, which is not a thing an operator can read off the service's properties. Whichever value
// loses would be invisible, and the one that loses might be the one that was correct.
func pinArgs(args []string, key string) []string {
	out := make([]string, 0, len(args)+4)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if isPinFlag(a) {
			// Skip the flag and, when it is the separate-argument form, its value.
			if !strings.Contains(a, "=") && i+1 < len(args) {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return append(out, "--config-pin", key, "--agent-policy-pin", key)
}

func isPinFlag(a string) bool {
	for _, f := range []string{"--config-pin", "-config-pin", "--agent-policy-pin", "-agent-policy-pin"} {
		if a == f || strings.HasPrefix(a, f+"=") {
			return true
		}
	}
	return false
}
