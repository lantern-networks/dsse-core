package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ★★ ONE ACT MAY CUT AN ESTABLISHED SESSION, AND NOTHING ENFORCED THAT (2026-08-19).
//
// The invariant is written down twice — on the registry where the connection map is created, and on the route
// that uses it: "The ONE place allowed to tear down established (T) sessions: an explicit administrator block.
// Every other revocation path (CP feed, mesh, node-reported automatic) only denies NEW handshakes."
//
// It is a load-bearing promise. A revocation that merely stops the next handshake is recoverable and quiet; a
// revocation that closes live connections takes a laptop off the network mid-use, which is why it was made an
// elevated act an operator cannot perform under a standing delegation alone. If a second caller acquired the
// ability, the elevated-act list would be describing a door that is no longer the only one.
//
// Nothing checked it. Counting the callers is the check: the registry method that closes connections may be
// reached from exactly one place, and that place is the administrator block.
func TestOnlyTheAdministratorBlockTearsDownLiveSessions(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	var callers []string
	found := false
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			// The method's own definition and its wrapper live in the registry file.
			if strings.Contains(code, "CloseIdentity(") {
				found = true
				if name == "transport_conn_registry.go" {
					continue
				}
				callers = append(callers, name+":"+strconv.Itoa(i+1)+" "+strings.TrimSpace(line))
			}
		}
	}
	if !found {
		t.Fatal("CloseIdentity is gone — either the teardown moved or this gate is reading the wrong tree")
	}
	if len(callers) != 1 {
		t.Fatalf("%d callers can tear down established sessions; the invariant says exactly one, the "+
			"administrator block: %v", len(callers), callers)
	}
	if !strings.HasPrefix(callers[0], "admin_device_admission_routes.go:") {
		t.Fatalf("the one caller is %q, not the administrator block", callers[0])
	}

	// ★ THE CONTROL: the OTHER revocation paths must still exist and must NOT close connections. If they had
	// been deleted, the count above would be satisfied while the product had lost the quiet revocation that
	// makes the loud one exceptional.
	feed, err := os.ReadFile(filepath.Join("secure_transport.go"))
	if err != nil {
		t.Fatalf("read the transport: %v", err)
	}
	// Read as CODE, not as text: the first version of this control matched a comment and stayed green when
	// the call was renamed away. Mentioning a guard is not calling one, twice over in one night.
	handshakeChecks := false
	for _, line := range strings.Split(string(feed), "\n") {
		code := line
		if j := strings.Index(code, "//"); j >= 0 {
			code = code[:j]
		}
		if strings.Contains(code, "revocations.IsRevoked(") {
			handshakeChecks = true
			break
		}
	}
	if !handshakeChecks {
		t.Fatal("the handshake no longer consults revocations, so nothing denies a NEW connection either — " +
			"and then the loud teardown is the only revocation there is")
	}
}
