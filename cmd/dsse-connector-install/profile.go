package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// profile.go — the connector's install profile: the file a customer carries to the machine.
//
// ★★★ A CONNECTOR SHOULD GET WHAT AN AGENT GETS (the operator's instruction, 2026-08-26): a token AND a
// profile, created and DOWNLOADED, rather than a wall of base64 to select out of a browser and paste into a
// terminal on another machine. The token half is unchanged — one-time, short-lived, spent on the first
// connection. The profile is the durable half in a form somebody can carry: every door in the operator's
// order, the authority to pin, and where this connector is to live.
//
// ★ WHY IT MATTERS BEYOND CONVENIENCE. A token pasted by hand is a token that can arrive truncated, and a
// truncated token fails as "this does not look like an enrolment token" only if it stops mid-base64 — a clean
// break at a JSON boundary is not reachable, but a partial DOOR LIST is: the operator sees a connector that
// enrolled, works, and silently has one region instead of two. A file is copied whole or not at all.
//
// ★★ AND THE FILE IS A CREDENTIAL UNTIL THE FIRST RUN, which is why it says so in its own note field and why
// this refuses to read one that is readable by everybody on a shared machine is NOT enforced here: the file
// arrives from a browser's download directory, where its mode is the browser's business. What is enforced is
// that nothing this installer WRITES from it is loose (see run()).

// installProfileKind is the schema discriminator, checked so that a validly-shaped but different document —
// an agent install profile, say, which also carries tenant_id and endpoints — cannot be applied as this one.
const installProfileKind = "dsse_connector_install_profile.v1"

// connectorInstallProfile is the downloadable half of "Add connector". The field names are the token's
// wherever the two carry the same fact, so an operator reading both sees one vocabulary.
type connectorInstallProfile struct {
	Kind          string   `json:"kind"`
	IssuedAt      string   `json:"issued_at,omitempty"`
	TenantID      string   `json:"tenant_id"`
	Site          string   `json:"site"`
	EdgeEndpoints []string `json:"edge_endpoints"`
	EdgeCAPEM     string   `json:"edge_ca,omitempty"`
	StateDir      string   `json:"state_dir,omitempty"`
	// Token is the one-time enrolment token. It is IN the profile rather than beside it because the two are
	// issued together and issuing a second token invalidates the first: a customer holding a profile and a
	// separately-issued token holds one working credential and one that silently is not.
	Token string `json:"token"`
	Note  string `json:"note,omitempty"`
}

// readInstallProfile reads the downloaded file and returns the token to install with and the state directory
// it names (empty when the profile does not choose one).
func readInstallProfile(path string) (token, stateDir string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", path, err)
	}
	var p connectorInstallProfile
	if uerr := json.Unmarshal(raw, &p); uerr != nil {
		return "", "", fmt.Errorf("%s is not a connector install profile (%v). Download it again from the "+
			"Console's Add connector", path, uerr)
	}
	// ★ THE KIND IS CHECKED BECAUSE THE WRONG FILE IS THE LIKELY MISTAKE. A deployment hands out several
	// JSON documents and they land in the same downloads folder. Applying an agent's install profile here
	// would enrol nothing and report no reason.
	if strings.TrimSpace(p.Kind) != installProfileKind {
		return "", "", fmt.Errorf("%s is a %q, not a connector install profile. Nothing was written",
			path, strings.TrimSpace(p.Kind))
	}
	if strings.TrimSpace(p.Token) == "" {
		return "", "", fmt.Errorf("%s carries no enrolment token, so this connector could never introduce "+
			"itself. Issue a new one from the Console's Add connector. Nothing was written", path)
	}
	return strings.TrimSpace(p.Token), strings.TrimSpace(p.StateDir), nil
}
