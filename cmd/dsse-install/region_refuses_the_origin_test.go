package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ BOTH DIRECTIONS, BECAUSE THE FIRST VERSION OF THIS GUARD REFUSED THE LEGITIMATE CARRY.
//
// The accident: running -region region-a on the directory that already IS region-a and stands up this
// deployment's database. The rewrite removed the database, the consensus store and both control planes from
// the file that starts them — invisible while they were running, fatal on the next bring-up. It happened, and
// it also created a second compose project beside the first, which then stood up an empty parallel deployment.
//
// The intent: carrying that same directory elsewhere and running -region region-b on the copy. The copy still
// carries the state-bearing compose — that is what carrying means — so a guard that looks only at the compose
// refuses the very thing this command exists to do.
func TestRegionRefusesTheOriginButAllowsTheCarry(t *testing.T) {
	stateBearing := "services:\n  dsse-store-a:\n    image: x\n  dsse-postgres-a:\n    image: y\n  dsse-control-plane-a:\n    image: z\n"

	setup := func(t *testing.T, recordedRegion string) string {
		t.Helper()
		dir := t.TempDir()
		// alreadyMinted looks for root.crt; a region install refuses outright without it.
		for name, body := range map[string]string{
			"root.crt":                "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
			"docker-compose.yml":      stateBearing,
			"deployment.env":          "ADMIN_TOKEN='x'\nDSSE_EDGE_REGION='" + recordedRegion + "'\n",
			agentPolicySigningKeyFile: strings.Repeat("ab", 32),
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	t.Run("the origin, named as itself, is refused", func(t *testing.T) {
		dir := setup(t, "region-a")
		err := regionInstall(dir, "region-a", machineShape{holds: regionShapeEdgesOnly, edges: true})
		if err == nil {
			t.Fatal("running -region on the directory that already is that region was allowed")
		}
		if !strings.Contains(err.Error(), "stands up this deployment's STATE") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
		// And it changed nothing: the file that starts the database is still the one that does.
		body, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
		if !strings.Contains(string(body), "dsse-postgres-a:") {
			t.Fatal("the compose file was rewritten despite the refusal")
		}
	})

	t.Run("a carried copy, named as somewhere else, is prepared", func(t *testing.T) {
		dir := setup(t, "region-a")
		if err := regionInstall(dir, "region-b", machineShape{holds: regionShapeEdgesOnly, edges: true}); err != nil {
			t.Fatalf("preparing a carried copy as another region was refused: %v", err)
		}
		body, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
		if strings.Contains(string(body), "dsse-postgres-a:") {
			t.Fatal("the joining region still stands up a database of its own")
		}
	})

	t.Run("a carry that lacks the signing authority is refused", func(t *testing.T) {
		dir := setup(t, "region-a")
		if err := os.Remove(filepath.Join(dir, agentPolicySigningKeyFile)); err != nil {
			t.Fatal(err)
		}
		err := regionInstall(dir, "region-b", machineShape{holds: regionShapeEdgesOnly, edges: true})
		if err == nil || !strings.Contains(err.Error(), "MINT ITS OWN SIGNING AUTHORITY") {
			t.Fatalf("a carry missing the deployment's signing key was not refused: %v", err)
		}
	})
}
