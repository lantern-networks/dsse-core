package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// Acceptance C (2026-11-07): only the declared-node profiles captured the bootstrap credentials privately and
// read the operator token from a file. The single-machine and three-Region orders piped the password, TOTP
// secret and token to the terminal and to a 0644 file in the current directory, and put the token in -verify's
// argv. Every published plan must now do the private thing.
func TestEveryProfileKeepsTheOperatorCredentialPrivate(t *testing.T) {
	for _, name := range []string{"single-region.json", "three-regions.json", "one-region-three-independent-entries.json", "three-regions-multi-edge.json", "one-region-multi-edge.json"} {
		t.Run(name, func(t *testing.T) {
			p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", name))
			if err != nil {
				t.Fatal(err)
			}
			steps := p.InstallOrder("/opt/dsse/x", "/home/ubuntu/plan.json")
			var bootstrap, verify string
			for _, s := range steps {
				if strings.Contains(s.Do, "-bootstrap-admin") {
					bootstrap = s.Do
				}
				if strings.Contains(s.Do, "-verify") {
					verify = s.Do
				}
			}
			if bootstrap == "" || verify == "" {
				t.Fatalf("the order has no bootstrap or verify step")
			}
			for _, want := range []string{"umask 077", "set -C", "-admin-token-file /opt/dsse/x/authority/operator-api-token", "> /opt/dsse/x/admin-credentials.txt 2>&1"} {
				if !strings.Contains(bootstrap, want) {
					t.Errorf("bootstrap step lacks %q: %s", want, bootstrap)
				}
			}
			if strings.Contains(bootstrap, "tee") {
				t.Errorf("bootstrap step still pipes the credentials to the terminal: %s", bootstrap)
			}
			if strings.Contains(verify, "-admin-token <") || !strings.Contains(verify, "-admin-token-file /opt/dsse/x/authority/operator-api-token") {
				t.Errorf("verify does not read the operator token from its private file: %s", verify)
			}
		})
	}
}
