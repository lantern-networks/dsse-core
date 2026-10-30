package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Compose normally lets the caller's environment override --env-file. Setup
// verifies the generated plan, so execute that same configuration rather than
// unrelated DSSE/PG values inherited from the operator's shell. Preserve Docker
// context/registry configuration; only variables referenced by this generated
// Compose are replaced. No credential is passed in command-line arguments.
func installerComposeCommand(ctx context.Context, dir string, args ...string) (*exec.Cmd, error) {
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		return nil, err
	}
	named := map[string]bool{}
	for _, match := range shellVarRef.FindAllStringSubmatch(string(raw), -1) {
		named[match[1]] = true
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = dir
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !named[key] {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	for key := range named {
		if value, ok := env[key]; ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	return cmd, nil
}
