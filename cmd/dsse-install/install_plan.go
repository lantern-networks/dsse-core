package main

import (
	"encoding/json"
	"path/filepath"
)

const installPlanFile = "install-plan.json"

func writeInstallPlan(dir string, plan *Plan) error {
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	return publishInstallerFile(filepath.Join(dir, installPlanFile), append(raw, '\n'), 0600)
}

func loadInstallPlan(dir, path string) (*Plan, error) {
	if path == "" {
		path = filepath.Join(dir, installPlanFile)
	}
	return LoadPlan(path)
}

func privateTokenDestination(dir string) string {
	return filepath.Join(dir, authorityDirName, "operator-api-token")
}

func privateInstallReadTokenDestination(dir string) string {
	return filepath.Join(dir, authorityDirName, "installation-state-read-token")
}

// Keep the explicit dependency on a complete plan. A snapshot is not a census
// update and cannot add, retire or silently forget authority members.
func localInstallMachine(dir string) (string, error) {
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return "", err
	}
	return env["DSSE_NODE_NAME"], nil
}
