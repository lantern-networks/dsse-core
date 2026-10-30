package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type installStartResult struct {
	Preflight installPreflightResult `json:"preflight"`
	Started   bool                   `json:"compose_started"`
}

func runStartNode(ctx context.Context, p *Plan, dir, machine, cert, key, ca string) (installStartResult, error) {
	return startLocalNode(ctx, p, dir, machine, cert, key, ca, runInstallPreflight, func(ctx context.Context, dir, project string) error {
		cmd, err := installerComposeCommand(ctx, dir, "compose", "-p", project, "--env-file", "deployment.env", "up", "-d")
		if err != nil {
			return err
		}
		return cmd.Run()
	})
}

func startLocalNode(ctx context.Context, p *Plan, dir, machine, cert, key, ca string, preflight func(context.Context, *Plan, string, string) (installPreflightResult, error), start func(context.Context, string, string) error) (installStartResult, error) {
	var result installStartResult
	if machine == "" {
		var err error
		machine, err = localInstallMachine(dir)
		if err != nil {
			return result, err
		}
	}
	r, node, ok := p.find(machine)
	if !ok {
		return result, fmt.Errorf("local machine is absent from the complete plan")
	}
	if cert != "" {
		if !node.Holds.has("edges") {
			return result, fmt.Errorf("CP-only nodes must not receive an Edge browser private key")
		}
		if err := installPortalCertificate(dir, cert, key, ca); err != nil {
			return result, err
		}
	}
	if machine != p.foundingRegion().controlPlane().Name {
		if _, err := os.Stat(runtimePath(dir, adminBootstrappedMarker)); err != nil {
			return result, fmt.Errorf("joining node has no closed-bootstrap marker; bootstrap on the issuer and create a fresh carry before starting")
		}
	}
	checked, err := preflight(ctx, p, dir, machine)
	result.Preflight = checked
	if err != nil {
		return result, err
	}
	if !checked.Ready {
		return result, fmt.Errorf("preflight did not confirm readiness; no services started")
	}
	project := "dsse-" + r.ID
	if machine == p.foundingRegion().controlPlane().Name {
		project = "dsse"
	}
	if err := start(ctx, dir, project); err != nil {
		return result, fmt.Errorf("Compose did not confirm startup; inspect 'docker compose -p %s --env-file %s ps' and rerun this node step; partially started services are not automatically deleted", project, filepath.Join(dir, "deployment.env"))
	}
	result.Started = true
	return result, nil
}
