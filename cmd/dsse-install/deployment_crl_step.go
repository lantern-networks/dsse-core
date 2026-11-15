package main

import "fmt"

// deploymentCRLStepCommand is the order's step that starts publishing this deployment's revocation lists.
//
// The publisher is a program of the release, and the release's service image carries it. The step installs
// that one every time: the service definitions this release generates pass the options this release's
// publisher understands, and a publisher an earlier deployment left on the machine does not know them — the
// service was started with an option the old program refuses, and never ran (review, 2026-11-14).
func deploymentCRLStepCommand(dir string) string {
	bin := "/usr/local/bin/dsse-deployment-crl"
	// deployment.env writes the value in single quotes.
	image := fmt.Sprintf("\"$(sed -n 's/^DSSE_IMAGE=//p' %s/deployment.env | tr -d \"'\")\"", dir)
	take := fmt.Sprintf("{ c=$(docker create %s) && docker cp \"$c\":%s %s/dsse-deployment-crl.from-image && docker rm \"$c\" >/dev/null && "+
		"sudo install -o root -g root -m 0755 %s/dsse-deployment-crl.from-image %s && rm -f %s/dsse-deployment-crl.from-image; }",
		image, bin, dir, dir, bin, dir)
	return fmt.Sprintf("%s && sudo %s/install-deployment-crl-services.sh", take, dir)
}

func deploymentCRLStepNeeds(p *Plan) string {
	if p.DeploymentCRLHTTPListen != "" {
		return fmt.Sprintf("sudo on this machine; %s free on it and reachable from devices as every origin in deployment_crl_origins", p.DeploymentCRLHTTPListen)
	}
	return "sudo on this machine; every public HTTP origin in deployment_crl_origins routed to the keyless publisher's loopback 127.0.0.1:18081 before -start-node (or set deployment_crl_http_listen and let this machine accept them)"
}
