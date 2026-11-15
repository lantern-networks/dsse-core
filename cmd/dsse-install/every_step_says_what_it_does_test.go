package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A step the operator watches for minutes must say what it is doing. "run the next step of the order" was what
// one step of a three-machine installation read as on its first walk.
func TestEveryStepOfEverySamplePlanSaysWhatItDoes(t *testing.T) {
	for name, plan := range samplePlans(t) {
		steps, err := upSteps(plan, "/d", "/d.plan.json", "Example Operator", "admin@example.test")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(steps) == 0 {
			t.Fatalf("%s: no steps — this test would pass on nothing", name)
		}
		for i, s := range steps {
			if stepTitle(s) == stepTitle(upStep{}) {
				t.Errorf("%s step %d on %s has no name of its own: %.120s", name, i+1, s.Machine, s.Shell)
			}
		}
	}
}

// The step that starts publishing revocation lists was the unnamed one, and it could not complete on a machine
// the installer had prepared itself.
func TestTheRevocationStepIsNamedAndBringsItsOwnPublisher(t *testing.T) {
	for name, plan := range samplePlans(t) {
		plan.DeploymentCRLOrigins = []string{"http://crl.example.test"}
		steps, err := upSteps(plan, "/d", "/d.plan.json", "Example Operator", "admin@example.test")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		found := false
		for _, s := range steps {
			if !strings.Contains(s.Shell, "install-deployment-crl-services.sh") {
				continue
			}
			found = true
			if got := stepTitle(s); got != "publish this deployment's revocation lists" {
				t.Errorf("%s: the step is called %q", name, got)
			}
			for _, want := range []string{"docker create", "DSSE_IMAGE", "sudo install -o root -g root -m 0755", "sudo /d/install-deployment-crl-services.sh"} {
				if !strings.Contains(s.Shell, want) {
					t.Errorf("%s: the step does not carry %q: %s", name, want, s.Shell)
				}
			}
			// The release's own publisher is installed every time. One left by an earlier deployment does
			// not know the options this release's service definition passes.
			if strings.Contains(s.Shell, "test -x") {
				t.Errorf("%s: the step keeps whatever publisher the machine already has: %s", name, s.Shell)
			}
		}
		if !found {
			t.Errorf("%s: a plan with revocation origins has no step that publishes them", name)
		}
	}
}

func TestTheFoundingMachineCanAcceptRevocationRequestsItself(t *testing.T) {
	const fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	write := func(t *testing.T, listen string) (string, error) {
		t.Helper()
		dir := t.TempDir()
		old := mintingPlan
		mintingPlan = &Plan{DeploymentCRLHTTPListen: listen}
		defer func() { mintingPlan = old }()
		return dir, writeDeploymentCRLServicesAt(dir, fingerprint, []string{"http://crl.example.test"}, filepath.Join(dir, "stage"), "/usr/local/bin/dsse-deployment-crl", filepath.Join(dir, "units"), os.Getuid())
	}
	dir, err := write(t, "0.0.0.0:80")
	if err != nil {
		t.Fatal(err)
	}
	socket, err := os.ReadFile(filepath.Join(dir, "dsse-crl-0123456789ab-front.socket"))
	if err != nil || !strings.Contains(string(socket), "ListenStream=0.0.0.0:80") {
		t.Fatalf("front socket: %v %s", err, socket)
	}
	service, _ := os.ReadFile(filepath.Join(dir, "dsse-crl-0123456789ab-front.service"))
	if !strings.Contains(string(service), "systemd-socket-proxyd 127.0.0.1:18081") {
		t.Fatalf("front service does not hand over to the loopback publisher: %s", service)
	}
	script, _ := os.ReadFile(filepath.Join(dir, "install-deployment-crl-services.sh"))
	if !strings.Contains(string(script), "systemctl enable --now dsse-crl-0123456789ab-front.socket") {
		t.Fatal("the activation script does not start the front socket")
	}
	if strings.Contains(string(script), "-eq 700 || ") && strings.Contains(string(script), `stat -c %a "$source")" -eq 700`) {
		t.Fatal("the activation script still refuses the directory the installer itself creates (0755)")
	}
	if !strings.Contains(string(script), "the check on line") {
		t.Fatal("a failing check does not say which one it was")
	}

	// Without the setting nothing listens for the operator.
	dir, err = write(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dsse-crl-0123456789ab-front.socket")); !os.IsNotExist(err) {
		t.Fatal("a front socket was generated although the plan did not ask for one")
	}
	if _, err := write(t, "crl.example.test:80"); err == nil {
		t.Fatal("a name was accepted where an address to listen on is needed")
	}
}

// Review finding (2026-11-14): the plan has always held the revocation origins; the setting this release's
// control plane reads them from is new. An upgraded machine kept its deployment.env, the variable was not in
// it, and inspection authorities made after the upgrade named no revocation list.
func TestAnUpgradeCarriesThePlansRevocationOriginsIntoTheSettingsThisReleaseReads(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "deployment.env")
	if err := os.WriteFile(env, []byte("DSSE_NODE_NAME='node-a'\nADMIN_TOKEN='keep'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := &Plan{DeploymentCRLOrigins: []string{"http://crl-a.example.test", "http://crl-b.example.test"}}
	if err := carryPlanSettingsThisReleaseReads(dir, plan); err != nil {
		t.Fatal(err)
	}
	got, _ := readEnvFile(env)
	if got["DSSE_DEPLOYMENT_CRL_ORIGINS"] != "http://crl-a.example.test,http://crl-b.example.test" || got["ADMIN_TOKEN"] != "keep" {
		t.Fatalf("deployment.env after the upgrade: %v", got)
	}
	// The start script this release generates reads exactly that variable.
	if src, err := os.ReadFile("launch.go"); err != nil || !strings.Contains(string(src), `-tenant-interception-crl-origins="${DSSE_DEPLOYMENT_CRL_ORIGINS:-}"`) {
		t.Fatalf("the generated start script no longer reads DSSE_DEPLOYMENT_CRL_ORIGINS (%v)", err)
	}
	// Run again, nothing changes; a plan without origins writes nothing.
	before, _ := os.ReadFile(env)
	_ = carryPlanSettingsThisReleaseReads(dir, plan)
	after, _ := os.ReadFile(env)
	if string(before) != string(after) {
		t.Fatal("a second upgrade rewrote the setting")
	}
	other := t.TempDir()
	_ = os.WriteFile(filepath.Join(other, "deployment.env"), []byte("A='b'\n"), 0o600)
	_ = carryPlanSettingsThisReleaseReads(other, &Plan{})
	if b, _ := os.ReadFile(filepath.Join(other, "deployment.env")); string(b) != "A='b'\n" {
		t.Fatalf("a deployment that publishes no lists had its settings changed: %q", b)
	}
}
