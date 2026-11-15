package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A layout whose machines are started with -start-node: -up fetches each machine's images before that
// machine's check, and hands the first machine the browser certificate it was given.
func TestUpGivesANodeStartItsImagesAndTheFirstMachineItsCertificate(t *testing.T) {
	plan := samplePlans(t)["one-region-three-independent-entries.json"]
	if plan == nil {
		t.Fatal("missing sample plan")
	}
	dir := "/opt/dsse/kiri"
	steps, err := upSteps(plan, dir, dir+".plan.json", "Example", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	nothingThere := func(string) bool { return false }

	if _, err := withWhatANodeStartNeeds(steps, plan, dir, upInput{}, nothingThere); err == nil || !strings.Contains(err.Error(), "-install-portal-certificate") {
		t.Fatalf("without a certificate -up must say what it needs before it starts anything, got %v", err)
	}
	if _, err := withWhatANodeStartNeeds(steps, plan, dir, upInput{PortalCertificate: "/c/chain.pem"}, nothingThere); err == nil {
		t.Fatal("a certificate without its key was accepted")
	}
	// A directory that already holds the certificate needs none handed in.
	if _, err := withWhatANodeStartNeeds(steps, plan, dir, upInput{}, func(p string) bool { return strings.HasSuffix(p, "clientless/tls.crt") }); err != nil {
		t.Fatalf("a deployment that holds its certificate was refused: %v", err)
	}

	got, err := withWhatANodeStartNeeds(steps, plan, dir, upInput{PortalCertificate: "/c/chain.pem", PortalKey: "/c/key.pem", PortalCA: "/c/ca.pem"}, nothingThere)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(steps) {
		t.Fatalf("steps changed in number: %d -> %d", len(steps), len(got))
	}
	starts, local := 0, 0
	for i, st := range got {
		if !strings.Contains(st.Shell, "-start-node") {
			if st.Shell != steps[i].Shell {
				t.Fatalf("a step that starts no node was changed: %s", st.Shell)
			}
			continue
		}
		starts++
		fetch := strings.Index(st.Shell, "docker compose --env-file deployment.env pull")
		if fetch < 0 || fetch > strings.Index(st.Shell, "dsse-install -start-node") {
			t.Fatalf("the images are not fetched before the check on %s: %s", st.Machine, st.Shell)
		}
		if unpack := strings.Index(st.Shell, "tar xzpf"); unpack > fetch {
			t.Fatalf("the images are fetched before the package is unpacked on %s: %s", st.Machine, st.Shell)
		}
		hasCert := strings.Contains(st.Shell, "-install-portal-certificate '/c/chain.pem' -portal-key '/c/key.pem' -portal-ca '/c/ca.pem'")
		if st.Kind == upRemote && (hasCert || strings.Contains(st.Shell, "portal-key")) {
			t.Fatalf("another machine's command names the first machine's key file: %s", st.Shell)
		}
		if st.Kind != upRemote {
			local++
			if !hasCert {
				t.Fatalf("the first machine was not handed the certificate: %s", st.Shell)
			}
		}
	}
	if starts != 3 || local != 1 {
		t.Fatalf("node starts = %d (first machine %d), want 3 and 1", starts, local)
	}
}

// A first machine that holds no Edge is never given the browser key: the paths name files on the Edge machines,
// each Edge machine's start installs from them, and only the CA reaches the first machine, for the last check.
// A plan without a profile takes none.
func TestUpLeavesTheBrowserKeyOnTheEdgeMachinesWhenTheFirstMachineHoldsNone(t *testing.T) {
	plans := samplePlans(t)
	dir := "/opt/dsse/x"
	in := upInput{PortalCertificate: "/c/chain.pem", PortalKey: "/c/key.pem"}
	for _, name := range []string{"three-regions-multi-edge.json", "one-region-multi-edge.json"} {
		plan := plans[name]
		if plan == nil {
			t.Fatalf("missing sample plan %s", name)
		}
		steps, err := upSteps(plan, dir, dir+".plan.json", "Example", "admin@example.test")
		if err != nil {
			t.Fatal(err)
		}
		caHere := func(p string) bool { return p == "/c/ca.pem" }
		if _, err := withWhatANodeStartNeeds(steps, plan, dir, upInput{}, caHere); err == nil || !strings.Contains(err.Error(), "on that machine") {
			t.Fatalf("%s: without a certificate -up must say where it belongs before it starts anything, got %v", name, err)
		}
		if _, err := withWhatANodeStartNeeds(steps, plan, dir, upInput{PortalCertificate: "chain.pem", PortalKey: "/c/key.pem"}, caHere); err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("%s: a path relative to the first machine was accepted for another machine: %v", name, err)
		}
		withCA := in
		withCA.PortalCA = "/c/ca.pem"
		if _, err := withWhatANodeStartNeeds(steps, plan, dir, withCA, func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "not on this machine") {
			t.Fatalf("%s: a CA bundle the last check cannot read was accepted: %v", name, err)
		}
		got, err := withWhatANodeStartNeeds(steps, plan, dir, withCA, caHere)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		edges, verified := 0, false
		for i, st := range got {
			named := strings.Contains(st.Shell, "portal-key")
			switch {
			case strings.HasPrefix(st.Shell, "dsse-install -verify "):
				verified = strings.HasSuffix(st.Shell, " -portal-ca '/c/ca.pem'")
			case !strings.Contains(st.Shell, "-start-node"):
				if st.Shell != steps[i].Shell {
					t.Fatalf("%s: a step that starts no node was changed: %s", name, st.Shell)
				}
			case st.Kind != upRemote:
				if named || len(st.HeldThere) != 0 {
					t.Fatalf("%s: the first machine, which holds no Edge, was named the browser key: %s", name, st.Shell)
				}
			case strings.HasPrefix(st.Machine, "cp-"):
				if named || len(st.HeldThere) != 0 {
					t.Fatalf("%s: %s holds no Edge and was named the browser key: %s", name, st.Machine, st.Shell)
				}
			default:
				edges++
				if !strings.Contains(st.Shell, "-install-portal-certificate '/c/chain.pem' -portal-key '/c/key.pem' -portal-ca '/c/ca.pem'") || len(st.HeldThere) != 3 {
					t.Fatalf("%s: %s is not started from its own certificate: %s", name, st.Machine, st.Shell)
				}
			}
			if strings.Contains(st.Shell, "-start-node") && !strings.Contains(st.Shell, "pull --policy missing --quiet") {
				t.Fatalf("%s: a node start without its images: %s", name, st.Shell)
			}
		}
		want := map[string]int{"three-regions-multi-edge.json": 6, "one-region-multi-edge.json": 2}[name]
		if edges != want || !verified {
			t.Fatalf("%s: Edge machines started from their certificate = %d (want %d), last check given the CA = %v", name, edges, want, verified)
		}
	}
}

// The Edge machines are asked for their files before the first step, and only those still to be started.
func TestUpAsksTheEdgeMachinesForTheirCertificateBeforeItStartsAnything(t *testing.T) {
	plan := samplePlans(t)["one-region-multi-edge.json"]
	dir := "/opt/dsse/x"
	steps, err := upSteps(plan, dir, dir+".plan.json", "Example", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	steps, err = withWhatANodeStartNeeds(steps, plan, dir, upInput{PortalCertificate: "/c/chain.pem", PortalKey: "/c/key.pem"}, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	missing := ""
	r := upRunner{run: func(_ context.Context, _, shell string, _ io.Writer) error {
		asked = append(asked, shell)
		if missing != "" && strings.Contains(shell, missing) {
			return errors.New("exit status 1")
		}
		return nil
	}}
	prog := &upProgress{Done: map[string]string{}}
	if err := whatOtherMachinesDoNotHold(context.Background(), steps, prog, nil, r, "", io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 4 {
		t.Fatalf("two Edge machines, two files each: asked %d times: %v", len(asked), asked)
	}
	for _, a := range asked {
		if !strings.HasPrefix(a, "ssh ") || !strings.Contains(a, "test -r") {
			t.Fatalf("not a question about a file on another machine: %s", a)
		}
	}
	missing = "edge-a-2"
	err = whatOtherMachinesDoNotHold(context.Background(), steps, prog, nil, r, "", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "edge-a-2") || !strings.Contains(err.Error(), "Nothing has been started") {
		t.Fatalf("a machine without its certificate was not named: %v", err)
	}
	// A machine the person has already done, or whose start is recorded, is not asked again.
	asked = nil
	if err := whatOtherMachinesDoNotHold(context.Background(), steps, prog, map[string]bool{"edge-a-2": true}, r, "", io.Discard); err != nil {
		t.Fatalf("a machine already done was asked for its files: %v", err)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %d times, want 2: %v", len(asked), asked)
	}
}

func TestUpRefusesACertificateForAPlanWithoutAProfile(t *testing.T) {
	plans := samplePlans(t)
	dir := "/opt/dsse/x"
	in := upInput{PortalCertificate: "/c/chain.pem", PortalKey: "/c/key.pem"}
	for name, plan := range plans {
		if declaredNodeMapProfile(plan.Profile) {
			continue
		}
		steps, err := upSteps(plan, dir, dir+".plan.json", "Example", "admin@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := withWhatANodeStartNeeds(steps, plan, dir, in, func(string) bool { return false }); err == nil {
			t.Fatalf("%s: a plan without a profile accepted a browser certificate", name)
		}
		same, err := withWhatANodeStartNeeds(steps, plan, dir, upInput{}, func(string) bool { return false })
		if err != nil || len(same) != len(steps) {
			t.Fatalf("%s: %v", name, err)
		}
		for i := range same {
			if same[i].Shell != steps[i].Shell {
				t.Fatalf("%s: a step was changed: %s", name, same[i].Shell)
			}
		}
	}
}

// With -ssh the package is removed from the other machine when that machine has started from it. A start that
// failed leaves the copy step recorded and the machine not started; the next run copies the package again.
func TestUpOverSSHCopiesAPackageAgainForAMachineThatHasNotStarted(t *testing.T) {
	plan := samplePlans(t)["one-region-multi-edge.json"]
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o700); err != nil {
		t.Fatal(err)
	}
	steps, err := upSteps(plan, dir, dir+".plan.json", "Example", "admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	progress := filepath.Join(t.TempDir(), "p.json")
	rec := &recordedUp{failAt: "-start-node -dir /opt/dsse/region-a -machine edge-a-1"}
	var log, out bytes.Buffer
	if _, err := executeUp(context.Background(), steps, upInput{SSH: true}, dir, t.TempDir(), "", loadUpProgress(progress), rec.runner(false), &log, &out); err == nil {
		t.Fatal("the start that was made to fail did not stop the run")
	}
	copies := func(ran []string) (n int) {
		for _, c := range ran {
			if strings.HasPrefix(c, "scp edge-a-1.tar.gz ") {
				n++
			}
		}
		return n
	}
	if copies(rec.ran) != 1 {
		t.Fatalf("the package was copied %d times before the failed start, want 1", copies(rec.ran))
	}
	again := &recordedUp{}
	if stopped, err := executeUp(context.Background(), steps, upInput{SSH: true}, dir, t.TempDir(), "", loadUpProgress(progress), again.runner(false), &log, &out); err != nil || stopped != -1 {
		t.Fatalf("the second run stopped at %d: %v", stopped, err)
	}
	if copies(again.ran) != 1 {
		t.Fatalf("the machine that had not started was not sent its package again: %v", again.ran)
	}
	removed := false
	for _, c := range again.ran {
		removed = removed || (strings.HasPrefix(c, "ssh ") && strings.Contains(c, "-start-node") && strings.Contains(c, "-machine edge-a-1") && strings.Contains(c, "rm -f"))
	}
	if !removed {
		t.Fatal("the package is not removed from the machine that started from it")
	}
	// A third run finds every machine started and copies nothing.
	third := &recordedUp{}
	if _, err := executeUp(context.Background(), steps, upInput{SSH: true}, dir, t.TempDir(), "", loadUpProgress(progress), third.runner(false), &log, &out); err != nil {
		t.Fatal(err)
	}
	if len(third.ran) != 0 {
		t.Fatalf("a finished install ran commands again: %v", third.ran)
	}
}
