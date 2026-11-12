package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func samplePlans(t *testing.T) map[string]*Plan {
	t.Helper()
	files, _ := filepath.Glob("../../docs/plans/*.json")
	if len(files) < 5 {
		t.Fatalf("expected the published sample plans, found %d", len(files))
	}
	out := map[string]*Plan{}
	for _, f := range files {
		p, err := LoadPlan(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[filepath.Base(f)] = p
	}
	return out
}

type recordedUp struct {
	ran       []string
	confirmed []string
	failAt    string // a substring; the first command containing it fails once
	failed    bool
}

func (r *recordedUp) runner(confirm bool) upRunner {
	return upRunner{
		run: func(_ context.Context, _, shell string, _ io.Writer) error {
			if r.failAt != "" && !r.failed && strings.Contains(shell, r.failAt) {
				r.failed = true
				return errors.New("refused")
			}
			r.ran = append(r.ran, shell)
			return nil
		},
		waitCP:  func(context.Context, string, string) error { return nil },
		confirm: func(m string) bool { r.confirmed = append(r.confirmed, m); return confirm },
		sleep:   func(context.Context, time.Duration) {},
		exists:  func(string) bool { return false },
	}
}

// -up must be able to run the order of EVERY published topology, not only the smallest: a shorter procedure for
// one machine that leaves the others as long as they were is not a shorter procedure.
func TestUpUnderstandsTheOrderOfEveryPublishedTopology(t *testing.T) {
	for name, plan := range samplePlans(t) {
		steps, err := upSteps(plan, "/d", "/d.plan.json", "Example Operator", "admin@example.test")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		order := plan.InstallOrder("/d", "/d.plan.json")
		if len(steps) != len(order) {
			t.Errorf("%s: the order has %d steps and -up has %d", name, len(order), len(steps))
		}
		machines, remote := 0, map[string]bool{}
		for _, r := range plan.Regions {
			machines += len(r.Machines)
		}
		for _, s := range steps {
			if s.Kind == upRemote {
				remote[s.Machine] = true
			}
		}
		if len(remote) != machines-1 {
			t.Errorf("%s: %d machines, but %d of them are started by a remote step (want every machine but the first)", name, machines, len(remote))
		}
	}
}

// With -ssh, what runs is the printed order itself, command for command; the only differences are the two
// values the order leaves to the reader, the credentials capture, and the ssh in front of another machine's line.
func TestUpOverSSHRunsThePrintedOrderCommandForCommand(t *testing.T) {
	for name, plan := range samplePlans(t) {
		dir := filepath.Join(t.TempDir(), "d")
		steps, err := upSteps(plan, dir, dir+".plan.json", "Example Operator", "admin@example.test")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rec := &recordedUp{}
		var log, out bytes.Buffer
		if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o700); err != nil {
			t.Fatal(err)
		}
		stopped, err := executeUp(context.Background(), steps, upInput{SSH: true}, dir, t.TempDir(), "", loadUpProgress(filepath.Join(t.TempDir(), "p.json")), rec.runner(false), &log, &out)
		if err != nil || stopped != -1 {
			t.Fatalf("%s: stopped at %d: %v\n%s", name, stopped, err, out.String())
		}
		order := plan.InstallOrder(dir, dir+".plan.json")
		if len(rec.ran) != len(order) {
			t.Fatalf("%s: the order has %d steps and %d commands ran", name, len(order), len(rec.ran))
		}
		minting := plan.foundingRegion().controlPlane().Name
		for i, s := range order {
			want := s.Do
			want = strings.Replace(want, "-organization <name>", "-organization 'Example Operator'", 1)
			want = strings.Replace(want, "-admin-email <address>", "-admin-email 'admin@example.test'", 1)
			got := rec.ran[i]
			switch {
			case s.Machine != minting:
				if !strings.HasPrefix(got, "ssh '") || !strings.HasSuffix(got, " "+shellQuote(want)) {
					t.Errorf("%s step %d: another machine's command must run there over ssh, unchanged:\n got %s\nwant ssh <host> %s", name, i+1, got, shellQuote(want))
				}
			case strings.Contains(want, "-bootstrap-admin"):
				if !strings.Contains(want, got) || strings.Contains(got, ">") {
					t.Errorf("%s step %d: the first-administrator command changed:\n got %s\nfrom %s", name, i+1, got, want)
				}
			case got != want:
				t.Errorf("%s step %d:\n got %s\nwant %s", name, i+1, got, want)
			}
		}
		if len(rec.confirmed) != 0 {
			t.Errorf("%s: -ssh asked a person to do something: %v", name, rec.confirmed)
		}
	}
}

// Without -ssh, nothing is copied or run on another machine by this command: each other machine is handed to the
// person once, with its package and its one command, and the run waits there.
func TestUpWithoutSSHHandsEachOtherMachineToThePersonOnce(t *testing.T) {
	plan := samplePlans(t)["three-regions.json"]
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	steps, err := upSteps(plan, dir, dir+".plan.json", "O", "a@example.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordedUp{}
	var log, out bytes.Buffer
	progress := filepath.Join(t.TempDir(), "p.json")
	// First run: the person is not there to answer, so it stops at the first other machine.
	stopped, err := executeUp(context.Background(), steps, upInput{}, dir, "/work", "", loadUpProgress(progress), rec.runner(false), &log, &out)
	if err == nil || steps[stopped].Kind != upRemote || steps[stopped].Machine != "node-b" {
		t.Fatalf("want it to stop waiting for node-b, got step %d err %v", stopped, err)
	}
	for _, c := range rec.ran {
		if strings.HasPrefix(c, "scp ") || strings.HasPrefix(c, "ssh ") {
			t.Fatalf("without -ssh this command reached another machine: %s", c)
		}
	}
	text := out.String()
	if !strings.Contains(text, "/work/node-b.tar.gz") || !strings.Contains(text, steps[stopped].Shell) {
		t.Fatalf("the handoff must name the package and the exact command:\n%s", text)
	}
	before := len(rec.ran)
	// Second run, told node-b is done: it does not repeat what completed, and stops at node-c.
	out.Reset()
	stopped, err = executeUp(context.Background(), steps, upInput{Confirmed: "node-b"}, dir, "/work", "", loadUpProgress(progress), rec.runner(false), &log, &out)
	if err == nil || steps[stopped].Machine != "node-c" {
		t.Fatalf("want it to stop waiting for node-c, got step %d err %v\n%s", stopped, err, out.String())
	}
	for _, c := range rec.ran[before:] {
		if strings.Contains(c, "-organization") || strings.Contains(c, "-bootstrap-admin") {
			t.Fatalf("a completed step ran again: %s", c)
		}
	}
	// Third run: node-b was the person's, and the rest is now given to SSH. Nothing is copied to node-b again;
	// node-c is copied to and started over ssh; and it finishes with the fleet-wide check.
	before = len(rec.ran)
	stopped, err = executeUp(context.Background(), steps, upInput{Confirmed: "node-b", SSH: true}, dir, "/work", "", loadUpProgress(progress), rec.runner(false), &log, &out)
	if err != nil || stopped != -1 {
		t.Fatalf("stopped at %d: %v", stopped, err)
	}
	copied, started := 0, 0
	for _, c := range rec.ran[before:] {
		if strings.Contains(c, "node-b.tar.gz") {
			t.Fatalf("a machine the person had already done was reached again: %s", c)
		}
		if strings.HasPrefix(c, "scp node-c.tar.gz ") {
			copied++
		}
		if strings.HasPrefix(c, "ssh 'node-c.") {
			started++
		}
	}
	if copied != 1 || started != 1 {
		t.Fatalf("node-c must be copied to once and started once over ssh, got %d and %d", copied, started)
	}
	if last := rec.ran[len(rec.ran)-1]; !strings.Contains(last, " -verify ") {
		t.Fatalf("the run must end by checking the whole deployment, ended with: %s", last)
	}
}

// A failure keeps what was done: the same command continues from the step that failed.
func TestUpContinuesFromTheStepThatFailed(t *testing.T) {
	plan := samplePlans(t)["single-region.json"]
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o700); err != nil {
		t.Fatal(err)
	}
	steps, err := upSteps(plan, dir, dir+".plan.json", "O", "a@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 6 {
		t.Fatalf("one machine is six steps, got %d", len(steps))
	}
	rec := &recordedUp{failAt: "-activate-auth"}
	var log, out bytes.Buffer
	progress := filepath.Join(t.TempDir(), "p.json")
	stopped, err := executeUp(context.Background(), steps, upInput{}, dir, dir, "", loadUpProgress(progress), rec.runner(false), &log, &out)
	if err == nil || stopped != 4 {
		t.Fatalf("want a failure at step 5, got %d %v", stopped+1, err)
	}
	ranBefore := len(rec.ran)
	stopped, err = executeUp(context.Background(), steps, upInput{}, dir, dir, "", loadUpProgress(progress), rec.runner(false), &log, &out)
	if err != nil || stopped != -1 {
		t.Fatalf("the second run stopped at %d: %v", stopped, err)
	}
	if again := rec.ran[ranBefore:]; len(again) != 2 || !strings.Contains(again[0], "-activate-auth") || !strings.Contains(again[1], " -verify ") {
		t.Fatalf("the second run must do only what was left, did: %q", again)
	}
	// The credentials went to their private file, not to the log or the screen.
	if strings.Contains(log.String()+out.String(), "bootstrap-admin") && strings.Contains(out.String(), "password:") {
		t.Fatal("credentials reached the screen")
	}
}

func TestAReleaseManifestSparesThePlanItsImages(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "release-manifest.json")
	d := strings.Repeat("a", 64)
	doc := map[string]any{"agent_publisher": "TEAMID1234", "container_images": map[string]any{
		"image_revision_label": "source-" + d, "postgres_major": 18,
		"images": map[string]string{"service_image": "ghcr.io/x/s@sha256:" + d, "console_image": "ghcr.io/x/c@sha256:" + d,
			"data_layer.etcd_image": "ghcr.io/x/e@sha256:" + d, "data_layer.postgres_image": "ghcr.io/x/p@sha256:" + d,
			"data_layer.postgres_tools_image": "ghcr.io/x/t@sha256:" + d}}}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	rel, err := readReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// One machine from three values.
	one, err := oneMachinePlanDocument(upInput{Deployment: "dsse.example.test", Address: "10.20.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	_ = withReleaseImages(one, rel, 0)
	plan, _, err := planFromDocument(one)
	if err != nil {
		t.Fatalf("the generated one-machine plan is not a valid plan: %v", err)
	}
	if plan.ServiceImage == "" || plan.DataLayer == nil || plan.DataLayer.PostgresMajor != 18 || plan.Publisher != "TEAMID1234" {
		t.Fatalf("the manifest's images did not reach the plan: %+v", plan)
	}
	// Every published topology takes its images the same way.
	files, _ := filepath.Glob("../../docs/plans/*.json")
	for _, f := range files {
		var m map[string]any
		b, _ := os.ReadFile(f)
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		_ = withReleaseImages(m, rel, 0)
		p, _, err := planFromDocument(m)
		if err != nil {
			t.Errorf("%s with the manifest's images: %v", filepath.Base(f), err)
			continue
		}
		if p.ServiceImage != "ghcr.io/x/s@sha256:"+d {
			t.Errorf("%s: service image %q", filepath.Base(f), p.ServiceImage)
		}
	}
	// A plan that names its own image keeps it.
	own := map[string]any{}
	b, _ := os.ReadFile("../../docs/plans/single-region.json")
	_ = json.Unmarshal(b, &own)
	own["service_image"] = "ghcr.io/mine/s@sha256:" + strings.Repeat("b", 64)
	_ = withReleaseImages(own, rel, 0)
	if own["service_image"] != "ghcr.io/mine/s@sha256:"+strings.Repeat("b", 64) {
		t.Fatal("the manifest overruled an image the plan chose")
	}
	// A manifest without digests is refused.
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`{"container_images":{"image_revision_label":"x","images":{"service_image":"ghcr.io/x/s:latest"}}}`), 0o600)
	if _, err := readReleaseManifest(bad); err == nil {
		t.Fatal("a manifest naming a tag instead of a digest was accepted")
	}
}

func TestNamesAreListedEightToALineAndCheckedBeforeAnythingIsCreated(t *testing.T) {
	var names []planClientName
	for i := 0; i < 19; i++ {
		names = append(names, planClientName{Name: "n" + string(rune('a'+i)) + ".example.test", Address: "10.0.0.1"})
	}
	lines := hostsLines(names)
	if len(lines) != 3 {
		t.Fatalf("19 names on one address are 3 lines of at most 8, got %d", len(lines))
	}
	for _, l := range lines {
		if n := len(strings.Fields(l)) - 1; n > 8 {
			t.Fatalf("a line carries %d names; a Windows hosts file reads nine and drops the rest", n)
		}
	}
	missing := namesThatDoNotResolve(names[:2], func(n string) ([]net.IP, error) {
		if n == names[0].Name {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		}
		return nil, errors.New("no such host")
	})
	if len(missing) != 1 || missing[0].Name != names[1].Name {
		t.Fatalf("want exactly the unresolved name, got %+v", missing)
	}
}

// storeUp is a store that answers `member add` and `member list` the way the test says, and records the rest.
type storeUp struct {
	refusals  []string // what the first `member add` attempts answer before one is accepted
	listed    bool     // whether `member list` already holds the member being announced
	adds      int
	lists     int
	slept     int
	otherRuns int
}

func (s *storeUp) runner() upRunner {
	return upRunner{
		run: func(_ context.Context, _, shell string, out io.Writer) error {
			switch {
			case strings.Contains(shell, " member add "):
				s.adds++
				if s.adds <= len(s.refusals) {
					fmt.Fprintln(out, "Error: "+s.refusals[s.adds-1])
					return errors.New("exit status 1")
				}
				return nil
			case strings.HasSuffix(shell, " member list"):
				s.lists++
				fmt.Fprintln(out, "1a2b, started, dsse-store-region-a, https://node-a.example.test:12390, https://node-a.example.test:12379, false")
				if s.listed {
					fmt.Fprintln(out, "3c4d, unstarted, , "+storePeerUnderTest+", , true")
				}
				return nil
			}
			s.otherRuns++
			return nil
		},
		waitCP:  func(context.Context, string, string) error { return nil },
		confirm: func(string) bool { return true },
		sleep:   func(context.Context, time.Duration) { s.slept++ },
		exists:  func(string) bool { return false },
	}
}

// storePeerUnderTest is the address the step under test announces; each test below runs one `member add` step.
var storePeerUnderTest string

func firstStoreAdd(t *testing.T) upStep {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "d")
	steps, err := upSteps(samplePlans(t)["three-regions.json"], dir, dir+".plan.json", "O", "a@example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		if add, ok := parseStoreMemberAdd(st.Shell); ok {
			if !strings.HasSuffix(add.list, " member list") || !strings.HasPrefix(add.peerURL, "https://") {
				t.Fatalf("the order's member add was not understood: %+v from %s", add, st.Shell)
			}
			storePeerUnderTest = add.peerURL
			return st
		}
	}
	t.Fatal("the three-region order announces no store member")
	return upStep{}
}

func runOneStep(t *testing.T, st upStep, s *storeUp) (int, error) {
	t.Helper()
	var log, out bytes.Buffer
	dir := t.TempDir()
	return executeUp(context.Background(), []upStep{st}, upInput{}, dir, dir, "", loadUpProgress(filepath.Join(t.TempDir(), "p.json")), s.runner(), &log, &out)
}

// Right after a member gets its vote the store refuses the next membership change for a moment. The order
// tells a person to wait and ask again; -up does the same instead of stopping.
func TestUpWaitsForTheStoreBeforeAnnouncingTheNextMember(t *testing.T) {
	st := firstStoreAdd(t)
	s := &storeUp{refusals: []string{"etcdserver: unhealthy cluster", "etcdserver: unhealthy cluster"}}
	if stopped, err := runOneStep(t, st, s); err != nil || stopped != -1 {
		t.Fatalf("the step must succeed once the store is ready, stopped at %d: %v", stopped, err)
	}
	if s.adds != 3 || s.slept != 2 || s.lists != 2 {
		t.Fatalf("want 3 attempts with a look at the members and a pause after each refusal, got adds=%d lists=%d pauses=%d", s.adds, s.lists, s.slept)
	}
}

// A member the store already lists is announced: the step is done, and is not asked for a second time.
func TestUpTakesAMemberTheStoreAlreadyListsAsAnnounced(t *testing.T) {
	st := firstStoreAdd(t)
	s := &storeUp{refusals: []string{"etcdserver: Peer URLs already exists"}, listed: true}
	if stopped, err := runOneStep(t, st, s); err != nil || stopped != -1 {
		t.Fatalf("an already announced member must not fail the step, stopped at %d: %v", stopped, err)
	}
	if s.adds != 1 || s.slept != 0 {
		t.Fatalf("want one attempt and no pause, got adds=%d pauses=%d", s.adds, s.slept)
	}
}

// Any other refusal is the step's failure, at once: waiting is only for a store that says it is not ready.
func TestUpDoesNotRepeatAMemberAddTheStoreRefusedForAnotherReason(t *testing.T) {
	st := firstStoreAdd(t)
	s := &storeUp{refusals: []string{"x509: certificate signed by unknown authority", "never reached"}}
	if stopped, err := runOneStep(t, st, s); err == nil || stopped != 0 {
		t.Fatalf("want the step to fail, got %d %v", stopped, err)
	}
	if s.adds != 1 || s.slept != 0 {
		t.Fatalf("want one attempt and no pause, got adds=%d pauses=%d", s.adds, s.slept)
	}
}

// A step that waited for another machine and gave up says where to look: on that machine.
func TestUpSaysWhereToLookWhenAnotherMachineNeverJoined(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	steps, err := upSteps(samplePlans(t)["three-regions.json"], dir, dir+".plan.json", "O", "a@example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		if !st.AfterRemote {
			continue
		}
		r := (&recordedUp{}).runner(true)
		r.run = func(context.Context, string, string, io.Writer) error { return errors.New("exit status 128") }
		var log, out bytes.Buffer
		wd := t.TempDir()
		_, err := executeUp(context.Background(), []upStep{st}, upInput{}, wd, wd, "", loadUpProgress(filepath.Join(t.TempDir(), "p.json")), r, &log, &out)
		if err == nil || !strings.Contains(err.Error(), "names resolve") || !strings.Contains(err.Error(), "exit status 128") {
			t.Fatalf("want the failure to keep its cause and say where to look, got: %v", err)
		}
		return
	}
	t.Fatal("the three-region order has no step that waits for another machine")
}
