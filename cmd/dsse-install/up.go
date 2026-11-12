package main

// up.go — `-up` runs the order `-order` prints.
//
// Standing a deployment up is a list of steps in one order, and `-order` prints that list for any plan: six
// steps for one machine, thirty-five for three regions with several Edges. Almost all of them are commands typed
// on the first machine, one after another, with waits between that the printed order describes in prose. -up
// runs them: the same commands, in the same order, waiting where the order tells a person to wait.
//
// What it cannot do from one machine is start another. For each other machine the order has a package to carry
// there and one command to run there. -up builds the package and then either hands that one command to the
// person (the default) or, with -ssh, does what the order's own scp and remote lines say. So a deployment takes
// one command per machine, or one command in all.
//
// It adds no step and decides nothing a plan does not already decide. A step it does not recognise stops it
// before anything runs.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type upInput struct {
	Plan           string
	Deployment     string
	Address        string
	AdminEmail     string
	Organization   string
	Dir            string
	Manifest       string
	AgentPublisher string
	PostgresMajor  int
	PrintNames     bool
	SSH            bool
	Confirmed      string
	Timeout        time.Duration
}

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// releaseImages is what a release manifest says about the server images of that release.
type releaseImages struct {
	ImageRevision  string
	Service        string
	Console        string
	Etcd           string
	Postgres       string
	PostgresTools  string
	PostgresMajor  int
	AgentPublisher string
}

// readReleaseManifest takes the image references from the release's own manifest, so nobody copies digests by
// hand. The manifest is the file published beside the installer and listed in the release's SHA256SUMS.
func readReleaseManifest(path string) (*releaseImages, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the release manifest: %w", err)
	}
	var m struct {
		AgentPublisher  string `json:"agent_publisher"`
		ContainerImages struct {
			ImageRevisionLabel string            `json:"image_revision_label"`
			Images             map[string]string `json:"images"`
			PostgresMajor      json.Number       `json:"postgres_major"`
		} `json:"container_images"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s is not a release manifest: %w", path, err)
	}
	im := m.ContainerImages.Images
	out := &releaseImages{
		ImageRevision: strings.TrimSpace(m.ContainerImages.ImageRevisionLabel),
		Service:       im["service_image"], Console: im["console_image"],
		Etcd: im["data_layer.etcd_image"], Postgres: im["data_layer.postgres_image"],
		PostgresTools:  im["data_layer.postgres_tools_image"],
		AgentPublisher: strings.TrimSpace(m.AgentPublisher),
	}
	if s := m.ContainerImages.PostgresMajor.String(); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			out.PostgresMajor = n
		}
	}
	for _, kv := range [][2]string{{"service_image", out.Service}, {"console_image", out.Console},
		{"data_layer.etcd_image", out.Etcd}, {"data_layer.postgres_image", out.Postgres},
		{"data_layer.postgres_tools_image", out.PostgresTools}} {
		if !immutableImageRef(kv[1]) {
			return nil, fmt.Errorf("%s names no digest-pinned %s, so it cannot say which images this release is", path, kv[0])
		}
	}
	if out.ImageRevision == "" {
		return nil, fmt.Errorf("%s carries no container_images.image_revision_label", path)
	}
	return out, nil
}

// oneMachinePlanDocument is the plan a person would have written for one machine holding everything.
func oneMachinePlanDocument(in upInput) (map[string]any, error) {
	dep := strings.ToLower(strings.TrimSpace(in.Deployment))
	if dep == "" || strings.ContainsAny(dep, " /:@") || !strings.Contains(dep, ".") {
		return nil, fmt.Errorf("-deployment must be a DNS name you control, such as dsse.example.com")
	}
	ip := net.ParseIP(strings.TrimSpace(in.Address))
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return nil, fmt.Errorf("-address must be an address this machine really has (not a loopback), because every name of the deployment is pointed at it")
	}
	doc := map[string]any{
		"deployment": dep,
		"regions": []any{map[string]any{
			"id": "region-a", "founding": true, "holds_state": true,
			"machines": []any{map[string]any{
				"name": "node-a", "holds": []any{"control-plane", "edges"},
				"addresses": []any{ip.String()}, "reachable": "node-a." + dep, "reachable_address": ip.String(),
			}},
		}},
	}
	if p := strings.TrimSpace(in.AgentPublisher); p != "" {
		doc["agent_publisher"] = p
	}
	return doc, nil
}

// withReleaseImages fills what the plan document leaves unsaid from the release manifest. An image the plan
// pins by digest stays: that is a decision, and this does not overrule it. A value that is not a digest — the
// sample plans carry names like "dsse:release" where an image goes — names no particular image, so the
// release's takes its place.
func withReleaseImages(doc map[string]any, rel *releaseImages, postgresMajor int) error {
	set := func(m map[string]any, key string, value any) {
		cur, ok := m[key]
		if text, isText := cur.(string); isText && strings.HasSuffix(key, "_image") && !immutableImageRef(text) {
			ok = false
		}
		if !ok || cur == nil || cur == "" || cur == float64(0) || strings.HasPrefix(fmt.Sprint(cur), "REPLACE_") {
			m[key] = value
		}
	}
	if rel != nil {
		set(doc, "image_revision", rel.ImageRevision)
		set(doc, "service_image", rel.Service)
		set(doc, "console_image", rel.Console)
		if rel.AgentPublisher != "" {
			set(doc, "agent_publisher", rel.AgentPublisher)
		}
		layer, _ := doc["data_layer"].(map[string]any)
		if layer == nil {
			layer = map[string]any{}
			doc["data_layer"] = layer
		}
		set(layer, "etcd_image", rel.Etcd)
		set(layer, "postgres_image", rel.Postgres)
		set(layer, "postgres_tools_image", rel.PostgresTools)
		if rel.PostgresMajor != 0 {
			set(layer, "postgres_major", rel.PostgresMajor)
		}
	}
	if postgresMajor != 0 {
		layer, _ := doc["data_layer"].(map[string]any)
		if layer == nil {
			layer = map[string]any{}
			doc["data_layer"] = layer
		}
		layer["postgres_major"] = postgresMajor
	}
	return nil
}

func planFromDocument(doc map[string]any) (*Plan, []byte, error) {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp("", "dsse-plan-*.json")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return nil, nil, err
	}
	tmp.Close()
	plan, err := LoadPlan(tmp.Name())
	if err != nil {
		return nil, nil, err
	}
	return plan, raw, nil
}

// hostsLines renders the deployment's names as hosts-file lines. At most eight names a line: the Windows hosts
// file reads nine names on a line and silently ignores the rest.
func hostsLines(names []planClientName) []string {
	byAddr := map[string][]string{}
	var order []string
	for _, n := range names {
		if _, seen := byAddr[n.Address]; !seen {
			order = append(order, n.Address)
		}
		byAddr[n.Address] = append(byAddr[n.Address], n.Name)
	}
	var out []string
	for _, addr := range order {
		list := byAddr[addr]
		for len(list) > 0 {
			n := min(8, len(list))
			out = append(out, addr+" "+strings.Join(list[:n], " "))
			list = list[n:]
		}
	}
	return out
}

// namesThatDoNotResolve lists the names this machine cannot resolve at all.
func namesThatDoNotResolve(names []planClientName, lookup func(string) ([]net.IP, error)) []planClientName {
	var missing []planClientName
	for _, n := range names {
		if addrs, err := lookup(n.Name); err != nil || len(addrs) == 0 {
			missing = append(missing, n)
		}
	}
	return missing
}

type upStepKind int

const (
	upRun        upStepKind = iota // a command on this machine
	upMint                         // the first act; kept if already done
	upFirstAdmin                   // output is credentials: captured to a private file
	upRestart                      // replaces the processes that were answering
	upCopy                         // the order's scp of a package to another machine
	upRemote                       // the one command another machine runs
)

type upStep struct {
	Kind    upStepKind
	Machine string
	// Shell is what `-order` prints for this step, with its placeholders filled in.
	Shell string
	// Capture, for the first administrator: the file its output goes to and nowhere else.
	Capture string
	// Package and Host, for a copy: the file and the SSH destination the order names.
	Package, Host string
	// AfterRemote marks a step on this machine that follows another machine's start, and so may have to wait
	// for that machine before it succeeds.
	AfterRemote bool
}

var (
	firstAdminCapture = regexp.MustCompile(`^\(umask 077; set -C; (.+) > (\S+) 2>&1\)$`)
	scpStep           = regexp.MustCompile(`^scp (\S+) (\S+):$`)
	controlPlaneURL   = regexp.MustCompile(`-control-plane (https://\S+)`)
	placeholder       = regexp.MustCompile(`<[A-Za-z][A-Za-z '-]*>`)
)

// upSteps turns the printed order into what -up runs. It recognises the steps by what they are, fills the two
// values the order leaves to the reader, and refuses a step that still asks for something it was not given.
func upSteps(plan *Plan, dir, planPath, organization, adminEmail string) ([]upStep, error) {
	minting := plan.foundingRegion().controlPlane().Name
	var out []upStep
	afterRemote := false
	for _, s := range plan.InstallOrder(dir, planPath) {
		do := s.Do
		step := upStep{Kind: upRun, Machine: s.Machine, Shell: do}
		switch {
		case s.Machine != minting:
			step.Kind = upRemote
		case strings.Contains(do, "-organization <name>"):
			step.Kind = upMint
			step.Shell = strings.Replace(do, "-organization <name>", "-organization "+shellQuote(organization), 1)
		case strings.Contains(do, "-bootstrap-admin"):
			m := firstAdminCapture.FindStringSubmatch(do)
			if m == nil || !strings.Contains(m[1], "-admin-email <address>") {
				return nil, fmt.Errorf("the first-administrator step is not in the form -up knows: %s", do)
			}
			step.Kind, step.Capture = upFirstAdmin, m[2]
			step.Shell = strings.Replace(m[1], "-admin-email <address>", "-admin-email "+shellQuote(adminEmail), 1)
		case strings.Contains(do, "--force-recreate"):
			step.Kind = upRestart
		case scpStep.MatchString(do):
			m := scpStep.FindStringSubmatch(do)
			step.Kind, step.Package, step.Host = upCopy, m[1], m[2]
		}
		if step.Kind == upRemote {
			afterRemote = true
		} else if step.Kind != upCopy {
			step.AfterRemote, afterRemote = afterRemote, false
		}
		if ph := placeholder.FindString(step.Shell); ph != "" {
			return nil, fmt.Errorf("a step asks for %s, which -up was not given, so it will not run this order unattended: %s", ph, do)
		}
		out = append(out, step)
	}
	if len(out) == 0 || out[0].Kind != upMint {
		return nil, fmt.Errorf("the order for this plan does not begin by minting the deployment, so -up will not run it")
	}
	return out, nil
}

// waitForControlPlane waits until the control plane answers. Started is not answering: compose returns as soon
// as the containers exist.
func waitForControlPlane(ctx context.Context, url, anchorFile string) error {
	pem, err := os.ReadFile(anchorFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s holds no certificate", anchorFile)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}}
	var last error
	// Three answers in a row, not one: while the process behind the door is still coming up, the door can
	// answer once and drop the next connection.
	steady := 0
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if steady++; steady >= 3 {
					return nil
				}
			} else {
				steady = 0
				last = fmt.Errorf("the control plane answered %d", resp.StatusCode)
			}
		} else {
			steady = 0
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the control plane at %s did not answer in time: %v", url, last)
		case <-time.After(2 * time.Second):
		}
	}
}

// firstRequestNeverAnswered reports whether a failed first-administrator step failed at its first request, in
// transport: the invitation was sent and no answer came back.
func firstRequestNeverAnswered(outputFile string) bool {
	raw, err := os.ReadFile(outputFile)
	if err != nil {
		return false
	}
	text := string(raw)
	if !strings.Contains(text, "/admin/admins/invite\"") {
		return false
	}
	for _, sign := range []string{": EOF", "connection refused", "connection reset"} {
		if strings.Contains(text, sign) {
			return true
		}
	}
	return false
}

func tailOf(path string, lines int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	all := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// upProgress is which steps of this order have completed, so a second run continues instead of starting over.
// A step is remembered by its position AND its exact command: a plan that changed is a different order.
type upProgress struct {
	path string
	Done map[string]string `json:"done"`
}

func loadUpProgress(path string) *upProgress {
	p := &upProgress{path: path, Done: map[string]string{}}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, p)
		if p.Done == nil {
			p.Done = map[string]string{}
		}
	}
	return p
}

func stepDigest(s upStep) string {
	sum := sha256.Sum256([]byte(s.Machine + "\x00" + s.Shell))
	return hex.EncodeToString(sum[:8])
}

func (p *upProgress) done(i int, s upStep) bool { return p.Done[strconv.Itoa(i)] == stepDigest(s) }

func (p *upProgress) mark(i int, s upStep) error {
	p.Done[strconv.Itoa(i)] = stepDigest(s)
	raw, _ := json.MarshalIndent(p, "", " ")
	return os.WriteFile(p.path, append(raw, '\n'), 0o600)
}

// upRunner is how -up touches the world, so the sequence can be exercised without one.
type upRunner struct {
	run     func(ctx context.Context, dir, shell string, out io.Writer) error
	waitCP  func(ctx context.Context, url, anchor string) error
	confirm func(machine string) bool
	sleep   func(ctx context.Context, d time.Duration)
	exists  func(path string) bool
}

func stepTitle(s upStep) string {
	switch s.Kind {
	case upMint:
		return "create this deployment's authorities, certificates and configuration"
	case upFirstAdmin:
		return "create the first administrator"
	case upRestart:
		return "restart what was started before the administrator existed"
	case upCopy:
		return "copy " + s.Package + " to " + s.Host
	case upRemote:
		return "start " + s.Machine
	}
	switch {
	case strings.Contains(s.Shell, " -carry "):
		return "pack what another machine needs"
	case strings.Contains(s.Shell, "-activate-auth"):
		return "turn on the authentication features"
	case strings.Contains(s.Shell, " -verify "):
		return "check the whole deployment"
	case strings.Contains(s.Shell, "member add"):
		return "announce a new store member"
	case strings.Contains(s.Shell, "member promote"):
		return "give the new store member its vote"
	case strings.Contains(s.Shell, "-start-node") || strings.HasSuffix(s.Shell, " up -d"):
		return "start this machine"
	}
	return "run the next step of the order"
}

// storeMemberAdd is a `member add` line of the order, read for the two things waiting on it needs.
type storeMemberAdd struct {
	// list is the same store command asking for the members instead.
	list string
	// peerURL is the address the new member is announced under.
	peerURL string
}

func parseStoreMemberAdd(shell string) (storeMemberAdd, bool) {
	i := strings.Index(shell, " member add ")
	if i < 0 {
		return storeMemberAdd{}, false
	}
	for _, f := range strings.Fields(shell[i:]) {
		if u, ok := strings.CutPrefix(f, "--peer-urls="); ok && u != "" {
			return storeMemberAdd{list: shell[:i] + " member list", peerURL: u}, true
		}
	}
	return storeMemberAdd{}, false
}

// storeListsPeer reports whether a `member list` answer holds a member announced under peerURL. A member that
// was announced and has not started yet has no name, so the address is what identifies it.
func storeListsPeer(list, peerURL string) bool {
	for _, line := range strings.Split(list, "\n") {
		f := strings.Split(line, ", ")
		if len(f) < 4 {
			continue
		}
		for _, u := range strings.Split(f[3], ",") {
			if strings.TrimSpace(u) == peerURL {
				return true
			}
		}
	}
	return false
}

// announceStoreMember runs a `member add` line the way the order tells a person to. Right after a member is
// given its vote the store refuses the next membership change until every member has been seen healthy; the
// order says to wait and ask again, and only if the member was not announced. So: a refusal is followed by a
// look at the members. A member already listed is announced, whatever the command said. A store that answers
// "unhealthy cluster" is asked again after a pause. Any other refusal is the step's failure, at once.
func announceStoreMember(ctx context.Context, r upRunner, dir, shell string, add storeMemberAdd, log io.Writer) error {
	for attempt := 0; ; attempt++ {
		var said bytes.Buffer
		err := r.run(ctx, dir, shell, io.MultiWriter(log, &said))
		if err == nil {
			return nil
		}
		var members bytes.Buffer
		if lerr := r.run(ctx, dir, add.list, &members); lerr == nil && storeListsPeer(members.String(), add.peerURL) {
			fmt.Fprintf(log, "the store lists %s: the member is announced\n", add.peerURL)
			return nil
		}
		if !strings.Contains(said.String(), "unhealthy cluster") || attempt >= 60 || ctx.Err() != nil {
			return err
		}
		fmt.Fprintln(log, "the store is not ready for a membership change yet; asking again in 5s")
		r.sleep(ctx, 5*time.Second)
	}
}

// executeUp runs the steps. It returns the index of the step that stopped it (or -1), and why.
func executeUp(ctx context.Context, steps []upStep, in upInput, dir, workDir, logPath string, prog *upProgress,
	r upRunner, logFile, stdout io.Writer) (int, error) {
	cpURL := ""
	for _, s := range steps {
		if m := controlPlaneURL.FindStringSubmatch(s.Shell); m != nil {
			cpURL = m[1]
			break
		}
	}
	anchor := filepath.Join(dir, "deployment-anchor.pem")
	confirmedList := map[string]bool{}
	for _, m := range strings.Split(in.Confirmed, ",") {
		if m = strings.TrimSpace(m); m != "" {
			confirmedList[m] = true
		}
	}
	for i := 0; i < len(steps); i++ {
		s := steps[i]
		label := fmt.Sprintf("[%d/%d] %s", i+1, len(steps), stepTitle(s))
		if prog.done(i, s) {
			fmt.Fprintf(stdout, "%s ... already done\n", label)
			continue
		}
		fmt.Fprintf(logFile, "\n===== %s step %d on %s: %s =====\n", time.Now().UTC().Format(time.RFC3339), i+1, s.Machine, stepTitle(s))
		began := time.Now()
		var err error
		switch s.Kind {
		case upMint:
			fmt.Fprintf(stdout, "%s ... ", label)
			if !r.exists(anchor) {
				err = r.run(ctx, workDir, s.Shell, logFile)
			}
		case upFirstAdmin:
			fmt.Fprintf(stdout, "%s ... ", label)
			if err = r.waitCP(ctx, cpURL, anchor); err != nil {
				break
			}
			if r.exists(s.Capture) {
				break
			}
			// The output holds the administrator's credentials. It goes to a private file and nowhere else, and
			// the file takes its final name only when the step succeeded, so a failed attempt can be run again.
			pending := s.Capture + ".pending"
			f, openErr := os.OpenFile(pending, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if openErr != nil {
				err = openErr
				break
			}
			err = r.run(ctx, workDir, s.Shell, f)
			f.Close()
			// The first thing this step does is invite the administrator. If that request never got an answer
			// — the door dropped the connection because the process behind it was not there yet — nothing was
			// created, and asking again is the same as waiting. Anything later in the step is not repeated.
			for attempt := 0; err != nil && attempt < 10 && ctx.Err() == nil && firstRequestNeverAnswered(pending); attempt++ {
				r.sleep(ctx, 3*time.Second)
				if err = r.waitCP(ctx, cpURL, anchor); err != nil {
					break
				}
				if f, openErr = os.OpenFile(pending, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); openErr != nil {
					err = openErr
					break
				}
				err = r.run(ctx, workDir, s.Shell, f)
				f.Close()
			}
			if err == nil {
				err = os.Rename(pending, s.Capture)
			} else {
				fmt.Fprintf(logFile, "the first-administrator step failed; what it printed is in %s\n", pending)
			}
		case upRestart:
			fmt.Fprintf(stdout, "%s ... ", label)
			if err = r.run(ctx, workDir, s.Shell, logFile); err == nil {
				// The processes that were answering are the ones being replaced: give them a moment to go, then
				// wait for the new ones.
				r.sleep(ctx, 10*time.Second)
				err = r.waitCP(ctx, cpURL, anchor)
			}
		case upCopy:
			// The copy belongs with the command that follows it on the other machine. Without -ssh both are
			// the person's, asked for together; and a machine the person has already done is not copied to
			// again by this command, with or without -ssh.
			target := ""
			for j := i + 1; j < len(steps) && target == ""; j++ {
				if steps[j].Kind == upRemote {
					target = steps[j].Machine
				}
			}
			if confirmedList[target] {
				if merr := prog.mark(i, s); merr != nil {
					return i, merr
				}
				continue
			}
			if !in.SSH {
				continue
			}
			fmt.Fprintf(stdout, "%s ... ", label)
			err = r.run(ctx, workDir, s.Shell, logFile)
		case upRemote:
			pkg, host := "", ""
			for j := i - 1; j >= 0 && pkg == ""; j-- {
				if steps[j].Kind == upCopy {
					pkg, host = steps[j].Package, steps[j].Host
				}
			}
			if confirmedList[s.Machine] {
				// The person has said this machine's command is done.
				fmt.Fprintf(stdout, "%s ... ", label)
				break
			}
			if in.SSH {
				fmt.Fprintf(stdout, "%s ... ", label)
				if host == "" {
					err = fmt.Errorf("the order names no SSH destination for %s", s.Machine)
					break
				}
				err = r.run(ctx, workDir, "ssh "+shellQuote(host)+" "+shellQuote(s.Shell), logFile)
				break
			}
			{
				fmt.Fprintf(stdout, "%s\n\n      This step belongs to %s.\n", label, s.Machine)
				if pkg != "" {
					fmt.Fprintf(stdout, "      1. Copy %s to %s (for example: scp %s %s:)\n", filepath.Join(workDir, pkg), s.Machine, filepath.Join(workDir, pkg), host)
					fmt.Fprintf(stdout, "      2. On %s, in the directory you copied it to, run:\n\n           %s\n\n", s.Machine, s.Shell)
				} else {
					fmt.Fprintf(stdout, "      On %s, run:\n\n           %s\n\n", s.Machine, s.Shell)
				}
				if !r.confirm(s.Machine) {
					return i, fmt.Errorf("waiting for %s: when its command has finished, run this command again with -confirmed %s", s.Machine, s.Machine)
				}
			}
			fmt.Fprintf(stdout, "%s ... ", label)
		default:
			fmt.Fprintf(stdout, "%s ... ", label)
			if add, ok := parseStoreMemberAdd(s.Shell); ok {
				err = announceStoreMember(ctx, r, workDir, s.Shell, add, logFile)
				break
			}
			err = r.run(ctx, workDir, s.Shell, logFile)
			// A step that follows another machine's start may be early: that machine is still joining. The
			// order says to wait for it; waiting is trying again, and a refusal changes nothing.
			for attempt := 0; err != nil && s.AfterRemote && attempt < 60 && ctx.Err() == nil; attempt++ {
				r.sleep(ctx, 5*time.Second)
				err = r.run(ctx, workDir, s.Shell, logFile)
			}
			if err != nil && s.AfterRemote {
				// What this step waited for is on the other machine, so that is where the cause is.
				err = fmt.Errorf("%w; the machine started just before this step has not joined — on that machine, check that its containers are running and that this deployment's names resolve there", err)
			}
		}
		if err != nil {
			fmt.Fprintf(stdout, "FAILED after %s\n", time.Since(began).Truncate(time.Second))
			return i, err
		}
		if merr := prog.mark(i, s); merr != nil {
			return i, merr
		}
		fmt.Fprintf(stdout, "done in %s\n", time.Since(began).Truncate(time.Second))
	}
	return -1, nil
}

// runUp is -up. It returns the process exit code.
func runUp(in upInput, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "dsse-install: "+format+"\n", a...)
		return 1
	}
	var doc map[string]any
	switch {
	case strings.TrimSpace(in.Plan) != "" && (in.Deployment != "" || in.Address != ""):
		return fail("give -up either -plan, or -deployment and -address for one machine — not both")
	case strings.TrimSpace(in.Plan) != "":
		raw, err := os.ReadFile(in.Plan)
		if err != nil {
			return fail("read the plan: %v", err)
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fail("%s is not a plan: %v", in.Plan, err)
		}
	default:
		var err error
		if doc, err = oneMachinePlanDocument(in); err != nil {
			return fail("%v", err)
		}
	}
	if p := strings.TrimSpace(in.AgentPublisher); p != "" {
		doc["agent_publisher"] = p
	}
	var rel *releaseImages
	if strings.TrimSpace(in.Manifest) != "" {
		var err error
		if rel, err = readReleaseManifest(in.Manifest); err != nil {
			return fail("%v", err)
		}
	}
	if err := withReleaseImages(doc, rel, in.PostgresMajor); err != nil {
		return fail("%v", err)
	}
	plan, planRaw, err := planFromDocument(doc)
	if err != nil {
		return fail("%v", err)
	}
	names := planNamesClientsUse(plan)
	if in.PrintNames {
		for _, line := range hostsLines(names) {
			fmt.Fprintln(stdout, line)
		}
		return 0
	}
	if strings.TrimSpace(plan.ServiceImage) == "" {
		return fail("the plan names no images. Pass -release-manifest with the release-manifest.json published beside this installer, and -up takes them from it")
	}
	if strings.TrimSpace(in.Dir) == "" || strings.TrimSpace(in.AdminEmail) == "" {
		return fail("-up needs -dir (where this deployment's keys will live) and -admin-email (the first administrator)")
	}
	dir, err := filepath.Abs(in.Dir)
	if err != nil {
		return fail("%v", err)
	}
	if out, err := exec.Command("docker", "compose", "version").CombinedOutput(); err != nil {
		return fail("Docker with Compose v2 is needed on this machine, and `docker compose version` failed: %v %s", err, strings.TrimSpace(string(out)))
	}
	// The names come first, before anything is created: every later step reaches the deployment by name.
	if missing := namesThatDoNotResolve(names, net.LookupIP); len(missing) > 0 {
		fmt.Fprintf(stderr, "dsse-install: %d of this deployment's %d names do not resolve on this machine, and every step after this one reaches the deployment by name.\n", len(missing), len(names))
		fmt.Fprintf(stderr, "Nothing has been created. Add them to DNS, or to this machine's hosts file:\n\n")
		for _, line := range hostsLines(names) {
			fmt.Fprintf(stderr, "    %s\n", line)
		}
		fmt.Fprintf(stderr, "\nThe same command with -print-names prints exactly these lines (for `| sudo tee -a /etc/hosts`). Then run this command again.\n")
		return 2
	}
	planPath := dir + ".plan.json"
	if have, err := os.ReadFile(planPath); err == nil {
		if !bytes.Equal(have, planRaw) {
			return fail("%s already holds a different plan. A deployment is minted once; to stand up a different one, use a different -dir", planPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail("%v", err)
	} else {
		if err := os.MkdirAll(filepath.Dir(planPath), 0o755); err != nil {
			return fail("%v", err)
		}
		if err := os.WriteFile(planPath, planRaw, 0o600); err != nil {
			return fail("%v", err)
		}
	}
	organization := strings.TrimSpace(in.Organization)
	if organization == "" {
		organization = "DSSE Deployment"
	}
	steps, err := upSteps(plan, dir, planPath, organization, strings.TrimSpace(in.AdminEmail))
	if err != nil {
		return fail("%v", err)
	}
	// Packages for other machines hold private keys; they are written to a private directory beside the
	// deployment, and every step runs from there, as the printed order assumes one working directory.
	workDir := dir + ".packages"
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fail("%v", err)
	}
	logPath := dir + ".install.log"
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fail("%v", err)
	}
	defer logFile.Close()
	self, err := os.Executable()
	if err != nil {
		return fail("%v", err)
	}
	// The steps call `dsse-install` by name, as the printed order does. Make that name this binary.
	binDir, err := os.MkdirTemp("", "dsse-install-self-")
	if err != nil {
		return fail("%v", err)
	}
	defer os.RemoveAll(binDir)
	if err := os.Symlink(self, filepath.Join(binDir, "dsse-install")); err != nil {
		return fail("%v", err)
	}
	env := append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), in.Timeout)
	defer cancel()
	// A person is there to answer only when input is a terminal. The null device is a character device too.
	interactive := false
	if f, ok := stdin.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			if null, nerr := os.Stat(os.DevNull); nerr != nil || !os.SameFile(st, null) {
				interactive = true
			}
		}
	}
	reader := bufio.NewReader(stdin)
	runner := upRunner{
		run: func(ctx context.Context, wd, shell string, out io.Writer) error {
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", shell)
			cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = wd, env, out, out
			return cmd.Run()
		},
		waitCP: waitForControlPlane,
		confirm: func(machine string) bool {
			if !interactive {
				return false
			}
			fmt.Fprintf(stdout, "      Press Enter here when that command has finished on %s. ", machine)
			_, err := reader.ReadString('\n')
			return err == nil
		},
		sleep: func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		},
		exists: func(path string) bool { _, err := os.Stat(path); return err == nil },
	}
	machines := 0
	for _, r := range plan.Regions {
		machines += len(r.Machines)
	}
	fmt.Fprintf(stdout, "%s: %d machine(s), %d steps. The log is %s\n", plan.Deployment, machines, len(steps), logPath)
	stopped, err := executeUp(ctx, steps, in, dir, workDir, logPath, loadUpProgress(dir+".install-progress.json"), runner, logFile, stdout)
	if err != nil {
		if strings.HasPrefix(err.Error(), "waiting for ") {
			fmt.Fprintf(stderr, "dsse-install: %v\n", err)
			return 3
		}
		if ctx.Err() != nil {
			fmt.Fprintf(stderr, "dsse-install: the time allowed for setup (-setup-timeout %s) ran out.\n", in.Timeout)
		}
		if steps[stopped].Kind != upFirstAdmin {
			fmt.Fprintf(stderr, "%s\n", tailOf(logPath, 25))
		}
		fmt.Fprintf(stderr, "dsse-install: step %d of %d did not complete (%v). Steps already done are kept; correct the cause and run the same command again. The full log is %s\n",
			stopped+1, len(steps), err, logPath)
		return 1
	}
	for _, line := range strings.Split(tailOf(logPath, 4), "\n") {
		if strings.Contains(line, "checks passed") {
			fmt.Fprintf(stdout, "      %s\n", strings.TrimSpace(line))
		}
	}
	console, capture := "", ""
	for _, n := range names {
		if strings.HasPrefix(n.Name, "console.") && console == "" {
			console = n.Name
		}
	}
	for _, s := range steps {
		if s.Kind == upFirstAdmin {
			capture = s.Capture
		}
	}
	fmt.Fprintf(stdout, "\nThe deployment is up.\n")
	fmt.Fprintf(stdout, "  Console:                  https://%s\n", console)
	fmt.Fprintf(stdout, "  First administrator:      %s — the password and second factor are in %s (private; read it, then keep it safe)\n", strings.TrimSpace(in.AdminEmail), capture)
	fmt.Fprintf(stdout, "  Trust anchor to hand out: %s\n", filepath.Join(dir, "deployment-anchor.pem"))
	fmt.Fprintf(stdout, "  On the administrator's PC and on each device, point the same names at the addresses they reach this deployment by (-print-names prints them).\n")
	return 0
}
