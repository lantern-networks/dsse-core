package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The files this installer derives are a function of the deployment's own values. Regenerating them with the
// installer that wrote them must therefore change nothing — on the machine that minted the deployment and on
// every machine prepared from a package. An upgrade relies on this: what it reports as changed is then what the
// release changed, and nothing else.
func TestRegeneratingWithTheSameInstallerChangesNothing(t *testing.T) {
	plans, _ := filepath.Glob("../../docs/plans/*.json")
	if len(plans) < 5 {
		t.Fatalf("expected the published sample plans, found %d", len(plans))
	}
	for _, planPath := range plans {
		t.Run(filepath.Base(planPath), func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "source")
			plan := installFromPlan(t, planPath, source)
			founding := plan.foundingRegion().controlPlane().Name
			for _, name := range plan.MachineNames() {
				t.Run(name, func(t *testing.T) {
					dir := source
					if name != founding {
						archive := filepath.Join(t.TempDir(), "node.tar.gz")
						if err := carryPlanMachine(plan, source, archive, name); err != nil {
							t.Fatal(err)
						}
						dir = unpackCarry(t, archive)
					}
					before := generatedFiles(t, dir)
					if err := upgradeDerivedFiles(dir); err != nil {
						t.Fatal(err)
					}
					after := generatedFiles(t, dir)
					names := map[string]bool{}
					for n := range before {
						names[n] = true
					}
					for n := range after {
						names[n] = true
					}
					sorted := []string{}
					for n := range names {
						sorted = append(sorted, n)
					}
					sort.Strings(sorted)
					for _, n := range sorted {
						b, had := before[n]
						a, has := after[n]
						switch {
						case !had:
							t.Errorf("%s appeared", n)
						case !has:
							t.Errorf("%s disappeared", n)
						case !bytes.Equal(a, b):
							t.Errorf("%s changed (%d differing line(s)): %s", n, differingLines(a, b), firstDifference(a, b))
						}
					}
				})
			}
		})
	}
}

func generatedFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range upgradeKeptFiles(dir) {
		if body, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			if name == "deployment.env" {
				// The regeneration states one default in words where the file was silent: whose certificate
				// the step-up portal is on. Absent and "deployment" mean the same thing to everything that
				// reads the setting, so the statement is not counted as a change.
				body = withoutSetting(body, stepUpPortalCertEnvKey, "deployment")
			}
			out[name] = body
		}
	}
	return out
}

func differingLines(a, b []byte) int {
	as, bs := bytes.Split(a, []byte("\n")), bytes.Split(b, []byte("\n"))
	seen := map[string]int{}
	for _, l := range as {
		seen[string(l)]++
	}
	for _, l := range bs {
		seen[string(l)]--
	}
	n := 0
	for _, c := range seen {
		if c < 0 {
			c = -c
		}
		n += c
	}
	return n
}

func firstDifference(a, b []byte) string {
	have := map[string]bool{}
	for _, l := range bytes.Split(b, []byte("\n")) {
		have[string(l)] = true
	}
	for _, l := range bytes.Split(a, []byte("\n")) {
		if !have[string(l)] {
			if i := bytes.IndexByte(l, '='); i > 0 && bytes.HasPrefix(l, []byte("DSSE_")) {
				return "new line sets " + string(l[:i])
			}
			if len(l) > 90 {
				l = l[:90]
			}
			return "new line: " + string(l)
		}
	}
	return "a line was removed"
}

func withoutSetting(body []byte, key, value string) []byte {
	var out [][]byte
	for _, l := range bytes.Split(body, []byte("\n")) {
		if bytes.HasPrefix(l, []byte(key+"=")) && string(bytes.Trim(l[len(key)+1:], `'"`)) == value {
			continue
		}
		out = append(out, l)
	}
	return bytes.TrimRight(bytes.Join(out, []byte("\n")), "\n")
}
