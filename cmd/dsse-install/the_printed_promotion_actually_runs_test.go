package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE PRINTED COMMAND IS THE PROCEDURE, SO IT HAS TO RUN (2026-08-31).
//
// The promotion step has to find a member's id by its name, which means a pipeline inside a `sh -c` inside a
// `docker compose exec` — three levels of quoting, and the operator pastes whatever comes out. Asserting that
// the string CONTAINS "member promote" would pass on a command that cannot execute.
//
// So this runs it, against an etcdctl that answers the way etcdctl answers, and requires that it promotes the
// LEARNER by id. The docker prefix is stripped: what is under test is the part that runs in the container.
func TestThePrintedPromotionFindsTheLearnerAndRuns(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	body := `{"deployment":"example.test","regions":[
	 {"id":"tokyo-a","founding":true,"holds_state":true,"machines":[{"name":"node-tokyo-a","holds":["control-plane","edges"],"addresses":["10.0.0.1","10.0.0.2"],"reachable":"node-tokyo-a.example.test","reachable_address":"203.0.113.1"}]},
	 {"id":"tokyo-c","holds_state":true,"machines":[{"name":"node-tokyo-c","holds":["control-plane","edges"],"addresses":["10.0.1.1","10.0.1.2"],"reachable":"node-tokyo-c.example.test","reachable_address":"203.0.113.2"}]}]}`
	if err := os.WriteFile(planPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}

	// An etcdctl that answers as etcdctl does: id, status, name, peer URLs, client URLs, isLearner.
	bin := t.TempDir()
	// ★ THE FAKE READS ITS ARGUMENTS, NOT ITS FIRST ONE. The real command grew --endpoints and --cacert when
	// the store started speaking TLS, and a fixture that looks only at $1 stops matching for a reason that
	// has nothing to do with what is under test.
	fake := "#!/bin/sh\n" +
		"sub=\"\"; for a in \"$@\"; do case \"$a\" in member|list|promote) sub=\"$sub $a\";; esac; done\n" +
		"case \"$sub\" in *\" member list\"*) set -- member list;; *\" member promote\"*) for a in \"$@\"; do case \"$a\" in -*) ;; member|promote) ;; *) id=\"$a\";; esac; done; set -- member promote \"$id\";; esac\n" +
		"if [ \"$1\" = member ] && [ \"$2\" = list ]; then\n" +
		"  echo '8211f1d0f64f3269, started, dsse-store-tokyo-a, http://a:12390, http://a:12379, false'\n" +
		"  echo '91bc3c398fb3c146, started, dsse-store-tokyo-c, http://c:12390, http://c:12379, true'\n" +
		"  exit 0\nfi\n" +
		"if [ \"$1\" = member ] && [ \"$2\" = promote ]; then echo \"PROMOTED $3\"; exit 0; fi\n" +
		"echo \"unexpected: $*\" >&2; exit 2\n"
	if err := os.WriteFile(filepath.Join(bin, "etcdctl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}

	// ★ A DIRECTORY THAT EXISTS (2026-09-02). The printed command now begins `cd <dir> && docker compose`,
	// because compose finds the deployment by the working directory and the founding machine's steps never
	// said which one. Running it against a path that is not there is the operator's experience too.
	found := false
	for _, step := range p.InstallOrder(t.TempDir(), planPath) {
		if !strings.Contains(step.Do, "member promote") {
			continue
		}
		found = true
		// ★ RUN THE WHOLE PRINTED COMMAND (2026-08-31). It used to be stripped of its docker prefix and the
		// remainder run directly, which stopped working the moment the command legitimately contained TWO
		// docker invocations — the promotion and the lookup that finds the id for it. A fake docker that
		// executes whatever follows `exec -T <service>` stands in for the container and leaves the command
		// itself untouched, which is the thing under test.
		if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(
			"#!/bin/sh\nshift $(( $# - $# ))\nseen=0\nfor a in \"$@\"; do\n"+
				"  if [ \"$seen\" = 2 ]; then break; fi\n  shift\n"+
				"  case \"$a\" in exec) seen=1;; -T) [ \"$seen\" = 1 ] && seen=2 && shift;; esac\n"+
				"done\nexec \"$@\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-c", step.Do)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("the printed promotion does not run: %v\n%s\ncommand was:\n%s", err, out, step.Do)
		}
		// ★ THE LEARNER'S ID, NOT THE FOUNDING MEMBER'S. Promoting the wrong one is the failure this lookup
		// exists to avoid, and it would still exit zero.
		if !strings.Contains(string(out), "PROMOTED 91bc3c398fb3c146") {
			t.Errorf("the promotion did not name the joining member's id.\ngot: %s\ncommand was:\n%s", out, step.Do)
		}
	}
	if !found {
		t.Fatal("the install order contains no promotion step, so a joining member would stay a learner forever " +
			"and the deployment would never become redundant")
	}
}
