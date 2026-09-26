package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"
)

// An Edge-local in-process store outliving its welcome is how the fleet view lost devices.
//
// GET /admin/device-runtime was served from a package-level map whose only writers were the steer transport.
// Restart the Edge and it was empty; a device came back only if it happened to dial a new mux, so a Mac could
// be steering perfectly and be absent from the operator's fleet view for hours. The durable record existed on
// the control plane the whole time — the Edge emitted device-state changes, shipped them, and the CP persisted
// them. Nobody read them back. The store was written as if the control plane did not exist.
//
// That is the failure this gate exists to stop repeating: not "someone used a map", which is often right, but
// "someone built an Edge-side store without answering what happens to it on restart, and whether the control
// plane is the thing that owns it."
//
// The gate is a RATCHET, deliberately. The stores that predate it are frozen in a baseline rather than
// retro-classified, because classifying thirty-five stores I have not studied would be guessing dressed as
// governance, and a wrong answer in a declaration is worse than no answer. What it enforces is that the NEXT
// one cannot be added silently: a new in-process store must say, in a comment on its type, how it survives an
// Edge restart. Answering forces the author to look at the control plane; that is the whole point.
//
// To add a store: put a `restart-durability:` line in its type's doc comment with one of the answers below.
// To remove one from the baseline (because it became durable): delete the line — the gate allows shrinkage.

const edgeStoreBaselineFile = "testdata/edge_inprocess_stores.txt"

// The permitted answers. Each is a claim someone can be held to, not a label.
var edgeStoreDurabilityAnswers = map[string]string{
	// The control plane owns the durable record; this store is a cache the Edge rebuilds from it. The shape the
	// repo's own principle asks for — persistence on the CP, the Edge as fetcher.
	"cp_durable": "the control plane holds it and the Edge rehydrates from there",
	// Persisted by the Edge itself (a -state-dir store, a file, Postgres). Durable across a restart, but the
	// Edge owns it — say why the control plane is not the owner.
	"edge_durable": "the Edge persists it locally; the reason the CP does not own it is stated",
	// Deliberately lost on restart, and nothing an operator reads depends on it surviving. Replay caches, rate
	// limiters, in-flight challenges. Losing it must be harmless, not merely tolerated.
	"ephemeral": "deliberately lost on restart; no operator-visible fact depends on it",
	// Pending observations are a different claim from harmlessly discardable caches.
	// The declared bound, flush lifecycle and loss semantics must be stated. This
	// does not classify authoritative configuration/inventory as disposable: emitted
	// records live in their own durable sink; the buffer contains unpublished work.
	"bounded_buffer": "pending observations with a declared bound and flush/loss semantics; emitted records are stored separately",
}

// The second question, which the durability answer does not contain. `f9eb0656` and the device-runtime store
// were both DURABLE ENOUGH in the sense the answers above ask about — what went wrong is that the state arrived
// as a by-product of one code path, so it was absent whenever traffic took another. A store can be perfectly
// persistent and still be empty for eleven days.
var edgeStorePopulationAnswers = map[string]string{
	// Something asserts this state on purpose and keeps asserting it: a heartbeat, an admin write, a poll. It
	// recovers on its own, because the assertion repeats.
	"assertion": "an explicit, repeating claim fills it; it re-converges without operator action",
	// Fetched from the control plane and refreshed. The shape this repo asks for.
	"hydrated": "pulled from the control plane, and refreshed rather than read once at boot",
	// A by-product of some other code path. NOT forbidden — but the author must name the path, because the state
	// is missing for every flow that does not take it, and testing that path will never reveal it.
	"side_effect": "a by-product of another path; the path is named, and being absent off it is acceptable",
}

// isInProcessStore: a struct with both a mutex and a map is state held in this process. That combination is
// what makes it a store rather than a value — it is guarded because more than one goroutine reaches it.
func isInProcessStore(st *ast.StructType) bool {
	hasMutex, hasMap := false, false
	for _, field := range st.Fields.List {
		if sel, ok := field.Type.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "sync" && strings.Contains(sel.Sel.Name, "Mutex") {
				hasMutex = true
			}
		}
		if _, ok := field.Type.(*ast.MapType); ok {
			hasMap = true
		}
	}
	return hasMutex && hasMap
}

// declaredClaim reads a `<marker> <answer>` claim from a type's doc comment, checking both the TypeSpec's own
// doc and the enclosing GenDecl's (a lone `type X struct` carries it on the GenDecl).
func declaredClaim(decl *ast.GenDecl, ts *ast.TypeSpec, marker string) (string, bool) {
	for _, doc := range []*ast.CommentGroup{ts.Doc, decl.Doc} {
		if doc == nil {
			continue
		}
		for _, line := range strings.Split(doc.Text(), "\n") {
			line = strings.TrimSpace(line)
			idx := strings.Index(line, marker)
			if idx < 0 {
				continue
			}
			rest := strings.TrimSpace(line[idx+len(marker):])
			answer := rest
			if cut := strings.IndexAny(rest, " \t—-"); cut > 0 {
				answer = rest[:cut]
			}
			return strings.TrimSpace(answer), true
		}
	}
	return "", false
}

func TestEdgeInProcessStoresDeclareHowTheySurviveARestart(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse cmd/edge: %v", err)
	}

	baselineRaw, err := os.ReadFile(edgeStoreBaselineFile)
	if err != nil {
		t.Fatalf("read %s: %v", edgeStoreBaselineFile, err)
	}
	baseline := map[string]bool{}
	for _, line := range strings.Split(string(baselineRaw), "\n") {
		if name := strings.TrimSpace(line); name != "" && !strings.HasPrefix(name, "#") {
			baseline[name] = true
		}
	}

	type undeclaredStore struct{ name, file string }
	var undeclared []undeclaredStore
	var badAnswer []string
	var missingPopulation []string
	seen := map[string]bool{}

	for _, pkg := range pkgs {
		for filename, file := range pkg.Files {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.TYPE {
					continue
				}
				for _, spec := range gen.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok || !isInProcessStore(st) {
						continue
					}
					name := ts.Name.Name
					seen[name] = true
					answer, declared := declaredClaim(gen, ts, "restart-durability:")
					if declared {
						if _, valid := edgeStoreDurabilityAnswers[answer]; !valid {
							badAnswer = append(badAnswer, name+" declares restart-durability: "+answer+" ("+filename+")")
						}
						// A store that answered the restart question must also answer how it fills. The two are
						// independent: the fleet view was durable in the first sense and empty in the second.
						pop, popDeclared := declaredClaim(gen, ts, "populated-by:")
						switch {
						case !popDeclared:
							missingPopulation = append(missingPopulation, name+"  ("+filename+")")
						default:
							if _, valid := edgeStorePopulationAnswers[pop]; !valid {
								badAnswer = append(badAnswer, name+" declares populated-by: "+pop+" ("+filename+")")
							}
						}
						continue
					}
					if baseline[name] {
						continue // predates the gate
					}
					undeclared = append(undeclared, undeclaredStore{name: name, file: filename})
				}
			}
		}
	}

	if len(missingPopulation) > 0 {
		sort.Strings(missingPopulation)
		answers := make([]string, 0, len(edgeStorePopulationAnswers))
		for a, meaning := range edgeStorePopulationAnswers {
			answers = append(answers, a+" = "+meaning)
		}
		sort.Strings(answers)
		t.Fatalf(`store(s) that answered the restart question but not how they fill:
  %s

Surviving a restart and being CORRECT are different properties, and this is the gap between them: a store can be
persisted perfectly and still be empty, because nothing ever put anything in it on the path the traffic took.
That is what kept a device heartbeating every fifteen seconds off the fleet view for eleven days.

  // populated-by: %s

If the answer is side_effect, name the path — a reviewer needs to ask what happens when traffic goes another way.`,
			strings.Join(missingPopulation, "\n  "), strings.Join(answers, "\n  // populated-by: "))
	}

	if len(badAnswer) > 0 {
		sort.Strings(badAnswer)
		answers := make([]string, 0, len(edgeStoreDurabilityAnswers))
		for a, meaning := range edgeStoreDurabilityAnswers {
			answers = append(answers, a+" = "+meaning)
		}
		sort.Strings(answers)
		t.Fatalf("unknown restart-durability answer:\n  %s\nvalid answers:\n  %s",
			strings.Join(badAnswer, "\n  "), strings.Join(answers, "\n  "))
	}

	if len(undeclared) > 0 {
		lines := make([]string, 0, len(undeclared))
		for _, s := range undeclared {
			lines = append(lines, s.name+"  ("+s.file+")")
		}
		sort.Strings(lines)
		t.Fatalf(`new in-process store(s) in cmd/edge with no answer for what happens on an Edge restart:
  %s

This is the shape that lost devices from the fleet view: a store held only in this process, serving something an
operator reads, written as if the control plane did not exist. Say what happens to it on restart, in a comment
on the type:

  // restart-durability: cp_durable — the control plane persists it; hydrated at startup (see …)
  // restart-durability: edge_durable — persisted to <path/store>; the CP does not own it because …
  // restart-durability: ephemeral — a replay cache; losing it costs nothing an operator can see
  // restart-durability: bounded_buffer — pending observations; state the bound, flush/loss semantics and emitted-record owner

If the honest answer is "the operator reads this and it vanishes on restart", that is the bug, not the
declaration.`, strings.Join(lines, "\n  "))
	}

	// Keep the baseline honest: a name that no longer exists is a line nobody will ever remove later.
	var stale []string
	for name := range baseline {
		if !seen[name] {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Fatalf("%s lists store(s) that no longer exist — remove them so the baseline keeps meaning something:\n  %s",
			edgeStoreBaselineFile, strings.Join(stale, "\n  "))
	}
}
