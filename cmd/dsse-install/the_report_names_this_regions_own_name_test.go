package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ★★★ A PRINTED INSTRUCTION TO REPAIR A CORRECT FILE (2026-08-29, found by building a deployment whose plan
// called its founding region "tokyo").
//
// The mint report said, unconditionally, `THIS REGION IS CALLED "region-a" — change DSSE_EDGE_REGION in
// deployment.env before the first start if it should be called something else`, over a deployment.env the plan
// had already set to "tokyo". An operator who follows that renames the region out from under every record and
// every device that has chosen it — and the name is the one thing renaming later moves neither of.
//
// It was only ever right because every deployment measured until then had accepted the default. That is the
// shape this repository keeps finding: a value that is really a variable, hard-coded once, correct everywhere
// it was looked at.
func TestTheMintReportNamesTheRegionTheDeploymentActuallyHas(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"),
		[]byte("EDGE_HOST='hikari.lab'\nDSSE_EDGE_REGION='tokyo'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Real authorities: report() fingerprints them, and a test that stubs the thing under test into not
	// running is a test of the stub.
	auth, err := mint("Hikari Networks", time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	// reportRegionName rather than report: the founding install mints, reports, and only THEN writes the
	// plan's values into deployment.env, so the line is printed by the plan branch afterwards. Testing it
	// through report() would assert the wrong moment — which is the mistake the second version of this fix
	// was made to correct.
	out := captureStdout(t, func() { reportRegionName(dir) })
	_ = auth

	if !strings.Contains(out, `THIS REGION IS CALLED "tokyo"`) {
		t.Errorf("the report does not name this region:\n%s", lineContaining(out, "THIS REGION IS CALLED"))
	}
	// The control: the old text named region-a AND told the operator to change it. Either half alone is
	// harmless; together they are an instruction to rename a correctly-named region.
	if strings.Contains(out, `THIS REGION IS CALLED "region-a"`) {
		t.Errorf("the report still names the default over a region the plan named:\n%s",
			lineContaining(out, "THIS REGION IS CALLED"))
	}
}

// ★★ AND THE CALL SITE IS WHERE THIS DEFECT LIVED, NOT THE HELPER (2026-08-29). The first fix made
// reportRegionName read deployment.env — correct, and still printed "region-a", because it was called from
// report() during the mint and the plan writes its values afterwards. A test of the helper alone passes on
// both versions. So this reads the source: the line must be printed after the plan has been applied.
func TestTheRegionsNameIsPrintedAfterThePlanHasHadItsSay(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	apply := strings.Index(body, "applyPlanToFoundingMachine(plan, *dir)")
	if apply < 0 {
		t.Fatal("main.go no longer applies the plan to the founding machine — this gate is asserting nothing")
	}
	after := strings.Index(body[apply:], "reportRegionName(*dir)")
	if after < 0 {
		t.Error("the plan branch never prints the region's name, so a planned install says nothing about " +
			"what its region is called — or says it from report(), where the plan has not been applied yet")
	}
}

// captureStdout runs f with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			b.Write(buf[:n])
			if rerr != nil {
				break
			}
		}
		done <- b.String()
	}()
	f()
	w.Close()
	os.Stdout = saved
	return <-done
}
