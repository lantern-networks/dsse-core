package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// ★★★ THE PRINTED PROCEDURE DESCRIBED ONE SHAPE ON EVERY SHAPE (2026-08-27, caught by walking a second
// region's control-plane machine). The compose was rendered correctly — a state-bearing join, no consensus
// store, no Edges — and the text beside it said "THIS REGION HOLDS NO STATE" and told the operator to start
// "the region front door, Edge x N". A machine running the authority and its database was handed the
// procedure for a machine that runs neither.
//
// An operator following it would look for Edges that are not there, and would never be told to bring up the
// database this region joins or to point it at the deployment's consensus store.
func TestThePrintedProcedureDescribesTheMachineItPrepared(t *testing.T) {
	stateBearing := capturedReport(t, machineShape{holds: regionShapeStateBearingJoin, edges: false})
	edgesOnly := capturedReport(t, machineShape{holds: regionShapeEdgesOnly, edges: true})

	// A machine that holds state is told what it joins, and what it must be pointed at.
	for _, want := range []string{"HOLDS STATE", "DSSE_ETCD_HOSTS", "the database", "the control plane pair"} {
		if !strings.Contains(stateBearing, want) {
			t.Errorf("a state-bearing region's control-plane machine is not told about %q", want)
		}
	}
	// ★ AND IT IS NOT TOLD TO START EDGES IT DOES NOT RUN.
	if strings.Contains(stateBearing, "Edge x N") {
		t.Error("a machine that runs no Edge is told to start Edges")
	}
	if strings.Contains(stateBearing, "HOLDS NO STATE") {
		t.Error("a machine that holds the deployment's state is told it holds none")
	}

	// The control, with the same walk: an Edges-only region still gets its own procedure.
	for _, want := range []string{"HOLDS NO STATE", "Edge x N", "SET DSSE_CONTROL_PLANE"} {
		if !strings.Contains(edgesOnly, want) {
			t.Errorf("an Edges-only region is not told about %q", want)
		}
	}
	if strings.Contains(edgesOnly, "DSSE_ETCD_HOSTS") {
		t.Error("a region that stands up no database is told to point at a consensus store")
	}
}

func capturedReport(t *testing.T, shape machineShape) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	reportRegion("/opt/dsse/region-b", "region-b", shape)
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("the report printed nothing, so this test measures nothing")
	}
	return buf.String()
}
