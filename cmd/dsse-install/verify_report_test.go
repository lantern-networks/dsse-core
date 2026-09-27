package main

import (
	"strings"
	"testing"
)

func TestVerificationReportDoesNotCountUnverifiedEnrolmentAsPassed(t *testing.T) {
	var err error
	output := captureStdout(t, func() {
		err = reportVerificationResults("synthetic", []verifyResult{
			{name: "control plane answers", ok: true},
			{name: "enrolment", skipped: true, note: "no customer organization"},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "1 checks passed; 1 not checked") ||
		strings.Contains(output, "2 checks passed") || strings.Contains(output, "a device can enrol exactly once") {
		t.Fatalf("report claimed more than was checked: %s", output)
	}
}

func TestVerificationReportKeepsFailuresAndSkipsDistinct(t *testing.T) {
	var err error
	output := captureStdout(t, func() {
		err = reportVerificationResults("synthetic", []verifyResult{
			{name: "control plane answers", ok: true},
			{name: "Edge answers", note: "unreachable"},
			{name: "enrolment", skipped: true},
		})
	})
	if err == nil || !strings.Contains(output, "1 of 3 checks failed") || strings.Contains(output, "checks passed") {
		t.Fatalf("failure was hidden: %v\n%s", err, output)
	}
}
