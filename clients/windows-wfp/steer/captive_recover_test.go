package main

import (
	"errors"
	"testing"
)

func TestRecoveryFailureCannotUnloadDriver(t *testing.T) {
	want := errors.New("guard readback failed")
	unloaded := false
	recovered, err := recoverBeforeDriverUnload(func() error { return want }, func() error { unloaded = true; return nil })
	if !errors.Is(err, want) || unloaded || recovered {
		t.Fatalf("err=%v unloaded=%t", err, unloaded)
	}
}

func TestVerifiedRecoveryPrecedesUnloadAndReportsFailure(t *testing.T) {
	cleared := false
	want := errors.New("driver stop refused")
	recovered, err := recoverBeforeDriverUnload(func() error { cleared = true; return nil }, func() error {
		if !cleared {
			t.Fatal("unloaded before verified recovery")
		}
		return want
	})
	if !errors.Is(err, want) || !recovered {
		t.Fatal(err)
	}
	if recovered, err := recoverBeforeDriverUnload(func() error { return nil }, nil); err != nil || !recovered {
		t.Fatal(err)
	}
}
