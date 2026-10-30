package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUninstallFailureAndIdempotentRetry(t *testing.T) {
	names := []string{"stop", "recover", "anchors", "profile", "verifier", "driver", "rollbackStore"}
	for _, failAt := range names {
		for _, afterMutation := range []bool{false, true} {
			t.Run(failAt+map[bool]string{false: "/before", true: "/after"}[afterMutation], func(t *testing.T) {
				var calls []string
				removed := map[string]bool{}
				failing := true
				step := func(name string) func() error {
					return func() error {
						calls = append(calls, name)
						if failing && name == failAt && !afterMutation {
							return errors.New("injected " + name)
						}
						removed[name] = true // Repeat of an already completed mutation is safe.
						if failing && name == failAt {
							return errors.New("injected " + name)
						}
						return nil
					}
				}
				s := uninstallSteps{step("stop"), step("recover"), step("anchors"), step("profile"), step("verifier"), step("driver"), step("rollbackStore")}
				if err := uninstallMachine(s); err == nil || !strings.Contains(err.Error(), "injected "+failAt) {
					t.Fatalf("failure lost: %v", err)
				}
				last := map[string]string{"stop": "stop", "recover": "recover", "anchors": "verifier", "profile": "verifier", "verifier": "verifier", "driver": "driver", "rollbackStore": "rollbackStore"}[failAt]
				var want []string
				for _, name := range names {
					want = append(want, name)
					if name == last {
						break
					}
				}
				if !reflect.DeepEqual(calls, want) {
					t.Fatalf("calls %v, want %v", calls, want)
				}
				if failAt != "rollbackStore" && removed["rollbackStore"] {
					t.Fatal("discarded repair packages on failure")
				}
				failing = false
				calls = nil
				if err := uninstallMachine(s); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(calls, names) || len(removed) != len(names) {
					t.Fatalf("retry incomplete: %v %v", calls, removed)
				}
				if err := uninstallMachine(s); err != nil {
					t.Fatal("repeat successful removal:", err)
				}
			})
		}
	}
}

func TestCleanupAggregatesIndependentFailures(t *testing.T) {
	err := uninstallMachine(uninstallSteps{
		stop: func() error { return nil }, recover: func() error { return nil },
		anchors:       func() error { return errors.New("store denied") },
		profile:       func() error { return errors.New("profile locked") },
		verifier:      func() error { return errors.New("verifier locked") },
		driver:        func() error { t.Fatal("driver removal after cleanup failure"); return nil },
		rollbackStore: func() error { t.Fatal("rollback store pruned"); return nil },
	})
	for _, want := range []string{"store denied", "profile locked", "verifier locked"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("lost %q: %v", want, err)
		}
	}
}

func TestRootRemovalFailureReadbackAndRetry(t *testing.T) {
	ours := []parsedRoot{root("a", "same name"), root("b", "same name")}
	state := []parsedRoot{ours[0], ours[1], root("foreign", "same name")}
	list := func() ([]parsedRoot, error) { return append([]parsedRoot(nil), state...), nil }
	fail := true
	remove := func(r parsedRoot) error {
		if fail && r.SHA256 == "a" {
			return errors.New("denied a")
		}
		for i, v := range state {
			if v.SHA256 == r.SHA256 {
				state = append(state[:i], state[i+1:]...)
				break
			}
		}
		return nil
	}
	err := removeRootsVerified(ours, list, remove)
	if err == nil || !strings.Contains(err.Error(), "denied a") || !strings.Contains(err.Error(), "still trusted") {
		t.Fatal(err)
	}
	if len(state) != 2 {
		t.Fatal("independent deletion not attempted", state)
	}
	fail = false
	for i := 0; i < 2; i++ {
		if err := removeRootsVerified(ours, list, remove); err != nil {
			t.Fatal(err)
		}
	}
	if len(state) != 1 || state[0].SHA256 != "foreign" {
		t.Fatal("foreign root altered", state)
	}
}

func TestRootRemovalDoesNotAcceptFalseSuccessOrUnreadableStore(t *testing.T) {
	ours := []parsedRoot{root("a", "ours")}
	if err := removeRootsVerified(ours, func() ([]parsedRoot, error) { return ours, nil }, func(parsedRoot) error { return nil }); err == nil {
		t.Fatal("no-op deletion accepted")
	}
	for _, failingRead := range []int{1, 2} {
		reads := 0
		err := removeRootsVerified(ours, func() ([]parsedRoot, error) {
			reads++
			if reads == failingRead {
				return nil, errors.New("store unreadable")
			}
			return nil, nil
		}, func(parsedRoot) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "store unreadable") {
			t.Fatal(err)
		}
	}
}

func TestRemovalDistinguishesMissingFromUnreadableArtifact(t *testing.T) {
	dir := t.TempDir()
	if roots, err := readOurRoots(filepath.Join(dir, "absent")); err != nil || len(roots) != 0 {
		t.Fatalf("%v %v", roots, err)
	}
	if _, err := readOurRoots(dir); err == nil {
		t.Fatal("directory accepted as absent artifact")
	}
	p := filepath.Join(dir, "malformed.pem")
	if err := os.WriteFile(p, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOurRoots(p); err == nil {
		t.Fatal("malformed artifact accepted")
	}
}

func TestInstallRollbackAndReplacementShareRecoveryGate(t *testing.T) {
	for _, failure := range []string{"stop", "recover", "driver", "none"} {
		t.Run(failure, func(t *testing.T) {
			var calls []string
			step := func(name string) func() error {
				return func() error {
					calls = append(calls, name)
					if failure == name {
						return errors.New(name)
					}
					return nil
				}
			}
			err := rollbackFreshMachine(step("stop"), step("recover"), step("driver"))
			if (err != nil) != (failure != "none") {
				t.Fatal(err)
			}
			want := []string{"stop"}
			if failure != "stop" {
				want = append(want, "recover")
				if failure != "recover" {
					want = append(want, "driver")
				}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("%v want %v", calls, want)
			}
			calls = nil
			err = recoverInstallerNetwork(step("stop"), step("recover"))
			if (err != nil) != (failure == "stop" || failure == "recover") {
				t.Fatal(err)
			}
			if strings.Contains(strings.Join(calls, ","), "driver") {
				t.Fatal("recovery unloads driver")
			}
		})
	}
}
