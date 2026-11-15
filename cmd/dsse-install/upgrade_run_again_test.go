package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A second run of -upgrade, and a first run that had to put files back. These operate on temporary deployments;
// every Docker and network dependency is a recorded in-process stub.
func TestUpgradeRunAgainAfterAFailedReplacementReplacesTheServices(t *testing.T) {
	dir := installedMachine(t, true)
	manifest := upgradeManifest(t, t.TempDir(), 18)
	first := &recordedUpgrade{failUp: true}
	var out, errOut bytes.Buffer
	input := upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}
	if code := runUpgrade(input, first.deps(""), &out, &errOut); code == 0 {
		t.Fatal("setup: injected Compose failure was ignored")
	}
	second := &recordedUpgrade{}
	out.Reset()
	errOut.Reset()
	code := runUpgrade(input, second.deps(""), &out, &errOut)
	if code == 0 && len(second.composed) == 0 {
		t.Fatalf("retry falsely succeeded without retrying services: %s", out.String())
	}
}

func TestUpgradeRunAgainAfterAFailedCheckChecksAgain(t *testing.T) {
	dir := oneMachineDeployment(t)
	manifest := upgradeManifest(t, t.TempDir(), 18)
	first := &recordedUpgrade{verifyFailures: 99}
	var out, errOut bytes.Buffer
	input := upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}
	if code := runUpgrade(input, first.deps(""), &out, &errOut); code == 0 {
		t.Fatal("setup: injected verification failure was ignored")
	}
	second := &recordedUpgrade{verifyFailures: 99}
	out.Reset()
	errOut.Reset()
	code := runUpgrade(input, second.deps(""), &out, &errOut)
	if code == 0 && second.verified == 0 {
		t.Fatalf("retry falsely succeeded without rechecking a failed deployment: %s", out.String())
	}
}

func TestUpgradeThatCannotFetchRemovesTheFileItAdded(t *testing.T) {
	dir := installedMachine(t, true)
	manifest := upgradeManifest(t, t.TempDir(), 18)
	rec := &recordedUpgrade{failPull: true}
	deps := rec.deps("")
	newFile := filepath.Join(dir, "start-new-helper.sh")
	deps.derived = func(dir string) error { return os.WriteFile(newFile, []byte("#!/bin/sh\nexit 0\n"), 0700) }
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}, deps, &out, &errOut); code == 0 {
		t.Fatal("setup: injected pull failure was ignored")
	}
	if _, err := os.Stat(newFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new derived file survives a claimed rollback: %v; %s", err, errOut.String())
	}
}

func TestUpgradeThatCannotFetchPutsAMountedFileBackThroughTheSameFile(t *testing.T) {
	dir := installedMachine(t, true)
	manifest := upgradeManifest(t, t.TempDir(), 18)
	path := filepath.Join(dir, "start-edge.sh")
	oldBody := []byte("#!/bin/sh\nexec old-release --old-option\n")
	newBody := []byte("#!/bin/sh\nexec new-release --new-option\n")
	if err := os.WriteFile(path, oldBody, 0700); err != nil {
		t.Fatal(err)
	}
	// A single-file bind mount retains this inode when the host path is atomically replaced.
	mounted, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer mounted.Close()
	rec := &recordedUpgrade{failPull: true}
	deps := rec.deps("")
	// This is the same in-place write used by writeLaunchScripts.
	deps.derived = func(dir string) error { return os.WriteFile(path, newBody, 0700) }
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}, deps, &out, &errOut); code == 0 {
		t.Fatal("setup: injected pull failure was ignored")
	}
	onHost, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(onHost, oldBody) {
		t.Fatalf("host was not restored: %s %v", onHost, err)
	}
	onMount, err := io.ReadAll(mounted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onMount, oldBody) {
		t.Fatalf("host was restored, but the running container's file inode still holds %q; %s", onMount, errOut.String())
	}
}

func TestUpgradeThatCannotFetchPutsTheLaunchScriptBackThroughTheSameFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	var setupOut bytes.Buffer
	if err := captureProcessStdout(&setupOut, func() error {
		installFromPlan(t, "../../docs/plans/single-region.json", dir)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "start-edge.sh")
	oldBody, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldBody = append(oldBody, []byte("\n# synthetic previous release marker\n")...)
	if err := os.WriteFile(path, oldBody, 0700); err != nil {
		t.Fatal(err)
	}
	mounted, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer mounted.Close()
	rec := &recordedUpgrade{failPull: true}
	deps := rec.deps("")
	deps.derived = upgradeDerivedFiles
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, deps, &out, &errOut); code == 0 {
		t.Fatal("setup: injected pull failure was ignored")
	}
	onHost, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(onHost, oldBody) {
		t.Fatal("host script was not restored")
	}
	onMount, err := io.ReadAll(mounted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onMount, oldBody) {
		t.Fatalf("real upgradeDerivedFiles + failed pull leaves the mounted script on the new content (%d bytes) while the host is restored (%d bytes); %s", len(onMount), len(onHost), errOut.String())
	}
}

func TestUpgradeThatCannotFetchPutsTheDoorConfigurationBackThroughTheSameFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	var setupOut bytes.Buffer
	if err := captureProcessStdout(&setupOut, func() error {
		installFromPlan(t, "../../docs/plans/single-region.json", dir)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "haproxy-edge.cfg")
	oldBody, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(oldBody, []byte("bind :443")) {
		t.Fatal("fixture has no 443 bind")
	}
	// A synthetic old rendering with a visible behavioral difference, not just a comment.
	oldBody = bytes.Replace(oldBody, []byte("bind :443"), []byte("bind :444"), 1)
	if err := os.WriteFile(path, oldBody, 0644); err != nil {
		t.Fatal(err)
	}
	mounted, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer mounted.Close()
	rec := &recordedUpgrade{failPull: true}
	deps := rec.deps("")
	deps.derived = upgradeDerivedFiles
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: upgradeManifest(t, t.TempDir(), 18), Timeout: time.Minute}, deps, &out, &errOut); code == 0 {
		t.Fatal("setup: injected pull failure was ignored")
	}
	onHost, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(onHost, oldBody) {
		t.Fatal("host HAProxy configuration was not restored")
	}
	onMount, err := io.ReadAll(mounted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onMount, oldBody) {
		t.Fatalf("failed pull: host HAProxy config was restored to bind :444 but retained inode contains bind :443=%v; this is the inode an in-container graceful reload reads; %s", bytes.Contains(onMount, []byte("bind :443")), errOut.String())
	}
}

// Compose returned and one service was left created, not started. The step asks Compose again instead of
// waiting to the end for a service nothing is going to start.
func TestUpgradeAsksComposeAgainForAServiceItLeftUnstarted(t *testing.T) {
	dir := installedMachine(t, true)
	manifest := upgradeManifest(t, t.TempDir(), 18)
	rec := &recordedUpgrade{}
	deps := rec.deps("")
	ups := func() int {
		n := 0
		for _, c := range rec.composed {
			if strings.Contains(c, " up -d") {
				n++
			}
		}
		return n
	}
	deps.settled = func(context.Context, string, string) error {
		if ups() < 2 {
			return errors.New("dsse-control-plane-a (created)")
		}
		return nil
	}
	var out, errOut bytes.Buffer
	if code := runUpgrade(upgradeInput{Dir: dir, Manifest: manifest, Timeout: time.Minute}, deps, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if ups() != 2 {
		t.Fatalf("compose was asked to bring the services up %d times, want 2: %v", ups(), rec.composed)
	}
}
