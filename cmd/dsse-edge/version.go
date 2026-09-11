package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

// Build identity, stamped at link time. Until 2026-07-27 the Edge could not say which build it was: a running
// binary carried no version and no commit, so answering "what is deployed?" meant guessing from file dates. This
// session's outage was bisected by rebuilding candidate commits one at a time — work that a stamped binary makes
// unnecessary.
//
// Set with:
//
//	go build -ldflags "-X main.buildVersion=$(cat VERSION) -X main.buildCommit=$(git rev-parse --short HEAD) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// The defaults below are what an unstamped (plain `go build`) binary reports, and they say so — an unstamped
// build must be recognisable as unstamped rather than silently claiming a version it does not have.
var (
	buildVersion = "0.0.0-dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// buildDirty is set to "true" by the release build when the working tree had uncommitted changes. A "dirty"
// artifact is not reproducible from any commit, which is the whole point of stamping, so it is reported loudly.
var buildDirty = "unknown"

// versionString is the one-line build identity used by -version, the startup log and the admin surface.
func versionString() string {
	s := fmt.Sprintf("dsse-edge %s (commit %s, built %s, %s/%s, %s)",
		buildVersion, buildCommit, buildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
	if buildDirty == "true" {
		s += " [DIRTY WORKING TREE — not reproducible from a commit]"
	}
	return s
}

// handleVersionFlag serves -version/--version before flag.Parse, so asking a binary what it is never depends on
// the rest of the (large) flag set parsing cleanly. Returns true when it handled the invocation.
func handleVersionFlag() bool {
	for _, a := range os.Args[1:] {
		switch strings.TrimLeft(a, "-") {
		case "version", "V":
			fmt.Println(versionString())
			if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				fmt.Println("module:", bi.Main.Path, bi.Main.Version)
			}
			return true
		}
	}
	return false
}
