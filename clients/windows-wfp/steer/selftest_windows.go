//go:build windows

// selftest_windows.go — `--mode selftest`: a read-only deployment validator. Confirms the critical
// steer-all prerequisites are healthy (WFP driver present, (T) mTLS transport + device identity accepted,
// signed-exclusion policy verifiable, AppID self-resolution) and reports PASS/FAIL per check. Exit 0 iff
// all pass — usable as a post-install / service health gate. Makes no changes.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// stateDir is where the adopted trust state lives, so the self-test can verify against the same key set the
// agent does rather than against the provisioned pin alone.
func runSelfTest(transport transportConfig, pinHex, policyURL, stateDir string) int {
	type check struct {
		name, detail string
		ok           bool
	}
	var results []check
	add := func(name string, ok bool, detail string) {
		results = append(results, check{name: name, ok: ok, detail: detail})
	}

	// 1. WFP callout driver present (the kernel connect-redirect backend).
	if h, err := openWFPDevice(); err == nil {
		syscall.CloseHandle(h)
		add("wfp-driver", true, "control device open OK")
	} else {
		add("wfp-driver", false, "driver not present/loaded: "+err.Error())
	}

	// 2 + 3. (T) transport mTLS reachable (device identity accepted) and signed exclusions verify.
	if transport.enabled {
		base := strings.TrimSpace(policyURL)
		if base == "" {
			base = "https://" + transport.host
		}
		base = strings.TrimRight(base, "/")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		pk, err := agentpolicy.FetchPubKey(ctx, transportHTTPClient(transport), base)
		cancel()
		if err == nil {
			add("(T)-transport-mtls", true, "edge reachable, device cert accepted (key "+pk.KeyID+")")
		} else {
			add("(T)-transport-mtls", false, err.Error())
		}
		if strings.TrimSpace(pinHex) != "" {
			// The same accepted-key set the running agent uses — the pin plus anything adopted — not the pin
			// alone. A self-test is what someone reaches for when they suspect a problem, so it verifying more
			// narrowly than the agent does is the worst direction to be wrong in: mid-rotation, with the Edge
			// signing under a key the device adopted but does not pin, this reported a FAILURE on a device that
			// was applying that exact policy correctly.
			keys := policyVerificationKeys(pinHex, stateDir)
			ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
			p, err := agentpolicy.FetchVerifiedExclusionsWithKeys(ctx2, transportHTTPClient(transport), base, keys)
			cancel2()
			if err == nil {
				add("signed-exclusions", true, fmt.Sprintf("verified against %d accepted key(s), %d server exclusion(s)", len(keys), len(p.ExcludedAppSigningIDs)))
			} else {
				add("signed-exclusions", false, fmt.Sprintf("%v (tried %d accepted key(s))", err, len(keys)))
			}
		}
	} else {
		add("(T)-transport-mtls", false, "transport not configured (--edge-transport-url)")
	}

	// 4. AppID bypass self-resolution (the steer-all safety primitive needs PID->image to work).
	if p, ok := processImagePath(uint32(os.Getpid())); ok {
		add("appid-self-resolve", true, p)
	} else {
		add("appid-self-resolve", false, "could not resolve own image path")
	}

	allOK := true
	for _, r := range results {
		mark := "PASS"
		if !r.ok {
			mark = "FAIL"
			allOK = false
		}
		fmt.Printf("[%s] %-20s %s\n", mark, r.name, r.detail)
	}
	if allOK {
		fmt.Println("selftest: ALL PASS")
		return 0
	}
	fmt.Println("selftest: FAILURES present")
	return 1
}
