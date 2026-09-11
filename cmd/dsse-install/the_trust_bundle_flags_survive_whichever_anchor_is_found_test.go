package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ TWO FLAGS WERE LEFT IN A BRANCH NOTHING REACHES ANY MORE (2026-09-07, measured on a freshly generated
// three-region deployment — every Edge was running with -trust-bundle-ca and nothing else).
//
// -trust-bundle-serial and -transport-trust-store used to sit inside the branch that anchors on the signing
// intermediate. A branch anchoring on the self-signed ROOT was added in front of it, correctly and for an
// unrelated reason, and became the branch every generated deployment takes. The two lines stayed behind.
//
// Nothing failed. The bundle was served, devices adopted it, every screen was green. What had gone was the
// ability to CHANGE the set: an operator adding a certificate through the Console was told "the trust set on
// this node is fixed at startup", which reads as a deliberate posture and was a branch that lost two lines.
// The published serial sat at 0, so nothing could ever advance past it either.
//
// The test EXECUTES the composed shell rather than reading it. A text assertion passes again the moment the
// lines are moved into a third branch, which is the whole shape of this defect.
func TestTheTrustBundleFlagsSurviveWhicheverAnchorIsFound(t *testing.T) {
	dir := t.TempDir()
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("writeLaunchScripts: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatalf("read start-edge.sh: %v", err)
	}
	fragment, err := trustBundleFragment(string(raw))
	if err != nil {
		t.Fatalf("%v", err)
	}

	for _, anchor := range []string{"deployment-anchor.pem", "transport-ca.crt"} {
		t.Run(anchor, func(t *testing.T) {
			here := t.TempDir()
			if err := os.WriteFile(filepath.Join(here, anchor), []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
				t.Fatalf("write %s: %v", anchor, err)
			}
			script := "set -u\nhere=" + here + "\n" + fragment + "\nprintf '%s' \"$TRUST_BUNDLE\"\n"
			out, err := exec.Command("sh", "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("running the composed block: %v\n%s", err, out)
			}
			composed := string(out)
			for _, want := range []string{
				"-trust-bundle-ca=" + filepath.Join(here, anchor),
				"-trust-bundle-serial=",
				"-transport-trust-store=",
			} {
				if !strings.Contains(composed, want) {
					t.Errorf("an Edge that found %s starts without %s\n  composed: %s\n"+
						"  without the store the set is fixed at boot and no certificate can be added or "+
						"withdrawn; at serial 0 no bundle can advance past it",
						anchor, want, composed)
				}
			}
		})
	}

	t.Run("and a deployment with neither still says so", func(t *testing.T) {
		here := t.TempDir()
		script := "set -u\nhere=" + here + "\n" + fragment + "\nprintf '%s' \"$TRUST_BUNDLE\"\n"
		out, err := exec.Command("sh", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("running the composed block: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "-trust-bundle-serial") {
			t.Errorf("a deployment with no anchor at all must serve no bundle rather than an empty one: %s", out)
		}
	})
}

// trustBundleFragment cuts the composed block out of the generated launcher: from the line that opens it to
// the end of the guard that appends the serial and the store.
func trustBundleFragment(script string) (string, error) {
	const open = "TRUST_BUNDLE=\"\"\n"
	start := strings.Index(script, open)
	if start < 0 {
		return "", errNoFragment("the launcher no longer opens with TRUST_BUNDLE=\"\"")
	}
	const guard = "if [ -n \"$TRUST_BUNDLE\" ]; then"
	guardAt := strings.Index(script[start:], guard)
	if guardAt < 0 {
		return "", errNoFragment("the launcher no longer guards the serial and the store on the composed " +
			"bundle — which is how they ended up inside one anchor's branch")
	}
	end := strings.Index(script[start+guardAt:], "\nfi\n")
	if end < 0 {
		return "", errNoFragment("the guard around the serial and the store is not closed")
	}
	return script[start : start+guardAt+end+len("\nfi\n")], nil
}

type errNoFragment string

func (e errNoFragment) Error() string { return string(e) }
