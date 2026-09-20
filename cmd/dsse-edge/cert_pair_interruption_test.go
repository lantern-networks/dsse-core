package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/certreload"
	"github.com/lantern-networks/dsse-core/durablefile"
)

func TestCertificatePairInterruptedReplacement(t *testing.T) {
	if dir := os.Getenv("DSSE_PAIR_INTERRUPT_DIR"); dir != "" {
		c, _ := os.ReadFile(filepath.Join(dir, "next.crt"))
		k, _ := os.ReadFile(filepath.Join(dir, "next.key"))
		stop, _ := strconv.Atoi(os.Getenv("DSSE_PAIR_INTERRUPT_AT"))
		calls := 0
		err := saveNamedCertPairWithReplace(filepath.Join(dir, "node.crt"), filepath.Join(dir, "keys", "node.key"), c, k, func(from, to string) error {
			if err := durablefile.Replace(from, to); err != nil {
				return err
			}
			calls++
			if calls == stop {
				os.Exit(77)
			} // abrupt termination: no deferred rollback
			return nil
		})
		t.Fatalf("child did not interrupt: %v", err)
	}
	for _, stop := range []int{1, 2} {
		t.Run(strconv.Itoa(stop), func(t *testing.T) {
			dir := t.TempDir()
			os.Mkdir(filepath.Join(dir, "keys"), 0700)
			oldC, oldK := rotationRecoveryPair(t, 1)
			newC, newK := rotationRecoveryPair(t, 2)
			cp, kp := filepath.Join(dir, "node.crt"), filepath.Join(dir, "keys", "node.key")
			for p, v := range map[string]string{cp: oldC, kp: oldK, filepath.Join(dir, "next.crt"): newC, filepath.Join(dir, "next.key"): newK} {
				if err := os.WriteFile(p, []byte(v), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCertificatePairInterruptedReplacement$")
			cmd.Env = append(os.Environ(), "DSSE_PAIR_INTERRUPT_DIR="+dir, "DSSE_PAIR_INTERRUPT_AT="+strconv.Itoa(stop))
			if err := cmd.Run(); err == nil {
				t.Fatal("child unexpectedly succeeded")
			} else if x, ok := err.(*exec.ExitError); !ok || x.ExitCode() != 77 {
				t.Fatalf("unexpected child exit: %v", err)
			}
			if stop == 1 {
				if _, err := tls.LoadX509KeyPair(cp, kp); err == nil {
					t.Fatal("fixture did not interrupt between replacements")
				}
			}
			// Actual main must recover before any admission check or listener uses
			// the interrupted material. A later known license error ends this child.
			seedCertPinStartup(t, dir)
			licensePath := filepath.Join(dir, "bad-license.json")
			os.WriteFile(licensePath, []byte("{"), 0600)
			module, _ := filepath.Abs("../..")
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-license-store", licensePath, "-tls-cert", cp, "-tls-key", kp}
			raw, _ := json.Marshal(args)
			argPath := filepath.Join(dir, "args.json")
			os.WriteFile(argPath, raw, 0600)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			startup := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			startup.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argPath)
			out, err := startup.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "certificate_pair_recovery result=restored") || !strings.Contains(string(out), "setup vendor license store:") {
				t.Fatalf("actual main did not recover before later startup gate: %v %s", err, out)
			}
			if _, err := certreload.NewReloadableCert(cp, kp); err != nil {
				t.Fatalf("restart did not recover: %v", err)
			}
			for p, v := range map[string]string{cp: oldC, kp: oldK} {
				got, _ := os.ReadFile(p)
				if string(got) != v {
					t.Fatal("uncommitted pair was not restored")
				}
			}
			if err := saveNamedCertPair(cp, kp, []byte(newC), []byte(newK)); err != nil {
				t.Fatal(err)
			}
			if _, err := certreload.NewReloadableCert(cp, kp); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(cp)
			if string(got) != newC {
				t.Fatal("successful retry was rolled back")
			}
		})
	}
}
