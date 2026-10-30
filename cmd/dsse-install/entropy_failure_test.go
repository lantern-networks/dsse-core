package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type unavailableEntropyReader struct{}

func (unavailableEntropyReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

// Run the failure in a subprocess: the pre-fix implementation's crypto/rand.Read
// aborts the process on Reader failure with the current toolchain, so the
// regression must not take down the whole test run.
func TestInstallerEntropyFailureDoesNotCreateMaterial(t *testing.T) {
	if mode := os.Getenv("DSSE_INSTALL_ENTROPY_FAILURE_CHILD"); mode != "" {
		switch mode {
		case "environment":
			dir := t.TempDir()
			rand.Reader = unavailableEntropyReader{}
			err := writeEnvironment(dir, []string{"example.test"}, nil)
			if err == nil || !strings.Contains(err.Error(), "random") {
				t.Fatalf("environment writer accepted unavailable entropy: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "deployment.env")); !os.IsNotExist(statErr) {
				t.Fatalf("environment file appeared after entropy failure: %v", statErr)
			}
		case "serial":
			key, err := newKey()
			if err != nil {
				t.Fatal(err)
			}
			rand.Reader = unavailableEntropyReader{}
			_, err = selfSigned(pkix.Name{CommonName: "test root"}, key, time.Now(), time.Now().Add(time.Hour))
			if err == nil || !strings.Contains(err.Error(), "serial") {
				t.Fatalf("certificate issuer accepted unavailable entropy: %v", err)
			}
		default:
			t.Fatalf("unknown child mode %q", mode)
		}
		fmt.Println("entropy failure was rejected")
		return
	}

	for _, mode := range []string{"environment", "serial"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestInstallerEntropyFailureDoesNotCreateMaterial$")
			cmd.Env = append(os.Environ(), "DSSE_INSTALL_ENTROPY_FAILURE_CHILD="+mode)
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "entropy failure was rejected") {
				t.Fatalf("entropy failure did not fail closed: %v; child output: %s", err, output)
			}
		})
	}
}
