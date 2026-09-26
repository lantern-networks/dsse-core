package main

import (
	"bytes"
	"context"
	"github.com/lantern-networks/dsse-core/dlp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLibraryProductionStartup(t *testing.T) {
	if path := os.Getenv("DSSE_LIBRARY_STARTUP_TEST_PATH"); path != "" {
		cfg := serverConfig{}
		kind := os.Getenv("DSSE_LIBRARY_STARTUP_TEST_KIND")
		if kind == "classifiers" {
			cfg.DLPClassifierStorePath = path
		} else {
			cfg.DLPFingerprintStorePath = path
		}
		rt := buildDLPRuntime(cfg)
		opts := dlp.Options{Classifiers: rt.classifiers.ClassifierSetForTenant("own"), Fingerprints: rt.fingerprints.FingerprintSetForTenant("own")}
		if len(dlp.DetectWithOptions([]byte("EMPLOYEE123"), "text/plain", opts)) != 1 {
			os.Exit(9)
		}
		return
	}
	for _, kind := range []string{"classifiers", "fingerprints"} {
		t.Run(kind, func(t *testing.T) {
			p := &allowlistSaveFixture{}
			if kind == "classifiers" {
				s := newDLPClassifierRuntimeStore()
				s.SetPersister(p)
				if err := s.SetSpecsDurable("own", []dlp.ClassifierSpec{{Name: "employee_id", Kind: "keyword", Keywords: []string{"EMPLOYEE123"}}}); err != nil {
					t.Fatal(err)
				}
			} else {
				s := newDLPFingerprintRuntimeStore("retained-source")
				s.SetPersister(p)
				if _, err := s.SetDatasetDurable("own", "employees", []string{"EMPLOYEE123"}); err != nil {
					t.Fatal(err)
				}
			}
			for _, valid := range []bool{true, false} {
				data := p.data
				if !valid {
					data = []byte(`{"invalid":"PRIVATE_SOURCE_MARKER"}`)
				}
				path := filepath.Join(t.TempDir(), "library.json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLibraryProductionStartup$")
				cmd.Env = append(os.Environ(), "DSSE_LIBRARY_STARTUP_TEST_PATH="+path, "DSSE_LIBRARY_STARTUP_TEST_KIND="+kind)
				out, err := cmd.CombinedOutput()
				cancel()
				if valid && err != nil {
					t.Fatalf("valid startup failed: %v %s", err, out)
				}
				if !valid {
					e, ok := err.(*exec.ExitError)
					if !ok || e.ExitCode() != 1 || !strings.Contains(string(out), "invalid or unavailable saved configuration") {
						t.Fatalf("invalid snapshot not rejected: %v %s", err, out)
					}
				}
				if strings.Contains(string(out), "PRIVATE_SOURCE_MARKER") {
					t.Fatal("source bytes leaked")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, data) {
					t.Fatal("startup rewrote original")
				}
			}
		})
	}
}
