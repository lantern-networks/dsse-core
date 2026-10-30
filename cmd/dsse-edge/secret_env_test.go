package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secretEnvTestFlags() (*flag.FlagSet, *string, *string, *string) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	admin := fs.String("admin-token", "", "")
	connector := fs.String("connector-secret", "default", "")
	listen := fs.String("listen", "", "")
	return fs, admin, connector, listen
}

func TestSecretEnvSetsFlagsAndRemovesVariables(t *testing.T) {
	fs, admin, connector, _ := secretEnvTestFlags()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ADMIN_TOKEN": "a-value", "CONNECTOR_SECRET": ""}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	var removed []string
	unset := func(k string) error { removed = append(removed, k); delete(env, k); return nil }
	if err := applySecretEnv(fs, "admin-token=ADMIN_TOKEN, connector-secret=CONNECTOR_SECRET", lookup, unset); err != nil {
		t.Fatal(err)
	}
	if *admin != "a-value" || *connector != "" {
		t.Fatalf("flags not set from the environment: admin=%q connector=%q", *admin, *connector)
	}
	if strings.Join(removed, ",") != "ADMIN_TOKEN,CONNECTOR_SECRET" || len(env) != 0 {
		t.Fatalf("used variables must be removed from the process environment: %v", removed)
	}
}

func TestSecretEnvRefusals(t *testing.T) {
	for _, tc := range []struct {
		args       []string
		spec, want string
	}{
		{nil, "listen=LISTEN", "not a secret flag"},
		{nil, "unknown-secret=X", "not a secret flag"},
		{nil, "admin-token=lower", "not an environment variable name"},
		{nil, "admin-token", "not flag=ENV"},
		{nil, "admin-token=ADMIN_TOKEN,admin-token=ADMIN_TOKEN", "twice"},
		{nil, "admin-token=MISSING", "not set"},
		{[]string{"-admin-token=on-the-command-line"}, "admin-token=ADMIN_TOKEN", "both on the command line"},
	} {
		fs, _, _, _ := secretEnvTestFlags()
		if err := fs.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		lookup := func(k string) (string, bool) {
			if k == "ADMIN_TOKEN" {
				return "the-secret-value", true
			}
			return "", false
		}
		err := applySecretEnv(fs, tc.spec, lookup, func(string) error { return nil })
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("spec %q: want error containing %q, got %v", tc.spec, tc.want, err)
		}
		if strings.Contains(err.Error(), "the-secret-value") || strings.Contains(err.Error(), "on-the-command-line") {
			t.Fatalf("an error must never carry a secret value: %v", err)
		}
	}
}

// Every secret flag must be one main() really defines, or -secret-env would
// refuse it at startup.
func TestSecretEnvFlagsAreDefinedByMain(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		source.Write(raw)
	}
	for name := range secretEnvFlags {
		if !strings.Contains(source.String(), "flag.String(\""+name+"\"") {
			t.Fatalf("-%s is listed as a secret flag but this program does not define it", name)
		}
	}
}
