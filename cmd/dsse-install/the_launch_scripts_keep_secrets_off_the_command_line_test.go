package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ EVERY SECRET WAS ON THE COMMAND LINE (2026-10-29, measured on a three-region lab).
//
// The launch scripts passed the admin token, the connector and workload secrets, the audit-ingest token, the
// ClickHouse password and the database DSN (with its password) as -flag=value. Any local user on the host reads
// those through ps or /proc/<pid>/cmdline: seven on a control plane, six on an Edge. Only the process owner and
// root read a process's environment, so the scripts now export the values and pass -secret-env with the variable
// NAMES. A binary that predates -secret-env still receives the old arguments, so machines upgraded one at a time
// keep starting.
//
// This runs the rendered scripts, against a stand-in binary, in both modes.
func TestTheLaunchScriptsKeepSecretsOffTheCommandLine(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(dir, "stub.sh")
	writeExecutable(t, stub, `#!/bin/sh
if [ "$1" = "-help" ]; then
  [ "$STUB_MODE" = new ] && echo "  -secret-env string"
  echo "  -admin-token string"
  exit 2
fi
printf '%s\n' "$@" > "$STUB_OUT.args"
env > "$STUB_OUT.env"
`)
	env := strings.Join([]string{
		"DSSE_EDGE_BINARY=" + stub,
		"ADMIN_TOKEN=SENTINEL-ADMIN", "CONNECTOR_SECRET=SENTINEL-CONNECTOR", "WORKLOAD_SECRET=SENTINEL-WORKLOAD",
		"AUDIT_INGEST_TOKEN=SENTINEL-AUDIT", "CLICKHOUSE_PASSWORD=SENTINEL-CLICKHOUSE",
		"DSSE_POSTGRES_DSN=postgres://dsse:SENTINEL-PGPASS@db/dsse", "EDGE_CP_TOKEN=SENTINEL-FLEET",
		"EDGE_HOST=lab.test", "DSSE_EDGE_LISTEN=:443", "DSSE_EDGE_ADMIN_LISTEN=:8443",
		"DSSE_CONTROL_PLANE=https://cp", "DSSE_CONTROL_PLANE_DATA=https://cpdata", "DSSE_CP_LISTEN=:9443",
		"DSSE_CP_ADMIN_LISTEN=:9444", "DSSE_MIGRATION_DIR=/m", "DSSE_CLICKHOUSE_ENDPOINT=http://ch:8123",
		"DSSE_CONNECTOR_EDGE_URL=https://edge", "DSSE_AUTHORITY_ORIGIN=https://auth", "DSSE_NODE_NAME=cp-a",
		"DSSE_ARCHIVE_ENDPOINT=", "DSSE_ARCHIVE_BUCKET=", "DSSE_ARCHIVE_AUTH_MODE=",
		"DSSE_CP_STATE_DIR=" + filepath.Join(dir, "cp-state"),
		"DSSE_ARCHIVE_WEBHOOK_URL=https://hook", "DSSE_ARCHIVE_WEBHOOK_SIGNING_SECRET=SENTINEL-HOOK",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	// After the bootstrap the Edge also carries its fleet credential.
	if err := os.WriteFile(filepath.Join(dir, "runtime", "admin-bootstrapped"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		script  string
		secrets int // how many values the pre-change script put on the command line
		names   []string
		exports []string // values the program must find in its environment
	}{
		{"start-control-plane.sh", 7, []string{"admin-token=ADMIN_TOKEN", "audit-ingest-receiver-token=AUDIT_INGEST_TOKEN",
			"hot-store-clickhouse-password=CLICKHOUSE_PASSWORD", "postgres-dsn=DSSE_POSTGRES_DSN"},
			[]string{"SENTINEL-ADMIN", "SENTINEL-CLICKHOUSE", "SENTINEL-PGPASS"}},
		{"start-edge.sh", 6, []string{"admin-token=ADMIN_TOKEN", "step-up-binding-secret=STEPUP_BINDING_SECRET",
			"steer-exclusion-source-token=EDGE_CP_TOKEN"},
			[]string{"SENTINEL-ADMIN", "SENTINEL-FLEET", "STEPUP_BINDING_SECRET=SENTINEL-CONNECTOR"}},
		{"start-archive-alert-publisher.sh", 1, []string{"postgres-dsn=DSSE_POSTGRES_DSN"},
			[]string{"SENTINEL-PGPASS"}},
	}
	for _, tc := range cases {
		for _, mode := range []string{"new", "old"} {
			out := filepath.Join(dir, tc.script+"-"+mode)
			cmd := exec.Command("sh", filepath.Join(dir, tc.script))
			cmd.Env = append(os.Environ(), "STUB_MODE="+mode, "STUB_OUT="+out)
			if tc.script == "start-archive-alert-publisher.sh" {
				// This one reads its inputs from the service environment, not deployment.env.
				cmd.Env = append(cmd.Env, strings.Split(strings.TrimSpace(env), "\n")...)
			}
			if raw, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s (%s binary): %v\n%s", tc.script, mode, err, raw)
			}
			args, err := os.ReadFile(out + ".args")
			if err != nil {
				t.Fatal(err)
			}
			environ, err := os.ReadFile(out + ".env")
			if err != nil {
				t.Fatal(err)
			}
			onCommandLine := strings.Count(string(args), "SENTINEL")
			if mode == "new" {
				if onCommandLine != 0 {
					t.Errorf("%s puts %d secret value(s) on the command line, where every local user reads them:\n%s",
						tc.script, onCommandLine, args)
				}
				for _, name := range tc.names {
					if !strings.Contains(string(args), name) {
						t.Errorf("%s does not hand the program %s through -secret-env", tc.script, name)
					}
				}
				for _, value := range tc.exports {
					if !strings.Contains(string(environ), value) {
						t.Errorf("%s does not export the value the program is told to read (%s)", tc.script, value)
					}
				}
				continue
			}
			// A binary without -secret-env must still start exactly as before.
			if onCommandLine != tc.secrets {
				t.Errorf("%s with an older binary passed %d secret argument(s), want the previous %d",
					tc.script, onCommandLine, tc.secrets)
			}
			if strings.Contains(string(args), "-secret-env") {
				t.Errorf("%s handed -secret-env to a binary that does not know it, which would refuse to start", tc.script)
			}
		}
	}
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}
