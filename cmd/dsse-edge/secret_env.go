package main

import (
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// secretEnvFlags are the flags whose values are secrets. A command line is
// readable by every local user through /proc/<pid>/cmdline and ps, so the
// launch scripts pass these through the environment instead, which only the
// process owner and root can read. -secret-env names the variable for each
// flag; the value itself never appears on the command line.
var secretEnvFlags = map[string]bool{
	"admin-token":                   true,
	"audit-ingest-receiver-token":   true,
	"audit-ingest-token":            true,
	"connector-secret":              true,
	"hot-store-clickhouse-password": true,
	"postgres-dsn":                  true,
	"steer-exclusion-source-token":  true,
	"step-up-binding-secret":        true,
	"workload-attestation-secret":   true,
}

// secretEnvFlag declares -secret-env. The launch scripts pass it only when
// -help lists it, so an older binary keeps receiving the old arguments.
func secretEnvFlag() *string {
	return flag.String("secret-env", "", "comma-separated flag=ENV pairs: read these secret flags from "+
		"environment variables instead of the command line, which every local user can read; the variables "+
		"are removed from this process after reading. Example: admin-token=ADMIN_TOKEN,postgres-dsn=DSSE_POSTGRES_DSN")
}

var secretEnvName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// applySecretEnv sets each listed flag from its environment variable, then
// removes those variables from this process so a child cannot inherit them.
// spec is "flag=ENV,flag=ENV". Errors name flags and variables, never values.
func applySecretEnv(fs *flag.FlagSet, spec string, lookup func(string) (string, bool), unset func(string) error) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	onCommandLine := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { onCommandLine[f.Name] = true })
	assigned := map[string]bool{}
	used := map[string]bool{}
	for _, pair := range strings.Split(spec, ",") {
		name, env, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || name == "" || env == "" {
			return fmt.Errorf("-secret-env entry %q is not flag=ENV", pair)
		}
		if !secretEnvFlags[name] || fs.Lookup(name) == nil {
			return fmt.Errorf("-secret-env: %q is not a secret flag of this program", name)
		}
		if !secretEnvName.MatchString(env) {
			return fmt.Errorf("-secret-env: %q is not an environment variable name", env)
		}
		if assigned[name] {
			return fmt.Errorf("-secret-env names -%s twice", name)
		}
		if onCommandLine[name] {
			return fmt.Errorf("-%s is given both on the command line and through -secret-env; "+
				"remove it from the command line, where every local user can read it", name)
		}
		value, present := lookup(env)
		if !present {
			return fmt.Errorf("-secret-env: -%s reads %s, which is not set", name, env)
		}
		if err := fs.Set(name, value); err != nil {
			return fmt.Errorf("-secret-env: -%s from %s was refused: %w", name, env, err)
		}
		assigned[name] = true
		used[env] = true
	}
	names := make([]string, 0, len(used))
	for env := range used {
		names = append(names, env)
	}
	sort.Strings(names)
	for _, env := range names {
		if err := unset(env); err != nil {
			return fmt.Errorf("-secret-env: could not remove %s from the environment: %w", env, err)
		}
	}
	return nil
}
