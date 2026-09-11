package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ★★★ A REPAIR THAT RESHAPES A MACHINE HAS TO SAY SO (2026-09-02, found by diffing a rewrite before anything
// was restarted — for the second time; the first was 2026-08-25).
//
// The repair printed the front-door files it rewrote and ended with "★ Nothing changes until the deployment
// is restarted." It had also just added dsse-store-b and dsse-store-c to a machine holding one etcd vote, and
// said nothing: the next `up -d` would have started two members beside a cluster that had never heard of
// them. The output was truthful and useless — it named files, and what matters is what the file now stands up
// that it did not before.
//
// So the repair diffs the services, and prints the ones that appeared and the ones that went. A removal is
// the more dangerous direction and is marked: `up -d` alone leaves an orphan running, and an orphan Edge
// serves stale enforcement while every screen says the deployment is healthy.
func reportComposeServiceChange(dir, before string) {
	after, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		return
	}
	was, now := composeServiceKeys(before), composeServiceKeys(string(after))
	var added, removed []string
	for s := range now {
		if !was[s] {
			added = append(added, s)
		}
	}
	for s := range was {
		if !now[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) == 0 && len(removed) == 0 {
		fmt.Printf("    it stands up the same services it did before.\n")
		return
	}
	if len(added) > 0 {
		fmt.Printf("    ★ it now stands up %d service(s) it did not before: %s\n",
			len(added), strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		fmt.Printf("    ★★ it no longer defines %d service(s): %s\n",
			len(removed), strings.Join(removed, ", "))
		fmt.Printf("       `up -d` will LEAVE THOSE RUNNING. Retire them with --remove-orphans, or they go on\n")
		fmt.Printf("       serving what they booted with while every screen says this deployment is healthy.\n")
	}
}

// composeServiceKeys is the set of top-level service names in a compose file.
func composeServiceKeys(body string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		// ★ A SERVICE KEY MAY CARRY A YAML ANCHOR: `dsse-store-a: &dsse-store`. Requiring the line to END
		// with a colon dropped exactly the services that define one, which in this file is the store — so a
		// repair that added or removed a store member would have reported nothing.
		trimmed := strings.TrimSpace(line)
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		rest := strings.TrimSpace(trimmed[colon+1:])
		if rest != "" && !strings.HasPrefix(rest, "&") {
			continue // a key with a value is a setting, not a service
		}
		name := trimmed[:colon]
		if strings.ContainsAny(name, " {}[]#\"'") {
			continue
		}
		out[name] = true
	}
	return out
}
