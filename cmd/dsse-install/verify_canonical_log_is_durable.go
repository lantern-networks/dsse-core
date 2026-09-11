package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// verify_canonical_log_is_durable.go — the record that outlives the container.
//
// ★★★ THE CANONICAL LOG WAS INSIDE THE CONTAINER (2026-08-26, measured on the generated deployment). The
// architecture is explicit: the local jsonl is the ORIGINAL and the shipment to the control plane is the copy,
// so that a control plane being down costs delivery and not the record. -log-dir defaults to the RELATIVE path
// "var/logs", which resolves against the working directory — in a container, the image's writable layer. Every
// jsonl on every node was there, outside the mounted volume, and every recreate destroyed that deployment's
// audit history. The volume was mounted and unused.
//
// A node reports where it writes, and this asks whether that is somewhere a restart cannot take with it. It is
// deliberately a question about the PATH rather than about the bytes: a check that reads the log would pass on
// a node that has simply not written anything yet.

// verifyCanonicalLogIsDurable asks every node where its canonical log lives.
func verifyCanonicalLogIsDurable(client *http.Client, doors []string) []verifyResult {
	out := []verifyResult{}
	add := func(ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: "the canonical log survives a restart", ok: ok,
			note: fmt.Sprintf(format, args...)})
	}
	asked := 0
	for _, door := range doors {
		door = strings.TrimRight(strings.TrimSpace(door), "/")
		if door == "" {
			continue
		}
		code, body, err := get(client, door+"/healthz", "")
		if err != nil || code != 200 {
			add(false, "%s did not answer /healthz (%d %v)", door, code, err)
			return out
		}
		var health struct {
			Logs *struct {
				Dir     string `json:"dir"`
				Durable bool   `json:"durable"`
			} `json:"logs"`
		}
		if json.Unmarshal(body, &health) != nil || health.Logs == nil {
			add(false, "%s does not say where it writes its canonical log — which is itself the answer for a "+
				"node old enough not to report it", door)
			return out
		}
		asked++
		if !health.Logs.Durable {
			add(false, "%s writes its canonical log to %q, which is a RELATIVE path — it resolves inside the "+
				"process's working directory, so on a container it dies with the container. The architecture "+
				"makes this log the original and the shipment the copy; here the only lasting copy is the one "+
				"at the far end of a best-effort shipment", door, health.Logs.Dir)
			return out
		}
	}
	if asked == 0 {
		add(false, "no node was asked")
		return out
	}
	add(true, "all %d node(s) write it to an absolute path", asked)
	return out
}
