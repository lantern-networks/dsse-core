package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const browserPortalNamesFile = "browser-portal-names.json"

// The Browser Portal has its own certificate and TLS lane. Never give its
// names to the Console certificate: on a shared IP an HTTP/2 browser can
// otherwise reuse its Console connection for a Portal request.
func canonicalBrowserPortalNames(names []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if !validPlanDNSName(name) {
			return nil, fmt.Errorf("invalid browser Portal name")
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func withoutBrowserPortalNames(names, portals []string) []string {
	if len(portals) == 0 {
		return names
	}
	excluded := make(map[string]bool, len(portals))
	for _, name := range portals {
		excluded[strings.ToLower(strings.TrimSpace(name))] = true
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if !excluded[strings.ToLower(strings.TrimSpace(name))] {
			out = append(out, name)
		}
	}
	return out
}

func writeBrowserPortalNames(dir string, names []string) error {
	canonical, err := canonicalBrowserPortalNames(names)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, browserPortalNamesFile), append(encoded, '\n'), 0o644)
}

// -add-host reissues the leaves from the transport SANs. Retain the Portal
// exclusion across that reissue rather than accidentally broadening the new
// management leaf. Older installations can recover the names from their env.
func readBrowserPortalNames(dir string) ([]string, error) {
	body, err := os.ReadFile(filepath.Join(dir, browserPortalNamesFile))
	if err == nil {
		var names []string
		if json.Unmarshal(body, &names) != nil {
			return nil, fmt.Errorf("invalid browser Portal name record")
		}
		return canonicalBrowserPortalNames(names)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	env := readDeploymentEnv(dir)
	names := []string{}
	if name := strings.TrimSpace(env["DSSE_NODE_PORTAL_NAME"]); name != "" {
		names = append(names, name)
	}
	for _, raw := range strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ",") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		u, parseErr := url.Parse(strings.TrimSpace(raw))
		if parseErr != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("invalid browser Portal origin")
		}
		names = append(names, u.Hostname())
	}
	return canonicalBrowserPortalNames(names)
}
