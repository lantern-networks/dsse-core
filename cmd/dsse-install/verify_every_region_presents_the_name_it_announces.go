package main

// verify_every_region_presents_the_name_it_announces.go — every address in the deployment's region map is
// dialled, with that name, and verified against the deployment's own anchor.
//
// ★★★ THE SECOND REGION HAD NEVER BEEN TOLD (2026-08-26, reported by win-dev-1 from real hardware, letter
// 104). -add-host was run once, on the directory of the region the operator happened to be in, and it
// re-issued the leaves of THAT region. The other region's certificate was minted before the name existed:
//
//	region-a  SAN: localhost, shinmac-mini.tail04460b.ts.net, ... IP 100.72.135.18
//	region-b  SAN: localhost, ...                                  (neither)
//
// Meanwhile the profile the Console hands a device lists BOTH doors by that name. So the second door resolved,
// answered, completed a TLS handshake — and failed verification on the device, which is the one place nobody
// was looking. It is letter 88's defect a second time, in the region the operator was not standing in.
//
// A deployment ANNOUNCING a name is a promise to present it. The announcement is the region map, so the check
// walks the map: for every region, dial the address that map hands out, with that name as the SNI, and verify
// against the anchor this deployment gives its devices. That is exactly the handshake a device performs, and
// it is the only form of this question that cannot be satisfied by the region the operator is standing in.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// verifyEveryRegionPresentsTheNameItAnnounces dials each entry of the deployment's region map the way a device
// does. dir is the deployment directory holding deployment.env and deployment-anchor.pem.
func verifyEveryRegionPresentsTheNameItAnnounces(dir string) []verifyResult {
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return []verifyResult{{name: "every region presents the name it announces", ok: false,
			note: fmt.Sprintf("could not read this deployment's own description: %v", err)}}
	}
	announced := strings.TrimSpace(env["DSSE_REGION_ENDPOINTS"])
	if announced == "" {
		// A single-region deployment announces no map, and there is nothing to be inconsistent with.
		return nil
	}
	anchor, err := deploymentAnchorPool(dir)
	if err != nil {
		return []verifyResult{{name: "every region presents the name it announces", ok: false,
			note: fmt.Sprintf("could not read the anchor this deployment gives its devices: %v", err)}}
	}

	results := []verifyResult{}
	for _, region := range sortedRegionEntries(announced) {
		name := "region " + region.id + " presents the name it announces"
		host, port, perr := hostAndPortFromEndpoint(region.url)
		if perr != nil {
			results = append(results, verifyResult{name: name, ok: false, note: fmt.Sprintf("the region map hands devices %q, which is not an address: %v", region.url, perr)})
			continue
		}
		conn, derr := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", net.JoinHostPort(host, port),
			&tls.Config{ServerName: host, RootCAs: anchor, MinVersion: tls.VersionTLS12})
		if derr != nil {
			// ★ A FAILURE HERE IS THE DEVICE'S FAILURE, WORD FOR WORD. It is dialled with the name the
			// deployment hands out and verified against the anchor the deployment distributes, so there is no
			// gap between what this says and what a device would experience.
			results = append(results, verifyResult{name: name, ok: false, note: fmt.Sprintf("a device dialling %s — the address this deployment hands out for %s — cannot "+
				"verify it: %v. Teach that region the name with: dsse-install -dir <that region's directory> "+
				"-add-host %s, then restart its nodes", region.url, region.id, derr, host)})
			continue
		}
		_ = conn.Close()
		results = append(results, verifyResult{name: name, ok: true, note: fmt.Sprintf("%s answers as %s and verifies against this deployment's anchor", region.url, host)})
	}
	return results
}

type announcedRegion struct{ id, url string }

// sortedRegionEntries parses "region-a=https://…;region-b=https://…" in a stable order, so the walk reads the
// same way twice.
func sortedRegionEntries(raw string) []announcedRegion {
	out := []announcedRegion{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, target, found := strings.Cut(entry, "=")
		if !found {
			// A bare address with no region tag still announces a name, and still has to present it.
			out = append(out, announcedRegion{id: "(unnamed)", url: strings.TrimSpace(entry)})
			continue
		}
		out = append(out, announcedRegion{id: strings.TrimSpace(id), url: strings.TrimSpace(target)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// hostAndPortFromEndpoint splits an https URL into the name a device uses for SNI and the port it dials.
func hostAndPortFromEndpoint(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", err
	}
	host := parsed.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("no host")
	}
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https", "wss", "":
			port = "443"
		default:
			return "", "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
		}
	}
	return host, port, nil
}

// deploymentAnchorPool is the anchor this deployment distributes to its devices — the only trust a device has.
func deploymentAnchorPool(dir string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("deployment-anchor.pem holds no certificate")
	}
	return pool, nil
}
