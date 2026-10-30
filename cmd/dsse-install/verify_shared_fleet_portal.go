package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// A server installation can prove directed Portal TLS without claiming a user
// authenticated or that established application traffic survived a failure.
func verifySharedFleetPortalEntrances(dir string, env map[string]string) verifyResult {
	result := verifyResult{name: "shared-fleet Portal entrance TLS"}
	plan, err := loadInstallPlan(dir, "")
	if err != nil || !declaredNodeMapProfile(plan.Profile) {
		result.note = "a complete declared shared-fleet install-plan.json is required to measure every entrance and Portal"
		return result
	}
	extra, err := os.ReadFile(filepath.Join(dir, "clientless", "trust.pem"))
	if err != nil && !os.IsNotExist(err) {
		result.note = "could not read the explicitly provisioned Portal trust"
		return result
	}
	roots, err := portalTrustPool(extra)
	if err != nil {
		result.note = "Portal trust is invalid; correct the approved CA input without disabling TLS validation"
		return result
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return verifySharedFleetPortalTLS(plan, env, roots, dialer.DialContext)
}

func verifySharedFleetPortalTLS(plan *Plan, env map[string]string, roots *x509.CertPool, dial func(context.Context, string, string) (net.Conn, error)) verifyResult {
	result := verifyResult{name: "shared-fleet Portal entrance TLS"}
	origins := []string{}
	type entranceAtRegion struct {
		machine  PlanMachine
		regionID string
	}
	entrances := []entranceAtRegion{}
	for _, region := range plan.Regions {
		for _, machine := range region.Machines {
			if machine.Holds.has("control-plane") {
				entrances = append(entrances, entranceAtRegion{machine: machine, regionID: region.ID})
			}
			if machine.Holds.has("edges") {
				origins = append(origins, "https://"+plan.edgePortalName(machine))
			}
		}
	}
	slices.Sort(origins)
	origins = slices.Compact(origins)
	actual := strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ",")
	slices.Sort(actual)
	actual = slices.Compact(actual)
	if len(entrances) == 0 || len(origins) == 0 || !slices.Equal(origins, actual) {
		result.note = "the complete plan and configured Portal origins differ; no partial entrance set is accepted"
		return result
	}
	checked, rejected := 0, 0
	for _, entrance := range entrances {
		for _, origin := range origins {
			host := strings.TrimPrefix(origin, "https://")
			if !validPlanDNSName(host) {
				result.note = "invalid planned Portal hostname"
				return result
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := verifyPortalTLSAt(ctx, dial, net.JoinHostPort(entrance.machine.reachableAt(), "443"), host, roots)
			cancel()
			if plan.Profile == "three-regions-multi-edge" && host != plan.regionPortalName(entrance.regionID) {
				if err == nil {
					result.note = fmt.Sprintf("%s accepted a foreign Region Portal name %s; each entrance must serve only its own Region", entrance.machine.Name, host)
					return result
				}
				rejected++
				continue
			}
			if err != nil {
				result.note = fmt.Sprintf("%s did not provide verified TLS for %s (%d/%d directed pairs measured); check the owning Region's certificate chain and approved verifier-host trust", entrance.machine.Name, host, checked+rejected, len(entrances)*len(origins))
				return result
			}
			checked++
		}
	}
	result.ok = true
	result.note = fmt.Sprintf("verified TLS on %d serving entrance/Portal pairs and refusal on %d foreign-Region pairs at the planned addresses; client DNS selection, IdP/browser completion and application resumption are separate acceptance", checked, rejected)
	return result
}

func verifyPortalTLSAt(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), address, host string, roots *x509.CertPool) error {
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots})
	defer client.Close()
	return client.HandshakeContext(ctx)
}

func unmeasuredSharedFleetAcceptance() verifyResult {
	return verifyResult{name: "browser, endpoint and failure acceptance", skipped: true,
		note: "not measured by this server installer: client DNS, real IdP/browser sign-in, native traffic resumption and fault/rejoin behavior through every entrance remain mandatory before device admission and release; server TLS success is not that evidence"}
}
