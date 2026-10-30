package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type clientHostProbe struct {
	Name                string
	Resolved            []string
	Connected           string
	CertificateSHA256   string
	CertificateDNSNames []string
	OK                  bool
	Error               string
}

type clientHostResolver func(context.Context, string) ([]net.IPAddr, error)
type clientHostDialer func(context.Context, string, string) (net.Conn, error)

// Dial by the actual hostname, not an IP override. Check the OS resolver,
// the connected address, and the certificate presented with that name as SNI.
// A TLS success is not a claim about which application owns the response.
func probeClientHost(ctx context.Context, entry clientHostEntry, roots *x509.CertPool, resolve clientHostResolver, dial clientHostDialer) clientHostProbe {
	result := clientHostProbe{Name: entry.Name}
	fail := func(err error) clientHostProbe { result.Error = err.Error(); return result }
	addresses, err := resolve(ctx, entry.Name)
	if err != nil {
		return fail(fmt.Errorf("name resolution: %w", err))
	}
	if len(addresses) == 0 {
		return fail(fmt.Errorf("name resolved to no addresses"))
	}
	for _, addr := range addresses {
		result.Resolved = append(result.Resolved, addr.IP.String())
		if !addr.IP.Equal(entry.IP) {
			return fail(fmt.Errorf("name resolves outside the declared regional entry: %s", addr.IP))
		}
	}
	raw, err := dial(ctx, "tcp", net.JoinHostPort(entry.Name, "443"))
	if err != nil {
		return fail(fmt.Errorf("connect by hostname: %w", err))
	}
	defer raw.Close()
	connected, _, err := net.SplitHostPort(raw.RemoteAddr().String())
	if err != nil || !entry.IP.Equal(net.ParseIP(connected)) {
		return fail(fmt.Errorf("connected peer differs from the declared entry: %s", raw.RemoteAddr()))
	}
	result.Connected = raw.RemoteAddr().String()
	conn := tls.Client(raw, &tls.Config{ServerName: entry.Name, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		return fail(fmt.Errorf("verified TLS/SNI: %w", err))
	}
	peer := conn.ConnectionState().PeerCertificates[0]
	sum := sha256.Sum256(peer.Raw)
	result.CertificateSHA256 = hex.EncodeToString(sum[:])
	result.CertificateDNSNames = peer.DNSNames
	result.OK = true
	return result
}

func runVerifyClientHosts(path, caFile string, plan *Plan, tenantLabels []string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	entries, err := parseClientHosts(string(body))
	if err != nil {
		return err
	}
	if err := plan.validateClientHostEntries(entries, tenantLabels); err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	if caFile != "" {
		bundle, err := os.ReadFile(caFile)
		if err != nil {
			return err
		}
		if !roots.AppendCertsFromPEM(bundle) {
			return fmt.Errorf("client CA file contains no certificates")
		}
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	results := make([]clientHostProbe, 0, len(entries))
	failures := 0
	for _, entry := range entries {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		result := probeClientHost(ctx, entry, roots, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
		cancel()
		if !result.OK {
			failures++
		}
		results = append(results, result)
	}
	report := map[string]any{
		"scope":                               "external OS name resolution and presented TLS certificate on port 443",
		"plan_names_complete":                 true,
		"tenant_dns_labels":                   tenantLabels,
		"application_role_and_owner_verified": false,
		"agent_connections_performed":         false,
		"results":                             results, "failures": failures,
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	if failures != 0 {
		return fmt.Errorf("%d client names failed resolution or verified TLS", failures)
	}
	return nil
}
