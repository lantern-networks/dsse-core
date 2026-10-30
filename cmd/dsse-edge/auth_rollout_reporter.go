package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
)

// Separate machine identity from the shared audit shipper certificate: a
// fleet-wide certificate cannot prove which individual CP or Edge was upgraded.
type authRolloutReporter struct {
	census                authrollout.Manifest
	member                authrollout.Member
	client                *http.Client
	url                   string
	ceremonyRecoveryReady bool
}

func newAuthRolloutReporter(censusPath, target, ca, cert, key, role string) (*authRolloutReporter, error) {
	if censusPath == "" && target == "" && ca == "" && cert == "" && key == "" {
		return nil, nil
	}
	if censusPath == "" || target == "" || cert == "" || key == "" {
		return nil, fmt.Errorf("authentication rollout requires census, report URL and individual node identity")
	}
	u, e := url.Parse(target)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("authentication rollout report URL must be HTTPS without credentials, query or fragment")
	}
	b, e := os.ReadFile(censusPath)
	if e != nil {
		return nil, e
	}
	var m authrollout.Manifest
	if e = json.Unmarshal(b, &m); e != nil {
		return nil, e
	}
	if e = m.Validate(); e != nil {
		return nil, e
	}
	tc, e := auditShipTLSConfig(ca, cert, key)
	if e != nil {
		return nil, e
	}
	return authRolloutReporterFor(m, target, tc, role)
}
func authRolloutReporterFor(m authrollout.Manifest, target string, tc *tls.Config, role string) (*authRolloutReporter, error) {
	if tc == nil {
		return nil, fmt.Errorf("individual rollout identity is missing")
	}
	// The production TLS helper loads the identity through GetClientCertificate
	// so renewed files are read on each handshake. Certificates is deliberately
	// empty in that configuration. Match the identity TLS will actually present,
	// retaining the callback on the client (and the authority's per-leaf pin check).
	var identity *tls.Certificate
	if tc.GetClientCertificate != nil {
		var err error
		identity, err = tc.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			return nil, fmt.Errorf("individual rollout identity could not be loaded")
		}
	} else if len(tc.Certificates) == 1 {
		identity = &tc.Certificates[0]
	}
	if identity == nil || len(identity.Certificate) == 0 {
		return nil, fmt.Errorf("individual rollout identity is missing")
	}
	sum := sha256.Sum256(identity.Certificate[0])
	pin := hex.EncodeToString(sum[:])
	for _, n := range m.Members {
		if !n.Retired && n.CertificateSHA256 == pin && n.Role == role {
			return &authRolloutReporter{census: m, member: n, url: target, client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
		}
	}
	return nil, fmt.Errorf("process identity and role are not in the expected deployment census")
}
func (p *authRolloutReporter) report(ctx context.Context) error {
	if p == nil {
		return nil
	}
	features := []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.DeviceUserFeature, authrollout.RevocationReauthenticationFeature}
	if p.ceremonyRecoveryReady {
		features = append(features, authrollout.CeremonyRecoveryFeature)
	}
	body, _ := json.Marshal(authrollout.Report{Generation: p.census.Generation, NodeID: p.member.ID, Version: buildVersion + "@" + buildCommit, Features: features})
	target := p.url
	if base := controlChannelCurrentDataURL(); base != "" {
		target = authRolloutEndpoint(base)
	}
	r, e := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(body))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := p.client.Do(r)
	if e != nil {
		return fmt.Errorf("authentication capability report transport failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication capability report status %d", resp.StatusCode)
	}
	return nil
}
func (p *authRolloutReporter) run(ctx context.Context) {
	if p == nil {
		return
	}
	lastStatus := ""
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		r := theAuthRollout.Load()
		if r != nil && r.authority != nil {
			// Only create a missing census. Never replace a deployment's committed
			// generation with a stale file carried by a restarting CP.
			if s, e := r.authority.Read(); e == nil && s.Schema == 0 {
				m := p.census
				m.Providers = map[string]string{}
				if reg := theIdPRegistry.Load(); reg != nil && reg.RefreshShared() == nil {
					for _, provider := range reg.ListAll() {
						m.Providers[authrollout.ProviderKey(provider.TenantID, provider.IdPID)] = authEvidenceProviderDigest(provider)
					}
					_ = r.authority.Configure(captureCPWriteLease(ctx), 0, m)
				}
			}
		}
		// The CP writes capability observations only through the leader's mTLS
		// route, including when this reporter runs on a standby CP.
		status := "confirmed"
		if err := p.report(ctx); err != nil {
			status = "unconfirmed"
		}
		if status != lastStatus {
			log.Printf("authentication_rollout_capability_report status=%s", status)
			lastStatus = status
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func authRolloutEndpoint(base string) string {
	return strings.TrimRight(base, "/") + "/fleet-capabilities/report"
}

func registerAuthRolloutFlags() struct{ census, url, ca, cert, key *string } {
	authRolloutCensus := flag.String("auth-rollout-census", "", "complete operator-declared CP and Edge census for rolling authentication upgrades")
	authRolloutURL := flag.String("auth-rollout-report-url", "", "HTTPS leader machine endpoint for authenticated node capability reports")
	authRolloutCA := flag.String("auth-rollout-ca", "", "CA verifying the rollout report authority")
	authRolloutCert := flag.String("auth-rollout-client-cert", "", "individual CP or Edge client certificate pinned by the rollout census")
	authRolloutKey := flag.String("auth-rollout-client-key", "", "private key of the individual rollout client certificate")

	return struct{ census, url, ca, cert, key *string }{authRolloutCensus, authRolloutURL, authRolloutCA, authRolloutCert, authRolloutKey}
}
