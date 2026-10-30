package deploymentcrl

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

// ProbeOnline checks every encoded HTTP CDP through the same unauthenticated
// path used by endpoint Online revocation checks. Independent origins must
// return identical, fresh issuer-signed DER; a redirect is not a status proof.
// It is a pre-connection gate, not a substitute for the endpoint OS check.
func ProbeOnline(ctx context.Context, chain []*x509.Certificate, client *http.Client, now time.Time) error {
	if len(chain) < 2 {
		return fmt.Errorf("complete deployment certificate chain required")
	}
	if client == nil {
		client = &http.Client{}
	}
	probeClient := *client
	probeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	lists := make(map[string][]byte, len(chain)-1)
	for i := 0; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		if cert == nil || issuer == nil {
			return fmt.Errorf("nil deployment certificate")
		}
		if _, err := DistributionPointsFromCertificate(cert, chain[len(chain)-1], issuer); err != nil {
			return err
		}
		var first []byte
		for _, point := range cert.CRLDistributionPoints {
			requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, point, nil)
			if err != nil {
				cancel()
				return err
			}
			resp, err := probeClient.Do(req)
			if err != nil {
				cancel()
				return fmt.Errorf("deployment CDP is unreachable: %w", err)
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, inspectioncrl.MaxDERBytes+1))
			closeErr := resp.Body.Close()
			cancel()
			if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
				return fmt.Errorf("deployment CDP did not return signed status")
			}
			if _, err := inspectioncrl.ParseAndValidate(body, issuer, now); err != nil {
				return fmt.Errorf("deployment CDP returned invalid status: %w", err)
			}
			if first != nil && !bytes.Equal(first, body) {
				return fmt.Errorf("deployment CRL origins disagree for one issuer")
			}
			first = body
		}
		lists[Fingerprint(issuer)] = first
	}
	return VerifyStatus(chain, lists, now)
}
