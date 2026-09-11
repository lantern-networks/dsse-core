package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enroll"
)

// identity.go — where a connector's certificate comes from.
//
// ★★★ WHY THIS EXISTS (2026-08-23, measured). The Admin Console's "Add connector" printed a command that could
// not start a connector. Run against the reference deployment with a fresh Site:
//
//	dsse-connector --token <…> --state-dir <…>
//	connector enrolled from token into site "install-probe" as conn-46926fdf27b0
//	connector transport TLS: connector identity certificate is mandatory outside dev mode (mTLS)
//
// The enrolment succeeded and the connector then refused to start. The Edge requires a certificate issued by
// the connector's own organization, and nothing in the enrolment issued one — the Console filled the gap with
// two placeholder lines, "<your connector certificate>", which is an instruction to go and run a certificate
// authority by hand before the product will start. An installer that mints the deployment's authorities and
// then asks the operator to mint one more, correctly, is not an installer.
//
// So the first run now finishes the job: generate a key, ask the Edge to sign it under the organization's
// device CA — the same POST /enroll a laptop uses, with a connector's own kind of proof — and persist the
// result beside the state. Every later start reads it back.
//
// ★ AN OPERATOR WHO BRINGS THEIR OWN IS LEFT ALONE. --connector-client-cert still wins: a deployment issuing
// connector identities from its own PKI keeps doing exactly that, and this never overwrites a file it did not
// write. The gap being closed is "no way to get one", not "one way to get one".
//
// ★ THE KEY NEVER LEAVES. Only the CSR is sent, and what comes back is checked against the key before it is
// stored — enroll.Run does both. A connector that cannot complete this stays down rather than starting with
// no identity, because starting anyway is the shape the mTLS requirement exists to prevent.

const (
	connectorIdentityCertFile = "connector.crt"
	connectorIdentityKeyFile  = "connector.key"
	connectorIdentityCAFile   = "connector-issuing-ca.pem"
)

// ensureConnectorIdentity gives the connector a certificate to present, and returns whether it issued a new one.
//
// It is a no-op when the operator supplied their own (*certPath non-empty), and a cheap file check on every run
// after the first. bootstrap is the Site secret from the enrolment token, and is only available on a first run —
// without it there is nothing to prove, so an unenrolled connector with no certificate is told exactly that
// rather than silently starting without one.
func ensureConnectorIdentity(ctx context.Context, stateDir string, st connectorState, bootstrap string,
	certPath, keyPath *string) (issued bool, err error) {
	if strings.TrimSpace(*certPath) != "" || strings.TrimSpace(*keyPath) != "" {
		// The operator brought their own. Nothing here may second-guess that: a deployment with its own
		// connector PKI is the case this whole file is trying to make unnecessary, not one to override.
		return false, nil
	}
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return false, nil
	}
	crt := filepath.Join(stateDir, connectorIdentityCertFile)
	key := filepath.Join(stateDir, connectorIdentityKeyFile)
	if fileExistsNonEmpty(crt) && fileExistsNonEmpty(key) {
		// ★★★ AND IT HAS TO BE THIS CONNECTOR'S CERTIFICATE (2026-08-26, measured — the lab connector held one
		// for a name it had stopped using and was refused by every Edge in the fleet, silently, for hours).
		//
		// A connector that re-enrols takes a NEW id and writes new state; the certificate on disk beside it is
		// the previous one. Nothing compared them, so the connector presented a certificate naming somebody
		// else and every Edge correctly refused it — with a message about the certificate not being bound to
		// the connector id, which reads as an Edge-side problem and is not.
		//
		// The certificate is the whole of a connector's authentication to the fleet, so a certificate for the
		// wrong name is not a degraded state to run in.
		if named, cerr := connectorIdentityCertNames(crt, st.ConnectorID); cerr != nil {
			return false, fmt.Errorf("this connector's identity certificate (%s) could not be read: %w", crt, cerr)
		} else if !named {
			if strings.TrimSpace(bootstrap) == "" {
				return false, fmt.Errorf("this connector is %s but the certificate in %s is issued for a "+
					"different name, so every Edge refuses it. Issue a fresh 'Add connector' command in the "+
					"Admin Console and start with --token, which obtains one for this name",
					st.ConnectorID, stateDir)
			}
			log.Printf("connector: the certificate in %s is issued for a different name than %s — obtaining one "+
				"for this connector", stateDir, st.ConnectorID)
			// Fall through to enrolment below, which writes both files for the current id.
		} else {
			*certPath, *keyPath = crt, key
			return false, nil
		}
	}
	if strings.TrimSpace(bootstrap) == "" {
		// Enrolled before, but with no certificate on disk — the state was copied without it, or an earlier
		// version of this connector wrote state and stopped there. Said plainly, because the alternative is a
		// mandatory-mTLS failure three lines later that names the flag and not the cause.
		return false, fmt.Errorf("this connector has no identity certificate and no enrollment token to obtain "+
			"one with: %s holds its state but not %s. Issue a fresh 'Add connector' command in the Admin Console "+
			"and start with --token", stateDir, connectorIdentityCertFile)
	}

	// ★★★ AND UNDER THE ENROLMENT NAME, when the organization has one. The Edge folds enrolment onto the
	// transport port BY the name in the ClientHello — a connection asking for the plain transport name is the
	// transport plane, which is not the plane that issues identities. Empty keeps the dialled host, which is
	// what a connector without an organization door has always sent.
	client, err := connectorEnrolmentClient(st.EdgeCAPath, connectorFirstNonEmpty(st.EdgeEnrolmentServerName, st.EdgeServerName))
	if err != nil {
		return false, err
	}
	endpoint := strings.TrimRight(strings.TrimSpace(st.EdgeURL), "/") + "/enroll"
	// ★★ THE SITE HAS TO HAVE REACHED THIS EDGE FIRST (2026-08-23, measured). A Site — and the bootstrap secret
	// hash the Edge checks against — is authored on the control plane and travels to the Edges in the config
	// bundle, which is a poll. Issuing "Add connector" and running the printed command immediately, as anybody
	// would, met the ordinary refusal:
	//
	//	obtain connector identity: enroll: refused: invalid or missing eligibility token
	//
	// which is the same sentence a genuinely wrong token gets, and sends the operator looking for the wrong
	// thing. The same command succeeded a minute later. So the first run WAITS rather than failing: a race is
	// not an error, and the operator should not have to know the fleet's poll interval.
	//
	// Bounded, and it says what it is waiting for. An unbounded retry would turn a genuinely wrong token into a
	// process that never says anything, which is worse than a refusal.
	var res enroll.Result
	deadline := time.Now().Add(connectorEnrolmentPropagationWait)
	for attempt := 1; ; attempt++ {
		// caPin is empty because the transport is ALREADY pinned: the token carried the Edge's transport CA and
		// the client above trusts nothing else. Passing an anchor we have no independent source for would be a
		// check against ourselves.
		res, err = enroll.Run(ctx, endpoint, st.ConnectorID, st.TenantID, "", enroll.Eligibility{
			Mode:  "connector",
			Token: bootstrap,
			Site:  st.Site,
		}, client)
		if err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false, fmt.Errorf("obtain connector identity from %s (gave up after %s): %w. If the Site was "+
				"created on the control plane moments ago, this Edge may not hold it yet; if the command is older "+
				"than the Site's latest 'Add connector', its bootstrap secret has been replaced",
				endpoint, connectorEnrolmentPropagationWait, err)
		}
		if logf := log.Printf; attempt == 1 {
			logf("connector identity: the Edge has not accepted this Site's bootstrap secret yet — waiting up to "+
				"%s for the Site to reach it (%v)", connectorEnrolmentPropagationWait, err)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(connectorEnrolmentRetryEvery):
		}
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return false, fmt.Errorf("create state dir: %w", err)
	}
	// The key first and at 0600. If the process dies between the two writes the next start finds no certificate
	// and re-enrols, which is recoverable; a certificate with no key is not.
	if err := os.WriteFile(key, res.KeyPEM, 0o600); err != nil {
		return false, fmt.Errorf("write connector key: %w", err)
	}
	if err := os.WriteFile(crt, res.CertPEM, 0o600); err != nil {
		return false, fmt.Errorf("write connector certificate: %w", err)
	}
	// The issuing CA is written too — not used to connect, but an operator asking "which authority is this
	// connector under" should be able to answer it from the connector's own directory.
	if len(res.CAPEM) > 0 {
		_ = os.WriteFile(filepath.Join(stateDir, connectorIdentityCAFile), res.CAPEM, 0o600)
	}
	*certPath, *keyPath = crt, key
	return true, nil
}

// connectorEnrolmentClient dials the Edge trusting ONLY the transport CA the enrollment token pinned. A
// connector's very first act is to hand a CSR to something claiming to be its Edge, so the system trust store
// is not good enough here: anything a public CA signed would do.
func connectorEnrolmentClient(edgeCAPath, serverName string) (*http.Client, error) {
	edgeCAPath = strings.TrimSpace(edgeCAPath)
	if edgeCAPath == "" {
		return nil, fmt.Errorf("this connector's enrollment token carried no Edge transport CA, so its first " +
			"connection could not be pinned; re-issue the 'Add connector' command from the Admin Console")
	}
	pem, err := os.ReadFile(edgeCAPath)
	if err != nil {
		return nil, fmt.Errorf("read pinned Edge CA %s: %w", edgeCAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("pinned Edge CA %s contains no certificate", edgeCAPath)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12,
				ServerName: strings.TrimSpace(serverName)},
		},
	}, nil
}

func fileExistsNonEmpty(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// ★★★ AND IT HAS TO RENEW (2026-08-23). The certificate above is issued with the same 60-day TTL a laptop's
// is, and a connector that never renews stops being able to reach its Edge on day 60 — the whole Site goes
// dark at once, and every connector installed in the same week goes dark in the same hour. That outage has
// happened in this tree once already with a 30-day leaf, which is why POST /enroll/renew exists at all; the
// connector simply was not calling it.
//
// Renewal is authenticated by the certificate being renewed, over the mTLS transport the connector is already
// on, so there is nothing to remember and no secret to keep: the connector proves it is the connector by being
// the connector. A revoked one cannot renew, which is what keeps revocation terminal rather than a countdown.

// connectorIdentityCheckEvery is how often the question is asked. Cheap — it reads one file — and the answer
// changes once every few weeks, so this is about surviving a long-running process, not about speed.
//
// WHEN the answer becomes yes is enroll.RenewalDue's to say, not this file's: two thirds of the certificate's
// OWN life. A fixed number of days here would agree with it on the 60-day certificates issued today and stop
// renewing in time on any deployment that shortened them — which is precisely what -enroll-cert-ttl is for.
const connectorIdentityCheckEvery = 6 * time.Hour

// How long a first run waits for its Site to reach the Edge it dials, and how often it asks. Longer than any
// reasonable config-bundle poll and short enough that a genuinely wrong token is reported while the operator
// is still watching.
const (
	connectorEnrolmentPropagationWait = 3 * time.Minute
	connectorEnrolmentRetryEvery      = 10 * time.Second
)

// renewConnectorIdentityLoop keeps the connector's certificate alive for as long as the process runs. It never
// returns except on ctx cancellation; a failed renewal is logged and retried at the next tick, because there
// are weeks of chances left and stopping the connector over one failed attempt would turn a transient Edge
// outage into a Site outage.
func renewConnectorIdentityLoop(ctx context.Context, stateDir string, st connectorState, edgeTLS *tls.Config,
	logf func(string, ...interface{})) {
	if strings.TrimSpace(stateDir) == "" || edgeTLS == nil {
		return // an operator-supplied identity, or no state: renewal is theirs to run
	}
	ticker := time.NewTicker(connectorIdentityCheckEvery)
	defer ticker.Stop()
	for {
		if err := renewConnectorIdentityIfDue(ctx, stateDir, st, edgeTLS, false, logf); err != nil && logf != nil {
			logf("connector identity renewal failed (will retry): %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// renewConnectorIdentityIfDue renews when enroll.RenewalDue says so, and does nothing otherwise.
//
// force skips only the DUE question, never any of the checks after it, so the renewal can be MEASURED against
// a live Edge without waiting forty days or reconfiguring the deployment's certificate lifetime. A check that
// cannot be run is a check nobody has run.
func renewConnectorIdentityIfDue(ctx context.Context, stateDir string, st connectorState, edgeTLS *tls.Config,
	force bool, logf func(string, ...interface{})) error {
	crt := filepath.Join(stateDir, connectorIdentityCertFile)
	current, err := connectorCertificateOnDisk(crt)
	if err != nil {
		return err
	}
	if !force && !enroll.RenewalDue(current.NotBefore, current.NotAfter, time.Now()) {
		return nil
	}
	keyPEM, csrPEM, err := enroll.GenerateKeyAndCSR(st.ConnectorID, st.TenantID)
	if err != nil {
		return fmt.Errorf("generate renewal key: %w", err)
	}
	// The CURRENT certificate is what authenticates this, so the call goes out on the connector's own mTLS
	// config — the same one its tunnel uses. The CSR proves possession of the NEW key and nothing else; the
	// Edge takes the identity from the verified certificate, never from what is sent.
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: edgeTLS.Clone()},
	}
	endpoint := strings.TrimRight(strings.TrimSpace(st.EdgeURL), "/") + "/enroll/renew"
	body := fmt.Sprintf(`{"csr_pem":%s}`, mustJSONString(string(csrPEM)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
		NotTo   string `json:"not_after"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("decode renewal response (status %d): %w", resp.StatusCode, err)
	}
	if strings.TrimSpace(out.Error) != "" {
		return fmt.Errorf("renewal refused: %s", out.Error)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || strings.TrimSpace(out.CertPEM) == "" {
		return fmt.Errorf("renewal returned status %d with no certificate", resp.StatusCode)
	}
	// ★ PROVE IT BEFORE ADOPTING IT. A certificate that does not match the new key, or does not chain to the
	// CA it came with, would replace a working identity with a broken one — and the connector would only find
	// out at the next reconnect, when it can no longer renew. Same rule as first enrolment.
	if err := enroll.ValidateIssuedCert([]byte(out.CertPEM), []byte(out.CAPEM), keyPEM, ""); err != nil {
		return fmt.Errorf("the renewed certificate did not verify, keeping the current one: %w", err)
	}
	// Written to temporary names and renamed, so a crash mid-write cannot leave a certificate that does not
	// match the key beside it. The pair has to move together or not at all.
	if err := writeThenRename(filepath.Join(stateDir, connectorIdentityKeyFile), keyPEM); err != nil {
		return err
	}
	if err := writeThenRename(crt, []byte(out.CertPEM)); err != nil {
		return err
	}
	if logf != nil {
		logf("connector identity renewed, valid until %s (restart to present it)", out.NotTo)
	}
	return nil
}

// connectorCertificateOnDisk is the certificate the connector is currently holding.
func connectorCertificateOnDisk(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read connector certificate: %w", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("connector certificate %s contains no PEM block", path)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse connector certificate: %w", err)
	}
	return cert, nil
}

func writeThenRename(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}

func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// connectorIdentityCertNames reports whether the certificate at path is issued for connectorID.
//
// The comparison is the one the Edge makes — the identity in the leaf against the connector id — so a
// certificate this says is right is one the fleet accepts, and there is one definition of "right" rather than
// two that can drift.
func connectorIdentityCertNames(path, connectorID string) (bool, error) {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return true, nil // nothing to compare against; the caller has bigger problems and says so elsewhere
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return false, fmt.Errorf("%s holds no PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	if strings.EqualFold(strings.TrimSpace(cert.Subject.CommonName), connectorID) {
		return true, nil
	}
	for _, name := range cert.DNSNames {
		if strings.EqualFold(strings.TrimSpace(name), connectorID) {
			return true, nil
		}
	}
	return false, nil
}
