package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// verify.go — the installer asking the machine what actually happened, after the connector has run.
//
// ★★★ THE HEADER OF main.go LISTED THREE QUESTIONS AND ANSWERED NONE OF THEM. "did it enrol, did it get an
// identity, can it reach more than one region" — the install run can only report what the TOKEN said, because
// at that moment the connector has not started. Everything in that list becomes true, or fails to, on the
// first run. So it is asked here, from the state directory the connector persisted into and from the doors
// themselves, and it is asked in the order these things can fail.
//
// ★ IT READS EVIDENCE, NOT INTENT. Every check below names a file the connector wrote or a handshake this
// machine completed. Nothing is inferred from the token: a token says what was ISSUED, and the whole point of
// this walk is the difference between what was issued and what this machine ended up with. In particular the
// doors are counted from the PERSISTED endpoint list, because that is the one every later start uses — the
// token is spent and gone.
//
// ★ "COULD NOT TELL" IS NEVER A PASS. Same rule as dsse-install -verify: a check that cannot run says which
// part it could not reach and fails, because a connector that cannot be checked is the one nobody checks
// again.

type verifyResult struct {
	name string
	ok   bool
	note string
}

// persistedState is the part of connector-state.json this walk reads. The connector owns this file; the field
// names here are its own (see cmd/dsse-connector/enrollment.go).
type persistedState struct {
	EdgeURL       string `json:"edge_url"`
	TenantID      string `json:"tenant_id"`
	Site          string `json:"site"`
	ConnectorID   string `json:"connector_id"`
	Region        string `json:"region"`
	EdgeCAPath    string `json:"edge_ca_path"`
	EdgeEndpoints string `json:"edge_endpoints"`
	// RuntimeSecret is what the connector presents to the doors on every later request. It is read here so
	// this walk can ask a door the question the connector asks it, rather than a weaker one. See askDoor.
	RuntimeSecret string `json:"runtime_secret"`
}

// The connector's own filenames. Kept as constants with this comment because they are a contract with another
// program: if cmd/dsse-connector renames one, this walk reports a healthy connector as un-enrolled.
const (
	stateFileName      = "connector-state.json"
	identityCertName   = "connector.crt"
	identityKeyName    = "connector.key"
	identityIssuerName = "connector-issuing-ca.pem"
	pinnedAnchorName   = "edge-ca.pem"
)

func verifyConnector(stateDir, binary, serviceName string, now time.Time) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) bool {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
		return ok
	}

	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		add("this machine has a connector installed", false,
			"%s is not there: nothing was installed here, or it was installed somewhere else", stateDir)
		return out
	}
	add("this machine has a connector installed", true, "%s", stateDir)

	// ★★★ ENROLLED IS NOT "THE COMMAND RAN". On 2026-08-23 a connector logged a line naming its connector id
	// while its state directory was empty — it had never enrolled, and every later start would have enrolled
	// again as somebody new. The file is the only evidence that the token was spent.
	statePath := filepath.Join(stateDir, stateFileName)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		add("this connector has enrolled", false,
			"no %s: the token has not been spent, so this connector has never run. Start it, then verify",
			stateFileName)
		return out
	}
	var st persistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		add("this connector has enrolled", false, "%s cannot be read (%v)", stateFileName, err)
		return out
	}
	if strings.TrimSpace(st.ConnectorID) == "" {
		add("this connector has enrolled", false,
			"%s names no connector: the deployment does not know this machine", stateFileName)
		return out
	}
	add("this connector has enrolled", true, "%s in site %s, organization %s",
		st.ConnectorID, orDash(st.Site), orDash(st.TenantID))

	out = append(out, verifyIdentity(stateDir, st, now)...)

	// The doors, counted from what every later start will use. See the file header.
	doors := parseDoors(st.EdgeEndpoints)
	if len(doors) == 0 && strings.TrimSpace(st.EdgeURL) != "" {
		doors = parseDoors(st.EdgeURL)
	}
	switch {
	case len(doors) == 0:
		add("this connector knows where the deployment is", false,
			"%s carries no address: this connector cannot reconnect without being enrolled again", stateFileName)
	case len(doors) == 1:
		// Not a failure: one region, with a control plane and its Edges, is the smallest shape this product
		// runs in production. It is reported with its consequence because that is the part nobody is told.
		add("this connector knows where the deployment is", true,
			"★ one door (%s): if it stops answering, everything behind this connector is unreachable until it comes back",
			doors[0].display())
	default:
		add("this connector knows where the deployment is", true,
			"%d doors, tried in this order: %s", len(doors), joinDoors(doors))
	}

	out = append(out, verifyDoorsAnswer(stateDir, st, doors)...)
	out = append(out, verifySurvivesAReboot(stateDir, binary, serviceName)...)
	return out
}

// verifyIdentity checks the certificate this connector got from the deployment's PKI. An identity that merely
// EXISTS is not one this deployment issued: the checks are separate on purpose, and the second is the one that
// distinguishes a connector of this deployment from a connector of some other.
func verifyIdentity(stateDir string, st persistedState, now time.Time) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) bool {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
		return ok
	}

	certPath := filepath.Join(stateDir, identityCertName)
	cert, err := readCertificate(certPath)
	if err != nil {
		// ★ THIS IS THE FAILURE THE OLD ENROLMENT COMMAND ENDED IN. It enrolled, then stopped on
		// "connector identity certificate is mandatory outside dev mode (mTLS)" — enrolled and unable to
		// connect, which reads as a network problem and is not one.
		add("it has an identity of its own", false, "%v", err)
		return out
	}
	if _, err := os.Stat(filepath.Join(stateDir, identityKeyName)); err != nil {
		add("it has an identity of its own", false,
			"%s is there but %s is not: this identity cannot be used", identityCertName, identityKeyName)
		return out
	}
	add("it has an identity of its own", true, "%s, subject %q", identityCertName, cert.Subject.CommonName)

	// ★★★ ISSUED BY THIS DEPLOYMENT. A connector's identity is minted by the organization's own certificate
	// authority at enrolment, and the issuing CA it was handed then is on this disk. Verifying the leaf
	// against it is the whole difference between "there is a certificate here" and "this machine belongs to
	// this deployment".
	issuerPath := filepath.Join(stateDir, identityIssuerName)
	issuer, ierr := readCertificate(issuerPath)
	if ierr != nil {
		add("the identity came from this deployment", false,
			"no readable %s, so nothing on this machine says who issued the identity above (%v)",
			identityIssuerName, ierr)
	} else {
		pool := x509.NewCertPool()
		pool.AddCert(issuer)
		if _, verr := cert.Verify(x509.VerifyOptions{
			Roots:       pool,
			CurrentTime: cert.NotBefore.Add(time.Second),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); verr != nil {
			add("the identity came from this deployment", false,
				"%s does not chain to %s (%v): this identity was not issued by the authority this connector enrolled into",
				identityCertName, identityIssuerName, verr)
		} else {
			add("the identity came from this deployment", true, "issued by %q", issuer.Subject.CommonName)
		}
	}

	// The same rule the connector itself applies (cmd/dsse-connector/identity.go): CN or a DNS SAN equal to
	// the connector id. A certificate naming somebody else is one the Edge will attribute to somebody else.
	if !certNames(cert, st.ConnectorID) {
		add("the identity names this connector", false,
			"the certificate says %q and %s says %q — the Edge attributes this connector's flows to the name in the certificate",
			cert.Subject.CommonName, stateFileName, st.ConnectorID)
	} else {
		add("the identity names this connector", true, "%s", st.ConnectorID)
	}

	switch {
	case now.Before(cert.NotBefore):
		add("the identity is valid now", false,
			"it is not valid until %s — this machine's clock and the deployment's do not agree",
			cert.NotBefore.UTC().Format(time.RFC3339))
	case now.After(cert.NotAfter):
		add("the identity is valid now", false,
			"it expired %s: this connector can no longer open a tunnel, and everything behind it is unreachable",
			cert.NotAfter.UTC().Format(time.RFC3339))
	default:
		add("the identity is valid now", true, "until %s (%s left)",
			cert.NotAfter.UTC().Format(time.RFC3339), roundDuration(cert.NotAfter.Sub(now)))
	}
	return out
}

// verifyDoorsAnswer asks each door the question the connector asks it: GET /connectors/{id}/profile, with the
// pinned anchors as the only roots, this connector's identity as the client certificate, and its runtime
// secret in the header. A door that answers 200 will carry this connector.
//
// ★★★ COUNTING DOORS IS NOT REACHING THEM. The install run can only count strings, and a list of two
// addresses where the second does not answer fails over into nothing. This is the check that separates "this
// connector was told about two regions" from "this connector has two regions".
//
// ★★★ AND A HANDSHAKE IS NOT AN ANSWER EITHER. The first version completed a TLS handshake per door and
// called that reached. A handshake proves an address is up and presents a certificate the anchors accept; it
// proves nothing about whether that door has heard of THIS connector, which is the thing that decides whether
// a flow arriving there gets anywhere. So this asks the door by name and with the connector's own credential.
//
// ★★ WHAT A 200 DOES AND DOES NOT PROVE, because the difference was measured on 2026-08-26 and misread. This
// connector's first tunnel upgrade to region-a returned 404 and it failed over to region-b — which reads as a
// dead region and was not one. The fleet had been recreated ninety seconds earlier and that Edge had not yet
// learned of a connector registered seconds before; asked again, both doors served the profile AND upgraded
// the tunnel (101). A door that answers 200 here knows this connector. Whether it will carry a tunnel THIS
// SECOND is a question only the connector's own reconnect answers, and a fleet that has just restarted says
// no to it for a while. Do not read one refusal, seconds after a restart, as a region that is gone.
func verifyDoorsAnswer(stateDir string, st persistedState, doors []door) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) bool {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
		return ok
	}

	anchorPath := strings.TrimSpace(st.EdgeCAPath)
	if anchorPath == "" {
		anchorPath = filepath.Join(stateDir, pinnedAnchorName)
	}
	anchors, count, err := readAnchorPool(anchorPath)
	if err != nil {
		// ★ THE MOMENT NOBODY CAN CHECK AFTERWARDS. Without pinned anchors the connector's FIRST connection —
		// the one carrying its request for an identity — trusted whatever answered. It is too late to fix for
		// this connector; it is not too late to say so.
		add("the connection to the deployment is pinned", false,
			"no usable anchors in %s (%v): this connector cannot verify what it is talking to", anchorPath, err)
		return out
	}
	add("the connection to the deployment is pinned", true, "%s, %d anchor(s)", anchorPath, count)

	identity, ierr := tls.LoadX509KeyPair(filepath.Join(stateDir, identityCertName),
		filepath.Join(stateDir, identityKeyName))
	if ierr != nil {
		add("each door answers this connector", false,
			"this connector's identity cannot be loaded, so the doors cannot be dialled the way it dials them (%v)", ierr)
		return out
	}

	if len(doors) == 0 {
		add("each door answers this connector", false, "there is no door to dial")
		return out
	}
	answered, notes := 0, []string{}
	for _, d := range doors {
		if err := askDoor(d, anchors, identity, st.ConnectorID, st.RuntimeSecret); err != nil {
			notes = append(notes, fmt.Sprintf("%s DID NOT answer for this connector (%v)", d.display(), err))
			continue
		}
		answered++
		notes = append(notes, fmt.Sprintf("%s answered", d.display()))
	}
	switch {
	case answered == 0:
		add("each door answers this connector", false,
			"none of %d answered — %s", len(doors), strings.Join(notes, "; "))
	case answered < len(doors):
		// ★ A PARTIAL ANSWER IS THE DANGEROUS ONE. The connector is up and working, and the failover it is
		// believed to have is not there. Nothing else in this deployment would report it.
		add("each door answers this connector", false,
			"%d of %d answered — %s. Losing the working one takes this site off the network",
			answered, len(doors), strings.Join(notes, "; "))
	default:
		add("each door answers this connector", true, "%d of %d — %s",
			answered, len(doors), strings.Join(notes, "; "))
	}
	return out
}

// verifySurvivesAReboot asks the two questions that decide whether this machine still has a connector tomorrow:
// is the program there, and is anything going to start it.
func verifySurvivesAReboot(stateDir, binary, serviceName string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) bool {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
		return ok
	}

	if _, err := os.Stat(binary); err != nil {
		add("the program this machine starts is on it", false,
			"%s is not there: whatever starts this connector starts nothing", binary)
	} else {
		add("the program this machine starts is on it", true, "%s", binary)
	}

	unit := filepath.Join("/etc/systemd/system", serviceName+".service")
	if _, err := os.Stat(unit); err != nil {
		add("it comes back after a reboot", false,
			"no %s: this connector runs only until this machine restarts, and then everything behind it is unreachable",
			unit)
	} else {
		add("it comes back after a reboot", true, "%s", unit)
	}
	return out
}

// askDoor asks one door for this connector's profile — the request cmd/dsse-connector/profile_poll.go makes on
// every poll, with the same header and the same material. 200 is the only answer that means this door will
// serve this connector.
//
// The status is reported rather than swallowed, because the two failures are different and an operator acts on
// them differently: a transport error is a door that is not there, and an HTTP status is a door that is there
// and will not carry this connector — which is what a region whose Edges have not heard of it looks like.
func askDoor(d door, anchors *x509.CertPool, identity tls.Certificate, connectorID, runtimeSecret string) error {
	base, err := d.baseURL()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, base+"/connectors/"+url.PathEscape(connectorID)+"/profile", nil)
	if err != nil {
		return err
	}
	if runtimeSecret != "" {
		req.Header.Set("x-connector-secret", runtimeSecret)
	}
	req.Header.Set("x-connector-id", connectorID)
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      anchors,
				Certificates: []tls.Certificate{identity},
				MinVersion:   tls.VersionTLS12,
			},
			DialContext: doorDialContext,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d — it answers, and not for this connector", resp.StatusCode)
	}
	return nil
}

// door is one entry of the endpoint list, keeping the region label so a failure names the region an operator
// would go and look at rather than an address they have to map back themselves.
type door struct {
	region string
	url    string
}

func (d door) display() string {
	if d.region == "" {
		return d.url
	}
	return d.region + "=" + d.url
}

func (d door) parsed() (*url.URL, error) {
	raw := d.url
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return url.Parse(raw)
}

// baseURL is the door as the connector dials it: scheme, host and port, no trailing slash.
func (d door) baseURL() (string, error) {
	u, err := d.parsed()
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%q names no host", d.url)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host, "/"), nil
}

// parseDoors reads "region=URL;region=URL" exactly as cmd/dsse-connector/region_failover.go does — the same
// separators (';' ',' newline) and the same trailing-slash trim. ★ IT DID NOT, AND THAT IS A SCREEN THAT LIES:
// splitting only on ';' turned a comma-separated pair into one door, and this installer told the operator
// their site had a single address while the connector was quietly failing over between two.
func parseDoors(raw string) []door {
	out := []door{}
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' || r == '\n' }) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		region, addr := "", field
		if i := strings.Index(field, "="); i > 0 {
			region, addr = strings.TrimSpace(field[:i]), strings.TrimSpace(field[i+1:])
		}
		if addr = strings.TrimRight(addr, "/"); addr == "" {
			continue
		}
		out = append(out, door{region: region, url: addr})
	}
	return out
}

func joinDoors(doors []door) string {
	parts := make([]string, 0, len(doors))
	for _, d := range doors {
		parts = append(parts, d.display())
	}
	return strings.Join(parts, ", ")
}

func readCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no %s on this machine", filepath.Base(path))
	}
	for rest := raw; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return nil, fmt.Errorf("%s holds no certificate", filepath.Base(path))
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("%s cannot be parsed: %w", filepath.Base(path), perr)
		}
		return cert, nil
	}
}

// readAnchorPool parses every anchor, skipping unparseable blocks the way the connector's own loader does: a
// corrupt extra anchor during a rotation must not read as "no anchors".
func readAnchorPool(path string) (*x509.CertPool, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	pool, n := x509.NewCertPool(), 0
	for rest := raw; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			continue
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, 0, fmt.Errorf("no parseable certificate")
	}
	return pool, n, nil
}

func certNames(cert *x509.Certificate, connectorID string) bool {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(cert.Subject.CommonName), connectorID) {
		return true
	}
	for _, name := range cert.DNSNames {
		if strings.EqualFold(strings.TrimSpace(name), connectorID) {
			return true
		}
	}
	return false
}

func roundDuration(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return d.Round(time.Minute).String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// reportVerify prints the walk and returns an error when any check failed, so the exit status is usable from
// whatever ran it.
func reportVerify(stateDir string, results []verifyResult) error {
	failed := 0
	fmt.Printf("dsse-connector-install -verify: %s\n\n", stateDir)
	for _, r := range results {
		mark := "ok  "
		if !r.ok {
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("  %s  %-44s %s\n", mark, r.name, r.note)
	}
	fmt.Println()
	if failed > 0 {
		fmt.Printf("dsse-connector-install -verify: %d of %d checks failed — the assets behind this connector are "+
			"NOT reliably reachable.\n", failed, len(results))
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Printf("dsse-connector-install -verify: %d checks passed — this connector enrolled, carries an identity "+
		"this deployment issued, and every door it knows answers it.\n", len(results))
	return nil
}

// doorDialContext is how this check reaches a door. It is a package variable ONLY so a test can reach a
// server it started itself without depending on the operating system to resolve a name.
//
// ★ RFC 6761 says every ".localhost" name resolves to loopback, and Linux and macOS honour that. Windows
// does not: the same test that passes on every CI runner fails there with "lookup edge.localhost: i/o
// timeout", and a developer box that is permanently red for a reason unrelated to the code stops being able
// to report a real break. Rather than make the test avoid names — the thing it is actually checking — the
// dial is the seam.
//
// Production never touches this: it is the ordinary dialer, with the same timeout it always had.
var doorDialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
