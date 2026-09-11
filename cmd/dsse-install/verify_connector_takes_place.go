package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// verify_connector_takes_place.go — step 6 of the install order, past the point it used to stop.
//
// ★★★ ENROLLING IS NOT TAKING ITS PLACE, THE SAME WAY IT WAS NOT FOR A DEVICE. The walk issued a connector an
// identity and threw the private key away, so what it established was that the deployment can MINT one —
// never that a connector holding it can register, be counted, or front anything. A customer's connector that
// enrols and is then refused is a deployment that looks correct on every screen and reaches no internal asset
// at all.
//
// ★★ AND A CONNECTOR REACHES ONLY THE EDGE. Everything it needs arrives through the region's door: it has no
// route to the control plane and no listener of its own. So this registers through the same door a device
// steers through, which is the only door it will ever have.

// connectorMTLSClient builds a client that presents the connector's issued certificate, verifying the
// deployment against its own anchor.
func connectorMTLSClient(dir string, certPEM, keyPEM []byte) (*http.Client, error) {
	anchor, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		return nil, fmt.Errorf("read the deployment anchor: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(anchor) {
		return nil, fmt.Errorf("the deployment anchor contains no certificate")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the issued connector certificate and its key do not pair: %w", err)
	}
	// ★★★ AND IT DIALS WHERE THE REST OF THE WALK DIALS. deploymentClient carries the NAME@ADDRESS overrides
	// so that a walk run from a machine whose resolver does not know this deployment's names can still reach
	// it. This client cannot be that one — a connector must present a client certificate — and it was built
	// without them, so on exactly those machines every other check passed and this one alone reported
	//
	//	POST /connectors/register -> dial tcp: lookup agents.<region>.<deployment>: no such host
	//
	// which reads as an Edge that refuses connectors. The overrides belong to every client the walk makes,
	// not to the first one that needed them.
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
	}}
	transport.DialContext = dialWithOverrides
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}

// verifyConnectorTakesItsPlace registers the connector the deployment just issued, and asks the Edge whether
// it is now one of its own.
func verifyConnectorTakesItsPlace(dir, edgeDoor, cpAdmin, adminToken, tenant, connectorID, siteID, siteSecret string,
	certPEM, keyPEM []byte, adminClient *http.Client) []verifyResult {
	out := []verifyResult{}
	client, err := connectorMTLSClient(dir, certPEM, keyPEM)
	if err != nil {
		return append(out, verifyResult{name: "the connector can take its place",
			note: fmt.Sprintf("could not present the issued identity: %v", err)})
	}
	body, _ := json.Marshal(map[string]any{
		"id": connectorID, "tenant_id": tenant, "connector_group_id": siteID,
		"name": "installer verification connector",
		// ★ A CONNECTOR EXISTS TO FRONT SOMETHING, so the deployment requires it to say what. This one fronts
		// an address that is deliberately unroutable: the check establishes that a connector can JOIN, and a
		// verification run must not leave a route to anything real behind it.
		"private_base_url": "https://installer-verification.invalid",
	})
	req, rerr := http.NewRequest(http.MethodPost, strings.TrimRight(edgeDoor, "/")+"/connectors/register",
		strings.NewReader(string(body)))
	if rerr != nil {
		return append(out, verifyResult{name: "the connector can take its place", note: rerr.Error()})
	}
	req.Header.Set("content-type", "application/json")
	// The Site's bootstrap secret is what authorises a connector's FIRST registration, exactly as it
	// authorised its enrolment — the connector has nothing else yet.
	req.Header.Set("x-connector-secret", siteSecret)
	resp, derr := client.Do(req)
	if derr != nil {
		return append(out, verifyResult{name: "the connector can take its place",
			note: fmt.Sprintf("POST /connectors/register -> %v", derr)})
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// The reason travels with the number. A check that reports a bare status costs whoever reads it an
		// investigation the deployment already did.
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return append(out, verifyResult{name: "the connector can take its place",
			note: fmt.Sprintf("POST /connectors/register -> %d %s. It holds a certificate this deployment "+
				"issued and cannot join it, so no internal asset behind it is reachable by anybody",
				resp.StatusCode, first(reason, 200))})
	}
	out = append(out, verifyResult{ok: true, name: "the connector can take its place",
		note: fmt.Sprintf("%s registered with the identity it was just issued", connectorID)})

	// ★★★ AND THE AUTHORITY COUNTS IT — not the node it happened to reach. A connector reaches only an Edge,
	// so a registration lands wherever the region's door sent it; if that never travels to the control plane,
	// the connector is known to exactly one node. Every screen reads the authority, and a route authored
	// there has nothing to attach to. Measured on a two-Edge fleet: edge-a held one connector, edge-b held
	// another, and the control plane held none.
	code, raw, derr := get(adminClient, strings.TrimRight(cpAdmin, "/")+"/admin/connectors", adminToken)
	if derr != nil || code != 200 {
		return append(out, verifyResult{name: "the authority counts the connector",
			note: fmt.Sprintf("GET /admin/connectors on the control plane -> %d %v", code, derr)})
	}
	if !strings.Contains(string(raw), connectorID) {
		return append(out, verifyResult{name: "the authority counts the connector",
			note: fmt.Sprintf("%s registered on an Edge and the control plane does not name it. A connector "+
				"reaches only an Edge, so what it delivers has to be carried to the authority — and this is "+
				"not. Every screen reads the authority, and a route authored there has no connector to attach "+
				"to", connectorID)})
	}
	out = append(out, verifyResult{ok: true, name: "the authority counts the connector",
		note: fmt.Sprintf("%s is one of this deployment's connectors", connectorID)})

	// ★★★ AND IT IS TAKEN BACK OUT. A check that registers a connector and leaves it teaches an operator to
	// distrust the connector list — and this one fronts an address that does not exist, so what it leaves
	// behind is a route to nowhere with a real identity attached. Reported rather than swallowed, for the
	// same reason the Site and the device are: something this installer created and could not remove is
	// something somebody has to know about.
	code, _, derr = deleteAt(adminClient, strings.TrimRight(cpAdmin, "/")+"/admin/connectors/"+connectorID, adminToken)
	switch {
	case derr == nil && (code == 200 || code == 204):
		return append(out, verifyResult{ok: true, name: "the verification connector's registration was removed",
			note: connectorID})
	case code == 404:
		// ★ WHICH IS THE SAME FINDING AGAIN, FROM THE OTHER SIDE. The authority cannot remove what it was
		// never told about. Reported rather than passed over: this run has left a registration on one node of
		// the fleet, fronting an address that does not exist, and an operator has to know which.
		return append(out, verifyResult{name: "the verification connector's registration was removed",
			note: fmt.Sprintf("%s could not be removed through the control plane, which does not name it. It "+
				"is registered on whichever Edge the region's door sent it to, and has to be removed there",
				connectorID)})
	default:
		return append(out, verifyResult{name: "the verification connector's registration was removed",
			note: fmt.Sprintf("DELETE /admin/connectors/%s -> %d %v", connectorID, code, derr)})
	}
}
