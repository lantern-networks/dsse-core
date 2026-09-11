package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// verify_connector.go — the sixth step of the install order.
//
// ★★★ IT COMES AFTER THE EDGES, AND THE ORDER IS A CONSEQUENCE, NOT A PREFERENCE. A connector holds no
// per-device token and no person is present at its first start; what it presents is its Site's bootstrap
// secret, and the party that checks it is an EDGE, because a connector reaches nothing else. So it needs
// three things that only exist by then: a Site created on the control plane, that Site carried to the Edge in
// the config bundle, and an Edge holding its organization's device-identity authority.
//
// ★★★ AND THE ONE THING WORTH CHECKING IS THE REFUSAL. A connector enrolling is a path; a connector enrolling
// under an organization it merely NAMED is a boundary. The secret is looked up within the claimed
// organization, so presenting a valid secret while claiming another organization finds nothing to match —
// the organization is proven by the match and never taken from the request. A deployment where that is
// reversed hands one customer an identity issued under another's authority, which no screen would show.
//
// ★ IT CREATES A SITE AND TAKES IT BACK OUT. The Site catalogue is replace-all from the control plane, so a
// leftover verification Site keeps a bootstrap secret live on every Edge in the fleet.
// ★ THE RETURN VALUE IS NAMED, and that is load-bearing. The cleanup below runs in a defer and APPENDS its
// result; with an unnamed return the slice has already been copied by then, so the Site removal ran and its
// verdict was silently dropped — a check that reported nothing whether it worked or not. Found by noticing
// the line was missing from the output, which is the only way it could have been found.
func verifyConnector(client *http.Client, dir, cpAdmin, edgeTransport, edgeAdmin, token, tenant string) (out []verifyResult) {
	out = []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}
	cpAdmin = strings.TrimRight(cpAdmin, "/")
	edgeTransport = strings.TrimRight(edgeTransport, "/")
	edgeAdmin = strings.TrimRight(edgeAdmin, "/")

	siteID := "dsse-install-verification-" + strings.ToLower(randomSecret()[:8])
	body, _ := json.Marshal(map[string]any{"site_id": siteID, "name": "installer verification"})
	code, raw, err := post(client, cpAdmin+"/admin/sites", token, body)
	if err != nil || (code != 200 && code != 201) {
		if code == 403 {
			add("the connector path was checked", false,
				"not checked: the credential given may not author Sites (403). Pass a token with "+
					"admin.connectors.write, or run this before -bootstrap-admin")
			return out
		}
		add("a Site can be created on the control plane", false,
			"POST /admin/sites -> %d %v (%s)", code, err, first(raw, 140))
		return out
	}
	add("a Site can be created on the control plane", true, "%s", siteID)
	defer func() {
		// Reported rather than swallowed: a Site this installer created and could not remove keeps a
		// bootstrap secret live on every Edge.
		code, _, derr := deleteAt(client, cpAdmin+"/admin/sites/"+siteID, token)
		if derr != nil || (code != 200 && code != 204 && code != 404) {
			out = append(out, verifyResult{name: "the verification Site was removed", ok: false,
				note: fmt.Sprintf("DELETE /admin/sites/%s -> %d %v. Its bootstrap secret is still accepted by "+
					"every Edge; remove it before handing the deployment over", siteID, code, derr)})
		} else {
			out = append(out, verifyResult{name: "the verification Site was removed", ok: true, note: siteID})
		}
	}()

	code, raw, err = post(client, cpAdmin+"/admin/sites/"+siteID+"/enrollment-command", token, []byte(`{}`))
	if err != nil || (code != 200 && code != 201) {
		add("the control plane issues a connector's bootstrap secret", false,
			"POST /admin/sites/%s/enrollment-command -> %d %v (%s)", siteID, code, err, first(raw, 140))
		return out
	}
	var issued struct {
		BootstrapSecret string `json:"bootstrap_secret"`
		TenantID        string `json:"tenant_id"`
	}
	if json.Unmarshal(raw, &issued) != nil || strings.TrimSpace(issued.BootstrapSecret) == "" {
		add("the control plane issues a connector's bootstrap secret", false, "no bootstrap secret was returned")
		return out
	}
	add("the control plane issues a connector's bootstrap secret", true, "shown once, only its hash is kept")
	if strings.TrimSpace(tenant) == "" {
		tenant = strings.TrimSpace(issued.TenantID)
	}

	// ★ THE SITE HAS TO TRAVEL BEFORE THE EDGE CAN CHECK ANYTHING. It goes in the config bundle, so the Edge
	// is briefly behind — and that is not a defect, it is how configuration moves. Waiting bounded is the
	// difference between checking the deployment and checking the poll interval.
	connectorID := "dsse-install-connector-" + strings.ToLower(randomSecret()[:8])
	keyPEM, csrPEM, cerr := generateVerificationCSR(connectorID)
	if cerr != nil {
		add("a connector can enrol through the Edge", false, "could not build a request: %v", cerr)
		return out
	}
	enrol := func(claimedTenant string) (int, []byte) {
		payload, _ := json.Marshal(map[string]any{
			"device_id": connectorID,
			"tenant":    claimedTenant,
			"eligibility": map[string]string{
				"mode": "connector", "site": siteID, "token": issued.BootstrapSecret,
			},
			"csr_pem": string(csrPEM),
		})
		c, b, _ := post(client, edgeTransport+"/enroll", "", payload)
		return c, b
	}
	code, raw = enrol(tenant)
	for waited := 0; code != 200 && waited < connectorSiteTravelWait; waited += 5 {
		time.Sleep(5 * time.Second)
		code, raw = enrol(tenant)
	}
	if code != 200 {
		add("a connector can enrol through the Edge", false,
			"POST /enroll (mode=connector) -> %d after %ds (%s). The Site is authored on the control plane and "+
				"reaches an Edge in the config bundle; an Edge that never receives it can admit no connector",
			code, connectorSiteTravelWait, first(raw, 160))
		return out
	}
	add("a connector can enrol through the Edge", true, "an identity was issued under %s", tenant)

	// ★★★ AND THEN IT USES IT. Enrolling proves the deployment can MINT a connector identity; taking its place
	// proves a connector holding one can join. Those are different deployments and this is the second.
	if issuedCert := enrolledCertificatePEM(raw); issuedCert != "" {
		out = append(out, verifyConnectorTakesItsPlace(dir, edgeTransport, cpAdmin, token, tenant, connectorID,
			siteID, issued.BootstrapSecret, []byte(issuedCert), keyPEM, client)...)
	}

	// ★★★ THE BOUNDARY. The same valid secret, claiming a different organization.
	other := "dsse-install-verification-other-org"
	code, raw = enrol(other)
	add("a connector cannot be issued under an organization it merely names", code != 200,
		"claiming %q with this Site's real secret answered %d — the organization is proven by the match, or "+
			"one customer's connector is issued under another's authority", other, code)

	// The connector's identity is in the enrolled inventory; take it back out.
	code, _, err = deleteAt(client, cpAdmin+"/admin/enrolled-devices/"+connectorID, token)
	if err != nil || (code != 200 && code != 204 && code != 404) {
		add("the verification connector was removed", false,
			"DELETE /admin/enrolled-devices/%s -> %d %v", connectorID, code, err)
	} else {
		add("the verification connector was removed", true, "%s", connectorID)
	}
	return out
}

// connectorSiteTravelWait bounds how long the Site is given to reach the Edge. Being behind for a poll is how
// configuration moves; staying behind is the defect.
const connectorSiteTravelWait = 60
