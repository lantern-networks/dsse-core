package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ A CUSTOMER'S DEVICE REGISTERS AND HEARTBEATS ON A NODE WHOSE OWN BUNDLE IS THE OPERATOR'S (2026-09-01,
// measured on a three-region deployment with a real Windows box).
//
// Walked through the HANDLERS, not the helper: the defect was never in a comparison, it was in what three
// call sites handed to it — evaluator.PolicyBundle, this node's own. A test of the helper alone would have
// passed against the broken build.
func TestACustomersDeviceIsAdmittedByAnEdgeWhoseOwnBundleIsTheOperators(t *testing.T) {
	const device, customer = "skusanagi-win10", "tenant_eksuhxrdhdimxjq2mbgqhd6tha"

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll(device, customer, "admitted by the deployment", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// testEvaluator's bundle is tenant_lab_001 — this node's own, and NOT the customer's, which is the whole
	// situation: the fleet credential belongs to the operator, so the bundle it pulled always will.
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: &recordingDomainEventOutbox{},
		EnrolledLedger:    ledger,
	})

	register := provenDeviceRequest(http.MethodPost, "/devices/register", device, `{
		"id":"`+device+`",
		"tenant_id":"`+customer+`",
		"hostname":"skusanagi-win10",
		"os":"windows",
		"agent_version":"0.3.0",
		"status":"registered"
	}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, register)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d, want %d; on a deployment that serves customers this is EVERY device: %s",
			rec.Code, http.StatusCreated, strings.TrimSpace(rec.Body.String()))
	}
	var dev model.Device
	if err := json.NewDecoder(rec.Body).Decode(&dev); err != nil {
		t.Fatalf("decode device: %v", err)
	}
	if dev.TenantID != customer {
		t.Errorf("recorded into %q, want the customer's organization %q", dev.TenantID, customer)
	}

	beat := provenDeviceRequest(http.MethodPost, "/devices/"+device+"/heartbeat", device, `{
		"tenant_id":"`+customer+`",
		"agent_version":"0.3.0",
		"status":"healthy"
	}`)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, beat)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("heartbeat = %d, want %d; a refused heartbeat is a device that goes on being carried and "+
			"decrypted while the deployment shows it as absent: %s",
			rec.Code, http.StatusAccepted, strings.TrimSpace(rec.Body.String()))
	}
}

// ★ AND THE ORGANIZATION IS STILL NOT THE REQUEST'S TO CHOOSE. The tenant comes from the enrolled inventory
// keyed by the proven identity; a body claiming a different one is refused, which is the check the old
// comparison was meant to be making and could not, because it was comparing against the node instead.
func TestADeviceCannotNameItsOwnOrganization(t *testing.T) {
	const device, customer = "skusanagi-win10", "tenant_eksuhxrdhdimxjq2mbgqhd6tha"

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll(device, customer, "admitted by the deployment", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: &recordingDomainEventOutbox{},
		EnrolledLedger:    ledger,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, provenDeviceRequest(http.MethodPost, "/devices/register", device, `{
		"id":"`+device+`",
		"tenant_id":"tenant_somebody_else",
		"os":"windows",
		"status":"registered"
	}`))
	if rec.Code == http.StatusCreated {
		t.Fatalf("a device named another organization and was recorded into it: %s", strings.TrimSpace(rec.Body.String()))
	}
}

// provenDeviceRequest builds a request carrying a verified device certificate for cn — what the (T) transport
// listener produces, and the gate the device lane reads its identity from.
func provenDeviceRequest(method, path, cn, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	return r
}
