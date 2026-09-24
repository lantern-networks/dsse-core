package enroll

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
)

// enroll_server.go — the Control Plane side of enrollment. The Issuer verifies eligibility + assigns
// tenant/group (Assign), signs the device CSR with the device CA (deviceca.Signer), records the admission
// (Record), and returns the issued cert + CA + AUTHORITATIVE assignment. The device NEVER dictates its
// tenant/group — Assign (CP policy) does. Refused enrollments return Response.Error.

// Assigner is the CP's eligibility check + tenant/group assignment. It returns ok=false to REFUSE (reason is
// surfaced to the client). A weak eligibility (token, no user) should map to a restricted group here.
type Assigner func(req Request) (tenant, group, reason string, ok bool)

// RecordFunc records a successful enrollment (e.g. enrolledinventory.Ledger.Enroll). Optional.
//
// ★ IT RETURNS AN ERROR, AND THE ISSUE IS REFUSED WHEN IT DOES (2026-08-12, nineteenth review). It used to
// return nothing, so the ledger's own refusals — a disabled identity, or one belonging to another tenant —
// could be logged and nothing else: the endpoint had already decided to answer 200 and hand over a
// certificate. A record that cannot say no is not a check, it is a note, and every guard added inside it was
// decoration until this signature changed.
type RecordFunc func(deviceID, tenant, group string) error

// RecordWithMachineFunc is RecordFunc plus what the agent said about the machine. When set it is used instead
// of Record — a separate hook rather than a changed signature, so every existing caller keeps compiling and
// keeps behaving identically.
type RecordWithMachineFunc func(deviceID, tenant, group, machineRef string) error

// Refusal is a refusal whose REASON is meant to reach whoever is setting the machine up.
//
// ★★ EVERY REFUSAL USED TO READ "not eligible", AND THAT IS RIGHT FOR ALMOST ALL OF THEM. Why a device was
// turned away is generally the deployment's business, not the caller's: "this identity belongs to another
// organization" tells a caller something about an organization that is not theirs.
//
// ★ BUT SOME REFUSALS EXIST TO BE ACTED ON, and by exactly the person holding the machine. "A different machine
// is already enrolled under this computer name — rename it" is useless in a log the installer will never read,
// and it discloses nothing beyond "that name is taken" to a caller who already holds a one-time credential an
// administrator issued for this organization. Those refusals say so by being this type; every other one keeps
// the flat answer.
type Refusal struct{ Reason string }

func (r Refusal) Error() string { return r.Reason }

// refusalForCaller returns what the device is told: the reason when the refusal was written to be acted on,
// and the flat answer otherwise.
func refusalForCaller(err error) string {
	var r Refusal
	if errors.As(err, &r) && strings.TrimSpace(r.Reason) != "" {
		return r.Reason
	}
	return "not eligible"
}

// recordFunc is whichever recorder was configured, adapted to one shape.
func (i Issuer) recordFunc() RecordWithMachineFunc {
	if i.RecordWithMachine != nil {
		return i.RecordWithMachine
	}
	if i.Record != nil {
		return func(deviceID, tenant, group, _ string) error { return i.Record(deviceID, tenant, group) }
	}
	return nil
}

// Issuer is the server-side enrollment issuer.
type Issuer struct {
	Signer *deviceca.Signer
	// SignerFor picks the authority a particular organization's devices are issued under, when the deployment
	// holds one per organization.
	//
	// ★★★ ONE SIGNER MEANT ONE ORGANIZATION COULD ENROL (2026-08-21, measured). The endpoint verified the
	// eligibility token against the NODE's organization, because a certificate signed by the node's device CA
	// identifies its devices as the node's organization — the tenant CA registry resolves a device by the CA
	// that issued it. So an administrator of any other organization could mint an enrolment token (201) that
	// no device could ever use (403), and the reason appeared only in the operator's log.
	//
	// Returning nil means this node has no authority for that organization, and the caller refuses rather than
	// issuing under the wrong one — a certificate that identifies a customer's laptop as somebody else's is
	// worse than a refusal.
	SignerFor func(tenantID string) *deviceca.Signer
	Assign    Assigner
	// AssignContext takes precedence when a request must carry cancellation or authority fencing.
	AssignContext func(context.Context, Request) (tenant, group, reason string, ok bool)
	CertTTL       time.Duration
	Record        RecordFunc // optional
	// RecordWithMachine takes precedence over Record when set. See RecordWithMachineFunc.
	RecordWithMachine RecordWithMachineFunc
	Logf              func(string, ...interface{}) // optional
	NowPolicyVersion  int                          // policy version stamped into the response (optional)
}

func (i Issuer) logf(format string, args ...interface{}) {
	if i.Logf != nil {
		i.Logf(format, args...)
	}
}

// Handler returns the HTTP handler for POST <enroll endpoint>. Wire it in cmd/edge (M4c). It is self-contained
// and unit-tested via httptest against the client (Run) for a full keygen→CSR→issue→validate E2E.
func (i Issuer) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, Response{Error: "method not allowed"})
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, Response{Error: "bad request"})
			return
		}
		if req.DeviceID == "" || req.CSRPEM == "" {
			writeJSON(w, http.StatusBadRequest, Response{Error: "device_id and csr required"})
			return
		}
		var tenant, group, reason string
		var ok bool
		if i.AssignContext != nil {
			tenant, group, reason, ok = i.AssignContext(r.Context(), req)
		} else {
			tenant, group, reason, ok = i.Assign(req)
		}
		if !ok {
			if reason == "" {
				reason = "not eligible"
			}
			i.logf("enroll_refused device=%q reason=%q", req.DeviceID, reason)
			writeJSON(w, http.StatusForbidden, Response{Error: reason})
			return
		}
		// Mint the cert with the CP-AUTHORITATIVE identity (device id + assigned tenant/group), NOT the
		// device-controlled CSR subject — the CSR only proves possession of the key. This binds the actual
		// certificate (what is presented downstream) to the CP's assignment, so a device cannot impersonate
		// another device/tenant via its CSR subject.
		subject := pkix.Name{CommonName: req.DeviceID, Organization: []string{tenant}}
		if group != "" {
			subject.OrganizationalUnit = []string{group}
		}
		signer := i.Signer
		if i.SignerFor != nil {
			if per := i.SignerFor(tenant); per != nil {
				signer = per
			} else if i.Signer == nil {
				writeJSON(w, http.StatusForbidden, Response{Error: "this node cannot issue an identity for that organization"})
				return
			}
		}
		certPEM, err := signer.Sign([]byte(req.CSRPEM), subject, i.CertTTL)
		if err != nil {
			i.logf("enroll_sign_error device=%q err=%v", req.DeviceID, err)
			writeJSON(w, http.StatusBadRequest, Response{Error: "invalid csr"})
			return
		}
		// ★ RECORDED BEFORE THE CERTIFICATE IS HANDED OVER. The record is where the ledger decides whether this
		// enrolment may happen at all, so a refusal has to reach the caller as a refusal — not as a 200 with a
		// usable identity and a line in a log nobody is reading. The signing above produces bytes and no side
		// effect; this is the write.
		if record := i.recordFunc(); record != nil {
			if err := record(req.DeviceID, tenant, group, req.MachineRef); err != nil {
				i.logf("enroll_refused device=%q tenant=%q reason=%q", req.DeviceID, tenant, err.Error())
				writeJSON(w, http.StatusForbidden, Response{Error: refusalForCaller(err)})
				return
			}
		}
		// ★ AND FROM WHERE. An enrolment is the moment a machine becomes a member of this deployment, and
		// "which machine asked" is part of that record — a device enrolling from an address nobody expected is
		// the shape of a stolen token being spent. Behind an L4 front door this is the DEVICE's address only
		// because the front door states it and the Edge is configured to believe that front door and no other;
		// without both, every enrolment in the region reads as coming from the same place.
		i.logf("enroll_issued device=%q tenant=%q group=%q source=%q", req.DeviceID, tenant, group, peerAddress(r))
		writeJSON(w, http.StatusOK, Response{
			CertPEM:       string(certPEM),
			CAPEM:         string(signer.CAPEM()),
			Tenant:        tenant,
			Group:         group,
			PolicyVersion: i.NowPolicyVersion,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// peerAddress is the address the request arrived from, taken from the connection and never from a header the
// caller could write.
func peerAddress(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
