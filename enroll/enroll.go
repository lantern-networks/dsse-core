// Package enroll is the platform-neutral endpoint-side enrollment core. A fresh, unenrolled agent generates a
// device keypair + CSR, presents an eligibility credential (MDM/token/interactive), and asks the Control Plane
// to issue a device identity certificate and assign its tenant + group. This package does the crypto + protocol
// + the SECURITY VALIDATION of what the CP returns; the CA-side issuance and the Windows storage (TPM/DPAPI)
// are separate.
//
// Key security property (ValidateIssuedCert): the issued cert must (a) chain to the CA the CP returned AND
// (b) carry OUR public key — so a CP (or an on-path attacker) cannot hand us a certificate minted for someone
// else's key. The tenant/group in the response are the CP's authoritative assignment; the device never
// self-asserts them.
package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Eligibility is how the device proves it is allowed to enroll. A weak credential (token, no user) must map
// to a restricted group server-side — the CP enforces that, not this package.
type Eligibility struct {
	Mode  string `json:"mode"` // mdm | token | interactive | connector
	Token string `json:"token,omitempty"`
	// Site names the connector group a "connector"-mode caller is enrolling into, and is meaningless in every
	// other mode. A connector cannot prove itself the way a device does — it holds no per-device token and no
	// person is present — so what it presents is the Site's bootstrap secret, and the server needs to know
	// WHICH Site to check it against.
	//
	// ★ THIS IS A CLAIM, NOT A CREDENTIAL, and the server treats it as one: the secret is checked against the
	// named Site WITHIN the claimed organization, so naming somebody else's Site simply fails to match. Same
	// shape as Tenant on the request beside it — a hint that has to survive being checked.
	Site string `json:"site,omitempty"`
}

// Request is the enrollment request the agent POSTs. Tenant is a REQUESTED hint; the CP is authoritative.
type Request struct {
	DeviceID    string      `json:"device_id"`
	Tenant      string      `json:"tenant,omitempty"`
	Eligibility Eligibility `json:"eligibility"`
	CSRPEM      string      `json:"csr_pem"`
	// MachineRef is what the agent can say about the MACHINE, as opposed to the name it enrols under.
	//
	// ★★★ WITHOUT IT A SECOND ENROLMENT OF ONE NAME HAS TWO CAUSES AND THE DEPLOYMENT CANNOT TELL THEM APART
	// (the operator's point, 2026-08-25). Since a device enrols under the name its own operating system gives
	// it, two machines called "laptop" are ordinary — and "already enrolled" then means either the same machine
	// coming back (renew) or a namesake that must be renamed. The refusal had to name both and let an operator
	// guess, while the one-time token was already spent.
	//
	// ★ IT IS EVIDENCE, NEVER A CREDENTIAL. The agent reports it, so any caller can claim any value: it is used
	// ONLY to distinguish those cases and to notice a machine that has been renamed, and it can neither grant
	// an enrolment nor widen one. Absent is fine and means the deployment answers as it did before.
	MachineRef string `json:"machine_ref,omitempty"`
}

// Response is what the CP returns on success: the issued device cert + the CA to pin, and the AUTHORITATIVE
// tenant/group assignment. Error is set (and the rest empty) on refusal.
type Response struct {
	CertPEM string `json:"cert_pem"`
	// CAPEM is the CA that ISSUED the certificate above — the device-identity CA. It is what the device uses
	// to prove its own chain, and it is NOT the root set for verifying the Edge.
	//
	// ★ THE NAME INVITED EXACTLY THAT MISTAKE (2026-08-12, found on win-dev-1). The Windows agent built its
	// transport with this as the server trust anchor, so the moment a box enrolled, every (T) call failed with
	// "certificate signed by unknown authority" — the device-issuing CA and the transport CA are different
	// PKIs by design. On a fail-open box the result was every flow going direct and unmediated; on a
	// fail-closed one it would be no network at all.
	//
	// The Edge's server certificate is verified against the TRANSPORT anchors: the install profile's pin plus
	// whatever the signed trust bundle has adopted. That channel is signed by the agent-policy key and it
	// ROTATES; this field is issued once, at enrolment, and never again — a device whose transport trust came
	// from here could never follow a CA rotation, and would look enrolled the whole time.
	CAPEM         string `json:"ca_pem"`
	Tenant        string `json:"tenant"`
	Group         string `json:"group"`
	PolicyVersion int    `json:"policy_version,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Doer is the minimal HTTP client used to POST the enrollment (http.Client satisfies it; tests inject a mock).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// GenerateKeyAndCSR creates a fresh device keypair (ECDSA P-256) and a CSR (CN=deviceID, O=tenant). The private
// key never leaves the device; only the CSR is sent. Returns PEM-encoded key and CSR.
func GenerateKeyAndCSR(deviceID, tenant string) (keyPEM, csrPEM []byte, err error) {
	if strings.TrimSpace(deviceID) == "" {
		return nil, nil, errors.New("enroll: device id required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: keygen: %w", err)
	}
	subj := pkix.Name{CommonName: deviceID}
	if tenant != "" {
		subj.Organization = []string{tenant}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subj}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: csr: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// ValidateIssuedCert checks the cert the CP returned: (a) it chains to the returned CA, (b) its public key
// equals OUR key, and (c) IF caPinSHA256 is non-empty, the returned CA's SHA-256 matches that pre-provisioned
// anchor. (a)+(b) alone prove only INTERNAL CONSISTENCY, not authenticity — the returned CA is otherwise
// untrusted, so a rogue CP / on-path attacker could return its own CA + a cert legitimately minted for our key
// and pass. AUTHENTICITY therefore requires either (c) a pinned CA anchor (from the signed install profile) OR
// that enrollment runs over an already-authenticated/pinned transport. caPinSHA256 empty = (c) skipped; do NOT
// rely on this function for trust without a pin or a pinned channel.
func ValidateIssuedCert(certPEM, caPEM, keyPEM []byte, caPinSHA256 string) error {
	cert, err := parseCert(certPEM)
	if err != nil {
		return fmt.Errorf("enroll: parse issued cert: %w", err)
	}
	ca, err := parseCert(caPEM)
	if err != nil {
		return fmt.Errorf("enroll: parse ca: %w", err)
	}
	if p := strings.TrimSpace(strings.TrimPrefix(caPinSHA256, "sha256:")); p != "" {
		sum := sha256.Sum256(ca.Raw)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), p) {
			return errors.New("enroll: returned CA does not match the pinned enrollment anchor")
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("enroll: issued cert does not chain to the returned CA: %w", err)
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return fmt.Errorf("enroll: parse our key: %w", err)
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certPub.Equal(&key.PublicKey) {
		return errors.New("enroll: issued cert public key does not match our device key")
	}
	return nil
}

// Enroll POSTs the request to the CP enrollment endpoint and decodes the response. A non-2xx or a response with
// Error set is returned as an error (the caller stays Unenrolled and retries).
func Enroll(ctx context.Context, endpoint string, req Request, doer Doer) (Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := doer.Do(httpReq)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out Response
	if e := json.Unmarshal(raw, &out); e != nil {
		return Response{}, fmt.Errorf("enroll: decode response (status %d): %w", resp.StatusCode, e)
	}
	if out.Error != "" {
		return out, fmt.Errorf("enroll: refused: %s", out.Error)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("enroll: status %d", resp.StatusCode)
	}
	return out, nil
}

// Result is a completed enrollment ready to persist: the device key + issued cert + CA to pin + assignment.
type Result struct {
	KeyPEM        []byte
	CertPEM       []byte
	CAPEM         []byte
	Tenant        string
	Group         string
	PolicyVersion int
}

// Run drives the full endpoint-side enrollment: generate key+CSR, POST, and VALIDATE the issued cert (including
// the caPin anchor cross-check) before returning it for storage. On any failure it returns an error and no
// Result (the agent stays Unenrolled and keeps its safe fail-closed posture). caPin (SHA-256 of the expected
// device CA, e.g. from the signed install profile) SHOULD be supplied so enrollment is not MITM-able; empty
// caPin requires the `doer`/endpoint to already be a pinned/authenticated transport.
func Run(ctx context.Context, endpoint, deviceID, tenant, caPin string, elig Eligibility, doer Doer) (Result, error) {
	return RunWithMachine(ctx, endpoint, deviceID, tenant, caPin, elig, "", doer)
}

// RunWithMachine is Run plus what this agent can say about the MACHINE, as opposed to the name it enrols
// under. See Request.MachineRef: it is evidence, never a credential, and an empty value is the same enrolment
// Run has always performed.
func RunWithMachine(ctx context.Context, endpoint, deviceID, tenant, caPin string, elig Eligibility,
	machineRef string, doer Doer) (Result, error) {
	keyPEM, csrPEM, err := GenerateKeyAndCSR(deviceID, tenant)
	if err != nil {
		return Result{}, err
	}
	resp, err := Enroll(ctx, endpoint, Request{
		DeviceID:    deviceID,
		Tenant:      tenant,
		Eligibility: elig,
		CSRPEM:      string(csrPEM),
		MachineRef:  machineRef,
	}, doer)
	if err != nil {
		return Result{}, err
	}
	if err := ValidateIssuedCert([]byte(resp.CertPEM), []byte(resp.CAPEM), keyPEM, caPin); err != nil {
		return Result{}, err
	}
	return Result{
		KeyPEM: keyPEM, CertPEM: []byte(resp.CertPEM), CAPEM: []byte(resp.CAPEM),
		Tenant: resp.Tenant, Group: resp.Group, PolicyVersion: resp.PolicyVersion,
	}, nil
}

func parseCert(p []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseECKey(p []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("no PEM key")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}
