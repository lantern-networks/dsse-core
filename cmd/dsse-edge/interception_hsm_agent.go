package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// hsmAgentProvider is an edgeplane.InterceptionRootProvider whose signing key lives in a PKCS#11 token held by the
// dsse-hsm-agent sidecar (deploy/reference/hsm-agent), reached over a unix socket.
//
// Why a sidecar rather than linking PKCS#11 into the Edge: PKCS#11 needs cgo, and the Edge builds
// CGO_ENABLED=0 onto `scratch`. Pulling a vendor .so into this process would give up the Tier-0 host hardening
// the trust model counts as a control, and would split the release into two build variants — see the decision
// record, docs/2026-07-28_pki_key_custody_sidecar_decision.ja.md.
//
// Nothing else in the interception path changes: leaf minting already signs through crypto.Signer, so this
// provider slots in where the file-backed one sits.

type hsmAgentProvider struct {
	cert    *x509.Certificate
	certPEM []byte
	// signer is crypto.Signer (not *hsmAgentSigner) so the same provider serves both a single sidecar and the
	// HA pool over several sidecars (interception_hsm_ha.go). The interception path only ever uses the Signer
	// interface, so nothing downstream cares which it is.
	signer crypto.Signer
}

func (p *hsmAgentProvider) Certificate() *x509.Certificate { return p.cert }
func (p *hsmAgentProvider) CertPEM() []byte                { return p.certPEM }
func (p *hsmAgentProvider) Signer() crypto.Signer          { return p.signer }

// KeyCustody makes the admin surface report hardware custody instead of "file" — the whole point of the
// exercise is that an operator can SEE which one they are running (interception_key_custody.go).
func (p *hsmAgentProvider) KeyCustody() string { return "pkcs11" }

// hsmAgentSigner is a crypto.Signer whose private half never exists in this process. Public is answered from
// the key the agent published at startup; Sign is a round trip over the socket.
type hsmAgentSigner struct {
	client *http.Client
	token  string
	keyID  string
	pub    crypto.PublicKey
}

func (s *hsmAgentSigner) Public() crypto.PublicKey { return s.pub }

func (s *hsmAgentSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	name := ""
	switch opts.HashFunc() {
	case crypto.SHA256:
		name = "SHA-256"
	case crypto.SHA384:
		name = "SHA-384"
	case crypto.SHA512:
		name = "SHA-512"
	default:
		return nil, fmt.Errorf("hsm-agent: unsupported hash %v", opts.HashFunc())
	}
	body, err := json.Marshal(map[string]string{
		"key_id": s.keyID,
		"digest": base64.StdEncoding.EncodeToString(digest),
		"hash":   name,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "http://hsm-agent/sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if s.token != "" {
		req.Header.Set("authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// The agent is unreachable. The caller is minting a leaf for a not-yet-seen host, so this becomes a
		// failed handshake for THAT host — fail-closed, exactly as designed. Already-cached leaves are
		// untouched, so the failure degrades gradually rather than cutting everything off at once
		// .
		return nil, fmt.Errorf("hsm-agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm-agent sign returned %s", resp.Status)
	}
	var out struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Signature)
}

// SignCert mints a purpose-bound leaf through the sidecar's /sign-cert. Unlike Sign — which signs an
// arbitrary digest, so a compromised Edge could build and hash a CA:TRUE or client-auth certificate and have the
// token sign it blind — this sends the TEMPLATE and lets the agent set IsCA / KeyUsage / ExtKeyUsage from the
// key's bound purpose, bound the validity, and build the certificate itself. The Edge no longer decides what the
// interception key can mint; the agent does, next to the key. Fail-closed exactly like Sign: an unreachable or
// refusing agent becomes a failed handshake for a not-yet-seen host, never a silent bypass.
func (s *hsmAgentSigner) SignCert(template, issuer *x509.Certificate, leafPub crypto.PublicKey, purpose string) ([]byte, error) {
	leafPubDER, err := x509.MarshalPKIXPublicKey(leafPub)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(template.IPAddresses))
	for _, ip := range template.IPAddresses {
		ips = append(ips, ip.String())
	}
	body, err := json.Marshal(map[string]any{
		"key_id":              s.keyID,
		"purpose":             purpose,
		"issuer_der":          base64.StdEncoding.EncodeToString(issuer.Raw),
		"leaf_public_key_der": base64.StdEncoding.EncodeToString(leafPubDER),
		"serial":              template.SerialNumber.String(),
		"common_name":         template.Subject.CommonName,
		"organization":        template.Subject.Organization,
		"dns_names":           template.DNSNames,
		"ip_addresses":        ips,
		"not_before":          template.NotBefore.UTC().Format(time.RFC3339),
		"not_after":           template.NotAfter.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "http://hsm-agent/sign-cert", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if s.token != "" {
		req.Header.Set("authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm-agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return nil, fmt.Errorf("hsm-agent sign-cert returned %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	var out struct {
		CertificateDER string `json:"certificate_der"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.CertificateDER)
}

// newHSMAgentProvider connects to the sidecar, adopts the named key, and pairs it with a CA certificate.
//
// certPath holds the CA certificate — public material, so the Edge may keep it on disk. When the file is
// absent the certificate is MINTED here, self-signed by the HSM-held key, which is the Day-0 flow: the key is
// born in hardware (agent -generate-key) and the certificate is then issued by it without the private half
// ever leaving the token.
func newHSMAgentProvider(socketPath, token, keyID, certPath, commonName string, now func() time.Time) (*hsmAgentProvider, error) {
	signer, err := newHSMAgentSignerForSocket(socketPath, token, keyID)
	if err != nil {
		return nil, err
	}
	return hsmProviderWithSigner(signer, certPath, commonName, now)
}

// newHSMAgentSignerForSocket dials ONE sidecar socket, adopts the named key, and returns a signer for it. The
// HA pool builds several of these — one per HSM appliance — and requires they all report the same public key.
func newHSMAgentSignerForSocket(socketPath, token, keyID string) (*hsmAgentSigner, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
	pub, resolvedID, err := fetchAgentKey(client, token, keyID)
	if err != nil {
		return nil, err
	}
	return &hsmAgentSigner{client: client, token: token, keyID: resolvedID, pub: pub}, nil
}

// hsmProviderWithSigner pairs a signer (single sidecar OR the HA pool) with the CA certificate — loaded from
// certPath if present, otherwise MINTED, self-signed by the signer, and persisted. Shared by the single and
// pooled constructors so the Day-0 mint path is identical either way.
func hsmProviderWithSigner(signer crypto.Signer, certPath, commonName string, now func() time.Time) (*hsmAgentProvider, error) {
	if now == nil {
		now = time.Now
	}
	if pemBytes, err := os.ReadFile(certPath); err == nil {
		blk, _ := pem.Decode(pemBytes)
		if blk == nil {
			return nil, fmt.Errorf("hsm-agent: %s is not PEM", certPath)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("hsm-agent: parse %s: %w", certPath, err)
		}
		// Verify the persisted certificate belongs to THIS token key, SYNCHRONOUSLY, before the provider is used
		//. Otherwise a stale certificate (from a rebuilt token, a swapped file) is paired with a key
		// it does not match, readiness goes true, and traffic is served under a chain the Edge cannot actually
		// sign — the async health monitor only notices after the window is already open. Fail closed at load.
		if err := edgeplane.VerifySignerMatchesCert(signer, cert); err != nil {
			return nil, fmt.Errorf("hsm-agent: persisted certificate %s does not match the token key — refusing to pair a certificate the key cannot sign under: %w", certPath, err)
		}
		return &hsmAgentProvider{cert: cert, certPEM: pemBytes, signer: signer}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("hsm-agent: read %s: %w", certPath, err)
	}

	cert, certPEM, err := mintSelfSignedWithSigner(signer, commonName, now)
	if err != nil {
		return nil, err
	}
	if certPath != "" {
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return nil, fmt.Errorf("hsm-agent: persist minted CA cert: %w", err)
		}
	}
	return &hsmAgentProvider{cert: cert, certPEM: certPEM, signer: signer}, nil
}

// fetchAgentKey resolves the key id and its public key from the agent. An empty keyID adopts the only key the
// agent holds; with several, the caller must name one rather than have the Edge guess which CA it is using.
func fetchAgentKey(client *http.Client, token, keyID string) (crypto.PublicKey, string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://hsm-agent/keys", nil)
	if err != nil {
		return nil, "", err
	}
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("hsm-agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("hsm-agent /keys returned %s", resp.Status)
	}
	var out struct {
		Keys map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, "", err
	}
	if len(out.Keys) == 0 {
		return nil, "", fmt.Errorf("hsm-agent holds no keys")
	}
	if keyID == "" {
		if len(out.Keys) != 1 {
			// Flag-agnostic on purpose: this resolver is shared by the interception, device-CA, and agent-policy
			// paths, and naming only the interception flag misdirects the other two (the token now holds all three).
			return nil, "", fmt.Errorf("hsm-agent holds %d keys; set the -...-hsm-agent-key-id for the key you mean", len(out.Keys))
		}
		for k := range out.Keys {
			keyID = k
		}
	}
	b64, ok := out.Keys[keyID]
	if !ok {
		return nil, "", fmt.Errorf("hsm-agent does not hold key %q", keyID)
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, "", fmt.Errorf("hsm-agent: bad public key encoding: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", fmt.Errorf("hsm-agent: parse public key: %w", err)
	}
	return pub, keyID, nil
}

// mintSelfSignedWithSigner issues the CA certificate using a signer whose private key is in hardware. This is
// the proof that the seam works end to end: x509.CreateCertificate takes a crypto.Signer, so the certificate
// is signed inside the HSM without this process ever holding the key.
func mintSelfSignedWithSigner(signer crypto.Signer, commonName string, now func() time.Time) (*x509.Certificate, []byte, error) {
	if commonName == "" {
		commonName = "DSSE Interception Root (HSM)"
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now().Add(-time.Hour),
		NotAfter:              now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, nil, fmt.Errorf("mint CA cert with the HSM key: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CertificateRequestDER asks the agent to produce a PKCS#10 request for THIS key, under the given subject.
//
// ★ WHY THE AGENT BUILDS IT AND NOT US (2026-08-15). A CSR is signed with the key it names, and the key
// lives in the token — so building it here means calling /sign with the request's TBS bytes, which is the
// escape hatch the purpose binding deliberately closed. Asking it as an arbitrary signature was answered
// 403, correctly, and the consequence was that the interception issuing CA could never be re-issued: its
// subject carries the tenant, and when the tenant was renamed the CA could not follow.
//
// So the agent builds the request itself from a subject, over a key it reads from its own token. This
// process sends no bytes to be signed and cannot name another key. See the agent's sign_csr.go.
func (s *hsmAgentSigner) CertificateRequestDER(commonName string, organization []string) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"key_id":       s.keyID,
		"common_name":  commonName,
		"organization": organization,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "http://hsm-agent/sign-csr", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if s.token != "" {
		req.Header.Set("authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hsm-agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hsm-agent sign-csr returned %s", resp.Status)
	}
	var out struct {
		CSRDER string `json:"csr_der"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.CSRDER)
}
