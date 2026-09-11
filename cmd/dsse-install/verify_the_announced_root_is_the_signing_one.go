package main

// verify_the_announced_root_is_the_signing_one.go — what the deployment TELLS a device to expect, against
// what it actually signs with.
//
// ★★★ NOTHING COMPARED THE TWO, AND THE TREE SAYS SO IN AS MANY WORDS. steer_agent_policy_routes.go carries
// the finding: with steering armed, a page arrived signed by an issuer under a root that was in no store on
// that machine, schannel refused it, and EVERY HTTPS request on the box failed at once — while the signal
// built to prevent exactly that reported interception_root_trust wanted=1 found=1, because the machine did
// hold the root it had been TOLD to look for. The announcement and the signing were each correct about
// themselves.
//
// ★★ AND THE OTHER HALF OF THE SAME QUESTION IS wanted=0. Reported from a Windows machine against the
// deployment this installer generates (letter 105): "the deployment named no roots to look for". A device
// told nothing cannot tell "this deployment does not inspect" from "this deployment inspects and did not say
// what to trust" — and the second one breaks every site on the machine the moment steering arms.
//
// So this asks the deployment both questions with one device identity: what do you announce, and does it
// match what you just signed with. It runs after the flow check, and it uses that flow's own leaf as the
// answer to "what signs" — not a second reading of the same configuration, which would agree with itself.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// verifyTheAnnouncedRootIsTheSigningOne asks the device-facing policy which interception roots this
// deployment names, and compares them with the authority that signed the measured flow.
func verifyTheAnnouncedRootIsTheSigningOne(dir, door, deviceMustHold string, certPEM, keyPEM []byte) []verifyResult {
	const name = "devices are told which root to expect"
	fail := func(format string, args ...any) []verifyResult {
		return []verifyResult{{name: name, ok: false, note: fmt.Sprintf(format, args...)}}
	}

	signing, err := interceptionAuthorityFingerprint(dir)
	if err != nil {
		return fail("%v", err)
	}
	// ★★★ WHAT A DEVICE MUST HOLD IS NOT WHAT SIGNS (letter 112, measured on real hardware). This
	// deployment's interception CA is signed by the deployment root, so it is an intermediate: installing the
	// announced fingerprint into a Root store leaves the chain open and every site still fails. The anchor
	// comes from the chain the Edge actually presented; when that chain ends in a certificate the server did
	// not send, the fingerprint is the deployment's own anchor file.
	expected, expectedWhat := signing, "signs intercepted traffic"
	if deviceMustHold == interceptionAnchorPlaceholder {
		if fp, aerr := deploymentAnchorFingerprint(dir); aerr == nil {
			expected, expectedWhat = fp, "closes the chain a device is shown"
		}
	} else if strings.TrimSpace(deviceMustHold) != "" {
		expected, expectedWhat = deviceMustHold, "closes the chain a device is shown"
	}
	// ★★★ THE DOCUMENT THAT DECIDES IS THE BUNDLE, NOT THE POLICY (2026-08-26, letter 110). This check first
	// read GET /steer/agent-policy, found the root correctly named there, and reported the deployment
	// healthy — while the Windows machine enrolled into it logged wanted=0 and lost every outbound TLS
	// connection the moment steering armed. The agent's "wanted" list comes from the signed trust bundle it
	// ADOPTS (trust_anchor_recovery.go), and the generated deployment was not serving one at all, because
	// -trust-bundle-ca was never passed. Two agent-facing documents, one of them the one that matters.
	//
	// So both are asked, and the bundle's answer is the one that decides. Verifying the wrong document is how
	// a check reports a deployment ready for a fleet it is about to take down.
	out := []verifyResult{}
	out = append(out, verifyTheDistributionDevicesAdoptNamesTheRoot(dir, door, expected, expectedWhat, certPEM, keyPEM))

	announced, err := announcedInterceptionRoots(dir, door, certPEM, keyPEM)
	if err != nil {
		return append(out, fail("the device-facing policy could not be read, so what this deployment tells a "+
			"device was NOT measured: %v", err)...)
	}
	if len(announced) == 0 {
		// ★ THE wanted=0 CASE, NAMED FOR ITS CONSEQUENCE. Silence is not neutral once the deployment is
		// inspecting: the device has nothing to check the certificates against, and the first armed browser
		// on that machine fails on every site at once.
		return append(out, fail("this deployment signs intercepted traffic under %s and tells devices to expect "+
			"NOTHING — a device cannot tell that from a deployment that does not inspect, and the certificates "+
			"it is about to be shown are from a root it was never told to hold", short(signing))...)
	}
	for _, a := range announced {
		if strings.EqualFold(a, expected) {
			return append(out, verifyResult{name: name, ok: true, note: fmt.Sprintf(
				"%d root(s) announced, including the one that %s (%s)", len(announced), expectedWhat, short(expected))})
		}
	}
	// ★★★ THE EXPENSIVE ONE. Both halves are internally consistent and they are about different roots, so
	// every self-report on both sides reads healthy.
	return append(out, fail("this deployment tells devices to expect %s; the certificate that %s is %s, and it "+
		"is NOT among them — a device that installs exactly what it was told to install still cannot close the "+
		"chain, and every site on it fails at once",
		strings.Join(shortAll(announced), ", "), expectedWhat, short(expected))...)
}

// verifyTheDistributionDevicesAdoptNamesTheRoot asks GET /bootstrap/trust-bundle — the document an agent
// ADOPTS, and the one its "wanted" list comes from.
//
// ★★★ NOT SERVED AT ALL IS THE CASE THAT HAPPENED. The endpoint exists only when the deployment was started
// with -trust-bundle-ca, and the generated deployment was not. Every enrolled device therefore had an empty
// wanted list while the Edge decrypted, which on Windows is SEC_E_UNTRUSTED_ROOT on every site at once. A 404
// here is not a missing feature; it is a fleet that will go down when steering arms.
func verifyTheDistributionDevicesAdoptNamesTheRoot(dir, door, expected, expectedWhat string, certPEM, keyPEM []byte) verifyResult {
	const name = "the distribution devices adopt names that root"
	roots, err := adoptedBundleInterceptionRoots(dir, door, certPEM, keyPEM)
	if err != nil {
		return verifyResult{name: name, ok: false, note: fmt.Sprintf(
			"the signed trust bundle could not be read (%v). This is where a device's wanted list comes "+
				"from: without it every device reports interception_root_trust wanted=0 while this deployment "+
				"decrypts, and the first browser to arm steering fails on every site", err)}
	}
	for _, r := range roots {
		if strings.EqualFold(r, expected) {
			return verifyResult{name: name, ok: true, note: fmt.Sprintf(
				"the bundle names %s, the certificate that %s — a device can now say whether it holds it "+
					"(wanted/found)", short(expected), expectedWhat)}
		}
	}
	return verifyResult{name: name, ok: false, note: fmt.Sprintf(
		"the bundle names %d certificate(s) and none of them is %s, which %s — a device that installs what "+
			"this bundle names STILL cannot close the chain, and reports itself ready while doing so: %s",
		len(roots), short(expected), expectedWhat, strings.Join(shortAll(roots), ", "))}
}

// interceptionAuthorityFingerprint is the sha256 of the authority this deployment inspects under, from its
// own material — the same fingerprint an agent compares against.
func interceptionAuthorityFingerprint(dir string) (string, error) {
	path := filepath.Join(dir, interceptionRootCertFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("this deployment holds no interception authority at %s: %v", path, err)
	}
	cert, err := firstCertificateIn(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %v", path, err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func firstCertificateIn(raw []byte) (*x509.Certificate, error) {
	for rest := raw; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return nil, fmt.Errorf("holds no certificate")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// readAllLimited reads at most limit bytes, so a document larger than this walk can believe fails rather than
// being read into memory without bound.
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

// adoptedBundleInterceptionRoots reads the signed trust bundle and returns the interception roots it names.
func adoptedBundleInterceptionRoots(dir, door string, certPEM, keyPEM []byte) ([]string, error) {
	body, err := deviceGet(dir, door, "/bootstrap/trust-bundle", certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	payload, perr := envelopePayload(body)
	if perr != nil {
		return nil, perr
	}
	return interceptionRootsIn(payload, "the bundle")
}

func announcedInterceptionRoots(dir, door string, certPEM, keyPEM []byte) ([]string, error) {
	body, err := deviceGet(dir, door, "/steer/agent-policy", certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	payload, perr := envelopePayload(body)
	if perr != nil {
		return nil, perr
	}
	return interceptionRootsIn(payload, "the policy")
}

// deviceGet fetches one device-facing document the way a device fetches it: mTLS with this device's own
// identity, the deployment's anchor as the only root.
func deviceGet(dir, door, path string, certPEM, keyPEM []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("the issued certificate and its key do not pair: %w", err)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
		}},
	}
	resp, err := client.Get(strings.TrimRight(door, "/") + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// ★ 404 ON THE BUNDLE IS NOT "NOT IMPLEMENTED". The endpoint is served only when the deployment was
		// given -trust-bundle-ca, so this status IS the finding: no device can learn which root to hold.
		return nil, fmt.Errorf("%s answered %d", path, resp.StatusCode)
	}
	return readAllLimited(resp.Body, 1<<20)
}

// envelopePayload unwraps the signed envelope agentpolicy produces — its document lives in payload_b64 — and
// passes an unsigned document through unchanged.
//
// The signature is deliberately not verified here: the question these checks ask is what the deployment SAYS,
// and whether a device would accept the signing key is a different question with its own failure.
func envelopePayload(body []byte) ([]byte, error) {
	var envelope struct {
		PayloadB64 string          `json:"payload_b64"`
		Payload    json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(body, &envelope) == nil {
		switch {
		case strings.TrimSpace(envelope.PayloadB64) != "":
			decoded, derr := base64.StdEncoding.DecodeString(envelope.PayloadB64)
			if derr != nil {
				return nil, fmt.Errorf("payload_b64 could not be decoded (%v)", derr)
			}
			return decoded, nil
		case len(envelope.Payload) > 0:
			return envelope.Payload, nil
		}
	}
	return body, nil
}

// interceptionRootsIn reads the roots out of one document.
//
// ★ "NO SUCH FIELD" AND "I COULD NOT READ THIS" ARE DIFFERENT ANSWERS, and the first version of this returned
// an empty list for both — which reports a deployment that announces nothing when the truth is a document
// this walk could not parse. The whole check is about not confusing silence with absence, so it must not do
// it itself. The absence names what the document DID carry, so the next person need not guess.
func interceptionRootsIn(payload []byte, what string) ([]string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("%s could not be read (%v)", what, err)
	}
	raw, present := doc["interception_root_sha256"]
	if !present {
		keys := make([]string, 0, len(doc))
		for k := range doc {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("%s carries no interception_root_sha256; it carries %s", what, strings.Join(keys, ", "))
	}
	var roots []string
	if err := json.Unmarshal(raw, &roots); err != nil {
		return nil, fmt.Errorf("interception_root_sha256 is not a list of roots (%v)", err)
	}
	return roots, nil
}

func short(fingerprint string) string {
	if len(fingerprint) <= 16 {
		return fingerprint
	}
	return fingerprint[:16] + "…"
}

func shortAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, short(s))
	}
	return out
}

// deploymentAnchorFingerprint is the sha256 of the deployment's own anchor — the self-signed certificate at
// the top of every chain this deployment presents, and therefore the one a device must hold.
func deploymentAnchorFingerprint(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		return "", err
	}
	cert, cerr := firstCertificateIn(raw)
	if cerr != nil {
		return "", cerr
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}
