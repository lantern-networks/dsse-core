package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// the_console_is_checked_the_way_a_browser_reaches_it.go
//
// ★★ THE CHECK REFUSED THE CERTIFICATE IT TELLS THE OPERATOR TO INSTALL (2026-11-05). The -order
// walk's final -verify asks the Console with -console, and it asked with the deployment client, which trusts
// this deployment's anchor and nothing else. That is right for the management planes and wrong for the Console:
// the Console is the outward-facing page, and the installer tells the operator to put their own certificate for
// its name in <dir>/console/ (the_console_is_the_first_screen_an_administrator_sees.go). A Console doing
// exactly that failed the walk with "unknown authority".
//
// So the Console is asked with its own client, trusting what can legitimately be presented there:
//
//   - the roots a browser on this machine trusts, for a certificate from a public CA;
//   - this deployment's anchor, for the certificate it issues itself on day zero;
//   - the operator's adopted certificate itself, byte for byte, for one from a CA only the operator's own
//     machines trust. A leaf in the root pool verifies only as itself, so this accepts that certificate and
//     no other one its issuer signed, and still checks its name and its dates.
//
// ★★ UNLESS THE ADOPTED CERTIFICATE IS ITSELF A CA (2026-11-05). A certificate in the root pool
// that may sign certificates is a root, not "this certificate only": with an adopted self-signed certificate
// carrying CA:TRUE and keyCertSign — which some certificate tools produce by default — another certificate for
// the same name, signed by it, passed every Console check. So, after the ordinary verification has passed, a
// chain that ends at the adopted certificate is accepted only when the adopted certificate is what was presented.
// This narrows the verification; it skips none of it.
//
// ★★ AND ONLY THE TRUST THE ADOPTION ADDED IS NARROWED (2026-11-06). When the adopted certificate
// was ALSO a root before it was adopted — this deployment's anchor, or one the OS trusts — a chain to it is the
// same certificate either way, so the narrowing refused a valid certificate that root had issued, which passed
// before the adoption. So a certificate that is not the adopted one is asked again of the roots without it: if
// they accept it, it never depended on the adoption.
//
// The management planes keep the deployment client: nothing here widens what they trust.
func consoleClient(dir string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	anchor, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		return nil, fmt.Errorf("read the deployment anchor: %w", err)
	}
	if !roots.AppendCertsFromPEM(anchor) {
		return nil, fmt.Errorf("the deployment anchor contains no certificate")
	}
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if leaf, ok, err := adoptedConsoleLeaf(dir); err != nil {
		return nil, err
	} else if ok {
		without := roots.Clone()
		roots.AddCert(leaf)
		config.VerifyConnection = onlyTheAdoptedCertificateItself(leaf.Raw, without)
	}
	transport := &http.Transport{TLSClientConfig: config}
	transport.DialContext = dialWithOverrides
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}

// onlyTheAdoptedCertificateItself runs after the ordinary verification has passed. Of the chains it built, one
// that ends anywhere but the adopted certificate stands on its own (a public CA, the deployment's anchor); one that
// ends at the adopted certificate stands when it is the adopted certificate alone, or when the presented
// certificate verifies, name and dates included, against the roots without the adopted one.
func onlyTheAdoptedCertificateItself(adopted []byte, without *x509.CertPool) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("the Console presented no certificate")
		}
		presented := state.PeerCertificates[0]
		if bytes.Equal(presented.Raw, adopted) {
			return nil
		}
		for _, chain := range state.VerifiedChains {
			if len(chain) > 0 && !bytes.Equal(chain[len(chain)-1].Raw, adopted) {
				return nil
			}
		}
		// The name was checked by the ordinary verification already. It is asked again with the name the client
		// sent; for a Console reached by address none is sent, and that check stands.
		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		if _, err := presented.Verify(x509.VerifyOptions{
			Roots: without, Intermediates: intermediates, DNSName: state.ServerName,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err == nil {
			return nil
		}
		return fmt.Errorf("the Console presented a certificate issued by the one in %s/, not that certificate "+
			"itself; the adopted certificate is trusted for itself only", consoleCertDirName)
	}
}

// adoptedConsoleLeaf is the first certificate of the operator's pair in <dir>/console/, when the pair is there —
// the same condition under which adoptConsoleCertificate points the Console at it.
func adoptedConsoleLeaf(dir string) (*x509.Certificate, bool, error) {
	crt := filepath.Join(dir, consoleCertDirName, "tls.crt")
	key := filepath.Join(dir, consoleCertDirName, "tls.key")
	if _, err := os.Stat(key); err != nil {
		return nil, false, nil
	}
	body, err := os.ReadFile(crt)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read the Console's certificate: %w", err)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, false, fmt.Errorf("%s holds no certificate", crt)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", crt, err)
	}
	return leaf, true, nil
}
