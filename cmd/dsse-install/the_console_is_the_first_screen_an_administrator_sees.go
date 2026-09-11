package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// the_console_is_the_first_screen_an_administrator_sees.go
//
// ★★★ THE FIRST SCREEN MUST NOT BE A CERTIFICATE WARNING (2026-09-03, the operator: "the certificate error
// every time you enter the Admin Console — shouldn't that be solved first, and be in the published install
// procedure?").
//
// The Console is served with this deployment's own management certificate, so a browser refuses it until
// something is done, and the published procedure would otherwise have to say "click through the warning" —
// on the first screen of a security product, to the person setting it up.
//
// There are two moments and they need different answers:
//
//   - Day zero. The administrator MUST reach this screen before anything exists, so "obtain a certificate
//     first" is not available. The answer is to VERIFY instead of accept: this deployment prints the
//     fingerprint of what it will present, and the administrator compares it in the browser. Comparing a
//     fingerprint is a different act from dismissing a warning.
//   - Afterwards. The operator's own certificate for the Console's name, the same slot the step-up portal
//     takes. Drop the pair into <dir>/console/ and re-run the installer on that directory; nothing about the
//     deployment's internal PKI changes, because this is the outward-facing page.
//
// ★ WHY THE REPAIR SETS IT RATHER THAN THE OPERATOR EDITING deployment.env: compose reads the variable from
// that file, and an operator who drops the pair and forgets the variable gets the old certificate with no
// error anywhere. The pair being present IS the intent; the variable is bookkeeping, so the installer does
// the bookkeeping.
const (
	consoleCertDirName = "console"
	consoleCertEnvKey  = "DSSE_CONSOLE_TLS_CERT"
	consoleKeyEnvKey   = "DSSE_CONSOLE_TLS_KEY"
)

// adoptConsoleCertificate points the Console at the operator's pair when one is there, and unsets it when it
// is taken away. Reports what it did, or "" when nothing changed.
func adoptConsoleCertificate(dir string) string {
	crt := filepath.Join(dir, consoleCertDirName, "tls.crt")
	key := filepath.Join(dir, consoleCertDirName, "tls.key")
	_, crtErr := os.Stat(crt)
	_, keyErr := os.Stat(key)
	present := crtErr == nil && keyErr == nil

	env := readDeploymentEnv(dir)
	had := strings.TrimSpace(env[consoleCertEnvKey]) != ""
	switch {
	case present && !had:
		if err := writeDeploymentEnvValues(dir, map[string]string{
			consoleCertEnvKey: "/deployment/" + consoleCertDirName + "/tls.crt",
			consoleKeyEnvKey:  "/deployment/" + consoleCertDirName + "/tls.key",
		}); err != nil {
			return fmt.Sprintf("could not point the Console at %s/: %v", consoleCertDirName, err)
		}
		return fmt.Sprintf("the Admin Console now presents the certificate in %s/ — restart it for the "+
			"change to take effect", consoleCertDirName)
	case !present && had:
		if err := writeDeploymentEnvValues(dir, map[string]string{consoleCertEnvKey: "", consoleKeyEnvKey: ""}); err != nil {
			return fmt.Sprintf("could not take the Console off %s/: %v", consoleCertDirName, err)
		}
		return fmt.Sprintf("★ %s/ no longer holds a certificate pair, so the Admin Console is back on this "+
			"deployment's own — a browser will warn again", consoleCertDirName)
	}
	return ""
}

// writeDeploymentEnvValues sets keys in this deployment's environment file, leaving everything else exactly
// as it is. An empty value removes the key's effect by setting it empty, which is what the compose default
// falls back from.
func writeDeploymentEnvValues(dir string, values map[string]string) error {
	path := filepath.Join(dir, "deployment.env")
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(PlanEnvironmentFor(string(body), values)), 0o600)
}

// reportConsoleFirstVisit says where the Console is and what to compare in the browser, at the moment the
// administrator is about to open it for the first time.
//
// ★★★ THE ANCHOR'S FINGERPRINT IS NOT WHAT THE BROWSER SHOWS (2026-09-03). The installer has printed the
// deployment anchor's fingerprint since 2026-08-22, and it is the right thing for a device's anchor file —
// but a browser warning shows the LEAF, and an administrator comparing the two finds they do not match and
// learns that the printed fingerprint is not for them. So this prints what they will actually be looking at.
func reportConsoleFirstVisit(dir, consoleURL string) {
	fmt.Printf("\n  ★ OPENING THE CONSOLE FOR THE FIRST TIME: your browser will refuse it, and it is right to.\n")
	fmt.Printf("  This deployment presents a certificate it issued itself, which nobody else vouches for.\n")
	if consoleURL != "" {
		fmt.Printf("    the Console      %s\n", consoleURL)
	}
	if fp := certificateFingerprintFile(filepath.Join(dir, "management.crt")); fp != "" {
		fmt.Printf("    what it presents %s\n", fp)
		fmt.Printf("    ★ COMPARE THAT in the browser's certificate view before you proceed. Comparing a\n")
		fmt.Printf("      fingerprint is a different act from dismissing a warning; only the first one tells\n")
		fmt.Printf("      you which server you reached.\n")
	}
	fmt.Printf("    to stop the warning: put your own certificate for the Console's name in %s/%s/\n",
		dir, consoleCertDirName)
	fmt.Printf("      as tls.crt and tls.key, then run  dsse-install -dir %s  and restart the Console.\n", dir)
	fmt.Printf("      This deployment's internal PKI does not change — the Console is the outward-facing\n")
	fmt.Printf("      page and its certificate is yours, the same as the step-up portal's.\n")
}

// certificateFingerprintFile is the SHA-256 of the leaf in a PEM file, formatted the way a browser shows it.
func certificateFingerprintFile(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return fingerprintForHumans(fingerprint(cert))
}

// consoleURLForFirstVisit is where this deployment's Console answers, taken from the deployment's own record
// of the names it was minted for rather than assembled from a guess.
func consoleURLForFirstVisit(dir string) string {
	env := readDeploymentEnv(dir)
	for _, key := range []string{"DSSE_CONSOLE_NAME", "DSSE_ADMIN_CONSOLE_ORIGIN"} {
		if v := strings.TrimSpace(env[key]); v != "" {
			if strings.HasPrefix(v, "https://") {
				return v
			}
			return "https://" + v
		}
	}
	if host := strings.TrimSpace(env["EDGE_HOST"]); host != "" {
		return "https://console." + host
	}
	return ""
}

// fingerprintForHumans is the form a person can actually compare: uppercase hex in colon-separated pairs,
// which is what a browser's certificate view shows and what `openssl x509 -fingerprint -sha256` prints.
//
// ★ THE EXISTING fingerprint() IS LEFT ALONE. It emits unseparated lowercase and is quoted in procedures and
// grepped by scripts; changing it to suit a screen would break the places it is already right. An
// administrator told to compare "1e0e2fd3…" against Chrome's "1E:0E:2F:D3:…" is being asked to do a
// conversion in their head at the exact moment they are deciding whether to trust a server.
func fingerprintForHumans(hexDigest string) string {
	hexDigest = strings.ToUpper(strings.TrimSpace(hexDigest))
	var b strings.Builder
	for i := 0; i < len(hexDigest); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		end := i + 2
		if end > len(hexDigest) {
			end = len(hexDigest)
		}
		b.WriteString(hexDigest[i:end])
	}
	return b.String()
}

// ★★★ AND THE DEPLOYMENT STATES WHETHER ITS STEP-UP PORTAL IS ON THE OPERATOR'S CERTIFICATE (2026-09-03).
//
// Every device profile carries this, because it decides whether a device must trust anything extra to
// complete a step-up. The control plane issues profiles and does not serve the portal, so it cannot look at
// the file — the deployment says it once in its own environment, and this keeps that statement true.
//
// Same bookkeeping as the Console's certificate, and the same reason: dropping the pair in IS the intent, and
// an operator who drops it and forgets a variable would have every device go on trusting an authority it did
// not need to.
const stepUpPortalCertEnvKey = "DSSE_STEP_UP_PORTAL_CERTIFICATE"

func adoptStepUpPortalCertificate(dir string) string {
	crt := filepath.Join(dir, "clientless", "tls.crt")
	key := filepath.Join(dir, "clientless", "tls.key")
	_, crtErr := os.Stat(crt)
	_, keyErr := os.Stat(key)
	present := crtErr == nil && keyErr == nil

	was := strings.ToLower(strings.TrimSpace(readDeploymentEnv(dir)[stepUpPortalCertEnvKey]))
	want := "deployment"
	if present {
		want = "operator"
	}
	if was == want {
		return ""
	}
	if err := writeDeploymentEnvValues(dir, map[string]string{stepUpPortalCertEnvKey: want}); err != nil {
		return fmt.Sprintf("could not record who the step-up portal's certificate belongs to: %v", err)
	}
	if present {
		return "the step-up portal is on YOUR certificate now — device profiles will say so, and a device " +
			"joining from here adds nothing to its trust store to complete a step-up"
	}
	return "★ clientless/ holds no certificate pair, so the step-up portal is on this deployment's own. " +
		"Every device joining from here has to trust this organization's transport anchor to complete a " +
		"step-up — which is right for a lab and is not what you want in production"
}
