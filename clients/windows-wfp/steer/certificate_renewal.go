package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// certificate_renewal.go — automated device-certificate renewal for the Windows agent.
//
// WHY: POST /enroll issues device certificates with a 60-day TTL and promises they are re-issued before
// expiry. Nothing performed that re-issue, so enrolling a real fleet would put every device into a
// simultaneous mTLS failure on day 60 — the same class of outage this lab already had once with a 30-day leaf.
// The Edge side (POST /enroll/renew) and the macOS client landed first; this is the Windows half, and the last
// thing standing between /enroll and production use.
//
// AUTHENTICATION IS THE CERTIFICATE BEING RENEWED. The request rides the (T) transport with the current
// identity, where the handshake has already proven the client cert chains to a registered tenant CA, names an
// enrolled identity, and is not revoked. No bootstrap token is involved — that secret is handed out once and
// must not have to live on every endpoint forever — and a revoked device is refused at the handshake, which is
// what makes revocation terminal rather than a 60-day countdown.
//
// THE SAME SHAPE AS macOS, deliberately. A pointer file names the certificate in force; renewed material is
// written beside it under its own fingerprint; the pointer is written LAST, as the single commit point, and
// only after the new identity has completed a real mTLS handshake. Keeping the two endpoints structurally
// identical means one description of the mechanism covers both, and a failure on one is diagnosable with what
// was learned on the other.
//
// WHAT IT WILL NOT DO: it never fails steering. Every error is logged and retried on the next tick. Renewal
// opens at two thirds of the certificate's life, leaving the last third as retry budget — 20 days on a 60-day
// certificate — so a temporarily broken renewal path is an alert, not an outage. Giving credential maintenance
// the power to stop steering would recreate the very failure this removes.

const (
	// maxRenewalCheckInterval bounds how rarely a device looks. Six hours is ample for the 60-day certificates
	// /enroll issues today, where the retry budget is 20 days.
	maxRenewalCheckInterval = 6 * time.Hour
	// minRenewalCheckInterval bounds how often. Set low deliberately: a check that finds the certificate NOT
	// due is purely local — it reads the certificate already in memory and makes no network request — so
	// frequent checking costs nothing. Only a check that finds renewal DUE talks to the Edge, and at that point
	// urgency is the correct behaviour. A 60-second floor was tried first and left a 5-minute certificate with
	// a single attempt inside its whole retry budget.
	minRenewalCheckInterval = 15 * time.Second
	// renewalAttemptsPerBudget is how many chances a device should get inside its retry budget. Twelve means a
	// transient failure — the Edge restarting, a network blip — costs one attempt out of twelve rather than
	// most of them.
	renewalAttemptsPerBudget = 12
	renewalPointerFile       = "device_identity_pointer.json"
)

// renewalCheckInterval derives how often to look from the certificate's own lifetime.
//
// A FIXED interval is wrong, and quietly so. Renewal opens at two thirds of life, leaving the last third as
// retry budget, and the interval has to fit inside that budget. With a 60-day certificate the budget is 20
// days and six-hourly checks give 80 attempts. With a ONE-HOUR certificate the budget is 20 minutes and
// six-hourly checks give ZERO — the certificate expires without the device ever looking. Short TTLs are not
// hypothetical: they are what an operator reaches for when tightening a fleet, and they are what the lab uses
// to exercise this path at all.
//
// So the interval scales with the budget and is only then clamped. The failure this prevents is the nastiest
// kind: everything appears configured, nothing logs an error, and the certificate simply expires.
func renewalCheckInterval(notBefore, notAfter time.Time) time.Duration {
	if notAfter.IsZero() || !notAfter.After(notBefore) {
		return maxRenewalCheckInterval
	}
	budget := notAfter.Sub(notBefore) / 3
	interval := budget / renewalAttemptsPerBudget
	if interval > maxRenewalCheckInterval {
		return maxRenewalCheckInterval
	}
	if interval < minRenewalCheckInterval {
		return minRenewalCheckInterval
	}
	return interval
}

// deviceIdentityPointer records which certificate is in force. Non-secret by construction: a fingerprint, file
// names, a container name, a subject and a date — never key material. A TPM identity names a KeyContainer and
// has an empty KeyFile; a file identity is the reverse. KeyStorage ("tpm"|"file") is the human-readable summary
// an operator and the status surface read without re-deriving it.
type deviceIdentityPointer struct {
	CertificateSHA256 string    `json:"certificate_sha256"`
	CertFile          string    `json:"cert_file"`
	KeyFile           string    `json:"key_file,omitempty"`
	KeyContainer      string    `json:"key_container,omitempty"`
	KeyStorage        string    `json:"key_storage,omitempty"`
	CommonName        string    `json:"common_name"`
	NotAfter          time.Time `json:"not_after"`
	InstalledAt       time.Time `json:"installed_at"`
	// Previous is the identity this one replaced — kept for ONE generation as the fallback, instead of being
	// deleted at renewal.
	//
	// The safety net used to be the day-0 bootstrap, which ages badly: a long-lived bootstrap goes on chaining
	// to a CA the fleet has retired, and re-provisioning it needs an out-of-band token every time. The previous
	// RENEWED identity is a strictly better net — it was issued by the CURRENT CA and proved itself on a real
	// handshake weeks ago — and its freshness is maintained by the renewal cycle that already exists, with no
	// second loop. Only N-1 is kept; the generation it displaces (N-2) is deleted, so nothing accumulates.
	Previous *supersededIdentity `json:"previous,omitempty"`
}

// supersededIdentity is the material of a retained previous generation: enough to present it if the current
// identity ever becomes unusable, and enough to delete it when it is displaced in turn.
type supersededIdentity struct {
	CertificateSHA256 string    `json:"certificate_sha256"`
	CertFile          string    `json:"cert_file"`
	KeyFile           string    `json:"key_file,omitempty"`
	KeyContainer      string    `json:"key_container,omitempty"`
	KeyStorage        string    `json:"key_storage,omitempty"`
	NotAfter          time.Time `json:"not_after"`
	RetainedAt        time.Time `json:"retained_at"`
}

// renewalDue mirrors renewalDue() in cmd/edge/enroll_renew_endpoint.go and DsseCertificateRenewal.renewalDue
// on macOS, and MUST keep mirroring them. If a client renewed later than the server's design assumes, the
// retry budget that turns a broken renewal path into an alert would not exist.
//
// Two triggers, in order:
//
//   - An operator's DECLARATION (renewIfIssuedBefore, zero = none): "any certificate issued before this is
//     stale." The comparison is against notBefore — when this certificate was ISSUED — not against now. That is
//     what makes it idempotent: a certificate renewed after the cutoff has a notBefore past it and stops
//     matching, with no server-side tracking of who has renewed. This is how a fleet leaves an old issuing CA
//     behind without waiting years for two-thirds of a ten-year certificate to elapse.
//   - The ordinary two-thirds-of-life schedule.
//
// A degenerate window (zero, or notAfter before notBefore) is NOT due on the schedule: treating "we cannot tell
// when this expires" as "renew now" would drive a renewal storm off one malformed certificate. The declaration
// trigger still applies to it — a stale-issuing-CA certificate should renew regardless of a malformed window.
func renewalDue(notBefore, notAfter, renewIfIssuedBefore, now time.Time) bool {
	if !renewIfIssuedBefore.IsZero() && notBefore.Before(renewIfIssuedBefore) {
		return true // the operator declared certificates this old stale
	}
	if notAfter.IsZero() || !notAfter.After(notBefore) {
		return false
	}
	life := notAfter.Sub(notBefore)
	return !now.Before(notBefore.Add(life * 2 / 3))
}

// loadDeviceIdentity returns the identity to present, preferring a RENEWED one over the bootstrap files.
//
// Once a device has renewed even once, the pointer names the certificate renewal proved working, and the
// files passed on the command line are by then the older credential heading for expiry. With no usable
// pointer the configured files are used unchanged, so a device that has never renewed behaves exactly as
// before. A pointer that names material which no longer loads is ignored rather than fatal — falling back to a
// working bootstrap identity beats refusing to start.
func loadDeviceIdentity(certFile, keyFile string) (tls.Certificate, string, error) {
	dir := filepath.Dir(certFile)
	if pointer, err := readIdentityPointer(dir); err == nil {
		cert, err := loadIdentityFromPointer(pointer)
		if err == nil {
			log.Printf("device key storage: %s", pointerStorageLabel(pointer))
			return cert, "renewed", nil
		}
		log.Printf("certificate_renewal pointer names material that cannot be loaded (%v) — trying the retained previous identity", err)
		// The retained previous identity (N-1) is what fallbackClientCertPEM REPORTS to the Edge's retire gate as
		// this device's safety net, so it MUST be what the device actually falls back to. Reporting N-1 (issued by
		// the current CA) while silently dropping to the day-0 bootstrap (issued by a CA the fleet may since have
		// retired) is exactly the false assurance that took the fleet down for seven minutes on 2026-08-02: the
		// gate retires the old CA believing nobody depends on it, then a device whose current identity will not
		// load presents the bootstrap and is refused at every handshake. Load N-1 here so the reported net is the
		// real one.
		if pointer.Previous != nil {
			if cert, perr := loadIdentityFromPointer(previousAsPointer(pointer.Previous)); perr == nil {
				log.Printf("certificate_renewal presenting the retained previous identity (N-1) fingerprint=%s not_after=%s",
					firstN(pointer.Previous.CertificateSHA256, 16), pointer.Previous.NotAfter.UTC().Format(time.RFC3339))
				return cert, "previous", nil
			} else {
				log.Printf("certificate_renewal retained previous identity is also unusable (%v) — falling back to the configured bootstrap certificate", perr)
			}
		} else {
			log.Printf("certificate_renewal no retained previous identity — falling back to the configured bootstrap certificate")
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	log.Printf("device key storage: FILE (bootstrap key from --transport-client-key; not TPM-bound)")
	return cert, "bootstrap", nil
}

// previousAsPointer adapts a retained N-1 generation into the shape loadIdentityFromPointer consumes, so the
// SAME loader (TPM container reopen or file pair) serves the current identity and its fallback — one code path,
// no second way for the two to disagree about how a stored identity is reconstructed.
func previousAsPointer(prev *supersededIdentity) deviceIdentityPointer {
	return deviceIdentityPointer{
		CertificateSHA256: prev.CertificateSHA256,
		CertFile:          prev.CertFile,
		KeyFile:           prev.KeyFile,
		KeyContainer:      prev.KeyContainer,
		KeyStorage:        prev.KeyStorage,
		NotAfter:          prev.NotAfter,
	}
}

// loadIdentityFromPointer reconstructs the identity a renewal pointer names: a TPM identity reopens the signer
// from its container and pairs it with the cert on disk; a file identity loads the pair as before. A TPM
// container that will not reopen is an error like any other unloadable material, so the caller falls back to
// the bootstrap identity rather than refusing to start.
func loadIdentityFromPointer(pointer deviceIdentityPointer) (tls.Certificate, error) {
	if strings.TrimSpace(pointer.KeyContainer) != "" {
		signer, err := reopenDeviceKeySigner(pointer.KeyContainer)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("reopen TPM key container %q: %w", pointer.KeyContainer, err)
		}
		certPEM, err := os.ReadFile(pointer.CertFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("read renewed certificate: %w", err)
		}
		return candidateFromIssued(string(certPEM), signer)
	}
	return tls.LoadX509KeyPair(pointer.CertFile, pointer.KeyFile)
}

// fallbackClientCertPEM returns the LEAF of the bootstrap certificate this device would present if its renewed
// identity became unusable — the one loadDeviceIdentity falls back to when the pointer names material that will
// not load.
//
// It exists because the Edge's retire gate can only see the certificate a device is presenting NOW. Retiring a
// CA that every device had already moved off still took the fleet down for seven minutes on 2026-08-02: a
// device whose pointer was set aside fell back to a bootstrap certificate issued under the retired CA and was
// refused at every handshake. Reporting the fallback lets the gate refuse to retire a CA that still issues
// somebody's safety net.
//
// PUBLIC CERTIFICATE ONLY. The key file sits beside it and is never read here; only the first CERTIFICATE block
// is returned, so a file that happens to hold a chain cannot leak more than the leaf.
// fallbackClientCertPEM reports the RETAINED PREVIOUS identity (N-1) when there is one, and the day-0 bootstrap
// otherwise. The retained generation is the better net — issued by the current CA and proven on a real
// handshake — and reporting it is what lets the day-0 bootstrap age out harmlessly instead of pinning a CA the
// fleet has retired. The Edge's gate is unchanged: it still just asks who issued whatever is reported.
func fallbackClientCertPEM(identityDir, bootstrapCertFile string) string {
	if strings.TrimSpace(identityDir) != "" {
		if pointer, err := readIdentityPointer(identityDir); err == nil && pointer.Previous != nil {
			if pem := leafPEMFromFile(pointer.Previous.CertFile); pem != "" {
				log.Printf("fallback_cert: reporting the retained previous identity fingerprint=%s not_after=%s",
					firstN(pointer.Previous.CertificateSHA256, 16), pointer.Previous.NotAfter.UTC().Format(time.RFC3339))
				return pem
			}
			// The retained material is gone (hand-deleted, a wiped directory) — say so and fall through to the
			// bootstrap rather than reporting nothing, which would silently remove the gate's constraint.
			log.Printf("fallback_cert: the retained previous identity %q is unreadable — falling back to the bootstrap credential",
				pointer.Previous.CertFile)
		}
	}
	return bootstrapClientCertPEM(bootstrapCertFile)
}

// bootstrapClientCertPEM is the day-0 credential named by --transport-client-cert: the fallback of last resort,
// used until a renewal has retained a generation of its own.
func bootstrapClientCertPEM(certFile string) string {
	if strings.TrimSpace(certFile) == "" {
		log.Printf("fallback_cert: no --transport-client-cert configured; nothing to report")
		return ""
	}
	pemOut := leafPEMFromFile(certFile)
	if pemOut == "" {
		// Worth a line: no reportable fallback is exactly the case where the retire gate would wrongly see no
		// constraint for this device, and silence here would leave that invisible.
		log.Printf("fallback_cert: %q yielded no usable certificate — reporting nothing, so the retire gate sees no constraint for this device", certFile)
		return ""
	}
	if block, _ := pem.Decode([]byte(pemOut)); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			log.Printf("fallback_cert: reporting the bootstrap credential issuer=%q not_after=%s",
				cert.Issuer.CommonName, cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	return pemOut
}

// leafPEMFromFile returns the FIRST certificate in a PEM file, re-encoded from the parsed certificate so that
// nothing but a certificate can ever reach the wire — a file holding a chain sends only its leaf, and a key
// file (or anything unparseable) sends nothing. Silent: callers decide what a miss means.
func leafPEMFromFile(certFile string) string {
	if strings.TrimSpace(certFile) == "" {
		return ""
	}
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return ""
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return ""
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
}

// pointerStorageLabel renders the mandated key-storage line from a pointer, so the startup log and the status
// surface say the same thing and neither has to re-derive it.
func pointerStorageLabel(pointer deviceIdentityPointer) string {
	if strings.TrimSpace(pointer.KeyContainer) != "" {
		return "TPM (Microsoft Platform Crypto Provider, container=" + pointer.KeyContainer + ")"
	}
	return "FILE — the device key is copyable (no TPM binding on this machine)"
}

func readIdentityPointer(dir string) (deviceIdentityPointer, error) {
	var pointer deviceIdentityPointer
	raw, err := os.ReadFile(filepath.Join(dir, renewalPointerFile))
	if err != nil {
		return pointer, err
	}
	if err := json.Unmarshal(raw, &pointer); err != nil {
		return pointer, err
	}
	// A usable pointer names a certificate and EITHER a key file (file identity) or a TPM container (hardware
	// identity). Requiring a key file would reject every TPM identity, which has none by design.
	if strings.TrimSpace(pointer.CertFile) == "" ||
		(strings.TrimSpace(pointer.KeyFile) == "" && strings.TrimSpace(pointer.KeyContainer) == "") {
		return pointer, fmt.Errorf("identity pointer names no usable key (neither key_file nor key_container)")
	}
	return pointer, nil
}

// recoveryTransport returns a copy of tc aimed at the RECOVERY listener instead of the (T) transport.
//
// Same pinned CA, same client certificate, same SNI — only the port differs. The recovery listener presents
// the transport server certificate, so nothing new has to be trusted to reach it: a device that could verify
// the Edge before it went away can still verify it now.
func recoveryTransport(tc *transportConfig, recoveryHostPort string) transportConfig {
	probe := *tc
	probe.host = recoveryHostPort
	// The region machinery targets the (T) listener; leaving it in place would send the recovery request to the
	// normal port and it would be refused at the handshake, which is the failure being worked around.
	probe.active = nil
	probe.pins = nil
	probe.liveClientCert = nil
	// A fresh session cache. Resumption would be meaningless here and could only confuse the diagnosis.
	probe.sessionCache = newSessionCachePointer(4)
	// Fall through to the shared tail so the separate-port and folded dials differ only in where they go.
	return withRecoverySNI(tc, probe)
}

// foldedRecoveryTransport is the recovery dial once the deployment has folded that path onto the MAIN
// transport port, where it is selected by SNI. It keeps the region machinery and the resolved Edge pins —
// unlike the separate-port dial, which clears them precisely because it targets a different listener — so a
// recovering device reaches the same address the tunnel does, without depending on the loopback resolver that
// the tunnel itself is needed to feed.
func foldedRecoveryTransport(tc *transportConfig, sni string) transportConfig {
	probe := *tc
	probe.liveClientCert = nil
	probe.sessionCache = newSessionCachePointer(4)
	probe.sendSNI = sni
	return probe
}

// recoveryDial decides WHERE a device whose certificate has already expired goes, and under what name. It is
// the Windows half of the same decision the macOS agent makes, and the order matters:
//
//  1. an ANNOUNCED recovery name wins — the deployment has folded that path onto the transport port, and the
//     dedicated endpoint may already be closed;
//  2. otherwise the endpoint, announced or configured, exactly as before;
//  3. otherwise nothing, and the caller says so.
//
// ★ WITHOUT (1) THE FOLD STRANDS THIS PLATFORM (2026-08-19). The deployment withdrew renewal_recovery_endpoint
// and closed :18545 on the evidence that both agents REPORT the recovery name — which this agent does. Sending
// the name is not the same as dialling it: an agent that reports the name and still dials a closed port has
// told the fleet it is ready for a fold it cannot follow. The devices that discover this are the ones already
// locked out, which is the slowest possible place for it to surface.
func recoveryDial(tc *transportConfig, recoveryHostPort string) (transportConfig, string, bool) {
	if sni := tc.currentRecoverySNI(); sni != "" {
		return foldedRecoveryTransport(tc, sni), fmt.Sprintf("%s under the announced name %q", tc.dialTarget(), sni), true
	}
	if strings.TrimSpace(recoveryHostPort) != "" {
		return recoveryTransport(tc, recoveryHostPort), recoveryHostPort, true
	}
	return transportConfig{}, "", false
}

// withRecoverySNI carries the announced name onto a separate-port recovery dial too. Harmless where that
// listener does not select on it, and correct the moment it does.
//
// The name is SENT and the chain is still verified against the name this device has always verified. That
// split was necessary when it was written: the deployment answered the recovery name with its ordinary
// transport certificate, whose SAN did not carry the name, so a client that verified what it sent refused the
// path — permanently, on the devices with no other way back. The deployment has since reissued that
// certificate WITH the name (measured 2026-08-20: the standard name check now passes), which makes the split
// unnecessary here and still correct: it costs nothing, and it is what keeps this working against a
// deployment that has not reissued yet.
func withRecoverySNI(tc *transportConfig, probe transportConfig) transportConfig {
	probe.sendSNI = tc.currentRecoverySNI()
	return probe
}

// startCertificateRenewal runs renewal in the background for as long as the agent steers.
//
// It is started ALONGSIDE steering rather than as an exclusive mode. The heartbeat had exactly that bug —
// --mode heartbeat returned before the data path started, so the agent the service actually runs never sent
// one — and there is no reason to repeat it here.
// liveRecovery, when non-nil, can carry a recovery endpoint that arrived AFTER startup — a signed trust bundle
// names one — and it then wins over the flag: the bundle is fleet-published and verified, the flag is whatever
// was typed at provisioning time.
// renewCutoff, when non-nil, carries the operator's "renew anything issued before this" declaration, published
// by the signed-policy sync from the SAME verified envelope the steering path already trusts (so this reader
// does not repeat the signature check — the weaker copy is always the one that survives). A nil pointer, or a
// nil value inside it, means "no declaration" and the schedule is purely two-thirds-of-life.
func startCertificateRenewal(tc *transportConfig, identityDir, recoveryHostPort string, liveRecovery *atomic.Pointer[string], renewCutoff *atomic.Pointer[time.Time], notifications ...<-chan struct{}) {
	if tc == nil || !tc.enabled || strings.TrimSpace(identityDir) == "" {
		log.Printf("certificate_renewal disabled (no (T) transport or no directory to keep a renewed identity in)")
		return
	}
	if strings.TrimSpace(recoveryHostPort) == "" && currentRecoveryEndpoint(recoveryHostPort, liveRecovery) == "" &&
		tc.currentRecoverySNI() == "" {
		// Worth saying out loud. Without a recovery endpoint a device that is switched off across its own
		// expiry cannot get back on its own, and that only becomes visible when somebody returns from leave.
		//
		// An ANNOUNCED recovery name counts as configured: once the deployment folds that path onto the
		// transport port it stops publishing an endpoint at all, and warning about a missing endpoint on a
		// device that has a perfectly good way in would train an operator to ignore this line.
		log.Printf("certificate_renewal recovery endpoint NOT configured and no recovery name announced — if " +
			"this device stays off past its certificate's expiry it will need manual re-enrolment " +
			"(--enroll-renew-recovery-url)")
	}
	var wake <-chan struct{}
	if len(notifications) != 0 {
		wake = notifications[0]
	}
	go runCertificateRenewalLoop(context.Background(), 30*time.Second, wake, func() time.Duration {
		return runRenewalCheck(tc, identityDir, currentRecoveryEndpoint(recoveryHostPort, liveRecovery), currentRenewCutoff(renewCutoff))
	})
	log.Printf("certificate_renewal scheduler started (interval derived from the certificate's own lifetime, max %s)",
		maxRenewalCheckInterval)
}

// currentRenewCutoff reads the operator's stale-before declaration in force right now (zero = none). Fail-safe
// by construction: the pointer is only ever set to a value that PASSED the shared signature check, so a missing
// or unverifiable policy simply leaves it unset and renewal falls back to the ordinary schedule — the safe
// direction, since reading a garbled response as "renew now" is how one bad reply becomes a fleet-wide storm.
func currentRenewCutoff(p *atomic.Pointer[time.Time]) time.Time {
	if p == nil {
		return time.Time{}
	}
	if v := p.Load(); v != nil {
		return *v
	}
	return time.Time{}
}

// currentRecoveryEndpoint returns the recovery endpoint in force right now: the bundle-delivered one when
// trust-anchor recovery has published one, otherwise the configured flag value.
func currentRecoveryEndpoint(configured string, live *atomic.Pointer[string]) string {
	if live != nil {
		if v := live.Load(); v != nil && strings.TrimSpace(*v) != "" {
			return strings.TrimSpace(*v)
		}
	}
	return strings.TrimSpace(configured)
}

// runRenewalCheck decides whether renewal is due and performs it, and returns how long to wait before looking
// again. Never fatal. renewIfIssuedBefore is the operator's stale-before declaration (zero = none).
func runRenewalCheck(tc *transportConfig, identityDir, recoveryHostPort string, renewIfIssuedBefore time.Time) time.Duration {
	current := tc.currentClientCert()
	if current == nil || len(current.Certificate) == 0 {
		log.Printf("certificate_renewal skipped reason=no_client_certificate")
		return maxRenewalCheckInterval
	}
	leaf := current.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(current.Certificate[0])
		if err != nil {
			log.Printf("certificate_renewal skipped reason=leaf_unparseable error=%v", err)
			return maxRenewalCheckInterval
		}
		leaf = parsed
	}
	next := renewalCheckInterval(leaf.NotBefore, leaf.NotAfter)
	daysRemaining := int(time.Until(leaf.NotAfter).Hours() / 24)

	// ALREADY EXPIRED — the device was switched off across its own expiry (a long holiday). The normal
	// transport will refuse the handshake, so renewing over it is not merely likely to fail, it CANNOT work.
	// Go to the recovery listener instead.
	if time.Now().After(leaf.NotAfter) {
		recovery, where, ok := recoveryDial(tc, recoveryHostPort)
		if !ok {
			log.Printf("certificate_renewal EXPIRED identity=%q expired_ago=%s and no recovery endpoint is "+
				"configured and no recovery name is announced — this device cannot renew itself and needs "+
				"manual re-enrolment",
				leaf.Subject.CommonName, time.Since(leaf.NotAfter).Round(time.Hour))
			return next
		}
		log.Printf("certificate_renewal EXPIRED identity=%q expired_ago=%s — the normal transport cannot carry "+
			"this handshake; recovering via %s", leaf.Subject.CommonName,
			time.Since(leaf.NotAfter).Round(time.Hour), where)
		// Ask the recovery listener; prove the answer on the NORMAL transport, where the device has to work.
		if err := renewAndInstall(&recovery, tc, identityDir, leaf.Subject.CommonName); err != nil {
			log.Printf("certificate_renewal RECOVERY FAILED identity=%q expired_ago=%s error=%v — retrying in %s",
				leaf.Subject.CommonName, time.Since(leaf.NotAfter).Round(time.Hour), err, next)
			return next
		}
		log.Printf("certificate_renewal RECOVERED identity=%q — steering can resume with the new certificate",
			leaf.Subject.CommonName)
		return next
	}

	if !renewalDue(leaf.NotBefore, leaf.NotAfter, renewIfIssuedBefore, time.Now()) {
		log.Printf("certificate_renewal not_due identity=%q days_remaining=%d next_check=%s renew_before=%s",
			leaf.Subject.CommonName, daysRemaining, next, renewIfIssuedBefore.UTC().Format(time.RFC3339Nano))
		return next
	}
	// Say WHICH trigger fired, so an operator who declared certificates stale can see their action take effect
	// rather than guessing whether the schedule happened to coincide.
	if !renewIfIssuedBefore.IsZero() && leaf.NotBefore.Before(renewIfIssuedBefore) {
		log.Printf("certificate_renewal DUE identity=%q reason=operator_cutoff issued=%s cutoff=%s days_remaining=%d — this certificate predates the cutoff an operator set",
			leaf.Subject.CommonName, leaf.NotBefore.UTC().Format(time.RFC3339), renewIfIssuedBefore.UTC().Format(time.RFC3339), daysRemaining)
	} else {
		log.Printf("certificate_renewal DUE identity=%q reason=schedule days_remaining=%d — requesting a new certificate",
			leaf.Subject.CommonName, daysRemaining)
	}

	if err := renewAndInstall(tc, tc, identityDir, leaf.Subject.CommonName); err != nil {
		// Loud but not fatal. The retry budget is what makes this an alert; only a path that stays broken for
		// weeks becomes an outage, and the day count says how much room is left.
		log.Printf("certificate_renewal FAILED identity=%q days_remaining=%d error=%v — the existing certificate is still in use and renewal will be retried in %s",
			leaf.Subject.CommonName, daysRemaining, err, next)
	}
	return next
}

// renewAndInstall obtains a new certificate, proves it on the wire, and puts it in force.
//
// requestTC is where the CSR is sent; probeTC is where the result is proven. They are the SAME for ordinary
// renewal and DIFFERENT during recovery, and that distinction is not cosmetic: the recovery listener refuses a
// still-valid certificate by design, so probing a freshly issued one against it always fails. The identity has
// to be proven where the device will actually use it — the normal (T) transport — which is also the more
// meaningful test.
func renewAndInstall(requestTC, probeTC *transportConfig, identityDir, commonName string) error {
	tc := requestTC
	// A FRESH KEY every renewal, never a re-certification of the existing one. Re-certifying lets a single key
	// serve for the life of the device, so a key that leaked once keeps being blessed by every later renewal.
	// On Windows this is generated IN THE TPM (non-exportable); without a usable TPM it falls back to a file key
	// and says so. The rest of this function does not care which — the signer is all it needs. This is the
	// migration: an existing fleet moves file key -> TPM key on its next renewal, with no server change.
	dk, err := newDeviceKey(commonName)
	if err != nil {
		return err
	}
	csrPEM, err := buildCSR(dk.signer, commonName)
	if err != nil {
		rollbackDeviceKey(dk)
		return err
	}

	certPEM, err := requestRenewal(tc, csrPEM)
	if err != nil {
		rollbackDeviceKey(dk)
		return err
	}
	expectedPub, err := expectedECDSAPublicKey(dk.signer)
	if err != nil {
		rollbackDeviceKey(dk)
		return err
	}
	issued, err := validateIssued(certPEM, expectedPub, commonName)
	if err != nil {
		rollbackDeviceKey(dk)
		return err
	}

	candidate, err := candidateFromIssued(certPEM, dk.signer)
	if err != nil {
		rollbackDeviceKey(dk)
		return err
	}

	fingerprint := sha256.Sum256(issued.Raw)
	name := hex.EncodeToString(fingerprint[:])
	dir := identityDir
	newCertPath := filepath.Join(dir, "device-"+name[:16]+".crt")

	// A file key writes its material; a TPM key writes NOTHING to disk — that is the whole point. 0600 is
	// honoured on POSIX and a no-op on Windows, where the file inherits the (administrator-only) directory ACL.
	newKeyPath := ""
	if !dk.hardware {
		newKeyPath = filepath.Join(dir, "device-"+name[:16]+".key")
		if err := os.WriteFile(newKeyPath, dk.keyPEM, 0o600); err != nil {
			return fmt.Errorf("write renewed key: %w", err)
		}
	}
	if err := os.WriteFile(newCertPath, []byte(certPEM), 0o644); err != nil {
		if newKeyPath != "" {
			os.Remove(newKeyPath)
		}
		rollbackDeviceKey(dk)
		return fmt.Errorf("write renewed certificate: %w", err)
	}

	// PROVE IT before anything depends on it. Nothing selects this material until the pointer names it, so a
	// failure here costs nothing — which is the difference between a failed renewal and a bricked device. A
	// discarded TPM key must be deleted from the chip, not merely forgotten.
	if err := probeIdentity(probeTC, &candidate); err != nil {
		if newKeyPath != "" {
			os.Remove(newKeyPath)
		}
		os.Remove(newCertPath)
		rollbackDeviceKey(dk)
		return fmt.Errorf("the renewed identity could not complete an mTLS handshake, so it was discarded: %w", err)
	}

	superseded, noPreviousPointer := readIdentityPointer(dir)
	pointer := deviceIdentityPointer{
		CertificateSHA256: name,
		CertFile:          newCertPath,
		KeyFile:           newKeyPath,
		KeyContainer:      dk.container,
		KeyStorage:        deviceKeyStorageKind(dk.hardware),
		CommonName:        issued.Subject.CommonName,
		NotAfter:          issued.NotAfter,
		InstalledAt:       time.Now().UTC(),
	}
	// Retain the identity being replaced as the fallback (N-1). It beats the day-0 bootstrap on both counts
	// that matter: it was issued by the CURRENT CA, and it proved itself on a real handshake when it was
	// installed. Its freshness then rides the renewal cycle instead of needing a second loop.
	if noPreviousPointer == nil && superseded.CertificateSHA256 != name {
		pointer.Previous = &supersededIdentity{
			CertificateSHA256: superseded.CertificateSHA256,
			CertFile:          superseded.CertFile,
			KeyFile:           superseded.KeyFile,
			KeyContainer:      superseded.KeyContainer,
			KeyStorage:        superseded.KeyStorage,
			NotAfter:          superseded.NotAfter,
			RetainedAt:        time.Now().UTC(),
		}
	}
	if err := writeIdentityPointer(dir, pointer); err != nil {
		if newKeyPath != "" {
			os.Remove(newKeyPath)
		}
		os.Remove(newCertPath)
		rollbackDeviceKey(dk)
		return fmt.Errorf("commit the renewed identity: %w", err)
	}

	// Live swap: every transportConfig copy shares this pointer, so the next dial presents the new certificate.
	// Established tunnels are left alone — renewal is housekeeping and must not interrupt steering. Applied to
	// the PROBE transport, which is the live one; the request transport may be a throwaway recovery copy.
	probeTC.setClientCert(&candidate)

	log.Printf("certificate_renewal INSTALLED identity=%q not_after=%s fingerprint=%s key_storage=%s",
		issued.Subject.CommonName, issued.NotAfter.UTC().Format(time.RFC3339), name[:16], deviceKeyStorageKind(dk.hardware))
	log.Printf("device key storage: %s", dk.storageLabel())

	// Only now that the new identity is committed and working: drop the generation that has just been pushed
	// out of the retained slot (N-2). N-1 is KEPT as the fallback; deleting it is what used to leave the day-0
	// bootstrap as the only net. After the commit, never before — if this fails the device still has a working
	// identity, whereas deleting first would risk a window with none. Exactly one generation is retained, so
	// certificates and TPM containers cannot accumulate.
	if noPreviousPointer == nil && superseded.Previous != nil &&
		superseded.Previous.CertificateSHA256 != name &&
		(pointer.Previous == nil || superseded.Previous.CertificateSHA256 != pointer.Previous.CertificateSHA256) {
		old := superseded.Previous
		if old.KeyFile != "" {
			os.Remove(old.KeyFile)
		}
		if old.CertFile != "" {
			os.Remove(old.CertFile)
		}
		if old.KeyContainer != "" {
			removeDeviceKeyContainer(old.KeyContainer)
		}
		log.Printf("certificate_renewal removed the generation before last fingerprint=%s (one generation is retained as the fallback)",
			firstN(old.CertificateSHA256, 16))
	}
	if pointer.Previous != nil {
		log.Printf("certificate_renewal retained the superseded identity as the fallback fingerprint=%s not_after=%s",
			firstN(pointer.Previous.CertificateSHA256, 16), pointer.Previous.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// deviceKeyStorageKind is the short token persisted in the pointer and logged, distinct from the human sentence
// storageLabel() renders.
func deviceKeyStorageKind(hardware bool) string {
	if hardware {
		return "tpm"
	}
	return "file"
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// requestRenewal posts the CSR over the (T) transport and returns the issued certificate PEM.
func requestRenewal(tc *transportConfig, csrPEM string) (string, error) {
	body, err := json.Marshal(map[string]string{"csr_pem": csrPEM})
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return tc.dial(20 * time.Second)
			},
		},
		Timeout: 30 * time.Second,
	}
	url := "https://" + tc.activeServerName() + "/enroll/renew"
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("renewal request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var decoded struct {
		CertPEM string `json:"cert_pem"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(raw, &decoded)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the Edge refused renewal: HTTP %d %s", resp.StatusCode, decoded.Error)
	}
	if strings.TrimSpace(decoded.CertPEM) == "" {
		return "", fmt.Errorf("the renewal response carried no certificate")
	}
	return decoded.CertPEM, nil
}

// validateIssued refuses anything that would leave the device worse off than before.
//
// Each check guards a way renewal can "succeed" and still break the endpoint. The key match matters most: a
// certificate issued for a DIFFERENT key installs cleanly and fails at the next handshake, by which point the
// old identity would be gone.
func validateIssued(certPEM string, expectedPub *ecdsa.PublicKey, expectedCommonName string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("the issued certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse the issued certificate: %w", err)
	}
	issuedKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !issuedKey.Equal(expectedPub) {
		return nil, fmt.Errorf("the issued certificate is for a DIFFERENT key — installing it would break the next handshake")
	}
	if cert.Subject.CommonName != expectedCommonName {
		return nil, fmt.Errorf("the issued certificate names %q, not %q", cert.Subject.CommonName, expectedCommonName)
	}
	if !cert.NotAfter.After(time.Now()) {
		return nil, fmt.Errorf("the issued certificate is already expired")
	}
	// It must make progress. Note what this deliberately does NOT require: that the new certificate outlive the
	// old one. Renewal legitimately SHORTENS validity when a fleet moves from hand-issued long-lived
	// certificates to short-lived managed ones, which is the migration this work exists to enable. "Not already
	// past its own renewal point" is what actually prevents a loop. The operator cutoff is deliberately NOT
	// passed here: this asks only whether the freshly issued certificate is already due on the SCHEDULE. A
	// just-issued certificate has a notBefore of now, which is after any cutoff anyway, so feeding the cutoff in
	// could only ever create a false loop-detection — the trigger's whole point is that renewal moves notBefore
	// past it.
	if renewalDue(cert.NotBefore, cert.NotAfter, time.Time{}, time.Now()) {
		return nil, fmt.Errorf("the issued certificate is already past its own renewal point — renewal would loop")
	}
	return cert, nil
}

// probeIdentity proves the candidate certificate on the wire — by completing a REQUEST, not just a handshake.
//
// ★ A SUCCESSFUL HANDSHAKE IS NOT PROOF. Measured against the real Edge: presenting an EXPIRED client
// certificate over TLS 1.3, the client's Handshake() returns success and the server's rejection only surfaces
// on the first read ("remote error: tls: expired certificate"). Under TLS 1.2 the same attempt fails at
// Handshake. So a probe that dials and closes would report success for a certificate the Edge refuses — which
// is precisely the case prove-then-commit exists to catch, and the device would then commit an identity it
// cannot use.
//
// So the probe writes a request and reads the answer. Any response proves the server accepted the certificate;
// what the response says does not matter.
func probeIdentity(tc *transportConfig, candidate *tls.Certificate) error {
	probe := *tc
	probe.liveClientCert = nil // do not disturb the live identity
	probe.clientCert = candidate
	// A fresh session cache: resuming a session established with the OLD certificate would prove nothing about
	// the new one, because a resumed handshake does not re-present the client certificate.
	probe.sessionCache = newSessionCachePointer(4)
	// Say what the server ASKED for and whether this candidate could answer it. A rejected renewal otherwise
	// surfaces only as the server's "certificate required", which is indistinguishable between "we sent the
	// wrong issuer", "we could not sign", and "we sent nothing" — three causes, one message. Selection happens
	// inside crypto/tls, so this is the only place the question is visible.
	probe.onCertificateRequest = func(cri *tls.CertificateRequestInfo, c *tls.Certificate) {
		issuer := "<unparsed>"
		if c.Leaf != nil {
			issuer = c.Leaf.Issuer.String()
		}
		if err := cri.SupportsCertificate(c); err != nil {
			log.Printf("certificate_renewal probe: the Edge would NOT accept the candidate issuer=%q reason=%v "+
				"(acceptable_cas=%d sigalgs=%v)", issuer, err, len(cri.AcceptableCAs), cri.SignatureSchemes)
			return
		}
		log.Printf("certificate_renewal probe: presenting the candidate issuer=%q (acceptable to the request)", issuer)
	}
	conn, err := probe.dial(20 * time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: dsse\r\nConnection: close\r\n\r\n")); err != nil {
		return fmt.Errorf("the renewed identity could not send over the tunnel: %w", err)
	}
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		// This is where a rejected client certificate actually appears under TLS 1.3.
		return fmt.Errorf("the Edge refused the renewed identity: %w", err)
	}
	return nil
}

// buildCSR signs a CSR with the device signer — a file key or a TPM signer, both of which satisfy crypto.Signer,
// so x509.CreateCertificateRequest neither knows nor cares where the private key lives.
func buildCSR(signer crypto.Signer, commonName string) (string, error) {
	// The subject carries no authority — the Edge overrides it from the verified certificate — but a CSR
	// without one is unusual enough that some parsers object.
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, signer)
	if err != nil {
		return "", fmt.Errorf("build CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// candidateFromIssued builds the live tls.Certificate from the issued PEM chain and the device signer. A TPM key
// has no file to load back through tls.LoadX509KeyPair, so the candidate is assembled directly: the signer is
// the private half, and the parsed leaf lets the transport skip a re-parse on every dial.
func candidateFromIssued(certPEM string, signer crypto.Signer) (tls.Certificate, error) {
	var chain [][]byte
	rest := []byte(certPEM)
	var leaf *x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		chain = append(chain, block.Bytes)
		if leaf == nil {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("parse issued leaf: %w", err)
			}
			leaf = c
		}
	}
	if len(chain) == 0 || leaf == nil {
		return tls.Certificate{}, fmt.Errorf("issued certificate PEM carried no certificate")
	}
	return tls.Certificate{Certificate: chain, PrivateKey: signer, Leaf: leaf}, nil
}

// rollbackDeviceKey undoes a key that was generated but not committed — a TPM container has to be deleted or it
// lingers in the chip (the orphan-accumulation failure in a different store). A file key leaves nothing behind
// until it is written, so this is a no-op for it.
func rollbackDeviceKey(dk deviceKeyMaterial) {
	if dk.hardware && dk.container != "" {
		removeDeviceKeyContainer(dk.container)
	}
}

func marshalKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func writeIdentityPointer(dir string, pointer deviceIdentityPointer) error {
	raw, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return err
	}
	// Written via a temporary file and renamed: a torn pointer would leave the agent unable to decide which
	// identity is current, which is worse than not having renewed at all.
	tmp := filepath.Join(dir, renewalPointerFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, renewalPointerFile))
}
