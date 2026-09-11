package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// interception_probe.go — turning "this process keeps failing" into a sentence a verifier said.
//
// The observer in interception_observation.go can only see the SHAPE of a flow: bytes in, bytes out, who closed.
// That is enough to know something is wrong and never enough to say what. This file gets the missing half by
// doing what the failing application does — open one flow to the same destination THROUGH THE SAME MUX, so the
// Edge intercepts it the same way — and then verifying the chain it is handed.
//
// ★ IT VERIFIES TWICE, AND THE DISAGREEMENT IS THE POINT. On 2026-08-21 an intercepted chain was accepted by
// Chrome and refused by openssl, git and Node, and the split was read as a difference in which roots were
// trusted for most of a day. It was not: it was pathLenConstraint:0, which some implementations enforce and
// others did not. A probe that asked one verifier would have reproduced exactly the confusion it exists to end.
// So the chain is checked against this device's own root stores with Go's verifier AND with the platform's, and
// when they differ the entry says so instead of picking a winner.
//
// ★ AND IT REPORTS SUCCESS. A probe that verifies fine while an application cannot is not a null result — it is
// the 2026-08-22 finding, where the machine store held the announced root and the file-based stores that Node,
// curl and git read still held the retired one. "The material verifies here and not there" is the sentence that
// points at the process instead of at the deployment, and nothing else on this device can say it.

const interceptionProbeTimeout = 10 * time.Second

// makeInterceptionProbe returns the hook interceptionObserver.probe expects. dial opens one flow to an authority
// through the steering mux — the same door the application's traffic went through, which is what makes the
// answer about interception rather than about this process's own network stack. nil dial => no probe.
func makeInterceptionProbe(dial func(authority string) (net.Conn, error)) func(string) (string, string) {
	if dial == nil {
		return nil
	}
	return func(destination string) (leafSHA256, reason string) {
		return probeInterceptedChain(dial, destination, deviceRootPool())
	}
}

// probeInterceptedChain is the whole probe, factored out so a test can drive it with an in-process listener and
// a pool it controls. A returned reason of "" means no statement could be made — the caller keeps its
// observation rather than inventing a cause.
func probeInterceptedChain(dial func(string) (net.Conn, error), destination string, deviceRoots *x509.CertPool) (string, string) {
	conn, err := dial(destination)
	if err != nil {
		// Not reportable as a verification result: failing to reach the Edge says nothing about the certificate.
		return "", ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(interceptionProbeTimeout))

	// ★ InsecureSkipVerify HERE IS THE MEASUREMENT, NOT A RELAXATION. The handshake must be allowed to COMPLETE
	// so the chain can be looked at; verifying inside the handshake would collapse every distinct reason into
	// one "handshake failed" and throw away the certificates that answer the question. Nothing read from this
	// connection is used for anything but the verification below, and no bytes are ever sent over it.
	//
	// No ServerName: a steered flow's authority is the address the application dialled, not a name (the agent
	// sees the connection, not the URL), so there is nothing truthful to put in the SNI. The consequence is
	// stated honestly in the reason below — the chain is checked for its ISSUERS and not for its name, which is
	// the half that was broken on both of the occasions this exists for.
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		return "", ""
	}
	defer tc.Close()
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return "", ""
	}
	sum := sha256.Sum256(chain[0].Raw)
	fingerprint := hex.EncodeToString(sum[:])

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	// DNSName is deliberately empty — see above. KeyUsages is any: an intercepted leaf is a server certificate,
	// and pinning the usage here would add a second way for this to disagree with the application for reasons
	// that have nothing to do with the question.
	opts := x509.VerifyOptions{Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}

	goOpts := opts
	goOpts.Roots = deviceRoots
	_, goErr := chain[0].Verify(goOpts)

	// Roots left nil asks the PLATFORM verifier on the systems that have one (on Windows this is CryptoAPI over
	// the same machine and user stores a browser consults), which is the verifier whose opinion differed.
	_, platformErr := chain[0].Verify(opts)

	return fingerprint, verificationSentence(goErr, platformErr)
}

// verificationSentence says what the two verifiers concluded, in their own words, without deciding between them.
func verificationSentence(goErr, platformErr error) string {
	const nameNote = " (the chain was checked for its issuers, not for its name: a steered flow carries an " +
		"address, so this device has no name to check it against)"
	switch {
	case goErr != nil && platformErr != nil:
		return fmt.Sprintf("the intercepted chain is refused by BOTH verifiers on this device — go: %s / platform: %s%s",
			trimVerifier(goErr), trimVerifier(platformErr), nameNote)
	case goErr != nil:
		// The 2026-08-21 shape, exactly.
		return fmt.Sprintf("the verifiers on this device DISAGREE about the intercepted chain: the platform accepts "+
			"it and Go refuses it — go: %s. An application's outcome depends on which verifier it uses%s",
			trimVerifier(goErr), nameNote)
	case platformErr != nil:
		return fmt.Sprintf("the verifiers on this device DISAGREE about the intercepted chain: Go accepts it and the "+
			"platform refuses it — platform: %s. An application's outcome depends on which verifier it uses%s",
			trimVerifier(platformErr), nameNote)
	default:
		// ★ SUCCESS IS A STATEMENT TOO, AND IT IS THE ONE THAT NARROWS A LIVE OUTAGE. On 2026-08-22 this box's
		// certificate store held the announced root and was correct while the FILE-based stores that Node, curl
		// and git read still held the retired one, and every HTTPS tool on the machine was dead for three hours.
		// "The device can verify this and your tool cannot" is the sentence that separates a deployment problem
		// from a machine's own configuration, and nothing else here can say it.
		return "the agent verified the intercepted chain against this device's own trust stores and " +
			interceptionVerifiedMarker + ", so the interception material is not the problem — a tool that is still " +
			"failing here is not reading these stores (a process reads its trust store when it starts, and the " +
			"file-based stores NODE_EXTRA_CA_CERTS/SSL_CERT_FILE name are not the machine store)" + nameNote
	}
}

// trimVerifier keeps a verifier's sentence intact but bounded. It does NOT classify: "x509: certificate signed by
// unknown authority" and "x509: ... path length constraint exceeded" are different facts, and the whole reason
// this path exists is that they were flattened into one for most of a day.
func trimVerifier(err error) string {
	s := strings.TrimSpace(err.Error())
	if len(s) > maxVerifierSentenceLen {
		s = s[:maxVerifierSentenceLen]
	}
	return s
}

// maxVerifierSentenceLen is what each verifier gets to say. The worst case is the sentence that carries BOTH of
// them plus the note about the name that could not be checked, and that whole thing has to fit inside
// maxInterceptionReasonLen or the journal cuts the tail — which is where the second verifier's disagreement is.
// Real x509 sentences are 60–130 characters, including the parenthesised pathLenConstraint one; this is
// deliberately roomier than that and still inside the budget. TestEverySentenceFitsInTheJournal holds the line.
const maxVerifierSentenceLen = 175
