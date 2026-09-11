package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// verify_device_admission.go — step 7 of the install order, which nothing has ever walked.
//
// ★★★ ENROLMENT IS NOT ADMISSION, AND THE CHECKS STOPPED AT ENROLMENT. -verify issued a certificate to a
// device and threw the private key away on the next line. So what was established was that the deployment can
// MINT an identity — not that a device holding one can carry a single byte of traffic. Those are different
// deployments, and this repository has shipped the gap between them more than once: a device enrolled
// cleanly, appeared on every screen, and was refused at the handshake, because the Edge's trust set was built
// at boot and the authority that signed it was registered afterwards.
//
// ★★★ AND REMOVAL HAS TO BE REVOCATION, OR THE INVENTORY IS A LIST OF NAMES. A certificate outlives the
// enrolment that produced it. If an Edge admits anything with a signature it can verify, then taking a device
// out of the inventory changes a screen and nothing else — the machine goes on steering with the certificate
// it already holds, and the operator who removed it has been told it is gone. The second half of this check
// exists for that, and it is the half that can fail without anybody noticing.

// deviceSteerProbe opens the steer transport the way a device agent does: mTLS with the certificate it was
// issued, then CONNECT /steer-mux. It returns the HTTP status line the Edge answered with.
func deviceSteerProbe(dir, door string, certPEM, keyPEM []byte) (string, error) {
	anchor, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		return "", fmt.Errorf("read the deployment anchor: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(anchor) {
		return "", fmt.Errorf("the deployment anchor contains no certificate")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", fmt.Errorf("the issued certificate and the key this installer generated do not pair: %w", err)
	}
	u, err := url.Parse(door)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", door, err)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", host, &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{pair},
		ServerName:   u.Hostname(),
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		// A handshake refusal IS an answer — it is how an Edge that admits at the handshake says no. Reported
		// as the outcome rather than as an error, so the caller can tell "refused" from "unreachable".
		return "handshake refused: " + err.Error(), nil
	}

	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	// The steer tunnel is opened with CONNECT, the same as the agents do. Nothing is sent through it: what is
	// being established is whether this identity is let in, not what it could carry.
	if _, err := fmt.Fprintf(conn, "CONNECT /steer-mux HTTP/1.1\r\nHost: %s\r\n\r\n", u.Hostname()); err != nil {
		return "", fmt.Errorf("write CONNECT: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		// ★★★ THE REFUSAL ARRIVES HERE, NOT AT THE DIAL (2026-08-24, measured). Under TLS 1.3 the client
		// finishes its side of the handshake without waiting, so a server that rejects the certificate sends
		// an alert that the client only sees on its first read. Treating that as "could not be reached" made
		// a working refusal read as a broken deployment — the check reported the Edge unreachable at the very
		// moment it was correctly refusing a blocked device.
		if isTLSRefusal(err) {
			return "handshake refused: " + err.Error(), nil
		}
		return "", fmt.Errorf("read the answer to CONNECT: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// verifyDeviceCanSteer is the enrolled device's first act: opening the transport it was enrolled for.
func verifyDeviceCanSteer(dir, door, deviceID string, certPEM, keyPEM []byte) verifyResult {
	answer, err := deviceSteerProbe(dir, door, certPEM, keyPEM)
	switch {
	case err != nil:
		return verifyResult{name: "the enrolled device can open the steer transport",
			note: fmt.Sprintf("%s could not be reached as a device: %v", door, err)}
	case strings.Contains(answer, " 200 "):
		return verifyResult{ok: true, name: "the enrolled device can open the steer transport",
			note: fmt.Sprintf("%s was admitted with the certificate it was just issued — enrolment and admission "+
				"are different deployments and this is the second one", deviceID)}
	default:
		return verifyResult{name: "the enrolled device can open the steer transport",
			note: fmt.Sprintf("%s enrolled and was then refused: %s. A device that holds a certificate this "+
				"deployment issued and cannot carry traffic is a deployment that looks correct on every screen",
				deviceID, first([]byte(answer), 200))}
	}
}

// verifyBlockingStopsTheDevice blocks the device the deployment just admitted, and asks it to steer again.
//
// ★★★ IT BLOCKS RATHER THAN REMOVES, AND THAT IS A STATEMENT ABOUT THE PRODUCT, NOT A CONVENIENCE. Blocking
// is what an administrator does to stop a machine, and it is the only one of the two that a fleet can carry:
// the entry stays and says enabled=false, so every Edge learns the refusal. REMOVING a device deletes the
// entry, which on every other node is indistinguishable from a device it has not been told about yet — and a
// door that refused those would refuse every agent in the seconds between enrolling and connecting. Removal
// therefore does NOT stop a machine today; that gap is recorded in the Edge's own admission code and needs a
// removal that leaves something behind.
//
// ★★ AND IT WAITS, BECAUSE THE ANSWER TRAVELS. The block is authored on the control plane and reaches an Edge
// in its next pull. A probe run immediately would measure the poll interval and call it a defect. How long it
// took is reported, because "it stops within N seconds" is the honest form of this promise and an operator
// deserves the number.
func verifyBlockingStopsTheDevice(dir, door, deviceID string, certPEM, keyPEM []byte,
	block func() (int, error)) verifyResult {
	if code, err := acceptedWithin(block, 60*time.Second); err != nil || (code != 200 && code != 204) {
		return verifyResult{name: "blocking a device stops it steering",
			note: fmt.Sprintf("%s could not be blocked, for a minute: %d %v", deviceID, code, err)}
	}
	deadline := time.Now().Add(90 * time.Second)
	started := time.Now()
	for {
		answer, err := deviceSteerProbe(dir, door, certPEM, keyPEM)
		if err != nil {
			return verifyResult{name: "blocking a device stops it steering",
				note: fmt.Sprintf("%s could not be reached as a device: %v", door, err)}
		}
		if !strings.Contains(answer, " 200 ") {
			return verifyResult{ok: true, name: "blocking a device stops it steering",
				note: fmt.Sprintf("%s was refused %s after it was blocked: %s", deviceID,
					time.Since(started).Round(time.Second), first([]byte(answer), 100))}
		}
		if time.Now().After(deadline) {
			return verifyResult{name: "blocking a device stops it steering",
				note: fmt.Sprintf("%s was BLOCKED and was still admitted after %s. An administrator who blocks "+
					"a machine has been told it is stopped; it is carrying traffic with the certificate it "+
					"already holds", deviceID, time.Since(started).Round(time.Second))}
		}
		time.Sleep(3 * time.Second)
	}
}

// isTLSRefusal reports that an error is the far side saying no at the TLS layer rather than the connection
// failing. Matched on the alert text because that is what crypto/tls gives a client: the alert is opaque
// bytes, and the deployment's answer to "may this device in" is exactly what it encodes.
func isTLSRefusal(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "remote error: tls:") || strings.Contains(msg, "tls: bad certificate")
}

// verifyRemovalStopsTheDevice is the same probe after the device has been REMOVED rather than blocked.
//
// ★★★ REMOVAL USED NOT TO STOP ANYTHING, AND THE REASON WAS THAT AN ABSENCE CANNOT TRAVEL. Deleting the entry
// made a removed device indistinguishable, on every other node, from one that node had not been told about
// yet — and a fleet learns about an enrolment a poll after it happens. The ledger now keeps a tombstone, which
// is a fact the config bundle can carry, so this is checkable at all.
func verifyRemovalStopsTheDevice(dir, door, deviceID string, certPEM, keyPEM []byte) verifyResult {
	deadline := time.Now().Add(90 * time.Second)
	started := time.Now()
	for {
		answer, err := deviceSteerProbe(dir, door, certPEM, keyPEM)
		if err != nil {
			return verifyResult{name: "a removed device can no longer steer",
				note: fmt.Sprintf("%s could not be reached as a device: %v", door, err)}
		}
		if !strings.Contains(answer, " 200 ") {
			return verifyResult{ok: true, name: "a removed device can no longer steer",
				note: fmt.Sprintf("%s was refused %s after it was removed: %s", deviceID,
					time.Since(started).Round(time.Second), first([]byte(answer), 100))}
		}
		if time.Now().After(deadline) {
			return verifyResult{name: "a removed device can no longer steer",
				note: fmt.Sprintf("%s was REMOVED from the inventory and was still admitted after %s. Its "+
					"certificate outlives the enrolment that produced it, so the removal changed a screen and "+
					"not what the machine can do", deviceID, time.Since(started).Round(time.Second))}
		}
		time.Sleep(3 * time.Second)
	}
}

// verifyUnblockingRestoresTheDevice puts the device back and waits for it to be admitted again.
//
// ★★★ IT IS ALSO WHAT MAKES THE REMOVAL CHECK MEAN ANYTHING (2026-08-24, caught by reading the number). The
// removal check ran on a device that was still blocked from the check before it, and reported "refused 0s
// after it was removed" — a pass that would have held with removal doing nothing at all. A control has to be
// able to fail, and this is what returns the device to a state where refusing it is news.
//
// It is worth checking for itself too: an operator who blocks a machine has to be able to unblock it, and a
// block that cannot be undone is a deletion with a friendlier name.
func verifyUnblockingRestoresTheDevice(dir, door, deviceID string, certPEM, keyPEM []byte,
	unblock func() (int, error)) verifyResult {
	if code, err := acceptedWithin(unblock, 60*time.Second); err != nil || (code != 200 && code != 204) {
		return verifyResult{name: "unblocking a device lets it steer again",
			note: fmt.Sprintf("%s could not be unblocked, for a minute: %d %v", deviceID, code, err)}
	}
	deadline := time.Now().Add(90 * time.Second)
	started := time.Now()
	for {
		answer, err := deviceSteerProbe(dir, door, certPEM, keyPEM)
		if err == nil && strings.Contains(answer, " 200 ") {
			return verifyResult{ok: true, name: "unblocking a device lets it steer again",
				note: fmt.Sprintf("%s was admitted again %s after the block was lifted", deviceID,
					time.Since(started).Round(time.Second))}
		}
		if time.Now().After(deadline) {
			return verifyResult{name: "unblocking a device lets it steer again",
				note: fmt.Sprintf("%s was unblocked and is still refused after %s. A block that cannot be "+
					"undone is a deletion with a friendlier name", deviceID, time.Since(started).Round(time.Second))}
		}
		time.Sleep(3 * time.Second)
	}
}

// acceptedWithin retries an administrative act until the node being asked accepts it.
//
// ★★★ A CONTROL PLANE THAT IS NOT THE LEADER LEARNS OF A DEVICE ON ITS OWN SCHEDULE (2026-08-26, measured —
// and it cost hours before it was understood). The roster is authored by whoever holds leadership; a standby
// re-reads it every fifteen seconds. So a device enrolled a moment ago is genuinely unknown to a standby, and
// blocking it there answers 404 — correctly. This walk enrols a device and immediately administers it, and it
// is routinely pointed at whichever control plane an operator names, which is a standby half the time.
//
// Reporting that 404 as "blocking does not work" is worse than not checking: it is a check that fails for a
// reason that is not the product, and a check that cries wolf is one an operator learns to skip. Three of this
// walk's results were exactly that.
//
// ★ IT STILL FAILS IF THE ACT NEVER LANDS. A minute is far longer than any reload interval here, so "not yet"
// and "never" stay distinguishable — and the message says the waiting happened.
func acceptedWithin(act func() (int, error), within time.Duration) (int, error) {
	deadline := time.Now().Add(within)
	var code int
	var err error
	for {
		code, err = act()
		if err == nil && (code == 200 || code == 204) {
			return code, nil
		}
		if time.Now().After(deadline) {
			return code, err
		}
		time.Sleep(3 * time.Second)
	}
}
