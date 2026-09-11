package edgeplane

import (
	"crypto/hkdf"
	"crypto/sha256"
	"os"
	"strconv"
	"strings"
	"time"
)

// Fleet-wide TLS session-ticket keys.
//
// THE PROBLEM (raised by the operator, 2026-07-28): behind a load balancer, a client that lands on a different
// Edge cannot resume its TLS session, so every rebalance costs a full handshake — asymmetric crypto, on a
// datapath where one endpoint holds many concurrent host connections under decrypt-all. Sharing the
// interception CA does not help: resumption depends on the SESSION TICKET KEY, and that was generated with
// rand.Read at process start. The comment on it said "process-stable", which is exactly the gap — it was never
// fleet-stable. (docs/pki_ideal_lifecycle_design.ja.md)
//
// THE FIX: derive the key from a secret every Edge in the fleet holds, so no coordination or shared storage is
// needed — same secret in, same key out.
//
// ROTATION IS NOT OPTIONAL. A ticket key that never changes undermines forward secrecy: anyone who later
// obtains it can decrypt every session that resumed under it. So the key is derived from (secret, EPOCH) where
// the epoch advances on a timer, and BOTH the current and previous epoch keys are installed. Go uses the first
// for new tickets and tries all of them when decrypting, so a ticket issued moments before a rollover still
// resumes instead of silently forcing the handshake the whole mechanism exists to avoid.

const (
	// sessionTicketRotationPeriod bounds how long one ticket key is used. Short enough that a leaked key
	// exposes a limited window, long enough that clients keep resuming across ordinary reconnects.
	sessionTicketRotationPeriod = 24 * time.Hour
	sessionTicketHKDFInfo       = "dsse interception session ticket key v1"
)

// fleetSessionTicketKeys derives the ticket keys every Edge sharing `secret` will independently arrive at.
//
// Returns (nil, false) when no secret is configured: the caller then keeps the existing per-process random
// key, which is correct for a single Edge and merely loses cross-node resumption. Silently deriving from an
// empty secret would be far worse — every deployment on earth would share a predictable ticket key.
func fleetSessionTicketKeys(secret string, now time.Time) ([][32]byte, bool) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, false
	}
	epoch := now.UTC().Unix() / int64(sessionTicketRotationPeriod/time.Second)
	// Current first (Go issues new tickets with keys[0]), then the previous epoch so tickets issued just
	// before the rollover still decrypt. Without the overlap every rotation would force a fleet-wide
	// handshake storm — the exact cost this is meant to remove.
	cur, err := deriveSessionTicketKey(secret, epoch)
	if err != nil {
		return nil, false
	}
	prev, err := deriveSessionTicketKey(secret, epoch-1)
	if err != nil {
		return [][32]byte{cur}, true
	}
	return [][32]byte{cur, prev}, true
}

func deriveSessionTicketKey(secret string, epoch int64) ([32]byte, error) {
	var out [32]byte
	// The epoch is the SALT, not part of the info string: it is the value that varies per rotation, which is
	// what a salt is for, and it keeps the info string a stable protocol label.
	k, err := hkdf.Key(sha256.New, []byte(secret), []byte(strconv.FormatInt(epoch, 10)), sessionTicketHKDFInfo, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], k)
	return out, nil
}

// interceptionSessionTicketSecret reads the fleet secret. Env rather than a flag so it is not visible in `ps`
// to every user on the host — it is a key-derivation secret, not a tuning knob.
func interceptionSessionTicketSecret() string {
	return strings.TrimSpace(os.Getenv("DSSE_INTERCEPTION_SESSION_TICKET_SECRET"))
}
