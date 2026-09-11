package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	certreload "github.com/lantern-networks/dsse-core/certreload"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// transportServedCert is the hot-reloadable certificate the transport listeners present; nil when the
// transport is startup-fixed or lab-auto-generated.
var transportServedCert *certreload.ReloadableCert

var errNoServedTransportCert = errors.New("no transport certificate is being served")

// What devices have actually SEEN, as opposed to what this node is now serving.
//
// A hot reload changes the certificate a NEW connection gets. Every established connection keeps the one it
// handshook with, so immediately after a replacement the fleet is split, and every check made over an
// existing connection reports success — including the check the operator makes to decide whether the
// replacement worked. On 2026-07-31 that is exactly what happened: a certificate no device could verify was
// replaced "live with no interruption", and the fleet did not fail until an Edge restart 24 minutes later
// forced everyone to re-handshake. docs/2026-07-31_edge_identity_certificate_replacement_outage.ja.md.
//
// So the Edge records, per device identity, the fingerprint of the certificate IT presented on that device's
// most recent handshake. "3 of 3 devices have re-handshaked and hold the new certificate" is a measurement;
// "the replacement was applied" is not. A device that has not reconnected is reported as still on the
// previous certificate rather than assumed fine — the assumption is the failure mode.

type serverCertSighting struct {
	Fingerprint string
	At          time.Time
}

type serverCertAdoption struct {
	mu sync.Mutex
	by map[string]serverCertSighting
	// path, when set, keeps the measurement across a restart. Without it every device reads as NotSeen the
	// moment the process restarts, and a rotation that finished yesterday is presented as one still waiting
	// for devices that already took it — absence of evidence read as evidence again (review C6).
	path string
}

var servedCertSightings = &serverCertAdoption{by: map[string]serverCertSighting{}}

// observe records which certificate this node presented to a device on its latest handshake. Observation
// only — nothing reads it to make a decision, and it can never fail a handshake.
func (a *serverCertAdoption) observe(identity string, served *x509.Certificate, now time.Time) {
	if a == nil || identity == "" || served == nil {
		return
	}
	sum := sha256.Sum256(served.Raw)
	fp := hex.EncodeToString(sum[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := a.by[identity].Fingerprint != fp
	a.by[identity] = serverCertSighting{Fingerprint: fp, At: now.UTC()}
	// Only a CHANGE is worth a write: which certificate a device holds changes on a rotation, not on every
	// handshake, so this costs nothing on the hot path.
	if changed {
		a.persistLocked()
	}
}

// load reads a previous process's measurements. A missing file is a first run, not a failure: measurement
// simply starts empty, which the report already distinguishes from "seen on the previous certificate".
func (a *serverCertAdoption) load(path string) {
	path = filepath.Clean(path)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.path = path
	blob, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("server_cert_adoption progress=load_failed detail=%v", err)
		}
		return
	}
	var stored struct {
		SchemaVersion string                        `json:"schema_version"`
		By            map[string]serverCertSighting `json:"by"`
	}
	if err := json.Unmarshal(blob, &stored); err != nil {
		log.Printf("server_cert_adoption progress=load_failed detail=%v", err)
		return
	}
	for k, v := range stored.By {
		if k != "" && v.Fingerprint != "" {
			a.by[k] = v
		}
	}
	log.Printf("server_cert_adoption progress=loaded devices=%d", len(a.by))
}

func (a *serverCertAdoption) persistLocked() {
	if a.path == "" {
		return
	}
	blob, err := json.MarshalIndent(struct {
		SchemaVersion string                        `json:"schema_version"`
		By            map[string]serverCertSighting `json:"by"`
	}{"server_cert_adoption.v1", a.by}, "", "  ")
	if err != nil {
		log.Printf("server_cert_adoption progress=persist_failed detail=%v", err)
		return
	}
	// ★ ONE DURABLE WRITE (2026-08-14). Staged by hand and finished on a bare os.Rename — see
	// ops/checks/one_durable_write.sh: the gate matched only the copies that fsync the directory, so the
	// ones that never did were invisible to it and read as compliant.
	if err := durablefile.Write(a.path, blob, 0o600); err != nil {
		log.Printf("server_cert_adoption progress=persist_failed detail=%v", err)
	}
}

func (a *serverCertAdoption) snapshot() map[string]serverCertSighting {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]serverCertSighting, len(a.by))
	for k, v := range a.by {
		out[k] = v
	}
	return out
}

// serverCertAdoptionReport is the answer to "has the replacement actually reached the fleet?".
type serverCertAdoptionReport struct {
	SchemaVersion string `json:"schema_version"`
	// ServingFingerprint is what this node hands to a new connection right now.
	ServingFingerprint string `json:"serving_fingerprint"`
	ServingSubject     string `json:"serving_subject,omitempty"`
	ServingNotBefore   string `json:"serving_not_before,omitempty"`
	// OnCurrent / OnPrevious / NotSeen are device identities, not counts alone: a count tells an operator to
	// wait, only the names tell them which device to chase.
	OnCurrent  []string `json:"on_current"`
	OnPrevious []string `json:"on_previous"`
	NotSeen    []string `json:"not_seen"`
	// MeasuringSince is the oldest sighting still held. It is what makes NotSeen readable: an empty
	// measurement on a node that started a minute ago says nothing about the fleet.
	MeasuringSince string `json:"measuring_since,omitempty"`
	// Complete is true only when EVERY enrolled device has been observed on the current certificate. Until
	// then a replacement is in flight, however healthy the deployment looks over its existing connections.
	Complete bool `json:"complete"`
}

func buildServerCertAdoption(serving *x509.Certificate, sightings map[string]serverCertSighting,
	enrolled []string) serverCertAdoptionReport {
	out := serverCertAdoptionReport{
		SchemaVersion: "admin_server_cert_adoption.v1",
		OnCurrent:     []string{}, OnPrevious: []string{}, NotSeen: []string{},
	}
	if serving != nil {
		sum := sha256.Sum256(serving.Raw)
		out.ServingFingerprint = hex.EncodeToString(sum[:])
		out.ServingSubject = serving.Subject.CommonName
		out.ServingNotBefore = serving.NotBefore.UTC().Format(time.RFC3339)
	}
	for _, id := range enrolled {
		seen, ok := sightings[id]
		switch {
		case !ok:
			out.NotSeen = append(out.NotSeen, id)
		case seen.Fingerprint == out.ServingFingerprint:
			out.OnCurrent = append(out.OnCurrent, id)
		default:
			out.OnPrevious = append(out.OnPrevious, id)
		}
	}
	oldest := time.Time{}
	for _, id := range enrolled {
		if seen, ok := sightings[id]; ok && !seen.At.IsZero() && (oldest.IsZero() || seen.At.Before(oldest)) {
			oldest = seen.At
		}
	}
	if !oldest.IsZero() {
		out.MeasuringSince = oldest.UTC().Format(time.RFC3339)
	}
	sort.Strings(out.OnCurrent)
	sort.Strings(out.OnPrevious)
	sort.Strings(out.NotSeen)
	out.Complete = len(out.OnPrevious) == 0 && len(out.NotSeen) == 0 && len(out.OnCurrent) > 0
	return out
}

// servedTransportLeaf is the leaf this node is currently presenting on the transport listener.
//
// ★★★ TWO PLACES KNEW WHAT THIS NODE SERVES AND ONLY ONE WAS ASKED (2026-09-06, read off the Console of a
// deployment built by the product's own installer). transportServedCert is set by ONE listener construction
// path (buildSecureTransportTLSConfig); a deployment whose Edge serves its door from the main listener
// registers the very same certificate through certreload and never touches that global. So this returned an
// error while /admin/certs listed the certificate by name and /admin/pki/certificates rendered it — the same
// file, read by the same process, present on the same screen.
//
// It is not a cosmetic disagreement. Every consumer of "what am I serving" then answers "cannot say", and the
// screen turns that into
//
//	Withdrawal blocked: The certificate this Edge presents cannot be read, so this cannot be judged.
//
// on EVERY transport anchor of EVERY organization — a gate that can never open, closed by a nil rather than by
// a measurement. It is also why a trust refusal could not be told from a stale one (served_is_current).
//
// The reload registry is the honest source: it is what the listeners actually present, and it is what the
// certificate inventory already reads. Ask the global first (it is exact when set), then the registry.
func servedTransportLeaf() (*x509.Certificate, error) {
	if leaf, err := leafOfReloadable(transportServedCert); err == nil {
		return leaf, nil
	}
	return registeredTransportLeaf()
}

func leafOfReloadable(r *certreload.ReloadableCert) (*x509.Certificate, error) {
	if r == nil {
		return nil, errNoServedTransportCert
	}
	c := r.Current()
	if c == nil || len(c.Certificate) == 0 {
		return nil, errNoServedTransportCert
	}
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// registeredTransportLeaf reads what the listeners present, from the registry they present it from.
//
// ★ ONE CERTIFICATE IS AN ANSWER, SEVERAL ARE NOT — and the unit is the CERTIFICATE, not the registration.
// Several listeners register the same file (the data plane, the renewal grace listener), so counting
// registrations answered "two" about one certificate and this returned nothing on the very deployment it was
// written for. certInventory has always deduplicated for the same reason; here the fingerprint is the key,
// because two files holding the same bytes are still one certificate to everyone downstream.
//
// With more than one DISTINCT certificate and no global to disambiguate, this node genuinely cannot say which
// is the transport leaf — and "cannot say" is the honest answer, not a guess dressed as a measurement.
func registeredTransportLeaf() (*x509.Certificate, error) {
	chain, err := registeredTransportChain()
	if err != nil {
		return nil, err
	}
	return chain[0], nil
}

// registeredTransportChain is the same answer as a CHAIN, for the callers that need what is presented rather
// than only its leaf.
//
// ★★★ THE FIX THAT ONLY REACHED THE REPORT (2026-09-06). servedTransportLeaf was taught to ask the registry
// and servedTransportChain — a second reader of the same question, twenty lines away — was not. So the
// deployment could say WHAT it serves (serving_sha256 appeared) while the transport-anchor withdrawal gate
// still refused with "the certificate the Edge presents cannot be read", because the gate reads the chain.
// One question, two functions, one of them fixed: the reporting improved and the blocked act stayed blocked.
// Both now come from here.
func registeredTransportChain() ([]*x509.Certificate, error) {
	var only []*x509.Certificate
	seen := map[string]bool{}
	for _, r := range certreload.Registered() {
		if r == nil {
			continue
		}
		c := r.Current()
		if c == nil || len(c.Certificate) == 0 {
			continue
		}
		chain := make([]*x509.Certificate, 0, len(c.Certificate))
		for _, der := range c.Certificate {
			if parsed, err := x509.ParseCertificate(der); err == nil {
				chain = append(chain, parsed)
			}
		}
		if len(chain) == 0 {
			continue
		}
		fp := certFingerprint(chain[0])
		if seen[fp] {
			continue
		}
		seen[fp] = true
		only = chain
	}
	if len(seen) != 1 {
		return nil, errNoServedTransportCert
	}
	return only, nil
}

// certFingerprint is the sha256 of a certificate's DER, the identifier used everywhere an operator
// correlates one certificate across screens and logs.
func certFingerprint(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
