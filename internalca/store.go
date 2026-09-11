// Package internalca holds the certificate authorities that issue certificates for ONE ORGANIZATION'S PRIVATE
// ASSETS — the intranet server behind a connector, the internal API, the appliance on a VLAN.
//
// ★★★ WHY THIS OBJECT EXISTS AT ALL (2026-09-01, found by walking an intercepted internal flow end to end).
// Interception makes the Edge the TLS *client* to the private asset. That direction had no trust anywhere in
// the deployment: the Edge verified the asset against the operating system's public roots, so every intranet
// server with an internal certificate — which is what an intranet server has — was refused after being
// decrypted. The device saw a correctly minted certificate and a working handshake, and then the page never
// arrived. Interception without this object can inspect an internal flow but cannot deliver it.
//
// ★★ WHY NOT REUSE THE ORGANIZATION'S INTERCEPTION ROOT. It is sitting right there on the Edge, it belongs to
// the same organization, and trusting it here would have made the lab go green in ten minutes. It is a
// different thing with a similar name: the interception root exists to be trusted BY DEVICES for certificates
// THIS DEPLOYMENT MINTS. Pointing the Edge's upstream verification at it would mean any holder of that key
// could impersonate any private asset, and it would silently pass an organization whose internal PKI is not
// the deployment's — the common case. The near thing with a similar name has been the wrong answer here often
// enough to name it: this is a separate object, authored separately, by the organization that owns the assets.
//
// The authority list is per organization and nothing else consults it: it widens trust only for that
// organization's own flows, to that organization's own private assets.
package internalca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Authority is one CA an organization vouches for when its Edges verify one of its private assets.
type Authority struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`

	// Read-only, filled in from the certificate itself so a reader never has to decode PEM to see what they
	// pasted. A screen that shows only the name someone typed cannot show that they pasted the wrong file.
	Subject   string `json:"subject,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	Expired   bool   `json:"expired,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Persistence is the durable home of the list. Nil means memory only, which is a test shape and never a
// deployment one: an Edge that keeps this list in memory forgets every organization's private assets on
// restart and refuses them until someone notices.
type Persistence interface {
	LoadAll() ([]Authority, error)
	Upsert(Authority) error
	Delete(id, tenantID string) error
}

type Store struct {
	mu          sync.RWMutex
	authorities map[string]Authority // keyed id+"\x00"+tenant
	persist     Persistence

	// ★ A CACHE THAT NEVER LEARNS IS WORSE THAN NO CACHE. The data path caches a built trust pool per
	// organization; without a value that changes when the list does, an authority pasted by an administrator
	// would not be used until the Edge restarted, and one deleted would keep being trusted. Every mutation
	// bumps this, and the data path's cache key carries it.
	revision map[string]uint64

	// Non-empty when this Edge has no durable home for the list. Reads answer empty and writes are refused
	// with this text, so nothing is quietly accepted and then lost.
	unavailable string
}

// NewUnavailableStore is what a deployment gets when the durable home cannot be reached — most often because
// the table has not been created on this node.
//
// ★★★ THE ABSENCE OF THIS FEATURE MUST NOT TAKE A NODE DOWN (2026-09-01, and it did: adding the store with a
// log.Fatalf on init put BOTH control planes of a region into a restart loop within a minute of the roll,
// because that node had not run the migration. A region lost its admin plane over an object no flow on it was
// using yet.) Nor may it come up pretending to work: an empty in-memory list would refuse every private asset
// while the Console showed a screen where authorities could be typed and lost. So it comes up REFUSING WRITES
// WITH THE REASON, which is the only state that is both survivable and honest.
func NewUnavailableStore(reason string) *Store {
	return &Store{authorities: map[string]Authority{}, revision: map[string]uint64{}, unavailable: strings.TrimSpace(reason)}
}

func NewStore(persist Persistence) (*Store, error) {
	s := &Store{authorities: map[string]Authority{}, persist: persist, revision: map[string]uint64{}}
	if persist == nil {
		return s, nil
	}
	loaded, err := persist.LoadAll()
	if err != nil {
		return nil, err
	}
	for _, a := range loaded {
		s.authorities[key(a.ID, a.TenantID)] = a
	}
	return s, nil
}

func key(id, tenant string) string {
	return strings.TrimSpace(id) + "\x00" + strings.TrimSpace(tenant)
}

// Describe parses the pasted material and rejects what cannot serve as an anchor. It is deliberately strict
// and says WHICH of the reasons applies: "invalid certificate" sends a reader to re-copy a file that was
// fine, when what was wrong was that they pasted a server's certificate instead of its issuer's.
func Describe(certificatePEM string, now time.Time) (subject string, notAfter time.Time, err error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certificatePEM)))
	if block == nil {
		return "", time.Time{}, fmt.Errorf("this is not certificate material: no PEM block was found (it should begin with -----BEGIN CERTIFICATE-----)")
	}
	if block.Type != "CERTIFICATE" {
		return "", time.Time{}, fmt.Errorf("this PEM block is a %q, not a certificate", block.Type)
	}
	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		return "", time.Time{}, fmt.Errorf("this certificate could not be read: %w", parseErr)
	}
	if !cert.IsCA {
		return "", time.Time{}, fmt.Errorf("%q is a certificate, not a certificate authority — paste the authority that ISSUED your server's certificate, not the server's own", cert.Subject.String())
	}
	if now.After(cert.NotAfter) {
		return cert.Subject.String(), cert.NotAfter, fmt.Errorf("%q expired on %s", cert.Subject.String(), cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return cert.Subject.String(), cert.NotAfter, nil
}

func (s *Store) Upsert(a Authority, now time.Time) (Authority, error) {
	a.ID = strings.TrimSpace(a.ID)
	a.TenantID = strings.TrimSpace(a.TenantID)
	a.Name = strings.TrimSpace(a.Name)
	a.CertificatePEM = strings.TrimSpace(a.CertificatePEM)
	if s.unavailable != "" {
		return Authority{}, fmt.Errorf("this deployment cannot store internal certificate authorities yet: %s", s.unavailable)
	}
	if a.ID == "" {
		return Authority{}, fmt.Errorf("an authority needs an id")
	}
	if a.TenantID == "" {
		return Authority{}, fmt.Errorf("an authority belongs to one organization and none was given")
	}
	subject, notAfter, err := Describe(a.CertificatePEM, now)
	if err != nil {
		return Authority{}, err
	}
	a.Subject, a.NotAfter, a.Expired = subject, notAfter.UTC().Format(time.RFC3339), false
	stamp := now.UTC().Format(time.RFC3339)
	s.mu.Lock()
	if existing, ok := s.authorities[key(a.ID, a.TenantID)]; ok && existing.CreatedAt != "" {
		a.CreatedAt = existing.CreatedAt
	} else {
		a.CreatedAt = stamp
	}
	a.UpdatedAt = stamp
	s.authorities[key(a.ID, a.TenantID)] = a
	s.revision[a.TenantID]++
	s.mu.Unlock()
	if s.persist != nil {
		if err := s.persist.Upsert(a); err != nil {
			return Authority{}, err
		}
	}
	return a, nil
}

func (s *Store) Delete(id, tenantID string, _ time.Time) bool {
	s.mu.Lock()
	_, ok := s.authorities[key(id, tenantID)]
	delete(s.authorities, key(id, tenantID))
	s.revision[strings.TrimSpace(tenantID)]++
	s.mu.Unlock()
	if ok && s.persist != nil {
		_ = s.persist.Delete(strings.TrimSpace(id), strings.TrimSpace(tenantID))
	}
	return ok
}

// List returns one organization's authorities, with expiry recomputed at read time so a screen shows an
// authority that has expired SINCE it was pasted.
func (s *Store) List(tenantID string, now time.Time) []Authority {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Authority{}
	for _, a := range s.authorities {
		if a.TenantID != tenantID {
			continue
		}
		if subject, notAfter, err := Describe(a.CertificatePEM, now); err == nil {
			a.Subject, a.NotAfter = subject, notAfter.UTC().Format(time.RFC3339)
			a.Expired = false
		} else {
			a.Expired = true
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ReplaceTenant is how an Edge takes a control plane's answer: the control plane is authoritative, so an
// authority it does not list is one this Edge must stop trusting.
func (s *Store) ReplaceTenant(tenantID string, authorities []Authority) {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, a := range s.authorities {
		if a.TenantID == tenantID {
			delete(s.authorities, k)
		}
	}
	for _, a := range authorities {
		a.TenantID = tenantID
		s.authorities[key(a.ID, tenantID)] = a
	}
	s.revision[tenantID]++
}

// Revision changes whenever this organization's list changes. It exists for caches downstream.
func (s *Store) Revision(tenantID string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision[strings.TrimSpace(tenantID)]
}

// AnchorsPEM is what the data path asks: the PEM of every anchor this organization vouches for, skipping any
// that no longer reads or has expired.
//
// ★ PEM, NOT A BUILT POOL. The caller has to ADD these to the platform's roots, and an *x509.CertPool cannot
// be merged into another one — it exposes no iteration. Returning a pool here forced the caller to either
// replace the system roots (an internet-wide outage for that organization) or write a merge that silently did
// nothing. Handing back the material lets the caller build one pool that holds both.
func (s *Store) AnchorsPEM(tenantID string, now time.Time) []string {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{}
	for _, a := range s.authorities {
		if a.TenantID != tenantID {
			continue
		}
		if _, _, err := Describe(a.CertificatePEM, now); err != nil {
			continue // an expired or unreadable anchor is not quietly used
		}
		out = append(out, a.CertificatePEM)
	}
	sort.Strings(out)
	return out
}

// ListAll is the fleet answer: every organization's authorities. Only the operator organization may ask, and
// only the Edges use it — a data-plane Edge carries flows for MANY organizations, so pulling only its own
// node's list would leave every other organization's private assets refused. That is the same mistake this
// deployment made eight times in one day: a question about somebody else answered with an attribute of this
// node.
func (s *Store) ListAll(now time.Time) []Authority {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Authority{}
	for _, a := range s.authorities {
		if subject, notAfter, err := Describe(a.CertificatePEM, now); err == nil {
			a.Subject, a.NotAfter = subject, notAfter.UTC().Format(time.RFC3339)
		} else {
			a.Expired = true
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ReplaceAll is how an Edge takes the control plane's whole answer. It replaces EVERY organization's list,
// including emptying one the control plane no longer lists: replacing organization by organization would keep
// trusting an authority for an organization that was deleted, because nothing would ever mention it again.
func (s *Store) ReplaceAll(authorities []Authority) {
	s.mu.Lock()
	defer s.mu.Unlock()
	touched := map[string]bool{}
	for tenant := range s.revision {
		touched[tenant] = true
	}
	s.authorities = map[string]Authority{}
	for _, a := range authorities {
		a.TenantID = strings.TrimSpace(a.TenantID)
		if a.TenantID == "" {
			continue
		}
		s.authorities[key(a.ID, a.TenantID)] = a
		touched[a.TenantID] = true
	}
	for tenant := range touched {
		s.revision[tenant]++
	}
}

// Reload re-reads the durable home. It exists because a store that loads once at boot is a store that answers
// with whatever was true when the process started.
//
// ★★★ THE SYNC LANE I FIRST ATTACHED THIS TO DOES NOT RUN ON EVERY DEPLOYMENT (2026-09-01). The control-plane
// pull is configured only where an Edge has no database of its own; on a deployment where the Edges share the
// control plane's database, nothing pulled and nothing re-read, so an authority an administrator added was
// invisible until every Edge was restarted — and the Console showed it saved. Both paths now refresh: an Edge
// with a source URL pulls it, an Edge with a database re-reads it.
func (s *Store) Reload() error {
	if s.persist == nil {
		return nil
	}
	loaded, err := s.persist.LoadAll()
	if err != nil {
		return err // the last good list stands; a momentary database error must not empty it
	}
	next := map[string]Authority{}
	for _, a := range loaded {
		next[key(a.ID, a.TenantID)] = a
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(next) == len(s.authorities) {
		same := true
		for k, a := range next {
			if existing, ok := s.authorities[k]; !ok || existing.CertificatePEM != a.CertificatePEM {
				same = false
				break
			}
		}
		if same {
			return nil // nothing changed: do not move the revision, or every cache downstream rebuilds on a timer
		}
	}
	touched := map[string]bool{}
	for _, a := range s.authorities {
		touched[a.TenantID] = true
	}
	s.authorities = next
	for _, a := range next {
		touched[a.TenantID] = true
	}
	for tenant := range touched {
		s.revision[tenant]++
	}
	return nil
}

// ConfigGeneration is this store's term in the config bundle's version.
//
// ★★★ AND ITS ABSENCE IS THE DEFECT THIS DEPLOYMENT HAS NOW MADE FIVE TIMES (2026-09-01). The bundle carries
// the object and an Edge applies a bundle only when the version is NEWER, so a store outside the sum changes
// the bundle's CONTENTS without changing its VERSION and no Edge ever re-pulls. Measured here exactly as it
// was for the connector registry, the people directory, the licence and the tenant registry before it: an
// authority was DELETED on the control plane, every Edge went on trusting it, and the only reason the earlier
// ADD had worked was that a roll had restarted the fleet and made it pull unconditionally.
//
// A sum over organizations, so any organization's change moves it.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total uint64
	for _, r := range s.revision {
		total += r
	}
	return total
}
