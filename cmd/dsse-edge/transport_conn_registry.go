package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

// transportConnRegistry tracks LIVE (T) connections by their admitted transport identity so a revocation can
// ACTIVELY close established sessions — not merely reject new handshakes. Per-handshake admission
// (secure_transport.go VerifyConnection) already denies a revoked identity's NEW connections within one
// revocation-sync interval (~2s), but an already-established long-lived (T) tunnel is not re-handshaked and so
// would otherwise persist until the client's region-failover tears it down. Wiring
// AdmissionRevocations.SetOnRevoked -> CloseIdentity closes those established tunnels in ~2s too.
//
// Connections self-register LAZILY once their TLS handshake completes (only ADMITTED identities get that far;
// VerifyConnection rejects the rest before any data plane), and unregister on Close.
// revocableConn is the minimal contract the registry needs from a tracked connection (so the map logic is
// unit-testable with a fake). *trackedTransportConn satisfies it.
type revocableConn interface{ Close() error }

// normConnID normalizes a transport identity the SAME way admission does (revocation.normalizeIdentity is
// lower+trim), so the registry keys match the lowercased ids that CloseIdentity/onRevoked look up. Without this
// a non-lowercase cert CN (e.g. a Windows hostname DESKTOP-01) would register under a raw key and CloseIdentity
// would miss it — silently defeating active session revocation for that device.
func normConnID(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

type transportConnRegistry struct {
	mu    sync.Mutex
	conns map[string]map[revocableConn]struct{}
	// ids is the reverse index (conn -> identity) so a connection can unregister ITSELF on Close without
	// knowing its identity. Needed because the tracked connection is now the RAW conn, which is handed to the
	// TLS layer before any identity exists (see wrap).
	ids map[revocableConn]string
	// revoked, when wired, reports whether an identity is currently revoked. Used to close a connection that
	// registered just AFTER a CloseIdentity sweep already ran (the register-after-sweep TOCTOU).
	revoked func(id string) (string, bool)
}

func newTransportConnRegistry() *transportConnRegistry {
	return &transportConnRegistry{
		conns: map[string]map[revocableConn]struct{}{},
		ids:   map[revocableConn]string{},
	}
}

// setRevokedCheck wires the current-revocation-state probe (edge: AdmissionRevocations.IsRevoked).
func (r *transportConnRegistry) setRevokedCheck(fn func(id string) (string, bool)) {
	if r != nil {
		r.revoked = fn
	}
}

func (r *transportConnRegistry) register(id string, c revocableConn) {
	if r == nil || c == nil {
		return
	}
	id = normConnID(id)
	if id == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.conns[id]
	if set == nil {
		set = map[revocableConn]struct{}{}
		r.conns[id] = set
	}
	set[c] = struct{}{}
	if r.ids == nil {
		r.ids = map[revocableConn]string{}
	}
	r.ids[c] = id
}

// unregisterConn removes c without the caller knowing its identity — the Close path of a tracked RAW conn,
// which is created before the TLS handshake assigns any identity. A no-op for a never-registered conn (a
// handshake that was rejected at admission never reaches register).
func (r *transportConnRegistry) unregisterConn(c revocableConn) {
	if r == nil || c == nil {
		return
	}
	r.mu.Lock()
	id, ok := r.ids[c]
	r.mu.Unlock()
	if !ok {
		return
	}
	r.unregister(id, c)
}

func (r *transportConnRegistry) unregister(id string, c revocableConn) {
	if r == nil || c == nil {
		return
	}
	id = normConnID(id)
	if id == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if set := r.conns[id]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(r.conns, id)
		}
	}
	delete(r.ids, c)
}

// CloseIdentity closes every live (T) connection for id and returns the count closed. Idempotent: a no-op when
// the identity has no live connections (e.g. it was only ever rejected at handshake, or already torn down).
// The connections are collected under the lock and closed OUTSIDE it (Close -> unregister re-takes the lock).
func (r *transportConnRegistry) CloseIdentity(id string) int {
	if r == nil {
		return 0
	}
	id = normConnID(id)
	if id == "" {
		return 0
	}
	r.mu.Lock()
	set := r.conns[id]
	victims := make([]revocableConn, 0, len(set))
	for c := range set {
		victims = append(victims, c)
	}
	r.mu.Unlock()
	for _, c := range victims {
		_ = c.Close()
	}
	return len(victims)
}

// wrap returns a tracking listener over the RAW (pre-TLS) listener. Each accepted connection is wrapped in a
// trackedRawConn that unregisters itself on Close; the identity is attached later, during the TLS handshake
// (see secure_transport.go attachConnRegistryTracking). When the registry is nil the listener is returned
// unchanged (feature off).
//
// ★ It MUST wrap the raw listener, NOT the tls.Listener — do not "simplify" this back.
//
// The first version of this file wrapped the *tls.Conn that tls.NewListener returns, in a struct that embedded
// it and forwarded every method. That took the whole fleet offline on 2026-07-27: the mTLS handshake still
// succeeded and nothing errored on either side, but the real macOS NE could no longer carry a (T) tunnel.
// Established by live bisect against the real client (3f787f5b works / aa50744d broken / HEAD broken /
// this shape works), and narrowed to the wrapper — re-adding the revocation callback alone did not break it.
//
// The precise mechanism is NOT known. Three plausible explanations were each tested and disproven (r.TLS going
// nil, the ALPN h2 handoff being skipped, a hijacked tunnel not carrying bytes) — see the note on
// TestSecureTransportListenerSupportsHijackedTunnel. Handing the TLS layer a plain net.Conn and letting
// tls.NewListener produce an untouched *tls.Conn avoids the whole class, so that is what this does.
func (r *transportConnRegistry) wrap(ln net.Listener) net.Listener {
	if r == nil || ln == nil {
		return ln
	}
	return &trackingTransportListener{Listener: ln, reg: r}
}

type trackingTransportListener struct {
	net.Listener
	reg *transportConnRegistry
}

func (l *trackingTransportListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackedRawConn{Conn: c, reg: l.reg}, nil
}

// trackedRawConn is the raw (pre-TLS) connection handed to tls.NewListener. It exists only so the connection
// can remove itself from the registry when it closes; closing it also tears down the TLS session above it,
// which is what makes CloseIdentity an effective kill-switch.
type trackedRawConn struct {
	net.Conn
	reg *transportConnRegistry
}

func (c *trackedRawConn) Close() error {
	c.reg.unregisterConn(c)
	return c.Conn.Close()
}

// logCloseIdentity is the SetOnRevoked hook: close a newly-revoked identity's live (T) sessions and log it.
func (r *transportConnRegistry) logCloseIdentity(identity, reason string) {
	if n := r.CloseIdentity(identity); n > 0 {
		log.Printf("transport_session_revoked identity=%q reason=%q closed_live_connections=%d (active kill-switch: established tunnels torn down, not just new handshakes)", identity, reason, n)
	}
}
