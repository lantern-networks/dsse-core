package engine

import "sync/atomic"

// PeerGuardFunc inspects the address a transfer actually connected to, before any byte of the request is
// sent. Returning an error aborts the transfer.
type PeerGuardFunc func(ip string) error

var peerGuard atomic.Pointer[PeerGuardFunc]

// SetPeerGuard installs the process-wide check applied to every connection this engine makes, at the moment
// the peer address is known and before the request goes out.
//
// Why this hook exists rather than validating the destination up front: a hostname check and the dial are two
// separate resolutions, so a name that resolved to a public address when it was checked can resolve to an
// internal one when it is dialed. Every OTHER egress path in this product already checks the CONNECTED PEER
// for exactly that reason; the re-origination path could not, because the dial happens inside libcurl. This
// closes that gap by putting the same question at the same place: not "where should this go" but "where did
// this actually connect".
//
// The policy itself is deliberately NOT here. The engine is transport, with no security logic and no opinion
// about which addresses are forbidden — the host supplies that, so the block list has one definition in one
// place and this package gains no dependency on it. Unset (the zero value) means no check, which is the right
// default for a transport: a host that wants a guard installs one.
func SetPeerGuard(f PeerGuardFunc) {
	if f == nil {
		peerGuard.Store(nil)
		return
	}
	peerGuard.Store(&f)
}

// checkPeer runs the installed guard. Called from the cgo pre-request callback on the transfer's thread.
func checkPeer(ip string) error {
	f := peerGuard.Load()
	if f == nil {
		return nil
	}
	return (*f)(ip)
}
