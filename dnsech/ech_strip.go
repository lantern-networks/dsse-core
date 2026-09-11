// Package dnsech implements ECH-strip: removing the ECH (Encrypted ClientHello) SvcParam from HTTPS/SVCB
// DNS records so a client falls back to plaintext SNI, restoring SNI-based intercept/bypass at the Edge.
// This is a metadata downgrade (not a crypto break); it is intended for managed devices and should be
// disclosed to users. The functions here are pure wire-format transforms (testable). The privacy-preserving
// alternative (the Edge terminates ECH) is a separate option.
//
// RR types: HTTPS = 65, SVCB = 64. SvcParamKey ech = 5 (RFC 9460 / draft-ietf-tls-svcb-ech).
package dnsech

import (
	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsTypeSVCB    = 64
	dnsTypeHTTPS   = 65
	svcParamKeyECH = 5
)

// StripECHFromDNSResponse parses a wire-format DNS message, removes the ech SvcParam from every
// HTTPS/SVCB resource record (answers / authorities / additionals), and re-packs. Returns the
// (possibly unchanged) message, the number of RRs from which ech was stripped, and an error. On a
// parse/pack error the original bytes are returned unchanged with err set (fail-open: never corrupt).
//
// As of golang.org/x/net dnsmessage, HTTPS/SVCB records are parsed into typed *HTTPSResource/*SVCBResource
// (priority + target + ordered SvcParams), so this uses DeleteParam(SVCParamECH) — a structural removal that
// re-packs with the remaining params in the required key order. (Earlier x/net returned an UnknownResource
// whose raw RDATA had to be hand-edited; the typed API supersedes that.)
func StripECHFromDNSResponse(raw []byte) ([]byte, int, error) {
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		return raw, 0, err
	}
	stripped := 0
	stripSection := func(rrs []dnsmessage.Resource) {
		for i := range rrs {
			switch body := rrs[i].Body.(type) {
			case *dnsmessage.HTTPSResource:
				if body.DeleteParam(dnsmessage.SVCParamECH) {
					stripped++
				}
			case *dnsmessage.SVCBResource:
				if body.DeleteParam(dnsmessage.SVCParamECH) {
					stripped++
				}
			}
		}
	}
	stripSection(m.Answers)
	stripSection(m.Authorities)
	stripSection(m.Additionals)
	if stripped == 0 {
		return raw, 0, nil
	}
	out, err := m.Pack()
	if err != nil {
		return raw, 0, err // fail-open: keep the original rather than emit a corrupt response
	}
	return out, stripped, nil
}
