package main

import (
	"log"
	"net"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/dns"
	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
)

// newEdgeDNSResolverFromEnv reads the DNS resolver environment (deployment-specific env names stay in
// cmd/edge, not the OSS core) and builds the resolver via dnsresolver.New. Upstream defaults to 1.1.1.1:53.
//
//	..._DNS_RESOLVER_UPSTREAM = "1.1.1.1:53"
//	..._DNS_ECH_STRIP         = true|false  (default true — strip ECH so the Edge sees the inner SNI)
//	..._DNS_DENY              = "bad.example,evil.test"   (comma list -> NXDOMAIN)
//	..._DNS_STUB              = "app.corp=100.64.0.9,..." (fqdn=stub IPv4 list)
//	..._DNS_RESOLVER_LISTEN   = ":15353"  (legacy plaintext UDP listener; empty = disabled)
func newEdgeDNSResolverFromEnv(tenantID string, conntrack *dns.ConntrackStore) *dnsresolver.Resolver {
	deny := []string{}
	for _, d := range strings.Split(os.Getenv("DSSE_DNS_DENY"), ",") {
		if t := strings.TrimSpace(d); t != "" {
			deny = append(deny, t)
		}
	}
	stub := map[string]string{}
	for _, pair := range strings.Split(os.Getenv("DSSE_DNS_STUB"), ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 {
			stub[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return dnsresolver.New(dnsresolver.Config{
		TenantID:  tenantID,
		Upstream:  strings.TrimSpace(os.Getenv("DSSE_DNS_RESOLVER_UPSTREAM")),
		ECHStrip:  envBoolDefault("DSSE_DNS_ECH_STRIP", true),
		Deny:      deny,
		Stub:      stub,
		Conntrack: conntrack,
	})
}

// maybeStartEdgeDNSResolverUDPFromEnv starts the legacy plaintext UDP DNS listener when the env addr is set.
// DEPRECATED in favour of DNS-over-tunnel (plaintext UDP leaks the queried domain locally); kept for
// backward compatibility and lab use.
func maybeStartEdgeDNSResolverUDPFromEnv(r *dnsresolver.Resolver) net.PacketConn {
	addr := strings.TrimSpace(os.Getenv("DSSE_DNS_RESOLVER_LISTEN"))
	if addr == "" || r == nil {
		return nil
	}
	conn, err := dnsresolver.StartUDP(addr, r)
	if err != nil {
		log.Printf("edge_dns_resolver start failed (plaintext UDP DNS control inactive): %v", err)
		return nil
	}
	log.Printf("edge_dns_resolver WARNING: plaintext UDP DNS listener active on %s — DEPRECATED, prefer DNS-over-tunnel (queries on plaintext UDP leak the domain locally)", addr)
	return conn
}
