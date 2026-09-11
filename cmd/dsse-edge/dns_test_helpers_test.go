package main

// fakeUpstreamDNS is a canned dnsresolver.UpstreamDNS for tests (returns a fixed reply for any query). It used
// to live in dns_over_tunnel_test.go; that file moved to oss/dnsresolver with the handler, but other cmd/edge
// tests (e.g. edge_hardening_fuzz_test.go) still need a local upstream stub, so it is kept here.
type fakeUpstreamDNS struct{ reply []byte }

func (f fakeUpstreamDNS) Resolve(_ []byte) ([]byte, error) { return f.reply, nil }
