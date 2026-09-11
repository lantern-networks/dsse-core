package dnsresolver

// Local SVCB/HTTPS test helpers for the DNS resolver tests. The ECH-strip logic itself now lives in the
// importable internal/dnsech package (with its own tests); these tiny fixtures stay with the resolver test
// until the resolver is extracted too.

const (
	dnsTypeHTTPS   = 65
	svcParamKeyECH = 5
)

// buildHTTPSRdata: SvcPriority(1) + root target + alpn(key1, "h2") + optional ech(key5, 4 bytes).
func buildHTTPSRdata(withECH bool) []byte {
	d := []byte{0x00, 0x01, 0x00}                         // priority=1, target=root(0x00)
	d = append(d, 0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2') // alpn: key=1, len=3, value=[0x02 'h' '2']
	if withECH {
		d = append(d, 0x00, 0x05, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF) // ech: key=5, len=4, value=DEADBEEF
	}
	return d
}
