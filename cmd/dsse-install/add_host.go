package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// add_host.go — a deployment learns another name it answers on, WITHOUT re-minting.
//
// ★★★ WHY THIS HAD TO EXIST (2026-08-25, reported from win-dev-1 after it could no longer steer).
//
// The certificates are issued once, from the hosts given at install. issueServerCertificates already says
// what happens when one is missing: "repaired only by re-minting, which orphans every anchor already
// distributed". A remote endpoint then measured exactly that. This deployment was generated on a laptop with
// localhost names, and the box reaching it over a tailnet found:
//
//	Subject : CN=localhost
//	SAN     : localhost / agents.localhost / ... / IP 203.0.113.120 / IP 10.77.0.10
//	          — neither shinmac-mini.tail04460b.ts.net nor 100.72.135.18
//
// So the one door was reachable and its certificate did not know that box existed. The only remedies on offer
// were: put the old port back, pin the deployment to a LAN address that dies the moment the laptop leaves the
// network, or re-mint and orphan every anchor already on every device.
//
// ★ THE AUTHORITIES ARE NOT TOUCHED. This loads them from the directory and re-issues only the LEAVES. The
// anchor every device has already adopted keeps verifying, which is the whole point: adding a name is not a
// rotation and must not be priced like one.
//
// ★★ AND IT IS ADDITIVE. The new names are merged with the ones already in the certificate, so a deployment
// that learns a second address does not lose the first — the failure this fixes, arrived at from the other
// side.
func addHostsToDeployment(dir, hosts string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("-dir is required: the directory holding this deployment's authorities")
	}
	newNames, newIPs, err := parseHosts(hosts)
	if err != nil {
		return err
	}
	if len(newNames) == 0 && len(newIPs) == 0 {
		return fmt.Errorf("-add-host needs at least one name or address")
	}
	minted, err := alreadyMinted(dir)
	if err != nil {
		return err
	}
	if !minted {
		return fmt.Errorf("%s holds no authorities, so there is nothing to add a name to. Install the "+
			"deployment first", dir)
	}

	// ★★★ A CARRIED MACHINE HOLDS THE CERTIFICATES AND NOT THE AUTHORITY THAT SIGNS THEM (2026-09-03, met by
	// following what -add-edge printed, on the machine it printed it on). root.crt is in every carried
	// directory — it is the anchor a node verifies against — so alreadyMinted says yes, and the next line
	// failed with
	//
	//	read /opt/dsse/osaka/root.key: open /opt/dsse/osaka/root.key: no such file or directory
	//
	// which names a file rather than the situation. Only the machine the deployment was MINTED on can issue a
	// certificate, deliberately: -carry excludes authority/ so that a machine which merely runs the product
	// cannot mint identities for it. Saying so is the whole fix.
	//
	// ★ AND IT ASKS WHERE THE KEY ACTUALLY IS. The first version of this guard looked for <dir>/root.key,
	// which exists nowhere — the CA keys live under authority/ so nothing running is ever handed them — so it
	// refused on every machine including the one that can do it. Measured immediately, on the machine where
	// the command had worked an hour earlier. Same lookup loadAuthorities uses, so the two cannot disagree.
	if _, err := os.Stat(authorityPathForReading(dir, "root.key")); err != nil {
		return fmt.Errorf("%s holds this deployment's certificates but not the authority that signs them — "+
			"it was CARRIED here, and -carry deliberately leaves authority/ behind so a machine that only "+
			"runs the product cannot mint identities for it. Run this on the machine the deployment was "+
			"minted on, then carry the result", dir)
	}

	auth, err := loadAuthorities(dir)
	if err != nil {
		return err
	}
	// What this deployment already answers on, read from the certificate rather than from a file somebody
	// might have edited. The certificate is the thing clients check.
	existingNames, existingIPs, err := hostsInCertificate(filepath.Join(dir, "transport.crt"))
	if err != nil {
		return err
	}
	names := mergeNames(existingNames, newNames)
	ips := mergeIPs(existingIPs, newIPs)

	// ★★★ AND SAY WHAT IS ABOUT TO BE LOST, BY NAME (2026-09-03, added after this command deleted the
	// per-region plane names from a three-region deployment and printed only a cheerful list of what
	// remained). The rule above is fixed, but the class of mistake it belongs to is not: this command
	// re-issues from a list it reconstructs, and anything the reconstruction misses leaves silently. So the
	// certificate that exists is compared with the certificate about to replace it, and every name that would
	// stop being served is named — before the leaves are written, not after.
	if lost := namesThatWouldStopBeingServed(cert(dir), names, ips); len(lost) > 0 {
		fmt.Printf("dsse-install: this would STOP serving %d name(s) that the certificate carries today:\n\n", len(lost))
		for _, n := range lost {
			fmt.Printf("  %s\n", n)
		}
		fmt.Printf("\nNothing was written. Pass them to -add-host together with the new name to keep them, or\n" +
			"re-issue from the plan, which is what knows every name this deployment answers on.\n")
		return fmt.Errorf("refusing to narrow this deployment's certificate")
	}

	if err := issueServerCertificates(dir, auth, names, ips, time.Now().UTC()); err != nil {
		return err
	}
	fmt.Printf("dsse-install: this deployment now answers on %d name(s) and %d address(es).\n\n", len(names), len(ips))
	for _, n := range names {
		fmt.Printf("  %s\n", n)
	}
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip)
	}
	fmt.Printf("\n  ★ THE ANCHOR IS UNCHANGED. Every device that has already adopted deployment-anchor.pem\n")
	fmt.Printf("  keeps verifying — this re-issued the leaves, not the authorities.\n")
	fmt.Printf("\n  ★★ RESTART THE NODES THAT PRESENT THESE. The certificates on disk are new; the processes\n")
	fmt.Printf("  holding the old ones are not. Until they restart, the name you just added is in a file and\n")
	fmt.Printf("  not on the wire.\n")
	return nil
}

// loadAuthorities reads the deployment's own CAs back off disk. It reads the KEYS as well as the certificates:
// re-issuing a leaf needs the issuer's key, and a function that could only read the public halves would be a
// function that cannot do this job.
func loadAuthorities(dir string) (*deploymentAuthorities, error) {
	a := &deploymentAuthorities{}
	for _, item := range []struct {
		certFile string
		keyFile  string
		cert     **x509.Certificate
		key      **ecdsa.PrivateKey
	}{
		{"root.crt", "root.key", &a.RootCert, &a.RootKey},
		{"management-ca.crt", "management-ca.key", &a.AdminCA, &a.AdminKey},
		{"transport-ca.crt", "transport-ca.key", &a.TransCA, &a.TransKey},
		{"device-ca.crt", "device-ca.key", &a.DeviceCA, &a.DeviceKey},
	} {
		cert, err := readCertificate(filepath.Join(dir, item.certFile))
		if err != nil {
			return nil, err
		}
		// ★ THE PRIVATE HALF MAY HAVE MOVED. The CA keys live under authority/ so that nothing running is ever
		// handed them; the certificates stay where every reader expects them, because they are public.
		keyPath := filepath.Join(dir, item.keyFile)
		if isAuthorityFile(item.keyFile) {
			keyPath = authorityPathForReading(dir, item.keyFile)
		}
		key, err := readECKey(keyPath)
		if err != nil {
			return nil, err
		}
		*item.cert, *item.key = cert, key
	}
	return a, nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cert, nil
}

func readECKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an EC private key", path)
	}
	return key, nil
}

// hostsInCertificate reads what a deployment currently answers on. The compose service names and the
// per-plane names are re-derived by issueServerCertificates from the host list, so they are dropped here —
// keeping them would feed derived names back in as if an operator had asked for them, and the list would grow
// a little every time somebody added one address.
func hostsInCertificate(path string) ([]string, []net.IP, error) {
	cert, err := readCertificate(path)
	if err != nil {
		return nil, nil, err
	}
	return hostsInCertificateFrom(cert)
}

// hostsInCertificateFrom is the same, from a certificate already in hand — so the rule can be tested against
// a leaf built in a test rather than against a file somebody has to mint first.
func hostsInCertificateFrom(cert *x509.Certificate) ([]string, []net.IP, error) {
	derived := map[string]bool{}
	for _, n := range composeServiceNames {
		derived[strings.ToLower(n)] = true
	}
	// ★ AND THE NODE'S OWN LOOPBACK, which issueServerCertificates adds to every leaf for the same reason it
	// adds the service names: it is how a node is reached from its own machine. Reading it back here would
	// file it as a name the OPERATOR gave, and the printed list of what this deployment answers on would
	// start naming something nobody asked for.
	derived["localhost"] = true
	// ★★★ WHICH HOSTS THIS CERTIFICATE IS FOR, decided before anything is dropped — because whether a
	// plane-prefixed name is re-derivable depends on whether its host is one of them. See the plane rule below.
	hosts := map[string]bool{}
	for _, n := range cert.DNSNames {
		low := strings.ToLower(strings.TrimSpace(n))
		if low == "" || derived[low] || planeNamePrefixed(low) || strings.HasPrefix(low, "*.") {
			continue
		}
		hosts[low] = true
	}
	names := []string{}
	for _, n := range cert.DNSNames {
		low := strings.ToLower(strings.TrimSpace(n))
		if low == "" || derived[low] {
			continue
		}
		// ★★★ A PLANE NAME IS DROPPED ONLY WHEN ITS HOST IS HERE TO RE-DERIVE IT FROM (2026-09-03, measured
		// by running -add-host on a three-region deployment and then redistributing what it produced).
		//
		// This dropped EVERY plane-prefixed name, on the reasoning written here before: "a per-plane name is
		// <plane>.<host>; the host itself is in the list too, so dropping these loses nothing". That is true
		// of agents.<deployment> — the issuer re-derives it from the deployment name. It is false of
		// agents.<region>.<deployment>, whose host would be <region>.<deployment>, which is in no list and is
		// re-derived by nothing. So on every multi-region deployment, adding ONE name silently deleted the
		// per-region plane names from every leaf.
		//
		// The failure is far from the act and shaped like an outage. Nothing happens at first: the running
		// processes still hold the old certificates. It appears when those certificates are next distributed
		// or the nodes next restart, and then it appears everywhere at once —
		//
		//	mesh peer osaka (wss://agents.osaka…/mesh/ingress/tunnel) link down: tls: failed to verify
		//	  certificate: x509: certificate is valid for keyaki.lab, node-osaka.keyaki.lab, … not
		//	  agents.osaka.keyaki.lab
		//	config-bundle sync: pull failed (keeping config): no in-boundary control plane reachable
		//
		// — the region doors, the inter-region mesh and the control-plane links together, from an operator
		// action whose whole promise is that it is additive.
		if planeNamePrefixed(low) {
			if _, rest, ok := strings.Cut(low, "."); ok && hosts[rest] {
				continue
			}
		}
		// ★★★ AND THE NODE WILDCARD, WHICH IS DERIVED FOR EXACTLY THE SAME REASON (2026-08-28, measured on
		// the lab). issueServerCertificates adds *.admin.<deployment name> to every leaf. Read back here it
		// was filed as a name the OPERATOR gave, so the next issue derived *.admin. from it as well, and the
		// certificate grew *.admin.*.admin.<host> — not a DNS name. ONE of those makes the WHOLE certificate
		// unusable: macOS answered "unsupported or invalid name syntax" for every name in it, including the
		// four plane names that had been working all morning.
		//
		// This is the third time in this loop: localhost, the plane names, and now this. Anything the issuer
		// DERIVES must be dropped on the way back in, or the deployment re-derives from its own output.
		if strings.HasPrefix(low, "*.admin.") {
			continue
		}
		names = append(names, n)
	}
	// ★ THE DERIVED ADDRESSES COME OUT FOR THE SAME REASON THE DERIVED NAMES DO. issueServerCertificates
	// adds the loopback and the region's own address to every leaf; reading them back files them as operator
	// intent, and the region address then appears TWICE in every certificate this deployment mints from here
	// on — once read back, once re-derived.
	addrs := []net.IP{}
	seen := map[string]bool{composeRegionAddress: true}
	for _, ip := range cert.IPAddresses {
		if ip == nil || ip.IsLoopback() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		addrs = append(addrs, ip)
	}
	return names, addrs, nil
}

// planeNamePrefixed reports whether a name is one this installer derives from a host rather than one an
// operator gave it.
func planeNamePrefixed(name string) bool {
	for _, prefix := range []string{"agents.", "admin.", "console.", "recovery.", "authority."} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func mergeNames(existing, added []string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, n := range append(append([]string{}, existing...), added...) {
		low := strings.ToLower(strings.TrimSpace(n))
		if low == "" || seen[low] {
			continue
		}
		seen[low] = true
		out = append(out, n)
	}
	return out
}

func mergeIPs(existing, added []net.IP) []net.IP {
	seen, out := map[string]bool{}, []net.IP{}
	for _, ip := range append(append([]net.IP{}, existing...), added...) {
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// cert re-reads the certificate this deployment serves, for the comparison above. Reading it twice is cheap
// and means the check is against the file rather than against a list built from it.
func cert(dir string) *x509.Certificate {
	c, err := readCertificate(filepath.Join(dir, "transport.crt"))
	if err != nil {
		return nil
	}
	return c
}

// namesThatWouldStopBeingServed compares the certificate on disk with what the next issue would carry, and
// returns every DNS name that would disappear.
//
// It has to model what issueServerCertificates ADDS, because most of the names in a leaf are not in the list
// passed to it: the compose service names, localhost, the deployment-wide plane names and the node wildcard
// are all derived there. A name that is derived is not lost, so it is not reported.
func namesThatWouldStopBeingServed(current *x509.Certificate, names []string, ips []net.IP) []string {
	if current == nil {
		return nil
	}
	willServe := map[string]bool{}
	for _, n := range names {
		willServe[strings.ToLower(strings.TrimSpace(n))] = true
	}
	for _, n := range composeServiceNames {
		willServe[strings.ToLower(n)] = true
	}
	willServe["localhost"] = true
	if p := planeNamesFor(cnHostFor(names, ips)); p.Split {
		for _, n := range []string{p.Agents, p.Admin, p.Console, p.Recovery, p.Authority} {
			willServe[strings.ToLower(strings.TrimSpace(n))] = true
		}
	}
	if primary := strings.ToLower(strings.TrimSpace(cnHostFor(names, ips))); primary != "" {
		willServe["*.admin."+primary] = true
	}
	lost := []string{}
	for _, n := range current.DNSNames {
		if low := strings.ToLower(strings.TrimSpace(n)); low != "" && !willServe[low] {
			lost = append(lost, n)
		}
	}
	sort.Strings(lost)
	return lost
}
