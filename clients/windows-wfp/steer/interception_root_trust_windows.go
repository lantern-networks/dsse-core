//go:build windows

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"log"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// interception_root_trust_windows.go — which of the interception roots the Edge names are actually in THIS
// machine's trust store. Switching the interception root is the one certificate operation the Console cannot
// offer, and the obstacle is not a button: nothing tells the Edge which root a device trusts, so a switch would
// start signing under a root some endpoints lack, and EVERY HTTPS request on those machines fails at once — the
// 2026-07-31 shape, wider, because interception applies to every site rather than one tunnel. So the Edge names
// the roots and the agent LOOKS. Fingerprints in, fingerprints out; no certificate ever leaves the box.

// interceptionRootsPresent returns the subset of `wanted` whose certificate is present in the machine's or the
// user's Root store — the stores the interception (TLS MITM) verification actually consults. Reports ONLY what
// it found: an empty answer means "found none", which the Edge reads as different from "did not report".
func interceptionRootsPresent(wanted []string) []string {
	if len(wanted) == 0 {
		log.Printf("interception_root_trust wanted=0 (the deployment named no roots to look for)")
		return nil
	}
	want := make(map[string]struct{}, len(wanted))
	for _, w := range wanted {
		want[strings.ToLower(strings.TrimSpace(w))] = struct{}{}
	}
	found := map[string]struct{}{}
	// LocalMachine\Root is the store an MDM profile or an admin install writes to (applies to everyone); the
	// CurrentUser\Root is where a per-user install lands and still decides whether THAT user's browsing works.
	for _, loc := range []uint32{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, windows.CERT_SYSTEM_STORE_CURRENT_USER} {
		scanRootStore(loc, want, found)
	}
	out := make([]string, 0, len(found))
	for fp := range found {
		out = append(out, fp)
	}
	sort.Strings(out)
	log.Printf("interception_root_trust wanted=%d found=%d scanned=localmachine,currentuser", len(wanted), len(out))
	for _, w := range wanted {
		if _, ok := found[strings.ToLower(strings.TrimSpace(w))]; !ok {
			log.Printf("interception_root_trust NOT_IN_TRUST_STORE sha256=%s", w)
		}
	}
	return out
}

// deviceRootPool builds a Go verification pool from the SAME two stores interceptionRootsPresent scans, so the
// probe in interception_probe.go checks an intercepted chain against what this machine actually trusts rather
// than against a pool compiled into the binary.
//
// ★ THIS EXISTS BECAUSE GO ON WINDOWS DOES NOT USE THESE STORES THE WAY THE PROBE NEEDS. Left with a nil Roots,
// crypto/x509 hands the whole question to CryptoAPI and returns the PLATFORM's opinion. That opinion is worth
// having — it is the second half of the probe — but it is not Go's, and the difference between the two is the
// thing that hid a defect for most of 2026-08-21. Getting Go's opinion about this device's roots means putting
// this device's roots in a pool Go will read, which is what this does.
//
// Best-effort by construction: a store that cannot be opened or a certificate that cannot be parsed contributes
// nothing. An empty pool is returned rather than nil, because nil means "ask the platform" and would silently
// turn the two verifications into one.
func deviceRootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	added := 0
	for _, loc := range []uint32{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, windows.CERT_SYSTEM_STORE_CURRENT_USER} {
		added += addRootStoreToPool(loc, pool)
	}
	log.Printf("interception_probe device root pool: %d certificate(s) from localmachine,currentuser", added)
	return pool
}

// addRootStoreToPool enumerates one "ROOT" system store into pool and returns how many certificates it added.
func addRootStoreToPool(location uint32, pool *x509.CertPool) int {
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0
	}
	store, err := windows.CertOpenStore(certStoreProvSystemW, 0, 0, location, uintptr(unsafe.Pointer(name)))
	if err != nil {
		return 0
	}
	defer windows.CertCloseStore(store, 0)

	added := 0
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil || ctx == nil {
			return added
		}
		if ctx.EncodedCert == nil || ctx.Length == 0 {
			continue
		}
		// The DER is owned by the store and freed as the enumeration advances, so it is copied before parsing.
		der := append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...)
		cert, perr := x509.ParseCertificate(der)
		if perr != nil {
			continue
		}
		pool.AddCert(cert)
		added++
	}
}

// certStoreProvSystemW is CERT_STORE_PROV_SYSTEM_W (wincrypt: (LPCSTR)10) — the provider that opens a named
// SYSTEM store like "ROOT". Passed as the storeProvider uintptr to CertOpenStore.
const certStoreProvSystemW = 10

// scanRootStore enumerates the "ROOT" system store at the given location and records every wanted fingerprint
// it holds, using the x/sys/windows CertContext wrappers (so no uintptr is reinterpreted as a pointer).
// Best-effort: a store that cannot be opened contributes nothing rather than failing the report.
func scanRootStore(location uint32, want, found map[string]struct{}) {
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return
	}
	store, err := windows.CertOpenStore(certStoreProvSystemW, 0, 0, location, uintptr(unsafe.Pointer(name)))
	if err != nil {
		return
	}
	defer windows.CertCloseStore(store, 0)

	// CertEnumCertificatesInStore frees the previous context as it returns the next, and everything once it
	// returns nil, so the loop needs no manual free.
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil || ctx == nil {
			return
		}
		if ctx.EncodedCert == nil || ctx.Length == 0 {
			continue
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		sum := sha256.Sum256(der)
		fp := hex.EncodeToString(sum[:])
		if _, ok := want[fp]; ok {
			found[fp] = struct{}{}
		}
	}
}
