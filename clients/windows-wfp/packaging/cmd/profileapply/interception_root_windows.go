//go:build windows

package main

// interception_root_windows.go — the store I/O behind planRootInstall. No decisions here.

import (
	"crypto/sha1"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// certFindSHA1Hash is CERT_FIND_SHA1_HASH: CERT_COMPARE_SHA1_HASH (1) << CERT_COMPARE_SHIFT (16). Defined
// here rather than taken from x/sys/windows, which does not export it, so the search predicate and the
// CRYPT_HASH_BLOB it is paired with stay next to each other.
const certFindSHA1Hash = 1 << 16

// crypt32 exposes the one call x/sys/windows does not wrap. Everything else (open, enumerate, close) is
// already there.
var (
	crypt32                              = windows.NewLazySystemDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore = crypt32.NewProc("CertAddEncodedCertificateToStore")
)

// openMachineRootStore opens LocalMachine\Root for read and write.
//
// The MACHINE store, not the user's: a per-user store leaves every other account — and every service, which
// is what the agent runs as — unable to verify intercepted TLS.
func openMachineRootStore() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(name)),
	)
	if err != nil {
		return 0, fmt.Errorf("open LocalMachine\\Root (needs elevation): %w", err)
	}
	return h, nil
}

// enumerateStore reads every certificate currently in the store.
func enumerateStore(store windows.Handle) ([]parsedRoot, error) {
	var out []parsedRoot
	var ctx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil {
			if err == windows.Errno(windows.CRYPT_E_NOT_FOUND) {
				break
			}
			// A store that cannot be READ must not be treated as an empty one: "nothing is there" is exactly
			// the answer that would let this add a colliding root.
			return nil, fmt.Errorf("enumerate LocalMachine\\Root: %w", err)
		}
		if next == nil {
			break
		}
		ctx = next
		der := make([]byte, next.Length)
		copy(der, unsafe.Slice(next.EncodedCert, next.Length))
		r, perr := parseRoot(der)
		if perr != nil {
			// A certificate already in the store that Go cannot parse is not this installer's problem, and
			// refusing the install over it would be worse than proceeding: it is skipped for COMPARISON only,
			// which is safe because a certificate we cannot parse cannot be the one we are adding.
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// addToStore writes one DER certificate into the store.
func addToStore(store windows.Handle, der []byte) error {
	r, _, err := procCertAddEncodedCertificateToStore.Call(
		uintptr(store),
		uintptr(windows.X509_ASN_ENCODING),
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		uintptr(windows.CERT_STORE_ADD_NEW),
		0,
	)
	if r == 0 {
		return fmt.Errorf("add certificate to LocalMachine\\Root: %w", err)
	}
	return nil
}

// doInstallInterceptionRoot lays the organization's interception root into the machine trust store.
//
// Fatal on refusal, deliberately. This runs as an MSI custom action, and the two outcomes have to be told
// apart: "already trusted" is the ordinary re-install and must not fail anything, while "a different
// authority already holds this name" is a machine that needs a person BEFORE more software is layered onto
// it. The alternative — install anyway, warn in a log — is how the store ends up holding the pair that breaks
// every HTTPS site on it.
// ★★ WHAT IT IS INSTALLING IS NAMED BY THE CALLER (2026-09-03, reported from the Windows box on the first
// run that installed a transport anchor through here).
//
// This path is shared with the organization's transport anchor now, and it announced BOTH as "interception
// root INSTALLED" — while the line printed immediately afterwards called the same act "this organization's
// transport anchor is trusted by this machine". One operation, two names, in adjacent lines of the same log.
// An operator reading it would take a transport anchor for an inspection authority, which is the family of
// mistake this whole day has been about.
func doInstallInterceptionRoot(path string) error {
	return doInstallTrustAnchor(path, "interception root")
}

// doInstallTrustAnchor lays certificates into the machine trust store and says what they are.
func doInstallTrustAnchor(path, what string) error {
	incoming, err := readInterceptionRoots(path)
	if err != nil {
		return err
	}
	store, err := openMachineRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	existing, err := enumerateStore(store)
	if err != nil {
		return err
	}
	plan, err := planRootInstall(existing, incoming)
	if err != nil {
		return err
	}
	for _, r := range plan.AlreadyPresent {
		fmt.Printf("profileapply: interception root already trusted, nothing to do: %s (%s)\n", r.Subject, r.SHA256)
	}
	for _, r := range plan.Add {
		if aerr := addToStore(store, r.DER); aerr != nil {
			return fmt.Errorf("%s (%s): %w", r.Subject, r.SHA256, aerr)
		}
		fmt.Printf("profileapply: %s INSTALLED into LocalMachine\\Root: %s (%s)\n", what, r.Subject, r.SHA256)
	}
	return nil
}

// removeFromStore deletes one certificate, found in the store by its DER bytes.
//
// CertFindCertificateInStore + CertDeleteCertificateFromStore, rather than deleting the context handed back
// by an enumeration: deleting during an enumeration invalidates the walk, and this way the certificate is
// located by exactly what identifies it.
func removeFromStore(store windows.Handle, der []byte) error {
	// ★★★ IT LOOKS IT UP BY SHA-1 HASH, AND THE PREVIOUS ATTEMPT LOOKED IT UP BY A CONTEXT IT BUILT ITSELF
	// (2026-09-07, measured on this box: the certificate was demonstrably in LocalMachine\Root, its thumbprint
	// printed from the store beside the one printed from the PEM, and every removal still failed with
	// "locate certificate for removal: Cannot find object or property").
	//
	// CERT_FIND_EXISTING does not search by content. It takes a PCCERT_CONTEXT that CAME FROM A STORE and
	// matches on the certificate's identity as the store knows it; a CertContext assembled on the stack around
	// a DER buffer is not one of those, so the search never matched anything and the removal reported a
	// certificate it could not find while that certificate sat in the store.
	//
	// The visible consequence was the one this file's own header warns about: an uninstall that returns 0 and
	// leaves a deployment's interception CA trusted — a root that signs any name on the internet, whose key
	// belongs to a deployment that may already have been destroyed. Measured three times on three
	// deployments before the cause was found, each time reported as "the uninstall does not collect".
	//
	// SHA-1 is not a security decision here. It is the identifier the certificate store indexes by, the same
	// one Windows shows as the Thumbprint, and the search is over a store this process already opened — the
	// certificate is then compared to the file it came from by the caller. Collision resistance is not what is
	// being relied on.
	sum := sha1.Sum(der)
	blob := struct {
		size uint32
		data *byte
	}{size: uint32(len(sum)), data: &sum[0]}
	ctx, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING, 0,
		certFindSHA1Hash, unsafe.Pointer(&blob), nil)
	if err != nil || ctx == nil {
		return fmt.Errorf("locate certificate for removal by SHA-1 %x: %w", sum, err)
	}
	// CertDeleteCertificateFromStore frees the context whether it succeeds or fails, so it must not be freed
	// again here.
	if derr := windows.CertDeleteCertificateFromStore(ctx); derr != nil {
		return fmt.Errorf(`delete certificate from LocalMachine\Root: %w`, derr)
	}
	return nil
}

// doRemoveInterceptionRoot takes out the root THIS package installed, named by the package's own artifact.
//
// ★ It never fails the uninstall. An uninstall that refuses leaves the machine holding both the agent and the
// root, which is strictly worse than either. Everything it cannot do, it says.
func doRemoveInterceptionRoot(path string) error {
	ours, err := readOurRoots(path)
	if err != nil {
		fmt.Printf("profileapply: %v\n", err)
		return nil
	}
	if len(ours) == 0 {
		fmt.Printf("profileapply: no interception-root artifact at %q — nothing this package can prove it "+
			"installed, so no certificate is removed\n", path)
		return nil
	}
	store, err := openMachineRootStore()
	if err != nil {
		fmt.Printf("profileapply: could not open the machine trust store to remove the interception root (%v) "+
			"— remove it by fingerprint by hand\n", err)
		return nil
	}
	defer windows.CertCloseStore(store, 0)

	existing, err := enumerateStore(store)
	if err != nil {
		fmt.Printf("profileapply: could not read the machine trust store (%v) — no certificate is removed\n", err)
		return nil
	}
	plan := planRootRemoval(existing, ours)
	for _, r := range plan.Absent {
		fmt.Printf("profileapply: interception root already absent, nothing to do: %s (%s)\n", r.Subject, r.SHA256)
	}
	for _, r := range plan.Remove {
		if rerr := removeFromStore(store, r.DER); rerr != nil {
			fmt.Printf("profileapply: ★ FAILED to remove the interception root %s (%s): %v — this machine "+
				"still trusts a CA for every name on the internet, whose key belongs to a deployment that may "+
				"no longer exist. Remove it by fingerprint by hand.\n", r.Subject, r.SHA256, rerr)
			continue
		}
		fmt.Printf("profileapply: interception root REMOVED from LocalMachine"+`\`+"Root: %s (%s)\n", r.Subject, r.SHA256)
	}
	return nil
}
