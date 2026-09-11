package main

// the_third_tier.go — a deployment that was minted without an interception authority can be given one.
//
// ★★★ ADDING A MISSING TIER IS NOT A ROTATION (2026-08-26). Re-running the installer on a directory that
// already holds authorities refuses to touch them, and rightly: replacing one orphans every anchor already
// distributed. That reasoning does not apply to a tier that has never existed. Nothing has been issued under
// it, so nothing can be orphaned — it is the same case as the agent-policy public half, which repair writes
// for exactly this reason: a deployment running since before something existed has no other way to get it.
//
// ★ AND IT IS SIGNED BY THIS DEPLOYMENT'S OWN ROOT, so it is not a second authority arriving beside the
// first. A device that already trusts this deployment's anchor needs to be told nothing new about who signs.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// defaultDeploymentYears is how long a tier added to an EXISTING deployment is valid for. It matches the
// installer's own default rather than trying to read the root's remaining life: a tier that outlives its root
// is not longer-lived, it just expires with it, and one that is shorter would quietly stop this deployment
// inspecting on a date nobody chose.
const defaultDeploymentYears = 10

// mintTheInterceptionTierIfMissing gives an existing deployment the third tier when it has none. It reports
// whether it minted one.
func mintTheInterceptionTierIfMissing(dir string, now time.Time, years int) (bool, error) {
	certPath := filepath.Join(dir, interceptionRootCertFile)
	if _, err := os.Stat(certPath); err == nil {
		return false, nil // already has one
	}
	// ★★★ A TIER IS A DEPLOYMENT FACT, AND MINTING ONE PER DIRECTORY MAKES TWO (2026-08-26, measured on this
	// change within minutes of writing it). Repairing a two-region deployment means running this in each
	// region's directory; both hold the same root key, so both minted — under one root, but two different
	// authorities, each region signing under its own. That is the "second deployment wearing different
	// clothes" shape this installer already refuses for databases and control planes, reproduced by the very
	// repair meant to close a gap.
	//
	// A joining region receives the deployment's material by being CARRIED from the region that created it.
	// So it is told to carry this too, rather than inventing a tier of its own.
	if shape, known := regionShapeFromCompose(dir); known && shape.holds != regionShapeStateBearing {
		fmt.Printf("  this region has NO interception authority, and one is NOT minted here: a joining region\n")
		fmt.Printf("  receives the deployment's material by carrying it. Copy %s\n", interceptionRootCertFile)
		fmt.Printf("  and its .key.pem from the region that holds this deployment's state, then restart. Until\n")
		fmt.Printf("  then this region's Edges inspect NOTHING.\n")
		return false, nil
	}
	rootCert, rootKey, err := readDeploymentRoot(dir)
	if err != nil {
		// ★ NOT AN ERROR THAT SHOULD STOP A REPAIR. A deployment whose root key has been taken offline — which
		// is where it belongs — cannot mint here, and everything else the repair does is still worth doing.
		// Said out loud, because the consequence is that this deployment goes on inspecting nothing.
		fmt.Printf("  this deployment has NO interception authority and one could not be minted here (%v).\n", err)
		fmt.Printf("  Until it has one, its Edges inspect NOTHING — the third tier of the architecture is\n")
		fmt.Printf("  absent. Mint %s (and its .key.pem) under this deployment's root and place both here.\n",
			interceptionRootCertFile)
		return false, nil
	}
	key, err := newInterceptionKey()
	if err != nil {
		return false, err
	}
	org := ""
	if len(rootCert.Subject.Organization) > 0 {
		org = rootCert.Subject.Organization[0]
	}
	subject := rootCert.Subject
	subject.CommonName = org + " Interception CA"
	cert, err := issueCARSA(subject, key, rootCert, rootKey, now, now.AddDate(years, 0, 0))
	if err != nil {
		return false, fmt.Errorf("issue the interception authority: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM(cert), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", interceptionRootCertFile, err)
	}
	if err := os.WriteFile(filepath.Join(dir, interceptionRootKeyFile), interceptionKeyPEM(key), 0o600); err != nil {
		return false, fmt.Errorf("write %s: %w", interceptionRootKeyFile, err)
	}
	fmt.Printf("  minted this deployment's INTERCEPTION authority — the third tier, which was missing.\n")
	fmt.Printf("  Its Edges inspected nothing until now; they will once they restart. Every device that\n")
	fmt.Printf("  already trusts this deployment's anchor needs to be told nothing new: it is signed by the\n")
	fmt.Printf("  same root.\n")
	return true, nil
}

// readDeploymentRoot loads the root this deployment signs its tiers with.
func readDeploymentRoot(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, err := readCertificate(filepath.Join(dir, "root.crt"))
	if err != nil {
		return nil, nil, err
	}
	key, err := readECKey(authorityPathForReading(dir, "root.key"))
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
