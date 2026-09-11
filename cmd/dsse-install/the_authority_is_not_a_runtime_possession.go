package main

import (
	"os"
	"path/filepath"
)

// ★★★ THE MINTING MATERIAL IS NOT A RUNTIME POSSESSION (2026-08-27).
//
// A generated deployment mounted its whole directory into both control planes, both Edges and the Console —
// and that directory holds every private key this deployment has, including its root CA's. Five of them are
// read by NOTHING at runtime: they are what this installer signs with, once, and they have no business inside
// a process that serves traffic. On one host that reads as "the operator's directory". Split across machines,
// which is how this product is meant to be deployed, it puts the deployment's root CA private key on every
// Edge box.
//
// ★ AND IT BROKE THE PHASE-0 ALLOWANCE. The PKI gap review accepts an on-disk root before HSM explicitly
// because it is not exposed to the Edge; the generated deployment exposed it. So this is not the Phase-1 HSM
// work arriving early — it is restoring the condition that made Phase 0 acceptable.
const (
	// authorityDirName holds what only the installer uses. Mounted by nothing.
	authorityDirName = "authority"
	// runtimeDirName holds what is written AFTER the deployment is running — the bootstrap marker, and a
	// licence an operator applies later. It is a directory rather than a list of files because a bind mount of
	// a file that does not exist yet creates a directory in its place, and the host can then never write it.
	runtimeDirName = "runtime"
	// interceptionRootsDirName holds the roots this node's Edge processes sign an organization's traffic
	// under, shared between them. Empty until an organization has one.
	interceptionRootsDirName = "interception-roots"
)

// authorityFiles are the private halves no running process reads. Verified by
// TestNoRunningNodeCanReachTheAuthorityMaterial, which mints a deployment and looks.
var authorityFiles = []string{
	"root.key",
	"management-ca.key",
	"transport-ca.key",
	"bundle-signing.key",
}

// ★★★ AND ONE THAT LOOKED LIKE IT BELONGED HERE AND DOES NOT (2026-08-27, corrected by four failing tests).
//
// interceptionRootKeyFile was on the list above, on the strength of grepping the start script for it and
// finding nothing. The Edge does read it — it finds the key by CONVENTION, as the sibling of the certificate
// path (network_extension_tls_interception.go: certPath + ".key.pem"), so it appears in no command line and in
// no script. A grep for what a node reads misses everything a node derives.
//
// ★★ AND THE FACT UNDERNEATH IS WORSE THAN THE MISTAKE. Today every Edge holds the deployment's interception
// ROOT key and signs from it. The PKI document puts the root offline and gives an Edge a per-tenant
// INTERMEDIATE, which is what deploy/reference already does — its own compose says "the Edge holds no root
// key". So this file staying at the top of the directory is not the design being satisfied; it is the gap
// being kept visible until the intermediate path reaches the generated deployment.
const interceptionRootKeyIsReadByTheEdge = interceptionRootKeyFile

// authorityPath is where a piece of minting material lives. Every reader and writer of it goes through here,
// so moving it again is one edit rather than a hunt.
func authorityPath(dir, name string) string { return filepath.Join(dir, authorityDirName, name) }

// runtimePath is where something written after start-up lives.
func runtimePath(dir, name string) string { return filepath.Join(dir, runtimeDirName, name) }

// ensureAuthorityLayout creates the two directories. 0700 on the authority: it is the deployment's own key
// material and nothing but the operator has any business reading it.
func ensureAuthorityLayout(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, authorityDirName), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, runtimeDirName), 0o700); err != nil {
		return err
	}
	// ★★★ WHERE AN ORGANIZATION'S INTERCEPTION ROOTS LIVE, MADE HERE SO THE CARRY CAN HOLD IT (2026-08-30).
	// The Edge processes of a node share it — one root per organization per node rather than one per process,
	// which is what per-process state gave and what made a region announce a root only one of its Edges signed
	// under. It is created empty, like runtime/: what goes in is written after the deployment is running.
	if err := os.MkdirAll(filepath.Join(dir, interceptionRootsDirName), 0o700); err != nil {
		return err
	}
	// ★ AND WHERE THE OPERATOR PUTS THE STEP-UP PORTAL'S CERTIFICATE. Created empty and mounted read-only, so
	// dropping a pair in is the whole act — and so the mount is a directory, which a missing file is not.
	// 0755: it is a certificate and its key, and the key inside carries its own mode.
	if err := os.MkdirAll(filepath.Join(dir, "clientless"), 0o755); err != nil {
		return err
	}
	// ★ AND WHERE THE OPERATOR PUTS THE ADMIN CONSOLE'S CERTIFICATE. The first screen an administrator sees
	// should not be a certificate warning; a pair here is served instead of the deployment's own.
	return os.MkdirAll(filepath.Join(dir, "console"), 0o755)
}

// isAuthorityFile reports whether a name belongs under authority/.
func isAuthorityFile(name string) bool {
	for _, a := range authorityFiles {
		if a == name {
			return true
		}
	}
	return false
}

// authorityPathForReading answers where a piece of minting material IS, which is not always where it belongs.
//
// ★★★ A DEPLOYMENT MINTED BEFORE THIS EXISTED STILL HAS ITS KEYS AT THE TOP (2026-08-27). Reading only the new
// location would make every existing deployment unrepairable — and a repair is exactly what such a deployment
// needs, because it is the one that has been handing its root key to five containers. Falling back is not
// tolerance of the old layout; it is the only way to reach a deployment in order to fix it.
func authorityPathForReading(dir, name string) string {
	moved := authorityPath(dir, name)
	if _, err := os.Stat(moved); err == nil {
		return moved
	}
	return filepath.Join(dir, name)
}

// moveAuthorityMaterialIntoPlace relocates minting material a previous installer left at the top of the
// deployment directory. Idempotent, and it moves rather than copies: a copy would leave the original exactly
// where every container is still being handed it, which is the whole defect.
//
// ★ IT IS PART OF REPAIR, not of minting. An operator running this command on a deployment that has been up
// for months is the only way that deployment stops exposing its root key, and they should not have to know it
// happened — but they are TOLD, because a key changing place is a thing to be able to find again.
func moveAuthorityMaterialIntoPlace(dir string) ([]string, error) {
	if err := ensureAuthorityLayout(dir); err != nil {
		return nil, err
	}
	var moved []string
	for _, name := range authorityFiles {
		from, to := filepath.Join(dir, name), authorityPath(dir, name)
		if _, err := os.Stat(from); err != nil {
			continue // not there: either already moved, or this deployment never had it
		}
		if _, err := os.Stat(to); err == nil {
			// Both exist. The one under authority/ is the one in force; remove the exposed copy rather than
			// leaving a private key where five containers can read it.
			if err := os.Remove(from); err != nil {
				return moved, err
			}
			moved = append(moved, name)
			continue
		}
		if err := os.Rename(from, to); err != nil {
			return moved, err
		}
		moved = append(moved, name)
	}
	return moved, nil
}
