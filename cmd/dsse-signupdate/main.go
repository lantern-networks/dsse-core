// Command dsse-signupdate mints the signed update manifest — the document that authorises a fleet to execute
// a particular set of bytes.
//
// It exists because nothing did. The Edge relays manifests and cannot sign one, the updater verifies them and
// cannot sign one, and both are deliberate: the key that authorises CODE is separate from the keys that
// authorise configuration, so no traffic node and no endpoint holds it. Which left the release side with no
// implementation at all — a mechanism everything else was built against and nobody could feed.
//
// ★ THE KEY THIS TOOL USES IS THE MOST DANGEROUS ONE IN THE PRODUCT. Anything it signs, every endpoint that
// pins it will execute with SYSTEM privileges, unattended. This is a LAB tool and a file-based key is a LAB
// answer: production signing belongs in the HSM the config-signing key already moved to, and the difference
// between those two is not a detail to be discovered later. The banner says so on every run rather than in a
// document nobody re-reads.
//
// Usage:
//
//	dsse-signupdate -generate -key lab-update.key            # create a key, print the public half
//	dsse-signupdate -key lab-update.key -pubkey              # print the public half (what edges pin)
//	dsse-signupdate -key lab-update.key -manifest m.json -out windows-amd64.json
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

func main() {
	keyPath := flag.String("key", "", "Ed25519 seed file (64 hex chars). Never place this where an edge or an endpoint can read it: it is the authority to run code on every device that pins it.")
	generate := flag.Bool("generate", false, "create a new key at -key and print its public half. Refuses to overwrite.")
	pubOnly := flag.Bool("pubkey", false, "print the public key hex and exit — this is what -agent-update-pin and --update-pin take")
	manifestPath := flag.String("manifest", "", "path to the manifest JSON to sign (the payload, not an envelope)")
	out := flag.String("out", "", "where to write the signed envelope (default: stdout)")
	flag.Parse()

	if strings.TrimSpace(*keyPath) == "" {
		fail("-key is required")
	}
	if *generate {
		if err := generateKey(*keyPath); err != nil {
			fail("%v", err)
		}
	}
	signer, err := loadSigner(*keyPath)
	if err != nil {
		fail("%v", err)
	}
	if *pubOnly || *generate {
		fmt.Println(signer.PublicKeyHex())
		if !*generate {
			return
		}
		fmt.Fprintf(os.Stderr, "dsse-signupdate: key written to %s. Pin the line above with -agent-update-pin on the "+
			"edge and --update-pin on the updater. Keep the FILE off both.\n", *keyPath)
		if strings.TrimSpace(*manifestPath) == "" {
			return
		}
	}
	if strings.TrimSpace(*manifestPath) == "" {
		fail("-manifest is required (or use -pubkey)")
	}

	raw, rerr := os.ReadFile(*manifestPath)
	if rerr != nil {
		fail("read %s: %v", *manifestPath, rerr)
	}
	// Strict decode, matching what every endpoint will do to it. A field this build does not know is refused
	// here rather than signed into an artefact the fleet then rejects for a reason nobody can see from the
	// release side.
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var m agentupdate.Manifest
	if derr := dec.Decode(&m); derr != nil {
		fail("%s is not a manifest: %v", *manifestPath, derr)
	}

	// agentupdate.Sign validates BEFORE signing — a correctly-signed invalid manifest is the worst artefact
	// this tool could produce, because it looks like a key problem on thousands of endpoints at once.
	env, serr := agentupdate.Sign(signer, m, time.Now())
	if serr != nil {
		fail("refusing to sign: %v", serr)
	}
	body, _ := json.MarshalIndent(env, "", "  ")

	fmt.Fprintf(os.Stderr, "dsse-signupdate: ★ SIGNED THE AUTHORITY TO EXECUTE CODE. %s %s/%s, delivery=%s, "+
		"artifact sha256:%s, valid until %s. Every endpoint pinning %s will run this.\n",
		m.Version, m.Platform, m.Arch, m.Delivery, m.ArtifactSHA256, m.NotAfter, signer.PublicKeyHex())

	// ★★★ AND SAY WHEN THE DIRTY CHECK COULD NOT BE APPLIED (2026-09-06, found while preparing a real release:
	// Validate refuses a target built from a modified tree, but Dirty() reads the BUILD METADATA and nothing
	// else. A version carrying none — "0.3.0", which is what the VERSION file holds and therefore the obvious
	// thing for a publisher to write — is structurally incapable of failing that check. The guard fired only
	// for publishers who had already carried the stamp, which is to say for nobody who needed it.
	//
	// It is said here rather than refused, because whether a release must name a commit is this product's
	// versioning policy and not this tool's to decide: the calendar-style versions in the test corpus are
	// releases too. What the tool can do is refuse to let "clean" and "cannot tell" leave looking identical.
	if v, verr := agentupdate.ParseVersion(m.Version); verr == nil && strings.TrimSpace(v.Build) == "" {
		fmt.Fprintf(os.Stderr, "dsse-signupdate: ★ %s carries no build metadata, so whether it was built from a "+
			"modified tree could not be checked — that check reads the build stamp. The binaries stamp "+
			"themselves (e.g. 0.3.0+9d0ccdb); publishing the version the artefact reports is what makes this "+
			"release traceable to a commit.\n", m.Version)
	}

	if strings.TrimSpace(*out) == "" {
		fmt.Println(string(body))
		return
	}
	if werr := os.WriteFile(*out, append(body, '\n'), 0o644); werr != nil {
		fail("write %s: %v", *out, werr)
	}
	fmt.Fprintf(os.Stderr, "dsse-signupdate: wrote %s\n", *out)
}

// generateKey creates a new signing key, and refuses to overwrite one.
//
// Refusing rather than prompting: overwriting this file orphans every endpoint that pinned the old public key,
// and they do not fail loudly — they refuse every manifest with "untrusted key", which reads as an attack.
func generateKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite an update-signing key — every endpoint that "+
			"pinned it would start reporting untrusted manifests, which reads as a substitution attack", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// 0600, and the seed only. Storing the full private key would put the public half in the same file for no
	// benefit; the seed is what the signer needs and it is 32 bytes.
	return os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600)
}

func loadSigner(path string) (*agentpolicy.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	seed, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
	if derr != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key %s must be %d hex-encoded bytes", path, ed25519.SeedSize)
	}
	return agentpolicy.NewSignerFromCrypto(ed25519.NewKeyFromSeed(seed))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "dsse-signupdate: "+format+"\n", args...)
	os.Exit(1)
}
