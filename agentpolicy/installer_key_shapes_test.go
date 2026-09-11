package agentpolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The macOS installer decides, in shell, whether a signing key in the agent configuration is usable. It cannot
// import this package, so the rule exists twice — and the last time it did, the copy was narrower than the
// original: 64-hex Ed25519 only, which silently discarded the ECDSA-P256 key the config-signing HSM switch put
// in force. The device's adopted plan key vanished without a message and the release freeze went unverified.
//
// So the two are compared here against the same inputs. A shell rule that diverges from the verifier fails in
// CI rather than on a device, where the symptom is a key that is simply not there.
const installerScript = "../clients/macos-network-extension/packaging/build_macos_ne_pkg.sh"

func TestInstallerKeyShapesMatchTheVerifier(t *testing.T) {
	if _, err := os.Stat(installerScript); err != nil {
		t.Skipf("installer script not present: %v", err)
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no shell: %v", err)
	}

	// A real P-256 point, because a hand-written 130-hex string is not necessarily ON the curve and the Go side
	// checks that it is. The shell cannot, which is a difference this test must not paper over: the shell's job
	// is to catch typos, the verifier's is to catch everything.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256 := hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y)) //nolint:staticcheck // matches the wire format in use

	cases := []string{
		strings.Repeat("a", 64),  // Ed25519
		p256,                     // ECDSA-P256 uncompressed
		strings.Repeat("a", 63),  // one short
		strings.Repeat("a", 65),  // one long
		strings.Repeat("a", 130), // right length, wrong prefix (not 04...)
		"zz" + strings.Repeat("a", 62),
		"",
	}
	for _, k := range cases {
		goOK := AcceptedPublicKeyHex(k)
		shOK := shellAccepts(t, k)
		if goOK != shOK {
			t.Errorf("key %q: verifier accepts=%v, installer accepts=%v — the installer's rule has drifted from "+
				"the rule that actually decides whether a key can be used", truncate(k), goOK, shOK)
		}
	}
}

// shellAccepts runs the installer's own length/shape rule, lifted from the script so the test cannot drift from
// what ships.
func shellAccepts(t *testing.T, key string) bool {
	t.Helper()
	src, err := os.ReadFile(installerScript)
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, `		case "$_k" in *[!0-9a-f]*) return 1 ;; esac`)
	end := strings.Index(body, `		esac`)
	if start < 0 || end < 0 || end < start {
		t.Fatal("could not lift the key-shape rule out of the installer — it moved; update this guard deliberately")
	}
	rule := body[start : end+len("		esac")]
	script := "#!/bin/sh\nset -eu\n_k=\"$1\"\ncheck() {\n" + rule + "\nreturn 0\n}\ncheck\n"
	cmd := exec.Command("sh", "-c", script+"", "sh", key)
	return cmd.Run() == nil
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "…(" + string(rune('0'+len(s)/100%10)) + string(rune('0'+len(s)/10%10)) + string(rune('0'+len(s)%10)) + ")"
	}
	return s
}
