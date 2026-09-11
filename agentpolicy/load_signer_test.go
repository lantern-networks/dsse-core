package agentpolicy

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fallback path must never mint a signing key. The Edge falls back to the on-disk key when the HSM is
// unreachable, and a key generated at that moment is one no device has pinned or adopted — the Edge would come
// up reporting itself healthy while signing policy the entire fleet rejects, with nothing in its own logs
// saying so. The guarantee is asserted the only way that means anything: the file must still not exist.
func TestLoadSignerNeverCreatesAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.hex")

	signer, err := LoadSigner(path, false)
	if err == nil {
		t.Fatal("LoadSigner returned a signer for a key that does not exist")
	}
	if signer != nil {
		t.Fatalf("LoadSigner returned a non-nil signer alongside an error: %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want it to wrap fs.ErrNotExist so a caller can tell 'no fallback configured' from 'the fallback is broken'", err)
	}
	if _, serr := os.Stat(path); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("LoadSigner created %s — a key the fleet has never pinned", path)
	}

	// The contrast that makes this function necessary: the load-or-generate entry point DOES mint one here, so
	// "load only" cannot be expressed by calling it after an existence check — the check and the call are not
	// atomic, and the call is the one that mints.
	if _, gerr := LoadOrGenerateSigner(path, false); gerr != nil {
		t.Fatalf("LoadOrGenerateSigner: %v", gerr)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Fatalf("LoadOrGenerateSigner should have created the key: %v", serr)
	}
}

// devMode=true throughout: these tests are about WHICH key is loaded, not about the file-mode guard, and on
// Windows a file written 0600 reads back 0666 so a production-mode load would fail there for an unrelated
// reason — and the malformed-key test would then pass for the wrong one.
//
// An existing key loads identically through both entry points — the split is about what happens when the file
// is absent, and must not become two different readers of the same file.
func TestLoadSignerReadsTheSameKeyAsLoadOrGenerate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.hex")
	seed := strings.Repeat("ab", ed25519.SeedSize)
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSigner(path, true)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	generated, err := LoadOrGenerateSigner(path, true)
	if err != nil {
		t.Fatalf("LoadOrGenerateSigner: %v", err)
	}
	if loaded.PublicKeyHex() != generated.PublicKeyHex() {
		t.Fatalf("the two entry points read different keys: %s vs %s", loaded.PublicKeyHex(), generated.PublicKeyHex())
	}
	want, _ := hex.DecodeString(seed)
	if loaded.PublicKeyHex() != hex.EncodeToString(ed25519.NewKeyFromSeed(want).Public().(ed25519.PublicKey)) {
		t.Fatalf("loaded key does not match the seed on disk: %s", loaded.PublicKeyHex())
	}
}

// A key that exists but is unusable is an ERROR, never a silent fall-through to minting a replacement — that
// substitution is exactly what review #34 removed from the normal path, and it must not return via this one.
func TestLoadSignerRejectsAMalformedKeyWithoutReplacingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.hex")
	if err := os.WriteFile(path, []byte("not-a-seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(path, true); err == nil {
		t.Fatal("a malformed key file was accepted")
	} else if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a malformed key must not be reported as absent (a caller would treat it as 'no fallback'): %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "not-a-seed" {
		t.Fatalf("the unusable key file was rewritten: %q", data)
	}
}
