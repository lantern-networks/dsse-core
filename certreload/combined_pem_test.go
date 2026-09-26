package certreload

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCombinedPEMRemainsReadable(t *testing.T) {
	d := t.TempDir()
	c, k := filepath.Join(d, "cert"), filepath.Join(d, "key")
	serial := writeSelfSigned(t, c, k, "combined")
	cert, _ := os.ReadFile(c)
	key, _ := os.ReadFile(k)
	if err := os.WriteFile(c, append(cert, key...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPair(c, c); err != nil {
		t.Fatal(err)
	}
	r, err := NewReloadableCert(c, c)
	if err != nil {
		t.Fatal(err)
	}
	if servedSerial(t, r).Cmp(serial) != 0 {
		t.Fatal("wrong certificate")
	}
	if err = r.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = pairPaths(c, c); err == nil {
		t.Fatal("pair writes must still require separate files")
	}
}
