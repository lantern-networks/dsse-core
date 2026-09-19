package blobstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDistinguishesAbsentEmptyAndDanglingLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot")
	p := FilePersister{Path: path}
	if b, e := p.Load(); b != nil || e != nil {
		t.Fatal("first boot", b, e)
	}
	if e := os.WriteFile(path, []byte{}, 0600); e != nil {
		t.Fatal(e)
	}
	if b, e := p.Load(); b == nil || e != nil {
		t.Fatal("empty file treated as absent", e)
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(path+".missing", path); e != nil {
		t.Skip(e)
	}
	if _, e := p.Load(); e == nil {
		t.Fatal("dangling link treated as first boot")
	}
}
