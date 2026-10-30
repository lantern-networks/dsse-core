package main

import (
	"os"
	"strings"
	"testing"
)

func TestMixedMissingAndUnreadableDNSResidueIsUnknown(t *testing.T) {
	readErrors := 0
	stat := func(path string) (os.FileInfo, error) {
		if strings.Contains(path, "unreadable") {
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	}
	found, known := dnsTakeoverResidueWithStat([]string{"missing", "unreadable"}, stat,
		func(string, error) { readErrors++ })
	if found || known {
		t.Fatalf("mixed missing and unreadable backup returned found=%t known=%t, want false/false", found, known)
	}
	if readErrors != 1 {
		t.Fatalf("read errors reported %d times, want 1", readErrors)
	}
}

func TestAllMissingDNSResidueIsKnownAbsent(t *testing.T) {
	found, known := dnsTakeoverResidueWithStat([]string{"one", "two"},
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, nil)
	if found || !known {
		t.Fatalf("all missing returned found=%t known=%t, want false/true", found, known)
	}
}

func TestAnyFoundDNSResidueIsKnownPresent(t *testing.T) {
	read := 0
	found, known := dnsTakeoverResidueWithStat([]string{"unreadable", "present"},
		func(path string) (os.FileInfo, error) {
			if strings.Contains(path, "unreadable") {
				return nil, os.ErrPermission
			}
			return nil, nil
		}, func(string, error) { read++ })
	if !found || !known || read != 1 {
		t.Fatalf("present after read error returned found=%t known=%t reports=%d, want true/true/1", found, known, read)
	}
}
