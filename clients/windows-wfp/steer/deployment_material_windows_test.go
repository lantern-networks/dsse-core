//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/lantern-networks/dsse-core/installprofile"
	"golang.org/x/sys/windows"
)

// Exercise initial publication, unchanged-file repair and replacement under a private parent.
func TestPublicInterceptionRootRemainsReadableAcrossReplacement(t *testing.T) {
	base := t.TempDir()
	setPrivate := func(path string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setPrivate(base)
	root := filepath.Join(base, "interception-root.pem")
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name  string
		data  string
		reset bool
	}{
		{"initial", "public root one", false},
		{"unchanged ACL repair", "public root one", true},
		{"atomic replacement", "public root two", false},
	} {
		t.Run(step.name, func(t *testing.T) {
			if step.reset {
				setPrivate(root)
			}
			applyDeploymentMaterial(installprofile.DeploymentMaterial{InterceptionRootPEM: []byte(step.data)}, filepath.Join(base, "enroll"))
			got, err := os.ReadFile(root)
			if err != nil || string(got) != step.data {
				t.Fatalf("material=%q error=%v", got, err)
			}
			sd, err := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			acl, _, err := sd.DACL()
			if err != nil || acl == nil {
				t.Fatalf("missing DACL: %v", err)
			}
			readable := false
			for i := uint32(0); i < uint32(acl.AceCount); i++ {
				var ace *windows.ACCESS_ALLOWED_ACE
				if err := windows.GetAce(acl, i, &ace); err != nil {
					t.Fatal(err)
				}
				if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
					continue
				}
				sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
				if !sid.Equals(users) {
					continue
				}
				readable = ace.Mask&windows.FILE_READ_DATA != 0
				if ace.Mask&(windows.FILE_WRITE_DATA|windows.WRITE_DAC|windows.WRITE_OWNER|windows.DELETE) != 0 {
					t.Fatal("public root allows user mutation")
				}
			}
			if !readable {
				t.Fatal("normal users cannot read the published CA after this operation")
			}
		})
	}
}
