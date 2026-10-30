package dlp

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSpillUsesProtectedIdentityACLAndDeleteOnClose(t *testing.T) {
	dir, err := os.MkdirTemp(t.TempDir(), "spill-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "body.enc")
	f, err := openEphemeralSpill(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	want, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	fileSD, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || fileSD.String() != want.String() {
		t.Fatal("spill file did not retain its protected identity-only DACL", err)
	}
	dirSD, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || dirSD.String() != want.String() {
		t.Fatal("spill directory did not retain its protected identity-only DACL", err)
	}
	if _, err := f.Write([]byte("synthetic encrypted frame")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("Windows retained a body file after Close", err)
	}
	if err := retireEphemeralSpill(dir); err != nil {
		t.Fatal(err)
	}
}
