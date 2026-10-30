//go:build windows

package main

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exercise native process/token lookup without WFP, an agent connection, or a
// browser launch. Mock owners cannot catch a failure at this OS boundary.
func TestCaptureStepUpOwnerCurrentInteractiveProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil {
		t.Fatalf("ProcessIdToSessionId: %v", err)
	}
	if session == 0 || session == invalidSessionID {
		t.Skip("requires a logged-in interactive Windows session")
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatalf("OpenProcess: %v", err)
	}
	defer windows.CloseHandle(p)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(p, &created, &exited, &kernel, &user); err != nil {
		t.Fatalf("GetProcessTimes: %v", err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("OpenProcessToken: %v", err)
	}
	defer token.Close()
	identity, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	var tokenSession, length uint32
	if err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&tokenSession)), 4, &length); err != nil {
		t.Fatalf("GetTokenInformation(SessionId): %v", err)
	}
	if tokenSession != session {
		t.Fatal("process and token session differ")
	}
	var stats stepUpTokenStatistics
	if err := windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&stats)), uint32(unsafe.Sizeof(stats)), &length); err != nil {
		t.Fatalf("GetTokenInformation(Statistics): %v", err)
	}
	if length != uint32(unsafe.Sizeof(stats)) {
		t.Fatalf("TokenStatistics returned only %d bytes", length)
	}
	owner := captureStepUpOwner(pid)
	if owner.PID != pid || owner.Session != session || owner.SID != identity.User.Sid.String() ||
		owner.Created != uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) ||
		owner.LogonID != uint64(uint32(stats.AuthenticationID.HighPart))<<32|uint64(stats.AuthenticationID.LowPart) || owner.LogonID == 0 {
		t.Fatal("captured owner does not match native process/token facts")
	}
	if captureStepUpOwner(pid) != owner {
		t.Fatal("owner changed while the same process remained alive")
	}
	if owner.authPrincipal() == "" || owner.authSession() == "" {
		t.Fatal("native owner cannot bind an authentication request")
	}
}

func TestStepUpTokenStatisticsLayout(t *testing.T) {
	var stats stepUpTokenStatistics
	if unsafe.Sizeof(stats) != 56 || unsafe.Offsetof(stats.AuthenticationID) != 8 ||
		unsafe.Offsetof(stats.ExpirationTime) != 16 || unsafe.Offsetof(stats.ModifiedID) != 48 || unsafe.Alignof(stats) < 4 {
		t.Fatal("TOKEN_STATISTICS layout or alignment differs from the Windows ABI")
	}
}

func TestStepUpTokenLogonIDInvalidHandle(t *testing.T) {
	if id, err := stepUpTokenLogonID(windows.Token(0)); err == nil || id != 0 {
		t.Fatal("invalid token must fail closed")
	}
}

func TestCaptureStepUpOwnerUnknownProcess(t *testing.T) {
	if got := captureStepUpOwner(0); got != (stepUpOwner{}) {
		t.Fatal("unknown process must not acquire an interactive owner")
	}
}
