//go:build windows

package main

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
	"golang.org/x/sys/windows"
	"net/url"
	"unsafe"
)

// Match TOKEN_STATISTICS, including its native alignment. A byte array only
// promises byte alignment and can make GetTokenInformation fail with
// ERROR_NOACCESS even when the token and buffer length are valid.
type stepUpTokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

func stepUpTokenLogonID(token windows.Token) (uint64, error) {
	var stats stepUpTokenStatistics
	var length uint32
	size := uint32(unsafe.Sizeof(stats))
	if err := windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&stats)), size, &length); err != nil {
		return 0, err
	}
	if length != size {
		return 0, fmt.Errorf("unexpected token statistics size: %d", length)
	}
	return uint64(uint32(stats.AuthenticationID.HighPart))<<32 | uint64(stats.AuthenticationID.LowPart), nil
}

// Capture kernel process/token facts while the WFP-attributed process is alive.
// PID alone is insufficient: it can be reused before a delayed STEPUP arrives.
func captureStepUpOwner(pid uint32) stepUpOwner {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return stepUpOwner{}
	}
	defer windows.CloseHandle(p)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(p, &created, &exited, &kernel, &user) != nil {
		return stepUpOwner{}
	}
	var token windows.Token
	if windows.OpenProcessToken(p, windows.TOKEN_QUERY, &token) != nil {
		return stepUpOwner{}
	}
	defer token.Close()
	identity, err := token.GetTokenUser()
	if err != nil {
		return stepUpOwner{}
	}
	var session, length uint32
	if windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &length) != nil || session == 0 || session == invalidSessionID {
		return stepUpOwner{}
	}
	logonID, err := stepUpTokenLogonID(token)
	if err != nil {
		return stepUpOwner{}
	}
	return stepUpOwner{LogonID: logonID, PID: pid, Session: session, SID: identity.User.Sid.String(), Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}
}

func defaultStepUpLauncherForOwner(resource, portalURL string, owner stepUpOwner) {
	if owner.PID == 0 || owner.SID == "" || owner.Session == 0 || captureStepUpOwner(owner.PID) != owner {
		fmt.Printf("steer_stepup_owner_unavailable\n")
		return
	}
	safe, ok := validatedStepUpURL(portalURL)
	u, parseErr := url.Parse(safe)
	if !ok || parseErr != nil || !stepUpOwnerMatchesURL(owner, u) {
		fmt.Printf("steer_stepup_invalid_url\n")
		return
	}
	exe, err := winbin.System("rundll32.exe")
	if err != nil {
		fmt.Printf("steer_stepup_browser_unavailable\n")
		return
	}
	command := fmt.Sprintf(`"%s" url.dll,FileProtocolHandler %s`, exe, safe)
	if err := launchInSession(command, uintptr(owner.Session), owner.SID, owner.LogonID); err != nil {
		fmt.Printf("steer_stepup_browser_launch_failed\n")
	}
}
