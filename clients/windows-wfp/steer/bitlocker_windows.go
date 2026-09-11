//go:build windows

// bitlocker_windows.go — disk-encryption posture (BitLocker) for the device-posture CONNECT headers, reported as
// on/off/"" (unknown). BitLocker protection status has no flat Win32 API; the supported in-process path is WMI
// (Win32_EncryptableVolume in ROOT\CIMV2\Security\MicrosoftVolumeEncryption), which works in session 0 without
// shelling out (the service cannot spawn a child process). x/sys/windows does not expose the IWbem* interfaces,
// so the minimal COM call chain is hand-rolled via vtable dispatch. Everything is wrapped so ANY failure — a
// missing namespace, an access error, a COM misstep — degrades to "" (unknown, header omitted), never a crash
// and never a guessed value.

package main

import (
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ole32          = windows.NewLazySystemDLL("ole32.dll")
	oleaut32       = windows.NewLazySystemDLL("oleaut32.dll")
	procCoCreate   = ole32.NewProc("CoCreateInstance")
	procProxyBlank = ole32.NewProc("CoSetProxyBlanket")
	procSysAlloc   = oleaut32.NewProc("SysAllocString")
	procSysFree    = oleaut32.NewProc("SysFreeString")
	procVarClear   = oleaut32.NewProc("VariantClear")
)

// COM/WMI constants.
const (
	clsctxInprocServer     = 0x1
	comAuthnWinNT          = 10 // RPC_C_AUTHN_WINNT (for CoSetProxyBlanket; distinct from the WFP engine's authn)
	comAuthzNone           = 0
	comAuthnLevelCall      = 3
	comImpLevelImpersonate = 3
	wbemFlagForwardOnly    = 0x20

	// vtable indices (IUnknown occupies 0..2: QueryInterface/AddRef/Release).
	idxRelease       = 2
	idxConnectServer = 3  // IWbemLocator::ConnectServer
	idxExecQuery     = 20 // IWbemServices::ExecQuery
	idxEnumNext      = 4  // IEnumWbemClassObject::Next
	idxObjGet        = 4  // IWbemClassObject::Get
)

// clsidWbemLocator = {4590F811-1D3A-11D0-891F-00AA004B2E24}; iidIWbemLocator = {DC12A687-737F-11CF-884D-00AA004B2E24}
var (
	clsidWbemLocator = windows.GUID{Data1: 0x4590F811, Data2: 0x1D3A, Data3: 0x11D0, Data4: [8]byte{0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
	iidIWbemLocator  = windows.GUID{Data1: 0xDC12A687, Data2: 0x737F, Data3: 0x11CF, Data4: [8]byte{0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
)

// variant is the 64-bit VARIANT (vt + 3 reserved words, then an 8-byte union). For VT_I4/VT_UI4 the low 32 bits
// of `val` hold the number; for VT_BSTR `val` is the OLECHAR* string pointer.
type variant struct {
	vt  uint16
	_   uint16
	_   uint16
	_   uint16
	val uintptr
	_   uintptr // decVal tail padding (VARIANT is 16 bytes on 64-bit; extra word keeps Get from overrunning)
}

const (
	vtI4   = 3
	vtBSTR = 8
	vtUI4  = 19
)

// comCall dispatches a COM method by vtable index (unsafe.Add keeps the pointer arithmetic vet-clean).
func comCall(this unsafe.Pointer, index int, a ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(this)
	fn := *(*uintptr)(unsafe.Add(vtbl, index*int(unsafe.Sizeof(uintptr(0)))))
	ret, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(this)}, a...)...)
	return ret
}

func sysAlloc(s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	r, _, _ := procSysAlloc.Call(uintptr(unsafe.Pointer(p)))
	return r
}
func sysFree(b uintptr) {
	if b != 0 {
		procSysFree.Call(b)
	}
}
func release(this unsafe.Pointer) {
	if this != nil {
		comCall(this, idxRelease)
	}
}

// diskEncryptionStatus reports BitLocker protection on the system drive: "on", "off", or "" (unknown). Any error
// yields "".
func diskEncryptionStatus() (status string) {
	defer func() { _ = recover() }() // any COM misstep -> "" (fail-safe), never crash the service

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Initialize COM for this locked thread. S_FALSE (already init) -> nil; a mode conflict -> don't uninit.
	needUninit := false
	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err == nil {
		needUninit = true
	}
	if needUninit {
		defer windows.CoUninitialize()
	}

	var loc unsafe.Pointer
	hr, _, _ := procCoCreate.Call(
		uintptr(unsafe.Pointer(&clsidWbemLocator)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIWbemLocator)), uintptr(unsafe.Pointer(&loc)))
	if int32(hr) < 0 || loc == nil {
		return ""
	}
	defer release(loc)

	ns := sysAlloc(`ROOT\CIMV2\Security\MicrosoftVolumeEncryption`)
	defer sysFree(ns)
	var svc unsafe.Pointer
	hr = comCall(loc, idxConnectServer, ns, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&svc)))
	if int32(hr) < 0 || svc == nil {
		return ""
	}
	defer release(svc)

	// WMI requires the proxy security be set or ExecQuery is access-denied.
	procProxyBlank.Call(uintptr(svc), comAuthnWinNT, comAuthzNone, 0, comAuthnLevelCall, comImpLevelImpersonate, 0, 0)

	lang := sysAlloc("WQL")
	defer sysFree(lang)
	query := sysAlloc("SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume")
	defer sysFree(query)
	var enum unsafe.Pointer
	hr = comCall(svc, idxExecQuery, lang, query, wbemFlagForwardOnly, 0, uintptr(unsafe.Pointer(&enum)))
	if int32(hr) < 0 || enum == nil {
		return ""
	}
	defer release(enum)

	sysDrive := strings.ToUpper(strings.TrimSpace(os.Getenv("SystemDrive")))
	if sysDrive == "" {
		sysDrive = "C:"
	}

	namePtr, _ := windows.UTF16PtrFromString("DriveLetter")
	statusPtr, _ := windows.UTF16PtrFromString("ProtectionStatus")

	for {
		var obj unsafe.Pointer
		var ret uint32
		hr = comCall(enum, idxEnumNext, 0xFFFFFFFF /* WBEM_INFINITE */, 1, uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&ret)))
		if int32(hr) < 0 || ret == 0 || obj == nil {
			break
		}

		drive := getVariantString(obj, namePtr)
		if strings.ToUpper(strings.TrimSpace(drive)) == sysDrive {
			ps, ok := getVariantUint(obj, statusPtr)
			release(obj)
			if !ok {
				return ""
			}
			if ps == 1 { // 1 = protection ON
				return "on"
			}
			return "off"
		}
		release(obj)
	}
	return ""
}

func getVariantString(obj unsafe.Pointer, name *uint16) string {
	var v variant
	if hr := comCall(obj, idxObjGet, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&v)), 0, 0); int32(hr) < 0 {
		return ""
	}
	defer procVarClear.Call(uintptr(unsafe.Pointer(&v)))
	if v.vt != vtBSTR || v.val == 0 {
		return ""
	}
	// Reinterpret the union's 8 bytes as the (COM-owned) BSTR pointer without a uintptr->Pointer conversion.
	p := *(*unsafe.Pointer)(unsafe.Pointer(&v.val))
	return windows.UTF16PtrToString((*uint16)(p))
}

func getVariantUint(obj unsafe.Pointer, name *uint16) (uint32, bool) {
	var v variant
	if hr := comCall(obj, idxObjGet, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&v)), 0, 0); int32(hr) < 0 {
		return 0, false
	}
	defer procVarClear.Call(uintptr(unsafe.Pointer(&v)))
	if v.vt != vtI4 && v.vt != vtUI4 {
		return 0, false
	}
	return uint32(v.val), true
}
