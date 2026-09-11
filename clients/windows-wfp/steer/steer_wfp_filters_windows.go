//go:build windows

// steer_wfp_filters_windows.go — W-3 refinement: enumerate the live WFP filters and confirm the driver's six
// filters are all present. The control-device open + stats IOCTL (steer_heartbeat.go) prove the driver is
// LOADED and responsive, but not that its filters are still installed. An admin tamper can delete individual
// filters (FwpmFilterDeleteByKey) while the driver stays loaded -> enforcement silently stops for those layers.
// This check closes that gap: if any of the six DSSE filters is missing, enforcement_agent_healthy goes false.
//
// Uses fwpuclnt.dll directly (FwpmEngineOpen0 / FwpmFilterCreateEnumHandle0 / FwpmFilterEnum0). We only read
// each FWPM_FILTER0's display name, which sits at offset 16 (right after the 16-byte filterKey GUID; the
// FWPM_DISPLAY_DATA0 that follows starts with the name LPWSTR). No cgo, no x/sys/windows dependency.
package main

import (
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	fwpuclnt                         = syscall.NewLazyDLL("fwpuclnt.dll")
	procFwpmEngineOpen0              = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0             = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmFilterCreateEnumHandle0  = fwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0              = fwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0 = fwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFreeMemory0              = fwpuclnt.NewProc("FwpmFreeMemory0")
	procFwpmFilterDeleteByKey0       = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
)

const rpcCAuthnWinNT = 0xFFFFFFFF // RPC_C_AUTHN_WINNT (open the WFP engine with the caller's identity)

// dsseFilterNames are the six filters the driver registers (outbound steer v4/v6, QUIC gate v4/v6, inbound
// server-initiated v4/v6). All six must be present for the agent to be "actually enforcing".
var dsseFilterNames = []string{
	"DsseSteerV4", "DsseSteerV6",
	"DsseQuicGateV4", "DsseQuicGateV6",
	"DsseInboundV4", "DsseInboundV6",
}

// utf16PtrToStringW reads a NUL-terminated UTF-16 string from a pointer (bounded to avoid running away on a
// corrupt pointer).
func utf16PtrToStringW(p *uint16) string {
	if p == nil {
		return ""
	}
	var u []uint16
	for i := 0; i < 512; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2))
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// dsseFiltersPresent enumerates WFP filters and returns how many of the six DSSE filters are installed (0..6)
// and whether the enumeration itself succeeded. Caller treats (success && count==6) as "filters healthy".
func dsseFiltersPresent() (count int, ok bool) {
	var engine syscall.Handle
	r, _, _ := procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&engine)))
	if r != 0 {
		return 0, false
	}
	defer procFwpmEngineClose0.Call(uintptr(engine))

	var enumHandle syscall.Handle
	r, _, _ = procFwpmFilterCreateEnumHandle0.Call(uintptr(engine), 0, uintptr(unsafe.Pointer(&enumHandle)))
	if r != 0 {
		return 0, false
	}
	defer procFwpmFilterDestroyEnumHandle0.Call(uintptr(engine), uintptr(enumHandle))

	found := make(map[string]bool, len(dsseFilterNames))
	const batch = 256
	for iter := 0; iter < 1024; iter++ { // cap iterations; 1024*256 filters is far beyond any real system
		var entries unsafe.Pointer // receives FWPM_FILTER0** (array of `num` pointers)
		var num uint32
		r, _, _ = procFwpmFilterEnum0.Call(uintptr(engine), uintptr(enumHandle), batch,
			uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&num)))
		if r != 0 {
			return 0, false
		}
		if num > 0 && entries != nil {
			arr := unsafe.Slice((*unsafe.Pointer)(entries), num)
			for _, fp := range arr {
				if fp == nil {
					continue
				}
				// FWPM_FILTER0: filterKey GUID (16 bytes), then FWPM_DISPLAY_DATA0 whose first field is
				// name (LPWSTR) at offset 16.
				namePtr := *(**uint16)(unsafe.Add(fp, 16))
				name := utf16PtrToStringW(namePtr)
				if name != "" {
					for _, want := range dsseFilterNames {
						if name == want {
							found[want] = true
						}
					}
				}
			}
			procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
		}
		if num < batch { // last batch: the enumeration is exhausted
			break
		}
	}
	return len(found), true
}

// deleteFirstDsseFilter deletes ONE of the driver's WFP filters by key -- a TEST AFFORDANCE that simulates an
// admin "partial tamper" (driver stays loaded but a filter is removed). It reads the matching filter's key
// (FWPM_FILTER0.filterKey at offset 0) and calls FwpmFilterDeleteByKey0. Reverse with sc stop/start
// DsseWfp (DriverEntry re-adds all six). Returns the deleted filter's display name.
func deleteFirstDsseFilter() (string, error) {
	var engine syscall.Handle
	if r, _, _ := procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&engine))); r != 0 {
		return "", fmt.Errorf("FwpmEngineOpen0 failed: 0x%x", r)
	}
	defer procFwpmEngineClose0.Call(uintptr(engine))

	var enumHandle syscall.Handle
	if r, _, _ := procFwpmFilterCreateEnumHandle0.Call(uintptr(engine), 0, uintptr(unsafe.Pointer(&enumHandle))); r != 0 {
		return "", fmt.Errorf("FwpmFilterCreateEnumHandle0 failed: 0x%x", r)
	}
	defer procFwpmFilterDestroyEnumHandle0.Call(uintptr(engine), uintptr(enumHandle))

	var key [16]byte
	var delName string
	const batch = 256
	for iter := 0; iter < 1024 && delName == ""; iter++ {
		var entries unsafe.Pointer
		var num uint32
		if r, _, _ := procFwpmFilterEnum0.Call(uintptr(engine), uintptr(enumHandle), batch,
			uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&num))); r != 0 {
			return "", fmt.Errorf("FwpmFilterEnum0 failed: 0x%x", r)
		}
		if num > 0 && entries != nil {
			arr := unsafe.Slice((*unsafe.Pointer)(entries), num)
			for _, fp := range arr {
				if fp == nil {
					continue
				}
				name := utf16PtrToStringW(*(**uint16)(unsafe.Add(fp, 16)))
				isDsse := false
				for _, want := range dsseFilterNames {
					if name == want {
						isDsse = true
						break
					}
				}
				if isDsse {
					copy(key[:], unsafe.Slice((*byte)(fp), 16)) // filterKey GUID is the first 16 bytes
					delName = name
					break
				}
			}
			procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
		}
		if num < batch {
			break
		}
	}
	if delName == "" {
		return "", fmt.Errorf("no DSSE filter found to delete")
	}
	if r, _, _ := procFwpmFilterDeleteByKey0.Call(uintptr(engine), uintptr(unsafe.Pointer(&key[0]))); r != 0 {
		return "", fmt.Errorf("FwpmFilterDeleteByKey0(%s) failed: 0x%x (admin required)", delName, r)
	}
	return delName, nil
}
