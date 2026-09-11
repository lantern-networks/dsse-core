//go:build windows

// catalog_windows.go — catalog (.cat) Authenticode verification. Windows SYSTEM binaries
// (notepad.exe, cmd.exe, …) are NOT embedded-signed; their signature lives in a security catalog. The
// embedded WinVerifyTrust(WINTRUST_FILE_INFO) path reports them unsigned. This adds the catalog path:
// hash the file, find the catalog that vouches for that hash, and WinVerifyTrust(WINTRUST_CATALOG_INFO).
// Used as a fallback by Signature so publisher:/signed: rules also cover catalog-signed apps.
package authenticode

import (
	"encoding/hex"
	"strings"
	"syscall"
	"unsafe"
)

var (
	procCryptCATAdminAcquireContext         = wintrustDLL.NewProc("CryptCATAdminAcquireContext")
	procCryptCATAdminCalcHashFromFileHandle = wintrustDLL.NewProc("CryptCATAdminCalcHashFromFileHandle")
	procCryptCATAdminEnumCatalogFromHash    = wintrustDLL.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATCatalogInfoFromContext      = wintrustDLL.NewProc("CryptCATCatalogInfoFromContext")
	procCryptCATAdminReleaseCatalogContext  = wintrustDLL.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext         = wintrustDLL.NewProc("CryptCATAdminReleaseContext")
)

const (
	wtdChoiceCatalog = 2
	maxPath          = 260
)

type winTrustCatalogInfo struct {
	cbStruct             uint32
	dwCatalogVersion     uint32
	pcwszCatalogFilePath *uint16
	pcwszMemberTag       *uint16
	pcwszMemberFilePath  *uint16
	hMemberFile          syscall.Handle
	pbCalculatedFileHash *byte
	cbCalculatedFileHash uint32
	_                    uint32
	pcCatalogContext     uintptr
	hCatAdmin            uintptr
}

type catalogInfo struct {
	cbStruct   uint32
	_          uint32
	wszCatalog [maxPath]uint16
}

// CatalogSignature verifies a file via the system catalog store. Returns (valid, signerName) where
// signerName is the catalog's signer (e.g. "Microsoft Windows"). (false,"") if no catalog vouches for it.
func CatalogSignature(path string) (bool, string) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, ""
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return false, ""
	}
	defer syscall.CloseHandle(h)

	var hCatAdmin uintptr
	if r, _, _ := procCryptCATAdminAcquireContext.Call(uintptr(unsafe.Pointer(&hCatAdmin)), 0, 0); r == 0 {
		return false, ""
	}
	defer procCryptCATAdminReleaseContext.Call(hCatAdmin, 0)

	var cbHash uint32
	procCryptCATAdminCalcHashFromFileHandle.Call(uintptr(h), uintptr(unsafe.Pointer(&cbHash)), 0, 0)
	if cbHash == 0 {
		return false, ""
	}
	hash := make([]byte, cbHash)
	if r, _, _ := procCryptCATAdminCalcHashFromFileHandle.Call(uintptr(h), uintptr(unsafe.Pointer(&cbHash)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
		return false, ""
	}

	hCatInfo, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(hCatAdmin, uintptr(unsafe.Pointer(&hash[0])), uintptr(cbHash), 0, 0)
	if hCatInfo == 0 {
		return false, "" // no catalog vouches for this file
	}
	defer procCryptCATAdminReleaseCatalogContext.Call(hCatAdmin, hCatInfo, 0)

	var ci catalogInfo
	ci.cbStruct = uint32(unsafe.Sizeof(ci))
	if r, _, _ := procCryptCATCatalogInfoFromContext.Call(hCatInfo, uintptr(unsafe.Pointer(&ci)), 0); r == 0 {
		return false, ""
	}
	catalogPath := syscall.UTF16ToString(ci.wszCatalog[:])

	// member tag = hex(hash), uppercased (the convention WinVerifyTrust expects for catalog members)
	tag := strings.ToUpper(hex.EncodeToString(hash))
	tagPtr, _ := syscall.UTF16PtrFromString(tag)
	catPtr, _ := syscall.UTF16PtrFromString(catalogPath)

	wci := winTrustCatalogInfo{
		pcwszCatalogFilePath: catPtr,
		pcwszMemberTag:       tagPtr,
		pcwszMemberFilePath:  p,
		hMemberFile:          h,
		pbCalculatedFileHash: &hash[0],
		cbCalculatedFileHash: cbHash,
		hCatAdmin:            hCatAdmin,
	}
	wci.cbStruct = uint32(unsafe.Sizeof(wci))

	wd := winTrustData{
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceCatalog,
		pFile:               uintptr(unsafe.Pointer(&wci)),
		dwStateAction:       wtdStateActionVerify,
	}
	wd.cbStruct = uint32(unsafe.Sizeof(wd))
	const invalidHandle = ^uintptr(0)
	ret, _, _ := procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&genericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	wd.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&genericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	if ret != 0 {
		return false, ""
	}
	display, _, _ := SignerDetails(catalogPath) // the catalog file's signer (e.g. Microsoft Windows)
	return true, display
}
