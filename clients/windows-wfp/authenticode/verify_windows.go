//go:build windows

// verify_windows.go — "is this file validly Authenticode-signed, and who signed it", as raw wintrust/crypt32
// calls with no new module dependency.
//
// ★ IT IS A PACKAGE BECAUSE THERE ARE NOW TWO CALLERS AND THERE MUST NOT BE TWO IMPLEMENTATIONS
// (2026-08-14). It was written for steer-exclusion app identity — the legacy bypass matches an image-PATH
// substring, which is spoofable — and it answers exactly the question the update gate needed next: before
// `msiexec /i` is launched as SYSTEM, who built these bytes? Writing a second WinVerifyTrust wrapper beside
// this one would have been the family this codebase keeps finding and this month decided to stop producing:
// two hand-written implementations of one rule, of which some later fix reaches one.
//
// The identity fields are deliberately the same three, in one vocabulary, so a `subject:` an operator writes
// for an exclusion and a `subject:` they write for the update gate mean the same thing.
package authenticode

import (
	"encoding/hex"
	"strings"
	"syscall"
	"unsafe"
)

var (
	wintrustDLL        = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = wintrustDLL.NewProc("WinVerifyTrust")

	crypt32DLL                            = syscall.NewLazyDLL("crypt32.dll")
	procCryptQueryObject                  = crypt32DLL.NewProc("CryptQueryObject")
	procCryptMsgGetParam                  = crypt32DLL.NewProc("CryptMsgGetParam")
	procCryptMsgClose                     = crypt32DLL.NewProc("CryptMsgClose")
	procCertFindCertificateInStore        = crypt32DLL.NewProc("CertFindCertificateInStore")
	procCertGetNameStringW                = crypt32DLL.NewProc("CertGetNameStringW")
	procCertGetCertificateContextProperty = crypt32DLL.NewProc("CertGetCertificateContextProperty")
	procCertFreeCertificateContext        = crypt32DLL.NewProc("CertFreeCertificateContext")
	procCertCloseStore                    = crypt32DLL.NewProc("CertCloseStore")
)

type sigGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2 — the standard Authenticode policy.
var genericVerifyV2 = sigGUID{0xaac56b, 0xcd44, 0x11d0, [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}

type winTrustFileInfo struct {
	cbStruct       uint32
	_              uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject uintptr
}

type winTrustData struct {
	cbStruct            uint32
	_                   uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	_                   uint32
	pFile               uintptr // union member (WTD_CHOICE_FILE) -> *winTrustFileInfo
	dwStateAction       uint32
	_                   uint32
	hWVTStateData       syscall.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

const (
	wtdUINone            = 2
	wtdRevokeNone        = 0
	wtdChoiceFile        = 1
	wtdStateActionVerify = 1
	wtdStateActionClose  = 2

	certQueryObjectFile                  = 1
	certQueryContentFlagPKCS7SignedEmbed = 0x400
	certQueryFormatFlagBinary            = 0x2
	cmsgSignerCertInfoParam              = 7
	certFindSubjectCert                  = 0x000B0000
	certNameSimpleDisplayType            = 4
	certNameAttrType                     = 3   // CERT_NAME_ATTR_TYPE: pvTypePara is an OID string (e.g. O=)
	certSHA256HashPropID                 = 107 // CERT_SHA256_HASH_PROP_ID: leaf cert SHA-256 thumbprint
	x509AsnEncoding                      = 0x1
	pkcs7AsnEncoding                     = 0x10000
)

// szOID_ORGANIZATION_NAME — the Subject Organization (O=) attribute OID. Pinning the signer's O is the practical
// analog of a macOS Team ID: stable across app versions and across the org's individual signing certs.
var oidOrganizationName = []byte("2.5.4.10\x00")

// Valid reports whether the file at path carries a valid embedded Authenticode signature that chains to a
// trusted root (no revocation check — kept offline/fast). False for unsigned, tampered, or untrusted-chain
// files.
//
// ★ ON WINDOWS THIS ALSO ANSWERS "HAVE THE BYTES CHANGED", which is why the update gate needs one tool here
// and macOS needs two. Measured on win-dev-1 (2026-08-13): flipping one byte in the middle of a signed MSI
// makes this return TRUST_E_BAD_DIGEST. Gatekeeper's assessment on macOS is a quarantine-time story and
// nothing quarantines a file a daemon downloaded, so that platform asks pkgutil and spctl separately; the
// reasoning is written out in clients/macos/updateplatform/publisher.go and does not carry over.
func Valid(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	fi := winTrustFileInfo{pcwszFilePath: p}
	fi.cbStruct = uint32(unsafe.Sizeof(fi))
	wd := winTrustData{
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               uintptr(unsafe.Pointer(&fi)),
		dwStateAction:       wtdStateActionVerify,
	}
	wd.cbStruct = uint32(unsafe.Sizeof(wd))
	const invalidHandle = ^uintptr(0)
	ret, _, _ := procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&genericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	// release the state data regardless of result
	wd.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&genericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	return ret == 0 // ERROR_SUCCESS == trusted
}

// SignerDetails extracts (display name, Subject O=, leaf SHA-256 hex) from the embedded PKCS#7 signature.
// Does NOT validate trust — pair with Valid (Signature does).
func SignerDetails(path string) (display, org, thumbprint string) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", "", ""
	}
	var encoding, contentType, formatType uint32
	var hStore, hMsg syscall.Handle
	ret, _, _ := procCryptQueryObject.Call(
		certQueryObjectFile, uintptr(unsafe.Pointer(p)),
		certQueryContentFlagPKCS7SignedEmbed, certQueryFormatFlagBinary, 0,
		uintptr(unsafe.Pointer(&encoding)), uintptr(unsafe.Pointer(&contentType)), uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&hStore)), uintptr(unsafe.Pointer(&hMsg)), 0)
	if ret == 0 {
		return "", "", ""
	}
	defer procCertCloseStore.Call(uintptr(hStore), 0)
	defer procCryptMsgClose.Call(uintptr(hMsg))

	// fetch the signer CERT_INFO (Issuer + SerialNumber) from the signed message
	var cb uint32
	procCryptMsgGetParam.Call(uintptr(hMsg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&cb)))
	if cb == 0 {
		return "", "", ""
	}
	buf := make([]byte, cb)
	ret, _, _ = procCryptMsgGetParam.Call(uintptr(hMsg), cmsgSignerCertInfoParam, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&cb)))
	if ret == 0 {
		return "", "", ""
	}
	pCert, _, _ := procCertFindCertificateInStore.Call(uintptr(hStore), x509AsnEncoding|pkcs7AsnEncoding, 0,
		certFindSubjectCert, uintptr(unsafe.Pointer(&buf[0])), 0)
	if pCert == 0 {
		return "", "", ""
	}
	defer procCertFreeCertificateContext.Call(pCert)

	display = certNameString(pCert, certNameSimpleDisplayType, 0)
	org = certNameString(pCert, certNameAttrType, uintptr(unsafe.Pointer(&oidOrganizationName[0])))
	thumbprint = certThumbprintSHA256(pCert)
	return display, org, thumbprint
}

// certNameString wraps CertGetNameStringW for a given name type (pvTypePara is an OID pointer for
// certNameAttrType, else 0). Returns "" if absent.
func certNameString(pCert uintptr, dwType uint32, pvTypePara uintptr) string {
	n, _, _ := procCertGetNameStringW.Call(pCert, uintptr(dwType), 0, pvTypePara, 0, 0)
	if n <= 1 {
		return ""
	}
	nameBuf := make([]uint16, n)
	procCertGetNameStringW.Call(pCert, uintptr(dwType), 0, pvTypePara, uintptr(unsafe.Pointer(&nameBuf[0])), n)
	return strings.TrimSpace(syscall.UTF16ToString(nameBuf))
}

// certThumbprintSHA256 returns the leaf certificate's SHA-256 thumbprint as lowercase hex ("" on failure).
func certThumbprintSHA256(pCert uintptr) string {
	var cb uint32
	procCertGetCertificateContextProperty.Call(pCert, certSHA256HashPropID, 0, uintptr(unsafe.Pointer(&cb)))
	if cb == 0 {
		return ""
	}
	buf := make([]byte, cb)
	ret, _, _ := procCertGetCertificateContextProperty.Call(pCert, certSHA256HashPropID, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&cb)))
	if ret == 0 {
		return ""
	}
	return hex.EncodeToString(buf[:cb])
}

// Signature is the combined check: a file is "trusted as <signer>" only when its Authenticode signature
// validates; the returned identity (Publisher/Org/Thumbprint) lets a rule pin a specific signer. Falls back to
// catalog signing for system binaries (display name only; Org/Thumbprint unavailable there).
//
// ★ THE CATALOG FALLBACK CANNOT SATISFY A `subject:` OR `thumbprint:` REQUIREMENT, and that is load-bearing
// for the update gate rather than an accident: a catalog-signed file yields no Org and no Thumbprint, so the
// two forms the gate accepts (see Requirement) fail closed on it. Only the exclusion vocabulary's looser
// `publisher:` form can match a catalog signature, and the gate refuses that form outright.
func Signature(path string) Sig {
	if Valid(path) {
		display, org, thumb := SignerDetails(path)
		return Sig{Valid: true, Publisher: display, Org: org, Thumbprint: thumb}
	}
	// Fall back to catalog (.cat) signing — Windows system binaries (notepad/cmd) are catalog-signed, not
	// embedded. Third-party exclusion targets are usually embedded-signed (handled above); this adds coverage.
	valid, pub := CatalogSignature(path)
	return Sig{Valid: valid, Publisher: pub}
}
