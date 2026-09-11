//go:build windows

package main

// brand_windows.go — the Lantern mark, in the two places a person looks to decide whether a window is real.
//
// ★ WHY A CREDENTIAL WINDOW IN PARTICULAR NEEDS THIS. This window exists to host an identity provider's own
// sign-in page, which means it is the one place in the product where a person is asked to type a password
// into something we drew. A window with no mark is a window that cannot be told apart from a window somebody
// else drew, and "it looked like the normal one" is how that goes wrong. The mark is not decoration here; it
// is the only thing on screen that says whose window this is before the page inside it loads.
//
// It is put in both places Windows will look, because they are different surfaces to a person:
//   - the window icon (title bar, Alt-Tab, taskbar) — how the window is recognised when it is NOT in front
//   - the header bar, beside the wordmark — how it is recognised when it IS
//
// ★ ONE ASSET, BOTH USES. The .ico carries every size Windows asks for (16 through 128 as DIB, 256 as PNG),
// so the small icon, the large icon and the header draw come from the same file rather than from three
// resources that can drift. It is embedded rather than installed beside the exe: a mark that can be replaced
// by writing a file next to the binary is not a mark that proves anything.

import (
	_ "embed"
	"unsafe"
)

//go:embed brand/lantern.ico
var lanternICO []byte

var (
	procCreateIconFromResourceEx = user32.NewProc("CreateIconFromResourceEx")
	procLookupIconIdFromDirEx    = user32.NewProc("LookupIconIdFromDirectoryEx")
	procDrawIconEx               = user32.NewProc("DrawIconEx")
	procSendMessageW             = user32.NewProc("SendMessageW")
	procDestroyIcon              = user32.NewProc("DestroyIcon")
)

const (
	wmSetIcon    = 0x0080
	iconSmall    = 0
	iconBig      = 1
	lrDefaultCol = 0x00000000
	diNormal     = 0x0003
)

// iconOfSize builds an HICON of the requested size from the embedded .ico.
//
// LookupIconIdFromDirectoryEx picks the best entry for the size being asked for — which is the whole reason
// for shipping several — and CreateIconFromResourceEx turns that entry into an icon. Doing it this way rather
// than writing the bytes to a temp file and calling LoadImage keeps the mark inside the binary: there is no
// moment where a file on disk decides what this window claims to be.
func iconOfSize(px int) uintptr {
	if len(lanternICO) == 0 {
		return 0
	}
	id, _, _ := procLookupIconIdFromDirEx.Call(
		uintptr(unsafe.Pointer(&lanternICO[0])),
		1, // fIcon
		uintptr(px), uintptr(px),
		lrDefaultCol,
	)
	if id == 0 || int(id) >= len(lanternICO) {
		return 0
	}
	// LookupIconIdFromDirectoryEx returns the OFFSET of the chosen entry's image data within the .ico, and
	// CreateIconFromResourceEx wants a pointer to that data plus its length. The length is read back out of
	// the directory rather than guessed: passing the rest of the file works for the last entry and silently
	// hands the next entry's bytes to every other one.
	off, size := int(id), 0
	if n := int(lanternICO[4]) | int(lanternICO[5])<<8; n > 0 {
		for i := 0; i < n; i++ {
			e := 6 + 16*i
			eSize := int(lanternICO[e+8]) | int(lanternICO[e+9])<<8 | int(lanternICO[e+10])<<16 | int(lanternICO[e+11])<<24
			eOff := int(lanternICO[e+12]) | int(lanternICO[e+13])<<8 | int(lanternICO[e+14])<<16 | int(lanternICO[e+15])<<24
			if eOff == off {
				size = eSize
				break
			}
		}
	}
	if size <= 0 || off+size > len(lanternICO) {
		return 0
	}
	h, _, _ := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&lanternICO[off])),
		uintptr(size),
		1,          // fIcon
		0x00030000, // dwVer: the icon format version Windows expects here
		uintptr(px), uintptr(px),
		lrDefaultCol,
	)
	return h
}

// applyWindowIcon sets the small and large icons of a window.
//
// Both, and separately: the small one is the title bar and Alt-Tab, the large one is the taskbar and the
// Alt-Tab overlay at larger DPI. Setting only ICON_BIG leaves a correct taskbar entry above a title bar still
// showing the Windows default, which reads as a window that was thrown together.
func applyWindowIcon(hwnd uintptr) {
	if small := iconOfSize(16); small != 0 {
		procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, small)
	}
	if big := iconOfSize(32); big != 0 {
		procSendMessageW.Call(hwnd, wmSetIcon, iconBig, big)
	}
}

// drawHeaderMark paints the symbol in the header bar. Returns the x offset the text should start at, so the
// wordmark moves out of the way when there is a mark and stays where it was when there is not.
func drawHeaderMark(hdc uintptr, left, top, size int) int {
	h := iconOfSize(size)
	if h == 0 {
		return left // no mark: leave the text exactly where it has always been
	}
	defer procDestroyIcon.Call(h)
	procDrawIconEx.Call(hdc, uintptr(left), uintptr(top), h,
		uintptr(size), uintptr(size), 0, 0, diNormal)
	return left + size + 12
}
