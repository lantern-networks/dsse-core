//go:build windows

// dsse-stepup-window: the Lantern DSSE-branded, app-owned OOB authentication window for the East-West step-up
// ceremony (task #14 — Windows parity with the macOS StepUpAuthWindow). It replaces the "surprise default-browser
// tab": the WFP agent (session-0 service) hands this exe the Edge-issued portal URL, and it opens a branded
// window hosting the REAL IdP login page (Edge clientless broker -> tenant IdP) in a WebView2. Credentials /
// passkey are entered on the genuine IdP origin (this window is only the container), which is what keeps the flow
// phishing-resistant — the client never sees or posts the user's secret. The window auto-closes when the ceremony
// reaches the Edge "Access approved" callback page; the held connection then auto-releases server-side (task #5),
// so no client re-run is needed.
//
// Layout mirrors the macOS window: a dark branded header (Lantern DSSE + セキュア認証), a WebView2 filling the
// body (a child HWND so the header/footer are not covered), and a status line at the bottom.
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/jchv/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"
)

// ---- Win32 (raw, self-contained — go-webview2's w32 helpers are an internal package we cannot import) ----

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procGetClientRect       = user32.NewProc("GetClientRect")
	procMoveWindow          = user32.NewProc("MoveWindow")
	procInvalidateRect      = user32.NewProc("InvalidateRect")
	procBeginPaint          = user32.NewProc("BeginPaint")
	procEndPaint            = user32.NewProc("EndPaint")
	procFillRect            = user32.NewProc("FillRect")
	procDrawTextW           = user32.NewProc("DrawTextW")
	procLoadCursorW         = user32.NewProc("LoadCursorW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procUpdateWindow        = user32.NewProc("UpdateWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procSetTimer            = user32.NewProc("SetTimer")
	procKillTimer           = user32.NewProc("KillTimer")

	// Bring-to-front (a service-spawned window is not the foreground process, so a bare SetForegroundWindow is
	// ignored -> only a taskbar flash; these implement the reliable AttachThreadInput + topmost-toggle dance).
	procSetWindowPos             = user32.NewProc("SetWindowPos")
	procBringWindowToTop         = user32.NewProc("BringWindowToTop")
	procGetForegroundWindow      = user32.NewProc("GetForegroundWindow")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procAttachThreadInput        = user32.NewProc("AttachThreadInput")
	procSystemParametersInfoW    = user32.NewProc("SystemParametersInfoW")
	procFlashWindowEx            = user32.NewProc("FlashWindowEx")
	procGetCurrentThreadId       = kernel32.NewProc("GetCurrentThreadId")

	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procSetBkMode        = gdi32.NewProc("SetBkMode")
	procSetTextColor     = gdi32.NewProc("SetTextColor")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procCreateFontW      = gdi32.NewProc("CreateFontW")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy = 0x0002
	wmSize    = 0x0005
	wmPaint   = 0x000F
	wmTimer   = 0x0113

	wsOverlappedWindow = 0x00CF0000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	swShow             = 5
	cwUseDefault       = 0x80000000
	idcArrow           = 32512
	colorWindow        = 5

	dtLeft       = 0x0000
	dtVCenter    = 0x0004
	dtSingleLine = 0x0020
	dtNoPrefix   = 0x0800

	transparentBk = 1

	closeTimerID      = 1
	foregroundTimerID = 2

	wsExTopmost   = 0x00000008
	swpNoSize     = 0x0001
	swpNoMove     = 0x0002
	swpShowWindow = 0x0040
	hwndTopmost   = ^uintptr(0)     // (HWND)-1
	hwndNotopmost = ^uintptr(0) - 1 // (HWND)-2

	spiGetForegroundLockTimeout = 0x2000
	spiSetForegroundLockTimeout = 0x2001
	spifSendChange              = 0x0002

	flashwStop      = 0
	flashwAll       = 0x00000003 // caption + taskbar button
	flashwTimernofg = 0x0000000C // keep flashing until the window comes to the foreground
)

type flashWInfo struct {
	cbSize    uint32
	hwnd      uintptr
	dwFlags   uint32
	uCount    uint32
	dwTimeout uint32
}

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type msgStruct struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

type rect struct{ left, top, right, bottom int32 }

type paintStruct struct {
	hdc         uintptr
	fErase      int32
	rcPaint     rect
	fRestore    int32
	fIncUpdate  int32
	rgbReserved [32]byte
}

// ---- window state ----

const (
	headerH = 60
	footerH = 30
	winW    = 560
	winH    = 780
)

var (
	mainHWND uintptr
	bodyHWND uintptr
	chromium *edge.Chromium

	statusText atomic.Value // string
	completed  atomic.Bool

	headerBrush  uintptr
	fontWordmark uintptr
	fontTagline  uintptr
	fontStatus   uintptr

	destLabel string
)

func setStatus(s string) {
	statusText.Store(s)
	if mainHWND != 0 {
		// repaint the footer strip
		procInvalidateRect.Call(mainHWND, 0, 1)
	}
}

func main() {
	portal := flag.String("portal", "", "Edge-issued step-up portal URL to host")
	dest := flag.String("dest", "", "destination host:port being authenticated (display only)")
	insecureSkipPortalVerify := flag.Bool("insecure-skip-portal-cert-verify", false,
		"accept ANY certificate for the step-up portal and the identity provider it redirects to. For a lab "+
			"whose portal certificate has not been provided yet. Off by default: this window is where a user "+
			"types their password and second factor.")
	flag.Parse()
	if strings.TrimSpace(*portal) == "" {
		fmt.Fprintln(os.Stderr, "dsse-stepup-window: --portal is required")
		os.Exit(2)
	}
	destLabel = strings.TrimSpace(*dest)
	if destLabel == "" {
		destLabel = destinationFromPortal(*portal)
	}
	statusText.Store(fmt.Sprintf("接続先 %s を認証しています…", destLabel))

	// ★★★ THIS WINDOW VERIFIES THE PORTAL'S CERTIFICATE (2026-09-03, the operator's decision, after the
	// Windows box read this code and reported what it does).
	//
	// It used to set --ignore-certificate-errors unconditionally, in a signed shipping binary, on the one
	// surface where a user types their corporate password and second factor. The comment defended it with
	// "it does not weaken WebAuthn RP binding", which is true of passkeys and is not the common case: an
	// Okta, an Entra ID or a Keycloak asking for a password and a TOTP hands both to whoever holds the
	// connection, and a window that accepts any certificate is a window that cannot tell who that is.
	//
	// It also made the operator's own decision unenforceable. They chose that the step-up portal's
	// certificate is the operator's to provide — and a window that never checks makes providing one worth
	// nothing. What now makes the portal trustworthy is the ORGANIZATION'S OWN TRANSPORT ANCHOR, laid into
	// the machine store at provision time beside the interception root: the device already relies on that CA
	// for its tunnel, so trusting it here adds no authority the device was not already trusting.
	//
	// ★ THE BYPASS SURVIVES AS AN EXPLICIT, LOUD OPT-IN. A lab whose portal certificate has not been
	// provided is a real situation, and WebView2 genuinely has no interstitial to click through — so
	// without an escape hatch that lab is simply stuck. It is off by default, it is named for what it does,
	// and it says so on stderr every time, because the danger of this flag is being left on.
	if *insecureSkipPortalVerify {
		fmt.Fprintln(os.Stderr, "dsse-stepup-window: WARNING — --insecure-skip-portal-cert-verify is set. "+
			"This window will accept ANY certificate for the portal and the identity provider it redirects to, "+
			"including one presented by somebody on the path. The password and second factor typed here go to "+
			"whoever holds the connection. Use it in a lab and nowhere else.")
		if os.Getenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") == "" {
			_ = os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--ignore-certificate-errors")
		}
	}

	if !buildWindow() {
		fmt.Fprintln(os.Stderr, "dsse-stepup-window: failed to create window")
		os.Exit(1)
	}

	chromium = edge.NewChromium()
	chromium.MessageCallback = onWebMessage
	if !chromium.Embed(bodyHWND) {
		fmt.Fprintln(os.Stderr, "dsse-stepup-window: failed to embed WebView2 (runtime missing?)")
		os.Exit(1)
	}
	chromium.Resize()
	// Report the live document title + URL back to Go whenever a document lands or its <title> changes. This
	// rides out the title-lag the macOS side hit (a title read at NavigationCompleted returns the PREVIOUS
	// page's title); load + a <title> MutationObserver fire only when the REAL title is present.
	chromium.Init(titleReporterJS)
	chromium.Navigate(*portal)

	forceForeground(mainHWND)
	// Re-assert shortly after: WebView2 finishing controller creation / first paint can steal focus during load.
	procSetTimer.Call(mainHWND, foregroundTimerID, 400, 0)
	runMessageLoop()
}

// forceForeground makes the step-up window impossible to miss even though a session-0-spawned process cannot
// reliably win Windows' foreground race. It (1) drops the foreground-lock timeout, (2) keeps the window TOPMOST
// so it is guaranteed visible above every other window until it closes, (3) best-effort grabs focus via the
// AttachThreadInput dance so the user can type immediately, and (4) FLASHES the taskbar button until the window
// is foreground as a fallback cue. Topmost + flash is the robust "the user notices it" guarantee; the raw
// SetForegroundWindow is only a nice-to-have here (it is unreliable from a non-foreground process).
func forceForeground(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	var prev uint32
	procSystemParametersInfoW.Call(spiGetForegroundLockTimeout, 0, uintptr(unsafe.Pointer(&prev)), 0)
	procSystemParametersInfoW.Call(spiSetForegroundLockTimeout, 0, 0, spifSendChange)

	procShowWindow.Call(hwnd, swShow)
	procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)

	fg, _, _ := procGetForegroundWindow.Call()
	fgThread, _, _ := procGetWindowThreadProcessId.Call(fg, 0)
	thisThread, _, _ := procGetCurrentThreadId.Call()
	if fg != 0 && fgThread != 0 && fgThread != thisThread {
		procAttachThreadInput.Call(thisThread, fgThread, 1)
		procBringWindowToTop.Call(hwnd)
		procSetForegroundWindow.Call(hwnd)
		procAttachThreadInput.Call(thisThread, fgThread, 0)
	} else {
		procBringWindowToTop.Call(hwnd)
		procSetForegroundWindow.Call(hwnd)
	}

	fw := flashWInfo{cbSize: uint32(unsafe.Sizeof(flashWInfo{})), hwnd: hwnd, dwFlags: flashwAll | flashwTimernofg, uCount: 5}
	procFlashWindowEx.Call(uintptr(unsafe.Pointer(&fw)))

	procSystemParametersInfoW.Call(spiSetForegroundLockTimeout, 0, uintptr(prev), spifSendChange)
}

// destinationFromPortal extracts the real hop from the portal's return_to query param (url.host is the Edge).
func destinationFromPortal(portal string) string {
	if u, err := url.Parse(portal); err == nil {
		if rt := u.Query().Get("return_to"); rt != "" {
			return rt
		}
		if u.Host != "" {
			return u.Host
		}
	}
	return "内部リソース"
}

// titleReporterJS posts "href\ntitle" to the host on load and on any <title> mutation. The host classifies the
// ceremony outcome from the callback page's title (mirrors the macOS live document.title read).
const titleReporterJS = `
(function(){
  function report(){ try { window.chrome.webview.postMessage(location.href + "\n" + document.title); } catch(e){} }
  if (document.readyState === "interactive" || document.readyState === "complete") report();
  window.addEventListener("DOMContentLoaded", report);
  window.addEventListener("load", report);
  try {
    var t = document.querySelector("title");
    if (t) new MutationObserver(report).observe(t, {childList:true, subtree:true, characterData:true});
  } catch(e){}
})();`

// onWebMessage receives the "href\ntitle" reports. On the Edge callback page it classifies approved/denied.
func onWebMessage(msg string) {
	nl := strings.IndexByte(msg, '\n')
	if nl < 0 {
		return
	}
	href, title := msg[:nl], msg[nl+1:]
	if !strings.Contains(href, "/clientless/auth/callback") || completed.Load() {
		return
	}
	switch {
	case strings.Contains(title, "Access approved") || strings.Contains(title, "承認"):
		completed.Store(true)
		setStatus("認証に成功しました — 接続を再開しています")
		// auto-close after ~2s so the user sees the success state (matches the macOS 2s dwell).
		procSetTimer.Call(mainHWND, closeTimerID, 2000, 0)
	case strings.Contains(title, "Access denied") || strings.Contains(title, "拒否"):
		setStatus("アクセスが拒否されました。要件をご確認ください。")
	}
}

func buildWindow() bool {
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	className := windows.StringToUTF16Ptr("DsseStepUpWindow")
	hCursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	headerBrush, _, _ = procCreateSolidBrush.Call(rgb(11, 20, 37)) // dark navy

	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   windows.NewCallback(wndProc),
		hInstance:     hInstance,
		hCursor:       hCursor,
		hbrBackground: colorWindow + 1,
		lpszClassName: className,
	}
	if r, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return false
	}

	title := windows.StringToUTF16Ptr("Lantern DSSE 認証")
	mainHWND, _, _ = procCreateWindowExW.Call(
		wsExTopmost, // start topmost so it appears above other windows even during WebView2 init; forceForeground drops it to non-topmost once focused
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		wsOverlappedWindow,
		cwUseDefault, cwUseDefault, winW, winH,
		0, 0, hInstance, 0,
	)
	if mainHWND == 0 {
		return false
	}
	// The mark, before anything is shown. A credential window that appears without one for even a moment has
	// already been the unmarked window somebody looked at.
	applyWindowIcon(mainHWND)

	// Child HWND (built-in STATIC) that hosts the WebView2, positioned below the header / above the footer so
	// the branded chrome is never covered.
	static := windows.StringToUTF16Ptr("STATIC")
	bodyHWND, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(static)),
		0,
		wsChild|wsVisible,
		0, headerH, winW, winH-headerH-footerH,
		mainHWND, 0, hInstance, 0,
	)
	if bodyHWND == 0 {
		return false
	}

	fontWordmark = createFont(20, 700)
	fontTagline = createFont(13, 400)
	fontStatus = createFont(13, 400)

	procShowWindow.Call(mainHWND, swShow)
	procUpdateWindow.Call(mainHWND)
	return true
}

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmSize:
		layoutBody(hwnd)
		if chromium != nil {
			chromium.Resize()
		}
		return 0
	case wmPaint:
		paint(hwnd)
		return 0
	case wmTimer:
		switch wParam {
		case closeTimerID:
			procKillTimer.Call(hwnd, closeTimerID)
			procDestroyWindow.Call(hwnd)
		case foregroundTimerID:
			procKillTimer.Call(hwnd, foregroundTimerID)
			forceForeground(hwnd)
		}
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

// layoutBody repositions the WebView2 host child to fill the area between the header and the footer.
func layoutBody(hwnd uintptr) {
	var rc rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	w := rc.right - rc.left
	h := rc.bottom - rc.top
	bodyH := h - headerH - footerH
	if bodyH < 0 {
		bodyH = 0
	}
	procMoveWindow.Call(bodyHWND, 0, headerH, uintptr(w), uintptr(bodyH), 1)
}

func paint(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	var rc rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	w := rc.right

	// Header bar (dark) + wordmark + tagline.
	header := rect{0, 0, w, headerH}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&header)), headerBrush)
	procSetBkMode.Call(hdc, transparentBk)

	// The mark sits left of the wordmark, vertically centred in the 60px header. drawHeaderMark returns where
	// the text starts, so a build where the icon could not be created still lays out exactly as it did before
	// rather than leaving a gap where a logo should be.
	const markSize = 32
	textLeft := drawHeaderMark(hdc, 20, (headerH-markSize)/2, markSize)

	procSelectObject.Call(hdc, fontWordmark)
	procSetTextColor.Call(hdc, rgb(255, 255, 255))
	drawText(hdc, "Lantern DSSE", rect{int32(textLeft), 8, w - 20, 34}, dtLeft|dtSingleLine|dtVCenter|dtNoPrefix)

	procSelectObject.Call(hdc, fontTagline)
	procSetTextColor.Call(hdc, rgb(150, 160, 180))
	drawText(hdc, "セキュア認証", rect{int32(textLeft), 34, w - 20, headerH - 6}, dtLeft|dtSingleLine|dtVCenter|dtNoPrefix)

	// Footer status line (on the default window background).
	footer := rect{0, rc.bottom - footerH, w, rc.bottom}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&footer)), uintptr(colorWindow+1))
	procSelectObject.Call(hdc, fontStatus)
	procSetTextColor.Call(hdc, rgb(70, 70, 70))
	s, _ := statusText.Load().(string)
	drawText(hdc, s, rect{16, rc.bottom - footerH + 4, w - 16, rc.bottom - 4}, dtLeft|dtSingleLine|dtVCenter|dtNoPrefix)

	procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
}

func drawText(hdc uintptr, s string, r rect, format uintptr) {
	if s == "" {
		return
	}
	u16, _ := windows.UTF16FromString(s)
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&u16[0])), uintptr(len(u16)-1), uintptr(unsafe.Pointer(&r)), format)
}

func runMessageLoop() {
	var msg msgStruct
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func rgb(r, g, b uint32) uintptr { return uintptr(r | (g << 8) | (b << 16)) }

func createFont(height int32, weight int32) uintptr {
	face := windows.StringToUTF16Ptr("Yu Gothic UI")
	h, _, _ := procCreateFontW.Call(
		uintptr(height), 0, 0, 0, uintptr(weight),
		0, 0, 0, 1 /*DEFAULT_CHARSET=1... actually SHIFTJIS=128; use 1*/, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(face)),
	)
	return h
}
