//go:build windows

// dsse-tray — the user-session system-tray UI (roadmap M3, docs/windows_agent_tray_ui_design.ja.md). It reads
// the DsseSteer service's read-only status endpoint (M2b) and reflects it as a tray icon + tooltip + balloon.
// It is a MIRROR, not a switch: NO capability to change enforcement (no pause/stop). Runs in the user session
// (the session-0 service cannot show UI). A background goroutine fetches status and asks the UI thread to render
// via PostMessage (so all NOTIFYICONDATA mutations happen on one thread — no data race).
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lantern-networks/dsse-core/agentstatus"
	"golang.org/x/sys/windows"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procLoadIconW        = user32.NewProc("LoadIconW")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmDestroy    = 0x0002
	wmCommand    = 0x0111
	wmApp        = 0x8000
	trayCallback = wmApp + 1
	wmRefresh    = wmApp + 2
	wmRButtonUp  = 0x0205
	wmLButtonDbl = 0x0203

	nimAdd     = 0
	nimModify  = 1
	nimDelete  = 2
	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nifInfo    = 0x10

	mfString     = 0x0000
	tpmRightBtn  = 0x0002
	tpmReturnCmd = 0x0100

	idQuit   = 1001
	idDetail = 1002

	idiApplication = 32512 // gray / stopped
	idiHand        = 32513 // red / dark|error
	idiExclamation = 32515 // amber / onboarding|disarmed
	idiShield      = 32518 // green / steering
)

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

type point struct{ x, y int32 }

// NOTIFYICONDATAW (modern full layout).
type notifyIconData struct {
	cbSize            uint32
	hWnd              uintptr
	uID               uint32
	uFlags            uint32
	uCallbackMessage  uint32
	hIcon             uintptr
	szTip             [128]uint16
	dwState           uint32
	dwStateMask       uint32
	szInfo            [256]uint16
	uTimeoutOrVersion uint32
	szInfoTitle       [64]uint16
	dwInfoFlags       uint32
	guidItem          [16]byte
	hBalloonIcon      uintptr
}

var (
	statusAddr string
	mainHWND   uintptr
	nid        notifyIconData         // touched only on the UI thread (render/showMenu)
	lastProt   agentstatus.Protection = "init"

	stMu     sync.Mutex // guards latest/latestOK, written by the fetch goroutine, read by the UI thread
	latest   agentstatus.Status
	latestOK bool
)

func iconForState(p agentstatus.Protection) uintptr {
	var id uintptr
	switch p.Icon() {
	case "green":
		id = idiShield
	case "amber":
		id = idiExclamation
	case "red":
		id = idiHand
	default:
		id = idiApplication
	}
	h, _, _ := procLoadIconW.Call(0, id)
	return h
}

func setU16(dst []uint16, s string) {
	u := windows.StringToUTF16(s)
	for i := range dst {
		if i < len(u) {
			dst[i] = u[i]
		} else {
			dst[i] = 0
		}
	}
	dst[len(dst)-1] = 0
}

// fetchOnce (goroutine) reads the status endpoint, stores it, and asks the UI thread to render.
func fetchOnce() {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	st := agentstatus.Status{}
	ok := false
	if resp, err := client.Get("http://" + statusAddr + "/status"); err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if s, perr := agentstatus.Parse(b); perr == nil {
			st, ok = s, true
		}
	}
	stMu.Lock()
	latest, latestOK = st, ok
	stMu.Unlock()
	procPostMessageW.Call(mainHWND, wmRefresh, 0, 0)
}

// render (UI thread) reflects the latest status onto the tray icon + tooltip, with a balloon on state change.
func render() {
	stMu.Lock()
	st, ok := latest, latestOK
	stMu.Unlock()

	prot := st.Protection
	var tip string
	if !ok {
		prot = agentstatus.Stopped
		tip = "DSSE — service not reachable"
	} else {
		who := st.Tenant
		if st.Group != "" {
			who += "/" + st.Group
		}
		tip = fmt.Sprintf("DSSE — %s\n%s · %s", prot.Label(), who, st.Region)
	}

	nid.uFlags = nifIcon | nifTip
	nid.hIcon = iconForState(prot)
	setU16(nid.szTip[:], tip)
	if prot != lastProt && lastProt != "init" {
		nid.uFlags |= nifInfo
		setU16(nid.szInfoTitle[:], "DSSE 状態が変わりました")
		setU16(nid.szInfo[:], prot.Label())
	}
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
	nid.uFlags = nifIcon | nifTip
	lastProt = prot
}

func showMenu() {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)
	procAppendMenuW.Call(hMenu, mfString, idDetail, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("状態を通知 (Show status)"))))
	procAppendMenuW.Call(hMenu, mfString, idQuit, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("終了 (Quit)"))))
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWin.Call(mainHWND) // so the menu dismisses correctly
	cmd, _, _ := procTrackPopupMenu.Call(hMenu, tpmRightBtn|tpmReturnCmd, uintptr(pt.x), uintptr(pt.y), 0, mainHWND, 0)
	switch cmd {
	case idQuit:
		procDestroyWindow.Call(mainHWND)
	case idDetail:
		stMu.Lock()
		st := latest
		stMu.Unlock()
		who := st.Tenant
		if st.Group != "" {
			who += "/" + st.Group
		}
		nid.uFlags = nifIcon | nifTip | nifInfo
		setU16(nid.szInfoTitle[:], "DSSE")
		setU16(nid.szInfo[:], fmt.Sprintf("%s\n%s · %s\nposture=%s edge=%v", st.Protection.Label(), who, st.Region, st.Posture, st.EdgeReachable))
		procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
		nid.uFlags = nifIcon | nifTip
	}
}

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch msg {
	case trayCallback:
		if lParam == wmRButtonUp || lParam == wmLButtonDbl {
			showMenu()
		}
		return 0
	case wmRefresh:
		render()
		return 0
	case wmCommand:
		if (wParam & 0xffff) == idQuit {
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case wmDestroy:
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func main() {
	addr := flag.String("status", "127.0.0.1:18011", "DsseSteer read-only status endpoint (host:port)")
	interval := flag.Int("interval", 3, "status poll interval (seconds)")
	flag.Parse()
	statusAddr = *addr

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	className := windows.StringToUTF16Ptr("DsseTrayWindow")
	hCursor, _, _ := procLoadCursorW.Call(0, 32512)
	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   windows.NewCallback(wndProc),
		hInstance:     hInstance,
		hCursor:       hCursor,
		lpszClassName: className,
	}
	if r, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return
	}
	title := windows.StringToUTF16Ptr("DSSE Tray")
	mainHWND, _, _ = procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)),
		0, 0, 0, 0, 0, 0, 0, hInstance, 0)
	if mainHWND == 0 {
		return
	}

	nid = notifyIconData{
		cbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:             mainHWND,
		uID:              1,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: trayCallback,
	}
	nid.hIcon = iconForState(agentstatus.Stopped)
	setU16(nid.szTip[:], "DSSE — starting…")
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))

	iv := *interval
	if iv < 1 {
		iv = 3
	}
	go func() {
		fetchOnce() // immediate first paint
		t := time.NewTicker(time.Duration(iv) * time.Second)
		defer t.Stop()
		for range t.C {
			fetchOnce()
		}
	}()

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
