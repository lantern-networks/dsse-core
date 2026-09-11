package engine

/*
#cgo LDFLAGS: -lcurl-impersonate
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

// libcurl-impersonate: apply a browser's TLS+H2 profile to an easy handle.
extern CURLcode curl_easy_impersonate(CURL *data, const char *target, int default_headers);

// Pre-request peer check, defined in http.go's Go side and shared by both paths (same package).
extern int brokerPrereqCB(void *clientp, char *conn_primary_ip, char *conn_local_ip, int primary_port, int local_port);
static CURLcode be_setcb_prereq(CURL *h) { return curl_easy_setopt(h, CURLOPT_PREREQFUNCTION, brokerPrereqCB); }

static CURL* be_init(void) { return curl_easy_init(); }
static void be_cleanup(CURL *h) { curl_easy_cleanup(h); }
static CURLcode be_setstr(CURL *h, CURLoption o, const char *v) { return curl_easy_setopt(h, o, v); }
static CURLcode be_setlong(CURL *h, CURLoption o, long v) { return curl_easy_setopt(h, o, v); }
static CURLcode be_setptr(CURL *h, CURLoption o, void *v) { return curl_easy_setopt(h, o, v); }
static CURLcode be_perform(CURL *h) { return curl_easy_perform(h); }
static CURLcode be_impersonate(CURL *h, const char *t) { return curl_easy_impersonate(h, t, 1); }
static long be_activesocket(CURL *h) { curl_socket_t s = CURL_SOCKET_BAD; curl_easy_getinfo(h, CURLINFO_ACTIVESOCKET, &s); return (long)s; }

// WebSocket in RAW mode: curl does the (fingerprinted) WS handshake, then we pass RAW frame bytes through with
// curl_easy_recv/curl_easy_send (curl_ws_recv/send un-frame to the payload even in raw mode; the low-level
// easy_recv/send give the actual post-handshake socket bytes = the WS frames themselves).
static CURLcode be_ws_raw(CURL *h) { return curl_easy_setopt(h, CURLOPT_WS_OPTIONS, (long)CURLWS_RAW_MODE); }
static CURLcode be_ws_recv(CURL *h, void *buf, size_t n, size_t *got) { return curl_easy_recv(h, buf, n, got); }
static CURLcode be_ws_send(CURL *h, const void *buf, size_t n, size_t *sent) { return curl_easy_send(h, buf, n, sent); }

static struct curl_slist* be_slist_append(struct curl_slist *l, const char *s) { return curl_slist_append(l, s); }
static void be_slist_free(struct curl_slist *l) { curl_slist_free_all(l); }
*/
import "C"

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unsafe"
)

// reoriginateWS re-originates a WebSocket through the REAL Chrome stack (libcurl-impersonate). curl performs the
// WS handshake itself (so the protocol — h2 Extended CONNECT or h1 — and the Chrome TLS/H2 fingerprint are the
// engine's own), then CURLWS_RAW_MODE lets curl_ws_send/recv carry RAW frame bytes, so we tunnel byte-transparently.
// Contract:
//   - X-Reorig-URL:     wss:// (or https) URL of the origin
//   - X-Reorig-Header:  the client's request headers to carry on the handshake (Chrome order); WS control headers
//     (Upgrade/Connection/Sec-WebSocket-*) are dropped — curl mints those.
//   - request body:     client->origin RAW WS frame bytes (post-101; the Edge already answered its client leg)
//   - response:         200, then origin->client RAW WS frame bytes.
func ReoriginateWS(w http.ResponseWriter, r *http.Request) {
	req := Request{URL: r.Header.Get("X-Reorig-URL")}
	if req.URL == "" {
		http.Error(w, "missing X-Reorig-URL", http.StatusBadRequest)
		return
	}
	req.HeaderLines = r.Header.Values("X-Reorig-Header")

	// HIJACK the (h1) connection from the Edge and tunnel raw bytes between it and the origin WS. The Edge dials
	// this leg as a raw h1 POST (not h2), so Hijack is available (h2 forbids it) — giving a clean full-duplex byte
	// pipe. (Go's h2 client does not stream a request body full-duplex, which zeroed the client->origin direction.)
	//
	// The hijack must NOT happen until the origin has accepted us. Hijacking takes the connection away from the
	// HTTP server, so nothing can write a status code afterwards — an earlier cut of this split hijacked first
	// and turned every pre-handshake failure into a bare EOF, losing "ws connect/handshake failed: curl N" from
	// the Edge's log. RelayWS therefore calls back for the client duplex only once the origin is connected.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}

	var conn net.Conn
	err := RelayWS(req, func() (io.ReadWriter, error) {
		c, bufrw, herr := hj.Hijack()
		if herr != nil {
			return nil, fmt.Errorf("hijack: %w", herr)
		}
		conn = c // recorded so the caller below knows the response was already committed
		if _, werr := bufrw.WriteString("HTTP/1.1 101 Broker-WS\r\n\r\n"); werr != nil {
			return nil, werr
		}
		if ferr := bufrw.Flush(); ferr != nil {
			return nil, ferr
		}
		// Reads come from bufrw (it may already hold bytes pulled off the socket with the request), writes go
		// straight to conn — RelayWS wants one duplex, so pair them.
		return hijackedDuplex{r: bufrw, w: conn}, nil
	})
	if conn != nil {
		conn.Close()
	}
	if err != nil {
		if conn == nil {
			// Nothing was hijacked, so the response is still ours to write: report WHY rather than hanging up.
			http.Error(w, fmt.Sprintf("ws: %v", err), http.StatusBadGateway)
			return
		}
		fmt.Fprintf(os.Stderr, "broker WS relay ended: %v\n", err)
	}
}

// hijackedDuplex pairs the buffered reader (which may hold bytes already pulled off the socket) with the raw
// connection for writes, so the relay core sees one io.ReadWriter.
type hijackedDuplex struct {
	r io.Reader
	w io.Writer
}

func (d hijackedDuplex) Read(p []byte) (int, error)  { return d.r.Read(p) }
func (d hijackedDuplex) Write(p []byte) (int, error) { return d.w.Write(p) }

// RelayWS opens a WebSocket to req.URL through the real Chrome stack and tunnels RAW frame bytes between the
// origin and the client until either side ends.
//
// connectClient is called ONCE, after the origin has accepted the handshake and before any byte is relayed. It
// returns the client duplex, and it is where the host commits its own side of the connection — the HTTP host
// hijacks and writes its 101 there, an in-process host publishes its response. Deferring it this way is what
// keeps a pre-handshake failure reportable: until it runs, the host has written nothing and can still answer
// with a status code.
//
// The duplex is a hijacked connection in the broker binary, and an in-memory pipe when the engine runs inside
// the Edge. An in-memory one must be BUFFERED. A synchronous pipe (net.Pipe) deadlocks here: the single loop
// below blocks writing origin→client, stops calling curl_ws_recv, and the origin drops the WS when its
// keep-alive PING goes unanswered.
func RelayWS(req Request, connectClient func() (io.ReadWriter, error)) error {
	target := req.URL
	fmt.Fprintf(os.Stderr, "broker WS  %s\n", target)
	// curl wants a ws/wss scheme to drive its WS engine.
	if strings.HasPrefix(target, "https://") {
		target = "wss://" + strings.TrimPrefix(target, "https://")
	} else if strings.HasPrefix(target, "http://") {
		target = "ws://" + strings.TrimPrefix(target, "http://")
	}

	h := C.be_init()
	if h == nil {
		return fmt.Errorf("curl init failed")
	}
	defer C.be_cleanup(h)

	prof := C.CString(impersonateTarget())
	rc := C.be_impersonate(h, prof)
	C.free(unsafe.Pointer(prof))
	if rc != C.CURLE_OK {
		return fmt.Errorf("impersonate failed: curl %d", int(rc))
	}

	cURL := C.CString(target)
	C.be_setstr(h, C.CURLOPT_URL, cURL)
	C.free(unsafe.Pointer(cURL))
	C.be_setlong(h, C.CURLOPT_CONNECT_ONLY, 2) // WebSocket connect-only
	if rawrc := C.be_ws_raw(h); rawrc != C.CURLE_OK {
		fmt.Fprintf(os.Stderr, "ws-diag: CURLWS_RAW_MODE setopt FAILED rc=%d (curl unframes -> need manual framing)\n", int(rawrc))
	} else {
		fmt.Fprintf(os.Stderr, "ws-diag: CURLWS_RAW_MODE set ok\n")
	}
	C.be_setlong(h, C.CURLOPT_SSL_VERIFYPEER, 1)
	C.be_setlong(h, C.CURLOPT_SSL_VERIFYHOST, 2)
	C.be_setcb_prereq(h) // peer check before the handshake request goes out (see SetPeerGuard)

	// Carry the Edge-authored request headers (cookies, sec-ch-*, referer, …) on the handshake; skip the WS
	// control headers curl generates itself. impersonate(…, 1) already set Chrome's default header set/order.
	var slist *C.struct_curl_slist
	for _, hv := range req.HeaderLines {
		lname := strings.ToLower(strings.TrimSpace(hv))
		if strings.HasPrefix(lname, "upgrade:") || strings.HasPrefix(lname, "connection:") ||
			strings.HasPrefix(lname, "sec-websocket-key:") || strings.HasPrefix(lname, "sec-websocket-version:") ||
			strings.HasPrefix(lname, "sec-websocket-extensions:") || strings.HasPrefix(lname, "host:") {
			continue
		}
		cs := C.CString(hv)
		slist = C.be_slist_append(slist, cs)
		C.free(unsafe.Pointer(cs))
	}
	if slist != nil {
		C.be_setptr(h, C.CURLOPT_HTTPHEADER, unsafe.Pointer(slist))
		defer C.be_slist_free(slist)
	}

	if rc := C.be_perform(h); rc != C.CURLE_OK {
		return fmt.Errorf("ws connect/handshake failed: curl %d", int(rc))
	}
	sock := int(C.be_activesocket(h))
	fmt.Fprintf(os.Stderr, "ws-diag: handshake ok, tunneling raw frames (sock=%d)\n", sock)

	// The origin accepted us. Only now may the host commit its side — a 101 (or an in-process response) written
	// before this point would promise a tunnel that does not exist.
	client, cerr := connectClient()
	if cerr != nil {
		return fmt.Errorf("client handshake: %w", cerr)
	}

	// A TLS handle is NOT safe for concurrent send+recv (one BoringSSL SSL*), so ALL curl_ws_* calls run in the
	// single loop below. The reader goroutine only pulls client->origin bytes off the client duplex into a channel,
	// and pokes a self-pipe so the loop wakes IMMEDIATELY on new client data (a slow PONG to the origin's keep-alive
	// PING makes the origin drop the WS — the abrupt recv0 we observed). No busy-poll, near-zero relay latency.
	wakeR, wakeW, _ := os.Pipe()
	if wakeR != nil {
		defer wakeR.Close()
		defer wakeW.Close()
	}
	wakeFd := -1
	if wakeR != nil {
		wakeFd = int(wakeR.Fd())
	}
	clientData := make(chan []byte, 64)
	go func() {
		defer close(clientData)
		buf := make([]byte, 32*1024)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				clientData <- b
				if wakeW != nil {
					_, _ = wakeW.Write([]byte{0})
				}
			}
			if err != nil {
				return
			}
		}
	}()

	var pending []byte
	var c2o, o2c int64
	reason := "?"
	readerOpen := true
	defer func() {
		fmt.Fprintf(os.Stderr, "ws-done: client->origin=%d origin->client=%d reason=%s\n", c2o, o2c, reason)
	}()
	rbuf := make([]byte, 32*1024)
	for {
		if pending == nil && readerOpen {
			select {
			case b, ok := <-clientData:
				if !ok {
					readerOpen = false
				} else {
					pending = b
				}
			default:
			}
		}
		progressed := false
		if len(pending) > 0 {
			var sent C.size_t
			sc := C.be_ws_send(h, unsafe.Pointer(&pending[0]), C.size_t(len(pending)), &sent)
			if sc == C.CURLE_OK {
				c2o += int64(sent)
				pending = pending[int(sent):]
				if len(pending) == 0 {
					pending = nil
				}
				progressed = true
			} else if sc != C.CURLE_AGAIN {
				reason = fmt.Sprintf("send_err=%d", int(sc))
				return nil
			}
		}
		var got C.size_t
		rc := C.be_ws_recv(h, unsafe.Pointer(&rbuf[0]), C.size_t(len(rbuf)), &got)
		if rc == C.CURLE_OK {
			if got == 0 {
				reason = "origin_closed(recv0)"
				return nil // origin closed, normal teardown
			}
			// Diagnostic: if the origin sends a WS CLOSE control frame (opcode 0x8), log its close code + reason so
			// we learn WHY the origin tears the WS down (1000 normal / 1008 policy / 1011 server / etc.).
			if got >= 2 && rbuf[0]&0x0f == 0x8 {
				plen := int(rbuf[1] & 0x7f)
				if plen >= 2 && int(got) >= 2+2 {
					code := int(rbuf[2])<<8 | int(rbuf[3])
					rsn := ""
					if int(got) > 4 {
						rsn = string(rbuf[4:int(got)])
						if len(rsn) > 60 {
							rsn = rsn[:60]
						}
					}
					fmt.Fprintf(os.Stderr, "ws-origin-CLOSE code=%d reason=%q\n", code, rsn)
				}
			}
			if _, werr := client.Write(rbuf[:int(got)]); werr != nil {
				reason = "client_write_err"
				return nil
			}
			o2c += int64(got)
			progressed = true
		} else if rc != C.CURLE_AGAIN {
			reason = fmt.Sprintf("recv_err=%d", int(rc))
			return nil
		}
		if !readerOpen && pending == nil {
			// the Edge closed the client half (browser gone). Nothing more to send; the origin->client side will
			// end when the origin closes or the recv errors above.
			_ = reason
		}
		if progressed {
			continue
		}
		// Block until the origin socket is readable (origin frame), the origin socket is writable (a send is
		// pending), OR the wake pipe fires (new client data queued) — whichever first. Zero added latency.
		waitFDs(sock, wakeFd, len(pending) > 0, 30*time.Second)
	}
}

// waitFDs blocks until the origin socket is readable (always), writable (when alsoWrite), or the wake pipe is
// readable (new client data) — up to d. Drains the wake pipe so it re-arms. The syscall.Select/FdSet
// implementation is Linux-shaped (see wait_linux.go); wait_other.go carries a portable stub so the
// package type-checks on non-Linux dev machines (the broker only runs in its Linux container).
