package engine

/*
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

extern size_t brokerWriteCB(char *ptr, size_t size, size_t nmemb, void *userdata);
extern size_t brokerHeaderCB(char *ptr, size_t size, size_t nmemb, void *userdata);
// Pre-request hook: fires once the peer address is known and BEFORE the request is sent, so a refusal costs
// the connection but never leaks the request. Shared by the HTTP and WebSocket paths.
extern int brokerPrereqCB(void *clientp, char *conn_primary_ip, char *conn_local_ip, int primary_port, int local_port);

// CURL/CURLM are opaque; use void* so cgo maps them to unsafe.Pointer.
static void* hc_easy_init(void) { return curl_easy_init(); }
static void hc_easy_cleanup(void *h) { curl_easy_cleanup(h); }
static void hc_easy_reset(void *h) { curl_easy_reset(h); }
static CURLcode hc_setstr(void *h, CURLoption o, const char *v) { return curl_easy_setopt(h, o, v); }
static CURLcode hc_setlong(void *h, CURLoption o, long v) { return curl_easy_setopt(h, o, v); }
static CURLcode hc_setptr(void *h, CURLoption o, void *v) { return curl_easy_setopt(h, o, v); }
static CURLcode hc_setcb_write(void *h) { return curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, brokerWriteCB); }
static CURLcode hc_setcb_header(void *h) { return curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, brokerHeaderCB); }
static CURLcode hc_setcb_prereq(void *h) { return curl_easy_setopt(h, CURLOPT_PREREQFUNCTION, brokerPrereqCB); }
// Set the request body from a known-length buffer. curl COPIES it and manages Content-Length itself (no chunked
// upload) — many origins (Amazon) reject the chunked Transfer-Encoding that CURLOPT_UPLOAD would otherwise use.
static CURLcode hc_set_body(void *h, const void *data, long len) {
	curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, len);
	return curl_easy_setopt(h, CURLOPT_COPYPOSTFIELDS, data);
}
static CURLcode hc_pause_cont(void *h) { return curl_easy_pause(h, CURLPAUSE_CONT); }
static void hc_set_private(void *h, void *p) { curl_easy_setopt(h, CURLOPT_PRIVATE, p); }
static size_t hc_write_pause(void) { return CURL_WRITEFUNC_PAUSE; }

extern CURLcode curl_easy_impersonate(void *data, const char *target, int default_headers);
static CURLcode hc_impersonate(void *h, const char *t) { return curl_easy_impersonate(h, t, 1); }
// curl_easy_impersonate(...,1) enables CURLOPT_ACCEPT_ENCODING, which makes curl AUTO-DECODE the response body and
// STRIP Content-Encoding + Content-Length. Set it back to NULL so curl does NOT decode: the origin's compressed
// body + Content-Encoding + Content-Length pass through verbatim and the browser decodes — exactly like the
// browseregress engine. (Delivering a decoded body with no Content-Encoding/Content-Length is what Chrome rejected
// for Amazon's getAsins XHR -> stuck skeleton.) The client's real Accept-Encoding is still sent (forwarded header).
static CURLcode hc_no_decode(void *h) { return curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, (char*)0); }

static struct curl_slist* hc_slist_append(struct curl_slist *l, const char *s) { return curl_slist_append(l, s); }
static void hc_slist_free(struct curl_slist *l) { curl_slist_free_all(l); }

// --- curl_multi: single event loop multiplexing all transfers (h2 streams share one conn per host, like Chrome) ---
static void* hc_multi_init(void) {
	CURLM *m = curl_multi_init();
	if (m) {
		// h2 stream multiplexing: curl reuses one connection per host and multiplexes streams onto it (Chrome-like)
		// when the origin speaks h2. We deliberately do NOT pin MAX_HOST_CONNECTIONS=1: unlike fhttp's h2 transport,
		// curl_multi with a hard 1-connection cap STALLS every request to a host while its single connection is
		// mid-GOAWAY/reconnect, which backs up the Edge and makes the browser reset its shared h2 connection —
		// failing dozens of streams at once. curl's default connection management already prefers multiplex + reuse
		// and avoids the connection storm; the retry loop below handles GOAWAY recycles.
		curl_multi_setopt(m, CURLMOPT_PIPELINING, (long)CURLPIPE_MULTIPLEX);
		// LEAK FIX: 0 (unlimited) let curl's connection cache grow without bound, so idle upstream connections
		// that the origin later closed (FIN) lingered in CLOSE_WAIT forever — curl only discards a dead cached
		// connection when it REUSES that host, so conns to one-off hosts leaked (24 CLOSE_WAIT accumulated over a
		// 3-day uptime; unbounded under diverse egress → FD/memory creep). A FINITE cap makes curl LRU-PRUNE the
		// least-recently-used idle connection (including a dead CLOSE_WAIT one) whenever the cache is full, so the
		// idle-conn set is bounded and dead conns are reaped. This is the TOTAL-connections cap; it does NOT
		// reintroduce the per-host stall the comment above warns about (that was MAX_HOST_CONNECTIONS=1 — h2 still
		// multiplexes many streams over one conn). Also bound the reuse cache directly and cap idle-conn age so a
		// stale keepalive is not reused. 256 total is generous for h2-multiplexed egress; tune by real fleet load.
		curl_multi_setopt(m, CURLMOPT_MAX_TOTAL_CONNECTIONS, 256L);
		curl_multi_setopt(m, CURLMOPT_MAXCONNECTS, 256L);
	}
	return m;
}
static CURLMcode hc_multi_add(void *m, void *e) { return curl_multi_add_handle(m, e); }
static CURLMcode hc_multi_remove(void *m, void *e) { return curl_multi_remove_handle(m, e); }
static CURLMcode hc_multi_perform(void *m, int *running) { return curl_multi_perform(m, running); }
static CURLMcode hc_multi_poll(void *m, int timeout_ms) { int n; return curl_multi_poll(m, NULL, 0, timeout_ms, &n); }
static CURLMcode hc_multi_wakeup(void *m) { return curl_multi_wakeup(m); }
// Return the next completed easy handle + its result, or NULL when none remain this drain.
static void* hc_multi_next_done(void *m, CURLcode *result) {
	int q;
	CURLMsg *msg;
	while ((msg = curl_multi_info_read(m, &q))) {
		if (msg->msg == CURLMSG_DONE) { *result = msg->data.result; return msg->easy_handle; }
	}
	return NULL;
}
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/cgo"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/net/http/httpguts"
)

const maxBufferedPerReq = 256 * 1024 // pause a transfer if the client hasn't drained this many bytes

// xfer is one in-flight request through the multi loop. The write/header callbacks (run on the loop thread) feed
// buf; the request goroutine drains buf to the ResponseWriter. Backpressure: when buf exceeds the cap the write
// callback returns CURL_WRITEFUNC_PAUSE; the drainer unpauses (via the loop) once it has read the bytes. Buffers
// are Go copies, so the easy handle can be recycled independently of draining.
type xfer struct {
	easy   unsafe.Pointer
	rs     *reqState
	mu     sync.Mutex
	buf    [][]byte
	buffed int
	paused bool
	fin    bool
	result C.CURLcode
	notify chan struct{} // signals the drainer that buf grew or fin was set
}

func (x *xfer) signal() {
	select {
	case x.notify <- struct{}{}:
	default:
	}
}

// multiEngine owns the CURLM and its single loop goroutine. All curl_multi_* / curl_easy_pause / add / remove calls
// happen ONLY on the loop goroutine; other goroutines communicate via queues + curl_multi_wakeup.
type multiEngine struct {
	multi   unsafe.Pointer
	prof    string
	mu      sync.Mutex
	addQ    []*xfer
	resumeQ []unsafe.Pointer
	cancelQ []unsafe.Pointer
	live    map[unsafe.Pointer]*xfer
	poolMu  sync.Mutex
	pool    []unsafe.Pointer
}

// Shard the multi loops BY HOST: a single loop bottlenecks (p90 ~2.3s at 100 concurrent), so Amazon's getAsins
// queues behind the image storm and the browser times it out -> skeleton. Round-robin sharding fixed the bottleneck
// but broke connection reuse (cold engines). Hashing by HOST gives each origin a STABLE engine — its connections
// stay warm/reused on its own loop — while spreading DIFFERENT hosts (the page host vs the image CDN) across
// separate loops/threads, so getAsins's host isn't stuck behind the CDN's image traffic.
const numEngines = 8

var (
	enginesOnce sync.Once
	engines     []*multiEngine
)

func initEngines() {
	enginesOnce.Do(func() {
		engines = make([]*multiEngine, numEngines)
		for i := range engines {
			engines[i] = &multiEngine{
				multi: unsafe.Pointer(C.hc_multi_init()),
				prof:  impersonateTarget(),
				live:  map[unsafe.Pointer]*xfer{},
			}
			go engines[i].loop()
		}
	})
}

// engineForHost returns a stable engine for a host (FNV-1a) — same host -> same loop -> warm connection reuse.
func engineForHost(host string) *multiEngine {
	initEngines()
	var h uint32 = 2166136261
	for i := 0; i < len(host); i++ {
		h ^= uint32(host[i])
		h *= 16777619
	}
	return engines[h%numEngines]
}

func (e *multiEngine) acquire() unsafe.Pointer {
	e.poolMu.Lock()
	if n := len(e.pool); n > 0 {
		h := e.pool[n-1]
		e.pool = e.pool[:n-1]
		e.poolMu.Unlock()
		C.hc_easy_reset(h)
		return h
	}
	e.poolMu.Unlock()
	return unsafe.Pointer(C.hc_easy_init())
}

func (e *multiEngine) release(h unsafe.Pointer) {
	e.poolMu.Lock()
	if len(e.pool) < 256 {
		e.pool = append(e.pool, h)
		e.poolMu.Unlock()
		return
	}
	e.poolMu.Unlock()
	C.hc_easy_cleanup(h)
}

// submit hands a configured easy handle to the loop; returns after the loop registers it.
func (e *multiEngine) submit(x *xfer) {
	e.mu.Lock()
	e.addQ = append(e.addQ, x)
	e.mu.Unlock()
	C.hc_multi_wakeup(e.multi)
}

func (e *multiEngine) requestResume(easy unsafe.Pointer) {
	e.mu.Lock()
	e.resumeQ = append(e.resumeQ, easy)
	e.mu.Unlock()
	C.hc_multi_wakeup(e.multi)
}

func (e *multiEngine) requestCancel(easy unsafe.Pointer) {
	e.mu.Lock()
	e.cancelQ = append(e.cancelQ, easy)
	e.mu.Unlock()
	C.hc_multi_wakeup(e.multi)
}

// loop is the single thread driving all transfers.
func (e *multiEngine) loop() {
	for {
		// drain queued adds / resumes / cancels (all curl_multi/easy mutation on this thread)
		e.mu.Lock()
		adds := e.addQ
		e.addQ = nil
		resumes := e.resumeQ
		e.resumeQ = nil
		cancels := e.cancelQ
		e.cancelQ = nil
		e.mu.Unlock()

		for _, x := range adds {
			e.live[x.easy] = x
			C.hc_multi_add(e.multi, x.easy)
		}
		for _, h := range resumes {
			if _, ok := e.live[h]; ok {
				C.hc_pause_cont(h)
			}
		}
		for _, h := range cancels {
			if x, ok := e.live[h]; ok {
				C.hc_multi_remove(e.multi, h)
				delete(e.live, h)
				x.mu.Lock()
				x.fin = true
				x.result = C.CURLE_ABORTED_BY_CALLBACK
				x.mu.Unlock()
				x.signal()
			}
		}

		var running C.int
		C.hc_multi_perform(e.multi, &running)

		// reap completed transfers
		for {
			var res C.CURLcode
			h := C.hc_multi_next_done(e.multi, &res)
			if h == nil {
				break
			}
			if x, ok := e.live[h]; ok {
				C.hc_multi_remove(e.multi, h)
				delete(e.live, h)
				x.mu.Lock()
				x.fin = true
				x.result = res
				x.mu.Unlock()
				x.signal()
			}
		}

		// wait for socket activity or a wakeup (100ms cap so queued work is picked up promptly)
		C.hc_multi_poll(e.multi, 100)
	}
}

// reqState accumulates response head + streams body via the write callback.
type reqState struct {
	w             http.ResponseWriter
	flusher       http.Flusher
	headers       http.Header
	wroteHead     bool
	statusCode    int
	contentLength int64 // from the origin's Content-Length header; -1 if absent (streaming/chunked)
	x             *xfer // set before start so callbacks reach the xfer
}

// maxBufferableResponse caps how large a finite (Content-Length) response we buffer in the broker before relaying.
// Buffering lets a mid-stream connection error be RETRIED cleanly instead of delivering a TRUNCATED body — the bug
// behind Amazon getAsins failing (69.6 KB of a 100 KB response reached the browser, Content-Length mismatch ->
// net::ERR_FAILED -> stuck skeleton). Responses larger than this, or with no Content-Length (SSE / token streams),
// still stream incrementally so real-time output is not delayed.
const maxBufferableResponse = 8 << 20 // 8 MiB

func (rs *reqState) ensureHead() {
	if rs.wroteHead {
		return
	}
	rs.wroteHead = true
	for k, vs := range rs.headers {
		for _, v := range vs {
			rs.w.Header().Add(k, v)
		}
	}
	if rs.statusCode == 0 {
		rs.statusCode = http.StatusBadGateway
	}
	rs.w.WriteHeader(rs.statusCode)
}

// brokerPrereqCB is libcurl's pre-request hook: it runs after the connection is established and before the
// request is written, which is the only moment the ACTUAL peer address is known and nothing has leaked yet.
// Aborting here costs a TCP connection to an address we refuse to talk to — the request itself, with its
// cookies and headers, is never sent.
//
//export brokerPrereqCB
func brokerPrereqCB(clientp unsafe.Pointer, primaryIP *C.char, localIP *C.char, primaryPort C.int, localPort C.int) C.int {
	ip := C.GoString(primaryIP)
	if err := checkPeer(ip); err != nil {
		log.Printf("egress engine: refused connection to %s — %v", ip, err)
		return C.int(C.CURL_PREREQFUNC_ABORT)
	}
	return C.int(C.CURL_PREREQFUNC_OK)
}

//export brokerWriteCB
func brokerWriteCB(ptr *C.char, size C.size_t, nmemb C.size_t, userdata unsafe.Pointer) C.size_t {
	n := int(size * nmemb)
	x := cgo.Handle(userdata).Value().(*xfer)
	x.mu.Lock()
	// If the client hasn't drained enough yet, PAUSE WITHOUT consuming this chunk. libcurl holds it and re-offers
	// the exact same bytes after CURLPAUSE_CONT — so we must NOT buffer it here, or it would be delivered twice
	// (which corrupted large responses: YouTube/Amazon docs failed while small ones, never hitting pause, worked).
	if x.buffed >= maxBufferedPerReq {
		x.paused = true
		x.mu.Unlock()
		x.signal()
		return C.hc_write_pause()
	}
	x.buf = append(x.buf, C.GoBytes(unsafe.Pointer(ptr), C.int(n)))
	x.buffed += n
	x.mu.Unlock()
	x.signal()
	return C.size_t(n)
}

//export brokerHeaderCB
func brokerHeaderCB(ptr *C.char, size C.size_t, nmemb C.size_t, userdata unsafe.Pointer) C.size_t {
	n := int(size * nmemb)
	x := cgo.Handle(userdata).Value().(*xfer)
	rs := x.rs
	line := strings.TrimRight(C.GoStringN(ptr, C.int(n)), "\r\n")
	if line == "" {
		return C.size_t(n)
	}
	if strings.HasPrefix(line, "HTTP/") {
		rs.headers = http.Header{}
		if parts := strings.SplitN(line, " ", 3); len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &rs.statusCode)
		}
		return C.size_t(n)
	}
	if i := strings.Index(line, ":"); i > 0 {
		name := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		// Drop hop-by-hop / connection-specific headers. HTTP/2 FORBIDS these, so if the origin's response carries
		// e.g. "Connection: keep-alive" and we let the Edge relay it over its h2 connection to the browser, the
		// browser resets that stream (RST_STREAM) -> the XHR fails with ERR_FAILED while sibling streams work. This
		// was intermittent because only some backend responses (e.g. Amazon's infinite-scroll getAsins) include
		// them. (Content-Encoding + Content-Length are kept: we pass the compressed body through and the browser
		// decodes; curl already de-chunked, so Transfer-Encoding must go.)
		switch {
		case strings.EqualFold(name, "Connection"), strings.EqualFold(name, "Keep-Alive"),
			strings.EqualFold(name, "Proxy-Connection"), strings.EqualFold(name, "Transfer-Encoding"),
			strings.EqualFold(name, "TE"), strings.EqualFold(name, "Trailer"),
			strings.EqualFold(name, "Upgrade"):
			return C.size_t(n)
		}
		// Drop any header whose name/value is invalid for HTTP/2. If the Edge relays such a header over its h2
		// connection to the browser, Go's h2 writer errors the whole CONNECTION (GOAWAY) — killing every in-flight
		// stream at once (observed: a cluster of getAsins + image requests failing together with ERR_FAILED /
		// ERR_INTERNET_DISCONNECTED). Skipping the offending header keeps the connection healthy.
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(val) {
			return C.size_t(n)
		}
		if strings.EqualFold(name, "Content-Length") {
			if cl, err := strconv.ParseInt(val, 10, 64); err == nil {
				rs.contentLength = cl
			}
		}
		rs.headers.Add(name, val)
	}
	return C.size_t(n)
}

// hostOf extracts the host[:port] from an absolute URL for engine sharding.
func hostOf(rawurl string) string {
	s := rawurl
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

// curlRetryable reports whether a curl result is a transient connection-recycle error worth retrying on a fresh
// connection (the origin sent a graceful GOAWAY / reset the h2 stream). Mirrors the fhttp fix 3221d4ca #3.
func curlRetryable(res C.CURLcode) bool {
	switch res {
	case C.CURLE_HTTP2, C.CURLE_HTTP2_STREAM, C.CURLE_RECV_ERROR, C.CURLE_SEND_ERROR,
		C.CURLE_PARTIAL_FILE, C.CURLE_GOT_NOTHING, C.CURLE_SSL_CONNECT_ERROR:
		return true
	}
	return false
}

// Request is the fully-decided origin request the engine re-originates: the Edge has already terminated the
// client TLS, inspected, applied policy and authored the final header set. The engine adds no security logic
// and makes no decisions — it emits what it is given through a real Chrome stack.
//
// HeaderLines are raw "Name: value" lines. Their ORDER does not need to be Chrome's: curl_easy_impersonate
// installs the profile's header set and order, and a supplied line whose name is already in the profile
// REPLACES it in place rather than moving it. Measured 2026-08-05 against a header-order sink: supplying
// User-Agent and Accept-Language left both in their Chrome positions, and only a name absent from the profile
// (Cookie) appended at the end. So the engine, not the caller, is what makes the order Chrome-shaped.
type Request struct {
	Method      string
	URL         string
	HeaderLines []string
	Body        []byte
}

// ReoriginateHTTP is the HTTP host for the engine: it decodes the X-Reorig-* wire form the broker binary is
// called with, then hands off to Reoriginate. An in-process host (the Edge, when the broker is embedded)
// builds a Request directly and skips this decoding entirely — same engine, no serialization.
func ReoriginateHTTP(w http.ResponseWriter, r *http.Request) {
	req := Request{
		Method: firstNonEmpty(r.Header.Get("X-Reorig-Method"), r.Method),
		URL:    r.Header.Get("X-Reorig-URL"),
	}
	if req.URL == "" {
		http.Error(w, "missing X-Reorig-URL", http.StatusBadRequest)
		return
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		req.Body, _ = io.ReadAll(r.Body)
	}
	// curl owns Content-Length/Transfer-Encoding for the body it sends; drop the client's to avoid a duplicate
	// Content-Length (the Akamai-loop class of defect). Drop Expect so curl doesn't wait on 100.
	for _, hv := range r.Header.Values("X-Reorig-Header") {
		lname := strings.ToLower(strings.TrimSpace(hv))
		if strings.HasPrefix(lname, "content-length:") || strings.HasPrefix(lname, "transfer-encoding:") ||
			strings.HasPrefix(lname, "expect:") {
			continue
		}
		req.HeaderLines = append(req.HeaderLines, hv)
	}
	Reoriginate(w, r.Context(), req)
}

// Reoriginate re-issues the request through the multi loop and streams the response into w, retrying a request
// that fails on a recycled connection BEFORE any response byte was written (fhttp fix 3221d4ca #3).
//
// w carries the response: Header/WriteHeader/Write, plus Flush when it implements http.Flusher (streaming is
// how a token stream stays real-time). That is the whole of the sink contract, which is why an in-process host
// can supply a pipe-backed ResponseWriter instead of a real one.
func Reoriginate(w http.ResponseWriter, reqCtx context.Context, req Request) {
	method, target, body := req.Method, req.URL, req.Body
	e := engineForHost(hostOf(target))

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		h := e.acquire()
		rs := &reqState{w: w, headers: http.Header{}, contentLength: -1}
		rs.flusher, _ = w.(http.Flusher)
		x := &xfer{easy: h, rs: rs, notify: make(chan struct{}, 1)}
		rs.x = x
		hx := cgo.NewHandle(x)

		prof := C.CString(e.prof)
		rc := C.hc_impersonate(h, prof)
		C.free(unsafe.Pointer(prof))
		if rc != C.CURLE_OK {
			hx.Delete()
			e.release(h)
			http.Error(w, fmt.Sprintf("impersonate failed: %d", int(rc)), http.StatusBadGateway)
			return
		}
		C.hc_no_decode(h) // pass the origin's compressed body + Content-Encoding/Length through (match browseregress)

		cURL := C.CString(target)
		C.hc_setstr(h, C.CURLOPT_URL, cURL)
		C.free(unsafe.Pointer(cURL))
		cMethod := C.CString(method)
		C.hc_setstr(h, C.CURLOPT_CUSTOMREQUEST, cMethod)
		C.free(unsafe.Pointer(cMethod))
		// Deliberately DO NOT set CURLOPT_ACCEPT_ENCODING: pass the origin's compressed body + Content-Encoding +
		// Content-Length through verbatim (the browser decodes). Preserves response framing so the Edge uses its
		// buffered keep-alive relay path (matching browseregress).
		C.hc_setlong(h, C.CURLOPT_FOLLOWLOCATION, 0)
		C.hc_setlong(h, C.CURLOPT_SSL_VERIFYPEER, 1)
		C.hc_setlong(h, C.CURLOPT_SSL_VERIFYHOST, 2)
		// Supply the AIA-learned links (aia.go) when there are any. Empty until a chase has actually succeeded,
		// so a deployment that never needs one runs on curl's own default bundle exactly as before.
		if ca := aiaStore.caInfo(); ca != "" {
			cCA := C.CString(ca)
			C.hc_setstr(h, C.CURLOPT_CAINFO, cCA)
			C.free(unsafe.Pointer(cCA))
		}
		C.hc_setlong(h, C.CURLOPT_PATH_AS_IS, 1)
		if body != nil {
			if len(body) > 0 {
				C.hc_set_body(h, unsafe.Pointer(&body[0]), C.long(len(body)))
			} else {
				C.hc_set_body(h, nil, 0)
			}
		}

		var slist *C.struct_curl_slist
		for _, hv := range req.HeaderLines {
			cs := C.CString(hv)
			slist = C.hc_slist_append(slist, cs)
			C.free(unsafe.Pointer(cs))
		}
		if slist != nil {
			C.hc_setptr(h, C.CURLOPT_HTTPHEADER, unsafe.Pointer(slist))
		}

		C.hc_setptr(h, C.CURLOPT_WRITEDATA, unsafe.Pointer(hx))
		C.hc_setcb_prereq(h) // peer check before the request goes out (see SetPeerGuard)
		C.hc_setcb_write(h)
		C.hc_setptr(h, C.CURLOPT_HEADERDATA, unsafe.Pointer(hx))
		C.hc_setcb_header(h)
		C.hc_set_private(h, unsafe.Pointer(hx))

		e.submit(x)

		clientGone := false
		ctx := reqCtx
		// Buffering: accumulate the body in the broker WITHOUT writing to the client so a mid-stream connection error
		// retries cleanly (wroteHead stays false) instead of delivering a TRUNCATED body — the getAsins bug. Most
		// origin responses have NO Content-Length (chunked), so we cannot rely on it; instead buffer by DEFAULT and
		// detect a real-time stream (SSE / AI token stream) by an IDLE GAP: a finite response downloads its body
		// continuously, a token stream dribbles with pauses. On the first gap (or when the buffer exceeds the cap) we
		// flush what we have and switch to incremental streaming, so real-time output is never held back.
		const holdGap = 300 * time.Millisecond
		var pending [][]byte
		pendingLen := 0
		buffering := false
		sawData := false
		flushPending := func() bool { // relay buffered bytes now; returns false if the client is gone
			rs.ensureHead()
			for _, c := range pending {
				if _, err := w.Write(c); err != nil {
					return false
				}
			}
			pending = nil
			if rs.flusher != nil {
				rs.flusher.Flush()
			}
			return true
		}
		for {
			x.mu.Lock()
			chunks := x.buf
			x.buf = nil
			x.buffed = 0
			wasPaused := x.paused
			x.paused = false
			fin := x.fin
			x.mu.Unlock()

			if len(chunks) > 0 && !sawData {
				sawData = true
				// Buffer by default so a mid-stream error can retry cleanly (the getAsins fix) — EXCEPT a
				// real-time token stream, which must stream from the first byte. The idle-gap heuristic below
				// only reverts to streaming after a >holdGap (300ms) pause; a DENSE token stream dribbles faster
				// than that, so it would stay buffered until the response completes — and an SSE stream never
				// completes, so the client receives nothing and times out (#28: the ChatGPT app). An explicit
				// text/event-stream content type is the reliable signal the gap heuristic misses.
				ct := strings.ToLower(strings.TrimSpace(rs.headers.Get("Content-Type")))
				buffering = !strings.HasPrefix(ct, "text/event-stream")
			}

			if buffering {
				pending = append(pending, chunks...)
				for _, c := range chunks {
					pendingLen += len(c)
				}
				if pendingLen > maxBufferableResponse { // too big to hold — flush and stream the rest
					buffering = false
					if !flushPending() {
						e.requestCancel(h)
						e.waitFin(x)
						clientGone = true
					}
				}
			} else {
				for _, c := range chunks {
					rs.ensureHead()
					if _, err := w.Write(c); err != nil {
						e.requestCancel(h)
						e.waitFin(x)
						clientGone = true
						break
					}
					if rs.flusher != nil {
						rs.flusher.Flush()
					}
				}
			}
			if clientGone {
				break
			}
			if wasPaused && !fin {
				e.requestResume(h)
			}
			if fin && len(chunks) == 0 {
				break
			}
			if len(chunks) == 0 {
				if buffering && sawData {
					select {
					case <-x.notify:
					case <-ctx.Done():
						e.requestCancel(h)
						e.waitFin(x)
						clientGone = true
					case <-time.After(holdGap):
						// Idle gap with no completion -> a real-time stream: flush what we buffered and stream the rest.
						buffering = false
						if !flushPending() {
							e.requestCancel(h)
							e.waitFin(x)
							clientGone = true
						}
					}
				} else {
					select {
					case <-x.notify:
					case <-ctx.Done():
						e.requestCancel(h)
						e.waitFin(x)
						clientGone = true
					}
				}
				if clientGone {
					break
				}
			}
		}

		if slist != nil {
			C.hc_slist_free(slist)
		}
		hx.Delete()
		e.release(h)

		if clientGone {
			return
		}
		// Retry a connection-recycle failure only if nothing was written to the client yet and attempts remain. In
		// buffering mode NOTHING is written until curl finishes, so a mid-stream error (retryable) lands here with
		// wroteHead==false and retries the whole request — the truncated body never reaches the browser.
		if curlRetryable(x.result) && !rs.wroteHead && attempt < maxAttempts-1 {
			continue
		}
		// Peer verification failed. Before giving up, do what a browser does and chase the issuer the origin did
		// not send (aia.go); retry only if that actually learned a new link. A verification failure is also the
		// one curl result that used to reach the operator through nothing but the 502 body a user happened to
		// see, so it is said out loud here regardless of whether the chase helps.
		if x.result == C.CURLE_PEER_FAILED_VERIFICATION && !rs.wroteHead {
			log.Printf("egress engine: peer verification FAILED for %s (curl %d) — the origin's chain does not verify against the CA bundle", hostOf(target), int(x.result))
			if attempt < maxAttempts-1 && aiaStore.learnFor(target) {
				continue
			}
		}
		if buffering && x.result == C.CURLE_OK {
			// Finite body fully buffered intact. Synthesize Content-Length (the origin sent none — chunked) so the
			// Edge relays it via its ROBUST buffered path (io.Copy) instead of the fragile incremental-stream path
			// that was resetting the browser<->Edge stream mid-body for getAsins.
			if rs.headers.Get("Content-Length") == "" {
				rs.headers.Set("Content-Length", strconv.Itoa(pendingLen))
			}
			rs.ensureHead()
			for _, c := range pending {
				if _, err := w.Write(c); err != nil {
					return
				}
			}
			if rs.flusher != nil {
				rs.flusher.Flush()
			}
			return
		}
		if x.result != C.CURLE_OK && !rs.wroteHead {
			http.Error(w, fmt.Sprintf("broker curl error %d", int(x.result)), http.StatusBadGateway)
		} else {
			rs.ensureHead()
		}
		return
	}
}

// waitFin blocks until the loop has marked the xfer finished (so the easy handle is out of the multi and safe to
// recycle) — used on the client-disconnect path.
func (e *multiEngine) waitFin(x *xfer) {
	for {
		x.mu.Lock()
		fin := x.fin
		x.mu.Unlock()
		if fin {
			return
		}
		<-x.notify
	}
}
