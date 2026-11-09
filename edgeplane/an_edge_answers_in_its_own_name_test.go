package edgeplane

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type localAnswerConn struct {
	io.Reader
	io.Writer
}

// Review of the fourth-walk fixes (2026-11-08): the refusal page's request parser accumulated headers without
// limit — a 4 MiB header fed 4 KiB at a time through the 1 MiB flow queue was read in full, because the queue
// bounds what is unread, not what has been read. The parse now stops at the bound http.Server uses.
func TestARefusedRequestsHeadersAreBounded(t *testing.T) {
	input := NewBufferedPipeHalf(muxVirtualConnCap)
	defer input.Close()
	guard := time.AfterFunc(10*time.Second, func() { input.Close() })
	defer guard.Stop()
	sent := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(input, "GET / HTTP/1.1\r\nHost: refused.invalid\r\nX-Pad: "); err != nil {
			sent <- err
			return
		}
		block := bytes.Repeat([]byte{'a'}, 4096)
		for i := 0; i < 1024; i++ { // 4 MiB of one header
			if _, err := input.Write(block); err != nil {
				sent <- err
				return
			}
		}
		_, err := io.WriteString(input, "\r\n\r\n")
		sent <- err
	}()
	answered := false
	err := ServeOneLocalHTTPRequest(localAnswerConn{Reader: input, Writer: io.Discard}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answered = true
		w.WriteHeader(http.StatusForbidden)
	}))
	input.Close()
	<-sent
	if err == nil || answered {
		t.Fatalf("a request whose headers exceed %d bytes was parsed and answered (err=%v)", LocalHTTPRequestMaxHeaderBytes, err)
	}
}

// And a request a browser actually sends is still answered, with its length and closed.
func TestAnOrdinaryRefusedRequestIsAnsweredOnce(t *testing.T) {
	in := strings.NewReader("GET /x HTTP/1.1\r\nHost: refused.invalid\r\nAccept: text/html\r\n\r\n")
	var out bytes.Buffer
	err := ServeOneLocalHTTPRequest(localAnswerConn{Reader: in, Writer: &out}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "<p>refused</p>")
	}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(&out), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || resp.ContentLength != int64(len("<p>refused</p>")) || !resp.Close || string(body) != "<p>refused</p>" {
		t.Fatalf("answer: %d len=%d close=%v body=%q", resp.StatusCode, resp.ContentLength, resp.Close, body)
	}
}
