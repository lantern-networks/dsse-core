package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func resp(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}
}

// ★★★ A NUMBER IS NOT A DIAGNOSIS. 403 is several different situations on these routes, and the Edge writes a
// sentence for every one of them. Two callers were throwing it away and logging the status alone.
func TestARefusalCarriesWhatTheEdgeActuallySaid(t *testing.T) {
	got := edgeRefusal(resp(403, `{"error":"this identity is already enrolled. Replacing its certificate is a renewal"}`))
	if !strings.Contains(got, "already enrolled") {
		t.Fatalf("the Edge's own sentence was dropped: %q", got)
	}
	if !strings.Contains(got, "403") {
		t.Fatalf("the number is still needed to match the Edge's access log: %q", got)
	}
	if !strings.Contains(got, "Forbidden") {
		t.Fatalf("the status name helps a reader who does not carry the table: %q", got)
	}
}

// A refusal that is not our JSON is still worth carrying: "<html>...403..." tells an operator there is a proxy
// in the path, which the number alone hides completely.
func TestARefusalFromSomethingInFrontOfTheEdgeIsStillCarried(t *testing.T) {
	got := edgeRefusal(resp(403, "<html><body><h1>403 Forbidden</h1><p>nginx</p></body></html>"))
	if !strings.Contains(got, "nginx") {
		t.Fatalf("a non-JSON refusal was reduced to a number: %q", got)
	}
}

// An empty body must say that it was empty rather than look like a message that happened to be blank.
func TestASilentRefusalSaysItWasSilent(t *testing.T) {
	got := edgeRefusal(resp(409, ""))
	if !strings.Contains(got, "no explanation") || !strings.Contains(got, "409") {
		t.Fatalf("%q", got)
	}
	if got := edgeRefusal(nil); got != "no response" {
		t.Fatalf("a nil response must not panic or read as a refusal with content: %q", got)
	}
}

// These go into single-line logs. A message that breaks the line makes every downstream reader wrong about
// which record it is looking at, and a body that is not an explanation must not become one.
func TestARefusalNeverBreaksTheLogRecord(t *testing.T) {
	got := edgeRefusal(resp(500, "{\"error\":\"line one\nline two\r\n   and   spaced\"}"))
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("the message broke the log line: %q", got)
	}
	if !strings.Contains(got, "line one line two and spaced") {
		t.Fatalf("flattening lost the words: %q", got)
	}
	long := strings.Repeat("x", 5000)
	if g := edgeRefusal(resp(500, `{"error":"`+long+`"}`)); len(g) > 500 {
		t.Fatalf("an oversized body became the log line (%d chars)", len(g))
	}
}

// The alternative field names the other routes use must be read too, or this quietly goes back to numbers the
// day a route answers with "message" instead of "error".
func TestTheOtherSpellingsOfAnErrorAreRead(t *testing.T) {
	for _, body := range []string{`{"message":"the thing"}`, `{"detail":"the thing"}`} {
		if got := edgeRefusal(resp(400, body)); !strings.Contains(got, "the thing") {
			t.Fatalf("%s -> %q", body, got)
		}
	}
}
