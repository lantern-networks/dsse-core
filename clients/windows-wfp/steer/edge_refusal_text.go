package main

// edge_refusal_text.go — when the Edge refuses, say what it said.
//
// ★★★ A NUMBER IS NOT A DIAGNOSIS (2026-08-29, the Mac session's point after losing two round trips to a
// misread error code, measured again here on Windows the same afternoon).
//
// The Edge writes a sentence with every refusal — the routes in cmd/dsse-edge answer
// {"error":"..."} and the sentences are written for the person who will read them. Several callers on this
// client threw that away and logged the status code alone:
//
//	export endpoint returned 403
//	effective-set report: unexpected status 409
//
// 403 is at least four different situations on those routes, and an operator holding the number has to guess
// which, or ask someone with the Edge's log. Certificate renewal already does the right thing
// ("the Edge refused renewal: HTTP %d %s"), so this is the same reading, behind one function so a third caller
// does not have to decide again.
//
// It is deliberately TOLERANT of the body's shape. A refusal that arrives as plain text, as HTML from something
// in front of the Edge, or as nothing at all is still more informative than the number by itself, and a reader
// that only understood one JSON shape would silently go back to printing numbers the day a proxy answered
// instead.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// maxRefusalBodyBytes bounds what is read from a refusal. Enough for a sentence and then some; a body larger
// than this is not an explanation, and reading it into a log line would be its own problem.
const maxRefusalBodyBytes = 8 << 10

// edgeRefusal reads the Edge's own words out of a response and returns "HTTP <code> <what it said>". The body
// is consumed, so callers must not read it afterwards — they are refusing, so there is nothing else to take.
//
// The returned string never contains a newline: these go into single-line logs, and a message that breaks the
// line makes every downstream grep wrong about which record it is looking at.
func edgeRefusal(resp *http.Response) string {
	if resp == nil {
		return "no response"
	}
	code := resp.StatusCode
	said := ""
	if resp.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRefusalBodyBytes))
		if err == nil {
			said = refusalSentence(raw)
		}
	}
	if said == "" {
		return "HTTP " + http.StatusText(code) + statusNumber(code) + " (the Edge sent no explanation)"
	}
	return "HTTP " + http.StatusText(code) + statusNumber(code) + ": " + said
}

func statusNumber(code int) string {
	// The number stays — an operator comparing against the Edge's access log needs it — but it is no longer
	// the whole message.
	return " (" + itoa(code) + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// refusalSentence pulls the human sentence out of whatever the far end sent.
func refusalSentence(raw []byte) string {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return ""
	}
	// The shape every dsse-edge route uses.
	var decoded struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal(raw, &decoded) == nil {
		for _, s := range []string{decoded.Error, decoded.Message, decoded.Detail} {
			if t := strings.TrimSpace(s); t != "" {
				return oneLine(t)
			}
		}
	}
	// Not our JSON: something in front of the Edge answered, or the route wrote plain text. Carry it anyway —
	// "<html>...403 Forbidden..." tells an operator there is a proxy in the path, which the number alone hides.
	return oneLine(text)
}

// oneLine flattens and bounds a message so it cannot break the log record it is placed in.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 400
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
