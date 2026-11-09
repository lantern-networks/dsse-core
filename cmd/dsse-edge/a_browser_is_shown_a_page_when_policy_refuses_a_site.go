package main

import (
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// writeSWGPolicyRefusal answers a steered request that policy refused.
//
// ★★ A BLOCKED SITE SHOWED THE DECISION'S JSON (acceptance C, 2026-11-07). Opening a denied site in a browser
// rendered the whole access decision: the English reason, internal identifiers, the user name the decision was
// keyed on and the policy that matched. None of that tells the person what happened or what to do, and the
// identifiers are the deployment's business. A browser now gets a page in its language naming the site, saying
// the organization's policy does not allow it, and giving the time and a reference an administrator can find in
// the log.
//
// ★ AND SO DOES EVERYTHING ELSE (acceptance C, fourth walk, 2026-11-08). A client that is not a browser was still
// handed the whole decision — the organization's id, the user name it was keyed on, the rule that matched and the
// conditions it matched on — and that client is whatever program on the device made the request: a CLI, an SDK,
// an updater, each free to log or report what it receives. It is told what a person is told, as JSON: that the
// request was refused, the generic reason, and the reference that finds the full decision in the log.
func writeSWGPolicyRefusal(w http.ResponseWriter, r *http.Request, host string, dec model.AccessDecision) {
	status := statusForDecision(dec.Decision)
	if !acceptsHTMLPage(r) {
		writeJSON(w, status, swgRefusalForClient(dec))
		return
	}
	when := time.Now().In(organizationZone(dec.TenantID)).Format("2006-01-02 15:04:05 MST")
	title, body, ref := "This site is blocked", "Your organization's policy does not allow access to "+host+
		". If you need it for your work, ask your administrator and give them the time and reference below.",
		"Time: "+when+" · Reference: "+dec.ID
	if ceremonyLanguage(r) == "ja" {
		title = "このサイトはブロックされています"
		body = host + " へのアクセスは、組織のポリシーで許可されていません。業務で必要なときは、下の時刻と参照番号を添えて管理者に問い合わせてください。"
		ref = "時刻：" + when + "　参照番号：" + dec.ID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" " +
		"content=\"width=device-width, initial-scale=1\"><title>" + html.EscapeString(title) + "</title></head>" +
		"<body style=\"font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;line-height:1.6\">" +
		"<h1 style=\"font-size:20px\">" + html.EscapeString(title) + "</h1><p>" + html.EscapeString(body) + "</p>" +
		"<p style=\"color:#555;font-size:14px\">" + html.EscapeString(ref) + "</p></body></html>"))
}

// swgClientRefusal is what a refused client that is not a browser is told. The reference is the decision's id,
// which an administrator searches the log by; everything else about the decision stays in the log.
type swgClientRefusal struct {
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	Reference string `json:"reference"`
}

// swgRefusalForClient reduces a decision to what a program on the device may be told.
//
// ★ THE DECISION'S OWN SENTENCE IS NOT FORWARDED (review of the fourth-walk fixes, 2026-11-08). The first version
// copied dec.Reason, on the belief that the evaluator's sentences were generic. They are not: when no rule
// matches, the evaluator names the nearest rule, the value it requires and the value this request carried — the
// rule's id and two people's identities, written for the administrator's log. A sentence written for an
// administrator is not a sentence for an arbitrary client, so the client gets one fixed sentence per kind of
// decision, with nothing of this request in it, and the reference that finds the full decision in the log.
func swgRefusalForClient(dec model.AccessDecision) swgClientRefusal {
	reason := "Access to this destination was refused by your organization's policy."
	if statusForDecision(dec.Decision) == http.StatusUnauthorized {
		reason = "Your organization's policy requires you to sign in before reaching this destination."
	}
	return swgClientRefusal{Decision: dec.Decision, Reason: reason, Reference: dec.ID}
}

// organizationZone is the zone an organization's own people are told times in — the refusal page, the expiry in
// an invitation — the organization's own, as every screen of the Console shows it (2026-11-08, acceptance C: the
// page said UTC to a person in an organization set to Asia/Tokyo, who then had to convert it before quoting it to
// an administrator). Without a tenant model, or for an organization with no zone set, UTC — named, never the
// host's own zone. Set at startup.
var organizationZone = func(string) *time.Location { return time.UTC }

// acceptsHTMLPage says whether a request asks for an HTML page rather than JSON, reading Accept's media ranges
// and quality values (review R2, 2026-11-08). Finding "text/html" anywhere in the header is not enough: a client
// that sends `application/json, text/html;q=0` has said it will NOT take HTML, and a JSON reader handed a page
// cannot parse the refusal it is owed. HTML is chosen when text/html is acceptable and at least as preferred
// as application/json; a header with neither keeps JSON. Only text/html counts, because that is the type these
// pages are served as: a client preferring application/xhtml+xml while refusing text/html has not accepted them.
func acceptsHTMLPage(r *http.Request) bool {
	htmlQ, jsonQ := -1.0, -1.0
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		fields := strings.Split(part, ";")
		media := strings.ToLower(strings.TrimSpace(fields[0]))
		q := 1.0
		for _, p := range fields[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f >= 0 && f <= 1 {
					q = f
				} else {
					q = 0
				}
			}
		}
		switch media {
		case "text/html":
			if q > htmlQ {
				htmlQ = q
			}
		case "application/json":
			if q > jsonQ {
				jsonQ = q
			}
		}
	}
	return htmlQ > 0 && htmlQ >= jsonQ
}
