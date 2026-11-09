package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"html"
	"net/http"
)

// writeSWGUpstreamFailure answers a steered request whose upstream could not be reached, in words the person at
// the browser can act on. The raw error is already in the gateway log.
//
// ★★ A SIGN-IN PAGE SHOWED RAW JSON (2026-11-06, measured on a three-region acceptance). The organization
// inspects HTTPS, so the browser's request to its own identity provider went through this gateway, which did
// not trust the provider's private CA and wrote
//
//	{"error":"Get \"https://idp…/auth?client_id=…&state=…\": x509: certificate signed by unknown authority"}
//
// into the window the step-up flow had just opened: a Go error, the full sign-in URL with its parameters, and
// no word about what to do. A certificate failure now says what it is and where an administrator fixes it
// (Certificates → Internal site certificates); a browser gets a page, anything else a JSON sentence.
func writeSWGUpstreamFailure(w http.ResponseWriter, r *http.Request, host string, err error) {
	if !upstreamCertificateVerificationFailed(err) {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	en := host + " presented a certificate this gateway cannot verify: it is not issued by an authority this " +
		"organization trusts, or it does not name " + host + ". If " + host + " is your organization's own " +
		"site with a private certificate authority, an administrator adds that authority's certificate under " +
		"Certificates, Internal site certificates. The detailed error is in the gateway log."
	ja := host + " の証明書を、このゲートウェイで検証できませんでした（この組織が信頼する認証局の発行ではないか、" +
		"名前が " + host + " と合いません）。" + host + " が自社の非公開の認証局を使うサイトなら、管理者が" +
		"「証明書」の「社内サイトの証明書」にその認証局の証明書を足してください。詳しいエラーはゲートウェイの記録にあります。"
	if !acceptsHTMLPage(r) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": en})
		return
	}
	title, body := "This site's certificate could not be verified", en
	if ceremonyLanguage(r) == "ja" {
		title, body = "このサイトの証明書を検証できません", ja
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" " +
		"content=\"width=device-width, initial-scale=1\"><title>" + html.EscapeString(title) + "</title></head>" +
		"<body style=\"font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px;line-height:1.6\">" +
		"<h1 style=\"font-size:20px\">" + html.EscapeString(title) + "</h1><p>" + html.EscapeString(body) + "</p></body></html>"))
}

// upstreamCertificateVerificationFailed says whether the upstream's certificate failed verification, by the error's
// TYPE only.
//
// ★ NOT BY ITS TEXT (2026-11-06). The egress classifier falls back to searching err.Error(), and
// a *url.Error's text carries the URL: the same "tls: handshake failure" read as a certificate error when the
// path happened to contain the word, and this page then told the person to register an authority for a failure
// that had nothing to do with one. errors.As unwraps the *url.Error, so only a verification error decides it.
func upstreamCertificateVerificationFailed(err error) bool {
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &verification) || errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) || errors.As(err, &invalid)
}
