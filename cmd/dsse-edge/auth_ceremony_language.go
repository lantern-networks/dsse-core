package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"strconv"
	"strings"
)

const ceremonyLanguageCookie = "__Host-dsse_portal_language"

// Presentation only. Never include this preference in grant evidence, browser
// identity, signed authentication requirements, or an IdP callback URL.
var ceremonyJapanese = map[string]string{
	"Unable to complete request":    "処理を完了できません",
	"Upload blocked":                "アップロードがブロックされました",
	"Upload could not be inspected": "アップロードを検査できませんでした",
	"This upload was stopped because inspection could not safely retain its undecided data. Retry later or contact your administrator.": "検査が終わっていないデータを安全に保持できないため、このアップロードを停止しました。時間をおいて再試行するか、管理者にお問い合わせください。",
	"Verification required": "本人確認が必要です",
	"This file could not be inspected (it may be encrypted or corrupted), and your organization requires this destination's uploads to be inspected. Contact your administrator if you believe this is a mistake.": "このファイルを検査できないため、組織のポリシーによりアップロードを停止しました。ファイルが暗号化されているか、破損している可能性があります。お心当たりがない場合は、管理者にお問い合わせください。",
	"Confirm destination":                   "接続先を確認",
	"Your application requested access to:": "アプリから次の接続先へのアクセスが要求されています。",
	"Continue only if you intended to connect to this destination. Your identity provider may use an existing sign-in.": "接続しようとした宛先であることを確認してから進んでください。認証サービスの既存のサインイン情報が使われる場合があります。",
	"Continue to sign in":                             "本人確認へ進む",
	"Continue to your identity provider":              "認証サービスへ移動します",
	"Opening your identity provider.":                 "認証サービスを開いています。",
	"Authentication completed":                        "本人確認が完了しました",
	"You verified with your identity.":                "認証サービスで本人確認が完了しました。",
	"You verified with a phishing-resistant passkey.": "フィッシング耐性のあるパスキーで本人確認しました。",
	"Connecting to":                                   "接続先:",
	"Return to your app. A waiting connection resumes only if current policy permits it. If it has timed out, reconnect. You can close this tab.": "元のアプリへ戻ってください。現在の通信ポリシーで許可されている場合に、待機中の接続が再開します。タイムアウトした場合は、元のアプリから再接続してください。このタブは閉じてかまいません。",
	"Signed in as":                      "サインインしたアカウント:",
	"Retry authentication":              "本人確認をやり直す",
	"Authentication node is restarting": "認証サービスを再起動しています",
	"Reconnect through another node and request a fresh sign-in link.": "元のアプリから再接続し、新しい認証画面を開いてください。",
	"Authentication portal is not configured correctly":                "認証画面の設定を確認する必要があります",
	"Configure an HTTPS origin without a path for the Portal.":         "認証画面へ接続できません。管理者にお問い合わせください。",
	"Sign-in link invalid":                      "この認証リンクは利用できません",
	"Restart authentication with a fresh link.": "元のアプリから接続し直して、新しい認証画面を開いてください。",
	"Return to your terminal and start the connection again to get a fresh sign-in link.": "元のアプリから接続し直して、新しい認証画面を開いてください。",
	"Wrong authentication portal":                                                         "認証画面の接続先が正しくありません",
	"Request a fresh link from your app.":                                                 "元のアプリから接続し直して、新しい認証画面を開いてください。",
	"Invalid authentication destination":                                                  "接続先を確認できません",
	"Start authentication from the application request.":                                  "元のアプリから接続し直して、本人確認を開始してください。",
	"Sign-in link expired":                                                                "認証リンクの有効期限が切れました",
	"Return to your app and request a fresh sign-in link.":                                "元のアプリから接続し直して、新しい認証画面を開いてください。",
	"Invalid binding":                                                                     "この通信の本人確認を開始できません",
	"Request a fresh sign-in link.":                                                       "元のアプリから接続し直して、新しい認証画面を開いてください。",
	"Invalid authentication age.":                                                         "本人確認の有効時間が正しく設定されていません。管理者にお問い合わせください。",
	"Invalid authentication grant lifetime.":                                              "アクセス許可の有効時間が正しく設定されていません。管理者にお問い合わせください。",
	"Invalid authentication methods.":                                                     "本人確認の方法が正しく設定されていません。管理者にお問い合わせください。",
	"Authentication upgrade state unavailable":                                            "認証サービスの準備状況を確認できません",
	"Request a fresh link when authentication services are available.":                    "認証サービスが利用できるようになってから、元のアプリで接続し直してください。",
	"Device user is not identified":                                                       "端末の利用者を確認できません",
	"Update the agent and start authentication from your own OS session.":                 "エージェントを更新し、ご自身のOSアカウントから接続し直してください。",
	"Device user is not assigned":                                                         "端末の利用者が登録されていません",
	"Ask your administrator to assign this OS account to your identity provider subject.": "このOSアカウントを認証サービスのアカウントへ割り当てるよう、管理者へ依頼してください。",
	"Device user binding is unavailable":                                                  "端末の利用者情報を利用できません",
	"Request a fresh authentication link after the deployment is ready.":                  "認証サービスの準備が整ってから、元のアプリで接続し直してください。",
	"Authentication upgrade in progress":                                                  "認証機能を更新しています",
	"The deployment must confirm all authentication nodes before single-request authentication can be enabled.": "認証サービスの更新が完了してから、もう一度接続してください。",
	"Authentication authority unavailable":                  "認証サービスに接続できません",
	"Try again when authentication services are available.": "認証サービスが利用できるようになってから、もう一度お試しください。",
	"Authentication requirements unavailable":               "必要な本人確認を実行できません",
	"Sign-in request already used":                          "この認証要求は使用済みです",
	"Authentication not completed":                          "本人確認が完了していません",
	"Retry authentication or request a fresh link.":         "本人確認をやり直すか、元のアプリから接続し直してください。",
	"Too many sign-in requests":                             "本人確認の要求が多すぎます",
	"Complete or wait for outstanding requests to expire.":  "開いている本人確認を完了するか、しばらく待ってから接続し直してください。",
	"Authentication state unavailable":                      "本人確認の状態を利用できません",
	"Invalid callback":                                      "本人確認の結果を受け取れません",
	"Restart authentication.":                               "元のアプリから接続し直して、本人確認をやり直してください。",
	"This step-up link is no longer valid. Return to your terminal and start the connection again to get a fresh one.": "この認証リンクは利用できなくなりました。元のアプリから接続し直して、新しい認証画面を開いてください。",
	"Authentication cancelled":       "本人確認がキャンセルされました",
	"No authentication was granted.": "アクセス許可は発行されていません。",
	"Sign-in unavailable":            "本人確認を利用できません",
	"Sign-in failed":                 "本人確認に失敗しました",
	"We couldn't reach your identity provider to complete authentication. Please try again, or contact your administrator.": "認証サービスに接続できなかったため、本人確認を完了できませんでした。もう一度お試しいただくか、管理者にお問い合わせください。",
	"We couldn't verify your identity provider's signing keys. Please try again, or contact your administrator.":            "認証サービスの署名を検証できませんでした。もう一度お試しいただくか、管理者にお問い合わせください。",
	"Access denied": "アクセスを許可できません",
	"We couldn't verify your identity for this resource. If you believe this is an error, contact your administrator.":                                                                           "この接続先に必要な本人確認を検証できませんでした。お心当たりがない場合は、管理者にお問い合わせください。",
	"This internal resource requires a phishing-resistant passkey, and your sign-in didn't provide one. Return to your terminal and try again with your passkey, or contact your administrator.": "この接続先ではフィッシング耐性のあるパスキーが必要です。元のアプリから接続し直し、パスキーで本人確認するか、管理者にお問い合わせください。",
	"Authentication signing unavailable": "本人確認の結果を保護できません",
	"Request a fresh link.":              "元のアプリから接続し直して、新しい認証画面を開いてください。",
	"Fresh sign-in required":             "本人確認をやり直してください",
	"An administrator requires a new identity verification. Return to your app and start a fresh sign-in.": "管理者が本人確認のやり直しを求めています。元のアプリから接続し直して、改めて本人確認してください。",
	"Authentication context changed":          "本人確認の条件が変更されました",
	"This account cannot approve the request": "このアカウントでは本人確認を完了できません",
	"Sign in with the account assigned to the originating OS user, or contact your administrator.": "接続元のOSアカウントに割り当てられたアカウントでサインインするか、管理者にお問い合わせください。",
	"Sign-in expired":                       "本人確認の有効期限が切れました",
	"Request-bound authentication required": "接続元から本人確認を開始してください",
	"Request a fresh sign-in link after the deployment has confirmed its authentication capabilities.": "認証サービスの準備が整ってから、元のアプリで接続し直してください。",
	"Authentication result could not be saved":                                                         "本人確認の結果を保存できませんでした",
	"Request a fresh link. Do not reuse this sign-in attempt.":                                         "この認証画面は再利用せず、元のアプリから接続し直してください。",
	"Authentication unavailable":                                                                       "本人確認を利用できません",
	"Destination confirmation invalid":                                                                 "接続先の確認をやり直してください",
	"Reload this page and confirm the destination again.":                                              "画面を再読み込みして、接続先をもう一度確認してください。",
	"Destination confirmation expired":                                                                 "接続先の確認が期限切れになったか、使用済みです",
	"The request could not be completed. Try again from your app, or contact your administrator.":      "処理を完了できませんでした。元のアプリからもう一度お試しいただくか、管理者にお問い合わせください。",
}

func ceremonyLanguage(requests ...*http.Request) string {
	if len(requests) == 0 || requests[0] == nil {
		return "en"
	}
	r := requests[0]
	if cookies := r.CookiesNamed(ceremonyLanguageCookie); len(cookies) == 1 && (cookies[0].Value == "en" || cookies[0].Value == "ja") {
		return cookies[0].Value
	}
	best, quality := "en", 0.0
	header := r.Header.Get("Accept-Language")
	if len(header) > 4096 {
		return best
	}
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(strings.TrimSpace(item), ";")
		base := strings.SplitN(strings.ToLower(strings.TrimSpace(parts[0])), "-", 2)[0]
		if base != "ja" && base != "en" {
			continue
		}
		q := 1.0
		for _, parameter := range parts[1:] {
			parameter = strings.TrimSpace(parameter)
			if strings.HasPrefix(parameter, "q=") {
				value, err := strconv.ParseFloat(strings.TrimPrefix(parameter, "q="), 64)
				if err != nil || value < 0 || value > 1 {
					q = 0
				} else {
					q = value
				}
			}
		}
		if q > quality {
			best, quality = base, q
		}
	}
	return best
}

func ceremonyTranslation(text, lang string) string {
	if lang == "ja" {
		if translated, ok := ceremonyJapanese[text]; ok {
			return translated
		}
	}
	return text
}

func ceremonyLabel(text string, requests ...*http.Request) string {
	return `<span data-dsse-text="` + html.EscapeString(text) + `">` + html.EscapeString(ceremonyTranslation(text, ceremonyLanguage(requests...))) + `</span>`
}

func ceremonyErrorLabel(text string, requests ...*http.Request) string {
	const fallback = "The request could not be completed. Try again from your app, or contact your administrator."
	translated := ceremonyTranslation(text, ceremonyLanguage(requests...))
	if ceremonyLanguage(requests...) == "ja" {
		if _, known := ceremonyJapanese[text]; !known {
			translated = ceremonyJapanese[fallback]
		}
	}
	return `<span data-dsse-text="` + html.EscapeString(text) + `" data-dsse-fallback="` + fallback + `">` + html.EscapeString(translated) + `</span>`
}

// Static, hash-authorized presentation code only. Switching language changes
// textContent and a non-credential, host-only preference cookie. It never reads
// a URL, submits a form, reloads a callback, contacts an IdP, or reads auth state.
var ceremonyLanguageScript = func() string {
	catalog, _ := json.Marshal(ceremonyJapanese)
	return `(function(){"use strict";const ja=` + string(catalog) + `;function select(lang,save){if(lang!=="ja"&&lang!=="en")return;document.documentElement.lang=lang;document.querySelectorAll("[data-dsse-text]").forEach(function(node){const text=node.getAttribute("data-dsse-text");node.textContent=lang==="ja"?(ja[text]||ja[node.getAttribute("data-dsse-fallback")]||text):text;});document.querySelectorAll("[data-dsse-language]").forEach(function(button){button.setAttribute("aria-pressed",String(button.getAttribute("data-dsse-language")===lang));});const heading=document.querySelector("h1");if(heading)document.title=heading.textContent+" — Lantern DSSE";if(save)document.cookie="` + ceremonyLanguageCookie + `="+lang+"; Path=/; Secure; SameSite=Lax; Max-Age=31536000";}document.querySelectorAll("[data-dsse-language]").forEach(function(button){button.addEventListener("click",function(){select(button.getAttribute("data-dsse-language"),true);});});select(document.documentElement.lang,false);}());`
}()

var ceremonyLanguageScriptHash = func() string {
	digest := sha256.Sum256([]byte(ceremonyLanguageScript))
	return base64.StdEncoding.EncodeToString(digest[:])
}()
