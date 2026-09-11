"use strict";

// ---------------------------------------------------------------------------
// Login page — the only pre-authentication surface.
//
// This script deliberately carries NONE of the admin feature catalog (GROUPS),
// endpoint map, or admin fetch/render code. It does exactly three things:
//   1. email + password + TOTP sign-in  (POST /admin/login/password -> /totp)
//   2. account activation                (the emailed /?activate=<token> link)
//   3. on success / existing session -> hand off to the admin console (console.html)
// Admin sign-in is FIRST-PARTY ONLY — SSO / IdP-federated admin login was abolished (admin access must
// not depend on an external IdP). End-user (workforce) IdP federation is a separate, unaffected feature.
// With no valid session, the admin console is never loaded.
// ---------------------------------------------------------------------------

const CONSOLE_PAGE = "console.html";

// --- i18n ---
let lang = localStorage.getItem("lang") || "en";
function t(key) { return (window.I18N[lang] && window.I18N[lang][key]) || window.I18N.en[key] || key; }
function applyI18n() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.getAttribute("data-i18n")); });
  document.getElementById("lang-en").classList.toggle("active", lang === "en");
  document.getElementById("lang-ja").classList.toggle("active", lang === "ja");
  const edge = document.getElementById("edge-url");
  const ctrl = document.getElementById("control-url");
  if (edge) edge.value = localStorage.getItem("edgeUrl") || "";
  if (ctrl) ctrl.value = localStorage.getItem("controlUrl") || "";
}
function setLang(l) { lang = l; localStorage.setItem("lang", l); applyI18n(); }

// Same-origin only: the Console is a front door that reverse-proxies the admin API, so the SPA always calls
// RELATIVE /admin/* paths. A stale absolute override in localStorage (from older builds) would wrongly send
// auth requests cross-origin to a backend that no longer serves them, so it is ignored and purged on boot.
function edgeBase() { return ""; }
function purgeStaleConfig() { ["edgeUrl", "controlUrl", "adminToken"].forEach((k) => localStorage.removeItem(k)); }
function setConn(cls, msg) {
  const el = document.getElementById("conn-status");
  el.className = "conn-status " + cls; el.textContent = msg;
}

// --- session pre-check: an already-signed-in operator skips the login form ---
async function forwardIfSignedIn() {
  const base = edgeBase(); // "" => same-origin (front-door proxied)
  try {
    const res = await fetch(base + "/admin/session", { headers: { accept: "application/json" }, credentials: "include" });
    if (!res.ok) return false;
    const s = await res.json();
    if (s && s.auth_method === "admin_session") { window.location.replace(CONSOLE_PAGE); return true; }
  } catch (e) { /* unreachable edge -> stay on the login page */ }
  return false;
}

// --- first-party sign-in: email + password -> (challenge) -> 2FA code -> session ---
let pendingChallenge = null;
async function firstPartySignIn() {
  const base = edgeBase();
  const email = document.getElementById("signin-email").value.trim();
  const password = document.getElementById("signin-password").value;
  if (!email) { setConn("err", t("enterEmail")); return; }
  try {
    if (!pendingChallenge) {
      const res = await fetch(base + "/admin/login/password", {
        method: "POST", credentials: "include",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) { setConn("err", t("invalidCredentials")); return; }
      const j = await res.json();
      pendingChallenge = j.challenge_token;
      document.getElementById("totp-row").style.display = "";
      document.getElementById("signin-totp").focus();
      setConn("ok", t("enterTotp"));
      return;
    }
    const code = document.getElementById("signin-totp").value.trim();
    const res = await fetch(base + "/admin/login/totp", {
      method: "POST", credentials: "include",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ challenge_token: pendingChallenge, code }),
    });
    if (!res.ok) {
      setConn("err", t("invalidCredentials"));
      pendingChallenge = null;
      document.getElementById("totp-row").style.display = "none";
      return;
    }
    // Authenticated: the session cookie is set. Clear secrets from the DOM and hand off to the console.
    pendingChallenge = null;
    document.getElementById("signin-password").value = "";
    document.getElementById("signin-totp").value = "";
    window.location.replace(CONSOLE_PAGE);
  } catch (e) { setConn("err", e.message); }
}

// --- activation (from the emailed link: /?activate=<token>) ---
let activationToken = null;
function setActivation(cls, msg) {
  const el = document.getElementById("activation-status");
  el.className = "conn-status " + cls; el.textContent = msg;
}
function initActivationFromURL() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("activate");
  if (!token) return false;
  activationToken = token;
  document.getElementById("signin-card").style.display = "none";
  document.getElementById("activation-panel").style.display = "";
  const base = edgeBase(); // "" => same-origin (front-door proxied)
  fetch(base + "/admin/activate?token=" + encodeURIComponent(token))
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error("invalid"))))
    .then((j) => { document.getElementById("activation-email").textContent = j.email || ""; })
    .catch(() => { setActivation("err", t("activationInvalid")); });
  return true;
}
function wireActivation() {
  const post = (path, body) => fetch(edgeBase() + path, {
    method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
  const pwBtn = document.getElementById("activate-password-btn");
  if (pwBtn) pwBtn.onclick = async () => {
    const pw = document.getElementById("activate-password").value;
    try {
      let res = await post("/admin/activate/password", { token: activationToken, new_password: pw });
      if (!res.ok) { setActivation("err", (await res.json()).error || t("requestFailed")); return; }
      res = await post("/admin/activate/totp/begin", { token: activationToken });
      if (!res.ok) { setActivation("err", t("requestFailed")); return; }
      const j = await res.json();
      document.getElementById("activate-otpauth").textContent = j.otpauth_uri;
      document.getElementById("activate-secret").textContent = j.secret || "";
      document.getElementById("activate-2fa").style.display = "";
      // Render a scannable QR from the otpauth URI (vendored qrcode.min.js, fully offline — no external call).
      const qrEl = document.getElementById("activate-qr");
      if (qrEl) {
        qrEl.innerHTML = "";
        if (window.QRCode) {
          new QRCode(qrEl, { text: j.otpauth_uri, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M });
        } else {
          qrEl.style.display = "none"; // lib missing → fall back to the manual secret below
        }
      }
      setActivation("ok", t("enroll2fa"));
    } catch (e) { setActivation("err", e.message); }
  };
  const doneBtn = document.getElementById("activate-complete-btn");
  if (doneBtn) doneBtn.onclick = async () => {
    const code = document.getElementById("activate-totp").value.trim();
    try {
      const res = await post("/admin/activate/totp/complete", { token: activationToken, code });
      if (!res.ok) { setActivation("err", (await res.json()).error || t("requestFailed")); return; }
      const j = await res.json();
      document.getElementById("activate-recovery-codes").textContent = (j.recovery_codes || []).join("\n");
      document.getElementById("activate-recovery").style.display = "";
      setActivation("ok", t("activationDone"));
    } catch (e) { setActivation("err", e.message); }
  };
}

// --- boot ---
async function init() {
  purgeStaleConfig(); // drop any stale absolute Edge URL / token so everything stays same-origin
  document.getElementById("lang-en").onclick = () => setLang("en");
  document.getElementById("lang-ja").onclick = () => setLang("ja");
  applyI18n();

  document.getElementById("signin-btn").onclick = () => firstPartySignIn();
  // Admin sign-in is first-party only (email + password + TOTP). SSO / IdP-federated admin login was
  // deliberately abolished — admin access must not depend on an external IdP (no IdP-outage lockout, no
  // second admin-auth surface to secure). End-user (workforce) IdP federation is unaffected.
  document.getElementById("signin-totp").addEventListener("keydown", (e) => { if (e.key === "Enter") firstPartySignIn(); });
  document.getElementById("signin-password").addEventListener("keydown", (e) => { if (e.key === "Enter") firstPartySignIn(); });

  wireActivation();
  if (initActivationFromURL()) return; // activation link -> activation takes over (no session forward)
  forwardIfSignedIn();
}
document.addEventListener("DOMContentLoaded", init);
