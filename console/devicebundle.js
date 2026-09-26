// devicebundle.js — hand one device everything it needs, in one download.
//
// ★★★ WHY (2026-08-30, the operator: both shapes should work — one bundled download AND the separate files).
//
// A device needs four things: the installer, the signed profile, the key that verifies the profile, and a
// one-time approval. Three of them are per-organization or per-device, so they CANNOT be baked into the
// installer: it is signed and notarised, and any per-device edit breaks both. So the four travel together in
// an archive instead, and the installer takes the other three from the folder it is opened from.
//
// That is the whole trick. There is no new server route and no new credential-bearing endpoint: this screen
// already mints the profile and the token with the administrator's own session, and the installer bytes have
// been reachable at /admin/agent-update-artifact since the day the Console could publish a release. What was
// missing was putting them in one file.
//
// ★ THE ARCHIVE IS WRITTEN HERE, UNCOMPRESSED. A zip with stored entries is a header, the bytes, and a
// directory — sixty lines — and the alternative is asking every deployment to serve a library from a CDN it
// may not be allowed to reach. The installer is already compressed; compressing it again would buy nothing.
//
// ★★ AND IT CARRIES A ONE-TIME CREDENTIAL, so it is treated as one: the archive holds ONE token, for ONE
// machine, and the README inside says to delete the file once the machine is up. A bundle for a fleet would
// be a file that enrols anything that reads it.

// crc32 — the checksum a zip entry carries. Table built once on first use.
let _zipCRCTable = null;
function zipCRC32(bytes) {
  if (!_zipCRCTable) {
    _zipCRCTable = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      _zipCRCTable[i] = c >>> 0;
    }
  }
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) crc = (_zipCRCTable[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8)) >>> 0;
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// zipStored builds a zip whose entries are stored, not deflated. entries: [{name, bytes: Uint8Array}]
function zipStored(entries) {
  const enc = new TextEncoder();
  const chunks = [];
  const central = [];
  let offset = 0;
  const u16 = (n) => [n & 0xFF, (n >>> 8) & 0xFF];
  const u32 = (n) => [n & 0xFF, (n >>> 8) & 0xFF, (n >>> 16) & 0xFF, (n >>> 24) & 0xFF];
  for (const e of entries) {
    const name = enc.encode(e.name);
    const crc = zipCRC32(e.bytes);
    // Local header. Version 2.0, no flags, method 0 (stored), a fixed DOS timestamp: the archive is about
    // what is in it, and a timestamp that changes every second makes two identical bundles look different.
    const local = [].concat(
      u32(0x04034B50), u16(20), u16(0), u16(0), u16(0), u16(0x21), // 1980-01-01
      u32(crc), u32(e.bytes.length), u32(e.bytes.length), u16(name.length), u16(0));
    chunks.push(new Uint8Array(local), name, e.bytes);
    central.push({ name, crc, size: e.bytes.length, offset });
    offset += local.length + name.length + e.bytes.length;
  }
  const dirStart = offset;
  for (const c of central) {
    const hdr = [].concat(
      u32(0x02014B50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0x21),
      u32(c.crc), u32(c.size), u32(c.size), u16(c.name.length),
      u16(0), u16(0), u16(0), u16(0), u32(0), u32(c.offset));
    chunks.push(new Uint8Array(hdr), c.name);
    offset += hdr.length + c.name.length;
  }
  const end = [].concat(u32(0x06054B50), u16(0), u16(0), u16(central.length), u16(central.length),
    u32(offset - dirStart), u32(dirStart), u16(0));
  chunks.push(new Uint8Array(end));
  return new Blob(chunks, { type: "application/zip" });
}

// A 404 permits an installer-free bundle. Other failures must be resolved before minting a token.
// The artifact endpoint can also return 404 for a missing published file, so do not assert "unpublished".
async function dbFetchInstaller(platform, arch) {
  const base = baseForPlane(_PROFILE_PLANE);
  const token = localStorage.getItem("adminToken") || "";
  const signedIn = idpSession && idpSession.auth_method === "admin_session";
  const headers = {};
  if (!signedIn && token) headers["authorization"] = "Bearer " + token;
  if (signedIn && idpSession.csrf_token) headers["x-csrf-token"] = idpSession.csrf_token;
  if (operateTenant) headers["x-operate-tenant"] = operateTenant;
  const path = "/admin/agent-update-artifact?platform=" + encodeURIComponent(platform) +
    "&arch=" + encodeURIComponent(arch);
  const res = await fetch(base + path, { headers, credentials: "include", redirect: "error" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(bl({ en: "Installer download failed (HTTP " + res.status + ").",
    ja: "インストーラを取得できませんでした（HTTP " + res.status + "）。" }));
  const buf = await res.arrayBuffer();
  if (!buf.byteLength) throw new Error(bl({ en: "The installer download was empty.", ja: "取得したインストーラが空です。" }));
  return new Uint8Array(buf);
}

// dbReadme is what the person opening the archive reads. It names the one act they perform and the one file
// they delete afterwards.
function dbReadme(hasInstaller, installerName) {
  const lines = [
    "This folder is one device's setup for this deployment.",
    "",
    hasInstaller
      ? "1. Open " + installerName + " and follow it."
      // ★★★ DO NOT SEND THE READER TO A SCREEN THAT IS EMPTY (2026-09-06, measured from a Windows box against
      // a deployment that had published nothing: GET /admin/agent-update-artifact answered 404 for both
      // platforms and the Console's Agent Releases screen offered nothing at all). This line used to say "get
      // it from the Console (Agent Releases > Download)". The person holding this folder is the DEVICE's
      // owner, not the operator; they cannot publish a release, and until somebody does there is nothing on
      // that screen for them to take. Being pointed at an empty page is worse than being told to ask, because
      // it looks like their mistake.
      : "1. This deployment could not provide an installer for this platform, so it is not in this folder",
    hasInstaller ? "" : "   and cannot be fetched from here. Ask whoever gave you this folder for the",
    hasInstaller ? "" : "   installer, put it in THIS folder, and open it.",
    "",
    "The installer takes install_profile.json, profile_signing_key.txt and enrolment_token.txt from the",
    "folder it is opened from. Nothing has to be typed, and nothing has to be copied into a system folder.",
    "",
    "enrolment_token.txt is a credential. It works for ONE machine, ONCE. Delete this folder when the",
    "machine is up; if the token is lost before it is used, approve the device again — it cannot be looked up.",
    "",
    "On macOS the system asks once to approve the network extension, in System Settings > General >",
    "Login Items & Extensions > Network Extensions. That prompt is Apple's and does not appear on a Mac",
    "managed by an MDM that pre-approves the extension.",
    "",
  ];
  return lines.filter((l) => l !== null).join("\n");
}

// downloadDeviceBundle mints one approval and hands over the whole set as a single archive.
async function downloadDeviceBundle(envelope, group, platform, arch, button) {
  if (button.__bundlePending) return;
  const enc = new TextEncoder();
  const key = profileSigningKeyOf(envelope);
  if (!key) {
    uiToast(bl({ en: "This deployment published no profile-signing key, so a device could not verify the "
                     + "configuration in this bundle.",
                 ja: "この配備は署名鍵を公開していないため、この一式では端末が設定を検証できません。" }), "err");
    return;
  }
  const retryLabel = bl({ en: "Download everything for one device", ja: "端末1台ぶんを一式でダウンロード" });
  let issuancePending = false;
  button.__bundlePending = true;
  button.disabled = true;
  button.textContent = bl({ en: "Preparing…", ja: "準備中…" });
  try {
    // Resolve the artifact before creating a credential. Only 404 permits a bundle without an installer.
    const installer = await dbFetchInstaller(platform, arch);
    issuancePending = true;
    const r = await apiFetch("POST", "/admin/enrolment-tokens", {
      label: group ? group : bl({ en: "Device configuration", ja: "端末の設定" }),
      group, expires_in_hours: 168, count: 1,
    }, _PROFILE_PLANE);
    issuancePending = false;
    if (r.status === 409 && r.body && r.body.partial === true &&
        Array.isArray(r.body.tokens) && r.body.tokens.length > 0 && enrolTokenRowsValid(r.body.tokens)) {
      showEnrolTokenOnce({ ...r.body, requested_count: 1 });
    }
    if (!r.ok || !enrolTokenCompleteBody(r.body, 1)) {
      const uncertain = r.ok || r.status >= 500 || (r.body && r.body.partial === true);
      uiToast(uncertain ? enrolTokenResponseWarning() :
        (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err");
      button.textContent = retryLabel;
      return;
    }
    const row = r.body.tokens[0];
    const secret = row.secret;
    // Keep the returned credential reachable even if ZIP construction or the browser download fails.
    bundleApprovalFallback(button, secret, row.token.id);
    const installerName = "dsse-agent-" + platform + "-" + arch + (platform === "windows" ? ".msi" : ".pkg");
    const entries = [
      { name: "install_profile.json", bytes: enc.encode(JSON.stringify(envelope, null, 2) + "\n") },
      { name: "profile_signing_key.txt", bytes: enc.encode(key + "\n") },
      { name: "enrolment_token.txt", bytes: enc.encode(secret + "\n") },
      { name: "README.txt", bytes: enc.encode(dbReadme(!!installer, installerName)) },
    ];
    if (installer) entries.unshift({ name: installerName, bytes: installer });
    const blob = zipStored(entries);
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = "dsse-device-setup-" + platform + "-" + arch + ".zip";
      document.body.appendChild(a);
      try { a.click(); } finally { a.remove(); }
    } finally { setTimeout(() => URL.revokeObjectURL(url), 10000); }
    if (!installer) {
      uiToast(bl({ en: "This deployment could not provide an installer for that platform, so the bundle carries "
                       + "only the configuration, the key and the approval. Put the installer in the folder "
                       + "before you hand it over, or check Agent Releases.",
                   ja: "この配備からその機械用のインストーラを取得できないため、設定・鍵・承認だけが入っています。"
                       + "渡す前にインストーラをフォルダに入れるか、Agent Releasesを確認してください。" }), "warn");
    }
    button.textContent = bl({ en: "Downloaded — one approval is now waiting for a device",
                              ja: "ダウンロード済み — 承認が1件、端末を待っています" });
  } catch (e) {
    uiToast(issuancePending ? enrolTokenResponseWarning() : String(e), "err");
    button.textContent = retryLabel;
  } finally {
    button.__bundlePending = false;
    button.disabled = false;
  }
}

// Keep the returned approval available independently of the archive download.
function bundleApprovalFallback(button, secret, tokenId) {
  const host = button.parentNode;
  if (!host) return;
  const previous = host.querySelector("[data-bundle-approval]");
  if (previous) previous.remove();
  const wrap = el("div", { style: "margin-top:8px" });
  wrap.setAttribute("data-bundle-approval", "1");
  wrap.appendChild(el("div", { class: "ui-view-desc", text: bl({
    en: "Even if no file was saved, the approval was made, and it is waiting for a "
      + "device either way. Take it by hand, or take it back so nothing is left waiting for a machine that "
      + "will never come. It is listed on Enrolment Tokens until one of those happens.",
    ja: "ファイルが保存されなかった場合も承認は作られており、端末を"
      + "待ち続けます。手で受け取るか、来ない端末を待たせないよう取り消してください。どちらかを行うまで、"
      + "参加トークンの画面に残ります。" }) }));
  const show = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Show the approval", ja: "承認を表示" }) });
  const revoke = el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Take it back", ja: "取り消す" }) });
  const shown = el("div", { style: "margin-top:6px" });
  show.addEventListener("click", () => {
    shown.textContent = "";
    // The same shape the token screen uses: the secret, selectable, said once. It is already in a file on
    // somebody's disk if the download worked, so showing it here adds no copy that did not exist.
    shown.appendChild(el("code", { style: "user-select:all; word-break:break-all", text: String(secret) }));
    show.disabled = true;
  });
  revoke.addEventListener("click", async () => {
    if (revoke.disabled) return;
    if (!tokenId) { uiToast(bl({ en: "This approval came back without an id, so it cannot be taken back from "
                                    + "here — Enrolment Tokens lists it.",
                                 ja: "この承認にはIDが無いため、ここからは取り消せません。参加トークンの画面に" +
                                     "一覧があります。" }), "err"); return; }
    revoke.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/enrolment-tokens/" + encodeURIComponent(tokenId) + "/revoke", {}, _PROFILE_PLANE);
      if (!r.ok) { uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return; }
      const token = r.body && r.body.token;
      if (!token || token.id !== tokenId || typeof token.revoked_at !== "string" || !token.revoked_at ||
          (token.used_at && (typeof r.body.note !== "string" || !r.body.note))) {
        uiToast(bl({ en: "Revocation could not be confirmed. Reload Enrolment Tokens to check its state.",
          ja: "取消結果を確認できません。登録トークンの一覧を再読込して状態を確認してください。" }), "err");
        return;
      }
      if (!button.__bundlePending && host.querySelector("[data-bundle-approval]") === wrap) {
        button.textContent = bl({ en: "Download everything for one device", ja: "端末1台ぶんを一式でダウンロード" });
      }
      wrap.textContent = "";
      if (r.body && r.body.note) {
        wrap.appendChild(el("div", { class: "ui-callout ui-callout-warn", role: "alert", text: r.body.note }));
        return;
      }
      wrap.appendChild(el("div", { class: "ui-view-desc", text: bl({
        en: "Taken back. Nothing can enrol with it, and nothing is left outstanding.",
        ja: "取り消しました。これで登録できるものはなく、未使用のまま残ることもありません。" }) }));
    } catch (e) {
      uiToast(String(e), "err");
    } finally {
      revoke.disabled = false;
    }
  });
  wrap.appendChild(el("div", { style: "display:flex; gap:8px; margin-top:6px" }, [show, revoke]));
  wrap.appendChild(shown);
  host.appendChild(wrap);
}
