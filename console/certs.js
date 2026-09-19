"use strict";

// certs.js — the certificate MAP: every certificate in this deployment as one object each, saying where it
// is used, what is in it, and what can be done to it (replace / download-to-install / rotate / renew).
//
// Backend: GET /admin/pki/certificates per node (facts + relations + capabilities). Labels live HERE — the
// server asserts relations its own configuration establishes; this file translates them into operator terms.
// Operations reuse the existing endpoints: PUT /admin/certs/{name} (+versions/rollback),
// POST /admin/interception-intermediate/rotate, POST /admin/device-certificates/renew-all.
//
// Rebuilt 2026-07-31 from the operator's frame: "I expect a screen where I can see WHERE each certificate is
// used, WHAT it contains, and replace / disable / install it." The previous screen listed the one
// hot-reloadable listener cert per node and nothing else. docs/pki_console_certificate_map_redesign.ja.md.

const _PKIMAP_NODES = [
  { plane: undefined, label: { en: "Enforcement Edge", ja: "エッジ（強制点）" } },
  { plane: "control", label: { en: "Control plane", ja: "コントロールプレーン" } },
];

// Operator terms for the server's semantic ids. UI rules (operator, 2026-07-31): no explanatory prose, and
// never アンカー/pin — a device "trusts" a certificate. Every role carries `use`: ONE fixed-grammar line
// stating who uses this and for what — the function is data, not an essay (operator, same day: "a name whose
// role I cannot tell is not a name").
// Every certificate has a short name tied to its role — "Edge Server cert", "Intercept Root CA" — used on
// every screen that mentions it. Before this, a certificate was referred to by its subject, which differs
// per deployment and reads as a machine value, so the same certificate looked like a different thing on the
// paths view than on this one.
const _PKIMAP_ROLES = {
  transport_server: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "hot", impact: { en: "Replaced in place. New connections get the new certificate; existing ones keep the old until they reconnect.", ja: "無停止で差し替わります。新しい接続から新証明書になり、既存の接続は再接続するまで旧証明書のままです。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Edge Server cert", ja: "Edge サーバ証明書" },
    section: "device",
    title: { en: "Edge identity certificate", ja: "Edge の本人証明書" },
    use: { en: "Shown by the Edge to every device; a device connects only after matching it against the certificates it trusts.",
           ja: "Edge が全端末に提示。端末は自分が信頼する証明書と照合できたときだけ接続する。" },
  },
  transport_anchor: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "overlap", impact: { en: "Not swapped — added alongside, then the old one is withdrawn once every device holds the new one. Swapping would cut off any device that had not caught up.", ja: "入れ替えではなく、並べて追加し、全端末が新しい方を持ってから旧を撤回します。入れ替えると、追いついていない端末が切断されます。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Device Trust CA", ja: "端末信頼CA" },
    section: "device",
    title: { en: "Certificate devices trust", ja: "端末が信頼する証明書" },
    use: { en: "Held by each device; what it matches the Edge's identity certificate against — this is how a device knows it reached the real Edge.",
           ja: "各端末が保持。Edge の本人証明書をこれと照合する — 接続先が本物の Edge だと分かる仕組みそのもの。" },
    install: { en: "Add next to the current one in each agent's trusted certificates; never swap.",
               ja: "各エージェントの信頼済み証明書に、現行のものと並べて追加します（入れ替えない）。" },
  },
  device_client_ca: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "overlap", impact: { en: "Added alongside, then the old one is retired once no device presents a certificate from it.", ja: "並べて追加し、その CA 由来の証明書を出す端末が居なくなってから旧を退役させます。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Device Auth CA", ja: "端末認証CA" },
    section: "device",
    title: { en: "Device verification CA", ja: "端末確認用 CA" },
    use: { en: "Used by the Edge to check that a connecting device's certificate was properly issued.",
           ja: "Edge が、接続してきた端末の証明書が正規に発行されたものかを確認するのに使う。" },
  },
  device_issuing_ca: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "reissue", impact: { en: "Every device certificate is re-issued from the new CA. Devices renew on their own schedule, or all at once from here.", ja: "全端末の証明書を新しい CA から再発行します。端末は自分の周期で更新するか、ここから一斉更新します。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Device Issuing CA", ja: "端末発行CA" },
    section: "device",
    title: { en: "Device certificate issuer", ja: "端末証明書の発行元" },
    use: { en: "Every device's own certificate is issued and renewed from this CA.",
           ja: "各端末の本人証明書は、ここから発行・更新される。" },
  },
  interception_root_pending: {
    // A root on its way to endpoint trust stores. It exists on this screen so the distribution can be
    // WATCHED — the interception switch is the one operation where a machine that missed it loses every
    // site, so "how far has it reached" has to be a number an operator can see before they act.
    nick: { en: "Intercept Root CA (incoming)", ja: "傍受ルートCA（配布中）" },
    replace: { how: "redistribute", impact: {
      en: "Not in use yet. It becomes the signer only once every endpoint trusts it.",
      ja: "まだ使われていません。全端末が信頼した時点で、はじめて署名に使えます。" } },
    section: "interception",
    title: { en: "Interception root being distributed", ja: "配布中の傍受ルート証明書" },
    use: { en: "Being installed into endpoint trust stores. Nothing is signed under it until every endpoint has it.",
           ja: "端末の信頼ストアへ配布中。全端末が持つまで、この配下では何も署名しない。" },
    install: { en: "Distribute into endpoint trust stores (MDM profile / manual import).",
               ja: "端末の信頼ストアへ配布します（MDM プロファイル / 手動インポート）。" },
  },
  interception_root: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "redistribute", impact: { en: "Every endpoint must trust the new root BEFORE the change, or HTTPS breaks for all of them. Distribute first, then switch.", ja: "変更の前に全端末が新ルートを信頼している必要があります。そうでなければ全端末で HTTPS が壊れます。先に配布し、その後で切り替えます。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Intercept Root CA", ja: "傍受ルートCA" },
    section: "interception",
    title: { en: "Interception root certificate", ja: "傍受ルート証明書" },
    use: { en: "Trusted by every steered endpoint — this trust is what lets the Edge decrypt (intercept) HTTPS.",
           ja: "全端末がこれを信頼している。その信頼が、Edge が HTTPS を復号(傍受)できる根拠。" },
    install: { en: "Distribute into endpoint trust stores (MDM profile / manual import).",
               ja: "端末の信頼ストアへ配布します（MDM プロファイル / 手動インポート）。" },
  },
  interception_intermediate: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "rotate", impact: { en: "Rotated in place. Sites already open keep working; new sites are signed by the new one. Endpoint trust does not change.", ja: "その場でローテートします。開いているサイトはそのまま動き、新しいサイトから新しい署名者になります。端末側の信頼設定は変わりません。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Intercept Signing CA", ja: "傍受署名CA" },
    section: "interception",
    title: { en: "Interception certificate signer", ja: "傍受証明書の署名者" },
    use: { en: "Issues, on the fly, the certificate shown for each intercepted site.",
           ja: "傍受するサイトごとの証明書を、その場で発行して署名する。" },
  },
  component_server: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "hot", impact: { en: "Replaced in place on the node you choose. The Console, connectors and the control plane pick it up on their next connection.", ja: "選んだノードで無停止に差し替わります。Console・コネクタ・コントロールプレーンは次の接続から新証明書を見ます。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Node Server cert", ja: "ノードサーバ証明書" },
    section: "component",
    title: { en: "Management identity certificate", ja: "管理系の本人証明書" },
    use: { en: "Verified by the Console, connectors and the control plane to confirm they reached the real node.",
           ja: "Console・コネクタ・コントロールプレーンが、接続先が本物のノードだと確認するために検証する。" },
  },
  agent_policy_signing_key: {
    // How this one is replaced, and what happens when it is. Each certificate has a different
    // correct method — in place, overlap-then-retire, re-issue, redistribute-first — and offering the
    // same "replace" everywhere would be a button that lies about what it does.
    replace: { how: "none", impact: { en: "Cannot be replaced from here: agents accept only this key, so a new one has to reach every agent before anything signed by it will be accepted.", ja: "この画面からは入れ替えられません。エージェントはこの鍵しか受け付けないため、新しい鍵を先に全エージェントへ届ける必要があります。" } },
    // A short handle, tied to the role, that an operator can say out loud and find on
    // another screen. The descriptive title says what it does; this is what it is CALLED.
    nick: { en: "Config Signing key", ja: "設定署名鍵" },
    section: "signing",
    title: { en: "Configuration signing key", ja: "設定への署名鍵" },
    use: { en: "Agents accept only configuration and trust material carrying this key's signature.",
           ja: "エージェントは、この鍵の署名が付いた設定・配布物だけを受け入れる。" },
  },
};

const _PKIMAP_RELS = {
  device_transport_anchors: { en: "verified by the certificates devices trust", ja: "端末が信頼する証明書で検証" },
  device_certificates: { en: "verifies device certificates", ja: "端末証明書を検証" },
  edge_transport_client_auth: { en: "verified at the transport handshake", ja: "トランスポート接続時に検証" },
  steered_endpoint_trust_stores: { en: "trusted by endpoint trust stores", ja: "端末の信頼ストアが信頼" },
  interception_root_pending: {
    // A root on its way to endpoint trust stores. It exists on this screen so the distribution can be
    // WATCHED — the interception switch is the one operation where a machine that missed it loses every
    // site, so "how far has it reached" has to be a number an operator can see before they act.
    nick: { en: "Intercept Root CA (incoming)", ja: "傍受ルートCA（配布中）" },
    replace: { how: "redistribute", impact: {
      en: "Not in use yet. It becomes the signer only once every endpoint trusts it.",
      ja: "まだ使われていません。全端末が信頼した時点で、はじめて署名に使えます。" } },
    section: "interception",
    title: { en: "Interception root being distributed", ja: "配布中の傍受ルート証明書" },
    use: { en: "Being installed into endpoint trust stores. Nothing is signed under it until every endpoint has it.",
           ja: "端末の信頼ストアへ配布中。全端末が持つまで、この配下では何も署名しない。" },
    install: { en: "Distribute into endpoint trust stores (MDM profile / manual import).",
               ja: "端末の信頼ストアへ配布します（MDM プロファイル / 手動インポート）。" },
  },
  interception_root: { en: "signed by the interception root", ja: "傍受ルートが署名" },
  agent_pinned_signing_key: { en: "registered in every agent", ja: "全エージェントに登録済み" },
  transport_server: { en: "verifies the transport server certificate", ja: "トランスポート サーバ証明書を検証" },
};

const _PKIMAP_SECTIONS = [
  { id: "device", title: { en: "Device ⇄ Edge trust", ja: "端末 ⇄ Edge の信頼" } },
  { id: "interception", title: { en: "Interception (decrypt-all)", ja: "傍受(すべて復号)" } },
  { id: "component", title: { en: "Component certificates", ja: "コンポーネント証明書" } },
  { id: "signing", title: { en: "Signing keys", ja: "署名鍵" } },
];

// The working set is the default; residue (still configured, used by nothing today) is behind one toggle.
let _pkiMapShowInactive = false;


// pkiDeploymentAct answers whether THIS caller may perform a deployment-level PKI act.
//
// ★★ THE DEPLOYMENT'S PKI IS ON A SCREEN EVERY CUSTOMER SEES (2026-08-18). Certificates is in the customer's
// navigation — correctly, because an organization must be able to see the authorities that intercept it and
// register its own device CA. What it also offered them was the deployment's own material: replace the
// certificate this node serves, distribute or withdraw a transport trust anchor, rotate the interception
// signer, retire a device CA. Every one of those answers 403 for a customer, and three of them only started
// answering 403 on 2026-08-17 — before that they worked.
//
// A button that cannot work is worse than no button: it reads as a fault in their own account, on the screen
// where a customer is least able to tell the difference.
function pkiDeploymentAct() {
  return typeof answeringForTheDeployment === "function" ? answeringForTheDeployment() : true;
}

function renderCertsView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Certificates", ja: "証明書" }) }),
    ]),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderCertsView(content) }),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  loadCertMap(host);
}

function fmtT(s) { if (!s) return "—"; try { return window.dsseFormatTime(s); } catch (e) { return s; } }

function certDaysLeft(notAfter) {
  const end = Date.parse(notAfter);
  if (!end) return null;
  return Math.floor((end - Date.now()) / 86400000);
}

function certExpiryBadge(days) {
  if (days === null) return null;
  if (days < 0) return uiBadge(bl({ en: "EXPIRED", ja: "期限切れ" }), "off");
  if (days <= 30) return uiBadge(bl({ en: days + "d left", ja: "残り" + days + "日" }), "off");
  return uiBadge(bl({ en: days + "d left", ja: "残り" + days + "日" }), "ok");
}

// An Apple configuration profile carrying the inspection root, generated here from the same public PEM the
// download button offers — the "install" verb for endpoint trust stores, with no server round-trip.
function pkiDownloadMobileconfig(item) {
  const b64 = (item.pem || "").replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  const cn = shortSubject(item.subject || "DSSE Inspection Root");
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key><string>${esc(cn)}.cer</string>
      <key>PayloadContent</key><data>${b64}</data>
      <key>PayloadDescription</key><string>${esc(cn)}</string>
      <key>PayloadDisplayName</key><string>${esc(cn)}</string>
      <key>PayloadIdentifier</key><string>example.dsse.inspection-root.cert</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>${crypto.randomUUID().toUpperCase()}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>${esc(cn)}</string>
  <key>PayloadIdentifier</key><string>example.dsse.inspection-root</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>${crypto.randomUUID().toUpperCase()}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`;
  const blob = new Blob([xml], { type: "application/x-apple-aspen-config" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "inspection-root.mobileconfig";
  a.click();
  URL.revokeObjectURL(a.href);
}

// Install = download the public material with a filename that says what it is.
function pkiDownloadPEM(item) {
  const base = (item.role || "certificate") + (item.sha256 ? "-" + item.sha256.slice(0, 12) : "");
  const blob = new Blob([item.pem || ""], { type: "application/x-pem-file" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = base + ".pem";
  a.click();
  URL.revokeObjectURL(a.href);
}

// Per-anchor device trust (adoption, assertions, the withdrawal gate) and the signing key's custody — the
// two retired screens' unique content, joined onto the map's cards (operator decision 2026-07-31: one page).
// A refusal an operator reads at the moment they are blocked. The server sends a code and the names the
// sentence needs; the wording lives here, in the language the screen is in. An unknown code falls back to
// the server's own sentence — a refusal that cannot be phrased must still be readable, never blank.
const _PKIGATE_REASONS = {
  trust_set_fixed_at_startup: { en: "This node's trust set is fixed at startup.", ja: "この拠点の信頼設定は起動時に固定されています。" },
  last_certificate:           { en: "This is the last one — withdrawing it leaves nothing to verify the Edge.", ja: "これが最後の1枚です。外すと Edge を検証できるものが無くなります。" },
  not_measurable:             { en: "Device trust cannot be measured on this node.", ja: "この拠点では端末の信頼状況を測れません。" },
  served_certificate_unreadable: { en: "The certificate this Edge presents cannot be read, so this cannot be judged.", ja: "この Edge が提示している証明書を読めないため、判断できません。" },
  none_verifies_served:       { en: "Nothing left would verify the certificate the Edge presents. Replace the Edge's certificate first.", ja: "残るもので Edge の証明書を検証できません。先に Edge の証明書を差し替えてください。" },
  no_single_certificate_does_both: { en: "No remaining certificate is both trusted by every device and able to verify the Edge. Not confirmed: ", ja: "残るものの中に、全端末が信頼し、かつ Edge を検証できるものがありません。未確認: " },
  device_ca_set_fixed_at_startup: { en: "This node's device-trust set is fixed at startup.", ja: "この拠点の端末信頼設定は起動時に固定されています。" },
  unknown_fingerprint:        { en: "No certificate here has that fingerprint.", ja: "その指紋の証明書はここにありません。" },
  last_device_ca:             { en: "This is the last one — no device certificate could be verified at all.", ja: "これが最後の1枚です。端末証明書を1つも検証できなくなります。" },
  no_enrolled_device:         { en: "There is no enrolled device to measure against.", ja: "測る対象となる登録済み端末がありません。" },
  still_presented_by:         { en: "Still in use by: ", ja: "まだ使われています: " },
  unseen_since_start:         { en: "Not seen since this node started, so what they use is unknown: ", ja: "この拠点の起動後に接続がなく、何を使っているか不明です: " },
};

// The phrases that need names end with their own separator, so the names simply follow.
function pkiGateReason(code, fallbackText, params) {
  const phrase = _PKIGATE_REASONS[code];
  if (!phrase) return fallbackText || "";
  return bl(phrase) + (params || []).join(", ");
}

let _pkiAnchorScope = null;
let _pkiMapAnchorInfo = {};
// What devices declined to trust. Carried late by construction — a refusal cannot travel over the
// connection it caused to fail — so this is history, not a live status, and the rows say which.
let _pkiRefusals = [];
// The three facts the paths screen held that live nowhere else: what checks each credential, how long past
// expiry the recovery address still renews, and the TLS connections this node makes whose certificate
// belongs to somebody else. Everything else that screen showed was these certificates, indexed by
// connection instead of by certificate — the same facts twice, which is why it is gone.
let _pkiExternal = [];
// A rotation in progress, and what it is waiting for. This was a screen of its own; it was empty whenever
// nothing was happening, and every act it offered already existed here. What it uniquely held was the
// ORDER — which step is next and why the one after it is blocked — so that moved onto the certificates the
// rotation is about.
let _pkiOperation = null;
let _pkiPathFacts = {};
let _pkiMapCustody = null;
// What the control plane says about whether this organization HAS an interception authority. Separate from
// _pkiMapCustody, which is what its traffic is inspected UNDER — only an Edge can answer that.
let _pkiTenantInterception = null;
let _pkiTransportAuthority = null;
// ★★★ THE OTHER TWO TIERS HAD NO SCREEN AT ALL (2026-08-22, measured by walking the Console). Fourteen acts
// exist for an organization's three authorities; this file called three of them. Every rotation, every way
// back, and everything about device identity and interception was API-only — which on this product means it
// did not exist, because an operator does not have a terminal.
let _pkiDeviceAuthority = null;
let _pkiInterceptionAuthority = null;
// What each movement is WAITING FOR, from the Edge that sees handshakes. The control plane holds the
// authority; only an Edge can say who has adopted, so these are read from the enforcement plane.
let _pkiTenantCAs = [];
let _pkiNameRename = null;
let _pkiInterceptionRotation = null;

async function loadCertMap(host) {
  uiState(host, "loading");
  const current = freshRender(host);

  _pkiMapAnchorInfo = {}; _pkiMapCustody = null; _pkiTenantInterception = null; _pkiRefusals = []; _pkiTransportAuthority = null;
  _pkiDeviceAuthority = null; _pkiInterceptionAuthority = null;
  _pkiNameRename = null; _pkiInterceptionRotation = null;
  _pkiTenantCAs = []; _pkiOperation = null; _pkiExternal = []; _pkiPathFacts = {}; _pkiAnchorScope = null;
  const failedReads = new Set();
  const readExtra = async (path, unused, plane) => {
    try {
      const r = await apiFetch("GET", path, unused, plane);
      // A CP deliberately refuses the Edge-only intermediate view; the authority is read below.
      if (path === "/admin/interception-intermediate" && r.status === 409) return r;
      if (!r.ok || !r.body || typeof r.body !== "object" || Array.isArray(r.body)) throw new Error();
      if (/^\/admin\/tenant-(transport|device|interception)-authority/.test(path) && typeof r.body.has_authority !== "boolean") throw new Error();
      return r;
    } catch (e) { failedReads.add(path); throw e; }
  };
  const extras = Promise.all([
    readExtra("/admin/tenant-cas").then((r) => {
      const rows = r.body.tenant_cas || r.body.cas || r.body.items;
      if (!Array.isArray(rows)) { failedReads.add("/admin/tenant-cas"); return; }
      _pkiTenantCAs = rows;
    }).catch(() => {}),
    readExtra("/admin/pki/operations").then((r) => {
      _pkiOperation = (r.ok && r.body && r.body.in_flight) ? r.body : null;
    }).catch(() => {}),
    readExtra("/admin/pki/paths").then((r) => {
      const paths = (r.ok && r.body && r.body.paths) || [];
      _pkiExternal = paths.filter((p) => p.external);
      _pkiPathFacts = {};
      paths.forEach((p) => {
        if (!p.server_cert_id) return;
        const f = _pkiPathFacts[p.server_cert_id] || {};
        if (p.client_auth_verified_by) f.verifiedBy = p.client_auth_verified_by;
        if (p.recovery_window_hours) f.recoveryHours = p.recovery_window_hours;
        _pkiPathFacts[p.server_cert_id] = f;
      });
    }).catch(() => {}),
    readExtra("/admin/pki/trust-refusals").then((r) => {
      if (r.ok && r.body && r.body.refusals) _pkiRefusals = r.body.refusals;
    }).catch(() => {}),
    readExtra("/admin/transport-trust-anchors").then((r) => {
      if (r.ok && r.body && r.body.anchors) r.body.anchors.forEach((a) => { _pkiMapAnchorInfo[a.sha256] = a; });
      // The reader has to be told when the decision counts machines this screen cannot name — otherwise an
      // empty list reads as an empty fleet, and a refusal naming machines they have never seen is unexplainable.
      if (r.ok && r.body) _pkiAnchorScope = r.body;
    }).catch(() => {}),
    readExtra("/admin/interception-intermediate").then((r) => {
      if (r.ok && r.body) _pkiMapCustody = r.body;
    }).catch(() => {}),
    // ★★★ AND THE ONE THE CONTROL PLANE ANSWERS (2026-09-03, the operator's report that this screen did not
    // match reality — and it disagreed with ITSELF, one card naming the organization's root in use and the
    // next saying its authority "could not be determined from this node", offering to load one).
    //
    // The card above reads /admin/interception-intermediate, and a control plane REFUSES that by design,
    // naming the remedy in the refusal: "that is an EDGE's answer … the authority itself is at
    // /admin/tenant-interception-authority". The screen treated the refusal as a failed fetch and fell
    // through to its unknown branch — so the instruction in the refusal was read by nobody.
    readExtra("/admin/tenant-interception-authority", undefined, "control").then((r) => {
      if (r.ok && r.body) _pkiTenantInterception = r.body;
    }).catch(() => {}),
    // ★ ON THE CONTROL PLANE, because that is where the authority is. Asked of an Edge this answers "this
    // organization has none" — truthfully about that node, and wrongly about the organization, which would
    // hide the control on exactly the screen it belongs to.
    readExtra("/admin/tenant-transport-authority", undefined, "control").then((r) => {
      if (r.ok && r.body) _pkiTransportAuthority = r.body;
    }).catch(() => {}),
    readExtra("/admin/tenant-device-authority?readiness=1", undefined, "control").then((r) => {
      if (r.ok && r.body) _pkiDeviceAuthority = r.body;
    }).catch(() => {}),
    readExtra("/admin/tenant-interception-authority", undefined, "control").then((r) => {
      if (r.ok && r.body) _pkiInterceptionAuthority = r.body;
    }).catch(() => {}),
    // ★ FROM AN EDGE, because only an Edge sees a handshake. Asked of the control plane these answer nothing,
    // and a screen that showed that would offer the destructive half of every movement with no evidence.
    readExtra("/admin/transport-name-rename").then((r) => {
      if (r.ok && r.body) _pkiNameRename = r.body;
    }).catch(() => {}),
    readExtra("/admin/interception-authority-rotation").then((r) => {
      if (r.ok && r.body) _pkiInterceptionRotation = r.body;
    }).catch(() => {}),
  ]);

  const results = await Promise.all(_PKIMAP_NODES.map(async (node) => {
    try {
      const r = await apiFetch("GET", "/admin/pki/certificates", undefined, node.plane);
      if (!r.ok) return { node, error: "HTTP " + r.status, status: r.status };
      // ★★★ THE LABEL COMES FROM WHAT ANSWERED, NOT FROM WHERE WE ASKED (2026-09-05, measured). This screen
      // asks two addresses and calls one "Enforcement Edge"; on a deployment whose console front door
      // proxies both to the same node, it received the control plane's certificates twice and labelled half
      // of them as the Edge's. The Edge's own transport certificate, its transport anchors and the
      // organization's interception root were on no screen, and nothing said they were missing.
      const said = (r.body && r.body.measured_on) || "";
      return { node, items: (r.body && r.body.items) || [], measuredOn: said,
               label: said ? { en: said, ja: said } : node.label };
    } catch (e) {
      return { node, error: String(e) };
    }
  }));

  await extras;
  if (results.every((x) => x.error)) {
    if (!current()) return;
    // ★★ THE CHECKLIST SENDS PEOPLE HERE (2026-08-17, walked as the operator from a half-built organization's
    // setup list). "Device identity — not set: this organization's devices are not accepted. Open certificates"
    // landed on a screen whose entire content was "HTTP 403 / HTTP 403". The reason is real and knowable — the
    // organization has not delegated its management, so nothing here is readable — and a status code is not it.
    const refused = results.every((x) => x.status === 403 || x.status === 401);
    uiState(host, "error", refused
      ? bl({ en: "This tenant's certificates are not readable here. It has not delegated its management, so nothing on this screen can be shown or changed until it does.",
             ja: "このテナントの証明書はここでは取得できません。運営に管理を委任していないため、この画面は表示も変更もできません。" })
      : results.map((x) => x.error).join(" / "), {
      label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadCertMap(host),
    });
    return;
  }

  if (!current()) return;
  if (failedReads.size) {
    uiState(host, "error", bl({ en: "Required PKI information could not be read. Retry before changing certificates.", ja: "必要なPKI情報を取得できません。証明書を変更する前に再試行してください。" }),
      { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadCertMap(host) });
    return;
  }
  host.innerHTML = "";

  results.filter((x) => x.error).forEach(({ node, error }) => {
    host.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: bl(node.label) + " could not be reached (" + error + ") — its certificates are unknown, not fine.",
      ja: bl(node.label) + " に到達できません（" + error + "）。証明書の状態は不明です（正常という意味ではありません）。" }) }));
  });

  // Same material on both nodes is one fact, not two rows: merge by fingerprint, keep both node labels.
  // Active if ANY node still uses it.
  const merged = [];
  const byKey = {};
  const seenNodes = new Set();
  results.forEach(({ node, items, measuredOn, label }) => {
    // Two addresses that reached the same machine are one machine. Its certificates are listed once, under
    // the name it gave, rather than twice under two plane names it did not claim.
    if (measuredOn && seenNodes.has(measuredOn)) return;
    if (measuredOn) seenNodes.add(measuredOn);
    const named = Object.assign({}, node, label ? { label } : {});
    (items || []).forEach((item) => {
      const key = item.role + ":" + (item.sha256 || item.id);
      if (byKey[key]) { byKey[key].nodes.push(named); byKey[key].active = byKey[key].active || item.active; return; }
      const row = { item, nodes: [named], active: !!item.active };
      byKey[key] = row;
      merged.push(row);
    });
  });
  // ★ AND IF ONLY ONE MACHINE ANSWERED, THE SCREEN SAYS SO RATHER THAN IMPLYING IT SAW EVERY NODE.
  if (seenNodes.size === 1) {
    host.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "One machine answered (" + [...seenNodes][0] + "). Certificates held only by another node — an "
        + "Edge's transport certificate, its trust anchors, an organization's inspection root — are not on "
        + "this screen.",
      ja: "答えた機械は1台です（" + [...seenNodes][0] + "）。別のノードだけが持つ証明書 —— Edge の transport "
        + "証明書、その信頼アンカー、組織の傍受ルート —— はこの画面には出ていません。" }) }));
  }

  const inactiveCount = merged.filter((r) => !r.active).length;
  if (inactiveCount) {
    host.appendChild(el("div", { style: "margin-bottom:10px" }, [
      el("button", { class: "ui-btn ui-btn-sm",
        text: _pkiMapShowInactive
          ? bl({ en: "Hide unused (" + inactiveCount + ")", ja: "未使用を隠す（" + inactiveCount + "）" })
          : bl({ en: "Show unused (" + inactiveCount + ")", ja: "未使用を表示（" + inactiveCount + "）" }),
        onClick: () => { _pkiMapShowInactive = !_pkiMapShowInactive; loadCertMap(host); } }),
    ]));
  }

  _PKIMAP_SECTIONS.forEach((section) => {
    const rows = merged.filter((r) => (_PKIMAP_ROLES[r.item.role] || {}).section === section.id)
      // ★★ "NOBODY OWNS THIS" IS NOT "NOTHING USES THIS" (2026-08-19). An unattributed device-trust CA was
      // collapsed under "unused" like any leftover — so the one row an operator must act on, a CA that admits
      // devices which then resolve to no organization, sat behind a toggle with the badge naming the problem
      // behind it too. Verified by putting one on the lab: card, badge and act were all hidden by default.
      //
      // Filtered here rather than by calling it active: `active` is what the RETIRE act is gated on (a CA some
      // device still presents must not be retirable), and making an unowned CA look active would take the
      // withdrawal away — which the first version of this change did, and the screen showed it.
      .filter((r) => r.active || r.item.owner_unknown || _pkiMapShowInactive);
    // ★★ THE SECTION WAS HIDDEN FROM EXACTLY THE PEOPLE WHO NEEDED IT (2026-08-18). Sections render only when
    // they already hold a certificate — so a tenant with no interception authority of its own, whose traffic is
    // therefore REFUSED rather than inspected, saw no interception section at all, and with it no way to load
    // one. The same shape as the device-CA gap next door: the screen exists, works, and disappears in the one
    // state it was built for.
    // ...and only when that control will actually render. An operator answering for the whole deployment is
    // not in a tenant, so an empty section would be a heading over nothing.
    const sectionHasSetupControl = (section.id === "device" || section.id === "interception") && !pkiDeploymentAct();
    if (!rows.length && !sectionHasSetupControl) return;
    const heading = [el("h3", { class: "ui-view-title", style: "font-size:15px; margin:18px 0 8px", text: bl(section.title) })];
    // The same act used to sit on the section heading as well. One act, one place — on the certificate it
    // changes.
    host.appendChild(el("div", { style: "display:flex; align-items:center" }, heading));
    if (section.id === "device") host.appendChild(tenantDeviceCAControl(host));
    if (section.id === "device") {
      host.appendChild(tenantTransportAuthorityControl(host));
      // The other two movements of the same tier, in the order an operator meets them: what devices dial,
      // and what issues them. See pkiMovementCard — three authorities, one shape.
      host.appendChild(tenantNameControl(host));
      host.appendChild(tenantDeviceAuthorityControl(host));
    }
    if (section.id === "interception") host.appendChild(tenantInterceptionControl(host));
    if (section.id === "interception") host.appendChild(tenantInterceptionCAControl(host));
    if (section.id === "device" && _pkiOperation) {
      const stages = _pkiOperation.stages || [];
      const next = stages.find((st) => st.key === _pkiOperation.next_stage) || stages.find((st) => !st.done);
      const names = { distribute: { en: "Distribute it alongside the current one", ja: "現行と並べて配布" },
                      adopt: { en: "Wait until every device holds it", ja: "全端末が持つまで待つ" },
                      switch: { en: "Switch the Edge onto it", ja: "Edge をこれに切り替える" },
                      retire: { en: "Withdraw the others", ja: "他を撤回" } };
      host.appendChild(el("div", { class: "ui-card", style: "margin-bottom:10px" }, [
        el("div", { style: "display:flex; align-items:center; gap:10px; flex-wrap:wrap" }, [
          uiBadge(bl({ en: "rotation in progress", ja: "入れ替えが進行中" }), "warn"),
          el("strong", { text: bl({ en: "Next: ", ja: "次: " }) +
            (next && names[next.key] ? bl(names[next.key]) : "—") }),
          next && next.blocked
            ? el("span", { class: "ui-view-desc", text: next.blocked })
            : null,
          el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Stop tracking", ja: "追跡をやめる" }),
            onClick: async () => {
              await apiFetch("DELETE", "/admin/pki/operations");
              loadCertMap(host);
            } }),
        ].filter(Boolean)),
      ]));
    }
    rows.forEach((row) => host.appendChild(certMapCard(row, host)));
  });

  // TLS this node depends on whose certificate belongs to someone else — sign-in, the region link, the log
  // store, the archive. Nothing here can be replaced from this product, and that is exactly why they are
  // listed: an expiry on any of them takes a function down, and until now they appeared on no screen an
  // operator would think to check.
  if (_pkiExternal.length) {
    host.appendChild(el("h3", { class: "ui-view-title", style: "font-size:15px; margin:18px 0 8px",
      text: bl({ en: "Managed outside this product", ja: "この製品の外で管理されているもの" }) }));
    host.appendChild(el("table", { class: "ui-table" }, el("tbody", {}, _pkiExternal.map((p) => {
      const names = { identity_provider: { en: "Signing users in", ja: "利用者のサインイン" },
                      region_mesh: { en: "Talking to other regions", ja: "他リージョンとの連携" },
                      hot_store: { en: "Storing logs", ja: "ログの保存先" },
                      cold_archive: { en: "Long-term log archive", ja: "ログの長期保管先" } }[p.id];
      const addrs = (p.addresses || []).filter(Boolean);
      // Whether this link is TLS at all — the question the section is FOR. A plain-HTTP dependency listed on
      // a certificates screen without a word implies a certificate it does not have; see the server note on
      // pkiPath.Encrypted for the three states and why the third is stated rather than guessed.
      const enc = p.encrypted === "no"
        ? uiBadge(bl({ en: "not encrypted — no certificate here", ja: "暗号化なし — 証明書はありません" }), "warn")
        : p.encrypted === "yes"
          ? uiBadge(bl({ en: "TLS", ja: "TLS" }), "ok")
          : uiBadge(bl({ en: "not stated by its address", ja: "住所からは判断できません" }), "off");
      return el("tr", {}, [
        el("td", {}, uiBadge(bl({ en: "external", ja: "外部管理" }), "off")),
        el("td", {}, el("strong", { text: names ? bl(names) : p.id })),
        el("td", { class: "ui-view-desc", style: "word-break:break-all",
          text: addrs.length > 2 ? bl({ en: addrs.length + " endpoints", ja: addrs.length + " 件" }) : addrs.join(" / ") }),
        el("td", {}, enc),
      ]);
    }))));
  }
}

// One certificate, one card: identity line, where-used line, contents, actions.
function certMapCard(row, host) {
  const item = row.item;
  const meta = _PKIMAP_ROLES[item.role] || { title: { en: item.role, ja: item.role }, what: { en: "", ja: "" } };
  const days = item.not_after ? certDaysLeft(item.not_after) : null;

  const head = el("div", { style: "display:flex; align-items:center; gap:10px; margin-bottom:4px; flex-wrap:wrap" }, [
    el("strong", { text: meta.nick ? bl(meta.nick) : bl(meta.title) }),
    meta.nick ? el("span", { class: "ui-view-desc", text: bl(meta.title) }) : null,
    certExpiryBadge(days),
    item.count ? uiBadge(bl({ en: item.count + " device(s) issued", ja: "発行先 " + item.count + " 台" }), "ok") : null,
    // Chain length answered no question an operator has: how many certificates are in a file is a fact
    // about the file.
    null,
    item.self_signed ? uiBadge(bl({ en: "self-signed", ja: "自己署名" }), "off") : null,
    // ★ A device-trust CA the registry cannot place. It still admits devices, and a device admitted through it
    // resolves to no tenant — so it is named here rather than left as a blank column. Withdrawal is not
    // automatic: a machine may hold a certificate from this CA, and removing it locks that machine out.
    item.owner_unknown ? uiBadge(bl({ en: "no tenant — place or withdraw", ja: "テナント未設定 — 割当か撤回を" }), "warn") : null,
    !row.active ? uiBadge(bl({ en: "unused", ja: "未使用" }), "off") : null,
    // The node, only when more than one serves this certificate; with one it repeats the deployment.
  ].concat(row.nodes.length > 1 ? row.nodes.map((n) => uiBadge(bl(n.label), "off")) : []).filter(Boolean));

  // WHERE USED — composed from the server's relations, never guessed.
  const usedBits = [];
  if (item.presented_at && item.presented_at.length) {
    // Same rule as the paths view: 0.0.0.0 is where a process listens, not somewhere anything connects.
    const at = item.presented_at.map((a) => uiListen(a)).join(", ");
    usedBits.push(bl({ en: "Presented at: " + at, ja: "提示: " + at }));
  }
  (item.verified_by || []).forEach((rel) => {
    const t = _PKIMAP_RELS[rel];
    if (t) usedBits.push(bl(t));
  });
  (item.verifies || []).forEach((rel) => {
    const t = _PKIMAP_RELS[rel];
    if (t) usedBits.push(bl(t));
  });
  if (item.bundle_serial) {
    usedBits.push(bl({ en: "distribution serial " + item.bundle_serial, ja: "配布通番 " + item.bundle_serial }));
  }

  const children = [
    head,
    meta.use ? el("div", { style: "margin-top:4px; font-size:13px", text: bl(meta.use) }) : null,
    usedBits.length ? el("div", { class: "ui-view-desc", style: "margin-top:4px; font-size:12.5px", text: usedBits.join(" · ") }) : null,
  ];

  const pathFact = _pkiPathFacts[item.id] || {};
  if (pathFact.verifiedBy || pathFact.recoveryHours) {
    const bits = [];
    if (pathFact.verifiedBy) {
      bits.push(bl({ en: "The far end is checked against ", ja: "接続してくる側は " }) +
        uiCertName(pathFact.verifiedBy) + bl({ en: "", ja: " で確認されます" }));
    }
    if (pathFact.recoveryHours) {
      // "Renew for 720h past expiry" states a mechanism. What an operator needs to know is which machines
      // it saves: the ones that were switched off when their certificate ran out.
      const days = Math.round(pathFact.recoveryHours / 24);
      bits.push(bl({
        en: "A device switched off when its certificate expired can still come back on its own, for " + days + " days",
        ja: "証明書が切れた時に電源が入っていなかった端末も、切れてから " + days + " 日以内なら自力で復帰できます" }));
    }
    children.push(el("div", { class: "ui-view-desc", style: "margin-top:6px; font-size:12.5px",
      text: bits.join(" · ") }));
  }

  // Whether this one may be removed yet, and if not what is holding it. Same shape as the transport
  // anchor's: one question, answered the same way wherever it is asked.
  if (item.role === "device_client_ca" && !item.can_retire &&
      (item.retire_blocked_reason || item.retire_blocked_code)) {
    children.push(el("div", { class: "ui-view-desc", style: "margin-top:6px" },
      el("span", { text: bl({ en: "Cannot be retired yet: ", ja: "まだ撤回できません: " }) +
        pkiGateReason(item.retire_blocked_code, item.retire_blocked_reason, item.retire_blocked_params) })));
  }

  // Who is known to trust this certificate. For the interception root this is the fact that decides whether
  // it can ever be switched: without it a switch is blind, and a blind switch breaks every site at once on
  // any machine that missed the distribution.
  if ((item.trusted_by || []).length || (item.not_reporting || []).length) {
    const trusted = item.trusted_by || [];
    const silent = item.not_reporting || [];
    children.push(el("div", { style: "margin-top:8px; font-size:13px" }, [
      uiBadge(bl({ en: trusted.length + " of " + (trusted.length + silent.length) + " confirmed",
                   ja: "確認済み " + trusted.length + "/" + (trusted.length + silent.length) }),
        silent.length ? "off" : "ok"),
      trusted.length
        ? el("span", { class: "ui-view-desc", style: "margin-left:8px",
            text: bl({ en: "holds it: ", ja: "保持: " }) + trusted.join(", ") })
        : null,
      silent.length
        ? el("span", { class: "ui-view-desc", style: "margin-left:8px",
            title: bl({ en: "Not reported is not the same as not trusted.",
                        ja: "未報告は「信頼していない」ではありません。" }),
            text: bl({ en: "not reported: ", ja: "未報告: " }) + silent.join(", ") })
        : null,
    ].filter(Boolean)));
  }

  // How this certificate is replaced, always stated — including when the answer is "not from here". A card
  // that simply omits the control leaves an operator unable to tell a missing capability from a missing
  // button, and both look like the product cannot do it.
  if (meta.replace) {
    const how = {
      hot:           { en: "Replaced in place", ja: "無停止で差し替え" },
      overlap:       { en: "Added first, old one withdrawn after", ja: "先に追加し、後から旧を撤回" },
      reissue:       { en: "Re-issued to every device", ja: "全端末へ再発行" },
      redistribute:  { en: "Distributed to endpoints first", ja: "先に端末へ配布" },
      rotate:        { en: "Rotated in place", ja: "その場でローテート" },
      none:          { en: "Not from this screen", ja: "この画面からは不可" },
    }[meta.replace.how];
    children.push(el("div", { style: "margin-top:8px; font-size:13px" }, [
      uiBadge(bl(how), meta.replace.how === "none" ? "off" : "ok"),
      el("span", { class: "ui-view-desc", style: "margin-left:8px", text: bl(meta.replace.impact) }),
    ]));
  }

  // What the node concluded about this certificate when it started. A certificate the fleet will refuse can
  // be put in place by redeploying, and that path was unguarded until 2026-08-01; saying it only in a log
  // would repeat the failure this screen exists to prevent.
  if (item.startup_problem) {
    // The server's own sentence already opens with "devices would refuse this certificate:" — adding the
    // label again rendered the warning twice over ("Devices would refuse this certificate: devices would
    // refuse…"). Keep the label only for a problem that does not carry it.
    const alreadyLabelled = /would refuse this certificate/i.test(item.startup_problem);
    children.push(el("div", { class: "ui-state ui-state-error", style: "margin-top:8px" }, [
      el("span", { text: (alreadyLabelled ? "" : bl({
        en: "Devices would refuse this certificate: ", ja: "端末はこの証明書を受け付けません: " })) + item.startup_problem }),
    ]));
  }

  // CONTENTS — the fields a replacement can get wrong, always visible.
  // A distinguished name, a 64-character fingerprint and a machine timestamp are all correct data and none
  // of them is readable as-is. The name is the CN; the tenant gets its own line when it says something
  // the name does not; the fingerprint shows enough to compare and copies in full.
  const fields = [];
  if (item.subject) {
    fields.push([bl({ en: "Name", ja: "名前" }), uiCertName(item.subject)]);
    // ★★ WHOSE IT IS COMES FROM THE DEPLOYMENT'S RECORD, NOT FROM THE CERTIFICATE (2026-08-19). This row read
    // the subject's O= field, which is a string whoever minted the certificate typed. On the lab that produced
    // both errors at once: an interception root the registry attributes to an organization showed NO
    // organization (its subject carries no O=), while a device CA the registry attributes to nobody showed
    // "Lantern DSSE" because that is what its subject says. A boundary read out of the material it bounds is
    // not a boundary. Attributed or absent — the server names the organization or the row is not drawn.
    if (item.tenant_display_name) {
      fields.push([bl({ en: "Tenant", ja: "テナント" }), item.tenant_display_name]);
    }
  }
  if (item.issuer && item.issuer !== item.subject) {
    fields.push([bl({ en: "Issued by", ja: "発行元" }), uiCertName(item.issuer)]);
  }
  // Where this sits in the hierarchy, and whether it is limited in what it may issue for. The target is one
  // self-signed root with constrained intermediates beneath it (pki_ideal_lifecycle_design.ja.md); this
  // deployment has five self-signed CAs and no constraints, and until now that was invisible. A deviation
  // nobody can see is a deviation nobody fixes.
  if (item.self_signed) {
    fields.push([bl({ en: "Position", ja: "階層上の位置" }),
      bl({ en: "Its own root — issued by nothing above it", ja: "自分自身がルート（上位が無い）" })]);
  }
  if ((item.capabilities || []).length && /ca|root|anchor/.test(item.role || "")) {
    fields.push([bl({ en: "May issue for", ja: "発行できる範囲" }), item.name_constrained
      ? bl({ en: "A limited set of names", ja: "限定された名前のみ" })
      : bl({ en: "Any name — not limited", ja: "制限なし（あらゆる名前を発行できる）" })]);
  }
  const names = [].concat(item.dns_names || [], item.ip_addresses || []).join(", ");
  if (names) fields.push([bl({ en: "Valid for", ja: "有効な名前" }), names]);
  if (item.not_before || item.not_after) {
    fields.push([bl({ en: "Valid", ja: "有効期間" }), uiWhen(item.not_before) + " → " + uiWhen(item.not_after)]);
  }
  if (fields.length || item.sha256) {
    const rows = fields.map(([k, v]) => el("tr", {}, [
      el("td", { style: "white-space:nowrap; opacity:.75; padding-right:12px", text: k }),
      el("td", { style: "word-break:break-all", text: v }),
    ]));
    if (item.sha256) {
      rows.push(el("tr", {}, [
        el("td", { style: "white-space:nowrap; opacity:.75; padding-right:12px",
          text: bl(item.role === "agent_policy_signing_key"
            ? { en: "Public key", ja: "公開鍵" } : { en: "Fingerprint", ja: "指紋" }) }),
        el("td", {}, uiFingerprint(item.sha256)),
      ]));
    }
    children.push(el("table", { class: "ui-table", style: "margin-top:8px" }, el("tbody", {}, rows)));
  }


  // ACTIONS — only what the server said is possible for this material on this node.
  const caps = item.capabilities || [];
  const actions = [];
  // Replace and history act on ONE node's listener even when both serve the same material, so a merged row
  // offers them per node — hot-reload happens where the button says it does, nowhere else.
  // Replacing the certificate this node SERVES became an operator act on 2026-08-17 (admin.certs.write moved
  // to super_admin, because it is the certificate every organization's devices are presented with). "Renew all
  // devices" below is NOT in that set — it is admin.endpoints.write, an organization's own fleet — so it stays.
  if (caps.indexOf("replace") >= 0 && pkiDeploymentAct()) {
    row.nodes.forEach((node) => {
      actions.push(el("button", { class: "ui-btn ui-btn-sm",
        text: bl({ en: "Replace", ja: "差し替え" }) + (row.nodes.length > 1 ? " — " + bl(node.label) : ""),
        onClick: () => openRotateForm(node, item, host) }));
    });
  }
  if (caps.indexOf("history") >= 0) {
    row.nodes.forEach((node) => {
      actions.push(el("button", { class: "ui-btn ui-btn-sm",
        text: bl({ en: "History / roll back", ja: "履歴・切り戻し" }) + (row.nodes.length > 1 ? " — " + bl(node.label) : ""),
        onClick: () => showCertHistory(node, certNameOf(item), host) }));
    });
  }
  if (caps.indexOf("download") >= 0 && item.pem) {
    actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Download PEM", ja: "PEM をダウンロード" }),
      title: meta.install ? bl(meta.install) : undefined,
      onClick: () => pkiDownloadPEM(item) }));
  }
  if (caps.indexOf("rotate_signer") >= 0 && pkiDeploymentAct()) {
    actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Rotate signer", ja: "署名者をローテート" }),
      onClick: () => rotateInterceptionSigner(row.nodes[0], host) }));
  }
  if (caps.indexOf("renew_all") >= 0) {
    actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Renew all devices now", ja: "全端末をいま更新" }),
      onClick: () => renewAllDevices(row.nodes[0], host) }));
    // Per-device certificate facts live on the Devices page — a device's certificate is a fact about the
    // device (operator decision 2026-07-31), so this points there rather than at a separate listing.
    actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Devices", ja: "デバイス一覧へ" }),
      onClick: () => renderGroup("enrolled") }));
  }
  // Retiring a CA from device trust: offered only on the unused ones — the server's gate refuses while any
  // observed device still chains from it, and the active flag is that same evidence.
  if (caps.indexOf("retire") >= 0 && !row.active && pkiDeploymentAct()) {
    actions.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Retire from device trust", ja: "信頼から外す" }),
      onClick: async () => {
        const ok = await uiConfirm({
          title: bl({ en: "Retire " + shortSubject(item.subject) + "?", ja: shortSubject(item.subject) + " を信頼から外しますか?" }),
          body: bl({
            en: "New device handshakes stop accepting certificates from this CA immediately. Adding it back is a single action.",
            ja: "以後の端末接続で、この CA から発行された証明書は受け付けられなくなります。戻すのは「追加」1回です。" }),
          confirmLabel: bl({ en: "Retire", ja: "外す" }),
        });
        if (!ok) return;
        const r = await apiFetch("DELETE", "/admin/device-client-cas/" + encodeURIComponent(item.sha256), undefined, row.nodes[0].plane);
        if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
        uiToast(bl({ en: "Retired.", ja: "外しました。" }), "ok");
        loadCertMap(host);
      } }));
  }
  // ★★ THE OTHER HALF OF "place or withdraw" (2026-08-19). The badge on an unattributed device-trust CA says
  // both, and only withdrawal was ever offered — while withdrawal is the half that locks machines out and
  // placing is the safe one. The act existed (POST /admin/tenant-cas records the owner) and the screen holding
  // the problem did not lead to it, so the reader was told what to do and left to find where.
  //
  // The certificate is carried over, so the operator is not asked to copy a PEM out of one card and into
  // another form to answer a question this screen already knows the subject of.
  if (caps.indexOf("place") >= 0 && pkiDeploymentAct()) {
    actions.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-primary",
      text: bl({ en: "Place with an organization", ja: "組織に割り当てる" }),
      onClick: () => openTenantDeviceCAForm(host, item.pem) }));
  }
  // Install material for endpoint trust stores: the PEM, and an MDM profile generated in place.
  if (item.role === "interception_root" && item.pem) {
    actions.push(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "MDM profile (.mobileconfig)", ja: "MDM プロファイル(.mobileconfig)" }),
      onClick: () => pkiDownloadMobileconfig(item) }));
  }
  // Applied is not adopted: a hot reload changes only NEW connections, so the fleet is split until every
  // device re-handshakes. Named devices, because "2 of 3" tells you to wait and only the name tells you which.
  const ad = item.adoption;
  if (ad && ad.serving_fingerprint) {
    // Three states, not two: a device still holding the previous certificate is a replacement in flight;
    // an identity that has never handshaked (a connector does not use this transport) is a different fact
    // and must not read as one, or the badge would be permanently wrong.
    const stale = ad.on_previous || [];
    const unseen = ad.not_seen || [];
    // Only the SPLIT is worth a badge. "No device is on an older one" describes an ordinary Tuesday, and a
    // card that speaks when nothing is wrong teaches an operator to stop reading it.
    if (stale.length) {
      head.appendChild(uiBadge(bl({ en: "not on every device yet", ja: "未到達の端末あり" }), "off"));
    }
    if (stale.length) {
      children.push(el("div", { style: "margin-top:6px; font-size:13px",
        title: bl({ en: "They keep the certificate they handshook with until they reconnect.",
                    ja: "再接続するまで、接続時の証明書を保持し続けます。" }) }, [
        el("span", { style: "font-weight:600", text: bl({ en: "Still on the previous certificate: ", ja: "以前の証明書のまま: " }) }),
        el("span", { class: "ui-view-desc", text: stale.join(", ") }),
      ]));
    }
    // "Never handshaked here" listed identities that do not use this transport at all — a connector is not
    // a problem to be solved. Dropped.
    // The devices that ARRIVED are the ordinary case; naming them all on every card is a fleet listing on a
    // certificate's page.
    // A device that REFUSED is not a device that has not arrived yet, and until now the two were the same
    // row of silence. What a device declined, and why, in its own words.
    // Device, what happened, how many times — three columns, in that order. Rendered as one run-on line it
    // read as "拒否（差し替え済み）win-dev-1x509: certificate signed by unknown authority (possibly because…"
    // and told an operator nothing they could use. The verifier's own words are kept, on demand: they are
    // evidence, and evidence is worth reading exactly once, when you go looking for it.
    // Refusals are a log. A log is what an operator goes to AFTER something is wrong; it is not a property
    // of the certificate, and printing it here made every card carry a history nobody asked for. What IS a
    // property of this certificate is whether anything is refusing it RIGHT NOW.
    // ★★ "THE CERTIFICATE IS CURRENT" IS NOT "THE REFUSAL IS HAPPENING" (2026-08-19, seen on the lab within
    // the hour). served_is_current says the refused certificate is the one being served — a property of the
    // CERTIFICATE — and this rendered it as "refusing right now", a property of the DEVICE. A refusal from a
    // window that was fixed twenty-eight minutes earlier, with dozens of successful handshakes since, sat on
    // the screen telling an operator their fleet was rejecting the certificate at that moment.
    //
    // For a reader those are opposite instructions: one says stop and fix, the other says a thing that already
    // ended. Recency is the missing half — the report carries last_at — so a refusal is only spoken of in the
    // present tense while it is recent enough to still be true.
    const refusalIsRecentMinutes = 15;
    const nowMs = Date.now();
    const refusingNow = (_pkiRefusals || []).filter((r) => {
      // ★★★ ONLY A KNOWN false HIDES IT (2026-09-05). served_is_current is now three-valued — true, false, or
      // null when the answering node cannot say what it is serving — and `!r.served_is_current` swallowed the
      // third. Measured on a live deployment: the inventory and the refusal named the same certificate,
      // 265b7f2f…, the flag came back false because the node could not read its own served leaf, and a device
      // refusing the Edge every few minutes appeared on no screen. "We do not know" must show the refusal;
      // only "we know this is about a certificate we replaced" may hide it.
      if (r.served_is_current === false) return false;
      const last = Date.parse(r.last_at || "");
      if (isNaN(last)) return true; // no timestamp: say it rather than hide it
      return (nowMs - last) <= refusalIsRecentMinutes * 60 * 1000;
    });
    if (refusingNow.length) {
      const who = [...new Set(refusingNow.map((r) => r.device_identity))];
      children.push(el("div", { class: "ui-state ui-state-error", style: "margin-top:8px" },
        el("span", { text: bl({ en: "Refusing this certificate now: " + who.join(", "),
                                ja: "いまこの証明書を拒否しています: " + who.join("、") }) })));
    }
  }

  // The per-device trust facts and the withdrawal gate, on the certificate they are about.
  if (item.role === "transport_anchor") {
    const a = _pkiMapAnchorInfo[item.sha256];
    if (a) {
      if (a.issues_current) head.appendChild(uiBadge(bl({ en: "issues the current identity", ja: "現行の発行元" }), "ok"));
      const r = a.readiness;
      if (r) {
        head.appendChild(uiBadge(bl({ en: r.ready_pct + "% trusted", ja: "信頼済み " + r.ready_pct + "%" }), r.safe_to_cut ? "ok" : "off"));
        const elsewhere = (_pkiAnchorScope && _pkiAnchorScope.devices_withheld_other_organizations) || 0;
        if (elsewhere > 0) {
          children.push(el("p", { class: "ui-view-desc", text: bl({
            en: "This decision also counts " + elsewhere + " machine(s) in other organizations. They are not listed here, and a refusal may name them.",
            ja: "この判断には、ほかの組織の端末 " + elsewhere + " 台も入っています。ここには表示しませんが、断られたときにその名前が出ることがあります。" }) }));
        }
        const never = r.never_reported_anything || [];
        const quiet = (r.silent || []).filter((d) => never.indexOf(d) < 0);
        const trustRows = [];
        const row = (label, list, tip) => { if (list && list.length) trustRows.push(el("div", { title: tip || undefined }, [
          el("span", { style: "font-weight:600", text: label + " (" + list.length + "): " }),
          el("span", { class: "ui-view-desc", text: list.join(", ") })])); };
        // Only what stands between here and being able to retire this certificate. The devices that already
        // trust it, and the ones a person has vouched for, are settled — listing them turned a gate into a
        // fleet roster, on a page about a certificate. Who vouched is kept in the audit record, which is
        // where that question is actually asked.
        row(bl({ en: "Not yet", ja: "まだ持っていない" }), r.not_ready,
            bl({ en: "Resolves when the device takes the current distribution.",
                 ja: "端末が現在の配布を採用すると解消します。" }));
        row(bl({ en: "Not reporting", ja: "報告が無い" }), quiet,
            bl({ en: "Resolves once the agent reports.", ja: "エージェントの報告で解消します。" }));
        row(bl({ en: "Never reported", ja: "一度も報告なし" }), never,
            bl({ en: "Switched off, or an identity with no agent.", ja: "電源断か、エージェントを持たない識別子です。" }));
        never.forEach((identity) => {
          trustRows.push(el("button", { class: "ui-btn ui-btn-sm", style: "margin-top:4px",
            text: bl({ en: "Confirm " + identity + " trusts this", ja: identity + " の信頼を確認済みにする" }),
            onClick: () => pkiMapVouch(a, identity, host) }));
        });
        if (trustRows.length) children.push(el("div", { style: "margin-top:8px; display:flex; flex-direction:column; gap:2px" }, trustRows));
      }
      // The replacement path, on the certificate it is about. "Add" lived on the section heading and
      // "withdraw" only appeared when the gate was already open, so a card whose method line says
      // "added first, old one withdrawn after" offered neither and read as un-replaceable.
      // The button says what the sentence above it says. "Add its replacement" invented a second vocabulary
      // for one act and left an operator to work out whether something would be removed — which is exactly
      // the thing this method does NOT do.
      if (pkiDeploymentAct()) {
        actions.push(el("button", { class: "ui-btn ui-btn-sm",
          text: bl({ en: "Distribute another one alongside", ja: "もう1枚を並べて配布" }),
          onClick: () => pkiMapAddTrustCertificate(host) }));
      }
      if (a.can_withdraw && pkiDeploymentAct()) {
        actions.push(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger",
          text: bl({ en: "Withdraw this certificate", ja: "この証明書を撤回" }),
          onClick: () => pkiMapWithdraw(a, host) }));
      } else if (a.withdraw_blocked_reason || a.withdraw_blocked_code) {
        children.push(el("div", { class: "ui-view-desc", style: "margin-top:6px",
          text: bl({ en: "Withdrawal blocked: ", ja: "撤回不可: " }) +
            pkiGateReason(a.withdraw_blocked_code, a.withdraw_blocked_reason, a.withdraw_blocked_params) }));
      }
    }
  }
  if (item.role === "interception_intermediate" && _pkiMapCustody) {
    const cust = _pkiMapCustody.key_custody || {};
    const kind = String(cust.custody || "");
    const custodyChips = [
      uiBadge(kind.indexOf("pkcs11") >= 0 ? bl({ en: "key in a PKCS#11 token", ja: "鍵は PKCS#11 トークン内" })
        : bl({ en: "key on the host", ja: "鍵はホスト上" }), kind.indexOf("pkcs11") >= 0 ? "ok" : "off"),
      cust.non_exportable === true ? uiBadge(bl({ en: "non-exportable", ja: "エクスポート不可" }), "ok") : null,
      cust.healthy === true ? uiBadge(bl({ en: "signing works", ja: "署名可能" }), "ok")
        : uiBadge(bl({ en: "cannot sign", ja: "署名不可" }), "off"),
    ].filter(Boolean);
    children.push(el("div", { style: "margin-top:8px; display:flex; gap:8px; flex-wrap:wrap",
      title: cust.checked_at ? bl({ en: "Last checked by signing: ", ja: "最終署名確認: " }) + cust.checked_at : undefined }, custodyChips));
    if ((_pkiMapCustody.name_constraints || []).length) {
      children.push(el("div", { class: "ui-view-desc", style: "margin-top:4px",
        text: bl({ en: "May issue only for: ", ja: "発行できる範囲: " }) + _pkiMapCustody.name_constraints.join(", ") }));
    }
    // ★★ WHETHER THIS SIGNER SIGNS ANYTHING (2026-08-19). The card stated the key's custody and that signing
    // WORKS, which reads as "this is the authority in use" — and on this deployment it signs for nobody: every
    // organization has an authority of its own. Measured the day two regions were found signing one
    // organization differently, where believing the deployment still signed under the provider's root is part
    // of why the difference looked like it could not matter.
    //
    // The list is the server's answer, not a count taken here: an empty list means retirable, and a screen
    // that inferred that from "no per-tenant issuers visible" would be inventing it (the mistake this file
    // already carries a note about, one function down).
    const signsFor = _pkiMapCustody.node_wide_intermediate_signs_for;
    if (Array.isArray(signsFor)) {
      children.push(el("div", { class: "ui-view-desc", style: "margin-top:4px",
        text: signsFor.length
          ? bl({ en: "Signs for: ", ja: "署名している組織: " }) + signsFor.join(", ")
          : bl({ en: "Signs for no organization — every one of them has an authority of its own, so this one can be retired.",
                 ja: "どの組織のためにも署名していません（全組織が自前の権威を持っています）。撤去できます。" }) }));
    }
  }

  if (actions.length) {
    children.push(el("div", { class: "ui-row-actions", style: "margin-top:8px; display:flex; gap:6px; flex-wrap:wrap" }, actions));
  }

  return el("div", { class: "ui-card", style: "margin-bottom:10px" }, children.filter(Boolean));
}

function pkiMapAddTrustCertificate(host, onDone) {
  const pemA = el("textarea", { class: "ui-textarea", placeholder: "-----BEGIN CERTIFICATE-----" });
  pemA.style.minHeight = "140px";
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Add", ja: "追加" }) });
  const m = uiModal({
    title: bl({ en: "Distribute another certificate alongside", ja: "もう1枚を並べて配布" }),
    body: [
      el("p", { class: "ui-view-desc", text: bl({
        en: "The current certificate keeps working. Devices pick this one up as well, and once every device "
          + "has it you can withdraw the old one. Nothing is removed by this step.",
        ja: "いまの証明書はそのまま動きます。端末はこれも受け取り、全端末が持った時点で旧いものを撤回できます。"
          + "この操作では何も外れません。" }) }),
      pemA,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    submit.disabled = true;
    const r = await apiFetch("POST", "/admin/transport-trust-anchors", { certificate_pem: pemA.value });
    if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
    m.close();
    // ★ THE LIST BELOW IS WHAT ONE REGION IS SERVING, AND THIS WAS WRITTEN WHERE EVERY REGION READS IT.
    // The two are seconds apart, and without saying so the screen reads as though the write was lost.
    uiToast(bl({
      en: "Added — serial " + (r.body && r.body.serial) + ". Every region picks it up on its next pull.",
      ja: "追加しました — 配布通番 " + (r.body && r.body.serial) + "。各区域は次の取得で受け取ります。" }), "ok");
    (onDone || (() => loadCertMap(host)))();
  });
}

async function pkiMapWithdraw(anchor, host, onDone) {
  const ok = await uiConfirm({
    title: bl({ en: "Withdraw " + (anchor.subject || "") + "?", ja: (anchor.subject || "") + " を撤回しますか?" }),
    body: bl({
      en: "Removed from distribution; devices drop it on their next fetch. Adding it back is a single action.",
      ja: "配布から外れ、端末は次回取得時に信頼を落とします。戻すのは「追加」1回です。" }),
    confirmLabel: bl({ en: "Withdraw", ja: "撤回" }),
  });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/transport-trust-anchors/" + encodeURIComponent(anchor.sha256));
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Withdrawn — serial " + (r.body && r.body.serial), ja: "撤回しました — 配布通番 " + (r.body && r.body.serial) }), "ok");
  (onDone || (() => loadCertMap(host)))();
}

async function pkiMapVouch(anchor, identity, host) {
  const reason = window.prompt(bl({
    en: "How do you know " + identity + " trusts this certificate?",
    ja: identity + " がこの証明書を信頼していると、どうして分かりますか？" }), "");
  if (reason === null) return;
  const r = await apiFetch("POST", "/admin/transport-trust-anchors/" + encodeURIComponent(anchor.sha256) + "/acknowledge",
    { identity: identity, reason: reason });
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Recorded as your assertion.", ja: "あなたの言明として記録しました。" }), "ok");
  loadCertMap(host);
}

// The one clause of a verifier's message that an operator acts on. Apple and Go phrase the same refusal
// differently and both are long; the difference that matters is which of a handful of things went wrong.
function pkiRefusalReason(raw) {
  const s = String(raw || "");
  if (/not trusted|unknown authority|signed by unknown/i.test(s)) {
    return bl({ en: "did not trust the certificate", ja: "この証明書を信頼できなかった" });
  }
  if (/expired|has expired/i.test(s)) return bl({ en: "the certificate had expired", ja: "証明書が期限切れだった" });
  if (/hostname|name mismatch|does not match/i.test(s)) {
    return bl({ en: "the name did not match", ja: "名前が一致しなかった" });
  }
  return s.length > 80 ? s.slice(0, 80) + "…" : s;
}

function shortSubject(subject) {
  const m = /CN=([^,]+)/.exec(subject || "");
  return m ? m[1] : subject;
}

// The name PUT /admin/certs/{name} expects — the server states it on the item.
function certNameOf(item) {
  return item.cert_name || (item.id || "").split(":")[1] || item.id;
}

function certNames(c) {
  return [].concat(c.dns_names || [], c.ip_addresses || []).join(", ");
}

async function renewAllDevices(node, host) {
  const ok = await uiConfirm({
    title: bl({ en: "Ask every device to renew now?", ja: "全端末にいま更新を要求しますか?" }),
    body: bl({
      en: "Declares certificates issued before now stale. Each device renews the next time it fetches its policy; one that is switched off renews when it returns. Established connections are not touched.",
      ja: "現在より前に発行された証明書を陳腐と宣言します。各端末は次のポリシー取得時に更新し、電源断の端末は復帰時に更新します。確立済みの接続には触れません。" }),
    confirmLabel: bl({ en: "Renew all", ja: "全端末を更新" }),
  });
  if (!ok) return;
  const r = await apiFetch("POST", "/admin/device-certificates/renew-all", {}, node.plane);
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  const affected = (r.body && r.body.known_affected) || [];
  uiToast(bl({ en: "Declared. Known affected now: " + (affected.join(", ") || "none"),
               ja: "宣言しました。現時点の対象: " + (affected.join("、") || "なし") }), "ok");
  loadCertMap(host);
}

async function rotateInterceptionSigner(node, host) {
  const ok = await uiConfirm({
    title: bl({ en: "Rotate the signing intermediate?", ja: "署名用の中間 CA をローテートしますか?" }),
    body: bl({
      en: "A new intermediate is issued by the same root and starts signing immediately. Endpoints keep trusting the root — nothing is re-provisioned, no connection is interrupted.",
      ja: "同じルートが新しい中間 CA を発行し、直ちに署名を開始します。端末はルートを信頼したままです — 再配布は不要で、接続も切れません。" }),
    confirmLabel: bl({ en: "Rotate", ja: "ローテート" }),
  });
  if (!ok) return;
  const r = await apiFetch("POST", "/admin/interception-intermediate/rotate", {}, node.plane);
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Rotated.", ja: "ローテートしました。" }), "ok");
  loadCertMap(host);
}

// The replace form. The private key is pasted and sent; it is never rendered back and never kept in the page.
function openRotateForm(node, cert, host, onDone) {
  const name = certNameOf(cert);
  const certA = el("textarea", { class: "ui-textarea", placeholder: "-----BEGIN CERTIFICATE-----" }); certA.style.minHeight = "120px";
  const keyA = el("textarea", { class: "ui-textarea", placeholder: "-----BEGIN PRIVATE KEY-----" }); keyA.style.minHeight = "120px";
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Replace certificate", ja: "証明書を差し替え" }) });

  const currentNames = certNames(cert) || "—";
  const warning = el("div", { class: "ui-preview", style: "margin-top:10px" }, [
    el("div", { text: bl({
      en: "Currently valid for: " + currentNames + ". A replacement that drops one of these breaks whatever relies on it.",
      ja: "現在有効な名前: " + currentNames + "。これらを欠く差し替えは、それに依存する相手を壊します。" }) }),
    cert.self_signed ? el("div", { text: bl({
      en: "This certificate is self-signed: peers trust the certificate itself. Add the new one to every peer that trusts it before switching.",
      ja: "この証明書は自己署名です。相手はこの証明書そのものを信頼しているため、切り替える前に、信頼している側へ新しいものを追加してください。" } ) }) : null,
    el("div", { text: bl({
      en: "Applied means NEW connections only. Devices keep the certificate they handshook with until they reconnect, so watch this card until every device is on it — a replacement devices cannot verify looks fine until then.",
      ja: "適用されるのは新しい接続だけです。端末は再接続するまで接続時の証明書を保持するため、全端末が新しい証明書になるまでこのカードで確認してください — 端末が検証できない証明書でも、それまでは正常に見えます。" }) }),
    el("div", { text: bl({
      en: "The current one is kept as a version and can be restored from History.",
      ja: "現在の証明書は版として保持され、「履歴・切り戻し」から戻せます。" }) }),
  ].filter(Boolean));

  const m = uiModal({
    title: bl({ en: "Replace ", ja: "差し替え: " }) + name + " — " + bl(node.label),
    body: [
      el("p", { class: "ui-view-desc", text: bl({
        en: "Paste the new certificate and its private key (PEM). Validated before it goes live; applied with no restart.",
        ja: "新しい証明書と秘密鍵(PEM)を貼り付けてください。適用前に検証し、無停止で反映されます。" }) }),
      el("div", { class: "ui-field-label", text: bl({ en: "Certificate (PEM)", ja: "証明書(PEM)" }) }), certA,
      el("div", { class: "ui-field-label", style: "margin-top:10px", text: bl({ en: "Private key (PEM)", ja: "秘密鍵(PEM)" }) }), keyA,
      warning,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });

  submit.addEventListener("click", async () => {
    if (!certA.value.trim() || !keyA.value.trim()) {
      uiToast(bl({ en: "Both the certificate and the key are required.", ja: "証明書と秘密鍵の両方が必要です。" }), "err");
      return;
    }
    submit.disabled = true;
    try {
      const r = await apiFetch("PUT", "/admin/certs/" + encodeURIComponent(name),
        { cert_pem: certA.value, key_pem: keyA.value }, node.plane);
      if (!r.ok) { submit.disabled = false; uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
      m.close();
      uiToast(bl({
        en: "Replaced on " + bl(node.label) + ". If peers stop connecting, roll back from History.",
        ja: bl(node.label) + " で差し替えました。相手が繋がらなくなった場合は「履歴・切り戻し」から戻してください。" }), "ok");
      (onDone || (() => loadCertMap(host)))();
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
}

async function showCertHistory(node, name, host) {
  const bodyHost = el("div", {}, el("span", { class: "ui-spinner" }));
  const m = uiModal({
    title: bl({ en: "History — ", ja: "履歴 — " }) + name + " — " + bl(node.label),
    body: [bodyHost],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Close", ja: "閉じる" }), onClick: () => m.close() })],
  });
  const load = async () => {
  uiState(bodyHost, "loading");
  try {
    const r = await apiFetch("GET", "/admin/certs/" + encodeURIComponent(name) + "/versions", undefined, node.plane);
    const versions = r.body && (r.body.versions || r.body);
    if (!r.ok || !Array.isArray(versions)) throw new Error("Certificate history unavailable");
    bodyHost.innerHTML = "";
    if (!versions.length) {
      bodyHost.appendChild(el("p", { class: "ui-view-desc", text: bl({
        en: "No previous versions. This certificate has not been replaced through the Console or the API.",
        ja: "過去の版はありません。この証明書は Console や API から差し替えられていません。" }) }));
      return;
    }
    versions.forEach((v) => {
      const no = v.version_no != null ? v.version_no : v.version;
      bodyHost.appendChild(el("div", { class: "ui-toolbar" }, [
        el("span", { text: "v" + no + " · " + fmtT(v.created_at || v.applied_at) }),
        el("span", { class: "ui-spacer" }),
        el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Roll back", ja: "戻す" }), onClick: async () => {
          const ok = await uiConfirm({
            title: bl({ en: "Roll back to v" + no + "?", ja: "v" + no + " に戻しますか?" }),
            body: bl({
              en: "Restores that certificate and its key on " + bl(node.label) + ".",
              ja: bl(node.label) + " にその証明書と秘密鍵を復元します。" }),
            confirmLabel: bl({ en: "Roll back", ja: "戻す" }),
          });
          if (!ok) return;
          const rr = await apiFetch("POST", "/admin/certs/" + encodeURIComponent(name) + "/rollback", { version_no: no }, node.plane);
          if (!rr.ok) { uiToast((rr.body && (rr.body.error || rr.body.message)) || ("HTTP " + rr.status), "err"); return; }
          uiToast(bl({ en: "Rolled back.", ja: "戻しました。" }), "ok");
          m.close();
          loadCertMap(host);
        } }),
      ]));
    });
  } catch (e) {
    uiState(bodyHost, "error", bl({ en: "Certificate history could not be read.", ja: "証明書の履歴を取得できません。" }),
      { label: bl({ en: "Retry", ja: "再試行" }), onClick: load });
  }
  };
  await load();
}


// ★★★ THE ONE BLOCKING ITEM A NEW ORGANIZATION COULD NOT CLEAR FROM ANY SCREEN (2026-08-17, found by creating
// an organization and following its own checklist). "Device identity" is what makes an organization's devices
// admissible as ITS devices, it is marked blocking, and its "set it" button lands here — on a screen that had
// no way to register one. The route has existed the whole time (POST /admin/tenant-cas, with the cross-tenant
// guard on it); nothing in the Console called it. Measured with grep: zero references.
//
// So a new organization could be created, delegated, given an administrator and rules, and never reach
// "working", with the product's own checklist pointing at a screen that could not finish the job.
// ★★ THE TENANT ADMINISTRATOR REPLACES THEIR OWN INTERCEPTION AUTHORITY — AND HAD NO SCREEN (2026-08-18,
// measured with grep: the Console referenced /admin/interception-intermediate exactly twice, both for the
// node-wide rotate an operator performs).
//
// This is the certificate that decrypts their people's traffic. The product's position is that it belongs to
// the tenant and not to the MSSP, that the two PKIs are independent, and that the tenant's own administrator
// performs the replacement. The route has carried the cross-tenant guard the whole time
// (admin.policy.write|admin.tenant.admin, object-scoped); nothing called it on the tenant's behalf.
//
// Without it the tenant's only path was to ask the operator — which is the arrangement being retired, and
// which puts the MSSP's hands on the material the whole design says it must not hold.
// tenantTransportAuthorityControl is where an organization's own transport authority is replaced.
//
// ★ THE ACT EXISTED ONLY AS AN API UNTIL THIS (2026-08-20). The machinery to move an organization onto a new
// authority — hand both to every Edge, announce them together, switch each Edge once its devices are measured
// holding the new one, then retire the old — was built, proven on the lab and reachable only with curl. A
// control an operator cannot reach is not a control, and the fallback they would have used instead (delete the
// authority, create another) is the order that cut a device off for half an hour.
//
// Two buttons because they are two decisions. Adding takes nothing away and can be done whenever. Retiring
// destroys what some Edge may still be presenting, so it is offered only while a rotation is actually in
// flight, and its wording says what it ends rather than what it removes.
// pkiMovementCard is the one shape every authority movement in this product has, so an operator learns it
// once: what is in force, what (if anything) is being moved to, what that is waiting for, and the two or
// three buttons that start it, finish it, or take it back.
//
// ★★★ WHY IT EXISTS (2026-08-22, measured by walking this Console). An organization has three authorities and
// fourteen acts between them. This file called THREE. Every way back, everything about device identity and
// everything about interception was API-only — which on this product means it did not exist, because the
// people who run it do not have a terminal. A screen that can only describe is not a screen.
//
// ★ AND THE DESTRUCTIVE HALF IS NEVER OFFERED WITHOUT ITS EVIDENCE. "Finish" carries the Edge's own answer
// about who has not moved; when the answer says not yet, the button is not there and the reason is, in the
// words of the person reading it rather than the field name it came from.
function pkiMovementCard(opts) {
  const card = el("div", { class: "ui-card", style: "margin-bottom:12px" });
  const busy = (b, on) => { b.disabled = on; b.textContent = on ? bl({ en: "Working…", ja: "実行中…" }) : b._label; };
  const act = (label, path, done, kind) => {
    const b = el("button", { class: "ui-btn ui-btn-sm" + (kind ? " " + kind : ""), text: label });
    b._label = label;
    b.addEventListener("click", async () => {
      busy(b, true);
      const r = await apiFetch("POST", path, {});
      busy(b, false);
      if (!r.ok) {
        uiToast(((r.body && r.body.error) || ("HTTP " + r.status)), "err");
        return;
      }
      uiToast(done, "ok");
      loadCertMap(opts.host);
    });
    return b;
  };
  const buttons = (opts.actions || []).filter(Boolean).map((a) => act(a.label, a.path, a.done, a.kind));
  card.appendChild(el("div", { style: "display:flex; align-items:center; gap:10px; flex-wrap:wrap" },
    [el("strong", { text: opts.title }), opts.badge || null, el("span", { style: "flex:1 1 auto" })]
      .concat(buttons).filter(Boolean)));
  if (opts.now) {
    card.appendChild(el("div", { class: "ui-view-desc", style: "margin-top:6px" }, [
      el("span", { text: opts.nowLabel }), el("strong", { text: " " + opts.now }),
    ]));
  }
  if (opts.waiting) {
    card.appendChild(el("div", { class: "ui-view-desc", style: "margin-top:6px" }, [
      el("span", { text: opts.waiting }),
    ]));
  }
  return card;
}

// pkiWaitingFor turns a readiness answer into the sentence an operator needs: who has not moved, by name.
// Never the raw field, and never a count on its own — "2 of 3" does not tell somebody which laptop to go and
// switch on.
function pkiWaitingFor(names, whenReady) {
  const who = (names || []).filter(Boolean);
  if (!who.length) return whenReady;
  return bl({ en: "Waiting for: ", ja: "待っているもの: " }) + who.join(", ");
}

// tenantNameControl is the name this organization's devices dial. Changing it is a MOVEMENT, not an edit:
// both names are served while devices move over, and the old one is dropped only when every device has said
// it is sending the new one.
//
// ★ IT IS ALSO THE ONE THING A STRANGER CAN SEE. A name taken from the company's own name answers "is this
// customer here" to anybody who can reach the port, with no credential. That is why this exists as a control
// and not as a field somebody edits in a store.
function tenantNameControl(host) {
  if (pkiDeploymentAct()) return el("div", { style: "display:none" });
  const st = _pkiTransportAuthority || {};
  if (!st.has_authority) return el("div", { style: "display:none" });
  const ready = _pkiNameRename || {};
  const moving = !!st.renaming;
  const mayFinish = moving && ready.may_retire_previous === true;
  return pkiMovementCard({
    host,
    title: bl({ en: "The name this tenant's devices dial", ja: "このテナントの端末が名乗る名前" }),
    badge: moving ? uiBadge(bl({ en: "being changed", ja: "変更中" }), "warn") : null,
    nowLabel: bl({ en: "Now:", ja: "現在:" }),
    now: st.server_name || "",
    waiting: moving
      ? (mayFinish
          ? bl({ en: "Every device is sending the new name. Finishing drops the old one.",
                 ja: "全端末が新しい名前を名乗っています。完了すると古い方は無くなります。" })
          : pkiWaitingFor((ready.still_sending_previous || []).concat(ready.never_reported || []),
              bl({ en: "Waiting for devices to report which name they send.",
                   ja: "端末がどちらの名前を名乗っているかの報告を待っています。" })))
      : bl({ en: "Both names are served while devices move over, so changing it takes nobody offline.",
             ja: "変更中は両方の名前を提供するので、誰も切断されません。" }),
    actions: moving
      ? [
          mayFinish ? {
            label: bl({ en: "Finish the change", ja: "変更を完了する" }),
            path: "/admin/tenant-transport-authority/retire-previous-name",
            done: bl({ en: "Finished — the old name is gone.", ja: "完了しました。古い名前は無くなりました。" }),
          } : null,
          {
            label: bl({ en: "Take it back", ja: "元に戻す" }),
            path: "/admin/tenant-transport-authority/abandon-rename",
            done: bl({ en: "Back on the name devices already know. Nothing was dropped.",
                       ja: "端末が既に知っている名前に戻しました。何も落としていません。" }),
          },
        ]
      : [],
  });
}

// tenantDeviceAuthorityControl is what issues this organization's device certificates. Replacing it runs the
// OTHER way round from the certificate above: here the device presents and the Edge checks, so the new one
// starts issuing immediately and the old one must stay accepted until the last device has been re-issued.
function tenantDeviceAuthorityControl(host) {
  if (pkiDeploymentAct()) return el("div", { style: "display:none" });
  const st = _pkiDeviceAuthority || {};
  if (!st.has_authority) return el("div", { style: "display:none" });
  // Only the CP evaluates the same shared population, freshness and regional
  // evidence as the retirement POST. An Edge-local observation is diagnostic.
  const ready = st.retirement_readiness || {};
  const moving = !!st.rotating;
  const tookBack = !!st.rotation_abandoned;
  const mayFinish = moving && ready.allowed === true;
  return pkiMovementCard({
    host,
    title: bl({ en: "What issues this tenant's device certificates",
                ja: "このテナントの端末証明書を発行するもの" }),
    badge: moving
      ? uiBadge(tookBack ? bl({ en: "taken back", ja: "取り下げ済み" }) : bl({ en: "being replaced", ja: "入れ替え中" }),
                tookBack ? "" : "warn")
      : null,
    nowLabel: bl({ en: "Issuing now:", ja: "いま発行しているもの:" }),
    now: (tookBack || !moving ? (st.signing && st.signing.subject) : (st.incoming && st.incoming.subject)) || "",
    waiting: moving
      ? (mayFinish
          ? bl({ en: "The control plane verified the retirement conditions. Registered device CAs that remain valid are retained. Conditions are checked again when you finish.",
                 ja: "コントロールプレーンが退役条件を確認しました。有効な持込CAは維持されます。実行時に条件を再確認します。" })
          : bl({ en: "Retirement is not ready: ", ja: "まだ退役できません: " })
            + (ready.reason || bl({ en: "The control plane's verification is unavailable. Reload to check again.",
                                    ja: "コントロールプレーンの確認結果を取得できていません。再読み込みして確認してください。" })))
      : bl({ en: "Devices may use this managed CA or another device CA registered to this organization.",
             ja: "この管理CA、またはこの組織に登録された持込CAの端末証明書を受け入れます。" }),
    actions: moving
      ? [
          mayFinish ? {
            label: bl({ en: "Finish the replacement", ja: "入れ替えを完了する" }),
            path: "/admin/tenant-device-authority/retire-previous",
            done: bl({ en: "Retirement saved. Each region applies it on its next refresh.", ja: "退役を保存しました。各地域への反映を待っています。" }),
          } : null,
          tookBack ? null : {
            label: bl({ en: "Take it back", ja: "元に戻す" }),
            path: "/admin/tenant-device-authority/abandon-rotation",
            done: bl({ en: "New certificates come from the one in force again; both stay accepted.",
                       ja: "新しい証明書は元のものから発行されます。両方とも受け入れたままです。" }),
          },
        ]
      : [{
          label: bl({ en: "Replace it", ja: "入れ替える" }),
          path: "/admin/tenant-device-authority/rotate",
          done: bl({ en: "Replacement started — devices move as they renew.",
                     ja: "入れ替えを開始しました。端末は更新時に移ります。" }),
          kind: "ui-btn-primary",
        }],
  });
}

// tenantInterceptionControl is whose root this organization's traffic is inspected under. The new one is
// handed over out of band — this deployment never holds the root key — so there is nothing here to create,
// only a change to complete or take back.
function tenantInterceptionControl(host) {
  if (pkiDeploymentAct()) return el("div", { style: "display:none" });
  const st = _pkiInterceptionAuthority || {};
  if (!st.has_authority) return el("div", { style: "display:none" });
  const ready = _pkiInterceptionRotation || {};
  const staged = !!st.staged;
  const mayPromote = staged && ready.may_promote === true;
  return pkiMovementCard({
    host,
    title: bl({ en: "Whose root this tenant's traffic is inspected under",
                ja: "このテナントの通信をどの根の下で検査するか" }),
    badge: staged ? uiBadge(bl({ en: "new one waiting", ja: "新しい方が待機中" }), "warn") : null,
    nowLabel: bl({ en: "In use:", ja: "使用中:" }),
    now: (st.root && st.root.subject) || "",
    waiting: staged
      ? (mayPromote
          ? bl({ en: "Every device trusts the new root. Switching is safe now.",
                 ja: "全端末が新しい根を信頼しています。いま切り替えて安全です。" })
          : pkiWaitingFor((ready.does_not_hold || []).concat(ready.never_reported || []),
              bl({ en: "Waiting for devices to trust the new root.",
                   ja: "端末が新しい根を信頼するのを待っています。" })))
      : bl({ en: "Nothing is waiting. A new root is handed over out of band; this deployment never holds its key.",
             ja: "待機中のものはありません。新しい根は別経路で渡され、この配備が鍵を持つことはありません。" }),
    actions: staged
      ? [
          mayPromote ? {
            label: bl({ en: "Switch to the new one", ja: "新しい方に切り替える" }),
            path: "/admin/tenant-interception-authority/promote",
            done: bl({ en: "Switched.", ja: "切り替えました。" }),
            kind: "ui-btn-primary",
          } : null,
          {
            label: bl({ en: "Take it back", ja: "取り下げる" }),
            path: "/admin/tenant-interception-authority/withdraw-incoming",
            done: bl({ en: "Taken back. Nothing was being signed with it, so no device is affected.",
                       ja: "取り下げました。まだ何も署名していないので、端末に影響はありません。" }),
          },
        ]
      : [],
  });
}

// tenantTransportAuthorityOffer is what an organization that is served the deployment's shared certificate is
// shown: what that means, and the one act that changes it.
//
// ★ THE NAME IS NOT ASKED FOR. An omitted name is derived from the organization's issued id, and that is the
// safe answer — SNI is plaintext and this deployment strips ECH, so a name taken from the company's own name
// tells every observer between a laptop and the Edge which company that laptop belongs to. A form that invited
// one would collect exactly that. An organization that wants its own domain on its own certificate is a
// deliberate decision made elsewhere, not a default a text field produces.
function tenantTransportAuthorityOffer(host) {
  const card = el("div", { class: "ui-card", style: "margin-bottom:12px" });
  const give = el("button", { class: "ui-btn ui-btn-sm ui-btn-primary",
    text: bl({ en: "Give this tenant its own", ja: "このテナント専用のものを作る" }) });
  give._label = give.textContent;
  give.addEventListener("click", async () => {
    give.disabled = true;
    give.textContent = bl({ en: "Working…", ja: "実行中…" });
    const r = await apiFetch("POST", "/admin/tenant-transport-authority", {}, "control");
    give.disabled = false;
    give.textContent = give._label;
    if (!r.ok) {
      uiToast(((r.body && r.body.error) || ("HTTP " + r.status)), "err");
      return;
    }
    uiToast(bl({ en: "Done. Devices installed from now on dial this tenant's own name.",
                 ja: "作成しました。以後インストールする端末は、このテナント専用の名前を名乗ります。" }), "ok");
    loadCertMap(host);
  });
  // Same shape as the movement cards beside it — title, button on the right, sentence under — so this reads as
  // the same object in a different state rather than a different screen.
  card.appendChild(el("div", { style: "display:flex; align-items:center; gap:10px; flex-wrap:wrap" }, [
    el("strong", { text: bl({ en: "The name this tenant's devices dial", ja: "このテナントの端末が名乗る名前" }) }),
    el("span", { style: "flex:1 1 auto" }), give,
  ]));
  card.appendChild(el("div", { class: "ui-view-desc", style: "margin-top:6px", text: bl({
    en: "This tenant's devices dial the deployment's shared name and are served the deployment's own " +
        "certificate. Giving it one of its own means its devices verify this deployment with nothing but " +
        "their own tenant's anchor — and it is what a device installed after that is told to send.",
    ja: "このテナントの端末は配備共通の名前を名乗り、配備自身の証明書を提示されます。専用のものを作ると、" +
        "端末は自テナントのアンカーだけでこの配備を検証できるようになり、以後インストールする端末には" +
        "その名前が配布されます。" }) }));
  return card;
}

function tenantTransportAuthorityControl(host) {
  // An operator answering for the whole deployment is not inside an organization, so there is nothing here to
  // rotate — the same reason the interception control below hides itself.
  if (pkiDeploymentAct()) return el("div", { style: "display:none" });
  const st = _pkiTransportAuthority || {};
  if (!st.has_authority) {
    // ★★★ AND UNTIL 2026-08-28 THIS SCREEN SIMPLY VANISHED HERE, WHICH LEFT NO WAY TO GIVE ONE. Every act a
    // transport authority has — replace it, rename it, finish, take it back — was on this screen, and the one
    // act that has to come first was on none of them: a customer could manage an authority they could never
    // create. The route has existed since 2026-08-20.
    //
    // Not an error and not a warning: most organizations are served the deployment's own certificate, and
    // saying "no authority" as a problem would make a normal state look broken. It is an offer.
    return tenantTransportAuthorityOffer(host);
  }
  const card = el("div", { class: "ui-card", style: "margin-bottom:12px" });
  const line = el("div", { class: "ui-view-desc", style: "margin-top:6px" });
  const busy = (b, on) => { b.disabled = on; b.textContent = on ? bl({ en: "Working…", ja: "実行中…" }) : b._label; };

  const replace = el("button", { class: "ui-btn ui-btn-sm ui-btn-primary",
    text: bl({ en: "Replace it", ja: "入れ替える" }) });
  replace._label = replace.textContent;
  replace.addEventListener("click", async () => {
    busy(replace, true);
    const r = await apiFetch("POST", "/admin/tenant-transport-authority/rotate", {});
    busy(replace, false);
    if (!r.ok) {
      uiToast(bl({ en: "Not replaced", ja: "入れ替えできません" }) + ": " + ((r.body && r.body.error) || ("HTTP " + r.status)), "err");
      return;
    }
    uiToast(bl({ en: "Replacement started — devices are being told about it now.",
                 ja: "入れ替えを開始しました。いま端末に伝えています。" }), "ok");
    loadCertMap(host);
  });

  const finish = el("button", { class: "ui-btn ui-btn-sm",
    text: bl({ en: "Finish the replacement", ja: "入れ替えを完了する" }) });
  finish._label = finish.textContent;
  finish.addEventListener("click", async () => {
    busy(finish, true);
    const r = await apiFetch("POST", "/admin/tenant-transport-authority/retire-previous", {});
    busy(finish, false);
    if (!r.ok) {
      uiToast(bl({ en: "Not finished", ja: "完了できません" }) + ": " + ((r.body && r.body.error) || ("HTTP " + r.status)), "err");
      return;
    }
    uiToast(bl({ en: "Retirement saved. Each region applies it on its next refresh.", ja: "退役を保存しました。各地域への反映を待っています。" }), "ok");
    loadCertMap(host);
  });

  const takeBack = el("button", { class: "ui-btn ui-btn-sm",
    text: bl({ en: "Take it back", ja: "元に戻す" }) });
  takeBack._label = takeBack.textContent;
  takeBack.addEventListener("click", async () => {
    busy(takeBack, true);
    const r = await apiFetch("POST", "/admin/tenant-transport-authority/abandon-rotation", {});
    busy(takeBack, false);
    if (!r.ok) {
      uiToast(((r.body && r.body.error) || ("HTTP " + r.status)), "err");
      return;
    }
    uiToast(bl({ en: "Taken back. Nothing was served under it, so no device is affected.",
                 ja: "元に戻しました。まだ何も提供していないので、端末に影響はありません。" }), "ok");
    loadCertMap(host);
  });

  card.appendChild(el("div", { style: "display:flex; align-items:center; gap:10px; flex-wrap:wrap" }, [
    el("strong", { text: bl({ en: "The certificate this tenant's devices trust",
                              ja: "このテナントの端末が信頼する証明書" }) }),
    st.rotating ? uiBadge(bl({ en: "being replaced", ja: "入れ替え中" }), "warn") : null,
    el("span", { style: "flex:1 1 auto" }),
    st.rotating ? finish : replace,
    // ★ THE WAY BACK, which this control did not have (2026-08-22). A replacement could only be ENDED by
    // finishing it — so an operator who started the wrong one had no way out of the screen they were on.
    // Safe by construction here: an incoming authority is only ANNOUNCED until it is finished, so taking it
    // back removes something no device is relying on.
    st.rotating ? takeBack : null,
  ].filter(Boolean)));
  // ★★★ WHAT IT IS NOW, WHICH THIS CARD DID NOT SAY (2026-09-05, read off a live deployment). The three
  // cards beside it all lead with the fact — "Now:", "In use:", "Issuing now:" — and this one offered
  // "Replace it" over prose alone, so the operator was given the act without its object. The server did not
  // send it either; GET /admin/tenant-transport-authority now reports the certificate the way its two
  // siblings do.
  if (st.signing && st.signing.subject) {
    card.appendChild(el("div", { class: "ui-view-desc", style: "margin-top:6px" }, [
      document.createTextNode(bl({ en: "In use: ", ja: "現在: " })),
      el("strong", { text: st.signing.subject }),
    ]));
  }
  if (st.rotating && st.incoming && st.incoming.subject) {
    card.appendChild(el("div", { class: "ui-view-desc" }, [
      document.createTextNode(bl({ en: "Being handed out alongside: ", ja: "並べて配布中: " })),
      el("strong", { text: st.incoming.subject }),
    ]));
  }
  card.appendChild(line);
  line.textContent = st.rotating
    ? bl({ en: "Both are being handed out. Each Edge moves to the new one on its own, once every device of this tenant has been seen holding it. Finish when they all have — that removes the old one for good.",
           ja: "いまは両方を配っています。各 Edge は、このテナントの全端末が新しい方を持ったと確認できた時点で、自分の判断で新しい方に移ります。全部が移ったら完了してください。完了すると古い方は無くなります。" })
    : bl({ en: "Replacing does not swap it. The new one is handed out alongside, and each Edge moves only after every device of this tenant holds it.",
           ja: "入れ替えても差し替わりません。新しい方を並べて配り、このテナントの全端末が持ってから、各 Edge が移ります。" });
  return card;
}

function tenantInterceptionCAControl(host) {
  // ★ AN OPERATOR ANSWERING FOR THE WHOLE DEPLOYMENT IS NOT IN A TENANT, so "this tenant's interception
  // authority" would be a sentence about nobody, with a button that resolves "self" to nothing and is refused.
  // They reach a tenant's PKI by entering that tenant — which is the arrangement this control exists to serve.
  if (pkiDeploymentAct()) return el("div", { style: "display:none" });
  const card = el("div", { class: "ui-card", style: "margin-bottom:12px" });
  const line = el("div", { class: "ui-view-desc", style: "margin-top:6px" });
  const add = el("button", { class: "ui-btn ui-btn-sm ui-btn-primary",
    text: bl({ en: "Load this tenant's interception CA", ja: "このテナントの傍受CAを入れる" }) });
  add.addEventListener("click", () => openTenantInterceptionCAForm(host, !!(_pkiTenantInterception && _pkiTenantInterception.has_authority)));

  // ★★★ THE ORDINARY CASE HAD NO BUTTON, ONLY A curl (2026-09-06, the operator: "PKI that is only completable
  // with curl should not exist — all of it belongs in the Admin Console").
  //
  // There are two shapes here, exactly as there are for a tenant's device identities one card below:
  //
  //   they bring their own root — loaded above, three PEMs, and this deployment signs under what they gave
  //   this deployment makes one — created here, and the organization gets a root of its own
  //
  // The second is the ordinary onboarding case: an organization without a CA team, which is most of them.
  // The route has accepted it since 2026-08-30 — an empty body means "make one for this organization" — and
  // this screen never offered it, so the only way to finish an organization's PKI was to post an empty body
  // by hand. Every organization on this deployment was completed that way, which is the tell: the product
  // could not do what the product's own walkthrough did.
  const mint = el("button", { class: "ui-btn ui-btn-sm",
    text: bl({ en: "Let this deployment make one", ja: "この配備に作らせる" }) });
  mint.addEventListener("click", async () => {
    mint.disabled = true;
    const body = {};
    if (operateTenant) body.tenant_id = operateTenant;
    const r = await apiFetch("POST", "/admin/tenant-interception-authority", body);
    mint.disabled = false;
    if (!r.ok) { const msg = (r.body && r.body.error) || ("HTTP " + r.status); uiToast(msg, "err"); return; }
    // ★ AND WHAT IT DOES NOT REACH. A device holds the root its configuration carried on the day it was
    // installed, so the ones already out there are still on the previous answer. Said here, once, rather than
    // discovered as a device that refuses every page.
    uiToast(bl({
      en: "Done. This tenant's traffic is inspected under its own root. Devices set up from now on carry that "
        + "root in their configuration; devices already installed are still on the previous one and need a "
        + "configuration made after today.",
      ja: "作成しました。以後このテナントの通信は自前のルートで傍受されます。これから設定する端末は、その"
        + "ルートを設定ごと受け取ります。既に入っている端末は以前のもののままなので、今日以降に作った設定が"
        + "必要です。" }), "ok");
    loadCertMap(host);
  });

  // Whether this organization already has one is the server's answer, not a guess: the mint is offered only
  // when the authority read came back and said there is none. EnsureCA returns the existing authority
  // unchanged, so a button shown beside one that exists is a control that cannot fail and teaches nothing.
  const answered = !!_pkiTenantInterception && typeof _pkiTenantInterception.has_authority === "boolean";
  const hasOwn = !!(_pkiTenantInterception && _pkiTenantInterception.has_authority);
  // Importing another authority stages it; it does not replace the active signer.
  // Keep that existing operation reachable once an authority has been installed.
  if (hasOwn) add.textContent = bl({ en: "Stage a replacement CA", ja: "次のCAを登録" });
  add.disabled = !answered || !!(_pkiTenantInterception && _pkiTenantInterception.staged);
  card.appendChild(el("div", { style: "display:flex; align-items:center; gap:10px; flex-wrap:wrap" }, [
    el("strong", { text: bl({ en: "This tenant's interception authority", ja: "このテナントの傍受の権威" }) }),
    el("span", { style: "flex:1 1 auto" }),
    (answered && !hasOwn) ? mint : null,
    add,
  ].filter(Boolean)));
  card.appendChild(line);
  // ★ THE SENTENCE COMES FROM THE SERVER'S ANSWER, NOT FROM A KEY THIS FILE MADE UP (2026-08-18). The first
  // draft counted `per_tenant_issuers`, which /admin/interception-intermediate does not return — so the card
  // read "this tenant has no interception authority of its own" directly above a card showing that tenant's
  // own root. The endpoint now answers about the tenant in scope and says which of the cases this is; the
  // detail sentence is its words, in the reader's terms, rather than this file's guess.
  const st = _pkiMapCustody || {};
  const mode = String(st.mode || "");
  const known = {
    own_offline_root: { en: "Traffic is inspected under this tenant's own root. A replacement is staged while devices adopt it; the current authority remains in use until promotion.",
                        ja: "このテナント自身のルートで傍受しています。次のCAは端末の信頼設定が整うまで待機し、切り替えまで現在のCAを使います。" },
    node_intermediate: { en: "This tenant is inspected under the deployment's own intermediate — the anchor its devices already trust — rather than a root of its own.",
                         ja: "このテナントは、自前のルートではなく配備側の中間で傍受されています（端末が既に信頼しているアンカー）。" },
    none: { en: "This tenant has no interception authority of its own, so its traffic is not inspected at all — it is deliberately not signed under another tenant's CA. Two ways out, and a tenant is in one of them: let this deployment make a root for it, or load a root it already has.",
            ja: "このテナントには自前の傍受の権威がありません。そのため通信は傍受されません — 他テナントのCAで署名することは意図的にしません。道は2つで、テナントはそのどちらかにいます。この配備にルートを作らせるか、既に持っているルートを入れるかです。" },
    revoked: { en: "This tenant's interception authority was revoked here, so its traffic is not inspected until a replacement is loaded.",
               ja: "このテナントの傍受の権威はここで失効させられています。差し替えを入れるまで傍受しません。" },
    shared: { en: "This deployment signs every tenant under one authority.", ja: "この配備は全テナントを1つの権威で署名しています。" },
  }[mode];
  // ★★★ AND WHEN THIS NODE CANNOT ANSWER, SAY WHAT THE AUTHORITY DOES (2026-09-03). A control plane refuses
  // /admin/interception-intermediate by design — it holds authorities and serves no traffic — so on the node
  // an operator actually opens this screen against, `mode` was always empty and this card always read "could
  // not be determined", directly beneath a card naming the organization's root IN USE. Worse, it went on
  // offering "Load this tenant's interception CA", which invites replacing an authority that exists.
  //
  // The authority endpoint is the one the refusal names, and the control plane answers it. Whether an
  // organization HAS its own authority and what its traffic is inspected UNDER are two questions; this card
  // asks the first when it cannot have the second, and says which it is answering.
  const auth = _pkiTenantInterception || {};
  // ★★★ AND "HAS ONE" OUTRANKS "IS NOT INSPECTED UNDER ONE" (2026-09-06, seen one second after minting an
  // authority from the button above). The custody read is an EDGE's answer about what it currently signs with,
  // and an Edge learns about a new authority on its next fetch — so for that minute it truthfully says "none",
  // and this card printed "This tenant has no interception authority of its own" directly beneath a card
  // naming that tenant's root by subject. The card above and the card below disagreed on the same screen,
  // which is the defect this file has already been fixed for once, arriving from the other direction.
  //
  // The two are different questions. When the authority answer says there IS one, the custody answer can only
  // add WHEN it takes effect — never deny it.
  // ★★★ AND "none" WAS NOT THE ONLY WAY TO SAY IT (2026-09-06, second walk, on a deployment built from the
  // tree). This branch was written for a custody read that said "none"; the read can equally say `shared` —
  // "This deployment signs every tenant under one authority" — or `node_intermediate`, and both were printed
  // directly beneath a card naming this organization's own root by subject. Same defect, different word for
  // the same lag: an Edge that has not fetched yet describes the world before the mint.
  //
  // So the rule is about MEANING, not about one value: any custody answer that says this organization is not
  // inspected under a root of its own is describing the moment before the Edges catch up, and the authority
  // answer outranks it. `revoked` is deliberately NOT in that set — it says this organization's authority was
  // taken out of service here, which is a real conflict and must stay visible.
  const custodyDeniesItsOwn = mode === "none" || mode === "shared" || mode === "node_intermediate";
  if (auth.has_authority && (!known || custodyDeniesItsOwn)) {
    const issuing = (auth.issuing && auth.issuing.subject) ? auth.issuing.subject : "";
    line.textContent = custodyDeniesItsOwn ? bl({
      en: "This tenant has its own interception authority" + (issuing ? " — issuing: " + issuing : "") +
        ". The Edges have not picked up its issuing tier yet; each does on its next fetch, and this tenant's "
        + "traffic is inspected under this root from then on.",
      ja: "このテナントは自前の傍受の権威を持っています" + (issuing ? "（発行元: " + issuing + "）" : "") +
        "。Edge はまだ発行用の層を受け取っていません。各 Edge は次回の取得で受け取り、以後このルートで傍受します。",
    }) : bl({
      en: "This tenant has its own interception authority" + (issuing ? " — issuing: " + issuing : "") +
        ". What its traffic is inspected under is an Edge's answer, and this screen asked the control plane, " +
        "which holds authorities and serves no traffic.",
      ja: "このテナントは自前の傍受の権威を持っています" + (issuing ? "（発行元: " + issuing + "）" : "") +
        "。実際に何で傍受されているかは Edge の答えで、この画面は制御プレーンに訊いています（制御プレーンは" +
        "権威を保持しますが通信は扱いません）。",
    });
    return card;
  }
  // An unrecognised mode says what it is rather than picking the most alarming branch by default — the whole
  // defect above was a screen confidently asserting the wrong one.
  line.textContent = known ? bl(known)
    // ★ "NO AUTHORITY" IS AN ANSWER, AND IT WAS BEING PRINTED AS "COULD NOT BE DETERMINED". The authority read
    // above says so plainly; only the custody read (an Edge's answer) is missing on a control plane, and that
    // is a different question. A screen that calls a known state unknown hides the control that fixes it.
    : answered && !hasOwn
    ? bl({ en: "This tenant has no interception authority of its own, so its traffic is not inspected. Two ways, "
             + "and a tenant is in one of them: let this deployment make a root for it, or load a root it "
             + "already has. The configuration its devices install carries that root, so nothing is placed on "
             + "them by hand.",
           ja: "このテナントには自前の傍受の権威がなく、通信は傍受されません。道は2つで、テナントはそのどちらかに"
             + "います。この配備にルートを作らせるか、既に持っているルートを入れるかです。そのルートは端末が入れる"
             + "設定に載るので、端末側で手を入れる必要はありません。" })
    : bl({ en: "The interception authority for this tenant could not be determined from this node.",
           ja: "このテナントの傍受の権威を、このノードからは判断できませんでした。" });
  return card;
}

function openTenantInterceptionCAForm(host, replacing = false) {
  // uiField is the whole form vocabulary on this screen — get()/setError() and nothing invented. (An earlier
  // draft of this control called a uiTextarea that does not exist, which would have rendered an empty modal
  // and told nobody why. Same family as the response keys the Console once invented for itself.)
  const field = (name, label, hint) => uiField({ name, type: "textarea", label: bl(label), hint: bl(hint) });
  const root = field("root_cert_pem", { en: "Root certificate", ja: "ルート証明書" },
    { en: "The anchor this tenant's devices trust. Certificate only.", ja: "このテナントの端末が信頼するアンカー。証明書のみ。" });
  const inter = field("intermediate_cert_pem", { en: "Issuing certificate", ja: "発行証明書" },
    { en: "The intermediate issued by that root. Certificate only.", ja: "そのルートが発行した中間証明書。証明書のみ。" });
  // ★ THE ONE FIELD THAT IS A PRIVATE KEY, SAID PLAINLY. The Edge mints a leaf per host, so it has to hold
  // this key — that is inherent, not an oversight. What is NOT inherent is letting somebody paste it without
  // knowing: this is the only field on the whole Certificates screen that asks for a key, and every other one
  // says "never paste a private key".
  const key = field("intermediate_key_pem", { en: "Issuing private key — this is a key, not a certificate", ja: "発行用の秘密鍵 — これは証明書ではなく鍵です" },
    { en: "The key belonging to the issuing certificate. The Edge signs with it and never returns it.",
      ja: "発行証明書に対応する鍵です。Edge が署名に使い、返すことはありません。" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl(replacing
    ? { en: "Stage replacement", ja: "次のCAを登録" } : { en: "Load", ja: "入れる" }) });
  const m = uiModal({
    title: bl(replacing ? { en: "Stage a replacement interception CA", ja: "次の傍受CAを登録" }
      : { en: "Load this tenant's interception CA", ja: "このテナントの傍受CAを入れる" }),
    body: [
      el("p", { class: "ui-view-desc", text: bl({
        en: "This authority decrypts this tenant's traffic. It is issued from the tenant's own offline root, never from the provider's — the two are independent, and the provider does not hold this root. Its devices must trust the root before this takes effect.",
        ja: "この権威がこのテナントの通信を復号します。テナント自身のオフラインルートが発行したものであり、提供者のものではありません — 両者は独立で、提供者はこのルートを保持しません。効かせる前に、端末がこのルートを信頼している必要があります。" }) }),
      root.el, inter.el, key.el,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    const read = (f) => String(f.get() || "").trim();
    // ★★★ THE AUTHORITY'S ROUTE, NOT THE INSPECTION ONE (2026-08-27, found by walking this screen on a
    // deployment with a real organization in it). This posted to /admin/interception-intermediate/{tenant} —
    // which is an EDGE's route, about what a node inspects under — so the control plane answered
    //
    //	this node holds organizations' interception AUTHORITIES but serves no traffic … Ask an Edge; the
    //	authority itself is at /admin/tenant-interception-authority
    //
    // naming its own replacement. Handing an organization's authority to the operator is a control-plane act:
    // it is an IMPORT, not a creation, and the field names differ because the two routes are about different
    // things. The device-CA form beside this one already posts to the authority's route and works.
    const body = {
      root_pem: read(root),
      issuing_cert_pem: read(inter),
      issuing_key_pem: read(key),
    };
    if (operateTenant) body.tenant_id = operateTenant;
    const missing = !body.root_pem || !body.issuing_cert_pem || !body.issuing_key_pem;
    if (missing) { root.setError(bl({ en: "All three are required.", ja: "3つとも必要です。" })); return; }
    submit.disabled = true;
    // ★ THE TENANT IS NAMED ONLY WHEN AN OPERATOR HAS ENTERED ONE. A customer administrator never has
    // operateTenant, and the route resolves the caller's own organization — the same idiom as the device-CA
    // form. It refuses a different tenant without cross-tenant rights.
    const r = await apiFetch("POST", "/admin/tenant-interception-authority", body);
    if (!r.ok) { submit.disabled = false; const msg = (r.body && r.body.error) || ("HTTP " + r.status); key.setError(msg); uiToast(msg, "err"); return; }
    m.close();
    uiToast(bl(r.body && r.body.staged === true
      ? { en: "Replacement staged. The current authority remains in use. Wait for device adoption before switching.",
          ja: "次のCAを登録しました。現在のCAは使用を続けます。端末の信頼設定が整ってから切り替えてください。" }
      : { en: "Authority saved. Each Edge applies it on its next refresh; devices must trust its root before inspection.",
          ja: "CAを保存しました。各Edgeは次回の取得で反映します。傍受には端末がルートを信頼している必要があります。" }), "ok");
    loadCertMap(host);
  });
}

function tenantDeviceCAControl(host) {
  const card = el("div", { class: "ui-card", style: "margin-bottom:12px" });
  const line = el("div", { class: "ui-view-desc", style: "margin-top:6px" });
  const add = el("button", { class: "ui-btn ui-btn-sm ui-btn-primary",
    text: bl({ en: "Register this tenant's device CA", ja: "このテナントの端末CAを登録" }) });
  add.addEventListener("click", () => openTenantDeviceCAForm(host));
  // ★★★ THE OTHER WAY IN, WHICH THIS SCREEN COULD READ AND NOT OFFER (2026-08-27, found by enrolling a device
  // into a real organization). There are two shapes and a customer is in exactly one of them:
  //
  //   they bring their own CA  — registered above, and the deployment ADMITS what it issues
  //   the deployment holds one — created here, and the deployment ISSUES the identities
  //
  // A device enrolling with a one-time token has no certificate yet, so it needs the second: something must
  // issue its identity. The Console read /admin/tenant-device-authority to display the state and had no
  // control that posted it, so an organization set up entirely through these screens could be handed an
  // enrolment token that nothing could act on.
  const issue = el("button", { class: "ui-btn ui-btn-sm",
    text: bl({ en: "Let this deployment issue them", ja: "この配備に発行させる" }) });
  issue.addEventListener("click", async () => {
    issue.disabled = true;
    const body = {};
    if (operateTenant) body.tenant_id = operateTenant;
    // ★★ THE NAME ON THE CERTIFICATE IS THE ONE THE ORGANIZATION IS CALLED (2026-08-27, seen on the first one
    // this created). Without display_name the authority defaults to the organization's internal id, and it is
    // not a label on a screen — it is the Organization field of the CA, so every device certificate in that
    // organization carries "O=tenant_drcrc6x5pbshmgjpsxwmf6rnn4" forever. The subject is fixed when the
    // authority is minted and EnsureCA returns the existing one unchanged, so the only chance to get it right
    // is here, once.
    const named = await apiFetch("GET", "/admin/tenant");
    const display = (named.ok && named.body && named.body.display_name) || operatingOrganizationName || "";
    if (display) body.display_name = display;
    const r = await apiFetch("POST", "/admin/tenant-device-authority", body);
    issue.disabled = false;
    if (!r.ok) { const msg = (r.body && r.body.error) || ("HTTP " + r.status); uiToast(msg, "err"); return; }
    uiToast(bl({ en: "Done. This tenant's devices are issued an identity by this deployment when they enrol.",
                 ja: "設定しました。以後、このテナントの端末は登録時にこの配備から身元を受け取ります。" }), "ok");
    loadCertMap(host);
  });
  // ★★★ IT ASKED A QUESTION THIS ORGANIZATION HAD ALREADY ANSWERED (2026-09-05, read off a live deployment).
  // The card offered both ways with equal weight — "Two ways, and a tenant is in one of them" — directly
  // above a card that said "Issuing now: CN=… Device Identity CA". The state was on the same screen, in the
  // response this file already holds, and this card did not look at it. Pressing the offer would have changed
  // nothing (EnsureCA returns the existing authority), which is the worse kind of wrong control: it does not
  // fail, so the reader learns nothing from pressing it.
  const issuing = !!(_pkiDeviceAuthority && _pkiDeviceAuthority.has_authority);
  card.appendChild(el("div", { style: "display:flex; align-items:center; gap:10px; flex-wrap:wrap" }, [
    el("strong", { text: bl({ en: "This tenant's device identity", ja: "このテナントの端末の身元" }) }),
    issuing ? uiBadge(bl({ en: "this deployment issues them", ja: "この配備が発行しています" }), "ok") : null,
    el("span", { style: "flex:1 1 auto" }),
    issuing ? null : issue,
    add,
  ].filter(Boolean)));
  card.appendChild(line);
  // What it ENABLES, in one line, and what is true right now underneath it.
  line.textContent = issuing
    ? bl({ en: "Settled: this deployment issues this tenant's device identities, which is what a device enrolling with a one-time token needs. Registering a CA they already have is still open — this deployment would then admit what that CA issues as well.",
           ja: "決着しています。この配備がこのテナントの端末の身元を発行しており、ワンタイムトークンで登録する端末に必要なのはこちらです。既に持っているCAの登録は、まだできます —— そのCAが発行した端末も受け入れるようになります。" })
    : bl({ en: "Two ways, and a tenant is in one of them. Register a CA they already have and this deployment admits what it issues — or let this deployment issue their device identities, which is what a device enrolling with a one-time token needs, because it has no certificate yet. Without either, its devices are refused at the handshake.",
           ja: "道は2つで、テナントはそのどちらかにいます。既に持っているCAを登録すれば、その発行した端末が受け入れられます。あるいは、この配備に端末の身元を発行させます —— ワンタイムトークンで登録する端末は、まだ証明書を持っていないので、こちらが要ります。どちらも無いと、その端末は接続時に拒否されます。" });
  {
    const rows = _pkiTenantCAs;
    // ★ THE SERVER ALREADY SCOPED THIS, AND THIS FILTER DID NOT (2026-08-18). The predicate keys on
    // operateTenant, which an operator has and a CUSTOMER never does — so for the reader this control is FOR,
    // `!operateTenant` was true and the filter passed everything through. It happened to be harmless because
    // GET /admin/tenant-cas answers a customer with their own registrations only; a filter that does nothing
    // is still worth removing, because the next reader will believe it is what makes this list safe.
    //
    // Kept for the operator, who legitimately receives every organization's and is looking at one.
    const mine = operateTenant
      ? rows.filter((x) => !x.tenant_id || String(x.tenant_id).toLowerCase() === String(operateTenant).toLowerCase())
      : rows;
    if (!mine.length) return card;
    card.appendChild(el("div", { class: "ui-view-desc", style: "margin-top:6px" },
      uiBadge(bl({ en: "Registered", ja: "登録済み" }), "ok")));
    mine.forEach((x) => card.appendChild(el("div", { class: "ui-view-desc" }, el("code", { text: x.subject || x.sha256 || "" }))));
  }
  return card;
}

// prefillPEM is set when this is opened from an unattributed CA already on the map: the certificate is known,
// and asking the operator to copy it out of one card and into this form would be asking them to re-supply a
// fact the screen is holding.
function openTenantDeviceCAForm(host, prefillPEM) {
  const pem = uiField({ name: "ca_pem", type: "textarea", label: bl({ en: "The CA certificate (PEM)", ja: "CA 証明書 (PEM)" }),
    value: String(prefillPEM || ""),
    hint: bl({ en: "Paste the certificate, or choose the file. Only the certificate — never a private key.",
               ja: "証明書を貼り付けるか、ファイルを選んでください。証明書のみ — 秘密鍵は決して入れないでください。" }) });
  const file = el("input", { type: "file", accept: ".pem,.crt,.cer" });
  file.addEventListener("change", () => {
    const f = file.files && file.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { const area = pem.el.querySelector("textarea"); if (area) { area.value = String(reader.result || ""); area.dispatchEvent(new Event("input", { bubbles: true })); } };
    reader.readAsText(f);
  });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Register", ja: "登録" }) });
  const m = uiModal({
    title: bl({ en: "Register this tenant's device CA", ja: "このテナントの端末CAを登録" }),
    body: [
      el("p", { class: "ui-view-desc", text: bl({
        en: "Devices holding a certificate from this CA are admitted as this tenant's. It is checked before it is saved: a CA the handshake would not accept is refused rather than written down.",
        ja: "このCAの証明書を持つ端末が、このテナントのものとして受け入れられます。保存前に検証します。接続時に受け入れられないCAは、記録せずに拒否します。" }) }),
      pem.el, file,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    const area = pem.el.querySelector("textarea");
    const value = String((area && area.value) || "").trim();
    if (!value) { pem.setError(bl({ en: "Paste the certificate or choose a file.", ja: "証明書を貼り付けるか、ファイルを選んでください。" })); return; }
    submit.disabled = true;
    // The organization is the one being operated in — the route refuses a CA for anybody else without
    // cross-tenant rights, and naming it here is what makes the refusal about the right organization.
    //
    // ★ AND AN EMPTY STRING IS NOT A NAME (2026-08-17, measured signed in as a customer administrator).
    // operateTenant is set for an operator and never for a customer, so `operateTenant || ""` posted an empty
    // tenant from the customer's own screen and the route answered 400 "tenant_id and ca_pem are both
    // required" — naming a field the person pressing the button never filled in, on the one control that
    // clears their blocking setup item. The field is omitted when there is nothing to say, and the server
    // answers for the caller's own organization.
    const body = { ca_pem: value };
    if (operateTenant) body.tenant_id = operateTenant;
    const r = await apiFetch("POST", "/admin/tenant-cas", body);
    if (!r.ok) { submit.disabled = false; const msg = (r.body && r.body.error) || ("HTTP " + r.status); pem.setError(msg); uiToast(msg, "err"); return; }
    if (!r.body || r.body.durable !== true) {
      submit.disabled = false;
      const msg = bl({ en: "The registration was not durably saved. Check its state before retrying; it may be lost on restart.",
                       ja: "登録を永続保存できていません。再起動で失われる可能性があります。状態を確認してから再試行してください。" });
      pem.setError(msg); uiToast(msg, "err"); return;
    }
    m.close();
    uiToast(bl({ en: "Registration saved. Each region applies it on its next refresh.", ja: "登録を保存しました。各地域への反映を待っています。" }), "ok");
    loadCertMap(host);
  });
}
