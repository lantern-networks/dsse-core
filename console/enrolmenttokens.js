"use strict";

// enrolmenttokens.js — "Enrolment Tokens": the admin's side of Day-0.
//
// An admin approves a MACHINE here and hands the resulting token to whoever is setting it up. No end user is
// involved: an IT admin images a batch of laptops before knowing who will use them, and the person is
// authenticated later, at access, by the IdP.
//
// Backend: GET /admin/enrolment-tokens -> {tokens, outstanding, outstanding_cap, max_lifetime_hours,
// expiring_within_48h}; POST /admin/enrolment-tokens {label, group, expires_in_hours};
// POST /admin/enrolment-tokens/{id}/revoke.

// ★★★ THE CONTROL PLANE SERVES THESE, AND THIS FILE SAID THE OPPOSITE (2026-09-05, measured against both
// doors of a running deployment once the Console's two planes were actually separated). The note here read
// "The EDGE serves these … The control-plane prefix would 404". The Edge answers:
//
//	409  this Edge does not hold this deployment's enrolment tokens and cannot answer for them — it forwards
//	     the one act it performs, spending a token, to the control plane. Ask the control plane: it is what
//	     the Admin Console talks to
//
// and the control-plane prefix answers 200 with the tokens. Nobody noticed because both of this Console's
// upstreams pointed at the control plane, so "the Edge plane" was the control plane and the wrong routing
// could not produce a wrong answer.
//
// Explicit here rather than in CP_AUTHORED_WRITES: that table is generated from the Edge's
// configWriteRejectedWhenSourced guard set and checked by ops/checks/cp_authored_routes_in_sync.sh, and this
// route refuses for its own reason, so an entry there would fail the gate. The reads are in
// CP_AUTHORED_READS, which says the same thing about the same resource.
const _ENROL_PLANE = "control";
let _enrolSearch = "";
let _enrolMaxLifetimeHours = 720;
// principal id -> email, for tokens issued before the approver's name was recorded with them.
let _enrolAdminLabels = {};

// Who approved this device, in a form a person can act on.
//
// This column used to print the raw principal id — a 32-character hex string that answers the question "who
// approved this machine?" with a value nobody can look up from the screen they are on. Which administrator
// authorised a device is the entire point of the enrolment-token feature; rendering it unreadably keeps the
// record and loses the accountability.
//
// The authority does not currently expose a name for a principal (its session introspection returns only the
// id), so this shows what it honestly can: a labelled, shortened REFERENCE, which reads as a pointer rather
// than posing as a name, and is enough to match against an audit entry. issued_by_label is used when the
// backend starts carrying one — see the open item on recording the approver's name at issuance, which is the
// real fix because an id resolves to nothing once the account is deleted.
// Three sources, in the order they can be trusted to still be true.
//
// The label recorded AT ISSUANCE is the only one that survives the account being deleted, which is the case
// this record exists for — approvals outlive the people who granted them. Resolving the id against the current
// account list covers tokens issued before that was recorded, and stops working the moment somebody leaves.
// The shortened reference is the honest last resort: it says "this is a pointer", rather than dumping
// thirty-two characters of hex into a table cell and calling it an answer.
function approvedByLabel(t, byPrincipal) {
  const recorded = (t.issued_by_label || "").trim();
  if (recorded) return recorded;
  const id = (t.issued_by || "").trim();
  if (!id) return "—";
  const resolved = byPrincipal && byPrincipal[id];
  if (resolved) return resolved;
  const short = id.replace(/^adm_/, "").slice(0, 8);
  return bl({ en: "an administrator · ref " + short, ja: "管理者 · 参照 " + short });
}

// The current account list, used only to name principals that were recorded before the label was. Best-effort:
// a failure here must not blank a page about devices.
async function loadAdminLabels() {
  try {
    const r = await apiFetch("GET", "/admin/admins", undefined, _ENROL_PLANE);
    if (!r.ok || !r.body || !r.body.admins) return {};
    const out = {};
    r.body.admins.forEach((a) => {
      if (a && a.principal_id && a.email) out[a.principal_id] = a.email;
    });
    return out;
  } catch (e) {
    return {};
  }
}

function renderEnrolmentTokensView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Enrolment Tokens", ja: "登録トークン" }) }),
      // Three sentences of standing explanation, read once and then in the way forever. What a token does is
      // stated where it is issued, in the form itself, at the moment it matters.
    ]),
    el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "+ Approve a device", ja: "+ 端末を承認" }), onClick: () => openEnrolTokenForm(content) }),
  ]));

  const search = el("input", { class: "ui-input ui-search", type: "search", placeholder: bl({ en: "Search by label…", ja: "ラベルで検索…" }) });
  search.value = _enrolSearch;
  const host = el("div", {});
  search.addEventListener("input", () => { _enrolSearch = search.value; renderEnrolTokenList(host); });
  content.appendChild(el("div", { class: "ui-toolbar" }, [search, el("span", { class: "ui-spacer" }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderEnrolTokenList(host) })]));
  content.appendChild(host);
  renderEnrolTokenList(host);
}

// A token's state is what an admin actually asks about — "can this still be used, and if not, why" — so it is
// computed once here and drives both the badge and the actions.
function enrolTokenState(t) {
  if (t.revoked_at) return { key: "revoked", label: bl({ en: "Revoked", ja: "失効" }), tone: "danger" };
  if (t.used_at) return { key: "used", label: bl({ en: "Used", ja: "使用済み" }), tone: "off" };
  if (t.expires_at && new Date(t.expires_at) <= new Date()) return { key: "expired", label: bl({ en: "Expired", ja: "期限切れ" }), tone: "off" };
  return { key: "waiting", label: bl({ en: "Waiting for device", ja: "端末待ち" }), tone: "ok" };
}

function enrolTimeLeft(expiresAt) {
  if (!expiresAt) return "—";
  const ms = new Date(expiresAt) - new Date();
  if (ms <= 0) return bl({ en: "expired", ja: "期限切れ" });
  const hours = Math.floor(ms / 3600000);
  if (hours >= 48) return bl({ en: String(Math.floor(hours / 24)) + " days left", ja: "残り " + Math.floor(hours / 24) + " 日" });
  if (hours >= 1) return bl({ en: String(hours) + " hours left", ja: "残り " + hours + " 時間" });
  return bl({ en: "under an hour left", ja: "残り 1 時間未満" });
}

async function renderEnrolTokenList(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  // Fetched alongside the tokens so a name can be shown for approvals recorded before the label was stored.
  _enrolAdminLabels = await loadAdminLabels();
  let body;
  try {
    const r = await apiFetch("GET", "/admin/enrolment-tokens", undefined, _ENROL_PLANE);
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderEnrolTokenList(host) }); return; }
    body = r.body || {};
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderEnrolTokenList(host) }); return; }

  const tokens = body.tokens || [];
  if (body.max_lifetime_hours) _enrolMaxLifetimeHours = body.max_lifetime_hours;
  if (!current()) return;
  host.innerHTML = "";

  // Unused tokens that have not been picked up are the thing this page has to make visible. They are live
  // credentials, and without a count nobody notices them accumulating until issuing starts failing.
  const outstanding = body.outstanding || 0;
  const cap = body.outstanding_cap || 0;
  const expiringSoon = (body.expiring_within_48h || []).length;
  if (outstanding || expiringSoon) {
    const parts = [bl({
      en: outstanding === 1 ? "1 approved device has not been set up yet"
                            : outstanding + " approved devices have not been set up yet",
      ja: "未セットアップの承認済み端末: " + outstanding + " 台" })];
    if (cap) parts.push(bl({ en: "limit " + cap, ja: "上限 " + cap }));
    if (expiringSoon) parts.push(bl({ en: expiringSoon + " expiring within 48 hours", ja: "48時間以内に期限切れ: " + expiringSoon + " 件" }));
  }

  // ★★ A TOKEN NOTHING CAN USE (2026-08-17, measured). This node's POST /enroll issues for exactly ONE
  // organization — it verifies the token against that organization, assigns it to the device, and signs with
  // the node's single device-identity CA. A customer administrator of any OTHER organization can mint a token
  // here and get a real secret back; the device then gets "invalid or missing eligibility token" and the
  // administrator goes looking at the device, the installer and the network. Say it on the screen that issues
  // them, not only in the response of the call that made one.
  if (body.tenant_warning) {
    // Composed here from the structured field rather than printing the server's sentence: that sentence is
    // English, and this screen is not. The server keeps saying it for anything that is not this console.
    // ★★ AND IT NAMED ANOTHER CUSTOMER (2026-08-18, walked as Northwind's own administrator). The sentence
    // printed "This node enrols devices for tenant_reference_lab only" on a screen belonging to a DIFFERENT
    // customer of the same provider — who may be a competitor, and who can act on none of it. The server now
    // withholds enrols_for_tenant from anybody but the deployment's operator, and this sentence is written so
    // that it reads correctly either way rather than leaving a blank where the name used to be.
    const enrolsFor = String(body.enrols_for_tenant || "");
    host.appendChild(el("div", { class: "ui-callout ui-callout-warn" }, [
      el("strong", { text: bl({ en: "Tokens issued here cannot be used against this node.",
                                ja: "ここで発行したトークンは、このノードでは使えません。" }) }),
      el("p", { class: "ui-view-desc", text: enrolsFor ? bl({
        en: "This node enrols devices for " + enrolsFor + " only. A device presenting a token issued here is "
          + "refused; it can only be used against an Edge that enrols for your tenant.",
        ja: "このノードが登録を受け付けるのは " + enrolsFor + " の端末だけです。ここで発行したトークンを提示した端末は拒否されます。"
          + "自テナントの登録を受け付ける Edge に対してのみ使えます。" })
        : bl({
        en: "This node does not enrol devices for your tenant. A device presenting a token issued here is "
          + "refused; it can only be used against an Edge that enrols for your tenant.",
        ja: "このノードは、あなたのテナントの端末登録を受け付けません。ここで発行したトークンを提示した端末は拒否されます。"
          + "自テナントの登録を受け付ける Edge に対してのみ使えます。" }) }),
      // ★ AND SAY WHAT DOES WORK (2026-08-17). The warning above stopped at the refusal, which leaves an
      // administrator holding a credential, a screen that issued it, and no route to a working device. The
      // route exists and is the design rather than a workaround: this token is the NODE's own issuance path,
      // and an organization brings its own device-issuing authority instead — the transport admits a device by
      // the certificate it presents, and reads which organization it belongs to from that certificate.
      el("p", { class: "ui-view-desc", text: bl({
        en: "Your tenant enrols devices with its own device CA instead: Certificates → "
          + "“Register this tenant’s device CA”, then issue device certificates from it. "
          + "The Edge admits a device by the certificate it presents.",
        ja: "自テナントの端末は、自テナントの端末CAで登録します。「証明書」画面の「このテナントの端末CAを登録」から登録し、"
          + "そこから端末証明書を発行してください。Edge は端末が提示した証明書で受け入れを判断します。" }) }),
    ]));
  }

  const q = _enrolSearch.trim().toLowerCase();
  const filtered = tokens.filter((t) => !q || (t.label || "").toLowerCase().includes(q) || (t.used_by || "").toLowerCase().includes(q));
  if (!tokens.length) {
    if (!current()) return;
    uiState(host, "empty", bl({
      en: "No devices approved yet. Approve one to let it enrol — its installer needs the token you get back.",
      ja: "承認済みの端末はまだありません。承認するとその端末が登録できます — 発行されたトークンをインストーラに設定してください。" }));
    return;
  }
  if (!filtered.length) { if (!current()) return; uiState(host, "empty", bl({ en: "No matches.", ja: "一致なし。" })); return; }

  const rows = filtered.map((t) => {
    const state = enrolTokenState(t);
    const actions = el("div", { class: "ui-row-actions" });
    if (state.key === "waiting") {
      actions.appendChild(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger", text: bl({ en: "Revoke", ja: "失効" }), onClick: () => revokeEnrolToken(t, host) }));
    }
    // What the token BECAME is the useful column once it has been used: an admin looking at this months later
    // wants the device, not the token.
    const outcome = t.used_by
      ? el("div", {}, [el("strong", { text: t.used_by }), el("div", { class: "ui-view-desc", text: bl({ en: "enrolled " + window.dsseFormatTime(t.used_at), ja: window.dsseFormatTime(t.used_at) + " に登録" }) })])
      : el("span", { class: "ui-view-desc", text: state.key === "waiting" ? enrolTimeLeft(t.expires_at) : "—" });

    return el("tr", {}, [
      el("td", {}, [el("strong", { text: t.label || bl({ en: "(no label)", ja: "(ラベルなし)" }) }),
        t.group ? el("div", { class: "ui-view-desc", text: bl({ en: "group " + t.group, ja: "グループ " + t.group }) }) : el("span", {})]),
      el("td", {}, uiBadge(state.label, state.tone)),
      el("td", {}, outcome),
      el("td", { class: "ui-view-desc", text: approvedByLabel(t, _enrolAdminLabels) }),
      el("td", { class: "ui-row-actions" }, actions),
    ]);
  });

  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "Device", ja: "端末" }), bl({ en: "Status", ja: "状態" }),
      bl({ en: "Enrolled as / time left", ja: "登録名 / 残り時間" }),
      bl({ en: "Approved by", ja: "承認者" }), bl({ en: "Actions", ja: "操作" }),
    ].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

async function openEnrolTokenForm(content) {
  const labelF = uiField({ name: "label", label: bl({ en: "What is this device?", ja: "どの端末ですか" }), required: true,
    placeholder: bl({ en: "e.g. Sales laptop for the Osaka office", ja: "例: 大阪オフィス 営業用ノート PC" }),
    hint: bl({ en: "Only you see this. It is how you will recognise the device before it has a name.", ja: "管理者にのみ表示されます。端末名が付く前に見分けるための記録です。" }) });

  // The lifetime is the issuer's call because only they know whether the installer is going to the next desk or
  // into a courier's hands. The options name the SITUATION rather than a number, so the choice is made on what
  // the admin actually knows.
  const validF = uiField({ name: "valid", label: bl({ en: "How long until it is set up?", ja: "セットアップまでの期間" }), type: "select", value: "72",
    options: [
      { value: "8", label: bl({ en: "Today — being set up now", ja: "本日中 — いま設定する" }) },
      { value: "72", label: bl({ en: "A few days — handing it over soon", ja: "数日 — まもなく渡す" }) },
      { value: "168", label: bl({ en: "A week — kitting a batch", ja: "1週間 — まとめて準備する" }) },
      { value: "336", label: bl({ en: "Two weeks — shipping it out", ja: "2週間 — 配送する" }) },
    ],
    hint: bl({ en: "The token stops working after this. A shorter window is safer; re-approve if it lapses.", ja: "この期間を過ぎるとトークンは使えません。短いほど安全です。過ぎた場合は再度承認してください。" }) });

  const groupF = uiField({ name: "group", label: bl({ en: "Device group (optional)", ja: "デバイスグループ (任意)" }),
    hint: bl({ en: "Policy group the device joins. It cannot choose its own.", ja: "端末が所属するポリシーグループ。端末側からは指定できません。" }) });

  // Kitting is the ordinary case, not the exception. An admin images fifty laptops at once, and making them
  // repeat this dialog fifty times is the kind of friction that ends with somebody going back to one shared
  // secret for the whole batch. Each token is still one machine, once — the batch is a convenience for the
  // person, not a weaker credential.
  const countF = uiField({ name: "count", label: bl({ en: "How many devices?", ja: "何台分ですか" }), value: "1",
    hint: bl({ en: "One token per device. For a batch you will get a file to work through — the tokens cannot be shown again.",
               ja: "1台につき1枚です。複数の場合はファイルで受け取ります — 後から再表示はできません。" }) });

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Approve device", ja: "端末を承認" }) });
  const m = uiModal({
    title: bl({ en: "Approve a device", ja: "端末を承認" }),
    body: [labelF.el, countF.el, validF.el, groupF.el],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    if (submit.disabled || !labelF.validate()) return;
    submit.disabled = true;
    try {
      const count = Math.max(1, Number(countF.get()) || 1);
      const r = await apiFetch("POST", "/admin/enrolment-tokens",
        { label: labelF.get(), group: groupF.get(), expires_in_hours: Number(validF.get()), count },
        _ENROL_PLANE);
      if (!r.ok && r.status === 409 && r.body && r.body.partial === true &&
          Array.isArray(r.body.tokens) && r.body.tokens.length > 0 && enrolTokenRowsValid(r.body.tokens)) {
        m.close();
        showEnrolTokenOnce({ ...r.body, requested_count: count });
        renderEnrolmentTokensView(content);
        return;
      }
      if (!r.ok) {
        submit.disabled = false;
        const uncertainPartial = r.status === 409 && r.body && r.body.partial === true;
        const msg = uncertainPartial ? enrolTokenResponseWarning() :
          (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status);
        labelF.setError(msg); uiToast(msg, "err"); return;
      }
      m.close();
      showEnrolTokenOnce(r.body);
      renderEnrolmentTokensView(content);
    } catch (e) { submit.disabled = false; uiToast(String(e), "err"); }
  });
  labelF.focus();
}

// A batch cannot be read off a screen. Fifty secrets in a modal is a list nobody can transcribe without losing
// one, so the file IS the deliverable — and since the tokens exist in this response and nowhere else, the
// download has to happen before the dialog closes.
function downloadTokenBatch(rows, count) {
  const header = "label,token_id,secret,expires_at\n";
  const csv = header + rows.map((r) => [
    r.token.label || "",
    r.token.id,
    r.secret,
    r.token.expires_at,
  ].map(value => '"' + String(value == null ? "" : value).replace(/"/g, '""') + '"').join(",")).join("\n") + "\n";
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "enrolment-tokens-" + count + ".csv";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// The secret exists in this one response and nowhere else — the Edge keeps only a hash — so the modal has to be
// unmistakable about that. A lost token is re-approved, not looked up.
function enrolTokenRowsValid(rows) {
  return rows.every(r => r && r.token && typeof r.token === "object" && !Array.isArray(r.token) &&
    typeof r.token.id === "string" && r.token.id.length > 0 && typeof r.secret === "string" && r.secret.length > 0);
}
function enrolTokenResponseWarning() {
  return bl({
    en: "Token issuance could not be confirmed. Tokens may already have been created. Resolve the failure and reload the unused-token list before issuing more; revoke any unneeded tokens.",
    ja: "トークンの発行結果を確認できません。サーバー側では発行済みの可能性があります。障害を解消し、未使用トークンの一覧を再読込してから追加発行してください。不要なものは失効してください。"
  });
}
function showEnrolTokenOnce(body) {
  const rows = (body && body.tokens) || [];
  if (!Array.isArray(rows) || !enrolTokenRowsValid(rows)) {
    uiToast(enrolTokenResponseWarning(), "err"); return;
  }
  const notice = body && body.partial === true ? [el("p", { class: "ui-view-desc", text: bl({
    en: "Issuance stopped: " + rows.length + " of " + body.requested_count + " requested tokens were returned. Save these tokens and investigate the failure before issuing more.",
    ja: "発行が途中で停止しました。要求 " + body.requested_count + " 件中 " + rows.length + " 件を受け取りました。このトークンを保存し、追加発行の前に失敗原因を確認してください。"
  }) })] : [];
  if (rows.length > 1) {
    let downloaded = false;
    const dl = el("button", { class: "ui-btn ui-btn-primary",
      text: bl({ en: "Download the tokens", ja: "トークンをダウンロード" }) });
    const m2 = uiModal({
      title: bl({ en: rows.length + " devices approved", ja: rows.length + " 台を承認しました" }),
      body: [
        ...notice,
        el("p", { class: "ui-view-desc", text: bl({
          en: "This is the only time these tokens are shown. Download them now — they cannot be retrieved later, and an approval that is lost has to be made again.",
          ja: "これらのトークンが表示されるのはこの一度だけです。いまダウンロードしてください — 後から取得はできず、失った分は承認をやり直すことになります。" }) }),
        el("p", { class: "ui-view-desc", text: bl({
          en: "The file contains live credentials, one per device. Delete it once the machines are set up.",
          ja: "ファイルには端末1台ごとの有効な資格情報が入っています。セットアップが終わったら削除してください。" }) }),
        dl,
      ],
      footer: [el("button", { class: "ui-btn", text: bl({ en: "Done", ja: "完了" }),
        onClick: () => {
          // Closing without downloading throws the batch away, so say so rather than letting it happen quietly.
          if (!downloaded) {
            uiToast(bl({ en: "Closed without downloading — those approvals cannot be recovered and will have to be made again.",
                         ja: "ダウンロードせずに閉じました — その承認は復元できず、やり直しになります。" }), "err");
          }
          m2.close();
        } })],
    });
    dl.addEventListener("click", () => {
      downloadTokenBatch(rows, rows.length);
      downloaded = true;
      dl.textContent = bl({ en: "Downloaded — download again", ja: "ダウンロード済み — 再ダウンロード" });
    });
    return;
  }
  const secret = (body && body.secret) || (rows.length === 1 && rows[0].secret);
  if (typeof secret !== "string" || !secret) { uiToast(enrolTokenResponseWarning(), "err"); return; }
  // ★★★ THE TOKEN IS A FILE, NOT A FIELD (2026-08-30). This offered the secret as text to read, and said to
  // "put it in the device's installer settings" — there are no installer settings. What the installer reads is
  // a file named enrolment_token.txt sitting next to it, so that is what this hands over. Typing a 43-character
  // secret by hand was never a step anyone should have been asked for, and a mistyped one fails at the Edge
  // with the same sentence as a token that was never issued.
  const dlToken = el("button", { class: "ui-btn ui-btn-primary",
    text: bl({ en: "Download enrolment_token.txt", ja: "enrolment_token.txt をダウンロード" }) });
  dlToken.addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([String(secret) + "\n"], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "enrolment_token.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    dlToken.textContent = bl({ en: "Downloaded — download again", ja: "ダウンロード済み — 再ダウンロード" });
  });
  const m = uiModal({
    title: bl({ en: "Device approved — take the token now", ja: "端末を承認しました — トークンを今受け取ってください" }),
    body: [
        ...notice,
      el("p", { class: "ui-view-desc", text: bl({
        en: "This is the only time this token is shown. If it is lost, approve the device again — it cannot be looked up.",
        ja: "このトークンが表示されるのはこの一度だけです。紛失した場合は再度承認してください — 後から確認することはできません。" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Put this file in the same folder as the installer, together with install_profile.json and profile_signing_key.txt from Device configuration. Then open the installer — it takes them from there, and nothing has to be typed or copied into a system folder.",
        ja: "このファイルを、インストーラと同じフォルダに、「端末の設定」で作った install_profile.json・profile_signing_key.txt と一緒に置いてください。あとはインストーラを開くだけです — そこから取り込まれるので、入力もシステムフォルダへのコピーも要りません。" }) }),
      el("div", { class: "ui-preview", text: String(secret) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "It works for one machine, once. Nobody needs to sign in to use it. Delete the file once the machine is set up.",
        ja: "1台につき一度だけ使えます。使用時のサインインは不要です。セットアップが終わったらファイルは削除してください。" }) }),
    ],
    footer: [dlToken, el("button", { class: "ui-btn", text: bl({ en: "Done", ja: "完了" }), onClick: () => m.close() })],
  });
}

async function revokeEnrolToken(t, host) {
  const name = t.label || t.id;
  const ok = await uiConfirm({
    title: bl({ en: "Revoke this approval?", ja: "この承認を取り消しますか?" }),
    body: bl({
      en: "“" + name + "” can no longer be set up with this token. Approve it again to issue a new one.",
      ja: "「" + name + "」はこのトークンではセットアップできなくなります。再度承認すると新しいトークンを発行できます。" }),
    confirmLabel: bl({ en: "Revoke", ja: "失効" }), danger: true,
  });
  if (!ok) return;
  let r;
  try { r = await apiFetch("POST", "/admin/enrolment-tokens/" + encodeURIComponent(t.id) + "/revoke", {}, _ENROL_PLANE); }
  catch (e) { uiToast(String(e), "err"); return; }
  if (!r.ok) { uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err"); return; }
  // An admin who revokes AFTER the device enrolled is reaching for the wrong control, and the API says so.
  // Surfacing that is the difference between them fixing the problem and believing it is already fixed.
  const note = r.body && r.body.note;
  uiToast(note || bl({ en: "Approval revoked.", ja: "承認を取り消しました。" }), note ? "err" : "ok");
  renderEnrolTokenList(host);
}
