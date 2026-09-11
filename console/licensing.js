"use strict";

// licensing.js — "Licensing & Seats": what an MSSP holds, how it is divided, and who cannot enrol.
//
// Built around the three things that actually generate work for an operator, in that order of urgency:
//
//   1. somebody cannot enrol a device and has rung up          → shown FIRST, with the reason
//   2. a licence has arrived and has to go in                  → one button, always previewed
//   3. a tenant needs seats                                  → edited in place, in the table
//
// The blocked list is at the top on purpose. A page that leads with totals and buries the one tenant that
// cannot work is a page an operator reads after the phone call instead of before it.
//
// Backend: GET /admin/license, POST /admin/license (with ?dry_run=true), POST /admin/seat-allocations,
// DELETE /admin/seat-allocations/{tenant}.

let _licSearch = "";

function renderLicensingView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Licensing & Seats", ja: "ライセンスとシート数" }) }),
      // ★ TWO READERS, ONE SCREEN (2026-08-17, measured as a customer administrator). The operator divides a
      // pool among organizations; a customer asks whether ITS devices can enrol and how many seats it holds.
      // The description described only the first, on a screen every customer sees in their navigation.
      el("p", { class: "ui-view-desc", text: answeringForTheDeployment()
        ? bl({ en: "How many devices you may enrol, how that is divided among your tenants, and which of them cannot enrol right now.",
               ja: "登録できる端末数、テナントごとの配分、そしていま登録できないテナント。" })
        : bl({ en: "How many devices your tenant may enrol, and how many of those seats are in use.",
               ja: "このテナントが登録できる端末数と、そのうち何台を使っているか。" }) }),
    ]),
    // ★ AND THE CONTROLS ARE THE OPERATOR'S. Measured signed in as a customer administrator: "Apply a
    // licence" answers 403, "Give seats to a tenant" answers 403, "Take back" answers 403. Three buttons that
    // cannot work, on a screen the customer's own navigation offers them — which is the failure the operator
    // nav was reshaped to avoid, arriving from the other side.
    ...(answeringForTheDeployment()
      ? [el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Apply a licence", ja: "ライセンスを適用" }),
          onClick: () => openApplyLicence(content) })]
      : []),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  loadLicensing(host, content);
}

async function loadLicensing(host, content) {
  uiState(host, "loading");
  const current = freshRender(host);
  let body;
  try {
    const r = await apiFetch("GET", "/admin/license");
    if (r.status === 503) {
      if (!current()) return;
      uiState(host, "empty", bl({
        en: "This deployment does not use licensing. Seats are not limited and there is nothing to divide.",
        ja: "この環境はライセンス管理を使っていません。シート数の制限も配分もありません。" }));
      return;
    }
    if (!r.ok) { if (!current()) return; uiState(host, "error", "HTTP " + r.status, { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadLicensing(host, content) }); return; }
    body = r.body || {};
  } catch (e) { if (!current()) return; uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadLicensing(host, content) }); return; }

  if (!current()) return;
  host.innerHTML = "";
  const tenants = body.tenants || [];

  // 1. WHO CANNOT WORK. First, always, and only when there is something to say.
  const blocked = tenants.filter((t) => t.blocked);
  if (blocked.length) {
    const rows = blocked.map((t) => el("li", {}, [
      el("strong", { text: t.tenant_id }),
      document.createTextNode(" — " + t.reason),
    ]));
    host.appendChild(el("div", { class: "ui-callout ui-callout-warn" }, [
      el("strong", { text: bl({
        en: blocked.length === 1 ? "1 tenant cannot enrol new devices"
                                 : blocked.length + " tenants cannot enrol new devices",
        ja: "新規登録できないテナント: " + blocked.length + " 件" }) }),
      el("ul", {}, rows),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Devices they already run are unaffected — only new enrolments are refused.",
        ja: "稼働中の端末には影響ありません。止まっているのは新規登録だけです。" }) }),
    ]));
  }

  // 2. WHAT YOU HOLD, and what changes next.
  host.appendChild(licenceSummary(body));

  // 3. WHERE IT WENT, editable in place.
  const search = el("input", { class: "ui-input ui-search", type: "search",
    placeholder: bl({ en: "Search tenants…", ja: "テナントを検索…" }) });
  search.value = _licSearch;
  const tableHost = el("div", {});
  search.addEventListener("input", () => { _licSearch = search.value; renderTenantTable(tableHost, body, host, content); });
  host.appendChild(el("div", { class: "ui-toolbar" }, [
    search, el("span", { class: "ui-spacer" }),
    ...(answeringForTheDeployment()
      ? [el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Give seats to a tenant", ja: "テナントにシートを割り当て" }),
          onClick: () => openAllocate(null, body, host, content) })]
      : []),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }),
      onClick: () => loadLicensing(host, content) }),
  ]));
  host.appendChild(tableHost);
  renderTenantTable(tableHost, body, host, content);
}

// What the operator holds. Deliberately short: seats, what is left to give out, and the NEXT thing that will
// change — not a list of every date, which reads as reference material rather than as something to act on.
function licenceSummary(body) {
  const box = el("div", { class: "ui-card" });
  // Enforcement that counts nothing is not enforcement, and a seat table reading zero looks exactly like an
  // empty fleet. Seats are counted per tenant; an enrolled entry with no tenant is counted against no pool, so
  // the limit cannot bite and nothing on this page would have said so.
  if (body.seat_counting === "not_counting") {
    box.appendChild(el("div", { class: "ui-preview", style: "margin-bottom:10px" }, [
      el("div", {}, el("strong", { text: bl({
        en: "The seat limit is not being applied", ja: "シート上限が適用されていません" }) })),
      el("div", { text: body.seat_counting_note || "" }),
      el("div", { text: bl({
        en: "Usage below reads zero for that reason, not because no devices are enrolled.",
        ja: "以下の使用数が0なのはそのためであり、端末が登録されていないからではありません。" }) }),
    ]));
  }
  if (!body.licensed && !body.enforced) {
    // This deployment does not gate enrolment on a licence. Saying "no devices can enrol" here would be false.
    box.appendChild(el("p", {}, el("strong", { text: bl({
      en: "Licensing is not enforced on this deployment", ja: "この環境ではライセンスによる制限を行っていません" }) })));
    box.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "Devices enrol without a seat limit. Apply a licence only if you are moving this deployment under one.",
      ja: "シート数の制限なく端末を登録できます。ライセンス管理下に移す場合にのみ適用してください。" }) }));
    return box;
  }
  if (!body.licensed) {
    const neverLicensed = body.state === "no_licence_installed";
    box.appendChild(el("p", {}, [
      el("strong", { text: neverLicensed
        ? bl({ en: "No licence installed", ja: "ライセンス未適用" })
        : bl({ en: "The installed licence no longer verifies", ja: "適用済みライセンスが検証できません" }) }),
    ]));
    box.appendChild(el("p", { class: "ui-view-desc", text: neverLicensed
      ? bl({ en: "Apply the licence file your vendor sent. No devices can enrol until you do.",
             ja: "ベンダから届いたライセンスファイルを適用してください。適用するまで端末は登録できません。" })
      : bl({ en: "It was accepted once and does not verify now. Devices already running are unaffected; no new one can enrol.",
             ja: "一度は受理されましたが現在は検証できません。稼働中の端末には影響ありませんが、新規登録はできません。" }) }));
    // ★ WHICH CHECK FAILED, FROM THE VERIFIER (2026-08-17). This used to assert the cause — "usually a vendor
    // signing key that has been withdrawn" — and on the lab that guess was wrong: the licence was addressed to
    // an MSSP id the deployment had since been renamed away from. Three causes, three different responses, and
    // the verifier names the one that happened. Guessing sent an operator after a replacement key while no
    // device could enrol.
    if (!neverLicensed && body.verification_error) {
      box.appendChild(el("p", { class: "ui-view-desc" }, [
        el("strong", { text: bl({ en: "Why: ", ja: "理由: " }) }),
        document.createTextNode(String(body.verification_error)),
      ]));
    }
    return box;
  }

  const seats = body.seats || 0;
  const unallocated = body.unallocated || 0;
  box.appendChild(el("p", {}, [
    el("strong", { text: bl({ en: seats + " seats licensed", ja: "ライセンスシート数 " + seats }) }),
    document.createTextNode(" · "),
    el("span", { text: bl({ en: unallocated + " not yet given to a tenant", ja: "未配分 " + unallocated }) }),
    body.is_evaluation ? document.createTextNode(" ") : document.createTextNode(""),
    body.is_evaluation ? uiBadge(bl({ en: "Evaluation", ja: "評価版" }), "warn") : el("span", {}),
  ]));
  if (unallocated < 0) {
    box.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "You have given out " + (-unallocated) + " more seats than you hold.",
      ja: "保有数より " + (-unallocated) + " シート多く配分しています。" }) }));
  }

  // ★★ WHAT IS ACTUALLY IN USE, which the line above does not say. "Not yet given to a tenant" counts the
  // operator's PLAN; the licence is billed in agents, so the count of agents is its own line. Absent for a
  // customer administrator — the backend sends it only to the operator, because a deployment-wide device count
  // tells a small customer how many devices belong to organizations they cannot see.
  if (typeof body.agents_enrolled === "number") {
    const enrolled = body.agents_enrolled;
    const left = typeof body.seats_remaining === "number" ? body.seats_remaining : seats - enrolled;
    box.appendChild(el("p", {}, [
      el("strong", { text: bl({ en: enrolled + " agents enrolled", ja: "登録済みエージェント " + enrolled }) }),
      document.createTextNode(" · "),
      el("span", { text: left >= 0
        ? bl({ en: left + " of the licence left", ja: "ライセンス残 " + left })
        : bl({ en: (-left) + " over the licence", ja: "ライセンス超過 " + (-left) }) }),
    ]));
    if (body.usage_note) {
      box.appendChild(el("p", { class: "ui-view-desc", text: bl({
        en: String(body.usage_note),
        ja: "登録済み " + enrolled + " 台に対しライセンスは " + seats + " 台です。" +
            "拒否は起きておらず、どの端末にも影響はありません —— ライセンスはエージェント数で数えるため、" +
            "これは供給元との契約の話です。" }) }));
    }
  }

  // What happens NEXT — one line, whichever comes first.
  const next = nextLicenceEvent(body);
  if (next) box.appendChild(el("p", { class: "ui-view-desc", text: next }));

  // The blocks, only when there is more than one — otherwise the seat count already says it.
  const grants = (body.grants || []).filter((g) => !g.feature);
  if (grants.length > 1) {
    box.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "Made up of " + grants.map((g) => g.seats + " seats until " + window.dsseFormatTime(g.ends_at)).join(", "),
      ja: "内訳: " + grants.map((g) => g.seats + "シート (" + window.dsseFormatTime(g.ends_at) + " まで)").join("、") }) }));
  }
  const features = body.features || [];
  if (features.length) {
    box.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "Optional capabilities licensed: " + features.join(", "),
      ja: "ライセンス済みオプション: " + features.join("、") }) }));
  }
  return box;
}

// The single most useful sentence on the page: what will change, and when. An operator does not need four dates;
// they need the next one.
function nextLicenceEvent(body) {
  const events = [];
  const push = (at, text) => { if (at) events.push({ at: new Date(at), text }); };
  push(body.next_pool_change_at, bl({
    en: "Seats change to " + body.next_pool_seats + " on " + window.dsseFormatTime(body.next_pool_change_at),
    ja: window.dsseFormatTime(body.next_pool_change_at) + " にシート数が " + body.next_pool_seats + " に変わります" }));
  push(body.expires_at, bl({
    en: "Renewal due " + window.dsseFormatTime(body.expires_at),
    ja: "更新期限 " + window.dsseFormatTime(body.expires_at) }));
  push(body.enrolment_stops_at, bl({
    en: "New enrolments stop " + window.dsseFormatTime(body.enrolment_stops_at),
    ja: window.dsseFormatTime(body.enrolment_stops_at) + " に新規登録が止まります" }));
  push(body.service_ends_at, bl({
    en: "Service ends " + window.dsseFormatTime(body.service_ends_at),
    ja: window.dsseFormatTime(body.service_ends_at) + " にサービスが終了します" }));
  const now = new Date();
  const upcoming = events.filter((e) => e.at > now).sort((a, b) => a.at - b.at);
  return upcoming.length ? upcoming[0].text : null;
}

function renderTenantTable(host, body, outerHost, content) {
  const q = _licSearch.trim().toLowerCase();
  const tenants = (body.tenants || []).filter((t) => !q || t.tenant_id.toLowerCase().includes(q));
  host.innerHTML = "";
  if (!(body.tenants || []).length) {
    uiState(host, "empty", bl({
      en: "No tenants yet. Give a tenant seats and its devices can start enrolling.",
      ja: "テナントがまだありません。シートを割り当てると、そのテナントの端末が登録できるようになります。" }));
    return;
  }
  if (!tenants.length) { uiState(host, "empty", bl({ en: "No matches.", ja: "一致なし。" })); return; }

  const mayAllocate = answeringForTheDeployment();
  const rows = tenants.map((t) => {
    // Dividing the pool is the operator's act; a customer reading its own row has nothing to press here.
    const actions = el("div", { class: "ui-row-actions" }, mayAllocate ? [
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Change seats", ja: "シート数を変更" }),
        onClick: () => openAllocate(t, body, outerHost, content) }),
    ] : []);
    if (mayAllocate && t.allocated > 0) {
      actions.appendChild(document.createTextNode(" "));
      actions.appendChild(el("button", { class: "ui-btn ui-btn-sm ui-btn-danger",
        text: bl({ en: "Take back", ja: "回収" }), onClick: () => removeAllocation(t, outerHost, content) }));
    }
    // The name a person uses, with the identifier underneath rather than instead of it. This page is read
    // while somebody is on the phone about a tenant that cannot enrol; making the reader translate ids in
    // their head is how the wrong tenant gets changed.
    const nameCell = t.display_name
      ? el("td", {}, [el("strong", { text: t.display_name }),
                      el("div", { class: "ui-view-desc", text: t.tenant_id })])
      : el("td", {}, el("strong", { text: t.tenant_id }));
    return el("tr", {}, [
      nameCell,
      el("td", { text: t.allocated > 0 ? String(t.allocated) : bl({ en: "none", ja: "なし" }) }),
      el("td", { text: String(t.used) }),
      el("td", {}, t.blocked
        ? el("div", {}, [uiBadge(bl({ en: "Cannot enrol", ja: "登録不可" }), "danger"),
                         el("div", { class: "ui-view-desc", text: t.reason || "" })])
        : uiBadge(bl({ en: "OK", ja: "OK" }), "ok")),
      el("td", { class: "ui-row-actions" }, actions),
    ]);
  });
  host.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [
      bl({ en: "Tenant", ja: "テナント" }), bl({ en: "Seats given", ja: "割当シート数" }),
      bl({ en: "In use", ja: "使用中" }), bl({ en: "Can enrol?", ja: "登録可否" }),
      bl({ en: "Actions", ja: "操作" }),
    ].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

async function openAllocate(tenant, body, host, content) {
  const idF = uiField({ name: "tenant", label: bl({ en: "Tenant", ja: "テナント" }), required: true,
    value: tenant ? tenant.tenant_id : "" });
  const seatsF = uiField({ name: "seats", label: bl({ en: "Seats", ja: "シート数" }), required: true,
    value: tenant ? String(tenant.allocated) : "",
    hint: bl({ en: (body.unallocated || 0) + " seats are not yet given to anyone.",
               ja: "未配分のシート数: " + (body.unallocated || 0) }) });
  const noteF = uiField({ name: "note", label: bl({ en: "Note (optional)", ja: "メモ (任意)" }) });

  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Save", ja: "保存" }) });
  const m = uiModal({
    title: tenant ? bl({ en: "Change seats for " + tenant.tenant_id, ja: tenant.tenant_id + " のシート数を変更" })
                  : bl({ en: "Give seats to a tenant", ja: "テナントにシートを割り当て" }),
    body: [idF.el, seatsF.el, noteF.el],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });
  submit.addEventListener("click", async () => {
    if (!idF.validate() || !seatsF.validate()) return;
    submit.disabled = true;
    const r = await apiFetch("POST", "/admin/seat-allocations",
      { tenant_id: idF.get(), seats: Number(seatsF.get()), note: noteF.get() });
    if (!r.ok) {
      submit.disabled = false;
      const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status);
      seatsF.setError(msg); uiToast(msg, "err"); return;
    }
    m.close();
    // Reducing below what a tenant is already using is allowed — say so rather than letting it look like it
    // failed. Nothing they run stops; only growth does.
    if (r.body && r.body.below_current_use) {
      uiToast(bl({ en: "Saved. This is below what it is already using — their existing devices keep working, but they cannot enrol more.",
                   ja: "保存しました。現在の使用数を下回っています — 稼働中の端末はそのまま動きますが、新規登録はできません。" }), "err");
    } else {
      uiToast(bl({ en: "Saved.", ja: "保存しました。" }), "ok");
    }
    loadLicensing(host, content);
  });
  idF.focus();
}

async function removeAllocation(tenant, host, content) {
  const ok = await uiConfirm({
    title: bl({ en: "Take back these seats?", ja: "シートを回収しますか?" }),
    body: bl({
      en: "“" + tenant.tenant_id + "” keeps the " + tenant.used + " devices it already runs, but cannot enrol any more until it is given seats again.",
      ja: "「" + tenant.tenant_id + "」は稼働中の " + tenant.used + " 台をそのまま使えますが、再度割り当てるまで新規登録はできません。" }),
    confirmLabel: bl({ en: "Take back", ja: "回収" }), danger: true,
  });
  if (!ok) return;
  const r = await apiFetch("DELETE", "/admin/seat-allocations/" + encodeURIComponent(tenant.tenant_id));
  if (!r.ok) { uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return; }
  uiToast(bl({ en: "Seats returned to the pool.", ja: "シートをプールに戻しました。" }), "ok");
  loadLicensing(host, content);
}

// Applying is always previewed. The API will say what the file would do — including whether it leaves the
// operator over-allocated — and finding THAT out afterwards is how a tenant's enrolment breaks with nobody
// realising why.
async function openApplyLicence(content) {
  const area = el("textarea", { class: "ui-input", rows: "6",
    placeholder: bl({ en: "Paste the licence file here, or choose it below.",
                      ja: "ライセンスファイルの内容を貼り付けるか、下から選択してください。" }) });
  const file = el("input", { class: "ui-input", type: "file", accept: ".json,.lic,.txt" });
  file.addEventListener("change", async () => {
    if (file.files && file.files[0]) area.value = await file.files[0].text();
  });
  const preview = el("div", {});
  const applyBtn = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Check this licence", ja: "ライセンスを確認" }) });
  let verified = false;

  const m = uiModal({
    title: bl({ en: "Apply a licence", ja: "ライセンスを適用" }),
    body: [
      el("p", { class: "ui-view-desc", text: bl({
        en: "The file your vendor sent. It is checked before anything changes.",
        ja: "ベンダから届いたファイルです。何かが変わる前に検証します。" }) }),
      area, file, preview,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), applyBtn],
  });

  applyBtn.addEventListener("click", async () => {
    const raw = area.value.trim();
    if (!raw) { uiToast(bl({ en: "Paste or choose a licence file first.", ja: "先にライセンスファイルを指定してください。" }), "err"); return; }
    applyBtn.disabled = true;

    if (!verified) {
      const r = await apiFetch("POST", "/admin/license?dry_run=true", raw);
      applyBtn.disabled = false;
      if (!r.ok) {
        preview.innerHTML = "";
        preview.appendChild(el("p", { class: "ui-view-desc", text: (r.body && r.body.error) || ("HTTP " + r.status) }));
        return;
      }
      const c = (r.body && r.body.change) || {};
      preview.innerHTML = "";
      const lines = [
        bl({ en: "Seats: " + c.seats_now + " → " + c.seats_after, ja: "シート数: " + c.seats_now + " → " + c.seats_after }),
        bl({ en: "Renewal due " + window.dsseFormatTime(c.expires_at), ja: "更新期限 " + window.dsseFormatTime(c.expires_at) }),
      ];
      if (c.is_evaluation) lines.push(bl({ en: "This is an evaluation licence.", ja: "これは評価版ライセンスです。" }));
      if (c.over_allocated_after > 0) {
        lines.push(bl({
          en: "You would be " + c.over_allocated_after + " seats over what you have already given out, so some tenants will need less.",
          ja: "配分済みのシート数を " + c.over_allocated_after + " シート超過します。一部のテナントの割当を減らす必要があります。" }));
      }
      lines.forEach((t) => preview.appendChild(el("p", { class: "ui-view-desc", text: t })));
      verified = true;
      applyBtn.textContent = bl({ en: "Apply it", ja: "適用する" });
      return;
    }

    const r = await apiFetch("POST", "/admin/license", raw);
    if (!r.ok) {
      applyBtn.disabled = false;
      uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return;
    }
    m.close();
    uiToast(bl({ en: "Licence applied.", ja: "ライセンスを適用しました。" }), "ok");
    renderLicensingView(content);
  });
}
