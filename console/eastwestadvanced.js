"use strict";


// eastwestadvanced.js — the Observations (Observe) view of Connector Access: the lateral-flow inventory the Edge
// records + the review-before-adopt flow (adoptFlowIntoRule). The old runtime tabs (standing Approvals / pending
// Verifications) were removed — transient grant/step-up state is not authored here.

// ewObservations (S1, Observe): the lateral-flow inventory the Edge records while pre-enforce — source → dest :
// service, with per-flow coverage against the current rules and a convergence summary. The operator reviews the
// UNCOVERED flows and adopts them into rules (S2); when uncovered reaches 0 it is safe to disable Allow-all (S5).
async function ewObservations(section) {
  uiState(section, "loading");
  const current = freshRender(section);
  let body;
  try { const r = await apiFetch("GET", "/admin/east-west/observations"); if (!r.ok) throw new Error("HTTP " + r.status); body = r.body || {}; }
  catch (e) { if (!current()) return; uiState(section, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => ewObservations(section) }); return; }
  if (!current()) return;
  section.innerHTML = "";
  const conv = body.convergence || {};
  const obs = body.observations || [];
  const cov = typeof conv.coverage_percent === "number" ? conv.coverage_percent.toFixed(0) : "0";
  section.appendChild(el("p", { class: "ui-view-desc", text: bl({
    en: obs.length + " observed lateral flows · " + (conv.covered_flows || 0) + " covered by rules (" + cov + "%) · " + (conv.uncovered_flows || 0) + " uncovered. Adopt the uncovered flows into rules; when uncovered reaches 0 it is safe to disable Allow-all.",
    ja: "観測した横方向フロー " + obs.length + " 件 · ルールでカバー " + (conv.covered_flows || 0) + " (" + cov + "%) · 未カバー " + (conv.uncovered_flows || 0) + "。未カバーをルール化し、0 になれば Allow-all を無効化しても安全。",
  }) }));
  if (!obs.length) { section.appendChild(emptyBox(bl({ en: "No lateral flows observed yet.", ja: "まだ横方向フローは観測されていません。" }))); return; }

  // S2 (Candidate + adopt): each UNCOVERED flow gets an "Adopt" button that OPENS THE RULE EDITOR pre-filled
  // (Source = Any, Destination = the observed host as a first-class endpoint, Service from the port, Access = Allow)
  // so the operator REVIEWS and adjusts the rule and only SAVES to apply it — nothing is created behind their back.
  // Covered flows already have a rule (no button). See adoptFlowIntoRule.
  const uncoveredCount = obs.filter((o) => !o.covered).length;
  section.appendChild(el("p", { class: "ui-view-desc", text: uncoveredCount
    ? bl({ en: uncoveredCount + " uncovered flow(s). Click Adopt to open a pre-filled rule (Source = Any, Allow) for review, then Save.", ja: "未カバー " + uncoveredCount + " 件。Adopt を押すと事前入力済みルール(送信元=Any・許可)が開くので、確認・調整して保存してください。" })
    : bl({ en: "All observed flows are already covered by rules.", ja: "観測フローはすべてルールでカバー済みです。" }) }));

  const rows = obs.map((o) => {
    // User column: the logged-in user behind the flow, or a "system" badge when unattended (machine/service).
    const userCell = o.user
      ? el("span", {}, [el("span", { text: "👤 " + o.user }), document.createTextNode(" "), uiBadge(bl({ en: "human", ja: "人間" }), "ok")])
      : uiBadge(bl({ en: "system", ja: "システム" }), "off");
    const actionCell = o.covered
      ? el("span", { class: "ui-view-desc", text: "—" })
      : el("button", { class: "ui-btn ui-btn-sm ui-btn-primary", text: bl({ en: "Adopt →", ja: "ルール化 →" }),
          title: bl({ en: "Open a pre-filled rule for this flow to review and save", ja: "このフローの事前入力ルールを開いて確認・保存" }),
          onClick: () => adoptFlowIntoRule(o, section) });
    return el("tr", {}, [
      el("td", { text: o.source || "—" }),
      el("td", {}, userCell),
      el("td", {}, el("code", { text: (o.destination || "—") + (o.port ? ":" + o.port : "") })),
      el("td", { text: o.service_family || "—" }),
      el("td", { text: String(o.count || 0) }),
      el("td", { class: "ui-view-desc", text: o.last_seen ? window.dsseFormatTime(o.last_seen) : "—" }),
      el("td", {}, o.covered ? uiBadge(bl({ en: "covered", ja: "カバー済" }), "ok") : uiBadge(bl({ en: "uncovered", ja: "未カバー" }), "warn")),
      el("td", { class: "ui-row-actions" }, actionCell),
    ]);
  });
  section.appendChild(el("table", { class: "ui-table" }, [
    el("thead", {}, el("tr", {}, [bl({ en: "Source", ja: "送信元" }), bl({ en: "User", ja: "ユーザー" }), bl({ en: "Destination", ja: "宛先" }), bl({ en: "Service", ja: "サービス" }), bl({ en: "Count", ja: "回数" }), bl({ en: "Last seen", ja: "最終" }), bl({ en: "Coverage", ja: "カバー" }), bl({ en: "Adopt", ja: "採用" })].map((x) => el("th", { text: x })))),
    el("tbody", {}, rows),
  ]));
}

// adoptFlowIntoRule turns an observed flow into a rule THE OPERATOR REVIEWS FIRST: it materializes the observed
// destination as a first-class network endpoint (so the rule references a named, editable object — not a raw IP)
// and resolves the service from the port, then opens the standard rule editor PRE-FILLED (Source = Any, Access =
// Allow). The operator adjusts anything and Saves — only then is the rule applied (via the normal POST /admin/rules).
async function adoptFlowIntoRule(o, section) {
  try {
    // 0) Duplicate guard: re-check coverage NOW (the Adopt button may be stale if another flow to the same
    //    destination+service was just adopted). If a rule already covers this flow, don't create a second — refresh.
    try {
      const cur = await apiFetch("GET", "/admin/east-west/observations");
      const fresh = cur && cur.ok && cur.body && (cur.body.observations || []).find((x) => x.observation_id === o.observation_id);
      if (fresh && fresh.covered) { uiToast(bl({ en: "A rule already covers this flow.", ja: "このフローはすでにルールでカバーされています。" }), "info"); ewObservations(section); return; }
    } catch (e) { /* non-fatal — proceed */ }

    // 1) Resolve the service by the observed port (unambiguous: 22→SSH, 445→SMB, 3389→RDP, 5985→WinRM-HTTP),
    //    falling back to the built-in-svc-<family> convention, else no service constraint.
    let serviceId = "";
    const svcs = await loadList("/admin/assets/services");
    const byPort = (svcs || []).find((s) => (s.ports || []).some((p) => String(p.protocol).toLowerCase() === "tcp" && p.port === o.port));
    if (byPort) serviceId = byPort.id;
    else if (o.service_family) serviceId = "builtin-svc-" + String(o.service_family).toLowerCase();

    // 2) Materialize (or reuse) a network endpoint for the destination so the rule references a GUI-visible,
    //    editable object. Dedup by address. When creating a NEW one, let the operator NAME it (default = the
    //    address). Track whether WE created it, so canceling the editor can undo it — nothing left behind unless
    //    a rule is actually saved.
    let endpointId = "", createdEndpoint = false;
    const eps = await loadList("/admin/assets/endpoints");
    const existingEp = (eps || []).find((e) => e.kind === "network" && (e.address || "").toLowerCase() === (o.destination || "").toLowerCase());
    if (existingEp) endpointId = existingEp.id;
    else {
      const alias = await uiPrompt({
        title: bl({ en: "Name this destination", ja: "宛先に名前を付ける" }),
        label: bl({ en: "A friendly name for " + o.destination + " (or keep the address).", ja: o.destination + " の分かりやすい名前(アドレスのままでも可)。" }),
        value: o.destination, placeholder: o.destination,
        confirmLabel: bl({ en: "Continue", ja: "続ける" }),
      });
      if (alias === null) return; // operator cancelled — create nothing
      const r = await apiFetch("POST", "/admin/assets/endpoints", { alias: (alias.trim() || o.destination), kind: "network", source: "manual", steered: false, address: o.destination });
      if (!r.ok || !r.body || !r.body.id) { uiToast((r.body && (r.body.error || r.body.message)) || bl({ en: "Could not create the destination endpoint.", ja: "宛先エンドポイントを作成できませんでした。" }), "err"); return; }
      endpointId = r.body.id; createdEndpoint = true;
    }

    // 3) Open the rule editor PRE-FILLED (no id ⇒ a new rule the operator reviews + saves). On cancel/Esc, undo
    //    the endpoint we just created (only if we created it) so canceling leaves nothing behind.
    openRuleEditor("east_west", "outbound", () => ewObservations(section), {
      priority: 100,
      name: "Adopted: " + (o.destination || "") + (o.port ? ":" + o.port : ""),
      source: [SUBJECT_ANY],
      destination: [endpointId],
      service_id: serviceId || undefined,
      action: { access: "allow", inspection: "inspect" },
      stage: "enforce",
      direction: "outbound",
    }, () => { if (createdEndpoint) apiFetch("DELETE", "/admin/assets/endpoints/" + encodeURIComponent(endpointId)).catch(() => {}); });
  } catch (e) { uiToast(String(e), "err"); }
}
