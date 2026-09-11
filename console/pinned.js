"use strict";

// ---------------------------------------------------------------------------
// "Pinned Sites" view — cert-pinning bypass RECOMMENDATIONS + ADOPTION.
//
// Some sites use certificate pinning and reject the edge's decrypt-all interception leaf, so they break under
// inspection. The edge DETECTS these (repeated interception-handshake failures) and proposes each as a durable
// TLS decrypt-bypass candidate — it NEVER auto-bypasses. This view is the operator surface to review those
// recommendations and adopt them: approve, then materialize (which writes the host into the SWG TLS bypass
// policy — the only state in which traffic is actually decrypt-bypassed).
//
// Backend (dsse-core / edge): GET /admin/policy-candidates, POST /admin/policy-candidates/{id}/review
// {decision, review_reason_code}, POST /admin/policy-candidates/{id}/materialize. Candidates whose
// source == "cert_pinning_detection" are the pinned-site (bypass) recommendations.
//
// Loaded after app.js, so apiFetch / bl / escapeHtml are in scope. app.js dispatches here for the GROUPS
// entry flagged `custom: "pinned"`.
// ---------------------------------------------------------------------------

const PINNED_STATUS_STYLE = {
  pending: "background:#fef3c7;color:#92400e",
  approved: "background:#dbeafe;color:#1e40af",
  materialized: "background:#dcfce7;color:#166534",
  rejected: "background:#fee2e2;color:#991b1b",
  suppressed: "background:#f3f4f6;color:#4b5563",
  dismissed: "background:#f3f4f6;color:#4b5563",
};

function pinnedStatusPill(status) {
  const s = String(status || "").trim() || "pending";
  const style = PINNED_STATUS_STYLE[s] || "background:#f3f4f6;color:#4b5563";
  return `<span style="${style};padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600">${escapeHtml(s)}</span>`;
}

function renderPinnedSitesView(content) {
  content.innerHTML = "";
  const h = document.createElement("h2");
  h.className = "group-title";
  h.textContent = bl({ en: "Pinned Sites", ja: "証明書ピンニングのサイト" });
  content.appendChild(h);
  const d = document.createElement("p");
  d.className = "group-desc";
  d.textContent = bl({
    en: "Sites that use certificate pinning reject the decrypt-all interception leaf and break under inspection. " +
      "The edge detects them and RECOMMENDS a TLS decrypt-bypass — it never bypasses on its own. Review each " +
      "recommendation and adopt it: Approve, then Materialize to write it into the TLS bypass policy (the only " +
      "state in which the site is actually decrypt-bypassed). Reject or Suppress a recommendation you do not want.",
    ja: "証明書ピンニングを使うサイトは復号傍受のサーバ証明書を拒否し、傍受下で壊れます。Edge はこれを検出し TLS 復号バイパスを" +
      "「推薦」します(自動でバイパスは絶対にしません)。各推薦をレビューして取り込んでください: 承認 → 取り込み" +
      "(Materialize)で TLS バイパスポリシーに書き込まれ、初めて実際にバイパスされます。不要な推薦は却下/抑制します。",
  });
  content.appendChild(d);

  const bar = document.createElement("div");
  bar.style.cssText = "margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap";
  const reloadBtn = document.createElement("button");
  reloadBtn.textContent = bl({ en: "Reload", ja: "再読込" });
  bar.appendChild(reloadBtn);
  // Search: filter the recommendations table AND the currently-bypassed list by host substring, so an operator
  // who discovers a broken site can check whether it is already detected/registered before adding it (there is
  // otherwise no way to tell). Filters the already-loaded data — it does not re-query the edge on each keystroke.
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = bl({ en: "Filter by host…", ja: "ホストで絞り込み…" });
  // Cap the width so the box does not stretch across the whole content area (readability); max-width keeps it
  // responsive on a narrow viewport.
  search.style.cssText = "width:280px;max-width:100%;padding:5px 9px";
  bar.appendChild(search);
  content.appendChild(bar);

  // Manual add: register a known pinned site directly, without waiting for the detector to surface it. Posts to
  // /admin/cert-pin-bypass, which approves + materializes in one step, so the site is decrypt-bypassed at once
  // and appears in both lists below exactly like a detected-then-adopted one.
  const addBar = document.createElement("div");
  addBar.style.cssText = "margin:0 0 8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap";
  const addInput = document.createElement("input");
  addInput.type = "text";
  addInput.placeholder = bl({ en: "Add a pinned site by host, e.g. gateway.example.com", ja: "証明書ピンニングのサイトをホスト名で追加 例: gateway.example.com" });
  // Capped width (not flex:1) so the field stays a readable size instead of spanning the full row.
  addInput.style.cssText = "width:380px;max-width:100%;padding:5px 9px";
  const addBtn = document.createElement("button");
  addBtn.textContent = bl({ en: "Register bypass", ja: "バイパス登録" });
  addBar.appendChild(addInput);
  addBar.appendChild(addBtn);
  // Inline status so the action is never silent (a thrown fetch used to leave the button stuck with no feedback).
  const addStatus = document.createElement("span");
  addStatus.style.cssText = "font-size:12px;margin-left:4px";
  addBar.appendChild(addStatus);
  content.appendChild(addBar);

  const container = document.createElement("div");
  content.appendChild(container);

  // Second section: the live decrypt-bypass set (shipped compatibility list + materialized recommendations).
  // This is why a host like github.com does NOT appear as a recommendation — it is bypassed by the shipped
  // list, so it is never intercepted, never fails a handshake, and never becomes a cert-pin candidate.
  const bypassHeader = document.createElement("h3");
  bypassHeader.textContent = bl({ en: "Currently bypassed (not decrypted)", ja: "現在バイパス中(復号しない)" });
  bypassHeader.style.cssText = "margin-top:22px";
  content.appendChild(bypassHeader);
  const bypassDesc = document.createElement("p");
  bypassDesc.className = "group-desc";
  bypassDesc.textContent = bl({
    en: "Hosts the edge never decrypts: the shipped compatibility list (Apple/iCloud/GitHub/OS-update/OCSP…) " +
      "plus the recommendations adopted (materialized) above. These never appear as recommendations because " +
      "they are never intercepted — e.g. github.com is on the shipped list.",
    ja: "Edge が一切復号しないホスト: 出荷時の互換リスト(Apple/iCloud/GitHub/OS更新/OCSP…)+ 上で取り込んだ" +
      "(materialized)推薦。これらは傍受されないので推薦には出ません(例: github.com は出荷リスト)。",
  });
  content.appendChild(bypassDesc);
  const bypassContainer = document.createElement("div");
  content.appendChild(bypassContainer);

  const filterText = () => search.value.trim().toLowerCase();
  const reloadAll = () => { reloadPinned(container, filterText()); reloadBypass(bypassContainer, filterText()); };
  reloadBtn.addEventListener("click", reloadAll);
  // Re-filter from the already-loaded data on each keystroke (no re-fetch).
  search.addEventListener("input", () => { paintPinned(container, filterText()); paintBypass(bypassContainer, filterText()); });

  const submitAdd = async () => {
    const host = addInput.value.trim();
    if (!host) return;
    addBtn.disabled = true;
    addStatus.style.color = "#4b5563";
    addStatus.textContent = bl({ en: "Registering…", ja: "登録中…" });
    try {
      const r = await apiFetch("POST", "/admin/cert-pin-bypass", { host: host });
      if (!r.ok) {
        let detail = "HTTP " + r.status;
        const j = r.body; // already-parsed body
        if (j && typeof j === "object" && j.error) detail += " — " + j.error;
        // A restarted edge invalidates the admin session, so a POST can 401/403 until the operator re-signs in.
        if (r.status === 401 || r.status === 403) detail += bl({ en: " (reload the page and sign in again)", ja: "(ページを再読込してサインインし直してください)" });
        addStatus.style.color = "#b91c1c";
        addStatus.textContent = bl({ en: "Failed: ", ja: "失敗: " }) + detail;
        return;
      }
      addInput.value = "";
      addStatus.style.color = "#047857";
      addStatus.textContent = bl({ en: host + " registered — now decrypt-bypassed.", ja: host + " を登録しました(復号バイパス有効)。" });
      reloadAll();
    } catch (e) {
      // A thrown fetch (network/TLS reset — e.g. right after an edge restart) must not fail silently.
      addStatus.style.color = "#b91c1c";
      addStatus.textContent = bl({ en: "Error: ", ja: "エラー: " }) + String((e && e.message) || e);
    } finally {
      addBtn.disabled = false;
    }
  };
  addBtn.addEventListener("click", submitAdd);
  addInput.addEventListener("keydown", (e) => { if (e.key === "Enter") submitAdd(); });

  reloadAll();
}

async function reloadBypass(container, filter) {
  container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "Loading…", ja: "読込中…" }))}</p>`;
  try {
    const r = await apiFetch("GET", "/admin/intercept/bypass-hosts");
    if (!r.ok) { container.innerHTML = `<p class="group-desc">HTTP ${r.status}</p>`; return; }
    container._bypassHosts = Array.isArray(r.body) ? r.body : [];
  } catch (e) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(String(e))}</p>`;
    return;
  }
  paintBypass(container, filter);
}

// paintBypass renders the cached bypass-host set filtered by substring. Split from reloadBypass so the search
// box can re-filter without re-querying the edge.
function paintBypass(container, filter) {
  const all = Array.isArray(container._bypassHosts) ? container._bypassHosts : [];
  const f = String(filter || "").trim().toLowerCase();
  const hosts = f ? all.filter((h) => String(h).toLowerCase().includes(f)) : all;
  if (all.length === 0) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "(none configured)", ja: "(設定なし)" }))}</p>`;
    return;
  }
  if (hosts.length === 0) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "(no matching hosts)", ja: "(一致するホストなし)" }))}</p>`;
    return;
  }
  const chips = hosts
    .slice()
    .sort()
    .map((h) => `<code style="display:inline-block;margin:2px 6px 2px 0;padding:2px 8px;background:#f3f4f6;color:#111827;border-radius:6px;font-size:12px">${escapeHtml(h)}</code>`)
    .join("");
  container.innerHTML = `<div>${chips}</div>`;
}

async function reloadPinned(container, filter) {
  container.innerHTML = `<p class="group-desc">${escapeHtml(bl({ en: "Loading…", ja: "読込中…" }))}</p>`;
  let data;
  try {
    const r = await apiFetch("GET", "/admin/policy-candidates");
    if (!r.ok) {
      container.innerHTML = `<p class="group-desc">HTTP ${r.status}</p>`;
      return;
    }
    data = r.body; // apiFetch returns { status, ok, body } with body already parsed (NOT a fetch Response)
  } catch (e) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(String(e))}</p>`;
    return;
  }
  const all = Array.isArray(data && data.candidates) ? data.candidates : [];
  // Cache the fetched (unfiltered) recommendations so the search box can re-filter without re-querying.
  container._pinnedAll = all
    .filter((c) => c.source === "cert_pinning_detection" || c.candidate_type === "bypass_policy")
    .sort((a, b) => (b.failure_count || 0) - (a.failure_count || 0));
  paintPinned(container, filter);
}

// paintPinned renders the cached recommendations filtered by host substring. Split from reloadPinned so the
// search box re-filters instantly and review/materialize actions repaint without dropping the current filter.
function paintPinned(container, filter) {
  container._filter = filter;
  const cached = Array.isArray(container._pinnedAll) ? container._pinnedAll : [];
  if (cached.length === 0) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(bl({
      en: "No pinned-site recommendations yet. When a site repeatedly rejects the interception leaf, it will appear here.",
      ja: "証明書ピンニングのサイトの推薦はまだありません。サイトが傍受のサーバ証明書を繰り返し拒否すると、ここに表示されます。",
    }))}</p>`;
    return;
  }
  const f = String(filter || "").trim().toLowerCase();
  const pinned = f
    ? cached.filter((c) => String(c.host || "").toLowerCase().includes(f) || String(c.sni || "").toLowerCase().includes(f))
    : cached;
  if (pinned.length === 0) {
    container.innerHTML = `<p class="group-desc">${escapeHtml(bl({
      en: "No pinned-site recommendations match the filter.",
      ja: "絞り込みに一致する 証明書ピンニングのサイト推薦はありません。",
    }))}</p>`;
    return;
  }

  const renderRow = (c) => {
    const site = escapeHtml(c.host || c.sni || "(unknown)");
    const port = c.port ? `:${escapeHtml(String(c.port))}` : "";
    const fails = escapeHtml(String(c.failure_count || 0));
    const last = escapeHtml(c.last_observed || c.updated_at || "—");
    const id = encodeURIComponent(c.candidate_id);
    const status = String(c.status || "pending").trim();
    // Attribution: approve an ENTITY, not an IP. An unattributed candidate (raw IP, no SNI) is investigate_only —
    // warn the operator and require a high-risk override to materialize (the Edge gates it too).
    const conf = String(c.confidence || "").trim();
    const investigate = String(c.suggested_action || "").trim() === "investigate_only";
    const dnsCorrelated = String(c.attribution_source || "").trim() === "dns_tunnel_correlation";
    // Colour by trust: high (DNS-correlated entity) = green, medium (SNI/hostname) = grey, investigate_only
    // (unattributed raw IP) = red. Show the DNS-recovered marker + the originating IP as evidence.
    const confStyle = investigate ? "background:#fee2e2;color:#991b1b"
      : conf === "high" ? "background:#dcfce7;color:#166534"
      : "background:#e5e7eb;color:#374151";
    const confSuffix = investigate ? " · " + bl({ en: "investigate only", ja: "要調査のみ" })
      : dnsCorrelated ? " · " + bl({ en: "DNS-correlated", ja: "DNS相関" })
      : "";
    const ipEvidence = dnsCorrelated && c.observed_ip
      ? ` title="${escapeHtml(bl({ en: "recovered from DNS; observed IP ", ja: "DNSから復元・観測IP " }) + String(c.observed_ip))}"`
      : "";
    const confBadge = conf
      ? `<span${ipEvidence} style="padding:1px 6px;border-radius:4px;${confStyle}">${escapeHtml(conf + confSuffix)}</span>`
      : "—";
    let actions = "";
    if (status === "pending") {
      actions =
        `<button data-act="approved" data-id="${id}" title="${escapeHtml(bl({ en: "Accept this recommendation, then Materialize to apply the bypass", ja: "この推薦を受理 → 取り込みでバイパス適用" }))}">${escapeHtml(bl({ en: "Approve", ja: "承認" }))}</button> ` +
        `<button data-act="rejected" data-id="${id}" title="${escapeHtml(bl({ en: "Decline this recommendation", ja: "この推薦を退ける" }))}">${escapeHtml(bl({ en: "Reject", ja: "却下" }))}</button> ` +
        `<button data-act="suppressed" data-id="${id}" title="${escapeHtml(bl({ en: "Stop resurfacing this destination as a candidate — it stays intercepted, NOT bypassed", ja: "今後この宛先を候補に再表示しない(傍受のまま・バイパスはしない)" }))}">${escapeHtml(bl({ en: "Suppress", ja: "抑制" }))}</button>`;
    } else if (status === "approved") {
      actions =
        `<button data-act="materialize" data-id="${id}" data-host="${escapeHtml(c.host || c.sni || "")}" data-investigate="${investigate ? "1" : ""}"><strong>${escapeHtml(bl({ en: "Materialize (apply bypass)", ja: "取り込み(バイパス適用)" }))}</strong></button> ` +
        `<button data-act="rejected" data-id="${id}">${escapeHtml(bl({ en: "Reject", ja: "却下" }))}</button>`;
    } else if (status === "materialized") {
      actions = `<span class="group-desc">${escapeHtml(bl({ en: "bypass active", ja: "バイパス適用中" }))}</span>`;
    } else {
      actions = `<button data-act="approved" data-id="${id}">${escapeHtml(bl({ en: "Re-approve", ja: "再承認" }))}</button>`;
    }
    return `<tr>
      <td><code>${site}${port}</code></td>
      <td>${confBadge}</td>
      <td style="text-align:right">${fails}</td>
      <td>${escapeHtml(last)}</td>
      <td>${pinnedStatusPill(status)}</td>
      <td>${actions}</td>
    </tr>`;
  };

  // What stays in the main list:
  //   (a) anything you've already ACTED ON (status != pending — approved / materialized / rejected /
  //       suppressed / dismissed): these are YOUR configured decisions and must always be visible,
  //       whatever their confidence (many adopted bypasses carry no confidence score); and
  //   (b) still-pending candidates we have positively identified (confidence medium/high — always a named
  //       host, safe to evaluate).
  // Only the PENDING low-confidence / unclassified / raw-IP noise is tucked behind the toggle.
  const confOf = (c) => String(c.confidence || "").trim().toLowerCase();
  const statusOf = (c) => String(c.status || "pending").trim();
  const isActionable = (c) => statusOf(c) !== "pending" || confOf(c) === "high" || confOf(c) === "medium";
  const actionable = pinned.filter(isActionable);
  const investigate = pinned.filter((c) => !isActionable(c));

  const confHelp = bl({
    en: "Can we identify this destination, so a bypass is safe? high = hostname recovered via DNS-over-tunnel correlation; medium = hostname from the TLS SNI; low = raw IP, no hostname (investigate only — bypassing no-decrypts an UNKNOWN destination).",
    ja: "この宛先を特定できているか(=バイパスして安全か)。high=DNS-over-tunnel 相関でホスト名復元 / medium=TLS SNI からホスト名 / low=生IPでホスト名不明(要調査 — バイパスは正体不明の宛先を非復号にする)。",
  });
  const thead = `<thead><tr>
      <th style="text-align:left">${escapeHtml(bl({ en: "Site (host / SNI)", ja: "サイト(host / SNI)" }))}</th>
      <th style="text-align:left;cursor:help" title="${escapeHtml(confHelp)}">${escapeHtml(bl({ en: "Attribution ⓘ", ja: "宛先の特定 ⓘ" }))}</th>
      <th style="text-align:right">${escapeHtml(bl({ en: "Failures", ja: "失敗数" }))}</th>
      <th style="text-align:left">${escapeHtml(bl({ en: "Last seen", ja: "最終検出" }))}</th>
      <th style="text-align:left">${escapeHtml(bl({ en: "Status", ja: "状態" }))}</th>
      <th style="text-align:left">${escapeHtml(bl({ en: "Adopt", ja: "取り込み" }))}</th>
    </tr></thead>`;
  const tableHTML = (arr) => `<table class="data-table" style="width:100%;border-collapse:collapse">${thead}<tbody>${arr.map(renderRow).join("")}</tbody></table>`;

  let html = actionable.length
    ? tableHTML(actionable)
    : `<p class="group-desc">${escapeHtml(bl({ en: "No attributed pinned-site recommendations right now.", ja: "現在、特定済みの 証明書ピンニングのサイト推薦はありません。" }))}</p>`;
  if (investigate.length) {
    html += `<details style="margin-top:14px">
      <summary style="cursor:pointer">${escapeHtml(bl({ en: `Show low-confidence / unclassified / raw-IP candidates (${investigate.length})`, ja: `確度低・未分類・生IPの候補を表示 (${investigate.length})` }))}</summary>
      <p class="group-desc" style="margin-top:6px">${escapeHtml(bl({
        en: "Candidates not yet safely identifiable: raw IPs with no recovered hostname, or hosts with no confidence score. Many are ad/tracking/CDN endpoints you would INSPECT, not bypass. Identify one before adopting it; a raw-IP bypass needs an explicit high-risk override.",
        ja: "まだ安全に特定できていない候補: ホスト名を復元できない生 IP、または確度が未評価のホスト。多くは広告/トラッキング/CDN で本来は検査すべき対象です。採用前に正体を特定してください(生IPのバイパスは高リスク 上書きが必要)。",
      }))}</p>
      ${tableHTML(investigate)}
    </details>`;
  }
  container.innerHTML = html;

  container.querySelectorAll("button[data-act]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = decodeURIComponent(btn.dataset.id);
      const act = btn.dataset.act;
      if (act === "materialize") {
        materializePinned(id, container, btn.dataset.investigate === "1", btn.dataset.host || "");
      } else {
        reviewPinned(id, act, container);
      }
    });
  });
}

async function reviewPinned(id, decision, container) {
  if (decision === "rejected" || decision === "suppressed") {
    const msg = decision === "rejected"
      ? bl({ en: "Reject this recommendation?", ja: "この推薦を却下しますか?" })
      : bl({ en: "Suppress this recommendation?", ja: "この推薦を抑制しますか?" });
    if (!window.confirm(msg)) return;
  }
  const r = await apiFetch("POST", "/admin/policy-candidates/" + encodeURIComponent(id) + "/review", {
    decision: decision,
    review_reason_code: "operator_" + decision,
  });
  if (!r.ok) {
    window.alert("HTTP " + r.status);
    return;
  }
  reloadPinned(container, container._filter || "");
}

async function materializePinned(id, container, investigateOnly, host) {
  if (!window.confirm(bl({
    en: "Materialize: write this site into the TLS decrypt-bypass policy? Traffic to it will no longer be decrypted/inspected.",
    ja: "取り込み: このサイトを TLS 復号バイパスポリシーに書き込みます。以後このサイトは復号/傍受されなくなります。よろしいですか?",
  }))) return;
  // An unattributed (investigate_only) candidate — a raw IP with no SNI — is high-risk: you cannot tell what
  // site/app it is. The Edge blocks it unless an explicit high-risk override is sent; require a second,
  // explicit confirmation and pass allow_high_risk so the operator owns that decision.
  let body = {};
  if (investigateOnly) {
    if (!window.confirm(bl({
      en: "HIGH RISK: this candidate is a raw IP with no attributed hostname (investigate_only). Bypassing it no-decrypts an UNKNOWN destination. Materialize anyway with a high-risk override?",
      ja: "高リスク: この候補はホスト名が特定できない生 IP(要調査のみ)です。バイパスすると不明な宛先を非復号にします。高リスク 上書きで取り込みますか?",
    }))) return;
    body = { allow_high_risk: true };
  }
  // ★ ADOPTION IS AUTHORED ON THE CONTROL PLANE, not on the Edge that happened to see the traffic.
  //
  // The durable product of adopting a pinned site is an Egress bypass RULE, and every config bundle replaces
  // the rule set wholesale. Materializing on a config-pulling Edge returned 200, the site started working, and
  // the next poll deleted it — while this page still showed the candidate as adopted, because only the rule was
  // erased and the candidate is Edge-local. An inspection bypass also has to hold fleet-wide: a site that must
  // not be decrypted must not be decrypted by whichever Edge the device reaches.
  //
  // /admin/cert-pin-bypass is self-contained (a host is all it needs) and is in CP_AUTHORED_WRITES, so apiFetch
  // sends it to the control plane. Materialize stays for the candidate types that ARE Edge-local.
  if (!host) {
    window.alert(bl({
      en: "This recommendation has no hostname to author a bypass for.",
      ja: "この推薦にはバイパスを作成できるホスト名がありません。",
    }));
    return;
  }
  const r = await apiFetch("POST", "/admin/cert-pin-bypass", { host: host, allow_high_risk: !!body.allow_high_risk });
  if (!r.ok) {
    let detail = "HTTP " + r.status;
    const j = r.body; // already-parsed body
    if (j && typeof j === "object" && j.error) detail += " — " + j.error;
    window.alert(detail + "\n" + bl({ en: "(only an Approved recommendation can be materialized)", ja: "(承認済みの推薦のみ取り込めます)" }));
    return;
  }
  reloadPinned(container, container._filter || "");
}
