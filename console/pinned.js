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
// Backend (dsse-core / control plane, which holds what every Edge observed): GET /admin/policy-candidates, POST /admin/policy-candidates/{id}/review
// {decision, review_reason_code}, POST /admin/policy-candidates/{id}/materialize. Candidates whose
// source == "cert_pinning_detection" are the pinned-site (bypass) recommendations.
//
// Loaded after app.js, so apiFetch / bl / escapeHtml are in scope. app.js dispatches here for the GROUPS
// entry flagged `custom: "pinned"`.
// ---------------------------------------------------------------------------

const PINNED_STATUS_STYLE = {
  pending: "background:#fef3c7;color:#92400e",
  approved: "background:#dbeafe;color:#1e40af",
  materialized: "background:#e5e7eb;color:#374151",
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
      "recommendation and adopt it: Approve, then Materialize to request a bypass rule. Candidate status alone " +
      "does not confirm that the serving Edge has applied it. Check the current bypass list below. Reject or Suppress a recommendation you do not want.",
    ja: "証明書ピンニングを使うサイトは復号傍受のサーバ証明書を拒否し、傍受下で壊れます。Edge はこれを検出し TLS 復号バイパスを" +
      "「推薦」します(自動でバイパスは絶対にしません)。各推薦をレビューして取り込んでください: 承認 → 取り込み" +
      "(Materialize)でバイパスルールの登録を要求します。候補の状態だけでは適用を確認できません。下の現在のバイパス一覧も確認してください。不要な推薦は却下/抑制します。",
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
  // /admin/cert-pin-bypass, which saves a registration at the control plane.
  // The serving Edge reports its own applied state separately.
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
    en: "Bypass patterns currently reported by the serving Edge. A saved registration may still be waiting for distribution. " +
      "The observation on an Edge and the registration at the control plane may appear as separate candidates. " +
      "Reviewing the observation does not revoke that separate rule. To remove a bypass, edit its rule in Internet Access.",
    ja: "接続先Edgeが現在報告しているバイパス対象です。保存した登録の配布がまだ完了していない場合があります。" +
      "Edgeの検出履歴と管理元の登録は別の候補として表示される場合があります。検出履歴を却下しても別の登録ルールは削除されません。" +
      "バイパスを解除するには、インターネットアクセスの該当ルールを編集してください。",
  });
  content.appendChild(bypassDesc);
  const bypassContainer = document.createElement("div");
  content.appendChild(bypassContainer);

  const filterText = () => search.value.trim().toLowerCase();
  const view = pinnedView(content, container, bypassContainer, addInput, addBtn, filterText);
  const reloadAll = view.load;
  container._reloadAll = reloadAll;
  container._write = view.write;
  reloadBtn.addEventListener("click", reloadAll);
  search.addEventListener("input", view.paint);

  const submitAdd = async () => {
    if (addBtn.disabled) return;
    const entered = addInput.value.trim();
    if (!entered) return;
    const host = pinnedExactHostname(entered);
    if (!host) {
      addStatus.style.color = "#b91c1c";
      addStatus.textContent = bl({en:"Enter one exact hostname, without an IP address, wildcard, URL, port or prefix.",ja:"IPアドレス、ワイルドカード、URL、ポート、範囲指定を含めず、単一のホスト名を入力してください。"});
      return;
    }
    addBtn.disabled = true;
    addStatus.style.color = "#4b5563";
    addStatus.textContent = bl({ en: "Registering…", ja: "登録中…" });
    try {
      const r = await container._write("/admin/cert-pin-bypass", { host: host }, c => pinnedRegistrationMatches(c, host));
      if (!r.ok) {
        let detail = "HTTP " + r.status;
        const j = r.body; // already-parsed body
        if (j && typeof j === "object" && j.error) detail += " — " + j.error;
        // A restarted edge invalidates the admin session, so a POST can 401/403 until the operator re-signs in.
        if (r.status === 401 || r.status === 403) detail += bl({ en: " (reload the page and sign in again)", ja: "(ページを再読込してサインインし直してください)" });
        addStatus.style.color = "#b91c1c";
        addStatus.textContent = bl(r.body && r.body.partial === true ? { en: "Incomplete: ", ja: "未完了: " } : { en: "Failed: ", ja: "失敗: " }) + detail;
        if (r.body && r.body.partial === true) await reloadAll();
        return;
      }
      addInput.value = "";
      addStatus.style.color = "#047857";
      addStatus.textContent = bl({ en: host + " — bypass rule saved. Check the serving Edge below.", ja: host + " のバイパスルールを保存しました。下のEdgeの状態も確認してください。" });
      await reloadAll();
    } catch (e) {
      // A thrown fetch (network/TLS reset — e.g. right after an edge restart) must not fail silently.
      addStatus.style.color = "#b91c1c";
      addStatus.textContent = bl({ en: "Error: ", ja: "エラー: " }) + String((e && e.message) || e);
    } finally {
      view.lock();
    }
  };
  addBtn.addEventListener("click", submitAdd);
  addInput.addEventListener("keydown", (e) => { if (e.key === "Enter") submitAdd(); });

  reloadAll();
}

// paintBypass renders the cached bypass-host set filtered by substring. Split from reloadBypass so the search
// box can re-filter without re-querying the edge.
function paintBypass(container, filter) {
  if (!Array.isArray(container._bypassHosts)) return;
  const all = container._bypassHosts;
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

// paintPinned renders the cached recommendations filtered by host substring. Split from reloadPinned so the
// search box re-filters instantly and review/materialize actions repaint without dropping the current filter.
function paintPinned(container, filter) {
  container._filter = filter;
  if (!Array.isArray(container._pinnedAll)) return;
  const cached = container._pinnedAll;
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
    // Registration requires the server's derived exact name; persisted confidence
    // cannot make an IP-only observation actionable as a named-site bypass.
    const registrationHost = pinnedExactHostname(c.registration_host || "");
    const conf = registrationHost ? String(c.confidence || "").trim() : "low";
    const investigate = !registrationHost || String(c.suggested_action || "").trim() === "investigate_only";
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
      actions = registrationHost
        ? `<button data-act="materialize" data-id="${id}" data-host="${escapeHtml(registrationHost)}" data-investigate="${investigate ? "1" : ""}"><strong>${escapeHtml(bl({ en: "Materialize (apply bypass)", ja: "取り込み(バイパス適用)" }))}</strong></button> `
        : `<span class="group-desc">${escapeHtml(bl({en:"Identify an exact hostname before registration.",ja:"登録前に単一のホスト名を特定してください。"}))}</span> `;
      actions += `<button data-act="rejected" data-id="${id}">${escapeHtml(bl({ en: "Reject", ja: "却下" }))}</button>`;
    } else if (status === "materialized") {
      actions = `<span class="group-desc">${escapeHtml(bl({ en: "registration requested; check Edge below", ja: "登録要求済み・下のEdgeの状態を確認" }))}</span>`;
    } else {
      actions = `<button data-act="approved" data-id="${id}">${escapeHtml(bl({ en: "Re-approve", ja: "再承認" }))}</button>`;
    }
    return `<tr>
      <td><code>${site}${port}</code>${registrationHost && registrationHost !== c.host ? `<div class="group-desc">${escapeHtml(bl({en:"Register: ",ja:"登録先: "}) + registrationHost)}</div>` : ""}</td>
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
  const confOf = (c) => pinnedExactHostname(c.registration_host || "") ? String(c.confidence || "").trim().toLowerCase() : "low";
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
  try {
    const r = await container._write("/admin/policy-candidates/" + encodeURIComponent(id) + "/review", {
      decision: decision,
      review_reason_code: "operator_" + decision,
    }, c => c.candidate_id === id && c.status === decision && c.source === "cert_pinning_detection" && c.candidate_type === "bypass_policy");
    if (!r.ok) {
      window.alert(pinnedRequestError(r));
      if (r.body && r.body.partial === true) await reloadPinnedView(container);
      return;
    }
    await reloadPinnedView(container);
  } catch (e) { window.alert(bl({ en: "Could not confirm the operation. Reload before retrying: ", ja: "操作結果を確認できません。再読込してから再試行してください: " }) + String((e && e.message) || e)); }

}

async function materializePinned(id, container, investigateOnly, host) {
  host = pinnedExactHostname(host);
  if (!host) { window.alert(bl({en:"Identify an exact hostname before registration.",ja:"登録前に単一のホスト名を特定してください。"})); return; }
  if (!window.confirm(bl({
    en: "Request a TLS decrypt-bypass rule for " + host + "? After the serving Edge applies it, traffic to this hostname will no longer be inspected.",
    ja: host + " のTLS復号バイパスルールを登録します。接続先Edgeへの適用後はこのホスト名を復号/傍受しません。よろしいですか?",
  }))) return;
  // A named candidate can retain a conservative legacy investigate_only label.
  // Keep the additional confirmation for that label; IP-only rows cannot reach here.
  let body = {};
  if (investigateOnly) {
    if (!window.confirm(bl({
      en: "This candidate is marked investigate_only. Verify that " + host + " is the intended hostname before excluding it from inspection. Continue with this explicit confirmation?",
      ja: "この候補は要調査と記録されています。" + host + " が意図したホスト名であることを確認してください。この名前を検査対象から除外する登録を続けますか?",
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
  try {
    const r = await container._write("/admin/cert-pin-bypass", { host: host, allow_high_risk: !!body.allow_high_risk }, c => pinnedRegistrationMatches(c, host));
    if (!r.ok) {
      window.alert(pinnedRequestError(r));
      if (r.body && r.body.partial === true) await reloadPinnedView(container);
      return;
    }
    await reloadPinnedView(container);
  } catch (e) { window.alert(bl({ en: "Could not confirm the operation. Reload before retrying: ", ja: "操作結果を確認できません。再読込してから再試行してください: " }) + String((e && e.message) || e)); }
}

function pinnedRequestError(response) {
  const partial = response.body && response.body.partial === true;
  const prefix = partial ? bl({ en: "Incomplete: ", ja: "未完了: " }) : bl({ en: "Failed: ", ja: "失敗: " });
  const detail = response.body && typeof response.body.error === "string" ? " — " + response.body.error : "";
  return prefix + "HTTP " + response.status + detail;
}

function reloadPinnedView(container) {
  return container._reloadAll();
}


function pinnedObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function pinnedSelection() { return typeof operateTenant === "undefined" ? "" : (operateTenant || ""); }
function pinnedInvalid() { return bl({en:"Could not load these lists correctly. Reload before editing.",ja:"一覧を正しく読み込めません。編集前に再読込してください。"}); }
function pinnedChanged() { return bl({en:"The organization or page changed. Reload before editing.",ja:"組織または画面が変わりました。編集前に再読込してください。"}); }
function pinnedUnconfirmed() { return bl({en:"Could not confirm the operation. Your input is kept. Reload before retrying.",ja:"操作結果を確認できません。入力は保持しています。再試行前に再読込してください。"}); }
function pinnedTenant(r) {
  if (!r?.ok || r.status !== 200 || !pinnedObject(r.body) || typeof r.body.tenant_id !== "string" || !r.body.tenant_id.trim()) throw new Error(pinnedInvalid());
  return r.body.tenant_id;
}
function pinnedCandidate(c, tenant) {
  if (!pinnedObject(c) || c.tenant_id !== tenant || typeof c.candidate_id !== "string" || !c.candidate_id.trim() ||
      typeof c.source !== "string" || !c.source || typeof c.candidate_type !== "string" || !c.candidate_type ||
      !Object.hasOwn(PINNED_STATUS_STYLE, c.status)) throw new Error(pinnedInvalid());
  for (const key of ["host","sni","confidence","suggested_action","last_observed","updated_at","attribution_source","observed_ip"]) {
    if (c[key] !== undefined && c[key] !== null && typeof c[key] !== "string") throw new Error(pinnedInvalid());
  }
  if ((c.failure_count !== undefined && (!Number.isSafeInteger(c.failure_count) || c.failure_count < 0)) ||
      (c.port !== undefined && (!Number.isInteger(c.port) || c.port < 0 || c.port > 65535))) throw new Error(pinnedInvalid());
  if (c.registration_host !== undefined && (!c.registration_host || pinnedExactHostname(c.registration_host) !== c.registration_host)) throw new Error(pinnedInvalid());
  return c;
}
function pinnedLists(candidates, bypass, tenant) {
  if (pinnedTenant(candidates) !== tenant || pinnedTenant(bypass) !== tenant) throw new Error(pinnedChanged());
  const list = candidates.body, hosts = bypass.body.hosts;
  if (!Array.isArray(list.candidates) || !Number.isSafeInteger(list.count) || list.count < list.candidates.length ||
      !Number.isSafeInteger(list.limit) || list.limit < 1 || list.candidates.length > list.limit ||
      !Object.hasOwn(bypass.body,"hosts") || (hosts !== null && !Array.isArray(hosts))) throw new Error(pinnedInvalid());
  const ids = new Set();
  for (const c of list.candidates) { pinnedCandidate(c,tenant); if (ids.has(c.candidate_id)) throw new Error(pinnedInvalid()); ids.add(c.candidate_id); }
  if ((hosts || []).some(h => typeof h !== "string" || !h.trim())) throw new Error(pinnedInvalid());
  return {candidates:list.candidates.filter(c => c.source === "cert_pinning_detection" && c.candidate_type === "bypass_policy").sort((a,b)=>(b.failure_count || 0)-(a.failure_count || 0)),hosts:hosts || []};
}
function pinnedExactHostname(value) {
  if (typeof value !== "string") return "";
  let name = value.trim().toLowerCase();
  if (!name || /[*\\/:@?#%\[\]\s]/.test(name)) return "";
  // Browser IDNA normalization is used only after URL syntax is excluded.
  if (/[^\x00-\x7f]/.test(name)) { try { name = new URL("http://" + name).hostname; } catch (_) { return ""; } }
  name = name.replace(/\.$/, "");
  const labels = name.split("."), last = labels.at(-1);
  if (!name || name.length > 253 || /^[0-9]+$/.test(last) || /^0x[0-9a-f]+$/.test(last)) return "";
  if (labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return "";
  return name;
}
function pinnedRegistrationMatches(c, host) {
  const target = pinnedExactHostname(host);
  return !!target && c.status === "materialized" && c.source === "cert_pinning_detection" && c.candidate_type === "bypass_policy" && pinnedExactHostname(c.host) === target;
}

// One page revision owns both lists. Failed reads discard the old action cache;
// late reads and writes cannot act on a new organization or a replacement view.
function pinnedView(content, candidates, bypass, input, addButton, filter) {
  const fresh = freshRender(content);
  const current = () => fresh() && content.isConnected !== false && candidates.isConnected !== false && bypass.isConnected !== false;
  let loaded = false, pending = false, tenant = "", selection = "", revision = 0;
  function active(stamp = revision) { return loaded && current() && stamp === revision && selection === pinnedSelection(); }
  function lock() { input.disabled = addButton.disabled = !active() || pending; candidates.querySelectorAll("button[data-act]").forEach(b => {b.disabled = !active() || pending;}); }
  function clear() { loaded = false; candidates._pinnedAll = undefined; bypass._bypassHosts = undefined; lock(); }
  function error(message) {
    clear();
    if (current()) { uiState(candidates,"error",message,{label:bl({en:"Reload lists",ja:"一覧を再読込"}),onClick:load}); bypass.innerHTML = ""; }
  }
  function paint() {
    if (!loaded || !current()) return;
    if (!active()) { error(pinnedChanged()); return; }
    paintPinned(candidates,filter()); paintBypass(bypass,filter()); lock();
  }
  async function load() {
    if (pending || !current()) return;
    clear(); const stamp = ++revision, selected = pinnedSelection();
    uiState(candidates,"loading"); bypass.innerHTML = "";
    try {
      const owner = pinnedTenant(await apiFetch("GET","/admin/tenant"));
      if (!current() || stamp !== revision) return;
      if (selected !== pinnedSelection() || (selected && selected !== owner)) throw new Error(pinnedChanged());
      const q = "expected_tenant_id=" + encodeURIComponent(owner);
      const [cs, bs] = await Promise.all([apiFetch("GET","/admin/policy-candidates?"+q),apiFetch("GET","/admin/intercept/bypass-hosts?scoped=1&"+q)]);
      if (!current() || stamp !== revision) return;
      if (selected !== pinnedSelection()) throw new Error(pinnedChanged());
      const lists = pinnedLists(cs,bs,owner);
      candidates._pinnedAll = lists.candidates; bypass._bypassHosts = lists.hosts;
      tenant = owner; selection = selected; loaded = true; paint();
    } catch(e) { if (current() && stamp === revision) error(String(e.message || e)); }
  }
  async function write(path, body, matches) {
    if (pending || !active()) throw new Error(pinnedChanged());
    pending = true; const stamp = revision; lock();
    try {
      let owner;
      try { owner = pinnedTenant(await apiFetch("GET","/admin/tenant")); }
      catch (_) { error(pinnedChanged()); throw new Error(pinnedChanged()); }
      if (!active(stamp) || owner !== tenant) { error(pinnedChanged()); throw new Error(pinnedChanged()); }
      let response;
      try { response = await apiFetch("POST",path+"?expected_tenant_id="+encodeURIComponent(tenant),body); }
      catch (_) { error(pinnedUnconfirmed()); throw new Error(pinnedUnconfirmed()); }
      if (!active(stamp)) { error(pinnedUnconfirmed()); throw new Error(pinnedUnconfirmed()); }
      if (!response?.ok) return response;
      try {
        if (response.status !== 200 || !matches(pinnedCandidate(response.body,tenant))) throw new Error("acknowledgement mismatch");
      } catch (_) { error(pinnedUnconfirmed()); throw new Error(pinnedUnconfirmed()); }
      // A confirmed write still needs a fresh read before another action.
      clear(); return response;
    } finally { pending = false; if (current()) lock(); }
  }
  lock(); return {load,write,paint,lock};
}
