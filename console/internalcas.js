"use strict";

// ---------------------------------------------------------------------------
// "Internal site certificates" — the authorities an organization vouches for over ITS OWN private sites.
//
// ★★★ WHY THIS SCREEN EXISTS (2026-09-01). An internal site behind a connector is opened by the Edge on the
// device's behalf, and the Edge checked its certificate against the list of public authorities every browser
// ships with — a list that will never contain a company's own. So an internal site was reached, decrypted
// correctly, and then refused, and the person at the browser saw a page that would not open with nothing to
// tell them apart from the site being down.
//
// The screen is written for the person who administers the sites, not for the person who wrote the Edge: it
// asks for the certificate of the authority that issued their internal sites' certificates, and it shows what
// it read out of what they pasted, so a wrong file is visible immediately.
//
// Backend: GET/POST /admin/internal-cas, DELETE /admin/internal-cas/{id}. Scoped to the signed-in
// organization on every route. Loaded after app.js, so apiFetch / bl / escapeHtml are in scope.
// ---------------------------------------------------------------------------

async function renderInternalCAsView(content) {
  content.innerHTML = "";
  const h = document.createElement("h2");
  h.className = "group-title";
  h.textContent = bl({ en: "Internal site certificates", ja: "社内サイトの証明書" });
  content.appendChild(h);
  const d = document.createElement("p");
  d.className = "group-desc";
  d.textContent = bl({
    en: "Your internal sites use certificates your company issued itself. Add the authority that issued them, " +
      "so your devices can open those sites.",
    ja: "社内サイトの証明書は、自社で発行したものです。それを発行した証明機関をここに登録すると、社内サイトが開けるようになります。",
  });
  content.appendChild(d);

  const list = document.createElement("div");
  content.appendChild(list);

  const form = document.createElement("div");
  form.style.cssText = "margin-top:18px;padding:14px;border:1px solid #e5e7eb;border-radius:8px;max-width:760px";
  const formTitle = document.createElement("div");
  formTitle.style.cssText = "font-weight:600;margin-bottom:8px";
  formTitle.textContent = bl({ en: "Add an authority", ja: "証明機関を追加" });
  form.appendChild(formTitle);

  const name = document.createElement("input");
  name.type = "text";
  name.placeholder = bl({ en: "A name you will recognise", ja: "自分でわかる名前" });
  name.style.cssText = "width:100%;padding:6px 9px;margin-bottom:8px";
  form.appendChild(name);

  const material = document.createElement("textarea");
  material.rows = 8;
  material.placeholder = "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----";
  material.style.cssText = "width:100%;padding:6px 9px;font-family:ui-monospace,monospace;font-size:12px";
  form.appendChild(material);

  const hint = document.createElement("div");
  hint.style.cssText = "color:#6b7280;font-size:12px;margin:6px 0 10px";
  hint.textContent = bl({
    en: "Paste the certificate of the AUTHORITY that issued your internal sites' certificates — not a site's own.",
    ja: "社内サイトの証明書を「発行した側」の証明書を貼ってください。サイト自身の証明書ではありません。",
  });
  form.appendChild(hint);

  const save = document.createElement("button");
  save.textContent = bl({ en: "Add", ja: "追加" });
  form.appendChild(save);
  const status = document.createElement("span");
  status.style.cssText = "margin-left:10px;font-size:13px";
  form.appendChild(status);
  content.appendChild(form);

  async function reload() {
    list.innerHTML = `<div style="color:#6b7280">${escapeHtml(bl({ en: "Loading…", ja: "読み込み中…" }))}</div>`;
    let data;
    try {
      // apiFetch(method, path, ...) returns { status, ok, body } with body already parsed — NOT a Response.
      const r = await apiFetch("GET", "/admin/internal-cas");
      if (!r.ok) {
        list.innerHTML = `<div style="color:#991b1b">HTTP ${r.status} — ${escapeHtml(String((r.body && r.body.error) || ""))}</div>`;
        return;
      }
      data = r.body;
    } catch (e) {
      list.innerHTML = `<div style="color:#991b1b">${escapeHtml(String(e && e.message ? e.message : e))}</div>`;
      return;
    }
    const rows = (data && data.internal_cas) || [];
    if (!rows.length) {
      // ★ AN EMPTY LIST IS NOT AN ERROR AND MUST NOT LOOK LIKE ONE. Most organizations have no internal sites.
      list.innerHTML = `<div style="color:#6b7280">${escapeHtml(bl({
        en: "Nothing added. Your devices open internal sites only if the authority that issued their certificates is listed here.",
        ja: "まだありません。社内サイトの証明書を発行した証明機関がここに無いと、そのサイトは開けません。",
      }))}</div>`;
      return;
    }
    const t = document.createElement("table");
    t.className = "data-table";
    t.innerHTML = `<thead><tr>
      <th>${escapeHtml(bl({ en: "Name", ja: "名前" }))}</th>
      <th>${escapeHtml(bl({ en: "Issued to", ja: "証明機関" }))}</th>
      <th>${escapeHtml(bl({ en: "Valid until", ja: "有効期限" }))}</th>
      <th></th></tr></thead>`;
    const tb = document.createElement("tbody");
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      // ★ EXPIRY IS SHOWN, NOT HIDDEN. An authority that has expired since it was pasted stops being used, and
      // a screen that still listed it as fine would send its reader to look at the connector instead.
      const until = row.expired
        ? `<span style="color:#991b1b">${escapeHtml(bl({ en: "expired — internal sites it issued will not open", ja: "期限切れ —— このもとで発行されたサイトは開けません" }))}</span>`
        : escapeHtml(String(row.not_after || "").slice(0, 10));
      tr.innerHTML = `<td>${escapeHtml(row.name || "")}</td>
        <td style="font-size:12px;color:#4b5563">${escapeHtml(row.subject || "")}</td>
        <td>${until}</td><td></td>`;
      const del = document.createElement("button");
      del.textContent = bl({ en: "Remove", ja: "削除" });
      del.onclick = async () => {
        del.disabled = true;
        try {
          const r = await apiFetch("DELETE", `/admin/internal-cas/${encodeURIComponent(row.id)}`);
          if (!r.ok) throw new Error((r.body && r.body.error) || `HTTP ${r.status}`);
          await reload();
        } catch (e) {
          del.disabled = false;
          alert(String(e && e.message ? e.message : e));
        }
      };
      tr.lastChild.appendChild(del);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    list.innerHTML = "";
    list.appendChild(t);
  }

  save.onclick = async () => {
    status.textContent = "";
    save.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/internal-cas", { name: name.value, certificate_pem: material.value });
      if (!r.ok) throw new Error((r.body && r.body.error) || `HTTP ${r.status}`);
      name.value = "";
      material.value = "";
      await reload();
    } catch (e) {
      // The server's refusals name WHICH mistake was made (a site's own certificate, an expired one, not
      // certificate material at all). Show them as they are rather than replacing them with "invalid".
      status.style.color = "#991b1b";
      status.textContent = String(e && e.message ? e.message : e);
    } finally {
      save.disabled = false;
    }
  };

  await reload();
}
