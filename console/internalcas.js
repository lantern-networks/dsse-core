"use strict";

// Each entry trusts one public CA certificate for this organization's upstream TLS connections.
function internalCAObject(v) { return v && typeof v === "object" && !Array.isArray(v); }
function internalCAText(v) { return typeof v === "string" && v.trim() !== ""; }
function internalCAPEM(v) {
  return typeof v === "string" && /^-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----$/.test(v.trim());
}
function validatedInternalCAs(body, tenant) {
  if (!internalCAObject(tenant) || !internalCAText(tenant.tenant_id) || !internalCAObject(body) || !Array.isArray(body.internal_cas)) throw new Error("Invalid internal certificate list or organization response");
  const ids = new Set();
  for (const a of body.internal_cas) {
    if (!internalCAObject(a) || !internalCAText(a.id) || a.tenant_id !== tenant.tenant_id || ids.has(a.id) || !internalCAPEM(a.certificate_pem) ||
        ["name","subject","not_after","created_at","updated_at"].some(k => a[k] !== undefined && typeof a[k] !== "string") ||
        (a.expired !== undefined && typeof a.expired !== "boolean")) throw new Error("Invalid internal certificate record");
    ids.add(a.id);
  }
  return body.internal_cas;
}
function internalCAUnconfirmed() { return bl({en:"The outcome is unconfirmed. Reload the list and retry if needed; your input has been kept.",ja:"結果を確認できません。一覧を再読込し、必要なら再試行してください。入力内容は保持しています。"}); }
function internalCAOutcome(r, action, expected) {
  if (!r?.ok) throw new Error(internalCAText(r?.body?.error) ? r.body.error : internalCAUnconfirmed());
  const a = r.body;
  if (r.status !== 200 || !internalCAObject(a) || a.id !== expected.id || a.tenant_id !== expected.tenant_id) throw new Error(internalCAUnconfirmed());
  if (action === "delete") { if (a.deleted !== true) throw new Error(internalCAUnconfirmed()); }
  else {
    validatedInternalCAs({internal_cas:[a]},{tenant_id:expected.tenant_id});
    if (a.name !== expected.name.trim() || a.certificate_pem.replace(/\s/g,"") !== expected.certificate_pem.replace(/\s/g,"")) throw new Error(internalCAUnconfirmed());
  }
}

async function renderInternalCAsView(content) {
  content.innerHTML = "";
  const fresh = freshRender(content);
  const current = () => fresh() && content.isConnected !== false && form.isConnected !== false;
  let tenantID = "", loaded = false, pending = false, draft = null;
  const list = el("div",{});
  const status = el("p",{role:"status","aria-live":"polite"});
  const name = el("input",{class:"ui-input",type:"text",placeholder:bl({en:"A name you will recognise",ja:"自分でわかる名前"}),"aria-label":bl({en:"Name",ja:"名前"})});
  const material = el("textarea",{class:"ui-input",rows:8,placeholder:"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----","aria-label":bl({en:"CA certificate",ja:"CA証明書"})});
  const add = el("button",{class:"ui-btn ui-btn-primary",text:bl({en:"Add",ja:"追加"}),onClick:save});
  const reloadButton = el("button",{class:"ui-btn",text:bl({en:"Reload",ja:"再読込"}),onClick:reload});
  const form = el("div",{class:"ui-card",style:"margin-top:18px;padding:16px;max-width:760px"},[
    el("h3",{text:bl({en:"Add an authority",ja:"証明機関を追加"})}), name, material,
    el("p",{class:"ui-view-desc",text:bl({en:"Paste exactly one public CA certificate that issued your internal site's certificate. Do not include a private key or a certificate chain.",ja:"社内サイトの証明書を発行したCAの公開証明書を1件貼ってください。秘密鍵や証明書チェーンを含めないでください。"})}),add,
  ]);
  content.appendChild(el("div",{class:"ui-view-head"},[
    el("div",{},[el("h2",{class:"ui-view-title",text:bl({en:"Internal site certificates",ja:"社内サイトの証明書"})}),
      el("p",{class:"ui-view-desc",text:bl({en:"Authorities trusted for your organization's internal sites. Changes are saved on this server; other servers must receive the update.",ja:"自組織の社内サイトで信頼する証明機関です。変更はこのサーバーで保存され、他のサーバーには更新の配布が必要です。"})})]),reloadButton,
  ]));
  content.append(list,status,form);
  function lock() {
    name.disabled = material.disabled = add.disabled = pending || !loaded;
    reloadButton.disabled = pending;
    list.querySelectorAll("button").forEach(b=>{b.disabled=pending});
  }
  function message(text, error=false) { status.textContent = text; status.className = error ? "ui-callout ui-callout-warn" : ""; }
  async function reload() {
    if (pending || !current()) return;
    loaded=false;lock();uiState(list,"loading");const latest=freshRender(list);
    try {
      const [r,t]=await Promise.all([apiFetch("GET","/admin/internal-cas"),apiFetch("GET","/admin/tenant")]);
      if (!current() || !latest()) return;
      if (!r?.ok || !t?.ok) throw new Error("HTTP " + (!r?.ok ? r?.status : t?.status));
      const rows=validatedInternalCAs(r.body,t.body);
      if (tenantID && tenantID !== t.body.tenant_id) { draft=null;name.value="";material.value="";message(bl({en:"The organization changed. Enter the certificate again for this organization.",ja:"組織が変わりました。この組織の証明書を改めて入力してください。"}),true); }
      tenantID=t.body.tenant_id;loaded=true;list.innerHTML="";
      if (!rows.length) uiState(list,"empty",bl({en:"No internal authorities added.",ja:"社内証明機関はまだ登録されていません。"}));
      else list.appendChild(el("table",{class:"ui-table"},[
        el("thead",{},el("tr",{},[bl({en:"Name",ja:"名前"}),bl({en:"Issued to",ja:"証明機関"}),bl({en:"Valid until",ja:"有効期限"}),bl({en:"Actions",ja:"操作"})].map(text=>el("th",{text})))),
        el("tbody",{},rows.map(a=>el("tr",{},[
          el("td",{text:a.name || a.id}),el("td",{text:a.subject || "—"}),
          el("td",{text:a.expired ? bl({en:"Expired — not trusted",ja:"期限切れ・信頼対象外"}) : (Number.isFinite(Date.parse(a.not_after)) ? a.not_after : bl({en:"Unknown expiry",ja:"期限不明"}))}),
          el("td",{},el("button",{class:"ui-btn ui-btn-sm ui-btn-danger",text:bl({en:"Remove",ja:"削除"}),onClick:()=>remove(a)})),
        ]))),
      ]));
    } catch(e) {
      if (!current() || !latest()) return;
      uiState(list,"error",String(e.message || e),{label:bl({en:"Retry",ja:"再試行"}),onClick:reload});
    } finally { if(current() && latest()) lock(); }
  }
  async function save() {
    if (pending || !loaded || !current()) return;
    const values={tenant_id:tenantID,name:name.value,certificate_pem:material.value};
    if (!internalCAPEM(values.certificate_pem)) { message(bl({en:"Paste one public CA certificate only; remove private keys and other material.",ja:"CAの公開証明書だけを1件貼ってください。秘密鍵やその他の内容を除いてください。"}),true);return; }
    // Keep a stable request ID when retrying the same input after an uncertain response.
    if (!draft || Object.keys(values).some(k=>draft[k]!==values[k])) draft={...values,id:"ica-"+crypto.randomUUID()};
    const submitted={...draft};pending=true;lock();message("");
    try {
      let r;try {r=await apiFetch("POST","/admin/internal-cas",submitted)}catch(_){throw new Error(internalCAUnconfirmed())}
      internalCAOutcome(r,"upsert",submitted);
      if(!current())return;
      draft=null;name.value="";material.value="";message(bl({en:"Authority saved.",ja:"証明機関を保存しました。"}));
    } catch(e) { if(current())message(e.message || String(e),true); }
    finally { pending=false;if(current())lock(); }
    if(current())await reload();
  }
  async function remove(a) {
    if(pending || !loaded || !current())return;
    pending=true;lock();let attempted=false;
    try {
      if(!await uiConfirm({title:bl({en:"Remove this authority?",ja:"この証明機関を削除しますか？"}),body:(a.name || a.id)+" — "+bl({en:"Internal sites using this authority may stop opening. Other servers must receive the update.",ja:"この証明機関を使う社内サイトが開けなくなる場合があります。他のサーバーには更新の配布が必要です。"}),confirmLabel:bl({en:"Remove",ja:"削除"}),danger:true}))return;
      if(!current())return;attempted=true;message("");
      let r;try{r=await apiFetch("DELETE","/admin/internal-cas/"+encodeURIComponent(a.id)+"?tenant_id="+encodeURIComponent(a.tenant_id))}catch(_){throw new Error(internalCAUnconfirmed())}
      internalCAOutcome(r,"delete",a);
      if(current())message(bl({en:"Authority removed.",ja:"証明機関を削除しました。"}));
    }catch(e){if(current())message(e.message || String(e),true)}
    finally{pending=false;if(current())lock()}
    if(attempted && current())await reload();
  }
  await reload();
}
