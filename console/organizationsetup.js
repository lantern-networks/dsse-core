"use strict";

// organizationsetup.js — "What still has to be done before this organization works".
//
// ★ A REGISTRY ROW IS THE ENTRANCE, NOT THE FINISH. An organization can exist in every list, be selectable in
// every menu, and enforce nothing — and until this screen existed the only way to find out was to know which
// twelve routes to call and what each answer meant.
//
// ★ IT SHOWS WHAT EACH THING LETS YOU DO, AND SETS IT. A checklist that reports done/not-done tells an
// operator something is missing and not what they lose by leaving it, so it gets worked in the order that
// matters least. Every row therefore carries the capability in plain words, the measured fact behind the
// state, and a control that takes you to where it is configured — a screen that can only describe is one
// somebody has to leave to get anything done.
//
// ★ IT ASKS BOTH PLANES AND SAYS WHO ANSWERED. The two planes hold different halves: device identity and
// inspection live on the Edge, the registry row and the administrators on the control plane, and each reports
// the other's as "not held here". Merging in the screen — rather than having one plane fetch from the other —
// keeps WHICH NODE ANSWERED WHAT on screen, so the day the two disagree a person can see it. That has already
// happened once: the same organization read "device identity: done, expires in 1812 days" on the Edge and
// "not held here" on the control plane, and a merge hidden in the server would have shown one of them.
//
// Backend: GET /admin/organization-setup (both planes; X-Operate-Tenant selects the organization).

// Where each item is actually configured. The API says which ROUTE sets a thing; a person needs the SCREEN.
// Empty means the control lives in this checklist itself.
const SETUP_DESTINATION = {
  registry: { group: "tenants", t: { en: "Open tenants", ja: "テナント一覧を開く" } },
  identity: { group: "tenants", t: { en: "Edit tenant", ja: "テナントを編集" } },
  regions: { group: "tenants", t: { en: "Edit tenant", ja: "テナントを編集" } },
  device_identity: { group: "certs", t: { en: "Open certificates", ja: "証明書を開く" } },
  inspection_authority: { group: "certs", t: { en: "Open certificates", ja: "証明書を開く" } },
  policy: { group: "egress-rules", t: { en: "Open rules", ja: "ルールを開く" } },
  administrator: { group: "administrators", t: { en: "Open administrators", ja: "管理者を開く" } },
  seats: { group: "licensing", t: { en: "Open licensing", ja: "ライセンスを開く" } },
  features: { group: "licensing", t: { en: "Open licensing", ja: "ライセンスを開く" } },
  enrolment: { group: "enrolment-tokens", t: { en: "Open joining tokens", ja: "参加トークンを開く" } },
  idp: { group: "idp", t: { en: "Open sign-in", ja: "サインインを開く" } },
  domains: { group: "tenant-settings", t: { en: "Open settings", ja: "設定を開く" } },
};

// ★ THE WORDING IS THE SCREEN'S, NOT THE API'S. The checklist came back in English and rendered inside a
// Japanese console, which is the one thing this Console has never done. The API's label and capability stay —
// they are what a non-Console consumer reads — and the screen keeps its own, keyed by the item's stable key.
//
// UNKNOWN KEYS FALL BACK TO THE API TEXT rather than being dropped. A checklist that silently omits an item
// the server added is the failure this whole surface exists to prevent, and it would look identical to an
// organization that has nothing left to do.
const SETUP_WORDS = {
  registry:    { l: { en: "Tenant record", ja: "テナントの登録" },
                 e: { en: "everything else — until this exists there is nothing to configure", ja: "他のすべての前提。これが無ければ設定するものがありません" } },
  identity:    { l: { en: "Name and time zone", ja: "名前とタイムゾーン" },
                 e: { en: "reports and log timestamps read in this tenant's own working day", ja: "レポートとログの時刻が、このテナントの一日で読めます" } },
  device_identity: { l: { en: "Device identity", ja: "端末の身元" },
                 e: { en: "this tenant's endpoints are admitted as theirs, and nobody else's", ja: "このテナントの端末が、そのテナントのものとして受け入れられます" } },
  inspection_authority: { l: { en: "Traffic inspection authority", ja: "通信検査の権限" },
                 e: { en: "their traffic is inspected under an authority that is theirs, not the deployment's", ja: "このテナントの通信が、配備側ではなく自社の権限で検査されます" } },
  policy:      { l: { en: "Access rules", ja: "アクセスルール" },
                 e: { en: "what this tenant's people and devices may reach", ja: "このテナントの人と端末が何に到達できるか" } },
  administrator: { l: { en: "Their administrator", ja: "そのテナントの管理者" },
                 e: { en: "the tenant runs itself instead of asking the operator for every change", ja: "変更のたびに運営に頼まず、テナントが自ら運用できます" } },
  seats:       { l: { en: "Device allowance", ja: "端末数の割当" },
                 e: { en: "a ceiling on how many devices this tenant may enrol", ja: "このテナントが登録できる端末数の上限" } },
  features:    { l: { en: "Paid features", ja: "有償機能" },
                 e: { en: "the optional capabilities this tenant has bought", ja: "このテナントが購入した追加機能" } },
  enrolment:   { l: { en: "Joining token", ja: "参加トークン" },
                 e: { en: "a new endpoint can enrol into this tenant", ja: "新しい端末がこのテナントに参加できます" } },
  idp:         { l: { en: "Sign-in", ja: "サインイン" },
                 e: { en: "their people sign in with the accounts they already have", ja: "このテナントの人が、既存のアカウントでサインインできます" } },
  domains:     { l: { en: "Their email domains", ja: "このテナントのメールドメイン" },
                 e: { en: "a person signing in is recognised as belonging to this tenant", ja: "サインインした人が、このテナントの所属として認識されます" } },
  regions:     { l: { en: "Where they are served", ja: "提供リージョン" },
                 e: { en: "their traffic and data stay inside the regions they agreed to", ja: "通信とデータが、合意したリージョンの中に留まります" } },
  delegation:  { l: { en: "Who runs it", ja: "運用の担当" },
                 e: { en: "the operator does this tenant's day-to-day work on its behalf", ja: "運営がこのテナントの日常運用を代行します" } },
};

// setupDetail composes the measured fact in the reader's language from the values the API returned.
//
// The API measures; the screen words it. Anything without a template here falls back to the API's own
// sentence, so an item added on the server still shows its evidence rather than a blank cell.
function setupDetail(item) {
  const v = item.values || {};
  const n = (x) => (typeof x === "number" ? x : 0);
  const list = (x) => (Array.isArray(x) && x.length ? x.join(", ") : "");
  switch (item.key) {
    case "device_identity": {
      const days = typeof v.soonest_days === "number" && v.soonest_days >= 0 ? v.soonest_days : null;
      return n(v.count) ? bl({ en: v.count + " certificate authority(ies)" + (days === null ? "" : " · soonest expires in " + days + " days"),
                               ja: "証明書 " + v.count + " 本" + (days === null ? "" : "（最短 " + days + " 日で期限）") })
                        : bl({ en: "no certificate authority — their devices cannot be admitted", ja: "証明書なし — このテナントの端末は受け入れられません" });
    }
    case "inspection_authority":
      return v.root ? String(v.root)
                    : bl({ en: "signed by the deployment's own authority", ja: "配備側の権限で署名されています" });
    case "policy":
      return n(v.count) ? bl({ en: v.count + " rule(s)", ja: "ルール " + v.count + " 件" })
                        : bl({ en: "no rules — nothing is enforced for them", ja: "ルールなし — 何も強制されません" });
    case "administrator":
      return n(v.count) ? bl({ en: v.count + " administrator(s)", ja: "管理者 " + v.count + " 名" })
                        : bl({ en: "nobody here can administer it", ja: "このテナントを管理できる人がいません" });
    case "seats":
      return n(v.seats) ? bl({ en: v.seats + " device(s)", ja: "端末 " + v.seats + " 台" })
                        : bl({ en: "no allowance — enrolment is ungated", ja: "割当なし — 登録が無制限です" });
    case "features":
      return list(v.features) || bl({ en: "none granted", ja: "付与なし" });
    case "enrolment":
      return n(v.count) ? bl({ en: v.count + " outstanding", ja: "有効 " + v.count + " 件" })
                        : bl({ en: "none — no new device can join", ja: "なし — 新しい端末は参加できません" });
    case "idp":
      return n(v.count) ? bl({ en: v.count + " identity provider(s)", ja: "IdP " + v.count + " 件" })
                        : bl({ en: "none — their people cannot sign in", ja: "なし — このテナントの人はサインインできません" });
    case "domains":
      return list(v.domains) || bl({ en: "none set", ja: "未設定" });
    case "identity":
      return v.name ? (v.name + (v.timezone ? " (" + v.timezone + ")" : bl({ en: " (UTC)", ja: "（UTC）" })))
                    : bl({ en: "no name of its own", ja: "固有の名前がありません" });
    case "regions":
      return (v.home || list(v.allowed)) ? [v.home, list(v.allowed)].filter(Boolean).join(" · ")
                                         : bl({ en: "unpinned — any region", ja: "未指定 — どのリージョンでも" });
    case "registry":
      return item.state === "done" ? bl({ en: "registered", ja: "登録済み" }) : bl({ en: "not registered", ja: "未登録" });
    case "delegation":
      return item.state === "done" ? bl({ en: "the operator runs it", ja: "運営が運用しています" })
                                   : bl({ en: "the tenant runs itself", ja: "テナントが自ら運用しています" });
    default:
      return item.detail;
  }
}

// setupWords returns the screen's wording for an item, falling back to whatever the API said.
function setupWords(item) {
  const w = SETUP_WORDS[item.key];
  return { label: w ? bl(w.l) : item.label, enables: w ? bl(w.e) : item.enables };
}

const SETUP_STATE = {
  done: { tone: "ok", t: { en: "Set", ja: "設定済み" } },
  missing: { tone: "warn", t: { en: "Not set", ja: "未設定" } },
  not_here: { tone: "off", t: { en: "Held elsewhere", ja: "別ノードが保持" } },
};

// organizationSetupMerged asks both planes and combines them item by item.
//
// For each item the answer that is NOT "held elsewhere" wins; when both defer, it stays deferred rather than
// being invented. The node that answered is kept on the row, because the merge is the screen's and a reader
// has to be able to see it.
async function organizationSetupMerged(tenantId) {
  const ask = async (plane) => {
    try {
      // Named per call, so filling a list of organizations cannot leave the console pointed at one of them.
      const r = await apiFetch("GET", "/admin/organization-setup", undefined, plane, undefined, tenantId);
      return r.ok ? r.body : null;
    } catch (e) { return null; }
  };
  const [edge, control] = await Promise.all([ask("edge"), ask("control")]);
  if (!edge && !control) return null;
  // ★ WHICH PLANE DID NOT ANSWER, kept and shown. With the Edge unreachable the first version listed only
  // the plane that DID answer — which reads as "that node owns all of this" rather than "the other one was
  // asked and said nothing". Silence about a failed half is the mistake this whole two-plane merge exists to
  // avoid, and it had crept back into the one line that reports the merge.
  const silent = [];
  if (!edge) silent.push(bl({ en: "the enforcement Edge", ja: "強制ノード(Edge)" }));
  if (!control) silent.push(bl({ en: "the control plane", ja: "コントロールプレーン" }));
  const merged = {};
  const order = [];
  [control, edge].forEach((answer) => {
    if (!answer || !Array.isArray(answer.items)) return;
    answer.items.forEach((item) => {
      if (!merged[item.key]) order.push(item.key);
      const held = merged[item.key];
      const better = !held || (held.state === "not_here" && item.state !== "not_here");
      if (better) merged[item.key] = Object.assign({}, item, { answered_by: answer.measured_on || "" });
    });
  });
  const items = order.map((k) => merged[k]);
  const blocking = items.filter((i) => i.blocking && i.state === "missing");
  const unknown = items.filter((i) => i.blocking && i.state === "not_here");
  // Items nobody could answer. Counted separately from "not set", because a count that adds the two together
  // tells a reader there is more to do than there is.
  const unanswered = items.filter((i) => i.state === "not_here").length;
  return {
    tenant_id: tenantId,
    items: items,
    done: items.filter((i) => i.state === "done").length,
    total: items.length,
    blocking: blocking,
    unknown: unknown,
    // Same three-valued answer the API gives, recomputed over the merged set: neither plane can say "yes"
    // alone, and a screen that rounded "nothing I can see is wrong" up to a green tick would be the most
    // expensive kind of wrong this checklist exists to prevent.
    operational: blocking.length ? "no" : (unknown.length ? "unknown" : "yes"),
    unanswered: unanswered,
    silent: silent,
    // ★ EACH NODE ONCE. Where the console reaches only one plane — which is every deployment whose Edge
    // admin surface it cannot see — both answers come from the same node, and this listed it twice: "Asked:
    // local/local-edge-001 · local/local-edge-001", which reads as two nodes agreeing when it is one node
    // answered twice.
    asked: [...new Set([control, edge].filter(Boolean).map((a) => a.measured_on || "?"))],
    // WHICH organization the planes actually answered for. Kept so the screen can refuse to label somebody
    // else's answer with this organization's name.
    answered_for: (control && control.tenant_id) || (edge && edge.tenant_id) || "",
  };
}

// organizationSetupBadge is the one-glance answer for the organizations list.
function organizationSetupBadge(summary) {
  if (!summary) return uiBadge(bl({ en: "Unknown", ja: "不明" }), "off");
  // ★ THE DENOMINATOR IS WHAT COULD BE ANSWERED. Counting the unanswerable items as "not done" understates
  // an organization whenever a plane is unreachable — with the Edge down, a healthy organization read "3/13"
  // and looked half-abandoned. Five of those thirteen were simply unseen.
  const answerable = summary.total - (summary.unanswered || 0);
  const label = summary.done + "/" + answerable + (summary.unanswered ? " (+" + summary.unanswered + "?)" : "");
  if (summary.operational === "no") return uiBadge(label + " " + bl({ en: "· not working yet", ja: "・未稼働" }), "warn");
  if (summary.operational === "unknown") return uiBadge(label + " " + bl({ en: "· partly unseen", ja: "・一部未確認" }), "off");
  return uiBadge(label + " " + bl({ en: "· working", ja: "・稼働" }), "ok");
}

// renderOrganizationSetup draws the checklist for the organization currently being operated within.
function renderOrganizationSetup(host, tenantId, onChanged) {
  uiState(host, "loading");
  // The Reload button in this very toolbar is how two renders overlap; without this the older answer wins.
  const current = freshRender(host);
  organizationSetupMerged(tenantId).then((summary) => {
    if (!current()) return;
    host.innerHTML = "";
    if (!summary) {
      uiState(host, "error", bl({ en: "Neither plane answered.", ja: "どちらのノードも応答しません。" }),
        { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => renderOrganizationSetup(host, tenantId, onChanged) });
      return;
    }
    // ★ AN ANSWER ABOUT A DIFFERENT ORGANIZATION MUST NOT BE SHOWN AS THIS ONE'S. A read carrying
    // X-Operate-Tenant is silently ignored for a caller who may not use it — correct, it keeps a tenant
    // administrator from ever reaching across — and the answer then describes the CALLER's organization while
    // the screen's title says another. Measured with a credential lacking cross-tenant rights: all three
    // organizations returned tenant_reference_lab's numbers.
    if (summary.tenant_id && summary.answered_for && summary.answered_for !== summary.tenant_id) {
      host.appendChild(el("p", { class: "ui-view-desc", text: bl({
        en: "This answer is about " + summary.answered_for + ", not " + summary.tenant_id + " — you may not read that tenant.",
        ja: "この回答は " + summary.answered_for + " のもので、" + summary.tenant_id + " のものではありません（そのテナントを読む権限がありません）。" }) }));
      return;
    }
    const head = el("div", { class: "ui-toolbar" }, [
      organizationSetupBadge(summary),
      el("span", { class: "ui-spacer" }),
      el("span", { class: "ui-view-desc", text: bl({ en: "Asked: ", ja: "問い合わせ先: " }) + summary.asked.join(" · ")
        + (summary.silent && summary.silent.length
            ? bl({ en: " · no answer from " + summary.silent.join(", "), ja: " ・応答なし: " + summary.silent.join("、") })
            : "") }),
      el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Reload", ja: "再読込" }), onClick: () => renderOrganizationSetup(host, tenantId, onChanged) }),
    ]);
    host.appendChild(head);

    // The blocking items first and named, because "5/13" does not tell anybody what to do next.
    if (summary.blocking.length) {
      host.appendChild(el("p", { class: "ui-view-desc", text: bl({
        en: "Not working yet — " + summary.blocking.map((i) => setupWords(i).label).join(", "),
        ja: "まだ稼働しません — " + summary.blocking.map((i) => setupWords(i).label).join("、") }) }));
    }

    const rows = summary.items.map((item) => {
      const state = SETUP_STATE[item.state] || SETUP_STATE.not_here;
      const dest = SETUP_DESTINATION[item.key];
      const action = [];
      if (item.state !== "not_here" && dest) {
        action.push(el("button", {
          class: "ui-btn ui-btn-sm" + (item.state === "missing" ? " ui-btn-primary" : ""),
          // ★ ENTER THE ORGANIZATION, DO NOT JUST DRAW ITS SCREEN (2026-08-16, found by pressing the button).
          // renderGroup alone rendered the destination BEHIND the modal, fetched with the borrowed
          // selection — and then closing the modal handed the selection back, leaving an operator looking at
          // one organization's certificates while every action they took went to another. No banner, because
          // the console was no longer operating within anybody.
          //
          // "Go and set this up for THIS organization" means going there, which is what entering is for: it
          // persists the choice, shows the banner, and puts the whole console in one place instead of two.
          text: bl(dest.t), onClick: () => enterTenantAndOpen(tenantId, dest.group),
        }));
      } else if (item.state === "not_here") {
        action.push(el("span", { class: "ui-view-desc", text: bl({ en: "ask the other node", ja: "別ノードで確認" }) }));
      }
      if (item.key === "delegation") {
        action.length = 0;
        action.push(organizationDelegationControl(item, tenantId, () => renderOrganizationSetup(host, tenantId, onChanged)));
      }
      const words = setupWords(item);
      return el("tr", {}, [
        el("td", {}, [
          el("strong", { text: words.label }),
          // The capability, in plain words. This is the column that decides whether an operator bothers.
          el("div", { class: "ui-view-desc", text: words.enables }),
        ]),
        el("td", {}, [
          uiBadge(bl(state.t), state.tone),
          el("div", { class: "ui-view-desc", text: item.state === "not_here" ? bl({ en: "held on the other node", ja: "別ノードが保持" }) : setupDetail(item) }),
          item.answered_by ? el("div", { class: "ui-view-desc", text: bl({ en: "from ", ja: "取得元 " }) + item.answered_by }) : document.createTextNode(""),
        ]),
        el("td", { class: "ui-row-actions" }, action),
      ]);
    });
    host.appendChild(el("table", { class: "ui-table" }, [
      el("thead", {}, el("tr", {}, [
        bl({ en: "What it does", ja: "この設定の役割" }),
        bl({ en: "Now", ja: "現在" }),
        bl({ en: "Set it", ja: "設定" }),
      ].map((x) => el("th", { text: x })))),
      el("tbody", {}, rows),
    ]));
  });
}

// organizationDelegationControl is the one setting with no screen of its own, so it is set here rather than
// described here.
function organizationDelegationControl(item, tenantId, onDone) {
  const on = item.state === "done";
  const btn = el("button", {
    class: "ui-btn ui-btn-sm" + (on ? "" : " ui-btn-primary"),
    text: on ? bl({ en: "Hand back", ja: "委任を解除" }) : bl({ en: "Let the operator run it", ja: "運営に任せる" }),
  });
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      // Named, not borrowed: this is a WRITE, and the one thing a write must never take from a global that
      // another screen can move underneath it is which organization it lands in.
      const r = await apiFetch("PUT", "/admin/operator-delegation", { managed: !on }, "control", undefined, tenantId);
      if (!r.ok) { btn.disabled = false; uiToast((r.body && r.body.error) || ("HTTP " + r.status), "err"); return; }
      uiToast(on ? bl({ en: "The tenant runs itself again.", ja: "テナントが自ら運用します。" })
                 : bl({ en: "The operator can now run this tenant.", ja: "運営がこのテナントを運用できます。" }), "ok");
      if (onDone) onDone();
    } catch (e) { btn.disabled = false; uiToast(String(e), "err"); }
  });
  return btn;
}
