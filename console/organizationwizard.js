"use strict";

// organizationwizard.js — creating an organization, as the sequence it actually is.
//
// ★ A ONE-PAGE FORM WOULD BE THE OLD DEFECT WEARING A NEW SHIRT. Filling in a name and pressing Add produces
// a registry row, and a registry row enforces nothing: the organization appears in every list, is selectable
// in every menu, and does nothing at all. The form was honest about what it wrote and silent about what that
// left undone, which is how "created it, and nothing happens" survived this long.
//
// ★ SO THIS DOES WHAT IT CAN, AND HANDS OVER THE REST VISIBLY. Three steps that genuinely complete —
// the organization, who runs it, its first administrator — and then the checklist, which shows what is left
// with a control for each. It does NOT pretend to do the parts that need material this screen cannot produce
// (a certificate authority is not something a wizard invents), and the difference between "done" and "still
// to do" is on screen rather than in somebody's head.
//
// ★ THE INVITATION IS HANDED OVER, NOT SENT. Same component as the Administrators screen — there is no SMTP
// in this product by decision, and a screen that says "sent" when nothing was sent is worse than one that
// says nothing.

// ★ CHOOSE, DO NOT TYPE. Every value that comes from a known set is offered as a choice: the regions this
// deployment actually has (read from the fleet, not guessed), the time zones, and who runs the organization.
// A text box for a value with a known set asks the operator to remember an exact string and then fails them
// on a typo — and for regions a typo is not a validation error, it is an organization pinned to a region that
// does not exist.
//
// The two fields that stay text are the ones with no set: the display name, and the first administrator's
// address. The identifier is derived from the name so it does not have to be invented either, and stays
// editable because it is permanent.
const WIZARD_ZONES = [
  "Asia/Tokyo", "Asia/Seoul", "Asia/Shanghai", "Asia/Singapore", "Asia/Kolkata", "Asia/Dubai",
  "Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Madrid",
  "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "America/Sao_Paulo",
  "Australia/Sydney", "UTC",
];

// deploymentRegions asks the fleet which regions exist. Falls back to nothing rather than to invented names:
// an empty list is honest and the field says so, while a made-up "region-a" would be a suggestion the
// deployment cannot honour.
async function deploymentRegions() {
  try {
    const r = await apiFetch("GET", "/admin/fleet/config-status", undefined, "control");
    const edges = (r.ok && r.body && Array.isArray(r.body.edges)) ? r.body.edges : [];
    return [...new Set(edges.map((e) => String(e.region_id || "").trim()).filter(Boolean))].sort();
  } catch (e) { return []; }
}

async function openOrganizationWizard(content) {
  const state = { tenantId: "", displayName: "", created: false };
  const regions = await deploymentRegions();

  // ★★★ THE IDENTIFIER IS NO LONGER ASKED FOR (2026-08-21). This form used to fill it in from the display
  // name — "Northwind Traders" became tenant_northwind — and that identifier becomes the name the
  // organization's agents send, which the transport port confirms or denies to anyone who asks by SNI. A
  // dictionary of company names then enumerates the customers on a deployment. The identifier is issued by
  // the server now, and the person creating an organization has one fewer thing to get right.
  const nameF = uiField({ name: "name", label: bl({ en: "Display name", ja: "表示名" }), required: true, placeholder: "Acme Corp",
    hint: bl({ en: "What everyone will see. The identifier behind it is issued automatically and never shown to anyone outside.",
               ja: "みんなが見る名前です。内部で使う識別子は自動で発行され、外からは分かりません。" }) });

  const zoneF = uiField({ name: "zone", label: bl({ en: "Time zone", ja: "タイムゾーン" }), type: "select", value: "Asia/Tokyo",
    options: WIZARD_ZONES.map((z) => ({ value: z, label: z })),
    hint: bl({ en: "Reports and log timestamps are read in this zone.", ja: "レポートとログの時刻はこのゾーンで読まれます。" }) });

  const noRegions = !regions.length;
  const homeF = uiField({ name: "home", label: bl({ en: "Home region", ja: "ホームリージョン" }), type: "select",
    value: regions[0] || "",
    options: [{ value: "", label: bl({ en: "— not pinned —", ja: "— 指定しない —" }) }].concat(regions.map((r) => ({ value: r, label: r }))),
    hint: noRegions ? bl({ en: "No region is reporting, so there is nothing to choose from yet.", ja: "報告しているリージョンがないため、選択肢がありません。" })
                    : bl({ en: "Where they are served from by default.", ja: "既定でどこから提供するか。" }) });

  // A choice per region rather than a comma-separated string: for regions a typo is not a validation error,
  // it is an organization pinned to a region that does not exist.
  const regionBoxes = regions.map((r) => {
    const cb = el("input", { type: "checkbox", value: r });
    cb.checked = true;
    return { region: r, box: cb, el: el("label", { class: "ui-check", style: "margin-right:12px" }, [cb, document.createTextNode(" " + r)]) };
  });
  const regionsF = {
    el: el("div", { class: "ui-field" }, [
      el("div", { class: "ui-field-label", text: bl({ en: "Regions they may occupy", ja: "占有してよいリージョン" }) }),
      regionBoxes.length ? el("div", {}, regionBoxes.map((b) => b.el))
                         : el("div", { class: "ui-view-desc", text: bl({ en: "No region is reporting.", ja: "報告しているリージョンがありません。" }) }),
      el("div", { class: "ui-field-hint", text: bl({ en: "Their traffic and data stay inside the ones you tick.", ja: "通信とデータは、チェックしたリージョンの中に留まります。" }) }),
    ]),
    get: () => regionBoxes.filter((b) => b.box.checked).map((b) => b.region),
  };

  // Who runs it. A real decision at onboarding, and the one the operator most often means to make and forgets:
  // without it the operator can enter this organization and change nothing.
  const runF = uiField({ name: "run", label: bl({ en: "Who runs it", ja: "運用の担当" }), type: "select", value: "operator", options: [
    { value: "operator", label: bl({ en: "We run it for them", ja: "運営が代行する" }) },
    { value: "themselves", label: bl({ en: "They run it themselves", ja: "テナントが自ら運用する" }) },
  ], hint: bl({ en: "You can change this later, and so can they.", ja: "後から変更できます。テナント側からも変更できます。" }) });

  const adminF = uiField({ name: "admin", label: bl({ en: "Their first administrator (email)", ja: "最初の管理者(メール)" }),
    placeholder: "admin@acme.example",
    hint: bl({ en: "Optional here — you will be given a link to hand over, nothing is emailed.", ja: "任意です。手渡し用のリンクが出ます。メールは送信されません。" }) });

  // ★★★ THE ONE MOMENT THIS COSTS NOTHING (2026-08-28). The Edge picks an organization's certificate by the
  // name a device sends, and a device that sends none is served the deployment's shared one. Giving an
  // organization its own name LATER is a movement — announce it, wait for every device to adopt it, serve both
  // until they have. Here there are no devices, and that is the only time that sentence is empty.
  //
  // ★ IT IS NOT THE THING THE HEADER SAYS A WIZARD MUST NOT INVENT. That is the INTERCEPTION root, which is
  // the customer's and arrives out of band. This one is minted by the deployment from the organization's own
  // issued id — nothing is invented and nothing is typed, which is also why no name is asked for here: the id
  // is unguessable and the company's own name on a plaintext SNI is what that protects against.
  const doorBox = el("input", { type: "checkbox" });
  doorBox.checked = true;
  const doorF = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-check" }, [doorBox, document.createTextNode(" " + bl({
      en: "Give them their own address on the Edges",
      ja: "この組織専用の入口アドレスを与える" }))]),
    el("div", { class: "ui-field-hint", text: bl({
      en: "Their devices then verify this deployment with nothing but their own organization's certificate, " +
          "and no other tenant's name is offered to them. Every Edge picks it up on its next fetch. " +
          "Doing it later means moving devices onto a new name; doing it now does not, because they have none.",
      ja: "以後この組織の端末は、自組織の証明書だけでこの配備を検証します。他テナントの名前は提示されません。" +
          "各 Edge は次回の取得で反映します。後から行うと端末を新しい名前へ移す作業になりますが、" +
          "いまはまだ端末が無いので、その必要がありません。" }) }),
  ]);

  const status = el("p", { class: "ui-view-desc" });
  const submit = el("button", { class: "ui-btn ui-btn-primary", text: bl({ en: "Create tenant", ja: "テナントを作成" }) });

  const m = uiModal({
    title: bl({ en: "Add a tenant", ja: "テナントを追加" }),
    body: [nameF.el, zoneF.el, homeF.el, regionsF.el, doorF, runF.el, adminF.el, status],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => m.close() }), submit],
  });

  const say = (text) => { status.textContent = text; };

  submit.addEventListener("click", async () => {
    if (!nameF.validate()) return;
    submit.disabled = true;
    try {
      // 1. The organization itself.
      say(bl({ en: "Creating the tenant…", ja: "テナントを作成しています…" }));
      const chosenRegions = regionsF.get();
      const created = await apiFetch("POST", "/admin/tenants", {
        display_name: nameF.get(), status: "active",
        timezone: zoneF.get(), home_region: homeF.get(), allowed_regions: chosenRegions,
        transport_authority: doorBox.checked,
      });
      if (!created.ok) {
        submit.disabled = false;
        const msg = (created.body && (created.body.error || created.body.message)) || ("HTTP " + created.status);
        nameF.setError(msg); say(""); uiToast(msg, "err"); return;
      }
      state.created = true;
      // The identifier the server issued — everything after this point acts inside it by name.
      const tenantId = (created.body && created.body.tenant_id) || "";
      // ★ SAID, NOT ASSUMED. The organization exists either way; whether it got its own address is a separate
      // outcome and the answer carries it. A wizard that ticked a box and reported nothing is how the previous
      // four joins in this chain stayed unnoticed.
      if (doorBox.checked) {
        const own = (created.body && created.body.transport_server_name) || "";
        const why = (created.body && created.body.transport_authority_note) || "";
        if (own) {
          say(bl({ en: "Their own address: ", ja: "この組織の入口アドレス: " }) + own);
        } else if (why) {
          uiToast(bl({ en: "Created, without its own address: ", ja: "作成しましたが、専用アドレスはありません: " }) + why, "err");
        }
      }
      // ★ AND WHETHER IT CAN CARRY TRAFFIC AT ALL. An organization created with no starting posture denies
      // every flow of every one of its devices while its own Internet Access screen says everything is
      // allowed and inspected — so if that could not be written, it is the loudest thing on this screen.
      if (created.body && created.body.starting_posture_note) {
        uiToast(bl({ en: "Created, and it carries no traffic: ", ja: "作成しましたが、通信を運びません: " }) +
                created.body.starting_posture_note, "err");
      }
      if (!tenantId) {
        // ★ NOT ASSUMED. The steps below all act inside this organization by naming it; with no id they would
        // silently act inside the operator's own, which is how a wizard once seated a customer's first
        // administrator in the wrong place.
        submit.disabled = false;
        const msg = bl({ en: "The organization was created but its identifier did not come back, so the rest of the setup was not run.",
                         ja: "組織は作成されましたが識別子が返らなかったため、以降の設定は実行していません。" });
        say(""); uiToast(msg, "err"); return;
      }
      state.tenantId = tenantId;
      state.displayName = nameF.get();

      // Everything after this point acts INSIDE the new organization — named on each call rather than by
      // moving the Console's selection there. A selection that moves is the selection every other thing running
      // at that moment reads, and later restores: that is how a deleted half-built organization ended up as the
      // Console's operating context after this wizard ran.

      // 2. Who runs it. Reported rather than assumed: a step that quietly failed would leave an operator
      // believing they can administer an organization they cannot.
      say(bl({ en: "Recording who runs it…", ja: "運用の担当を記録しています…" }));
      const delegated = runF.get() === "operator";
      const deleg = await apiFetch("PUT", "/admin/operator-delegation", { managed: delegated }, "control", undefined, tenantId);
      if (!deleg.ok) {
        uiToast(bl({ en: "The tenant was created, but who runs it could not be set — set it in the checklist.",
                     ja: "テナントは作成しましたが、運用の担当を設定できませんでした。チェックリストで設定してください。" }), "err");
      }

      // 3. Their first administrator, if one was named.
      let invitation = null;
      const email = adminF.get().trim();
      if (email) {
        say(bl({ en: "Creating the invitation…", ja: "招待を作成しています…" }));
        const invited = await apiFetch("POST", "/admin/admins/invite", { email: email, roles: ["admin"] }, "control", undefined, tenantId);
        if (invited.ok) {
          invitation = invited.body && invited.body.invitation;
        } else {
          uiToast(bl({ en: "The tenant was created; the invitation failed — invite from Administrators.",
                       ja: "テナントは作成しました。招待に失敗したので、管理者画面から招待してください。" }), "err");
        }
      }

      m.close();
      uiToast(bl({ en: "Tenant created.", ja: "テナントを作成しました。" }), "ok");
      renderOrganizationsView(content);
      // 4. What is left. The wizard ends on the checklist rather than on a success message, because the
      // organization does not work yet and the screen should say so while somebody is still here.
      //
      // ★ THE INVITATION FIRST, AND THE CHECKLIST ONLY AFTER IT IS CLOSED. Opening both put the checklist on
      // top of the one-time link, which is the single thing in this flow that cannot be recovered by looking
      // again — the operator would have had to reissue it.
      const showChecklist = () => openOrgSetup({ tenant_id: tenantId, display_name: state.displayName }, null);
      if (invitation) openInvitationHandover(invitation, { onClosed: showChecklist });
      else showChecklist();
    } catch (e) {
      submit.disabled = false; say(""); uiToast(String(e), "err");
    }
  });

  nameF.focus();
}
