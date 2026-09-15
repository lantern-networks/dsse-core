"use strict";

// agentprofile.js — "Device configuration": the one file every endpoint needs, made here.
//
// ★★★ BEFORE THIS SCREEN THERE WAS NO WAY TO PRODUCE IT WITHOUT THE REPOSITORY AND THE SIGNING KEY
// (2026-08-25, reported from a real endpoint). Making one meant: ssh to the machine holding the source, find
// cmd/dsse-genprofile, hand it the deployment's raw signing seed as a FILE PATH, and copy the JSON back. An
// operator has no checkout, no Go toolchain, and no shell on the control plane — and the deployment's signing
// key belongs in the deployment, not in a person's hands.
//
// ★★ NOTHING ON THIS SCREEN IS TYPED. Every value is one the deployment already knows: the organization is the
// caller's, the addresses are its own regions, the groups are its registry, and the bypass entries are its
// catalogue. What an operator decides is which group, what happens when no Edge can be reached, and what is
// left uninspected. Typed values here are matched by string on the device, where a typo is accepted, signed,
// installed, and silently wrong.
//
// Backend: GET /admin/agent-profile/options -> {tenant_id, transport_endpoints, transport_endpoints_note,
// device_groups, bypass_catalog, postures}; POST /admin/agent-profile -> a signed envelope.

// The control plane holds the organization's authorities and issues the complete
// profile. A configuration-consuming Edge cannot supply those bootstrap pins.
const _PROFILE_PLANE = "control";

let _profileOptions = null;
// The endpoints, in the order a device tries them. Held here because the ORDER is the decision.
let _profileEndpoints = [];

function renderAgentProfileView(content) {
  content.innerHTML = "";
  content.appendChild(el("div", { class: "ui-view-head" }, [
    el("div", {}, [
      el("h2", { class: "ui-view-title", text: bl({ en: "Device configuration", ja: "端末の設定" }) }),
      el("p", { class: "ui-view-desc", text: bl({
        en: "The settings a device on this deployment needs. Making them produces one file.",
        ja: "この配備の端末に入れる設定です。作ると1つのファイルになります。" }) }),
    ]),
  ]));
  const host = el("div", {});
  content.appendChild(host);
  loadAgentProfileForm(host);
}

async function loadAgentProfileForm(host) {
  uiState(host, "loading");
  const current = freshRender(host);
  let body;
  try {
    const r = await apiFetch("GET", "/admin/agent-profile/options", undefined, _PROFILE_PLANE);
    if (!r.ok) {
      if (!current()) return;
      uiState(host, "error", (r.body && r.body.error) || ("HTTP " + r.status),
        { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadAgentProfileForm(host) });
      return;
    }
    body = r.body || {};
  } catch (e) {
    if (!current()) return;
    uiState(host, "error", String(e), { label: bl({ en: "Retry", ja: "再試行" }), onClick: () => loadAgentProfileForm(host) });
    return;
  }
  if (!current()) return;
  _profileOptions = body;
  // ★★★ AN ADDRESS A DEVICE CANNOT REACH IS NOT OFFERED AS A CHOICE (reported from real hardware,
  // 2026-08-26). A deployment brought up on localhost produces "agents.localhost"; on a laptop that is the
  // machine itself, and with the default posture — do not carry traffic until an Edge answers — a device
  // taking that profile loses the network entirely. The screen marks them and leaves them unticked; the
  // server refuses outright when there is nothing else.
  const unreachable = {};
  (body.transport_endpoints_unreachable || []).forEach((e) => { unreachable[e] = true; });
  _profileEndpoints = (body.transport_endpoints || []).map((e) => ({
    value: e, on: !unreachable[e], unreachable: !!unreachable[e],
  }));
  host.innerHTML = "";
  renderAgentProfileForm(host);
}

// "region-a=https://agents.example.com" is what a device reads. A person reads the region and the address.
function profileEndpointParts(raw) {
  const i = String(raw).indexOf("=");
  if (i <= 0) return { region: "", url: String(raw) };
  return { region: String(raw).slice(0, i), url: String(raw).slice(i + 1) };
}

function renderAgentProfileForm(host) {
  const opts = _profileOptions || {};

  // Which devices. A group is chosen, never typed: the registry is the deployment's, and a name that does not
  // match one silently puts a device in a group nothing governs.
  const groups = opts.device_groups || [];
  const groupF = uiField({
    name: "group", type: "select", value: "",
    label: bl({ en: "Which devices", ja: "どの端末に" }),
    options: [{ value: "", label: bl({ en: "Every device in this organization", ja: "この組織のすべての端末" }) }]
      .concat(groups.map((g) => ({ value: g.name, label: g.name }))),
    hint: groups.length
      ? bl({ en: "Groups this deployment knows. Posture and exceptions can differ per group.",
             ja: "この配備が知っているグループです。姿勢や例外はグループごとに変えられます。" })
      : bl({ en: "No groups exist yet, so this applies to every device in the organization.",
             ja: "グループがまだ無いため、この組織のすべての端末が対象です。" }),
  });

  // Where a device starts. Checked, in order, and reorderable — the order IS what a device tries.
  const endpointHost = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label", text: bl({ en: "Where devices connect", ja: "接続先" }) }),
  ]);
  const endpointList = el("div", { class: "ui-checklist" });
  endpointHost.appendChild(endpointList);
  endpointHost.appendChild(el("span", { class: "ui-field-hint", text: opts.transport_endpoints_note || "" }));
  if ((opts.transport_endpoints_unreachable || []).length) {
    endpointHost.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "One or more of this deployment's addresses resolves to the machine itself, so a device would dial "
        + "itself and — not carrying traffic until an Edge answers — lose the network. Those are left unticked.",
      ja: "この配備の住所のうち、端末側では自分自身を指すものがあります。その端末は自分にダイヤルし、"
        + "Edge に繋がらないため通信を止めます（ネットワークが落ちます）。それらはチェックを外してあります。" }) }));
  }
  renderProfileEndpoints(endpointList);

  // The organization is shown, never chosen. Choosing it would let one customer's administrator make
  // configuration that enrols machines into another's; the server reads it from the caller regardless.
  //
  // ★★ AND IT IS SHOWN BY NAME (2026-09-05). Under a label reading "Organization" this printed
  // tenant_xkcgvvava4k5d63ral2q23iwu4 — the id that goes INTO the file, which is not the answer to the
  // question the label asks. Every other surface in this Console calls that organization Kaede Foods. The id
  // stays underneath, because it is what an operator quotes into an API call and what the profile carries.
  const tenantID = String(opts.tenant_id || "");
  const tenantName = (typeof operatingOrganizationName === "string" && operatingOrganizationName.trim()) || "";
  const tenantRow = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label", text: bl({ en: "Organization", ja: "組織" }) }),
    el("div", { class: "ui-preview", text: tenantName || tenantID || "—" }),
    ...(tenantName && tenantID ? [el("span", { class: "ui-field-hint", text: tenantID })] : []),
  ]);

  // ── What happens when no Edge can be reached ──
  //
  // Not "fail-closed / fail-open": those are the flag's words, not an operator's. The question being answered
  // is what a laptop does in a hotel, and it is asked in those terms.
  const postureName = "profile_posture_" + Math.floor(performance.now());
  const closedIn = el("input", { type: "radio", name: postureName, value: "fail-closed" });
  closedIn.checked = true;
  const openIn = el("input", { type: "radio", name: postureName, value: "fail-open" });
  const ackF = uiField({ name: "ack", type: "checkbox",
    label: bl({ en: "I understand, and choose this", ja: "上を理解した上で選びます" }) });
  ackF.el.style.display = "none";
  const openWarn = el("div", { class: "ui-callout ui-callout-warn" }, [
    el("p", { class: "ui-view-desc", text: bl({
      en: "While a device is carrying traffic this way, none of it is recorded and no rule is applied to it. "
        + "A device that has been blocked reaches the internet again for as long as it lasts.",
      ja: "その間、その端末の通信は記録されず、ルールも適用されません。"
        + "ブロックした端末も、その間はインターネットに出られます。" }) }),
    ackF.el,
  ]);
  openWarn.style.display = "none";
  const syncPosture = () => {
    const open = openIn.checked;
    openWarn.style.display = open ? "" : "none";
    ackF.el.style.display = open ? "" : "none";
    if (!open) ackF.set(false);
  };
  closedIn.addEventListener("change", syncPosture);
  openIn.addEventListener("change", syncPosture);
  const postureHost = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label", text: bl({ en: "When no Edge can be reached", ja: "通信が止まったとき" }) }),
    el("label", { class: "ui-checkrow" }, [closedIn, el("span", { text: bl({
      en: "Do not carry traffic until one can be", ja: "Edge に繋がらない間は通信させない" }) })]),
    el("label", { class: "ui-checkrow" }, [openIn, el("span", { text: bl({
      en: "Carry traffic unfiltered in the meantime", ja: "Edge に繋がらない間は素通しにする" }) })]),
    openWarn,
  ]);

  // ── Virtual machines on the device ──
  //
  // ★★★ A VIRTUAL MACHINE HAS ITS OWN NETWORK AND THIS DEPLOYMENT DOES NOT SEE IT (2026-09-01, measured on a
  // real Windows box). The words on this screen are "virtual machines", not WSL, not Hyper-V, not vEthernet:
  // the person deciding knows whether their people run virtual machines, and does not need to know which
  // technology carries them.
  const vmName = "vmegress-" + Math.random().toString(36).slice(2);
  const vmBlockIn = el("input", { type: "radio", name: vmName, value: "blocked" });
  vmBlockIn.checked = true;
  const vmAllowIn = el("input", { type: "radio", name: vmName, value: "allowed" });
  const vmAckF = uiField({ name: "vmack", type: "checkbox",
    label: bl({ en: "I understand, and choose this", ja: "上を理解した上で選びます" }) });
  vmAckF.el.style.display = "none";
  const vmWarn = el("div", { class: "ui-callout ui-callout-warn" }, [
    el("p", { class: "ui-view-desc", text: bl({
      en: "Traffic from a virtual machine is not carried through this deployment: it is not recorded, no rule "
        + "is applied to it, and it does not appear anywhere. Anyone using the device can start one — no "
        + "administrator rights are needed.",
      ja: "仮想マシンの通信はこの配備を通りません。記録されず、ルールも適用されず、どこにも現れません。"
        + "端末を使う人なら誰でも起動できます —— 管理者権限は要りません。" }) }),
    vmAckF.el,
  ]);
  vmWarn.style.display = "none";
  const syncVM = () => {
    const allow = vmAllowIn.checked;
    vmWarn.style.display = allow ? "" : "none";
    vmAckF.el.style.display = allow ? "" : "none";
    if (!allow) vmAckF.set(false);
  };
  vmBlockIn.addEventListener("change", syncVM);
  vmAllowIn.addEventListener("change", syncVM);
  const vmHost = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label", text: bl({ en: "Virtual machines on the device", ja: "端末の中の仮想マシン" }) }),
    el("label", { class: "ui-checkrow" }, [vmBlockIn, el("span", { text: bl({
      en: "Do not let them reach the internet", ja: "インターネットに出させない" }) })]),
    el("label", { class: "ui-checkrow" }, [vmAllowIn, el("span", { text: bl({
      en: "Let them out without being inspected", ja: "検査せずに外に出す" }) })]),
    vmWarn,
  ]);

  // ── What is left uninspected ──
  const catalog = opts.bypass_catalog || [];
  const bypassChecks = {};
  const bypassHost = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label", text: bl({ en: "Left uninspected", ja: "通さないもの" }) }),
  ]);
  const bypassList = el("div", { class: "ui-checklist" });
  bypassHost.appendChild(bypassList);
  catalog.forEach((entry) => {
    const cb = el("input", { type: "checkbox" });
    bypassChecks[entry.id] = cb;
    // ★ THE HUMAN NAME, NOT THE ID (2026-08-25, seen on the screen). The catalogue's `name` is its identifier
    // — apple_push, windows_update — and printing it asks an operator to decide about "fido2_passkey_hybrid_
    // cable". The description is what the entry IS; the vendor puts it in a world they recognise.
    const label = profileBypassLabel(entry);
    // Direct children of the row, so its own flex gap separates them — a wrapping span would put the name and
    // the vendor hard against each other, which is what the first version did.
    bypassList.appendChild(el("label", { class: "ui-checkrow" }, [
      cb,
      el("span", { text: label }),
      entry.vendor ? el("span", { class: "ui-view-desc", text: entry.vendor }) : null,
      el("span", { class: "ui-spacer" }),
      entry.risk ? el("span", { class: "ui-badge", text: profileRiskLabel(entry.risk) }) : null,
    ]));
  });
  if (!catalog.length) {
    bypassHost.appendChild(el("p", { class: "ui-view-desc", text: bl({
      en: "This deployment publishes no catalogue, so there is nothing to choose from here.",
      ja: "この配備はカタログを公開していないため、ここから選べるものはありません。" }) }));
  }

  const submit = el("button", { class: "ui-btn ui-btn-primary",
    text: bl({ en: "Make the configuration", ja: "設定ファイルを作る" }) });
  const errHost = el("div", {});

  submit.addEventListener("click", async () => {
    if (submit.disabled) return;
    errHost.innerHTML = "";
    const chosen = _profileEndpoints.filter((e) => e.on).map((e) => e.value);
    if (!chosen.length) {
      uiToast(bl({ en: "Choose at least one address, or a device has nowhere to start.",
                   ja: "接続先を1つ以上選んでください。無いと端末はどこにも繋げません。" }), "err");
      return;
    }
    const failOpen = openIn.checked;
    if (failOpen && !ackF.get()) {
      ackF.setError(bl({ en: "This has to be chosen deliberately.", ja: "これは明示的に選ぶ必要があります。" }));
      return;
    }
    if (vmAllowIn.checked && !vmAckF.get()) {
      vmAckF.setError(bl({ en: "This has to be chosen deliberately.", ja: "これは明示的に選ぶ必要があります。" }));
      return;
    }
    // Keep the profile and its later tokens bound to the same submitted group.
    const group = groupF.get();
    submit.disabled = true;
    try {
      const r = await apiFetch("POST", "/admin/agent-profile", {
        group,
        transport_endpoints: chosen,
        posture: failOpen ? "fail-open" : "fail-closed",
        ack_fail_open: failOpen,
        virtual_machine_egress: vmAllowIn.checked ? "allowed" : "blocked",
        ack_virtual_machine_egress: vmAllowIn.checked && vmAckF.get(),
        bypass_catalog_ids: Object.keys(bypassChecks).filter((id) => bypassChecks[id].checked),
      }, _PROFILE_PLANE);
      submit.disabled = false;
      if (!r.ok) {
        const msg = (r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status);
        errHost.appendChild(el("div", { class: "ui-callout ui-callout-warn" }, [el("p", { text: msg })]));
        uiToast(msg, "err");
        return;
      }
      showAgentProfileMade(r.body, group);
    } catch (e) {
      submit.disabled = false;
      uiToast(String(e), "err");
    }
  });

  host.appendChild(el("div", { class: "ui-card" }, [
    groupF.el, endpointHost, tenantRow, postureHost, vmHost, bypassHost, errHost,
    el("div", { class: "ui-row-actions" }, [submit]),
  ]));
}

// The catalogue's description is written for whoever maintains the catalogue, and some entries carry a second
// sentence aimed at an engineer ("Required by `stapler` and by first-launch ticket lookup"). What belongs on a
// screen where somebody decides whether to inspect something is WHAT IT IS — one clause, no jargon, no code
// spans. The rest stays in the catalogue, where the audience for it is.
//
// ★ ABBREVIATIONS ARE NOT SENTENCE ENDS. Cutting at the first ". " turned "iCloud (incl. Private Relay)" into
// "iCloud (incl" — a label that is worse than the untrimmed text, and wrong in a way nobody would report.
const PROFILE_NOT_SENTENCE_END = ["incl", "excl", "e.g", "i.e", "etc", "vs", "approx", "ca", "inc", "ltd"];

function profileBypassLabel(entry) {
  const raw = String(entry.description || entry.name || "").replace(/`/g, "").trim();
  if (!raw) return entry.id;
  const re = /\.\s+(?=[A-Z(])/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const before = raw.slice(0, m.index);
    const lastWord = (before.match(/([A-Za-z.]+)$/) || ["", ""])[1].toLowerCase();
    if (PROFILE_NOT_SENTENCE_END.indexOf(lastWord) >= 0) continue;
    return before.trim();
  }
  return raw;
}

function profileRiskLabel(risk) {
  if (risk === "high") return bl({ en: "not looking here is risky", ja: "見ない危険が大きい" });
  if (risk === "medium") return bl({ en: "some risk in not looking", ja: "見ない危険がある" });
  return bl({ en: "little risk in not looking", ja: "見ない危険は小さい" });
}

// The list a device works through, top first. Order is a decision, so it is made by moving rows rather than
// by editing a string.
function renderProfileEndpoints(host) {
  host.innerHTML = "";
  _profileEndpoints.forEach((entry, i) => {
    const parts = profileEndpointParts(entry.value);
    const cb = el("input", { type: "checkbox" });
    cb.checked = entry.on;
    cb.addEventListener("change", () => { entry.on = cb.checked; });
    const up = el("button", { class: "ui-btn ui-btn-sm", text: "↑", onClick: () => moveProfileEndpoint(host, i, -1) });
    const down = el("button", { class: "ui-btn ui-btn-sm", text: "↓", onClick: () => moveProfileEndpoint(host, i, 1) });
    up.disabled = i === 0;
    down.disabled = i === _profileEndpoints.length - 1;
    host.appendChild(el("label", { class: "ui-checkrow" }, [
      cb,
      parts.region ? el("strong", { text: parts.region }) : null,
      el("span", { class: "ui-view-desc", text: parts.url }),
      entry.unreachable ? el("span", { class: "ui-badge ui-badge-danger", text: bl({
        en: "devices cannot reach this", ja: "端末からは届きません" }) }) : null,
      el("span", { class: "ui-spacer" }),
      up, down,
    ]));
  });
}

function moveProfileEndpoint(host, i, delta) {
  const j = i + delta;
  if (j < 0 || j >= _profileEndpoints.length) return;
  const tmp = _profileEndpoints[i];
  _profileEndpoints[i] = _profileEndpoints[j];
  _profileEndpoints[j] = tmp;
  renderProfileEndpoints(host);
}


// profileSigningKeyOf reads the deployment's profile-signing public key out of the envelope the server just
// signed, so the operator can place it on the device as its own file.
//
// ★★★ THE DEVICE MUST NOT TAKE THIS KEY OUT OF THE PROFILE (2026-08-29, the operator's decision). The macOS
// installer used to: it decoded the profile without checking the signature, read this field, and wrote it as
// the pin the profile would then be verified against. A substituted profile signed by whoever substituted it
// passed. Reading it HERE is a different act — it arrives over an authenticated Console session, and the
// operator places it on the device separately, the way the one-time token is placed. The device then refuses
// any profile this key did not sign.
function profileSigningKeyOf(envelope) {
  try {
    const body = JSON.parse(atob(envelope.payload_b64));
    const key = ((body || {}).deployment || {}).agent_policy_signing_public_key || "";
    return String(key).trim();
  } catch (e) { return ""; }
}

// preferredRegionsOf reads the rank this deployment put in the profile, best first.
//
// ★ SAID ON THE SCREEN, BECAUSE IT CHANGES WHERE DEVICES GO (2026-08-30). Until today the rank was never
// filled and every device ranked its regions by measured latency alone; now the order this deployment offers
// becomes the preference. A behaviour change nobody can see on the screen that causes it is one an operator
// discovers from a device.
function preferredRegionsOf(envelope) {
  try {
    const body = JSON.parse(atob(envelope.payload_b64));
    const pri = body.region_priority || {};
    return Object.keys(pri).sort((a, b) => pri[a] - pri[b]);
  } catch (e) { return []; }
}

function downloadProfileSigningKey(envelope) {
  const key = profileSigningKeyOf(envelope);
  if (!key) { uiToast(bl({ en: "This deployment published no profile-signing key.", ja: "この配備は署名鍵を公開していません。" }), "err"); return; }
  const url = URL.createObjectURL(new Blob([key + "\n"], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "profile_signing_key.txt";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadAgentProfile(envelope) {
  const text = JSON.stringify(envelope, null, 2) + "\n";
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  // ★★★ THE NAME IS PART OF THE LANE (2026-08-30). The installer looks beside itself for a file called
  // install_profile.json, and this handed the person "dsse-agent-profile.json" — so downloading all three
  // things the Console offers, putting them next to the installer and opening it did NOT work, and the
  // installer's refusal named a file the Console had never produced. The bytes were always right; the label
  // on them was the whole failure.
  a.download = "install_profile.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ★★ THE SCREEN MUST NOT HAND OVER ONLY HALF. This file says where and how to connect; it deliberately carries
// no certificate, because it is reused across a group and a device's identity is one machine's. An operator
// who leaves with only this cannot enrol anything — so the same act offers the group's tokens.
function showAgentProfileMade(envelope, group) {
  const dl = el("button", { class: "ui-btn ui-btn-primary",
    text: bl({ en: "Download", ja: "ダウンロード" }) });
  const dlKey = el("button", { class: "ui-btn",
    text: bl({ en: "Download the key", ja: "鍵をダウンロード" }) });
  const countF = uiField({ name: "count", value: "1",
    label: bl({ en: "How many devices?", ja: "何台分ですか" }),
    hint: group
      ? bl({ en: "One token per device, for the group “" + group + "”.",
             ja: "1台につき1枚、グループ「" + group + "」で作ります。" })
      : bl({ en: "One token per device.", ja: "1台につき1枚です。" }) });
  const makeTokens = el("button", { class: "ui-btn",
    text: bl({ en: "Make the tokens", ja: "まとめて作る" }) });

  // ★★★ OR TAKE THE WHOLE SET IN ONE FILE (2026-08-30, the operator asked for both shapes). Four things reach
  // a device — the installer, this configuration, the key that verifies it, and one approval — and until now
  // an operator collected them one at a time and then had to know that the installer reads the other three
  // from the folder it sits in. This is that folder, as one download. The separate buttons stay, because a
  // deployment that distributes its installer once per version does not want it in every bundle.
  // ★ type:"select" is not decoration — uiField renders a free-text box without it, and the options simply
  // do not appear. A control that silently becomes something else is how a screen offers a choice nobody can
  // make.
  // ★★★ THE DEFAULT WAS MAC WHOEVER WAS LOOKING (2026-09-07, measured: a Windows operator, in that machine's
  // own browser, was handed dsse-device-setup-darwin-arm64.zip). The archive is the same three files either
  // way until this deployment publishes an installer, so nothing was corrupt — what was wrong was the
  // README's last paragraph, which then gave macOS instructions on a Windows box, and the approval minted
  // against the wrong platform. The button is pressable again afterwards, but the approval just spent is not,
  // so the default is where this has to be fixed rather than the recovery.
  //
  // Read from the browser, which is the one thing here that knows. A machine this does not recognise falls
  // through to the previous default rather than to nothing: an unfamiliar agent string is not a reason to
  // make somebody choose before they can see what the choices mean.
  const guessedPlatform = (function () {
    try {
      const d = navigator.userAgentData;
      const ua = String((d && d.platform) || navigator.platform || navigator.userAgent || "");
      const arm = /arm|aarch64/i.test(String(navigator.userAgent || "")) ||
                  /arm/i.test(String((d && d.architecture) || ""));
      if (/win/i.test(ua)) return arm ? "windows/arm64" : "windows/amd64";
      if (/mac|darwin/i.test(ua)) return arm || /Mac OS X 1[1-9]/.test(String(navigator.userAgent || ""))
        ? "darwin/arm64" : "darwin/amd64";
    } catch (e) { /* fall through */ }
    return "darwin/arm64";
  })();
  const platformF = uiField({ name: "platform", type: "select", value: guessedPlatform,
    label: bl({ en: "Which kind of machine?", ja: "どの種類の機械ですか" }),
    hint: bl({ en: "Only the installer differs; the rest of the set is the same.",
               ja: "違うのはインストーラだけで、あとは同じです。" }),
    options: [
      { value: "darwin/arm64", label: bl({ en: "Mac (Apple silicon)", ja: "Mac(Apple シリコン)" }) },
      { value: "darwin/amd64", label: bl({ en: "Mac (Intel)", ja: "Mac(Intel)" }) },
      { value: "windows/amd64", label: bl({ en: "Windows (64-bit)", ja: "Windows(64bit)" }) },
      { value: "windows/arm64", label: bl({ en: "Windows (Arm)", ja: "Windows(Arm)" }) },
    ] });
  const bundle = el("button", { class: "ui-btn ui-btn-primary",
    text: bl({ en: "Download everything for one device", ja: "端末1台ぶんを一式でダウンロード" }) });

  const m = uiModal({
    title: bl({ en: "The configuration is ready", ja: "設定ができました" }),
    body: [
      // ★★★ SAY WHERE THE FILE GOES (2026-08-30). "Install this on the devices it is for" and "put it beside
      // the configuration" told a person nothing they could act on, and the place it actually had to go was a
      // folder Finder cannot write to — so every install began with a terminal. The installer now takes these
      // from the folder it is opened from, and the screen says so, because a download whose destination is
      // unstated is a download somebody has to be told about separately.
      el("p", { class: "ui-view-desc", text: bl({
        en: "Save it into the same folder as the installer on the device. The installer takes it from there.",
        ja: "端末側で、インストーラと同じフォルダに保存してください。インストーラがそこから取り込みます。" }) }),
      (function () {
        const pref = preferredRegionsOf(envelope);
        if (pref.length < 2) return el("span", {});
        return el("p", { class: "ui-view-desc", text: bl({
          en: "Devices taking this configuration prefer " + pref[0] + ", and use " + pref.slice(1).join(", ")
            + " when it cannot be reached. Latency decides only between regions of equal preference.",
          ja: "この設定を取る端末は " + pref[0] + " を優先し、そこへ届かないときに "
            + pref.slice(1).join("、") + " を使います。同じ優先度どうしのときだけ、速いほうが選ばれます。" }) });
      })(),
      dl,
      el("hr", {}),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Devices also need the key that proves this file came from here — into the same folder, beside it. "
          + "A device that has the configuration and not the key installs and stays inert, which is deliberate: "
          + "without it the file could name whatever key signed it.",
        ja: "この設定が「ここから来た」ことを示す鍵も要ります。同じフォルダに、並べて置いてください。"
          + "鍵の無い端末はインストールされても何もしません。これは意図的で、鍵が無ければ設定は"
          + "「自分に署名した鍵」を名乗れてしまうからです。" }) }),
      dlKey,
      el("hr", {}),
      el("p", { class: "ui-view-desc", text: bl({
        en: "The devices still have no certificate. This file says where and how to connect; it carries no "
          + "identity, because it is the same for every device in the group. Each machine needs one token, "
          + "used once, to get its own.",
        ja: "端末はまだ証明書を持っていません。この設定は「どこへ・どう繋ぐか」だけで、身元は運びません"
          + "（グループの全端末で同じものだからです）。1台ごとに一度きりのトークンが1枚要ります。" }) }),
      countF.el,
      makeTokens,
      el("hr", {}),
      el("p", { class: "ui-view-desc", text: bl({
        en: "Or take all four in one file. It carries ONE approval, for ONE machine: the person unarchives it "
          + "and opens the installer, which takes the rest from the folder beside it. Delete the folder once "
          + "the machine is up.",
        ja: "4つをまとめて1ファイルで受け取ることもできます。中の承認は1台ぶん1回きりです — 展開して"
          + "インストーラを開くだけで、残りは隣のファイルから取り込まれます。端末が立ち上がったら"
          + "フォルダごと削除してください。" }) }),
      platformF.el,
      bundle,
    ],
    footer: [el("button", { class: "ui-btn", text: bl({ en: "Done", ja: "完了" }), onClick: () => m.close() })],
  });

  dl.addEventListener("click", () => {
    downloadAgentProfile(envelope);
    dl.textContent = bl({ en: "Downloaded — download again", ja: "ダウンロード済み — 再ダウンロード" });
  });

  dlKey.addEventListener("click", () => {
    downloadProfileSigningKey(envelope);
    dlKey.textContent = bl({ en: "Downloaded — download again", ja: "ダウンロード済み — 再ダウンロード" });
  });

  // ★ AND THE LABEL MUST STOP TALKING ABOUT THE PREVIOUS CHOICE (2026-09-07). After a download the button
  // reads "Downloaded — one approval is now waiting for a device". It is pressable again — the handler
  // re-enables it — but the sentence is about the archive that was just taken, so an operator who then picks
  // a different machine reads a button that says the work is done and does not press it. It was read exactly
  // that way. Changing the machine changes what the button would produce, so it goes back to offering it.
  const bundleLabel = bundle.textContent;
  platformF.el.addEventListener("change", () => {
    bundle.textContent = bundleLabel;
    bundle.disabled = false;
  });

  bundle.addEventListener("click", () => {
    const [platform, arch] = String(platformF.get() || guessedPlatform).split("/");
    downloadDeviceBundle(envelope, group, platform, arch, bundle);
  });

  makeTokens.addEventListener("click", async () => {
    const count = Math.max(1, Number(countF.get()) || 1);
    makeTokens.disabled = true;
    try {
      // The SAME group the configuration was made for. A profile for one group and tokens for another is the
      // mismatch nobody notices until the devices are built.
      const r = await apiFetch("POST", "/admin/enrolment-tokens", {
        label: group ? group : bl({ en: "Device configuration", ja: "端末の設定" }),
        group, expires_in_hours: 168, count,
      }, _PROFILE_PLANE);
      makeTokens.disabled = false;
      if (!r.ok) {
        uiToast((r.body && (r.body.error || r.body.message)) || ("HTTP " + r.status), "err");
        return;
      }
      if (typeof showEnrolTokenOnce === "function") showEnrolTokenOnce(r.body);
    } catch (e) {
      makeTokens.disabled = false;
      uiToast(String(e), "err");
    }
  });
}
