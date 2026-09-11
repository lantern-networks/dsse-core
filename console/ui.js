"use strict";

// ---------------------------------------------------------------------------
// ui.js — the shared component primitives for the product-quality console.
// Vanilla, dependency-free; uses the globals from app.js (bl, escapeHtml). These
// replace the raw-JSON-card + window.alert/confirm paradigm with a consistent
// vocabulary: toasts, a real confirm/preview modal, typed form fields with
// validation, a data table, and first-class empty/loading/error states.
// See docs/console_ux_design_direction.md.
// ---------------------------------------------------------------------------

// el(tag, props, children) — terse DOM builder.
function el(tag, props, children) {
  const node = document.createElement(tag);
  if (props) {
    for (const k in props) {
      if (k === "class") node.className = props[k];
      else if (k === "html") node.innerHTML = props[k];
      else if (k === "text") node.textContent = props[k];
      else if (k.startsWith("on") && typeof props[k] === "function") node.addEventListener(k.slice(2).toLowerCase(), props[k]);
      else if (props[k] != null) node.setAttribute(k, props[k]);
    }
  }
  (Array.isArray(children) ? children : children != null ? [children] : []).forEach((c) => {
    if (c == null) return;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  });
  return node;
}

// uiToast(message, kind) — transient feedback. kind: "ok" | "err" | "info".
function uiToast(message, kind) {
  let host = document.querySelector(".ui-toasts");
  if (!host) { host = el("div", { class: "ui-toasts" }); document.body.appendChild(host); }
  const t = el("div", { class: "ui-toast ui-toast-" + (kind || "info"), text: message });
  host.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; setTimeout(() => t.remove(), 250); }, kind === "err" ? 6000 : 3200);
}

// uiConfirm({title, body, confirmLabel, cancelLabel, danger, preview}) -> Promise<bool>.
// A real modal (not window.confirm): proportional severity (danger), an optional preview/diff block, keyboard
// (Esc cancels, Enter confirms). Resolves true on confirm, false on cancel.
function uiConfirm(opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const close = (v) => { backdrop.remove(); document.removeEventListener("keydown", onKey); resolve(v); };
    const onKey = (e) => { if (e.key === "Escape") close(false); else if (e.key === "Enter") close(true); };
    const bodyEls = [];
    if (opts.body) bodyEls.push(el("div", { text: opts.body }));
    if (opts.preview) bodyEls.push(el("div", { class: "ui-preview", text: opts.preview }));
    const confirmBtn = el("button", {
      class: "ui-btn " + (opts.danger ? "ui-btn-danger" : "ui-btn-primary"),
      text: opts.confirmLabel || bl({ en: "Confirm", ja: "確認" }),
      onClick: () => close(true),
    });
    const backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) close(false); } }, [
      el("div", { class: "ui-modal", role: "dialog" }, [
        el("div", { class: "ui-modal-head", text: opts.title || bl({ en: "Are you sure?", ja: "よろしいですか?" }) }),
        el("div", { class: "ui-modal-body" }, bodyEls),
        el("div", { class: "ui-modal-foot" }, [
          el("button", { class: "ui-btn", text: opts.cancelLabel || bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => close(false) }),
          confirmBtn,
        ]),
      ]),
    ]);
    document.body.appendChild(backdrop);
    document.addEventListener("keydown", onKey);
    confirmBtn.focus();
  });
}

// uiPrompt(opts) — a single-line text input dialog. opts: {title, label, value, placeholder, confirmLabel}.
// Resolves the entered string on OK/Enter, or null on Cancel/Esc.
function uiPrompt(opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const close = (v) => { backdrop.remove(); document.removeEventListener("keydown", onKey); resolve(v); };
    const onKey = (e) => { if (e.key === "Escape") close(null); else if (e.key === "Enter") close(input.value); };
    const input = el("input", { class: "ui-input", type: "text", value: opts.value != null ? opts.value : "", placeholder: opts.placeholder || "" });
    const okBtn = el("button", { class: "ui-btn ui-btn-primary", text: opts.confirmLabel || bl({ en: "OK", ja: "OK" }), onClick: () => close(input.value) });
    const backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) close(null); } }, [
      el("div", { class: "ui-modal", role: "dialog" }, [
        el("div", { class: "ui-modal-head", text: opts.title || "" }),
        el("div", { class: "ui-modal-body" }, [opts.label ? el("div", { class: "ui-field-label", text: opts.label }) : null, input].filter(Boolean)),
        el("div", { class: "ui-modal-foot" }, [
          el("button", { class: "ui-btn", text: bl({ en: "Cancel", ja: "キャンセル" }), onClick: () => close(null) }),
          okBtn,
        ]),
      ]),
    ]);
    document.body.appendChild(backdrop);
    document.addEventListener("keydown", onKey);
    input.focus(); input.select();
  });
}

// uiState(container, kind, message, action) — render an empty/loading/error placeholder. kind:
// "loading" | "empty" | "error". action (optional) = {label, onClick} for a retry/CTA button.
function uiState(container, kind, message, action) {
  container.innerHTML = "";
  const inner = [];
  if (kind === "loading") inner.push(el("span", { class: "ui-spinner" }));
  inner.push(el("span", { text: message || (kind === "loading" ? bl({ en: "Loading…", ja: "読込中…" }) : kind === "empty" ? bl({ en: "Nothing here yet.", ja: "まだありません。" }) : bl({ en: "Something went wrong.", ja: "問題が発生しました。" })) }));
  const node = el("div", { class: "ui-state" + (kind === "error" ? " ui-state-error" : "") }, inner);
  if (action) node.appendChild(el("div", { class: "ui-state-actions" }, el("button", { class: "ui-btn", text: action.label, onClick: action.onClick })));
  container.appendChild(node);
}

// uiField(spec) — a typed, validated form field. spec:
//   { name, label, type: "text"|"textarea"|"select"|"checkbox", value, placeholder, hint, required,
//     options:[{value,label}], validate:(v)=>string|"" }
// Returns { el, get(), set(v), validate()->bool, focus(), setError(msg) }.
function uiField(spec) {
  spec = spec || {};
  const id = "f_" + spec.name + "_" + Math.floor(performance.now() * 1000);
  let input;
  if (spec.type === "textarea") {
    input = el("textarea", { class: "ui-textarea", id, placeholder: spec.placeholder || "" });
    input.value = spec.value || "";
  } else if (spec.type === "select") {
    input = el("select", { class: "ui-select", id }, (spec.options || []).map((o) => {
      const opt = el("option", { value: o.value, text: o.label });
      if (o.value === spec.value) opt.selected = true;
      return opt;
    }));
  } else if (spec.type === "checkbox") {
    input = el("input", { type: "checkbox", id });
    input.checked = !!spec.value;
  } else {
    input = el("input", { class: "ui-input", id, type: spec.type || "text", placeholder: spec.placeholder || "" });
    input.value = spec.value || "";
  }
  const errMsg = el("div", { class: "ui-field-error-msg" });
  const labelEls = [spec.label || spec.name];
  if (spec.required) labelEls.push(el("span", { class: "ui-field-req", text: "*" }));
  const wrap = el("div", { class: "ui-field" }, [
    el("label", { class: "ui-field-label", for: id }, labelEls),
    input,
    spec.hint ? el("span", { class: "ui-field-hint", text: spec.hint }) : null,
    errMsg,
  ]);
  const get = () => (spec.type === "checkbox" ? input.checked : input.value.trim());
  const setError = (msg) => { if (msg) { wrap.classList.add("ui-field-err"); errMsg.textContent = msg; } else { wrap.classList.remove("ui-field-err"); errMsg.textContent = ""; } };
  input.addEventListener("input", () => setError(""));
  const validate = () => {
    const v = get();
    if (spec.required && (v === "" || v === false)) { setError(bl({ en: "Required.", ja: "必須です。" })); return false; }
    if (spec.validate) { const m = spec.validate(v); if (m) { setError(m); return false; } }
    setError(""); return true;
  };
  return { el: wrap, get, set: (v) => { if (spec.type === "checkbox") input.checked = !!v; else input.value = v; }, validate, focus: () => input.focus(), setError };
}

// uiBadge(text, kind) -> span. kind: ok|off|warn|danger.
// ★★★ TWO ENDPOINTS SPELL A DEVICE'S NAME DIFFERENTLY, AND EVERY SCREEN THAT JOINED THEM LOST THE ROW
// (2026-09-05, measured on a live deployment against a Mac that was steering at that moment).
//
//   GET /admin/enrolled-devices        identity        "shinnomac-mini"
//   GET /admin/steer-exclusions/observed  device_identity "ShinnoMac-mini"
//
// The ledger normalizes what it stores; the device's own report carries the hostname as the machine spells it.
// The server joins them lowercased wherever it does this itself (steer_exclusion_observed.go,
// recovery_name_readiness.go, interception_authority_rotation_readiness.go). The Console did not, so
// `steer[d.identity]` was undefined for a device that had reported thirty seconds earlier — and the screen
// silently fell through to the "reports runtime but not steer-state" branch. It still said "Steering", which is
// why this survived: nothing looked broken. What was lost was everything the report carries — the posture, the
// active region, whether fail-open is engaged, the exclusion count, the pinned roots. A device in fail-open
// would have read as an ordinary steering device.
//
// So: one place that says what a device identity compares as, and every join goes through it.
function deviceKey(identity) { return String(identity == null ? "" : identity).trim().toLowerCase(); }

// byDeviceIdentity indexes a list of records that carry a device identity, keyed the way deviceKey compares.
function byDeviceIdentity(rows, field) {
  const out = {};
  (rows || []).forEach((r) => { const k = deviceKey(r && r[field || "device_identity"]); if (k) out[k] = r; });
  return out;
}

function uiBadge(text, kind) { return el("span", { class: "ui-badge ui-badge-" + (kind || "off"), text }); }

// uiModal({title, body, footer}) -> { el, close }. A bare modal shell for forms (the confirm/preview variant is
// uiConfirm). body/footer are arrays of nodes. Esc and backdrop-click close it.
function uiModal(opts) {
  opts = opts || {};
  let backdrop, closed = false;
  // opts.onClose (optional) fires ONCE when the modal is dismissed by ANY path (Cancel, Esc, backdrop, or a
  // programmatic close). Callers use it to tell "closed without completing" (e.g. undo a pre-created object).
  const close = () => { if (closed) return; closed = true; if (backdrop) backdrop.remove(); document.removeEventListener("keydown", onKey); if (opts.onClose) opts.onClose(); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  backdrop = el("div", { class: "ui-modal-backdrop", onClick: (e) => { if (e.target === backdrop) close(); } }, [
    el("div", { class: "ui-modal", role: "dialog" }, [
      el("div", { class: "ui-modal-head", text: opts.title || "" }),
      el("div", { class: "ui-modal-body" }, opts.body || []),
      el("div", { class: "ui-modal-foot" }, opts.footer || []),
    ]),
  ]);
  document.body.appendChild(backdrop);
  document.addEventListener("keydown", onKey);
  return { el: backdrop, close };
}

// uiTabs(defs, current, onPick) -> nav element. defs: [{id, label}]. A segmented tab bar in the shared style.
function uiTabs(defs, current, onPick) {
  const bar = el("div", { class: "ui-tabs" });
  defs.forEach((d) => {
    const b = el("button", { class: "ui-tab" + (d.id === current ? " active" : ""), text: d.label, onClick: () => onPick(d.id) });
    bar.appendChild(b);
  });
  return bar;
}

// uiPeriodSegment(current, onPick, periods) -> a 24h / 7d / 30d selector. Lifted out of the Overview view,
// which had it as an inline one-off; a second screen needed the same control, and two copies of a control is
// how two screens start disagreeing about what "7d" means.
function uiPeriodSegment(current, onPick, periods) {
  const seg = el("div", { style: "display:flex;border:1px solid var(--ui-line,#242a35);border-radius:8px;overflow:hidden" });
  (periods || ["24h", "7d", "30d"]).forEach((v) => seg.appendChild(el("button", {
    class: "ui-btn ui-btn-sm" + (current === v ? " ui-btn-primary" : ""), text: v,
    onClick: () => { if (current !== v) onPick(v); },
  })));
  return seg;
}

// uiCoverageNote(coverage) -> one line saying which range the numbers on screen actually cover, or null when
// there is nothing worth saying. A report can cover LESS than the period asked for: the read is row-capped, so
// a busy tenant's "30d" is silently the most recent slice of it. That used to be invisible — the period was a
// constant no screen printed — and a number whose range you cannot see is not a number you can act on.
function uiCoverageNote(coverage) {
  if (!coverage || !coverage.from || !coverage.to) return null;
  const span = uiDayRange(coverage.from, coverage.to);
  if (coverage.truncated) {
    // The limit decided the range. Lead with the range that is real, and say plainly why it is not the one asked for.
    return el("div", { class: "ui-view-desc" }, [
      el("strong", { text: span }),
      document.createTextNode(" · " + bl({ en: "limit reached — older activity is not included", ja: "上限に到達 — これより前の利用は含まれていません" })),
    ]);
  }
  if (coverage.retained_from) {
    // Nothing exists before this point. Stated as a fact, not as loss: a quiet period and rotated-away records
    // look the same from here, and only one of them is worth alarming an operator about.
    const begins = uiDayRange(coverage.retained_from, coverage.to).split(" – ")[0];
    return el("div", { class: "ui-view-desc", text: span + " · " + bl({ en: "records begin ", ja: "記録の開始 " }) + begins });
  }
  return el("div", { class: "ui-view-desc", text: span });
}

// uiDayRange formats two timestamps as a local-time span. Same-day collapses to one date plus times, because
// "Aug 7 – Aug 7" reads as a bug.
function uiDayRange(fromISO, toISO) {
  const a = new Date(fromISO), b = new Date(toISO);
  if (isNaN(a) || isNaN(b)) return "";
  const day = (d) => d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const time = (d) => d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return day(a) === day(b) ? day(a) + " " + time(a) + " – " + time(b) : day(a) + " – " + day(b);
}

// ── How certificate facts are shown, everywhere ──────────────────────────────────────────────────────
// These existed nowhere, so each screen printed the raw value it happened to hold: a distinguished name
// with its attribute keys, a 64-character fingerprint, and a date formatted for a locale the screen is not
// in. All three are correct data and none of them is a thing to put in front of an operator as-is.

// uiCertName is the human half of a subject. "CN=Lantern DSSE Transport,O=Lantern DSSE" is a structure, not
// a name; the name is what someone would say out loud.
function uiCertName(subject) {
  const s = String(subject || "").trim();
  if (!s) return "";
  const cn = s.match(/CN=([^,]+)/);
  return (cn ? cn[1] : s.replace(/^[A-Z]+=/, "")).trim();
}

// There is deliberately no helper here that reads an organization out of a subject. The certificates screen
// had one and labelled its output "Tenant"; whose material something is comes from the deployment's own
// attribution (tenant_display_name), because O= is a string whoever minted the certificate typed.

// uiFingerprint shows enough to compare two certificates by eye and keeps the rest for the clipboard. A
// 64-character hex string across a card is noise that hides everything beside it.
function uiFingerprint(hex) {
  const h = String(hex || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  if (!h) return null;
  const short = h.slice(0, 8) + "…" + h.slice(-4);
  const span = el("span", { style: "display:inline-flex; align-items:center; gap:6px" }, [
    el("code", { text: short, title: h }),
    el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Copy", ja: "コピー" }),
      onClick: () => { navigator.clipboard.writeText(h); uiToast(bl({ en: "Copied", ja: "コピーしました" }), "ok"); } }),
  ]);
  return span;
}

// uiWhen writes a moment the way the screen's language writes it. toLocaleString() with no locale follows
// the BROWSER, so a Japanese console on an English-locale machine printed 08/01/2026, 12:37:44 PM.
function uiWhen(value) {
  if (!value) return "";
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d.getTime())) return String(value);
  const p = (n) => String(n).padStart(2, "0");
  const ymd = d.getFullYear() + "/" + p(d.getMonth() + 1) + "/" + p(d.getDate());
  return ymd + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}

// uiListen turns a bind address into somewhere an operator can go. 0.0.0.0 is where a process listens, not
// where anything connects; on screen it is a number that answers no question.
function uiListen(addr) {
  const a = String(addr || "").trim();
  const m = a.match(/^(?:0\.0\.0\.0|\[::\]|::)?:(\d+)$/) || a.match(/^0\.0\.0\.0:(\d+)$/);
  if (m) return bl({ en: "port " + m[1], ja: "ポート " + m[1] });
  return a;
}
