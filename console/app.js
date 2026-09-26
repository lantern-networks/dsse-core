"use strict";

// ---------------------------------------------------------------------------
// Feature registry — every admin API endpoint the Edge exposes, grouped. Each
// endpoint: { m: method, p: path (with {param}), l: bilingual label, body: optional JSON template }.
// This is the "all features" surface: status (GET) + configuration change (POST/PUT/DELETE) for everything.
// ---------------------------------------------------------------------------
const GROUPS = [
  {
    id: "overview", custom: "overview", t: { en: "Overview", ja: "概要" },
    d: { en: "System health, your tenant, usage, and roles — at a glance.", ja: "システムの稼働状況・テナント・利用状況・ロールを一目で。" },
    eps: [
      { m: "GET", p: "/admin/state", l: { en: "Edge state", ja: "Edge 状態" } },
      { m: "GET", p: "/admin/tenant", l: { en: "Tenant", ja: "テナント" } },
      { m: "GET", p: "/admin/usage/summary", l: { en: "Usage summary", ja: "利用サマリ" } },
      { m: "GET", p: "/admin/rbac/catalog", l: { en: "RBAC role catalog", ja: "RBAC ロールカタログ" } },
    ],
  },
  {
    // Named for what the screen shows, not for who is looking at it: it sits under "Customers" beside the
    // registry, and "Operator > Operator" was a menu nobody designed.
    id: "operator-home", custom: "operatorhome", t: { en: "Overview", ja: "概要" },
    endpoints: [],
  },
  {
    id: "operators", custom: "operators", t: { en: "Operators", ja: "オペレータ" },
    endpoints: [],
  },
  {
    id: "tenants", custom: "organizations",
    t: { en: "Tenants", ja: "テナント" },
    d: { en: "Tenant profiles: update the authenticated tenant, and (super-admin, admin.tenant.admin) list / create / lifecycle / delete tenants across the fleet. Status active|suspended|archived is the tenant lifecycle.", ja: "テナントの情報。自テナントは誰でも更新でき、全テナントの一覧・作成・状態変更・削除は運営だけができます。状態は 有効／停止中／保管 の3つです。" },
    eps: [
      { m: "GET", p: "/admin/tenant", l: { en: "Get this tenant", ja: "自テナント取得" } },
      { m: "POST", p: "/admin/tenant", l: { en: "Update this tenant", ja: "自テナント更新" }, body: { display_name: "Lab Tenant (console)", home_region: "region-a", allowed_regions: ["region-a", "region-b"], status: "active" } },
      { m: "GET", p: "/admin/tenants", l: { en: "List all tenants (super-admin)", ja: "全テナントの一覧(運営のみ)" } },
      { m: "POST", p: "/admin/tenants", l: { en: "Create / upsert tenant (super-admin)", ja: "テナントの作成・更新(運営のみ)" }, body: { tenant_id: "tenant_acme_001", display_name: "Acme Corp", status: "suspended", plan: "enterprise", home_region: "region-a", allowed_regions: ["region-a", "region-b"] } },
      { m: "DELETE", p: "/admin/tenants/{tenant_id}", l: { en: "Delete tenant (super-admin)", ja: "テナントの削除(運営のみ)" } },
    ],
  },
  {
    id: "administrators", custom: "administrators",
    t: { en: "Administrators", ja: "管理者" },
    d: { en: "The administrators of this tenant — invite, suspend, change roles, or remove them (scoped to your tenant).", ja: "このテナントの管理者 — 招待・停止・ロール変更・削除(自テナントに限定)。" },
    eps: [
      { m: "GET", p: "/admin/admins", l: { en: "List administrators", ja: "管理者一覧" } },
      { m: "POST", p: "/admin/admins/invite", l: { en: "Invite an admin", ja: "管理者を招待" }, body: { email: "admin@example.com", roles: ["tenant_admin"] } },
    ],
  },
  {
    id: "eastwest-rules", custom: "eastwest",
    t: { en: "Connector Access", ja: "コネクタ経由アクセス" },
    d: { en: "Rules for a device reaching internal resources through a connector — who can reach what, internally (client → server / outbound). Server→client inbound is on the Incoming Connections page.", ja: "デバイスが コネクタ経由で内部リソースへ到達する通信ルール — 誰が社内の何に到達できるか(端末から社内へ)。社内から端末へ入ってくる通信は「受信接続」のページです。" },
    eps: [],
  },
  {
    id: "egress-rules", custom: "egress",
    t: { en: "Internet Access", ja: "インターネットアクセス" },
    d: { en: "Rules for what your users and devices can reach on the internet.", ja: "ユーザーとデバイスがインターネット上で到達できる先のルール。" },
    eps: [],
  },
  {
    id: "effective-policy", custom: "effective",
    t: { en: "Policy decision check", ja: "ポリシー判定確認" },
    d: { en: "See exactly how a destination is decided, and which rule wins.", ja: "ある宛先がどう判定されるか・どのルールが効くかを確認。" },
    eps: [],
  },
  {
    id: "inspection-posture", custom: "posture",
    t: { en: "Inspection Settings", ja: "傍受の設定" },
    d: { en: "Choose what traffic is inspected (decrypted) and what is bypassed.", ja: "どの通信を傍受(復号)し、どれをバイパスするかを設定。" },
    eps: [],
  },
  {
    id: "dlp-findings", custom: "dlpfindings",
    t: { en: "DLP Findings", ja: "DLP 検出" },
    d: { en: "What data-loss prevention has detected in inspected uploads — identifier type, count, and action, never the raw value.", ja: "傍受したアップロードで DLP が検出した内容 — 識別子の種類・件数・アクション(生の値は非表示)。" },
    eps: [],
  },
  {
    id: "sensitive-data", custom: "sensitivedata",
    t: { en: "Sensitive Data", ja: "機密データ" },
    d: { en: "The DLP library — built-in and custom identifiers, exact-data-match datasets, and the allowlist. Referenced by DLP policies.", ja: "DLP ライブラリ — 組み込み/カスタム識別子、完全一致データ、許可リスト。DLP ポリシーから参照されます。" },
    eps: [],
  },
  {
    id: "dlp-policies", custom: "dlppolicies",
    t: { en: "DLP Policies", ja: "DLP ポリシー" },
    d: { en: "Reusable DLP policies (what to detect + action + account) that Internet Access rules select.", ja: "再利用可能な DLP ポリシー(検出対象+アクション+アカウント)。「インターネットアクセス」のルールから選択します。" },
    eps: [],
  },
  {
    id: "assets", custom: "assets",
    t: { en: "Groups & Services", ja: "グループ・サービス" },
    d: { en: "Name the devices, groups, and services your rules refer to.", ja: "ルールが参照するデバイス・グループ・サービスに名前を付ける。" },
    eps: [],
  },
  {
    id: "internal-cas", custom: "internalcas",
    t: { en: "Internal site certificates", ja: "社内サイトの証明書" },
    d: { en: "Register the authority that issued your internal sites' certificates, so devices can open them.", ja: "社内サイトの証明書を発行した証明機関を登録すると、そのサイトが開けるようになります。" },
    eps: [],
  },
  {
    id: "pinned-sites", custom: "pinned",
    t: { en: "Sites to Bypass", ja: "バイパスするサイト" },
    d: { en: "Some sites break when inspected (certificate pinning). Review and approve which to bypass.", ja: "傍受すると壊れるサイトの候補。バイパスする対象を承認します。" },
    eps: [],
  },
  {
    id: "predefined-catalog", custom: "catalog",
    t: { en: "Built-in Bypass List", ja: "組込バイパスリスト" },
    d: { en: "The built-in list of well-known sites bypassed by default; override per tenant.", ja: "組込の既定バイパスリスト。テナントごとに上書きできます。" },
    eps: [],
  },
  {
    id: "idp", custom: "idp",
    t: { en: "IdP integration", ja: "IdP 連携" },
    d: { en: "Trusted sign-in providers for your users.", ja: "ユーザーのサインインに使う信頼済みプロバイダ。" },
    eps: [],
  },
  {
    id: "grants", custom: "grants",
    t: { en: "Access Approvals", ja: "アクセス承認" },
    d: { en: "Temporary access approvals — review and revoke.", ja: "一時的なアクセス承認 — 一覧と取り消し。" },
    eps: [],
  },
  {
    id: "swg", custom: "swg", t: { en: "SaaS Tenant Restriction", ja: "SaaS テナント制限" },
    d: { en: "Restrict SaaS sign-in (Google Workspace / Microsoft 365) to your company's own tenant — block personal and other-company accounts.", ja: "SaaS サインイン(Google Workspace / Microsoft 365)を会社のテナント(テナント)のみに制限 — 個人アカウントや他社アカウントを遮断。" },
    eps: [
      { m: "GET", p: "/admin/swg/tenant-restriction", l: { en: "Get tenant-restriction", ja: "テナント制限を取得" } },
      { m: "POST", p: "/admin/swg/tenant-restriction", l: { en: "Update tenant-restriction (enable + header values)", ja: "テナント制限を更新 (有効化 + ヘッダ値)" }, body: { saas_enablement: { "saas_google_workspace": true }, header_value_updates: { "operator_config_ref:google_workspace_allowed_domains": "example.com" } } },
      { m: "GET", p: "/admin/swg/tenant-restriction/versions", l: { en: "History (versions)", ja: "履歴 (版)" } },
      { m: "POST", p: "/admin/swg/tenant-restriction/rollback", l: { en: "Roll back to a version", ja: "版にロールバック" }, body: { version_no: 1 } },
    ],
  },
  {
    id: "dns", custom: "dnsfilter", t: { en: "DNS Filtering", ja: "DNS フィルタ" },
    d: { en: "Block or redirect name lookups; applied immediately.", ja: "名前解決のブロック/リダイレクト。即時反映。" },
    eps: [
      { m: "GET", p: "/admin/dns-policy", l: { en: "Get DNS policy", ja: "DNS ポリシー取得" } },
      { m: "PUT", p: "/admin/dns-policy", l: { en: "Apply DNS policy", ja: "DNS ポリシー適用" }, body: { deny: ["evil.example"], sinkhole: { "ads.example": "100.64.0.250" }, stub_ipv4: {}, ech_strip: true } },
    ],
  },
  {
    id: "serverinit", custom: "incoming", t: { en: "Incoming Connections (server-initiated)", ja: "受信接続(サーバ発)" },
    d: { en: "Block SERVER-INITIATED connections into a device — the reverse of normal client-initiated traffic — with reviewed exceptions. Enforced at the device firewall.", ja: "サーバが起点でデバイスに張ってくる接続(通常のクライアント発とは逆向き)を遮断。レビュー済み例外あり・端末ファイアウォールで強制。" },
    eps: [
      { m: "POST", p: "/admin/server-initiated", l: { en: "Toggle enforcement", ja: "強制の切替" }, body: { enabled: true } },
      { m: "GET", p: "/admin/legacy-exceptions", l: { en: "List exceptions", ja: "例外一覧" } },
      { m: "POST", p: "/admin/legacy-exceptions", l: { en: "Add exception", ja: "例外追加" }, body: { id: "ex-1", source_server: "10.0.0.10", device_group: "workstations", service_family: "smb", business_owner: "secops", expires_at: "2026-12-31T00:00:00Z", mode: "allow" } },
      { m: "GET", p: "/admin/legacy-exceptions/export", l: { en: "Export firewall rules", ja: "ファイアウォール規則の書き出し" } },
    ],
  },
  {
    id: "vlan", custom: "networkzones", t: { en: "Networks", ja: "ネットワーク" },
    d: { en: "Define a network once; sites and everything else select it.", ja: "ネットワークを一度定義。サイト等はここから選択。" },
    eps: [
      { m: "GET", p: "/admin/vlan-objects", l: { en: "List objects", ja: "オブジェクト一覧" } },
      { m: "POST", p: "/admin/vlan-objects", l: { en: "Add object", ja: "オブジェクト追加" }, body: { id: "vlan-10", name: "workstations", class: "managed_endpoint", cidrs: ["10.10.0.0/24"] } },
      { m: "GET", p: "/admin/vlan-boundary-policies", l: { en: "List policies", ja: "ポリシー一覧" } },
      { m: "POST", p: "/admin/vlan-boundary-policies", l: { en: "Add policy", ja: "ポリシー追加" }, body: { id: "bp-1", source_class: "managed_endpoint", dest_class: "server", action: "deny" } },
      { m: "GET", p: "/admin/vlan-boundary-policies/export", l: { en: "Export firewall rules", ja: "ファイアウォール規則の書き出し" } },
    ],
  },
  {
    id: "apps", custom: "applications", t: { en: "Applications", ja: "アプリケーション" },
    d: { en: "Your internal apps and SaaS apps.", ja: "社内アプリと SaaS アプリ。" },
    eps: [
      { m: "GET", p: "/admin/applications", l: { en: "List applications", ja: "アプリ一覧" } },
      { m: "GET", p: "/admin/applications/{application_id}", l: { en: "Get application", ja: "アプリ取得" } },
      { m: "POST", p: "/admin/applications", l: { en: "Upsert application", ja: "アプリ登録/更新" }, body: { application_id: "wiki", name: "Wiki", application_type: "private_app", status: "active", application_sensitivity: "normal" } },
    ],
  },
  {
    id: "enrolled", custom: "devices",
    t: { en: "Devices", ja: "デバイス" },
    d: { en: "Devices allowed to connect through the secure gateway.", ja: "セキュアゲートウェイ経由の接続を許可するデバイス。" },
    eps: [],
  },
  {
    // ★ THE ORGANIZATION'S OWN VIEW OF THE OPERATOR. The envelope shipped with no customer-facing screen at
    // all: the API let a customer read it and turn it off, and the only places it could be set were the
    // operator's checklist and the creation wizard. A control the controlled party cannot reach is not one.
    plane: "control",
    id: "operator-access", custom: "operatorAccess",
    t: { en: "Operator access", ja: "運営のアクセス" },
    d: { en: "What the company running this service may do inside your tenant, and every time they used it.", ja: "このサービスを運用する会社が、あなたのテナントの中で何をできるか。使われた記録も。" },
    eps: [],
  },
  {
    plane: "control",
    id: "tenant-settings", custom: "tenantSettings",
    t: { en: "Tenant settings", ja: "テナント設定" },
    d: { en: "This tenant's name, and the timezone its operators read times in.", ja: "このテナントの名称と、運用者が時刻を読むタイムゾーン。" },
    eps: [
      { m: "GET", p: "/admin/tenant", l: { en: "Read this tenant", ja: "自テナントを取得" } },
      { m: "POST", p: "/admin/tenant", l: { en: "Update this tenant", ja: "自テナントを更新" }, body: { timezone: "Asia/Tokyo" } },
    ],
  },
  {
    id: "licensing", custom: "licensing",
    t: { en: "Licensing & Seats", ja: "ライセンスとシート数" },
    d: { en: "Seats you hold, how they are divided among tenants, and who cannot enrol.", ja: "保有シート数・テナントごとの配分・登録できないテナント。" },
    eps: [],
  },
  {
    // ★ RESTORED (2026-08-13). This entry was deleted as collateral by 6a24785b, whose subject was removing the
    // operations assistant — and "sites" was left in NAV_SECTIONS, so the nav has pointed at a page that does
    // not exist since 2026-08-05. Worse, the Connectors page had been folded INTO Sites a month earlier
    // (d0ad48ca), so deleting this took the only route to a connector with it: an operator looking for their
    // connector found neither page, and nothing anywhere said why.
    id: "sites", custom: "sites", t: { en: "Sites", ja: "サイト" },
    d: { en: "Sites (connector groups) that front your private networks, rolled up from their connectors. A site's detail is where its connectors are.", ja: "プライベートネットワークの入口となるサイト(コネクタグループ)。配下のコネクタから集約。サイトの詳細からコネクタを開けます。" },
    eps: [
      { m: "GET", p: "/admin/sites", l: { en: "List sites", ja: "サイト一覧" } },
      { m: "GET", p: "/admin/sites/{site_id}", l: { en: "Get site", ja: "サイト取得" } },
    ],
  },
  {
    id: "agents", custom: "agentReleases",
    t: { en: "Agent Releases", ja: "エージェント配布" },
    d: { en: "Which version each kind of device is offered, and how to change it.", ja: "端末の種類ごとに配布中のバージョンと、その変更。" },
    eps: [],
  },
  {
    id: "enrolment-tokens", custom: "enrolmentTokens",
    t: { en: "Enrolment Tokens", ja: "登録トークン" },
    d: { en: "Approve a device before it is set up. One token, one machine, once.", ja: "セットアップ前に端末を承認します。1枚のトークンで1台だけ、一度だけ。" },
    eps: [],
  },
  {
    id: "agent-profile", custom: "agentProfile",
    t: { en: "Device configuration", ja: "端末の設定" },
    d: { en: "The settings a device needs to reach this deployment. Made here and signed by it.", ja: "端末がこの配備に繋ぐための設定です。ここで作り、配備が署名します。" },
    eps: [],
  },
  {
    id: "certs", custom: "certs", t: { en: "Certificates", ja: "証明書" },
    d: { en: "Rotate a service server certificate with no restart (hot-reload). Validated before it is applied; a bad cert/key is rejected and the previous one keeps serving.", ja: "サービスのサーバ証明書を、停止せずに入れ替えます。適用前に検証し、壊れた証明書や鍵は拒否します(その場合は前の証明書のままです)。" },
    eps: [
      { m: "GET", p: "/admin/certs", l: { en: "List certificates", ja: "証明書一覧" } },
      { m: "PUT", p: "/admin/certs/{name}", l: { en: "Rotate certificate", ja: "証明書をローテーション" }, ex: { name: "edge" }, body: { cert_pem: "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n", key_pem: "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n" } },
      { m: "GET", p: "/admin/certs/{name}/versions", l: { en: "History (versions, key redacted)", ja: "履歴 (版・鍵は秘匿)" }, ex: { name: "edge" } },
      { m: "POST", p: "/admin/certs/{name}/rollback", l: { en: "Roll back to a version", ja: "版にロールバック" }, ex: { name: "edge" }, body: { version_no: 1 } },
    ],
  },
  { plane: "control",
    id: "steerexcl", custom: "steerexcl", t: { en: "Steering Exclusions", ja: "ステアリング除外" },
    d: { en: "Apps excluded from steering to the secure gateway, set per tenant, group, or device. Centrally enforced — users cannot change it.", ja: "セキュアゲートウェイへのステアリングから除外するアプリをテナント/グループ/デバイス単位で設定。中央で強制されユーザーは変更不可。" },
  },
  { plane: "control",
    id: "identities", custom: "people", t: { en: "People & Service Accounts", ja: "ユーザー・サービスアカウント" },
    d: { en: "People, service accounts and their access, and tool activity.", ja: "ユーザー・サービスアカウントとそのアクセス、ツール利用状況。" },
    eps: [
      { m: "GET", p: "/admin/human-identities", l: { en: "List human identities", ja: "人間 identity 一覧" } },
      { m: "POST", p: "/admin/human-identities", l: { en: "Upsert human identity", ja: "人間 identity 登録/更新" }, body: { id: "u1", subject: "u1", email: "u1@example.com", source: "manual", status: "active" } },
      { m: "GET", p: "/admin/human-identities/sources", l: { en: "Identity sources", ja: "identity ソース" } },
      { m: "GET", p: "/admin/non-human-identities", l: { en: "List NHIs", ja: "NHI 一覧" } },
      { m: "POST", p: "/admin/non-human-identities", l: { en: "Upsert NHI", ja: "NHI 登録/更新" }, body: { id: "nhi-1", name: "ci-bot", nhi_type: "service_account", owner_user_id: "u1", status: "active" } },
      { m: "GET", p: "/admin/non-human-identities/risk", l: { en: "NHI risk", ja: "NHI リスク" } },
      { m: "GET", p: "/admin/delegated-grants", l: { en: "List delegated grants", ja: "委譲された許可の一覧" } },
      { m: "POST", p: "/admin/delegated-grants", l: { en: "Create delegated grant", ja: "委譲された許可の作成" }, body: { id: "grant-1", actor_nhi_id: "nhi-1", subject_user_id: "u1", allowed_tool_ids: [], status: "active" } },
      { m: "POST", p: "/admin/delegated-grants/{grant_id}/revoke", l: { en: "Revoke grant", ja: "委譲された許可の失効" } },
      { m: "GET", p: "/admin/agent-tools", l: { en: "List agent tools", ja: "agent tools 一覧" } },
      { m: "GET", p: "/admin/tool-call-events", l: { en: "Tool-call events", ja: "ツール呼び出しの記録" } },
      { m: "GET", p: "/admin/human-approval-events", l: { en: "Approval events", ja: "承認イベント" } },
    ],
  },
  { plane: "control",
    id: "aiusage", custom: "aiserviceusage", t: { en: "AI service usage", ja: "AI サービス利用" },
    d: { en: "Which AI services your users reached through the SSE, and how they were governed.", ja: "利用者が SSE 経由で到達した AI サービスと、そのガバナンス状況。" },
    eps: [
      { m: "GET", p: "/admin/ai-usage-report", l: { en: "AI usage report", ja: "AI 利用レポート" } },
    ],
  },
  { plane: "control",
    id: "audit", custom: "logsaudit", t: { en: "Logs & Audit", ja: "ログ・監査" },
    d: { en: "Activity logs, access decisions, delivery health, and exports.", ja: "アクティビティログ・アクセス判断・配信の健全性・エクスポート。" },
    eps: [
      { m: "GET", p: "/admin/logs/{stream}", l: { en: "Read log stream (audit, access, decision_trace, …)", ja: "ログの読み取り(管理監査・アクセス・判定の記録 など)" }, ex: { stream: "audit" } },
      { m: "GET", p: "/admin/access-decisions/{decision_id}", l: { en: "Get access decision", ja: "アクセス判断取得" } },
      { m: "GET", p: "/admin/audit-outbox/health", l: { en: "Audit outbox health", ja: "監査の送信待ちキューの状態" } },
      { m: "GET", p: "/admin/audit-outbox/dead", l: { en: "Audit outbox dead-letters", ja: "監査の送信待ちキュー(配送不能)" } },
      { m: "GET", p: "/admin/domain-event-outbox/health", l: { en: "Domain-event outbox health", ja: "ドメインイベントの送信待ちキューの状態" } },
      { m: "GET", p: "/admin/export-jobs", l: { en: "Export jobs", ja: "書き出しジョブ" } },
      { m: "POST", p: "/admin/export-jobs", l: { en: "Create export job", ja: "書き出しジョブの作成" }, body: { stream: "audit", format: "ndjson", from: "2026-01-01T00:00:00Z", to: "2027-01-01T00:00:00Z" } },
    ],
  },
  { plane: "control",
    id: "tokens", custom: "apitokens", t: { en: "API Tokens & Roles", ja: "API トークン・ロール" },
    d: { en: "Create and revoke API tokens, scoped to roles.", ja: "ロール単位の API トークンの作成・取り消し。" },
    eps: [
      { m: "GET", p: "/admin/api-tokens", l: { en: "List API tokens", ja: "API トークン一覧" } },
      { m: "POST", p: "/admin/api-tokens", l: { en: "Create API token", ja: "API トークン作成" }, body: { name: "console", role: "admin" } },
      { m: "POST", p: "/admin/api-tokens/{token_id}/rotate", l: { en: "Rotate token", ja: "トークンをローテ" } },
      { m: "POST", p: "/admin/api-tokens/{token_id}/revoke", l: { en: "Revoke token", ja: "トークンを失効" } },
    ],
  },
];

// ---------------------------------------------------------------------------
// State + i18n
// ---------------------------------------------------------------------------
let lang = localStorage.getItem("lang") || "en";
function t(key) { return (window.I18N[lang] && window.I18N[lang][key]) || (window.I18N.en[key]) || key; }
function bl(obj) { return (obj && (obj[lang] || obj.en)) || ""; }

function applyI18n() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.getAttribute("data-i18n")); });
  document.getElementById("lang-en").classList.toggle("active", lang === "en");
  document.getElementById("lang-ja").classList.toggle("active", lang === "ja");
  buildNav();
  warnIfViewsMissing();
  const active = document.querySelector(".nav button.active");
  // ★ AN OPERATOR LANDS ON THEIR OWN SCREEN. The customer Overview shows them a deployment full of things
  // they cannot touch — super_admin holds none of the customer-side write permissions — and hides the three
  // they actually work on. Only for the operator's own organization; a customer administrator is unaffected.
  // ★ AND ONLY WHILE THEY ARE OUTSIDE ONE (2026-08-17). "Am I an operator" is not "am I inside an
  // organization", and this line asked the first while meaning the second — so pressing Manage on a customer
  // entered that customer, switched the nav to their screens, and then rendered the OPERATOR'S landing page
  // inside them. The banner said "operating in tenant_acme"; the page showed the list of all organizations,
  // with its licence panel printing a bare "HTTP 403" where a number belongs, because that read is refused
  // inside a customer. The screen also has no nav entry there, so nothing was highlighted to click away from.
  const requested = consumeGroupAfterEnter();
  const landing = requested || ((signedInAsOperator() && !operateTenant) ? "operator-home" : GROUPS[0].id);
  renderGroup(active && !requested ? active.dataset.group : landing);
}

function setLang(l) { lang = l; localStorage.setItem("lang", l); applyI18n(); refreshModeBanner(); }

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------
// baseForPlane routes a call to the Edge (live config/enforcement) or the control plane (audit/reporting).
// Same-origin by default: with no explicit override, edge calls are RELATIVE ("") and control-plane calls go
// to the "/control" prefix — both reverse-proxied by the console front door. Absolute overrides (lab /
// cross-origin) are still honored when set.
// CP_AUTHORED_WRITES — the resources this deployment's Edge REFUSES to author because it pulls its config
// from a control plane (cmd/edge configWriteRejectedWhenSourced). A write to the Edge for any of these returns
// 409 with a message written for a developer, which is what an operator saw when deleting a device and again
// when changing a device's risk.
//
// This list exists so no CALL SITE has to remember. The first fix routed the device writes one by one, and the
// very next thing the operator touched — risk — was still broken, because the audit that produced that list was
// itself incomplete. A rule that every caller must remember is a rule that will be forgotten; routing decided in
// ONE place cannot be.
//
// Generated from the Edge source. REGENERATE WITH THE GATE ITSELF:
//   sh ops/checks/cp_authored_routes_in_sync.sh    (it prints exactly which routes differ, both ways)
//
// ★ The command that used to sit here was not the one the gate runs: it ignored the
// "cp-authored-conditional:" marker, so following it added a route the gate then rejected. A regeneration
// recipe that disagrees with the check it is meant to satisfy is worse than none — 2026-08-22, found while
// three transport-rename routes were missing from this table and one entry named a path that does not exist
// ("retire-previous", where the route is "retire-previous-name"). Writes for all three went to the Edge and
// came back 409, in the GUI, silently.
const CP_AUTHORED_WRITES = [
	"POST /admin/applications",
	"POST /admin/applications/{application_id}/publish",
	"POST /admin/applications/{application_id}/unpublish",
	"DELETE /admin/applications/{application_id}",
  "POST /admin/swg/tenant-restriction",
  "DELETE /admin/assets/endpoints/{id}",
  "DELETE /admin/assets/groups/{id}",
  "DELETE /admin/assets/services/{id}",
  "DELETE /admin/connectors/{connector_id}",
  "DELETE /admin/internal-cas/{id}",
  "DELETE /admin/device-groups/{id}",
  "DELETE /admin/dlp-fingerprints",
  "DELETE /admin/dlp-policies",
  "DELETE /admin/enrolled-devices/{identity}",
  "DELETE /admin/idp-connections/{id}",
  "DELETE /admin/legacy-exceptions/{id}",
  "DELETE /admin/operator-elevations/{id}",
  "DELETE /admin/policies/{policy_id}",
  "DELETE /admin/rules/{id}",
  "DELETE /admin/sites/{site_id}",
  "DELETE /admin/steer-exclusions/{id}",
  "DELETE /admin/tenant-cas/{tenant_id}",
  "DELETE /admin/tenant-cas/{tenant_id}/{sha256}",
  "DELETE /admin/tenants/{tenant_id}",
  "DELETE /admin/transport-trust-anchors/{sha256}",
  "DELETE /admin/transport-trust-anchors/{sha256}/acknowledge/{identity}",
  "DELETE /admin/vlan-objects/{object_id}",
  "PATCH /admin/device-groups/{id}",
  "POST /admin/internal-cas",
  "POST /admin/transport-trust-anchors",
  "POST /admin/transport-trust-anchors/{sha256}/acknowledge",
  "POST /admin/api-tokens",
  "POST /admin/api-tokens/{token_id}/revoke",
  "POST /admin/api-tokens/{token_id}/rotate",
  "POST /admin/assets/endpoints",
  "POST /admin/assets/groups",
  "POST /admin/assets/services",
  "POST /admin/cert-pin-bypass",
  "POST /admin/connectors/{connector_id}/name",
  "POST /admin/connectors/{connector_id}/routes",
  "POST /admin/delegated-grants",
  "POST /admin/delegated-grants/{grant_id}/revoke",
  "POST /admin/device-groups",
  "POST /admin/dlp-allowlist",
  "POST /admin/dlp-classifiers",
  "POST /admin/dlp-fingerprints",
  "POST /admin/dlp-policies",
  "POST /admin/dlp-rules",
  "POST /admin/east-west",
  "POST /admin/east-west/rollback",
  "POST /admin/east-west/observations/adopt",
  "POST /admin/connector-discovery/refresh",
  "POST /admin/policy-candidates",
  "POST /admin/policy-candidates/{candidate_id}/review",
  "POST /admin/policy-candidates/{candidate_id}/materialize",
  "POST /admin/policy-candidates/{candidate_id}/approve-private-app",
  "POST /admin/cert-pin-bypass",
  "POST /admin/enrolled-devices",
  "POST /admin/enrolled-devices/{identity}/allow-reenrolment",
  "POST /admin/enrolled-devices/{identity}/disable",
  "POST /admin/enrolled-devices/{identity}/enable",
  "POST /admin/enrolled-devices/{identity}/group",
  "POST /admin/enrolled-devices/{identity}/kind",
  "POST /admin/human-identities",
  "POST /admin/human-identities/import",
  "POST /admin/human-identities/sources/policies",
  "POST /admin/idp-connections",
  "POST /admin/idp-connections/{id}/default",
  "POST /admin/inspection-posture",
  "POST /admin/legacy-exceptions",
  "POST /admin/non-human-identities",
  "POST /admin/operator-elevations",
  "POST /admin/operator-elevations/{id}/approve",
  "POST /admin/policies",
  "POST /admin/policies/{policy_id}/status",
  "POST /admin/risk-signals",
  "POST /admin/rules",
  "POST /admin/server-initiated",
  "POST /admin/sites",
  "POST /admin/sites/{site_id}/enrollment-command",
  "POST /admin/sites/{site_id}/networks",
  "POST /admin/steer-exclusions",
  "POST /admin/steer-exclusions/{id}/rollback",
  "POST /admin/tenant",
  "POST /admin/tenant-cas",
  "POST /admin/tenant-device-authority",
  "POST /admin/tenant-device-authority/abandon-rotation",
  "POST /admin/tenant-device-authority/retire-previous",
  "POST /admin/tenant-device-authority/rotate",
  "POST /admin/tenant-transport-authority/abandon-rename",
  "POST /admin/tenant-transport-authority/abandon-rotation",
  "POST /admin/tenant-transport-authority/rename",
  "POST /admin/tenant-transport-authority/retire-previous",
  "POST /admin/tenant-transport-authority/retire-previous-name",
  "POST /admin/tenant-transport-authority/rotate",
  "POST /admin/tenants",
  "POST /admin/transport-admission/restore",
  "POST /admin/transport-admission/revoke",
  "POST /admin/vlan-boundary-policies",
  "POST /admin/vlan-objects",
  "PUT /admin/dns-policy",
  "PUT /admin/operator-delegation",
];

// cpAuthoritative reports whether this request belongs to the control plane. Path params are matched
// as one segment; a query string is ignored (DELETE /admin/dlp-policies?id=... is the same resource).
// CP_AUTHORED_READS — resources whose AUTHORITY is the control plane, so the READ must go there too.
//
// ★ WHY A SECOND LIST (2026-08-15). CP_AUTHORED_WRITES exists because the Edge REFUSES those writes; that is
// a property of the guard, and reads were correctly left alone. The tenant registry is a different thing: the
// Edge accepts the read and answers from its own copy, which arrives by config bundle and is therefore
// whatever this Edge last pulled. So creating an organization wrote to the control plane while the list read
// an Edge, and deleting one removed it from the control plane while the list kept showing it — the screen
// said "deleted", a reload said otherwise, and both were telling the truth about different planes.
//
// Measured on the lab: the two planes answered with different tenant counts, and one of them had been carrying
// a tenant created in June that the control plane has never heard of.
//
// Only entries whose authority genuinely IS the control plane belong here. A read that merely happens to
// work on both planes must stay on the Edge, which is the node that enforces and therefore the node whose
// answer is about what is actually happening.
//
// ★★★ THE LIST WAS TWO ENTRIES LONG BECAUSE NOTHING COULD TELL (2026-09-05). Both of this Console's upstreams
// pointed at the control plane, so every read on the "Edge" plane was already answered by the authority and a
// missing entry here cost nothing and showed nothing. With the planes actually separated (see
// consoleEdgeUpstreamFor in cmd/dsse-install) each of these was measured against BOTH doors of one running
// deployment, and each is a resource the Edge answers with its own emptiness:
//
//	/admin/enrolment-tokens   the Edge refuses outright — "this Edge does not hold this deployment's
//	                          enrolment tokens … Ask the control plane: it is what the Admin Console talks to"
//	/admin/usage/summary      control plane: human_seat quantity 2. Edge: no meters at all. The licence is
//	                          counted for the deployment, not for whichever node the browser reached.
//	/admin/usage/health       control plane: mode postgres. Edge: mode memory. Both say "ok" about different
//	                          stores, which is the worse kind of agreement.
//	/admin/export-jobs        written by the control plane's export worker.
//	/admin/api-tokens         control plane: the tokens. Edge: none.
//	/admin/audit-chain/verify the Edge answers 503; the chain is the authority's.
//	/admin/fleet/config-status the Edge answers 404; only the authority knows the fleet.
//	/admin/sites              measured 2026-09-06 by creating a site and reading both planes in the same
//	                          second: control ["osaka-branch","plane-probe"], edge ["osaka-branch"]. Sites are
//	                          AUTHORED on the control plane (the write is in the table below) and an Edge holds
//	                          a copy it refreshes on its next fetch, so the screen said "Site created." and
//	                          went on saying "No sites yet. Create a site, then install a connector into it."
//	                          — which reads as a failure, and the next thing an operator does is create it again.
//	/admin/connectors         measured 2026-09-07 on a three-region lab with twenty connectors, every one of
//	                          them holding a live tunnel: the control plane's registry had 21 rows heartbeated
//	                          within the last 60 seconds; EVERY Edge had none. A connector heartbeats to the
//	                          door it is attached to, that Edge updates its own copy and carries the liveness
//	                          up (connector_reported_to_control_plane, ~35/min in the measurement), and no
//	                          Edge ever learns about a beat it did not personally receive. So the authority is
//	                          the only node that knows the whole fleet is alive, and every other one answers
//	                          "last seen when it registered here".
//
//	                          What that cost is on one screen, in one function, in the same second:
//
//	                              const [rs, rc] = await Promise.all([
//	                                apiFetch("GET", "/admin/sites"),      // control plane — fresh
//	                                apiFetch("GET", "/admin/connectors"), // an Edge — its own beats only
//	                              ]);
//
//	                          sites.js then counts "N / M connectors online" from the SECOND list, so a site
//	                          whose row came back healthy from the authority was drawn "0 / 2 connectors
//	                          online" with an Offline badge beside each connector — for the whole fleet, in
//	                          every organization whose connectors happen to attach elsewhere. An operator
//	                          reading that concludes their site is unreachable while traffic is flowing
//	                          through it, and the deployment cannot tell them apart from one that has gone.
//	/admin/enrolled-devices   measured 2026-09-07 across ALL TWENTY organizations of one deployment: the Edge
//	                          answered one FEWER enrolled device than the control plane in every single one,
//	                          and 0 against the authority's 3 in one of them. Admission is decided at the
//	                          control plane — it holds the claim, and the installer gives it
//	                          -enrolled-inventory-store=postgres — so what an Edge holds is the copy it has
//	                          pulled so far. The Devices screen and the Overview device tile were reporting a
//	                          deployment's newest enrolments as absent, in every organization at once, to an
//	                          operator whose reason for opening the screen is usually to see whether a machine
//	                          they just installed has arrived.
//	/admin/device-runtime     and its PRESENCE, from the same place, because the two are read together and a
//	                          ledger without presence is worse than neither. Measured in the same minute, for
//	                          an organization whose device is in another region:
//
//	                              control  skusanagi-win10-renge  steer_active=true  edge=tokyo-west/…
//	                              edge     (nothing)
//
//	                          The control plane answers fleet-wide and names the region, because a steering
//	                          device re-ships its state once a minute and device_runtime_projection.go folds
//	                          those into a fleet view. An Edge answers about the devices that report to IT.
//	                          deviceStateOf has had the branch for this since 2026-08-14 — "Steering · via
//	                          <edge>", written so that a failed-over device reads as a fact and not an
//	                          incident — and it has never had the data to reach it from a Console attached to
//	                          another node.
//
//	★ These two were briefly added and taken out again on the same evening, on the reasoning that presence is
//	  per-Edge and does not travel, so an authoritative ledger would put a device that is steering elsewhere on
//	  the screen and assert it was offline. That reasoning was wrong, and it was wrong because it was never
//	  measured: /admin/device-runtime returns a MAP, the sweep that "showed" it empty was reading .length on an
//	  object, and the mechanism that carries presence to the authority had been working the whole time.
//
// The last three already passed plane:"control" at their call sites and keep working either way. They are
// listed anyway, because a rule that lives at the call site is the rule this table exists to replace.
const CP_AUTHORED_READS = [
  "GET /admin/swg/tenant-restriction",
  // Reports use retained logs from the whole deployment, including other regions.
  "GET /admin/ai-usage-report",
  // DLP objects are authored on the control plane. Edges enforce the compiled rules;
  // their local object stores cannot populate the policy editor or its detector library.
  "GET /admin/dlp-policies",
  "GET /admin/dlp-classifiers",
  "GET /admin/dlp-fingerprints",
  "GET /admin/tenants",
  "GET /admin/tenant",
  "GET /admin/enrolment-tokens",
  "GET /admin/usage/summary",
  "GET /admin/usage/health",
  "GET /admin/export-jobs",
  "GET /admin/api-tokens",
  "GET /admin/audit-chain/verify",
  "GET /admin/fleet/config-status",
  "GET /admin/sites",
  "GET /admin/connectors",
  "GET /admin/enrolled-devices",
  "GET /admin/device-runtime",
  "GET /admin/policy-candidates",
  "GET /admin/east-west/observations",
];

function cpAuthoredRead(method, path) {
  if (method !== "GET") return false;
  const clean = String(path).split("?")[0];
  if (/^\/admin\/policy-candidates\/[^/]+$/.test(clean)) return true;
  return CP_AUTHORED_READS.some((entry) => entry.slice(entry.indexOf(" ") + 1) === clean);
}

// cpAuthoritative answers the one question every call site used to have to remember: does this belong to the
// control plane? Named for what it decides, not for the half of it that came first.
function cpAuthoritative(method, path) {
  if (method === "GET") return cpAuthoredRead(method, path);
  const clean = String(path).split("?")[0];
  return CP_AUTHORED_WRITES.some((entry) => {
    const sp = entry.indexOf(" ");
    if (entry.slice(0, sp) !== method) return false;
    const want = entry.slice(sp + 1).split("/");
    const got = clean.split("/");
    if (want.length !== got.length) return false;
    return want.every((seg, i) => (seg.startsWith("{") && seg.endsWith("}")) ? got[i] !== "" : seg === got[i]);
  });
}

function baseForPlane(plane) {
  // Same-origin only: edge calls are relative (""), control-plane calls use the "/control" prefix — both
  // reverse-proxied by the console front door. Stale absolute overrides are ignored (purged on boot).
  return plane === "control" ? "/control" : "";
}

// idpSession holds the signed-in operator (from GET /admin/session) when authenticated via the per-tenant
// IdP. When present, calls rely on the session cookie (credentials) + CSRF — not the break-glass bearer.
let idpSession = null;

// operateTenant: a cross-tenant operator (super_admin/owner) can "operate within" a chosen tenant; its id is
// sent as X-Operate-Tenant on every admin call. The backend honors it ONLY for admin.tenant.admin holders
// (others are scoped to self, fail-closed). Persisted so a reload keeps the context; cleared by "Exit tenant".
//
// ★ PER TAB, NOT PER BROWSER (2026-08-16, found by opening two tabs). It lived in localStorage, which every
// tab shares. Measured: entering an organization in one tab did NOT change what another tab SENT — each tab
// keeps its own copy in memory, so no write leaked — but the other tab's next reload silently adopted the
// choice, landing an operator inside a customer they had not opened. Two tabs on two organizations is an
// ordinary way to work, so the context belongs to the tab. sessionStorage survives reloads within a tab, which
// is the only thing entering an organization needs, and does not cross to another.
const tenantStore = (function () {
  try { return window.sessionStorage; } catch (e) { return null; }
})();
// operatingOrganizationName is the display name of the organization being operated in, as the reader knows it.
// The id is what the machinery uses; the name is what a sentence uses.
let operatingOrganizationName = "";
let operateTenant = (function () {
  try {
    // A value left by the previous (browser-wide) behaviour is dropped rather than inherited: a stale
    // organization silently restored on the next load is the defect this change exists to remove.
    if (localStorage.getItem("operateTenant")) localStorage.removeItem("operateTenant");
    return (tenantStore && tenantStore.getItem("operateTenant")) || null;
  } catch (e) { return null; }
})();

// tenantOverride names the organization for ONE call, without touching the console's current selection.
//
// ★ A GLOBAL MUTATED BY AN ASYNC LOOP IS HOW THE CONSOLE ENDED UP IN AN ORGANIZATION NOBODY CHOSE
// (2026-08-16). The organizations list fills its Setup column one row at a time, and did it by assigning the
// selection and restoring it in a finally. Anything that captured the selection WHILE that loop was running
// captured a row's organization as "the previous value" and later restored it — leaving the console
// operating within an organization the operator never picked, banner and all. Measured: after a wizard run
// the console was operating within a tenant that had just been deleted.
//
// Reads that are ABOUT an organization now say so per call. The selection is reserved for the one case that
// really is a mode: an operator entering an organization to work in it.
async function apiFetch(method, path, body, plane, signal, tenantOverride, retriedAfterElevation, retriedOnControl) {
  // A caller that did not say which plane gets the right one: anything the CONTROL PLANE is authoritative for
  // — the writes it refuses on the Edge, and the reads whose answer must come from the authority — goes to the
  // control plane; everything else keeps the Edge, which is the node that enforces. An explicit plane always
  // wins, so a deliberate choice is never overridden.
  if (plane === undefined && cpAuthoritative(method, path)) plane = "control";
  const base = baseForPlane(plane); // "" => same-origin relative (front-door proxied) — a valid base
  const token = localStorage.getItem("adminToken") || "";
  const headers = { accept: "application/json" };
  const signedIn = idpSession && idpSession.auth_method === "admin_session";
  // Prefer the IdP session: send the cookie (credentials) + CSRF; only fall back to the bearer when not signed in.
  if (!signedIn && token) headers["authorization"] = "Bearer " + token;
  if (signedIn && method !== "GET" && idpSession.csrf_token) headers["x-csrf-token"] = idpSession.csrf_token;
  const actingTenant = tenantOverride || operateTenant;
  if (actingTenant) headers["x-operate-tenant"] = actingTenant;
  const opts = { method, headers, credentials: "include" };
  if (signal) opts.signal = signal;
  if (body !== undefined && body !== null && method !== "GET") {
    headers["content-type"] = "application/json";
    opts.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  const res = await fetch(base + path, opts);
  const text = await res.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch (e) { parsed = text; }
  const answer = { status: res.status, ok: res.ok, body: parsed };

  // ★★ THE SCREEN USED TO PRINT A curl COMMAND (2026-08-21, read while finishing a certificate rotation).
  // Some acts inside a customer's organization need time the operator has been granted, and when none was
  // running the toast said: "Grant one with POST /admin/operator-elevations (X-Operate-Tenant: …)". An API
  // call, shown on a page, as the way to proceed — the same defect the rotation control itself was built to
  // fix one layer up. So the refusal is offered here, once, for every act that can hit it: a caller that
  // forgets is a rule that will be forgotten.
  //
  // ★ ASKED, NEVER AUTOMATIC. Nothing is granted without the operator saying so and saying why: the
  // organization sees every one of these, and one taken silently on their behalf would be exactly what the
  // envelope exists to prevent.
  // The retry happens exactly once: a second refusal after time was granted is a real refusal, and asking
  // again would be a loop that keeps opening elevations the organization then has to read.
  if (res.status === 403 && parsed && parsed.elevation_required && !retriedAfterElevation) {
    const granted = await offerOperatorElevation(parsed.elevation_required, plane);
    if (granted) return apiFetch(method, path, body, plane, signal, tenantOverride, true, retriedOnControl);
  }

  // ★★★ AND A NODE THAT SAYS "ASK THE AUTHORITY" IS ASKED (2026-09-06, found by pressing "Download everything
  // for one device" on a three-region deployment: the button minted nothing and said "Preparing…" forever).
  //
  // The tables below decide the plane BEFORE the call, and they are lists. A list is complete on the day it is
  // written. This one was not even then: the routes it is generated from are the ones the Edge refuses because
  // it PULLS ITS CONFIG from an authority, and there is a second reason a node refuses — it does not hold the
  // store at all. Enrolment tokens are refused that way, and so are an organization's three PKI authorities:
  //
  //	POST /admin/enrolment-tokens              409 "this Edge does not hold this deployment's enrolment tokens"
  //	POST /admin/tenant-interception-authority 501 "…-tenant-interception-authority-store is not set"
  //
  // Both were reachable from a screen, both went to the Edge, and both failed in front of an operator who had
  // done nothing wrong. Generating a second list would have the same shape as the first: a route added on the
  // Edge one day, and a screen that breaks until somebody notices. So the refusal itself is used. A 409 or 501
  // that NAMES the control plane is a node saying the answer is not its to give, and it is given before the act
  // — nothing has happened yet, which is why asking again is safe. Once, and never from the control plane
  // itself: a second refusal there is a real one.
  if ((res.status === 409 || res.status === 501) && plane !== "control" && !retriedOnControl &&
      /control plane/i.test(String((parsed && (parsed.error || parsed.message)) || ""))) {
    return apiFetch(method, path, body, "control", signal, tenantOverride, retriedAfterElevation, true);
  }
  return answer;
}

// offerOperatorElevation asks the operator whether to take the time this act needs, and takes it if they say
// so. Returns true when the act may now be retried.
async function offerOperatorElevation(need, plane) {
  const org = operatingOrganizationName || (need && need.tenant_id) || "";
  // ★★★ IT USED TO ASK FOR A REASON AND SAY "THIS ORGANIZATION SEES IT" (2026-08-22, measured — the Edge was
  // logging the field being dropped on every grant).
  //
  //	WARNING: POST /admin/operator-elevations — the request body carried a field this route does not read,
  //	and it was DROPPED: json: unknown field "reason". The call will answer as if it had been applied.
  //
  // The route is right and the screen was wrong. The design decided against a reason field deliberately, and there
  // is a test that fails if one appears: a free-text reason nobody verifies is bookkeeping that LOOKS like
  // accountability. So the operator typed a sentence, the screen promised the customer would read it, and
  // nothing kept it.
  //
  // What the organization actually sees is better and is all true: who took the time, when, over which
  // organization, and that it ended. This asks for the same deliberate act — nothing here is ever automatic —
  // and states only that.
  const ok = await uiConfirm({
    title: bl({ en: "This needs time granted inside " + org, ja: org + " の中で作業する時間が要ります" }),
    body: bl({
      en: "What it is for: " + (need.why || "") + ". " + org + " sees that you took it, when, and that it ended. It ends by the clock; nothing renews it.",
      ja: "対象: " + (need.why || "") + "。" + org + " からは、誰がいつ取得し、いつ終わったかが見えます。時間が来れば自動で終わり、更新もされません。" }),
    confirmLabel: bl({ en: "Ask for 20 minutes", ja: "20分もらう" }),
  });
  if (!ok) return false;
  const r = await apiFetch("POST", "/admin/operator-elevations", { minutes: 20 }, plane);
  if (!r.ok) {
    uiToast(bl({ en: "Not granted", ja: "受け取れません" }) + ": " + ((r.body && r.body.error) || ("HTTP " + r.status)), "err");
    return false;
  }
  const until = r.body && r.body.elevation && r.body.elevation.expires_at;
  uiToast(bl({
    en: "You have time inside " + org + (until ? " until " + new Date(until).toLocaleTimeString() : "") + ".",
    ja: org + " の中で作業できます" + (until ? "（" + new Date(until).toLocaleTimeString() + "まで）" : "") + "。" }), "ok");
  return true;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
// NAV_SECTIONS groups the features into a small, human information architecture (plain section names; the
// per-feature order within a section is intentional). Every group id appears exactly once; any id not listed
// falls into "More" so nothing is ever hidden by accident.
const NAV_SECTIONS = [
  { t: { en: "Overview", ja: "概要" }, ids: ["overview"] },
  { t: { en: "Policies", ja: "ポリシー" }, ids: ["eastwest-rules", "egress-rules", "effective-policy", "serverinit"] },
  { t: { en: "Web & Traffic", ja: "Web・通信" }, ids: ["inspection-posture", "swg", "aiusage", "pinned-sites", "predefined-catalog", "dns"] },
  { t: { en: "Devices & Identities", ja: "デバイス・ユーザー" }, ids: ["enrolled", "identities", "idp", "grants", "steerexcl"] },
  { t: { en: "Network & Apps", ja: "ネットワーク・アプリ" }, ids: ["assets", "apps", "vlan", "sites", "internal-cas"] },
  { t: { en: "DLP", ja: "DLP" }, ids: ["dlp-findings", "sensitive-data", "dlp-policies"] },
  { t: { en: "Operations", ja: "運用" }, ids: ["agents", "audit"] },
  // Certificates get a section of their own, in the order an operator moves through them: is the deployment
  // set up, what is each component serving, what do endpoints trust, what do devices verify, what does the
  // fleet hold, and how does a new device get a certificate at all. Scattered across Administration and the
  // catch-all "More", these read as six unrelated pages; together they are one subject, and the questions they
  // answer only make sense in relation to each other — which one is trusted and which one signs is exactly the
  // distinction people get wrong.
  { t: { en: "Certificates & PKI", ja: "証明書・PKI" },
    ids: ["certs", "enrolment-tokens", "agent-profile"] },
  // ★ THE OPERATOR'S OWN SECTION. An operator's screens are not a subset of a customer's — super_admin holds
  // none of the customer-side write permissions — so they get their own place rather than being scattered
  // through screens built for somebody else's job.
  { t: { en: "Operator", ja: "運営" }, ids: ["operator-home", "operators"] },
  { t: { en: "Administration", ja: "管理" }, ids: ["tenants", "administrators", "operator-access", "tokens", "tenant-settings", "licensing"] },
];

// The operator's information architecture. Same groups, their order, their sections — see buildNav for why a
// filtered copy of the customer's nav was the wrong shape. "operator-home" leads because it is where an
// operator lands, and it is not repeated under a section of its own name.
const OPERATOR_NAV_SECTIONS = [
  { t: { en: "Tenants", ja: "テナント" }, ids: ["operator-home", "tenants"] },
  { t: { en: "Your people", ja: "自社の担当者" }, ids: ["operators"] },
  { t: { en: "What you distribute", ja: "配布するもの" }, ids: ["agents", "certs"] },
  // ★★★ THE OPERATOR'S OWN DEVICES (2026-08-25, found by walking a freshly installed deployment). A
  // deployment that has just been installed has exactly ONE organization — the operator's — and every device
  // it enrols belongs to it. The bootstrap administrator holds admin.enrollment.write and
  // admin.steering.write, and the server would have accepted both acts; the nav simply had no way to them, so
  // the Console of a new deployment could neither approve a device nor produce the settings file it needs.
  // The devices were being enrolled with curl, which is not a product.
  //
  // Not a subset of the customer nav — this is the operator acting INSIDE THEIR OWN organization, which is the
  // ordinary case for a self-run deployment and stays correct for an MSSP whose own machines are also managed.
  // ★★★ AND THE OPERATOR'S OWN ORGANIZATION IS A REAL ORGANIZATION (2026-08-25, found while trying to author
  // one egress rule on a freshly installed deployment). The operator's navigation deliberately excludes the
  // customer screens — an MSSP operator enters an organization to change its rules, and the banner says so
  // while they are in it. That reasoning is sound and it left one case with no way through at all: a
  // deployment that has JUST been installed has exactly one organization, the operator's, and there is nothing
  // to enter. Devices enrol into it, policy is enforced for it, and the Console offered no route to any of
  // that — while the same account holds admin.policy.write and admin.applications.write and the server
  // accepts both. A default-deny deployment whose first rule cannot be written is not a deployment.
  //
  // Named for whose they are, so it never reads as somebody else's screens. An MSSP operator whose own
  // organization holds nothing sees empty screens, which is honest; the alternative was an act that could not
  // be performed and no way to find that out.
  { t: { en: "Your own organization", ja: "自社の組織" },
    // Not "overview": the operator already lands on their own home, and two screens both called Overview is
    // the kind of duplication that makes a person doubt which one they are reading.
    ids: ["enrolled", "enrolment-tokens", "agent-profile", "egress-rules", "eastwest-rules",
      "effective-policy", "apps", "sites", "assets", "identities", "idp", "grants", "steerexcl",
      "inspection-posture", "dns"] },
  { t: { en: "Commercial", ja: "契約・課金" }, ids: ["licensing"] },
  { t: { en: "Record", ja: "記録" }, ids: ["audit"] },
];

// navGroupVisible hides cross-tenant surfaces (the Organizations registry) from non-super-admins; the real
// authorization remains server-side. Keeps the nav honest for a tenant-admin.
// Feature entitlements (the license gate). Default all-on until GET /admin/entitlements resolves; paid-feature
// surfaces (DLP) are hidden when the tenant is not licensed. Shared across scripts via window.
window.dsseEntitlements = window.dsseEntitlements || { dlp: true };

// The TENANT's clock, from GET /admin/session. Times are rendered and day boundaries computed in this zone —
// not the browser's.
//
// The browser's zone is the OPERATOR's location, which for an MSSP is routinely not the tenant's region. An
// engineer in Tokyo reviewing a German tenant's logs would otherwise see every timestamp shifted, and "today"
// would cover the wrong day for the customer whose incident it is. The API keeps returning UTC; this converts
// at the point of display only, so exports and comparisons stay in one zone.
window.dsseTenantTimezone = window.dsseTenantTimezone || "UTC";

// dsseFormatTime renders an instant in the tenant's zone, with the zone shown so nobody has to guess which
// clock they are reading — the whole failure mode here is a plausible-looking time that means something else.
window.dsseFormatTime = function (value, options) {
  if (!value) return "—";
  const at = new Date(value);
  if (isNaN(at.getTime())) return String(value);
  const opts = Object.assign({
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    timeZone: window.dsseTenantTimezone, timeZoneName: "short",
  }, options || {});
  try {
    return at.toLocaleString(undefined, opts);
  } catch (e) {
    // An unknown zone must not blank the column: showing UTC is worse than nothing only if it pretends to be
    // local, so it is labelled.
    return at.toISOString().replace("T", " ").replace(".000Z", "") + " UTC";
  }
};

// dsseTenantDayRange returns [start, end) of a day in the TENANT's zone, as UTC instants for the API.
// Offset arithmetic would be wrong across a daylight-saving transition; letting the zone do it is why the
// tenant setting stores an IANA name rather than an offset.
window.dsseTenantDayRange = function (daysAgo) {
  const zone = window.dsseTenantTimezone || "UTC";
  const now = new Date();
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: zone, year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(new Date(now.getTime() - (daysAgo || 0) * 86400000));
  const get = (type) => (parts.find((p) => p.type === type) || {}).value;
  const dayStart = `${get("year")}-${get("month")}-${get("day")}T00:00:00`;
  // Resolve that wall-clock time in the tenant's zone back to an instant.
  const guess = new Date(dayStart + "Z");
  const shown = new Date(guess.toLocaleString("en-US", { timeZone: zone }));
  const local = new Date(guess.toLocaleString("en-US", { timeZone: "UTC" }));
  const start = new Date(guess.getTime() + (local.getTime() - shown.getTime()));
  return { from: start.toISOString(), to: new Date(start.getTime() + 86400000).toISOString() };
};
const DLP_NAV_IDS = ["dlp-findings", "sensitive-data", "dlp-policies"];

// signedInAsOperator: the principal belongs to the OPERATOR's own organization. Distinct from holding
// admin.tenant.admin — a customer's administrator can be given cross-tenant powers on a single-tenant
// deployment, and an operator is defined by which organization they are in, not by what they can reach.
function signedInAsOperator() {
  return !!(idpSession && idpSession.is_operator_tenant);
}

// OPERATOR_GROUPS are the only screens an operator has any use for. Everything else in this Console is built
// for administering ONE organization, and an operator holds none of the customer-side write permissions —
// so those screens would show them a deployment full of controls that answer 403.
//
// ★★ DERIVED FROM THE SECTIONS, NOT LISTED AGAIN (2026-08-25). These were two hand-kept lists that had to
// agree, and when they disagreed the failure was silent: a section naming an id this list omitted rendered
// NOTHING — no heading, no entry, no error — so a screen added to the operator's navigation was simply absent,
// and the deployment read as though the screen had never been built. Derivation makes disagreement impossible.
const OPERATOR_GROUPS = OPERATOR_NAV_SECTIONS.reduce((all, s) => all.concat(s.ids), []);

function navGroupVisible(id) {
  // ★ AN OPERATOR'S NAV IS NOT A CUSTOMER'S WITH TWO ITEMS ADDED. Signed in as an operator, the first build
  // of this showed the whole customer navigation — policies, DLP, devices — none of which they can change.
  // They enter an organization to do that, and the banner says so while they are in it.
  //
  // ★★ AND WHILE THEY ARE IN ONE, THEY MUST SEE IT (2026-08-16, found by pressing a button that said it would
  // open a customer's rules). This returned the operator's seven screens whether or not an organization had
  // been entered, so "entering" was a data context with no navigation behind it: five of the twelve destination
  // buttons on the setup checklist pointed at screens the nav would not show — rules, administrators, joining
  // tokens, sign-in, settings. Measured: pressing "Open rules" entered Northwind and landed on the operator
  // home, and there was NO route in the console to that organization's rules at all. The permissions were
  // never the problem — with delegation standing, the same session reads /admin/rules for that organization
  // with a 200. Only the nav was missing, so an operator whose whole job is running delegated organizations
  // could not reach most of what they run.
  if (signedInAsOperator() && !operateTenant) return OPERATOR_GROUPS.indexOf(id) >= 0;
  if (id === "operator-home" || id === "operators") return false;
  // The organization registry is a deployment-level screen. Inside a customer it is not what this console is
  // about, and the way back out is the banner's "Exit tenant" — not a menu entry that quietly changes subject.
  if (id === "tenants") return answeringForTheDeployment();
  // Paid-feature gate: hide the DLP surfaces when the tenant is not licensed for DLP.
  if (!window.dsseEntitlements.dlp && DLP_NAV_IDS.indexOf(id) >= 0) return false;
  return true;
}

// A console missing most of its views is not a console with a broken page — it is a session that lapsed
// while the shell stayed up. Say it once, at the top, instead of letting the operator discover it screen by
// screen (and conclude the product regressed).
function warnIfViewsMissing() {
  const missing = Object.values(CUSTOM_VIEWS).filter((fn) => typeof window[fn] !== "function");
  const existing = document.getElementById("views-missing-banner");
  if (existing) existing.remove();
  // ★★ IT USED TO STAY SILENT FOR ONE OR TWO (2026-08-13). The threshold was three, on the reasoning that a
  // couple of missing views means a stale cache rather than a broken session — but the failure an operator
  // actually hit was ONE screen disappearing, and it disappeared for eight days precisely because nothing said
  // anything. One is the number. A banner that waits for a third is the same silence with a counter.
  if (missing.length === 0) return;
  const banner = el("div", { id: "views-missing-banner", class: "ui-state ui-state-error",
    style: "margin:12px 16px" }, [
    el("span", { text: bl({
      // Two causes, and the count tells them apart: a handful means the session or the cache, ONE means that
      // screen's script did not load or was removed. Saying only the first sent an operator to sign in again
      // about a page that no longer existed.
      en: missing.length + " of " + Object.keys(CUSTOM_VIEWS).length + " screens did not load" +
          (missing.length === 1 ? " (" + missing[0] + "). Reload; if it persists, that screen is missing from this build."
                                : " — your session has probably expired. Reload and sign in again."),
      ja: Object.keys(CUSTOM_VIEWS).length + " 画面中 " + missing.length + " 個が読み込まれていません" +
          (missing.length === 1 ? "(" + missing[0] + ")。再読込しても直らない場合、その画面はこのビルドに含まれていません。"
                                : "。セッションが切れている可能性が高いです。再読込してサインインし直してください。"),
    }) }),
    el("div", { class: "ui-state-actions" },
      el("button", { class: "ui-btn", text: bl({ en: "Reload", ja: "再読込" }),
        onClick: () => location.reload() })),
  ]);
  const content = document.getElementById("content");
  if (content && content.parentNode) content.parentNode.insertBefore(banner, content);
}

function buildNav() {
  const nav = document.getElementById("nav");
  nav.innerHTML = "";
  const placed = new Set();
  const addButton = (g) => {
    const btn = document.createElement("button");
    btn.textContent = bl(g.t);
    btn.dataset.group = g.id;
    btn.onclick = () => renderGroup(g.id);
    nav.appendChild(btn);
    placed.add(g.id);
  };
  // ★ AN OPERATOR'S NAV IS NOT THE CUSTOMER'S NAV WITH ROWS REMOVED (2026-08-17). Seven of the customer's
  // groups survive the operator filter, and they were left sitting in the customer's order, scattered across
  // four of the customer's sections — so the operator's LANDING screen ("Operator") appeared third, inside a
  // section also called "Operator", and the organization registry — the thing an operator actually works on —
  // was last, under "Administration". A menu whose section and only item share a name is a menu nobody
  // designed; this is the operator's own order, in the order they work: who they run, then who runs it, then
  // what they hand out, then what everyone is trusting, then the money, then the record.
  const sections = (signedInAsOperator() && !operateTenant) ? OPERATOR_NAV_SECTIONS : NAV_SECTIONS;
  sections.forEach((sec) => {
    const groups = sec.ids.map((id) => GROUPS.find((g) => g.id === id)).filter(Boolean).filter((g) => navGroupVisible(g.id));
    if (!groups.length) return;
    const h = document.createElement("div");
    h.className = "nav-section";
    h.textContent = bl(sec.t);
    nav.appendChild(h);
    groups.forEach(addButton);
  });
  const leftover = GROUPS.filter((g) => !placed.has(g.id) && navGroupVisible(g.id));
  if (leftover.length) {
    const h = document.createElement("div");
    h.className = "nav-section";
    h.textContent = bl({ en: "More", ja: "その他" });
    nav.appendChild(h);
    leftover.forEach(addButton);
  }
}

function pathParams(p) { return (p.match(/\{([^}]+)\}/g) || []).map((x) => x.slice(1, -1)); }

// Every curated view and the function that draws it. Kept as DATA so a missing one can be detected
// rather than silently skipped: each of these used to be guarded by `typeof X === "function"`, which turns
// a script that failed to load into the generic endpoint cards — the console quietly becomes the API
// explorer it replaced, and looks like a product that regressed by a month. Session expiry does exactly
// that, because every view script 302s to the login page.
const CUSTOM_VIEWS = {
  overview: "renderOverviewView",
  agentReleases: "renderAgentReleasesView",
  swg: "renderTenantRestrictionView",
  assets: "renderAssetsView",
  eastwest: "renderEastWestView",
  egress: "renderEgressView",
  effective: "renderEffectivePolicyView",
  dlpfindings: "renderDLPFindingsView",
  sensitivedata: "renderSensitiveDataView",
  dlppolicies: "renderDLPPoliciesView",
  posture: "renderInspectionPostureView",
  idp: "renderIdPConnectionsView",
  grants: "renderGrantsView",
  catalog: "renderPredefinedCatalogView",
  devices: "renderDevicesView",
  applications: "renderApplicationsView",
  sites: "renderSitesView",
  steerexcl: "renderSteerExclusionsView",
  dnsfilter: "renderDnsView",
  organizations: "renderOrganizationsView",
  operators: "renderOperatorsView",
  operatorhome: "renderOperatorHomeView",
  operatorAccess: "renderOperatorAccessView",
  administrators: "renderAdministratorsView",
  apitokens: "renderApiTokensView",
  licensing: "renderLicensingView",
  certs: "renderCertsView",
  internalcas: "renderInternalCAsView",
  networkzones: "renderNetworkZonesView",
  incoming: "renderIncomingView",
  people: "renderPeopleView",
  aiserviceusage: "renderAiServiceUsageView",
  logsaudit: "renderLogsAuditView",
  pinned: "renderPinnedSitesView",
};

function renderGroup(groupId) {
  const group = GROUPS.find((g) => g.id === groupId) || GROUPS[0];
  document.querySelectorAll(".nav button").forEach((b) => b.classList.toggle("active", b.dataset.group === group.id));
  const content = document.getElementById("content");
  content.innerHTML = "";

  // A curated view whose script did not load must SAY SO. Falling through to the generic endpoint cards
  // renders a plausible, wrong product — the API explorer this console replaced — and an operator reads
  // that as a regression, not as a failure. The common cause is an expired session: every view script
  // 302s to the login page, so all 33 of them vanish at once and the whole console appears to roll back.
  if (group.custom && CUSTOM_VIEWS[group.custom] && typeof window[CUSTOM_VIEWS[group.custom]] !== "function") {
    uiState(content, "error", bl({
      en: "This screen could not be loaded. Your session may have expired — reload, and sign in again if asked.",
      ja: "この画面を読み込めませんでした。セッションが切れている可能性があります。再読込し、求められたらサインインし直してください。",
    }), { label: bl({ en: "Reload", ja: "再読込" }), onClick: () => location.reload() });
    return;
  }

  // Custom (curated) views render their own surface instead of the generic endpoint cards.
  if (group.custom === "overview" && typeof renderOverviewView === "function") {
    renderOverviewView(content);
    return;
  }
  if (group.custom === "swg" && typeof renderTenantRestrictionView === "function") {
    renderTenantRestrictionView(content);
    return;
  }
  if (group.custom === "assets" && typeof renderAssetsView === "function") {
    renderAssetsView(content);
    return;
  }
  if (group.custom === "eastwest" && typeof renderEastWestView === "function") {
    renderEastWestView(content);
    return;
  }
  if (group.custom === "egress" && typeof renderEgressView === "function") {
    renderEgressView(content);
    return;
  }
  if (group.custom === "effective" && typeof renderEffectivePolicyView === "function") {
    renderEffectivePolicyView(content);
    return;
  }
  if (group.custom === "dlpfindings" && typeof renderDLPFindingsView === "function") {
    renderDLPFindingsView(content); return;
  }
  if (group.custom === "sensitivedata" && typeof renderSensitiveDataView === "function") {
    renderSensitiveDataView(content); return;
  }
  if (group.custom === "dlppolicies" && typeof renderDLPPoliciesView === "function") {
    renderDLPPoliciesView(content); return;
  }
  if (group.custom === "posture" && typeof renderInspectionPostureView === "function") {
    renderInspectionPostureView(content);
    return;
  }
  if (group.custom === "idp" && typeof renderIdPConnectionsView === "function") {
    renderIdPConnectionsView(content);
    return;
  }
  if (group.custom === "grants" && typeof renderGrantsView === "function") {
    renderGrantsView(content);
    return;
  }
  if (group.custom === "catalog" && typeof renderPredefinedCatalogView === "function") {
    renderPredefinedCatalogView(content);
    return;
  }
  if (group.custom === "devices" && typeof renderDevicesView === "function") {
    renderDevicesView(content);
    return;
  }
  if (group.custom === "applications" && typeof renderApplicationsView === "function") {
    renderApplicationsView(content);
    return;
  }
  if (group.custom === "sites" && typeof renderSitesView === "function") {
    renderSitesView(content);
    return;
  }
  if (group.custom === "steerexcl" && typeof renderSteerExclusionsView === "function") {
    renderSteerExclusionsView(content);
    return;
  }
  if (group.custom === "dnsfilter" && typeof renderDnsView === "function") {
    renderDnsView(content);
    return;
  }
  if (group.custom === "organizations" && typeof renderOrganizationsView === "function") {
    renderOrganizationsView(content);
    return;
  }
  if (group.custom === "operatorhome" && typeof renderOperatorHomeView === "function") {
    renderOperatorHomeView(content);
    return;
  }
  if (group.custom === "operatorAccess" && typeof renderOperatorAccessView === "function") {
    renderOperatorAccessView(content);
    return;
  }
  if (group.custom === "operators" && typeof renderOperatorsView === "function") {
    renderOperatorsView(content);
    return;
  }
  if (group.custom === "administrators" && typeof renderAdministratorsView === "function") {
    renderAdministratorsView(content);
    return;
  }
  if (group.custom === "apitokens" && typeof renderApiTokensView === "function") {
    renderApiTokensView(content);
    return;
  }
  if (group.custom === "tenantSettings" && typeof renderTenantSettingsView === "function") { renderTenantSettingsView(content); return; }
  if (group.custom === "licensing" && typeof renderLicensingView === "function") { renderLicensingView(content); return; }
  if (group.custom === "agentReleases" && typeof renderAgentReleasesView === "function") { renderAgentReleasesView(content); return; }
  if (group.custom === "enrolmentTokens" && typeof renderEnrolmentTokensView === "function") { renderEnrolmentTokensView(content); return; }
  if (group.custom === "agentProfile" && typeof renderAgentProfileView === "function") { renderAgentProfileView(content); return; }
  if (group.custom === "certs" && typeof renderCertsView === "function") { renderCertsView(content); return; }
  if (group.custom === "internalcas" && typeof renderInternalCAsView === "function") { renderInternalCAsView(content); return; }
  if (group.custom === "networkzones" && typeof renderNetworkZonesView === "function") { renderNetworkZonesView(content); return; }
  if (group.custom === "incoming" && typeof renderIncomingView === "function") { renderIncomingView(content); return; }
  if (group.custom === "people" && typeof renderPeopleView === "function") { renderPeopleView(content); return; }
  if (group.custom === "aiserviceusage" && typeof renderAiServiceUsageView === "function") { renderAiServiceUsageView(content); return; }
  if (group.custom === "logsaudit" && typeof renderLogsAuditView === "function") { renderLogsAuditView(content); return; }
  if (group.custom === "pinned" && typeof renderPinnedSitesView === "function") {
    renderPinnedSitesView(content);
    return;
  }
  const h = document.createElement("h2"); h.className = "group-title"; h.textContent = bl(group.t); content.appendChild(h);
  const d = document.createElement("p"); d.className = "group-desc"; d.textContent = bl(group.d); content.appendChild(d);
  const plane = group.plane || "edge";
  group.eps.forEach((ep) => content.appendChild(renderCard(ep, plane)));
}

function renderCard(ep, plane) {
  const card = document.createElement("div"); card.className = "card";
  const head = document.createElement("div"); head.className = "card-head";
  const m = document.createElement("span"); m.className = "method " + ep.m; m.textContent = ep.m;
  const label = document.createElement("span"); label.className = "card-label"; label.textContent = bl(ep.l);
  const path = document.createElement("span"); path.className = "path"; path.textContent = ep.p;
  const planeTag = document.createElement("span"); planeTag.className = "plane-tag"; planeTag.textContent = plane === "control" ? "control plane" : "edge";
  head.appendChild(m); head.appendChild(label); head.appendChild(path); head.appendChild(planeTag);
  card.appendChild(head);

  const params = pathParams(ep.p);
  const inputs = {};
  if (params.length) {
    const pdiv = document.createElement("div"); pdiv.className = "params";
    params.forEach((pn) => {
      const inp = document.createElement("input"); inp.placeholder = pn; inp.dataset.param = pn; inputs[pn] = inp;
      if (ep.ex && ep.ex[pn] != null) inp.value = ep.ex[pn]; // pre-fill a valid example so the card works on click
      pdiv.appendChild(inp);
    });
    card.appendChild(pdiv);
  }

  let bodyEl = null;
  const isWrite = ep.m !== "GET";
  if (isWrite && ep.body !== undefined) {
    bodyEl = document.createElement("textarea"); bodyEl.className = "body";
    bodyEl.value = JSON.stringify(ep.body, null, 2);
    card.appendChild(bodyEl);
  }

  const resp = document.createElement("pre"); resp.className = "resp"; resp.style.display = "none";
  const btn = document.createElement("button");
  btn.className = "run" + (ep.m === "DELETE" ? " delete" : isWrite ? " write" : "");
  btn.textContent = isWrite ? t("submit") : t("run");
  btn.onclick = async () => {
    let p = ep.p;
    for (const pn of params) {
      const v = (inputs[pn].value || "").trim();
      p = p.replace("{" + pn + "}", encodeURIComponent(v));
    }
    let body;
    if (bodyEl) {
      try { body = JSON.parse(bodyEl.value); } catch (e) { showResp(resp, { status: 0, ok: false, body: "Invalid JSON: " + e.message }); return; }
    }
    resp.style.display = "block"; resp.textContent = "…";
    try {
      const r = await apiFetch(ep.m, p, body, plane);
      showResp(resp, r);
    } catch (e) {
      showResp(resp, { status: 0, ok: false, body: t("requestFailed") + ": " + e.message });
    }
  };
  card.appendChild(btn);
  card.appendChild(resp);
  return card;
}

function showResp(el, r) {
  el.style.display = "block";
  const cls = r.ok ? "s-ok" : "s-err";
  const bodyText = typeof r.body === "string" ? r.body : JSON.stringify(r.body, null, 2);
  el.innerHTML = '<span class="' + cls + '">HTTP ' + r.status + "</span>\n" + escapeHtml(bodyText);
}
// escapeHtml is ATTRIBUTE-SAFE: it escapes quotes (" and ') as well as & < >, so a value interpolated into a
// double- or single-quoted HTML attribute (e.g. title="${escapeHtml(untrusted)}") cannot break out of the
// attribute and inject markup (review #30). Safe for text content too — a quote renders as &quot;/&#39;.
// Coerces to string so a null/undefined value is escaped as text instead of throwing.
function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------------------------------------------------------------------------
// Boot — auth gate
//
// The admin console is built ONLY after GET /admin/session confirms an authenticated admin session.
// With no session (or no Edge configured) we redirect to the login page (index.html) before any admin
// surface — nav, the endpoint catalog, anything — is rendered. login.js owns sign-in/SSO/activation.
// ---------------------------------------------------------------------------
async function init() {
  // Same-origin front door: drop any stale absolute Edge URL / token so all calls stay same-origin.
  ["edgeUrl", "controlUrl", "adminToken"].forEach((k) => localStorage.removeItem(k));
  document.getElementById("lang-en").onclick = () => setLang("en");
  document.getElementById("lang-ja").onclick = () => setLang("ja");
  document.getElementById("signout-btn").onclick = async () => {
    try { await apiFetch("POST", "/admin/logout", {}, "edge"); } catch (e) { /* ignore */ }
    idpSession = null;
    window.location.replace("index.html");
  };

  const signedIn = await ensureSignedIn();
  if (!signedIn) { window.location.replace("index.html"); return; }

  const gate = document.getElementById("gate-status");
  if (gate) gate.style.display = "none";
  document.getElementById("console-layout").style.display = "";
  renderWhoami();
  // Resolve feature entitlements (the license gate) before the nav is built, so unlicensed paid-feature surfaces
  // (DLP) are hidden from the start.
  try { const r = await apiFetch("GET", "/admin/entitlements"); if (r && r.ok && r.body && r.body.features) window.dsseEntitlements = r.body.features; } catch (e) { /* default all-on */ }
  applyI18n();
  refreshModeBanner();
  // Keep the posture banner current even if the mode is changed elsewhere (another operator / the API).
  if (!modeBannerTimer) modeBannerTimer = setInterval(refreshModeBanner, 15000);
}

// ensureSignedIn reads GET /admin/session and captures the operator identity when an admin-session cookie
// is present (so calls use cookie + CSRF). Returns true only for a definitive authenticated session.
async function ensureSignedIn() {
  try {
    const res = await fetch("/admin/session", { headers: { accept: "application/json" }, credentials: "include" });
    if (!res.ok) { idpSession = null; return false; }
    const s = await res.json();
    idpSession = (s && s.auth_method === "admin_session") ? s : null;
    // Adopt the tenant's clock for every surface. Absent means UTC, never the browser's zone — silently using
    // the operator's own location is how a report ends up covering the wrong day for the customer.
    if (s && typeof s.timezone === "string" && s.timezone.trim()) window.dsseTenantTimezone = s.timezone.trim();
  } catch (e) { idpSession = null; }
  return !!idpSession;
}

function renderWhoami() {
  const row = document.getElementById("whoami-row");
  const who = document.getElementById("whoami");
  const out = document.getElementById("signout-btn");
  if (idpSession) {
    // ★★★ THE HEADER NAMED THE PERSON BY THEIR ROW ID (2026-09-05, read off a live deployment):
    //
    //   Operating as adm_d6204f27a07f048c7942adbbb6b9bef2 (admin, super_admin)
    //
    // The name was in the same response the whole time — GET /admin/session resolves principal_label
    // precisely so a record of who did something can hold more than an id — and this line used the id and
    // printed the role slugs beside it. Both are plumbing: the reader signs in as an address, and
    // "super_admin" is a permission name, not a word anyone says.
    //
    // Which organization this is and that it is being operated across the boundary are already on screen, in
    // the tenant chip and the banner under it, in sentences. So the header carries the name, and the id and
    // roles stay reachable on hover for the moment somebody needs to quote them.
    const id = idpSession.principal_id || "";
    const roles = (idpSession.roles || []).map((r) => (typeof roleLabelBL === "function" ? roleLabelBL(r) : r));
    who.textContent = (idpSession.principal_label || "").trim() || id;
    who.title = [id, roles.join(", ")].filter(Boolean).join(" · ");
    row.style.display = ""; out.style.display = "";
    renderTenantIndicator();
  } else {
    row.style.display = "none"; out.style.display = "none";
    const ti = document.getElementById("tenant-indicator"); if (ti) ti.style.display = "none";
  }
}

// hasCrossTenantAdmin: does the signed-in operator manage the tenant registry / operate across tenants?
// Heuristic from session roles; the authoritative gate is server-side (admin.tenant.admin). super_admin is the
// operator role and owner is "*" (both include cross-tenant); a customer tenant_admin has neither.
function hasCrossTenantAdmin() {
  const roles = (idpSession && idpSession.roles) || [];
  return roles.includes("super_admin") || roles.includes("owner");
}

// answeringForTheDeployment: is THIS screen about the whole deployment, or about one organization?
//
// ★★ THE PREDICATE THAT WAS WRONG IN SIX PLACES IN ONE NIGHT (2026-08-17). Holding cross-tenant permission and
// currently looking at the deployment are different questions, and screen after screen asked the first while
// meaning the second. The results, each measured: the nav kept the operator's menu inside a customer; the
// enforcement banner offered to change the OPERATOR tenant's mode from a customer's screen; entering a
// customer landed on the operator's own page inside them; the Overview listed every organization on the
// deployment, with their plans and configuration versions, while rendered inside one of them; and two more
// panels labelled a customer's screen with deployment-wide counts.
//
// Entering an organization is a MODE. It decides what is written AND what is shown. This is that rule, once,
// with a name — the server-side counterpart is adminAnswerScope (docs/who_is_this_answer_about.ja.md).
//
// ★★ AND THE FIRST HALF WAS STILL A ROLE (2026-08-21, found on a customer's own Certificates screen). It asked
// hasCrossTenantAdmin() — super_admin or owner — which a CUSTOMER organization grants inside itself. So a
// customer whose administrator holds super_admin was treated as answering for the whole deployment, and every
// screen that asks this hid the organization-level half from the organization it belongs to. Measured: the
// certificate-replacement card, whose own title is "The certificate this tenant's devices trust", was invisible
// to that tenant.
//
// Belonging to the operator organization is the question, and the session already answers it: is_operator_tenant
// is stamped by the server from -operator-tenant-id. Same correction as the server-side gates in
// operator_is_an_organization_not_a_role.go — a super_admin of a customer is a super_admin OF THAT CUSTOMER.
function answeringForTheDeployment() {
  return signedInAsOperator() && !operateTenant;
}

// renderTenantIndicator shows the current organization (tenant) in the header so the tenant in context is
// always visible (Phase 0 of the multi-tenant console; the super-admin tenant switcher comes later).
async function renderTenantIndicator() {
  const elx = document.getElementById("tenant-indicator");
  if (!idpSession) { if (elx) elx.style.display = "none"; renderOperatingBanner(null); return; }
  try {
    const r = await apiFetch("GET", "/admin/tenant");
    const name = (r.ok && r.body && (r.body.display_name || r.body.tenant_id)) || operateTenant || "";
    if (elx) {
      if (name) {
        elx.textContent = name;
        elx.title = bl({ en: "Current tenant: ", ja: "現在のテナント: " }) + ((r.body && r.body.tenant_id) || operateTenant || "");
        elx.classList.toggle("operating", !!operateTenant);
        elx.style.display = "";
      } else { elx.style.display = "none"; }
    }
    // ★ THE NAME THE READER KNOWS, KEPT FOR EVERY OTHER SCREEN (2026-08-21). The elevation offer below used
    // to say "tenant_northwind" — an internal id, in a sentence asking a person to make a decision.
    if (name) operatingOrganizationName = name;
    renderOperatingBanner(name);
  } catch (e) { if (elx) elx.style.display = "none"; renderOperatingBanner(operateTenant); }
}

// enterTenant / exitTenant: a cross-tenant operator switches the operating tenant. We hard-reload so every
// view's in-memory state and caches are cleared (no cross-tenant data bleed); the persisted operateTenant is
// re-applied on boot.
// enterTenantAndOpen enters an organization AND lands on the screen the caller meant, across the reload that
// entering requires. The destination is stashed rather than passed, because entering reloads the page — and a
// caller that navigated first and entered second would leave the console showing one organization's data
// while operating in another, which is exactly the defect this exists to fix.
function enterTenantAndOpen(tenantId, groupId) {
  try { if (tenantStore) tenantStore.setItem("openGroupAfterEnter", String(groupId || "")); } catch (e) {}
  enterTenant(tenantId);
}

// consumeGroupAfterEnter returns (once) the screen stashed by enterTenantAndOpen.
function consumeGroupAfterEnter() {
  try {
    if (!tenantStore) return "";
    const g = tenantStore.getItem("openGroupAfterEnter");
    tenantStore.removeItem("openGroupAfterEnter");
    return g && GROUPS.some((x) => x.id === g) && navGroupVisible(g) ? g : "";
  } catch (e) { return ""; }
}

function enterTenant(tenantId) {
  if (!tenantId) return;
  try { if (tenantStore) tenantStore.setItem("operateTenant", tenantId); } catch (e) {}
  location.reload();
}
function exitTenant() {
  try { if (tenantStore) tenantStore.removeItem("operateTenant"); } catch (e) {}
  location.reload();
}

// freshRender guards a host element against a stale answer overwriting a fresher one. Call it BEFORE the
// fetch; call the function it returns AFTER, and return early if it says false.
//
//   const current = freshRender(host);
//   const r = await apiFetch(...);
//   if (!current()) return;          // a newer render of this host has started — this answer is out of date
//   host.innerHTML = ""; ...
//
// ★ WHY (2026-08-16, measured, not theorised). Every screen in this console renders by starting an async read
// and then replacing its host's contents when the read RESOLVES. Two overlapping renders therefore land in
// completion order, not request order, and the SLOWER one wins whichever was asked for last. Measured on the
// organization checklist: with the first request answering slowly and stale and the second answering at once
// with the truth, the screen settled on the stale one — an organization with 11 of 13 items done displayed as
// "0/13 — not working". An operator pressing Reload, or a screen re-reading itself after a change, is exactly
// how two renders overlap.
//
// The counter lives on the element so it is per host: two screens rendering at once do not cancel each other.
function freshRender(host) {
  if (!host) return () => true;
  const seq = (host.__renderSeq = (host.__renderSeq || 0) + 1);
  return () => host.__renderSeq === seq;
}

// renderOperatingBanner shows a prominent, persistent banner while operating within another tenant, with an
// explicit "Exit tenant" affordance. name is the operate-target display name (falls back to the id).
function renderOperatingBanner(name) {
  const b = document.getElementById("operating-banner");
  if (!b) return;
  if (!operateTenant) { b.style.display = "none"; b.innerHTML = ""; return; }
  b.innerHTML = "";
  b.appendChild(el("span", { class: "operating-dot" }));
  b.appendChild(el("span", { html: bl({ en: "Operating within <b>" + escapeHtml(String(name || operateTenant)) + "</b> as operator — every change is audited.", ja: "<b>" + escapeHtml(String(name || operateTenant)) + "</b> を運営として操作中 — 変更はすべて記録されます。" }) }));
  b.appendChild(el("button", { class: "ui-btn ui-btn-sm", text: bl({ en: "Exit tenant", ja: "テナントを出る" }), onClick: exitTenant }));
  b.style.display = "";
  renderDelegationState(b);
}

// ★★ ENTERING AN ORGANIZATION THAT HAS NOT DELEGATED LOOKS EXACTLY LIKE ENTERING ONE THAT HAS (2026-08-17,
// measured). The standing delegation is the customer's to give, and without it every admin read inside that
// organization is refused. Measured as the operator inside a customer that had not delegated: /admin/state,
// /admin/enrolled-devices, /admin/rules, /admin/east-west, /admin/license, /admin/agent-updates and
// /admin/connectors ALL answered 403 — and the Overview drew "0 devices, 0 connectors, 0 policies, 0%
// posture" from those refusals. An operator would have read that as a customer with nothing deployed. It is
// the oldest defect in this codebase wearing new clothes: a value that means "nothing" and a value that means
// "you may not know" rendered as the same character.
//
// One authoritative question rather than sniffing the refusals: GET /admin/operator-access answers 200 with
// `managed` for any organization, including one that has refused everything else.
async function renderDelegationState(bar) {
  if (!signedInAsOperator() || !operateTenant) return;
  const asked = operateTenant;
  let managed = null;
  try {
    const r = await apiFetch("GET", "/admin/operator-access", undefined, "control");
    if (r.ok && r.body && typeof r.body.managed === "boolean") managed = r.body.managed;
  } catch (e) { return; } // unreadable: say nothing rather than claim a state
  if (managed !== false || asked !== operateTenant || !bar.isConnected) return;
  bar.classList.add("operating-undelegated");
  bar.appendChild(el("span", { class: "ui-badge ui-badge-warn", style: "margin-left:10px",
    text: bl({ en: "not delegated — figures on these screens are missing, not zero",
               ja: "委任なし — この先の数値は「0」ではなく「取得できていません」" }) }));
}

// ---------------------------------------------------------------------------
// East-West posture banner (always visible on every page)
// ---------------------------------------------------------------------------
// Observe is an EAST-WEST concept. By default East-West is in OBSERVE (all internal/lateral traffic is
// allowed and recorded, NOT enforced); the banner is loud (amber) with a single button to disable observe
// and begin per-hop enforcement (default-deny). While enforcing it is calm (green). Egress has no observe —
// it is allowed + inspected by policy — so this banner is scoped to East-West. It reflects the same state
// the East-West rules view governs (GET/POST /admin/east-west, east_west_enabled).
let modeBannerTimer = null;

// The Connector-access posture is the East-West learning-lifecycle ramp: OBSERVE (watch + record, allow all) →
// PARTIAL (rules enforce, but a flow no rule matches is still allowed — safe adoption) → FULL (rules enforce and
// unmatched is denied — the terminal default-deny). The banner shows the current stage and offers the adjacent
// steps; the FULL step is gated on convergence (uncovered observed flows → 0).
// ★★ THE TAB CAN BE SHOWING ONE ADMINISTRATOR WHILE ACTING AS ANOTHER (2026-08-17, observed by accident).
//
// The header is rendered once, at boot, from the session read then. The session lives in a COOKIE, which every
// tab and window of the browser shares — so signing in anywhere replaces it everywhere, and a tab left open
// keeps displaying the name, the roles and the ORGANIZATION BADGE of whoever it booted as. What it displayed
// during that night: "Northwind Traders", a Northwind administrator's id, `admin`. What it was actually
// acting as: a reference-lab account holding super_admin. Every write that tab made would have landed in the
// other organization, under the other principal, with the header quietly disagreeing.
//
// This is checked on the banner's existing 15s timer rather than on a new one, and it does NOT sign anyone out
// or reload underneath them: a page that navigates away while an administrator is mid-form is its own kind of
// harm. It says what happened and hands them the reload.
async function revalidateSession() {
  const was = idpSession;
  if (!was) return;
  let now = null;
  try {
    const res = await fetch("/admin/session", { headers: { accept: "application/json" }, credentials: "include" });
    now = res.ok ? await res.json() : null;
  } catch (e) { return; } // unreachable: a network blip is not an identity change
  const gone = !now || now.auth_method !== "admin_session";
  const changed = !gone && ((now.principal_id || "") !== (was.principal_id || "") ||
                            (now.tenant_id || "") !== (was.tenant_id || ""));
  if (!gone && !changed) return;
  if (sessionRevalidationNotified) return;
  sessionRevalidationNotified = true;
  const bar = document.getElementById("mode-banner");
  const say = gone
    ? bl({ en: "You have been signed out in another tab. This page is showing what it last loaded — reload to sign in again.",
           ja: "別のタブでサインアウトされました。この画面は最後に読み込んだ内容のままです。再読込してサインインし直してください。" })
    : bl({ en: "A different administrator signed in in another tab, so this page is no longer showing who it is acting as. Reload before you change anything.",
           ja: "別のタブで別の管理者がサインインしました。この画面はもう「いま操作している人」を表示していません。何かを変更する前に再読込してください。" });
  if (bar) {
    bar.style.display = "";
    bar.classList.remove("enforcing", "observing");
    bar.textContent = "";
    const label = document.createElement("span");
    label.className = "mode-banner-label";
    label.textContent = "● " + say;
    bar.appendChild(label);
    const b = document.createElement("button");
    b.className = "mode-banner-btn";
    b.textContent = bl({ en: "Reload", ja: "再読込" });
    b.onclick = () => window.location.reload();
    bar.appendChild(b);
  }
  if (modeBannerTimer) { clearInterval(modeBannerTimer); modeBannerTimer = null; }
}
let sessionRevalidationNotified = false;

async function refreshModeBanner() {
  // Who this tab is acting as is checked first: a banner about enforcement mode is worth less than a banner
  // saying the page is no longer about the administrator whose name is at the top of it.
  await revalidateSession();
  if (sessionRevalidationNotified) return;
  const el = document.getElementById("mode-banner");
  if (!el) return;
  // ★ AN OPERATOR OUTSIDE AN ORGANIZATION HAS NO CONNECTOR-ACCESS POSTURE (2026-08-17). This banner reports
  // ONE organization's enforcement mode and offers to change it. Read with no organization named it answers
  // for the operator's OWN tenant — so the operator's home carried a full-width banner about "your connector
  // access", with a button that would have moved the operator tenant's enforcement, on a screen that is
  // otherwise entirely about the deployment. Inside an organization it is correct and stays.
  if (signedInAsOperator() && !operateTenant) { el.style.display = "none"; return; }
  let mode = null;
  try {
    const res = await apiFetch("GET", "/admin/east-west");
    if (res && res.ok && res.body && typeof res.body === "object") {
      mode = res.body.mode || (res.body.east_west_enabled ? "full" : "observe");
    }
  } catch (e) { /* leave the banner as-is on a transient error */ }
  if (mode === null) { el.style.display = "none"; return; }

  el.style.display = "";
  el.classList.toggle("enforcing", mode === "full");
  el.classList.toggle("observing", mode !== "full");
  el.textContent = "";

  const label = document.createElement("span");
  label.className = "mode-banner-label";
  label.textContent = {
    observe: bl({ en: "● Connector access: OBSERVE — connections to internal resources are allowed and recorded, not blocked. Review them, adopt rules, then ramp up.",
                  ja: "● コネクタ経由アクセス: 観測 — 内部リソースへの接続は許可・記録のみで、ブロックしていません。確認・ルール化のうえ段階的に強制してください。" }),
    partial: bl({ en: "● Connector access: PARTIAL ENFORCE — your rules apply, but a connection no rule matches is still allowed (safe adoption). Drive uncovered flows to 0, then go Full.",
                  ja: "● コネクタ経由アクセス: 部分強制 — ルールは適用されますが、どのルールにも一致しない接続はまだ許可されます(安全な移行)。未カバーを0にしてから完全強制へ。" }),
    full:    bl({ en: "● Connector access: FULL ENFORCE — only approved connections to internal resources are allowed; everything else is denied.",
                  ja: "● コネクタ経由アクセス: 完全強制 — 承認された内部リソースへの接続のみ許可され、それ以外は拒否されます。" }),
  }[mode];
  el.appendChild(label);

  const mkBtn = (text, onclick) => { const b = document.createElement("button"); b.className = "mode-banner-btn"; b.textContent = text; b.onclick = onclick; el.appendChild(b); };

  if (mode === "observe") {
    mkBtn(bl({ en: "Start partial enforcement", ja: "部分強制を開始" }), () => setEastWestMode("partial", bl({
      en: "Start partial enforcement? Your connector-access rules begin to apply (authenticate/deny/allow). Connections no rule matches stay ALLOWED for now — nothing new is blocked.",
      ja: "部分強制を開始しますか? コネクタ経由アクセスのルールが適用され始めます(認証/拒否/許可)。どのルールにも一致しない接続は当面は許可のまま — 新たに遮断されるものはありません。" })));
  } else if (mode === "partial") {
    mkBtn(bl({ en: "Turn on full enforcement", ja: "完全強制を有効化" }), () => confirmFullEnforce());
    mkBtn(bl({ en: "Back to observe", ja: "観測に戻す" }), () => setEastWestMode("observe", bl({
      en: "Return to observe? Rule enforcement stops — all connections to internal resources are allowed again (still recorded).",
      ja: "観測に戻しますか? ルール適用を停止し、内部リソースへの接続はすべて再び許可されます(記録は継続)。" })));
  } else if (mode === "full") {
    mkBtn(bl({ en: "Back to partial", ja: "部分強制に戻す" }), () => setEastWestMode("partial", bl({
      en: "Return to partial enforcement? Rules still apply, but connections no rule matches will be allowed again instead of denied.",
      ja: "部分強制に戻しますか? ルールは適用されたまま、どのルールにも一致しない接続は拒否でなく再び許可されます。" })));
  }
}

// confirmFullEnforce gates the terminal deny flip on convergence: it checks the Observe inventory and, if any
// uncovered flow remains, warns that Full Enforce will BLOCK it (adopt first). The operator can still proceed.
async function confirmFullEnforce() {
  let uncovered = null;
  try {
    const r = await apiFetch("GET", "/admin/east-west/observations");
    if (r && r.ok && r.body && r.body.convergence) uncovered = r.body.convergence.uncovered_flows;
  } catch (e) { /* fall through with uncovered unknown */ }
  let msg;
  if (uncovered && uncovered > 0) {
    msg = bl({
      en: "⚠ " + uncovered + " observed flow(s) are still UNCOVERED by any rule. Full enforcement will BLOCK them. Adopt them from the Observations tab first, or proceed and break those connections?",
      ja: "⚠ 観測されたフローのうち " + uncovered + " 件がまだどのルールにもカバーされていません。完全強制はこれらを遮断します。先に Observations タブでルール化するか、このまま進めて該当接続を切断しますか?" });
  } else {
    msg = bl({
      en: "Turn on full enforcement? Connections to internal resources that no rule allows will be denied. Uncovered observed flows: " + (uncovered === null ? "unknown" : "0") + ".",
      ja: "完全強制を有効化しますか? どのルールでも許可されない内部リソースへの接続は拒否されます。未カバーの観測フロー: " + (uncovered === null ? "不明" : "0") + "。" });
  }
  setEastWestMode("full", msg);
}

async function setEastWestMode(mode, confirmMsg) {
  if (!window.confirm(confirmMsg)) return;
  try {
    const res = await apiFetch("POST", "/admin/east-west", { mode });
    if (!res || !res.ok) {
      window.alert(bl({ en: "Failed to change connector-access posture (status ", ja: "コネクタ経由アクセスの変更に失敗(状態 " }) + (res ? res.status : "?") + ")");
    }
  } catch (e) { window.alert(String(e)); }
  refreshModeBanner();
}

document.addEventListener("DOMContentLoaded", init);
