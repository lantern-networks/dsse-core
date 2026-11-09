// UI chrome strings (EN/JA). Feature group titles + endpoint labels live in app.js (bilingual inline).
window.I18N = {
  en: {
    appTitle: "Lantern DSSE — Admin Console",
    edgeUrl: "Edge admin API URL",
    controlPlaneUrl: "Control plane API URL (audit / reporting)",
    adminToken: "Admin token",
    save: "Save",
    testConnection: "Test connection",
    tlsHint: "The Console is a separate-host client; it calls the Edge admin API over TLS. Trust the Edge certificate in your browser if it is self-signed.",
    run: "Run",
    submit: "Submit",
    body: "Request body (JSON)",
    connected: "connected",
    notConfigured: "Set the Edge URL and admin token, then Save.",
    enterEmail: "Enter your work email.",
    configSaved: "Saved.",
    requestFailed: "Request failed",
    noToken: "No admin token set — set it above and Save.",
    signInEmail: "Work email",
    signInTitle: "Sign in",
    setup: "Setup (Edge URL)",
    checkingSession: "Checking your session…",
    signIn: "Sign in",
    signOut: "Sign out",
    password: "Password",
    totpCode: "2FA code",
    operatingAs: "Operating as",
    breakGlass: "Break-glass admin token (optional)",
    signedOut: "Signed out.",
    invalidCredentials: "Invalid credentials.",
    signInUnreachable: "Sign-in could not be completed (HTTP {status}): something failed on the server. Try again shortly, and tell the operator if it continues.",
    signInRefused: "Sign-in was refused (HTTP {status}).",
    enterTotp: "Enter your 2FA code.",
    activateTitle: "Activate your admin account",
    newPassword: "New password",
    setPassword: "Set password",
    enroll2fa: "Scan this in your authenticator app, then enter the 6-digit code:",
    cantScan: "Can't scan? Enter this secret key manually:",
    showOtpauth: "Show otpauth URI",
    completeActivation: "Enroll 2FA & finish",
    recoveryCodes: "Save these one-time recovery codes:",
    activationDone: "Account activated. You can now sign in with your email, password, and 2FA.",
    activationInvalid: "This activation link is invalid or expired.",
  },
  ja: {
    appTitle: "Lantern DSSE — 管理コンソール",
    edgeUrl: "Edge 管理 API の URL",
    controlPlaneUrl: "制御プレーン API の URL (監査 / レポート)",
    adminToken: "管理トークン",
    save: "保存",
    testConnection: "接続テスト",
    tlsHint: "本コンソールは別ホストのクライアントです。Edge の管理 API へ TLS で接続します。自己署名証明書の場合はブラウザで Edge の証明書を信頼してください。",
    run: "実行",
    submit: "送信",
    body: "リクエストボディ (JSON)",
    connected: "接続成功",
    notConfigured: "Edge URL と管理トークンを入力して保存してください。",
    enterEmail: "会社メールを入力してください。",
    configSaved: "保存しました。",
    requestFailed: "リクエスト失敗",
    noToken: "管理トークン未設定 — 上で設定して保存してください。",
    signInEmail: "会社メール",
    signInTitle: "サインイン",
    setup: "セットアップ (Edge URL)",
    checkingSession: "セッションを確認しています…",
    signIn: "サインイン",
    signOut: "サインアウト",
    password: "パスワード",
    totpCode: "2FA コード",
    operatingAs: "操作ユーザ",
    breakGlass: "ブレークグラス管理トークン (任意)",
    signedOut: "サインアウトしました。",
    invalidCredentials: "認証情報が正しくありません。",
    signInUnreachable: "サインインを完了できませんでした（HTTP {status}）。サーバー側で問題が起きています。しばらくしてからもう一度試し、続く場合は運営者に連絡してください。",
    signInRefused: "サインインが拒否されました（HTTP {status}）。",
    enterTotp: "2FA コードを入力してください。",
    activateTitle: "管理アカウントを有効化",
    newPassword: "新しいパスワード",
    setPassword: "パスワードを設定",
    enroll2fa: "認証アプリでこれを読み取り、6桁コードを入力してください:",
    cantScan: "読み取れない場合は、このシークレットキーを手動で入力してください:",
    showOtpauth: "otpauth URI を表示",
    completeActivation: "2FA を登録して完了",
    recoveryCodes: "このワンタイム・リカバリコードを保管してください:",
    activationDone: "アカウントを有効化しました。email・パスワード・2FA でサインインできます。",
    activationInvalid: "この有効化リンクは無効または期限切れです。",
  },
};

// The language a reader sees before choosing one. A choice is remembered per browser AND per host name — each
// region's Console is its own site to the browser — so a reader who chose Japanese on one region's Console met
// English on the next (0.4.1 acceptance B rerun). Without a choice here, the browser's own language preference
// decides, in the order the reader set it.
window.dsseInitialLang = function () {
  try {
    const saved = localStorage.getItem("lang");
    if (saved === "en" || saved === "ja") return saved;
  } catch (e) { /* storage unavailable: fall through to the browser's preference */ }
  const nav = typeof navigator !== "undefined" ? navigator : {};
  const prefs = (nav.languages && nav.languages.length) ? nav.languages : [nav.language || ""];
  for (const p of prefs) {
    const l = String(p).toLowerCase();
    if (l.startsWith("ja")) return "ja";
    if (l.startsWith("en")) return "en";
  }
  return "en";
};
