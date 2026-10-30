"use strict";

function sharedFleetTenantWarning(tenant) {
  if (!tenant || !tenant.shared_fleet_warning) return "";
  return bl({en: "Some new connections may be refused because this deployment also uses Regions outside this tenant's allowed Regions. The Region restriction remains enforced. Use a separately scoped deployment to avoid this availability loss.",
    ja: "この配備は許可リージョン外のEdgeも使用するため、このテナントの新しい接続が一部拒否される可能性があります。リージョン制限は維持されます。可用性を確保するには、許可範囲に合わせた別の配備を使用してください。"});
}

function tenantFleetSaveContext() {
  return JSON.stringify([typeof operateTenant === "undefined" ? null : operateTenant,
    typeof idpSession === "undefined" ? null : idpSession]);
}

async function saveTenantWithFleetConfirmation(path, body, plane) {
  const owner = tenantFleetSaveContext();
  body = JSON.parse(JSON.stringify(body));
  const result = await apiFetch("POST", path, body, plane);
  if (result.ok || result.body?.code !== "shared_fleet_residency_confirmation_required") return result;
  if (owner !== tenantFleetSaveContext()) return {ok: false, cancelled: true};
  const accepted = await uiConfirm({title: bl({en: "Some connections may be refused", ja: "一部の接続が拒否される可能性があります"}),
    body: bl({en: "This deployment distributes connections to Edges in every Region. Edges outside the allowed Regions will refuse this tenant. Use a separately scoped deployment to avoid these failures. Save this restriction with that availability impact?",
      ja: "この配備は全リージョンのEdgeへ接続を分散します。許可リージョン外のEdgeはこのテナントの接続を拒否します。失敗を避けるには、許可範囲に合わせた別の配備が必要です。この影響を理解した上で制限を保存しますか？"}),
    confirmLabel: bl({en: "Save with this restriction", ja: "影響を承知して制限を保存"}), danger: true});
  if (!accepted || owner !== tenantFleetSaveContext()) return {ok: false, cancelled: true};
  return apiFetch("POST", path, Object.assign({}, body, {acknowledge_shared_fleet_residency_impact: true}), plane);
}
