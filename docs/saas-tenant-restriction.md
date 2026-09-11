# SaaS tenant restriction

Google Workspace, Microsoft 365, ChatGPT and Anthropic Claude are built-in providers. Every new tenant can configure them in **AdminConsole → SaaS Tenant Restriction**, with no installer options, startup files or package customization. All providers start **off**.

1. Enter the tenant in AdminConsole and open **SaaS Tenant Restriction**.
2. Choose **Configure** for a provider and enter its allowed account scope:

   | Provider | Allowed value |
   | --- | --- |
   | Google Workspace | Company domains, separated by commas |
   | Microsoft 365 | Entra directory GUIDs or verified domains, separated by commas; also enter the directory GUID of the tenant managing the restriction |
   | ChatGPT | One workspace ID |
   | Anthropic Claude | Organization UUIDs, separated by commas |

3. Save with enforcement off to prepare the setting. Saved values are hidden; a blank form field keeps the previous value.
4. Enable enforcement when you are ready to restrict sign-ins. Disable it to stop injecting the restriction headers.

The control plane saves the tenant's settings durably and distributes them to the Edges. A successful save confirms persistence; Edges apply the update on their configuration synchronization cycle. Region failover uses the same tenant settings. Other tenants are unaffected.

The SaaS request must pass through TLS inspection. A bypassed request cannot receive restriction headers. The provider interprets the header and applies its account restrictions; applicable plans and allowed account identifiers are provider-specific. DLP detection and SaaS account restrictions are separate controls.

For API automation, POST `/admin/swg/tenant-restriction` on the control plane with the authenticated tenant scope, `provider`, `allowed_value` and `enabled`; Microsoft 365 also uses `context_tenant_id`. Omitted value fields retain their saved values. An explicit empty string clears a value while enforcement is off. GET lists status without disclosing configured values.

Existing startup-file configurations retain their legacy update format. The built-in configuration does not require those files. This screen does not provide configuration-history rollback.
