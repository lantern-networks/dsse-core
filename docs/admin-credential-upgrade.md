# Upgrading administrator credential storage

Migrations 048, 049 and 051 add persisted TOTP replay counters, optimistic credential revisions and a required write protocol. Back up the database and stop **all** control-plane processes that use the first-party credential database before applying these migrations. Upgrade those processes together, apply their configured component migrations, then restart them on the same release. Do not mix an older credential writer with migration 051: the database refuses its INSERT, UPDATE, DELETE and TRUNCATE statements, and an older binary can report a change without saving it.

A rollback needs the matching pre-upgrade database backup and binaries during a coordinated outage; preserve and reconcile any account, token and TOTP changes made after that backup. Do not remove the trigger or reset replay counters to make old writers work. Test the restored state before reopening administrator access.

Each authenticated first-party administrator request reads current status and roles from the shared database when PostgreSQL credential storage is configured. A missing, suspended or removed account is refused; unavailable storage does not fall back to a startup cache. Existing sessions use the current roles. API tokens retain their issued roles/scopes but still require an active originating account. Legacy first-party principals whose IDs differ from their credential retain access through their persisted email and tenant association.

An operator API client writing an object for another organization must provide the matching `X-Operate-Tenant` header as well as any tenant in the body. Delegated access and elevation checks still apply. The Console already supplies the header. A body tenant alone does not select an organization.

Organization purge uses the credential writer protocol, including when an earlier removal already emptied the table. Log-export download-link creation reports 409 on a standby control plane and 503 when its saved token cannot be confirmed.
