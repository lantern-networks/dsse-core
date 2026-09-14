# Administrator access and customer delegation

This guide covers Console administration, not end-user [IdP sign-in](idp.md) or
[East-West OOB grants](east-west-policy.md). The role catalog and sensitive-operation
list describe the current experimental implementation and may change.

## Identity, role, and organization are separate checks

An administrator has a home organization and assigned roles. The selected Console
organization determines the requested context; selecting a customer does not itself
grant access. In a deployment using the tenant model, cross-organization administration
requires both membership in the configured operator organization and the relevant
cross-organization permission. Customer delegation is an additional requirement.

**`super_admin` is a role, not proof that its holder is the deployment operator.**
A customer's `super_admin` administers that customer; the role name does not authorize
reading another customer's policy, keys, or logs. Deployment-wide routes have additional
operator-boundary checks. With the tenant model enabled but no operator organization
configured, cross-organization administration is refused.

| Role | Current permission profile |
|---|---|
| `owner` | Wildcard permission role; protect its credentials as highly privileged. Organization and route boundaries still matter |
| `super_admin` | Top organization administrator; has `admin.tenant.admin`. Cross-organization reach still depends on operator membership and delegation |
| `tenant_admin` | Derived from the within-tenant `admin` permission set, without `admin.tenant.admin` |
| `admin` | Within-tenant operational administration; not the deployment operator merely by its name |
| `analyst` | Reads selected operational/policy views; can create/read/cancel exports |
| `auditor` | Reads audit and related state; can create/read exports |
| `approver` | State and approval/break-glass workflow permissions, including approval writes |

This is a guide to intent, not a substitute for the current permission catalog.
`GET /admin/rbac/catalog` and each route's authorization determine the exact permitted
acts. In particular, analyst is not "read everything", and read-oriented roles can
still export data. Grant the smallest role set that covers the intended work.

## Create and maintain named accounts

1. Follow [Deployment](deployment.md) for initial bootstrap, then sign in with the named
   administrator and MFA as described in [First use](after-verify.md).
2. Enter the organization where the new administrator belongs. In **Administrators**,
   invite the person and select roles appropriate to that organization.
3. Hand over the invitation privately. The Console does not send an email; the link is
   one-time and expires after 24 hours. Treat it as a credential, including copied messages.
4. Complete activation and the required sign-in/MFA setup. Verify both an allowed action
   and an action outside the account's intended scope.
5. Review roles and accounts periodically. Suspend access when needed, and review related
   API tokens and sessions as part of offboarding. Validate the denial with a new request.

Role assignment has its own escalation checks. The scoped operator role is `super_admin`;
the invitation and role-update routes refuse assigning `owner` in the operator tenant.
Do not infer a supported account-provisioning flow merely because a role is in the catalog.

Administrator OIDC configuration and customer end-user IdP connections are separate.
Successfully configuring the customer's IdP does not configure Console sign-in or prove
the administrator's MFA behavior. Verify the actual administration login path you use.

## Durable first-party authentication

Use a durable `-first-party-store` (a file path or `postgres`) when administrator
credentials must survive a restart. `memory` does not provide restart persistence.
Successful TOTP sign-in records the consumed time step alongside the credential, so
restarting with the same durable state does not make that code reusable. One-time
recovery-code consumption is also saved before sign-in succeeds. A credential write
failure refuses sign-in rather than issuing a session whose replay protection was not saved.

For PostgreSQL, the component startup migration includes
`048_admin_local_credentials_totp_counter.sql` and
`049_admin_local_credentials_revision.sql`. The default
`-postgres-run-migrations=true` applies it before credential loading. If migrations
are disabled, apply these migrations through your database upgrade procedure before
starting the updated binary. Back up the credential store and validate the upgrade
on a separate environment first.

Older file snapshots and database rows have no consumed-step history; the new field
starts at zero and protection is established by the first successful sign-in after
upgrade. Previously consumed codes cannot be reconstructed. Stop all authentication authorities for this upgrade, apply the migrations, and
restart them with the updated binary. Do not run mixed versions: older binaries do
not participate in the concurrency checks.

PostgreSQL credential writes compare a database generation before accepting a
change. Simultaneous consumption of the same TOTP or recovery code through separate
authorities sharing this database permits only one successful save. A stale write
is refused, the local credential snapshot is refreshed for the next request, and
the failed operation is not automatically retried. A sign-in conflict returns a
storage-unavailable response; restart the sign-in flow with a fresh code.

This does not provide continuous synchronization of existing session authorization
across authorities. Independent databases and shared JSON files are not coordinated
by this mechanism. PostgreSQL deletion is tenant-scoped and generation-checked as well: a stale
individual or tenant-cascade deletion cannot erase an account recreated at the same
email address. Conflicts fail the request and refresh local state without retrying
the deletion automatically. A tenant cascade stops at its first failure and can
have already removed earlier accounts; inspect the reported outcome before retrying.

Credential persistence calls carry a five-second deadline. PostgreSQL honors that
deadline; filesystem operations are not guaranteed to be interruptible. Existing
session checks and principal labels read the last committed account snapshot without
waiting for a credential write. Suspension and role changes take effect after a
successful save; a failed save does not publish the requested change.

An authenticator replacement starts a new step history. Account activation still
allows immediate sign-in with the current code; the first successful sign-in consumes
it for subsequent authentication attempts.

Activation attempts with a valid invitation are audited under the target account's
organization. Invalid or expired invitations cannot establish an organization; review
those failures in the node organization's audit trail, rather than expecting them in
a customer's account history. Audit records do not contain invitation tokens,
passwords, authenticator secrets, or recovery codes.

## Delegated operation inside a customer

When creating an organization, **Who runs it → We run it for them** establishes the
standing delegation described in [Organizations](organizations.md). Without it, an
operator entering the customer is refused even for reads, including device configuration
and logs. Confirm the customer name in the header before each administrative change.

Some sensitive acts require a further **20-minute elevation** inside the organization.
Examples include creating customer authorities and selected authority rotation or removal
operations. The Console explains the act and records that the operator took this access
and when it ended. The window does not renew automatically. It governs the delegated
operator path; it is not an end-user authentication grant or a blanket rule that every
customer administrator must elevate for every change.

Customers can withdraw their operator delegation. The operator must not be able to
reopen a delegation the customer withdrew through the ordinary delegation control.
After withdrawal, test operator reads and writes with the previous session and confirm
the customer can still administer its own organization. Review the audit record for
delegation, elevation, the actual change, and withdrawal as distinct events.

## Recovery is a separate authority

Generated deployments initially arm an owner credential while the
`runtime/admin-bootstrapped` marker is absent. Bootstrap and service recreation close
that initial path. Lost-account recovery requires access to the founding control plane's
deployment directory; use the canonical [break-glass procedure](deployment.md#break-glass-and-closing-it).

Protect filesystem and service-control access accordingly. Customer delegation does not
remove the host operator's ability to change the running service or restore its state.
Treat recovery as a privileged, recorded operation: retain the reason and actor, confirm
named-account access, close the recovery path, and verify the deployment afterwards.
Do not re-mint deployment CAs to recover an administrator password.

## Boundary checks before handover

| Actor / condition | Check |
|---|---|
| Customer administrator | Own customer works; another customer's identifiers/context are refused |
| Operator without delegation | Customer read and write are refused |
| Delegated operator without elevation | Routine authorized work works; an elevated act is refused |
| Elevated operator | Intended act works; expiry ends that authority |
| Customer withdraws delegation | Previous operator context no longer authorizes customer access |
| Analyst / auditor / approver | Test exact required routes, including export and write boundaries |
| Suspended account / revoked token | A fresh request using the old credential is refused |
| Recovery completed | Named login works and the initial owner path is closed |

Run these checks in disposable organizations with non-sensitive data; record failures
as limitations, not as a reason to broaden roles until the test passes. This table is a
verification plan, not a report of a completed live isolation audit.

Implementation: [role permissions](../cmd/dsse-edge/admin_auth_store.go),
[operator organization gate](../cmd/dsse-edge/operator_is_an_organization_not_a_role.go),
[elevated acts](../cmd/dsse-edge/operator_elevated_acts.go).
Continue with [Audit logs and data handling](audit-and-data.md).
