# Schemas

The contract-first JSON Schemas this implementation validates against. These files are the canonical form:
what the code reads is what is here.

## What is here


- `access_decision.schema.json`
- `policy.schema.json`
- `policy_bundle.schema.json`
- `access_log.schema.json`
- `audit_log.schema.json`
- `authentication_event.schema.json`
- `session.schema.json`
- `connector.schema.json`
- `connector_registration.schema.json`
- `connector_heartbeat.schema.json`
- `connector_tunnel.schema.json`
- `connector_log.schema.json`
- `tool_call_event.schema.json`
- `delegated_access_grant.schema.json`
- `human_approval_event.schema.json`
- `non_human_identity.schema.json`
- `mcp_server.schema.json`
- `agent_tool.schema.json`
- `inspection_profile.schema.json`
- `inspection_event.schema.json`
- `edge_region.schema.json`
- `edge_cluster.schema.json`
- `agent_config.schema.json`
- `agent_rollout_policy.schema.json`
- `agent_status.schema.json`
- `agent_update_event.schema.json`
- `trusted_keyring.schema.json`
- `protected_app_map.schema.json`
- `mdm_managed_app_config.schema.json`
- `signed_config_envelope.schema.json`
- `domain_event_outbox.schema.json`
- `domain_event_object_manifest.schema.json`
- `usage_meter.schema.json`

## How it is kept

- The JSON Schemas here are what the implementation reads; nothing else is canonical.
- A schema change updates the JSON file. Anything that describes the schema in prose follows it, not the
  other way round.

## Checking them

From the repository root, validate JSON syntax (not schema semantics) with:

```sh
for f in schemas/*.json; do python3 -m json.tool "$f" > /dev/null || echo "invalid: $f"; done
```
