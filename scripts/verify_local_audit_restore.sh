#!/usr/bin/env bash
# Exercise a cold backup and isolated restore of the installer's local audit store.
# Usage: verify_local_audit_restore.sh REPORT_DIR
set -euo pipefail

if [[ $# != 1 ]]; then
    echo 'Usage: verify_local_audit_restore.sh REPORT_DIR' >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
oss_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
report_dir=$1
mkdir -p -- "$report_dir"
report_dir=$(CDPATH= cd -- "$report_dir" && pwd)
chmod 700 "$report_dir"
if [[ -e "$report_dir/clickhouse-data.tar" || -e "$report_dir/SHA256SUMS" || -e "$report_dir/summary.json" ]]; then
    echo 'Report directory already contains audit-restore evidence; use a new directory' >&2
    exit 2
fi

clickhouse_image=$(python3 - "$oss_dir/cmd/dsse-install/compose.go" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
matches = re.findall(r'\$\{DSSE_CLICKHOUSE_IMAGE:-([^}]+)\}', text)
if len(matches) != 1 or not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', matches[0]):
    raise SystemExit('installer must have exactly one immutable ClickHouse default')
print(matches[0])
PY
)
copy_image='alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6'
fixture_password='dsse-local-restore-synthetic-only'
schema_dir="$oss_dir/cmd/dsse-install/clickhouse"
test_id="dsse-audit-restore-$(date -u +%Y%m%d%H%M%S)-$$"
source_container="$test_id-source"
restored_container="$test_id-restored"
source_volume="$test_id-source-data"
restored_volume="$test_id-restored-data"

cleanup() {
    docker rm -f "$source_container" "$restored_container" >/dev/null 2>&1 || true
    docker volume rm "$source_volume" "$restored_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

query() {
    docker exec "$1" clickhouse-client --user dsse --password "$fixture_password" \
        --database dsse --format TabSeparatedRaw --query "$2"
}
wait_ready() {
    local attempt
    for attempt in {1..60}; do
        if query "$1" 'SELECT 1' >/dev/null 2>&1 && \
           query "$1" "EXISTS TABLE dsse.events" 2>/dev/null | grep -qx 1 && \
           query "$1" "EXISTS TABLE dsse.events_rollup_5m" 2>/dev/null | grep -qx 1; then
            return 0
        fi
        sleep 1
    done
    echo 'ClickHouse or installer audit schema did not become ready' >&2
    return 1
}

docker volume create "$source_volume" >/dev/null
docker volume create "$restored_volume" >/dev/null
docker run -d --name "$source_container" \
    -e CLICKHOUSE_DB=dsse -e CLICKHOUSE_USER=dsse \
    -e CLICKHOUSE_PASSWORD="$fixture_password" \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    -v "$source_volume:/var/lib/clickhouse" \
    -v "$schema_dir:/docker-entrypoint-initdb.d:ro" \
    "$clickhouse_image" >/dev/null
wait_ready "$source_container"

docker exec -i "$source_container" clickhouse-client --user dsse \
    --password "$fixture_password" --database dsse --query \
    'INSERT INTO dsse.events (event_id, tenant_id, edge_region_id, ts, stream, finding_type, action, application_id, user_id, device_id, destination, identifier_types, instance_class, rule_id, raw) FORMAT JSONEachRow' <<'JSON'
{"event_id":"audit-a","tenant_id":"tenant-a","edge_region_id":"region-a","ts":"2026-10-19 00:00:00.000","stream":"audit","finding_type":"","action":"allow","application_id":"test","user_id":"user-a","device_id":"device-a","destination":"app-a","identifier_types":[],"instance_class":"","rule_id":"rule-a","raw":"{\"tenant_id\":\"tenant-a\",\"event_id\":\"audit-a\"}"}
{"event_id":"audit-b","tenant_id":"tenant-b","edge_region_id":"region-a","ts":"2026-10-19 00:00:00.000","stream":"audit","finding_type":"","action":"deny","application_id":"test","user_id":"user-b","device_id":"device-b","destination":"app-b","identifier_types":[],"instance_class":"","rule_id":"rule-b","raw":"{\"tenant_id\":\"tenant-b\",\"event_id\":\"audit-b\"}"}
JSON

[[ $(query "$source_container" 'SELECT count() FROM dsse.events') == 2 ]]
[[ $(query "$source_container" 'SELECT sum(events) FROM dsse.events_rollup_5m') == 2 ]]
source_a=$(query "$source_container" "SELECT raw FROM dsse.events WHERE tenant_id = 'tenant-a'")
source_b=$(query "$source_container" "SELECT raw FROM dsse.events WHERE tenant_id = 'tenant-b'")
[[ $source_a == '{"tenant_id":"tenant-a","event_id":"audit-a"}' ]]
[[ $source_b == '{"tenant_id":"tenant-b","event_id":"audit-b"}' ]]

# A cold copy is intentional: a live filesystem tar is not a consistent backup.
docker stop -t 30 "$source_container" >/dev/null
[[ $(docker inspect --format '{{.State.Running}}' "$source_container") == false ]]
docker run --rm -v "$source_volume:/data:ro" -v "$report_dir:/backup" \
    "$copy_image" sh -c 'cd /data && tar -cf /backup/clickhouse-data.tar .'
[[ -s "$report_dir/clickhouse-data.tar" ]]
chmod 600 "$report_dir/clickhouse-data.tar"
backup_hash=$(shasum -a 256 "$report_dir/clickhouse-data.tar" | awk '{print $1}')
printf '%s  clickhouse-data.tar\n' "$backup_hash" > "$report_dir/SHA256SUMS"
chmod 600 "$report_dir/SHA256SUMS"
(cd "$report_dir" && shasum -a 256 -c SHA256SUMS >/dev/null)
docker run --rm -v "$restored_volume:/data" -v "$report_dir:/backup:ro" \
    "$copy_image" sh -c 'cd /data && tar -xf /backup/clickhouse-data.tar'

docker run -d --name "$restored_container" \
    -e CLICKHOUSE_DB=dsse -e CLICKHOUSE_USER=dsse \
    -e CLICKHOUSE_PASSWORD="$fixture_password" \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    -v "$restored_volume:/var/lib/clickhouse" \
    -v "$schema_dir:/docker-entrypoint-initdb.d:ro" \
    "$clickhouse_image" >/dev/null
wait_ready "$restored_container"
[[ $(query "$restored_container" 'SELECT count() FROM dsse.events') == 2 ]]
[[ $(query "$restored_container" 'SELECT sum(events) FROM dsse.events_rollup_5m') == 2 ]]
[[ $(query "$restored_container" "SELECT raw FROM dsse.events WHERE tenant_id = 'tenant-a'") == "$source_a" ]]
[[ $(query "$restored_container" "SELECT raw FROM dsse.events WHERE tenant_id = 'tenant-b'") == "$source_b" ]]
[[ $(query "$restored_container" "SELECT count() FROM dsse.events WHERE tenant_id = 'tenant-a' AND event_id = 'audit-b'") == 0 ]]

query "$restored_container" \
    "INSERT INTO dsse.events (event_id, tenant_id, edge_region_id, ts, stream, finding_type, action, application_id, user_id, device_id, destination, identifier_types, instance_class, rule_id, raw) VALUES ('audit-after-restore', 'tenant-a', 'region-a', now64(3), 'audit', '', 'allow', 'test', 'user-a', 'device-a', 'app-a', [], '', 'rule-a', '{\"tenant_id\":\"tenant-a\",\"event_id\":\"audit-after-restore\"}')" >/dev/null
[[ $(query "$restored_container" 'SELECT count() FROM dsse.events') == 3 ]]
[[ $(query "$restored_container" 'SELECT sum(events) FROM dsse.events_rollup_5m') == 3 ]]

python3 - "$report_dir/summary.json" "$clickhouse_image" "$backup_hash" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    'passed': True,
    'mode': 'cold-local-clickhouse-volume',
    'image': sys.argv[2],
    'backup_sha256': sys.argv[3],
    'source_events': 2,
    'restored_events': 2,
    'events_after_new_write': 3,
    'rollups_restored_and_writable': True,
    'tenant_scoped_reads_verified': True,
}, indent=2, sort_keys=True) + '\n')
path.chmod(0o600)
PY
echo "Local audit backup/restore passed; report: $report_dir/summary.json"
