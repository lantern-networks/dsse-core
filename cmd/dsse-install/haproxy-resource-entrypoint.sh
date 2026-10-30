#!/bin/sh
# Size using the memory visible to this process, not a DSSE connection ceiling.
set -eu
available=$(awk '$1 == "MemAvailable:" { printf "%.0f", $2 * 1024 }' /proc/meminfo)
test -n "$available" || { echo 'Cannot determine available host memory' >&2; exit 1; }
limit=max
used=0
if test -r /sys/fs/cgroup/memory.max; then
    limit=$(cat /sys/fs/cgroup/memory.max)
    used=$(cat /sys/fs/cgroup/memory.current)
elif test -r /sys/fs/cgroup/memory/memory.limit_in_bytes; then
    limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
    used=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes)
fi
memory_mb=$(awk -v available="$available" -v limit="$limit" -v used="$used" 'BEGIN {
    if (limit != "max" && limit + 0 > 0 && limit - used < available) available = limit - used;
    mb = int(available / 1048576);
    if (mb < 1) exit 1;
    printf "%.0f", mb;
}') || { echo 'Insufficient physical/cgroup memory for HAProxy' >&2; exit 1; }
ulimit -Sn "$(ulimit -Hn)"
echo "HAProxy resources: soft=$(ulimit -Sn) hard=$(ulimit -Hn) memory_mb=$memory_mb (available host/cgroup memory)"
# HAProxy uses its own buffer/SSL/per-connection model to derive maxconn and
# descriptor demand under -m. We do not guess bytes per FD or add a fixed count.
exec docker-entrypoint.sh haproxy -m "$memory_mb" -f /usr/local/etc/haproxy/haproxy.cfg
