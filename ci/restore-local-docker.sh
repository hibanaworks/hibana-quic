#!/bin/sh
set -eu
if [ "$(id -u)" != 0 ]; then
    echo 'OS root privileges are required to restore the original Docker daemon.' >&2
    exit 1
fi
# A zombie is not a running daemon. Keep the existing image/storage directory.
for task_proc in /proc/[0-9]*; do
    [ -r "$task_proc/comm" ] && [ -r "$task_proc/stat" ] || continue
    [ "$(cat "$task_proc/comm")" = dockerd ] || continue
    [ "$(readlink "$task_proc/ns/user")" = "$(readlink /proc/self/ns/user)" ] || continue
    task_state=$(awk '{print $3}' "$task_proc/stat")
    [ "$task_state" = Z ] && continue
    echo "A live dockerd already exists at ${task_proc##*/}; inspect it before restarting." >&2
    exit 1
done
mkdir -p /run/codex-docker
if [ -f /run/codex-docker/dockerd.pid ]; then
    mv /run/codex-docker/dockerd.pid "/run/codex-docker/dockerd.pid.stale.$(date -u +%Y%m%dT%H%M%SZ)"
fi
exec /usr/local/bin/dockerd \
    --host=unix:///var/run/docker.sock \
    --pidfile=/run/codex-docker/dockerd.pid \
    --exec-root="/run/codex-docker/exec-direct-recovery-$(date -u +%Y%m%dT%H%M%SZ)" \
    --storage-driver=vfs \
    --group=agent \
    --allow-direct-routing=true
