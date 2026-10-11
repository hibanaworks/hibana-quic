#!/usr/bin/env bash
# Metadata only: never starts, stops, execs into, builds, pulls, or removes a container.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
  echo 'python3 is required for timeout-bounded, filtered Docker metadata inspection.' >&2
  exit 1
fi
exec python3 - "$@" <<'PY'
import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description='Read-only inventory of existing quic-interop-runner containers.')
parser.add_argument('--context', action='append', default=[], help='Only inspect this Docker context; repeatable.')
parser.add_argument('--timeout', type=float, default=12.0, help='Per Docker command timeout in seconds.')
args = parser.parse_args()
if not 0 < args.timeout <= 120:
    parser.error('--timeout must be in (0, 120]')

report = {
    'schema_version': 1,
    'generated_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
    'target_name': 'quic-interop-runner',
    'mode': 'metadata-only',
    'environment_overrides_present': {k: bool(os.getenv(k)) for k in ('DOCKER_HOST', 'DOCKER_CONTEXT')},
    'contexts': [],
    'exact_match_count': 0,
}

def run(prefix, tail):
    try:
        completed = subprocess.run(prefix + tail, text=True, capture_output=True,
                                   timeout=args.timeout, check=False)
        return completed.returncode, completed.stdout, completed.stderr.strip()[:1200]
    except subprocess.TimeoutExpired:
        return 124, '', 'Docker metadata request timed out.'
    except OSError as exc:
        return 126, '', str(exc)

if not shutil.which('docker'):
    report['status'] = 'DOCKER_CLI_UNAVAILABLE'
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(2)

if args.context:
    endpoints = [(name, ['docker', '--context', name]) for name in dict.fromkeys(args.context)]
else:
    # The first entry honors any environment-selected endpoint; named contexts are explicit.
    endpoints = [('effective-current-endpoint', ['docker'])]
    rc, output, error = run(['docker'], ['context', 'ls', '--format', '{{.Name}}'])
    if rc == 0:
        for name in dict.fromkeys(line.strip() for line in output.splitlines() if line.strip()):
            endpoints.append((name, ['docker', '--context', name]))
    else:
        report['context_list_error'] = {'exit_code': rc, 'message': error}

allowed_labels = ('com.docker.compose.project', 'com.docker.compose.service',
                  'com.docker.compose.project.working_dir', 'com.docker.compose.project.config_files')

for name, prefix in endpoints:
    entry = {'context': name}
    rc, output, error = run(prefix, ['container', 'inspect', 'quic-interop-runner'])
    entry['inspect_exit_code'] = rc
    if rc == 0:
        try:
            objects = json.loads(output)
            if not isinstance(objects, list):
                raise ValueError('Expected docker inspect JSON list.')
            exact = [obj for obj in objects if isinstance(obj, dict)
                     and obj.get('Name', '').lstrip('/') == 'quic-interop-runner']
            if not exact:
                raise ValueError('No exact container name in inspect response.')
            filtered = []
            for obj in exact:
                cfg = obj.get('Config') or {}
                host = obj.get('HostConfig') or {}
                labels = cfg.get('Labels') or {}
                state = obj.get('State') or {}
                mounts = obj.get('Mounts') or []
                filtered.append({
                    'id': obj.get('Id'), 'name': obj.get('Name'),
                    'image_id': obj.get('Image'), 'configured_image': cfg.get('Image'),
                    'status': state.get('Status'), 'running': state.get('Running'),
                    'working_dir': cfg.get('WorkingDir'),
                    'executable': obj.get('Path'),  # Deliberately omit full arguments and Env.
                    'privileged': host.get('Privileged'),
                    'network_mode': host.get('NetworkMode'),
                    'networks': list((obj.get('NetworkSettings') or {}).get('Networks', {}).keys()),
                    'compose': {key: labels[key] for key in allowed_labels if key in labels},
                    'mounts': [{key: m.get(key) for key in ('Type', 'Name', 'Source', 'Destination', 'RW')}
                               for m in mounts if isinstance(m, dict)],
                })
            entry['exact_matches'] = filtered
            report['exact_match_count'] += len(filtered)
        except (ValueError, TypeError, AttributeError) as exc:
            entry['parse_error'] = str(exc)
    else:
        entry['inspect_error'] = error
        rc_ps, out_ps, err_ps = run(prefix, ['ps', '-a', '--format', '{{json .}}'])
        entry['list_exit_code'] = rc_ps
        if rc_ps == 0:
            related = []
            for line in out_ps.splitlines():
                try:
                    obj = json.loads(line)
                    container_name = obj.get('Names', '')
                    if re.search(r'quic|neqo|^(server|client|sim)$', container_name, re.I):
                        related.append({key: obj.get(key) for key in ('ID', 'Names', 'Image', 'State', 'Status')})
                except (ValueError, AttributeError):
                    entry['list_parse_warning'] = True
            entry['related_containers'] = related
        else:
            entry['list_error'] = err_ps
    report['contexts'].append(entry)

report['status'] = 'EXACT_CONTAINER_FOUND' if report['exact_match_count'] else 'NOT_FOUND_OR_UNREACHABLE'
report['note'] = 'The effective endpoint and a named context may refer to the same daemon; deduplicate IDs before acting. No container state was changed.'
print(json.dumps(report, ensure_ascii=False, indent=2))
sys.exit(0 if report['exact_match_count'] else 2)
PY
