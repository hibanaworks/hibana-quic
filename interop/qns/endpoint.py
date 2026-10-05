#!/usr/bin/env python3
"""Pinned-runner endpoint adapter. Container execution is separately gated."""
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit

SUPPORTED = {'handshake', 'transfer', 'chacha20', 'resumption', 'zerortt', 'keyupdate'}

class Unsupported(ValueError):
    pass

def command(env, resolve=socket.getaddrinfo):
    case, role = env.get('TESTCASE', ''), env.get('ROLE', '')
    if case not in SUPPORTED:
        raise Unsupported(f'unsupported endpoint testcase: {case!r}')
    if role not in ('client', 'server'):
        raise ValueError('ROLE must be client or server')
    if env.get('CLIENT_PARAMS', '') or env.get('SERVER_PARAMS', ''):
        raise ValueError('extra parameter strings are not accepted or evaluated')
    args = ['/usr/local/bin/hibana-quic-hq', role]
    if case == 'keyupdate' and role == 'client':
        args += ['--key-update', 'once']
    if case == 'chacha20':
        args += ['--cipher', 'chacha20']
    if case in ('resumption', 'zerortt'):
        args += ['--session', 'resume']
    if case == 'zerortt':
        args += ['--early', 'buffered' if role == 'server' else 'replay-safe']
    if role == 'server':
        return args + ['--listen', '[::]:443', '--cert', '/certs/cert.pem',
                       '--key', '/certs/priv.key', '--www', '/www',
                       '--timeout-seconds', '120']
    requests = env.get('REQUESTS', '').split()
    if not requests:
        raise ValueError('client REQUESTS must contain at least one HTTPS URL')
    if case in ('resumption', 'zerortt') and len(requests) < 2:
        raise ValueError('resumption requires requests for two connections')
    origin = None
    for request in requests:
        url = urlsplit(request)
        if (url.scheme != 'https' or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment
                or not url.path.startswith('/') or '\\' in request):
            raise ValueError('invalid hq request URL')
        candidate = (url.hostname, url.port or 443)
        if origin is not None and origin != candidate:
            raise ValueError('one connection requires one exact request origin')
        origin = candidate
    host, port = origin
    answers = resolve(host, port, type=socket.SOCK_DGRAM)
    if not answers:
        raise ValueError('request host did not resolve')
    family, _, _, _, address = answers[0]
    if family == socket.AF_INET:
        target = f'{address[0]}:{port}'
    elif family == socket.AF_INET6:
        target = f'[{address[0]}]:{port}'
    else:
        raise ValueError('unsupported address family')
    args += ['--connect', target, '--server-name', host, '--ca', '/certs/ca.pem',
             '--downloads', '/downloads', '--timeout-seconds', '120']
    for request in requests:
        args += ['--request', request]
    return args

def main():
    try:
        args = command(os.environ)
    except Unsupported as error:
        print(error, file=sys.stderr)
        return 127
    except (ValueError, OSError) as error:
        print(f'endpoint configuration failed: {error}', file=sys.stderr)
        return 1
    # Run only inside the authorized QNS container. This adapter does not alter
    # host networking, install helpers, or try to bypass a denied route setup.
    try:
        subprocess.run(['/setup.sh'], check=True)
        if os.environ['ROLE'] == 'client':
            subprocess.run(['/wait-for-it.sh', 'sim:57832', '-s', '-t', '30'], check=True)
        Path('/logs').mkdir(exist_ok=True)
        print('qlog/keylog emission is not implemented; no files are fabricated', file=sys.stderr)
        # Diagnostic mode emits fixed public counters only, on existing activity;
        # it adds no protocol timer/wakeup and never exports TLS secret material.
        child_env = os.environ.copy()
        child_env['HIBANA_QUIC_DIAGNOSTICS'] = '1'
        with open(f"/logs/{os.environ['ROLE']}.log", 'ab', buffering=0) as log:
            return subprocess.run(args, stdout=log, stderr=log, check=False, env=child_env).returncode
    except (OSError, subprocess.CalledProcessError) as error:
        print(f'endpoint execution failed: {error}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
