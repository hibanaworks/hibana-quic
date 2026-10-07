#!/usr/bin/env python3
"""Unchanged pinned runner; separate implementation config, bounded safe evidence."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import tempfile
import tarfile
import shutil
import traceback

ROOT = Path(os.environ['ROOT']).resolve()
RUNNER = ROOT / '.ci-work/runner'
SAFE = ROOT / 'ci-safe-results'
RAW = ROOT / '.ci-work/raw'
EXPECTED = {'handshake', 'transfer'}
CASE_ABBREVIATIONS = {'handshake': 'H', 'transfer': 'DC', 'longrtt': 'LR', 'transferloss': 'L2', 'transfercorruption': 'C2', 'ipv6': '6', 'chacha20': 'C20', 'resumption': 'R', 'zerortt': 'Z', 'blackhole': 'B', 'keyupdate': 'U', 'amplificationlimit': 'A', 'handshakeloss': 'L1', 'handshakecorruption': 'C1', 'multiplexing': 'M', 'retry': 'S', 'ecn': 'E', 'v2': 'V2', 'rebind-port': 'BP', 'rebind-addr': 'BA'}
REFERENCE = 'neqo'
IMPLEMENTATIONS = {'neqo', 'quiche', 'hibana-quic'}
# Diagnostics are untrusted input, including logs produced by the peer. Nothing
# below copies a message, pathname, JSON key, or unknown enum into the artifact.
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_LOG_LINES = 65536
MAX_LINE_BYTES = 32768
MAX_JSON_BYTES = 16384
MAX_JSON_RECORDS = 256
MAX_JSON_SAMPLES = 16
MAX_DIRECTORY_ENTRIES = 64
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_BYTES = 1 << 40
MAX_COUNT = 1000000
ENDPOINT_ENUMS = {
    'event': {'hq_progress'}, 'stage': {'listener', 'connection'},
    'lifecycle': {'Listening', 'Active', 'Closing', 'Draining', 'Closed'},
    'status': {'success', 'failure', 'idle-expired'}, 'role': {'client', 'server'},
    'handshake_mode': {'full', 'resumed', 'fallback'},
    'authentication': {'peer-finished', 'cached-ticket-finished', 'verified-certificate'},
}
ENDPOINT_BOOLEANS = {'resources_retired', 'http_transfer_complete', 'lifecycle_closed', 'resumption_offered', 'resumed', 'handshake_complete', 'pending_work',
    'certificate_chain_hostname_time_verified'}
ENDPOINT_NUMBERS = {key: MAX_COUNT for key in (
    'connections', 'idle_expired_connections', 'key_generation', 'files_completed', 'streams_completed', 'live_streams', 'datagrams_sent',
    'datagrams_received', 'authenticated_packets', 'discarded_packets',
    'send_key_generation', 'authenticated_receive_key_generation',
    'connection_index', 'connection_generation', 'tickets_cached',
    'reactor_polls', 'reactor_waits', 'reactor_socket_events',
    'reactor_timer_events', 'reactor_wake_events')}
ENDPOINT_NUMBERS.update({'body_bytes': MAX_BYTES, 'duration_ms': 3600000,
    'elapsed_us': 3600000000, 'next_deadline_us': 3600000000, 'close_deadline_us': 3600000000})
ENDPOINT_CLASSES = {
    'panicked at': 'rust-panic', 'stack overflow': 'stack-overflow',
    'stack backtrace:': 'rust-backtrace', 'fatal runtime error:': 'runtime-fatal',
    'already borrowed': 'refcell-borrow', 'already mutably borrowed': 'refcell-borrow',
    'BorrowMutError': 'refcell-borrow', 'BorrowError': 'refcell-borrow',
    'deadline waiting for a fresh v1 Initial': 'initial-timeout',
    'deadline expired on connection ': 'connection-timeout',
    'connection retired before all expected files completed': 'incomplete-files',
    'peer closed before every expected file and stream completed': 'peer-closed-early',
    'endpoint configuration failed:': 'endpoint-configuration',
    'endpoint execution failed:': 'endpoint-execution',
    'server initial receive: non-native UDP source address': 'non-native-udp-source',
    'first packet:': 'first-packet', 'packet production:': 'packet-production',
    'packet receive:': 'packet-receive', 'bounded TLS:': 'bounded-tls',
    'Authentication': 'authentication', 'Certificate': 'certificate',
    'BufferTooSmall': 'buffer-too-small', 'Capacity': 'capacity',
    'ConnectionRefused': 'connection-refused', 'PermissionDenied': 'permission-denied',
}
RUNNER_PATTERNS = {
    'container-exit-abort': ('Aborting on container exit',),
    'simulator-assertion': ('assert failed.',),
    'simulator-fatal': ('NS_FATAL_ERROR',),
    'simulator-abort-condition': ('aborted. cond=',),
    'simulator-fatal-location': ('msg=', 'file=', 'line='),
    'address-in-use': ('Address already in use',),
    'address-unavailable': ('Cannot assign requested address',),
    'device-busy': ('Device or resource busy',),
    'operation-not-permitted': ('Operation not permitted',),
    'permission-denied': ('Permission denied',),
    'missing-command': ('command not found',),
    'missing-library': ('error while loading shared libraries',),
    'missing-file': ('No such file or directory',),
    'tap-open-failed': ('Could not open', '/dev/net/tun'),
    'tap-allocation-failed': ('Could not allocate tap interface',),
    'out-of-memory': ('Cannot allocate memory',),
    'allocation-failed': ('std::bad_alloc',),

    'simulator-started': ('Container sim', 'Started'),
    'simulator-starting': ('Container sim', 'Starting'),
    'simulator-startup-error': ('Error response from daemon', 'sim'),
    'simulator-wait-timeout': ('wait-for-it.sh: timeout occurred after', 'sim:57832'),
    'copy-simulator-log-failed': ('Copying logs from sim failed:',),
    'copy-client-log-failed': ('Copying logs from client failed:',),
    'copy-server-log-failed': ('Copying logs from server failed:',),
    'network-setup-failed': ('RTNETLINK answers:',),
    'network-create-failed': ('failed to create network',),
    'case-timeout': ('Test failed: took longer than ',),
    'file-length-mismatch': ('File size of ', "doesn't match. Original:"),
    'file-content-mismatch': ('File contents of ', 'do not match.'),
    'missing-files': ('Missing files:',),
    'unexpected-files': ('Found unexpected downloaded files:',),
    'file-compare-error': ('Could not compare files ',),
    'file-check-passed': ('Check of downloaded files succeeded.',),
    'capture-or-file-missing': ('testcase.check() threw FileNotFoundError:',),
    'handshake-count-mismatch': ('Expected exactly 1 handshake. Got:',),
    'two-handshake-count-mismatch': ('Expected exactly 2 handshakes. Got:',),
    'resumption-handshake-count-mismatch': ('Expected exactly 2 handshake. Got:',),
    'early-data-not-sent': ("Client didn't send any 0-RTT data.",),
    'early-late-payload-limit': ('Client sent too much data in 1-RTT packets.',),
    'resumption-unexpected-certificate': ('Server sent a Certificate message in the second handshake.',),
    'quic-version-mismatch': ('Wrong version. Expected',),
}
SAFE_VALIDATION_ERRORS = {'wrong QUIC version', 'wrong matrix direction', 'missing result row', 'unexpected/duplicate case', 'case abbreviation mismatch', 'missing case', 'unknown case result', 'invalid result file', 'invalid result schema'}
SAFE_EXCEPTION_TYPES = {'RuntimeError', 'ValueError', 'TypeError', 'FileNotFoundError',
    'PermissionError', 'OSError', 'TimeoutError', 'TimeoutExpired', 'CalledProcessError',
    'KeyError', 'AttributeError', 'ModuleNotFoundError', 'JSONDecodeError', 'RecursionError'}
CONSOLE_CLASSES = {'ModuleNotFoundError': 'python-dependency', 'unrecognized arguments:': 'runner-cli-arguments', 'No such file or directory': 'missing-tool-or-file', 'Cannot connect to the Docker daemon': 'docker-daemon-unavailable', 'Error response from daemon': 'docker-environment', 'no matching manifest': 'container-image-platform', 'permission denied': 'permission-denied', 'tshark not found': 'tshark-unavailable',
    'not compliant.': 'implementation-compliance-failed',
    'pull access denied': 'image-pull-denied', 'no such image': 'image-unavailable',
    'invalid reference format': 'image-reference-invalid',
    'unable to get image': 'image-resolution-failed',
    'client version': 'docker-api-client-version',
    'interface_name requires Docker Engine': 'docker-engine-interface-name-prerequisite',
    'unknown flag': 'docker-cli-flag', 'additional property': 'compose-schema',
    'must be a mapping': 'compose-schema', 'invalid interpolation': 'compose-interpolation',
    'failed to create network': 'docker-network-create',
    'pool overlaps': 'docker-network-overlap', 'ipv6 is disabled': 'docker-ipv6-disabled',
    'failed to create task': 'container-task-create', 'oci runtime': 'container-runtime',
    'executable file not found': 'container-executable',
    'address already in use': 'address-in-use', 'operation not permitted': 'operation-not-permitted'}

def console_classes(text):
    return sorted({label for pattern, label in CONSOLE_CLASSES.items() if pattern.lower() in text.lower()})

def _open_beneath(root, parts, directory=False):
    """Hold each directory descriptor; never follow even an ancestor symlink."""
    root = Path(root).absolute()
    components = root.parts[1:] + tuple(parts)
    if not components or any(p in ('', '.', '..') or '/' in p or '\\' in p for p in components):
        raise ValueError('unsafe diagnostic path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(components):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(components) - 1 or directory:
                flags |= os.O_DIRECTORY
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise

def _file_error(error):
    return 'missing' if isinstance(error, FileNotFoundError) else 'rejected-or-unreadable'

def diagnostic_file(root, parts, limit=MAX_LOG_BYTES, content=True):
    """Read/hash only regular, bounded files from an explicitly selected path."""
    fd = None
    try:
        fd = _open_beneath(root, parts)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            return {'state': 'rejected-nonregular-or-linked'}, None
        if not 0 <= before.st_size <= MAX_BYTES:
            return {'state': 'size-out-of-range'}, None
        metadata = {'state': 'present', 'bytes': before.st_size}
        if before.st_size > limit:
            metadata['state'] = 'too-large'
            return metadata, None
        digest, chunks, count = hashlib.sha256(), [], 0
        while count <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            digest.update(chunk)
            if content:
                chunks.append(chunk)
        after = os.fstat(fd)
        if count > limit or count != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            metadata['state'] = 'changed-or-too-large'
            return metadata, None
        metadata['sha256'] = digest.hexdigest()
        return metadata, b''.join(chunks) if content else None
    except (OSError, ValueError) as error:
        return {'state': _file_error(error)}, None
    finally:
        if fd is not None:
            os.close(fd)

def diagnostic_lines(raw):
    # Limits apply to bytes BEFORE decoding. No partial parse is reported as a
    # complete parse; oversized/invalid inputs retain only safe metadata/hash.
    if len(raw) > MAX_LOG_BYTES:
        return 'too-large', []
    lines = raw.splitlines()
    if len(lines) > MAX_LOG_LINES:
        return 'too-many-lines', []
    if any(len(line) > MAX_LINE_BYTES for line in lines):
        return 'line-too-large', []
    try:
        return 'parsed', [line.decode('utf-8') for line in lines]
    except UnicodeDecodeError:
        return 'invalid-utf8', []

def strict_json(raw, allow_floats=False):
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError('JSON size limit')
    def pairs(items):
        if len(items) > 128 or len({key for key, _ in items}) != len(items):
            raise ValueError('JSON duplicate key or object limit')
        return dict(items)
    def nonfinite(_):
        raise ValueError('JSON nonfinite number')
    data = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    def check(value, depth=0):
        if depth > 8:
            raise ValueError('JSON depth limit')
        if isinstance(value, dict):
            for child in value.values():
                check(child, depth + 1)
        elif isinstance(value, list):
            if len(value) > 128:
                raise ValueError('JSON array limit')
            for child in value:
                check(child, depth + 1)
        elif isinstance(value, float) and (not allow_floats or not math.isfinite(value)):
            # Endpoint reports are integer-only. The unchanged runner also has
            # finite start/end timestamps, which are parsed but never exported.
            raise ValueError('JSON noninteger or nonfinite number')
    check(data)
    return data

def withheld(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
    return {'withheld': True, 'sha256': hashlib.sha256(encoded).hexdigest()}

def endpoint_json(line):
    raw = line.encode('utf-8')
    summary = {'record_sha256': hashlib.sha256(raw).hexdigest()}
    try:
        data = strict_json(raw)
        if not isinstance(data, dict):
            raise ValueError('JSON object required')
    except (ValueError, RecursionError, UnicodeError):
        summary['state'] = 'invalid-or-oversized-json'
        return summary
    summary['state'] = 'parsed'
    for key, choices in ENDPOINT_ENUMS.items():
        if key in data:
            value = data[key]
            summary[key] = value if isinstance(value, str) and value in choices else withheld(value)
    for key in sorted(ENDPOINT_BOOLEANS):
        if key in data:
            value = data[key]
            summary[key] = value if type(value) is bool else withheld(value)
    for key, maximum in ENDPOINT_NUMBERS.items():
        if key in data:
            value = data[key]
            minimum = -1 if key in ('next_deadline_us', 'close_deadline_us') else 0
            summary[key] = value if type(value) is int and minimum <= value <= maximum else withheld(value)
    if 'error' in data:
        value = data['error']
        summary['error'] = withheld(value)
        if isinstance(value, str):
            summary['error_classes'] = sorted({label for pattern, label in ENDPOINT_CLASSES.items() if pattern in value})
            match = re.search(r'deadline expired on connection ([0-9]{1,6}): ([0-9]{1,6}) complete files, ([0-9]{1,6}) live;', value)
            if match:
                summary['timeout_progress'] = dict(zip(('connection_index', 'files_completed', 'live_streams'), map(int, match.groups())))
    known = set(ENDPOINT_ENUMS) | ENDPOINT_BOOLEANS | set(ENDPOINT_NUMBERS) | {'error'}
    unknown = {key: value for key, value in data.items() if key not in known}
    if unknown:
        summary['unknown_fields_count'] = len(unknown)
        summary['unknown_fields'] = withheld(unknown)
    return summary

def summarize_log(raw, endpoint=False):
    state, lines = diagnostic_lines(raw)
    record = {'parse_state': state}
    if state != 'parsed':
        return record
    record['line_count'] = len(lines)
    record['error_classes'] = sorted({label for pattern, label in ENDPOINT_CLASSES.items() if any(pattern in line for line in lines)})
    if endpoint:
        # Fixed native diagnostic grammar only. Retain the latest actual tap
        # sample per session and exact successful terminal fields, never raw
        # error strings, peer-controlled paths, or arbitrary JSON metadata.
        frontiers, terminals, traces, trace_capacities, clocks = {}, [], {}, [], {}
        frontier_count = terminal_count = frontier_samples_omitted = trace_count = 0
        for line in lines:
            match = re.fullmatch(r'connection-clock session=([0-9]{1,10}) now_us=([0-9]{1,13}) deadline_us=([0-9]{1,13}) stage=(requested|returned)', line)
            if match:
                session, now, deadline, stage = match.groups()
                if int(session) <= 0xffffffff and max(int(now), int(deadline)) <= 3600000000000:
                    if session in clocks or len(clocks) < 64:
                        clocks[session] = dict(session=int(session), now_us=int(now), deadline_us=int(deadline), stage=stage)
            match = re.fullmatch(r'connection-trace session=([0-9]{1,10}) ordinal=([0-9]{1,10}) event=(514|515|516) metadata=([0-9]{1,10})', line)
            if match:
                session, ordinal, event, metadata = map(int, match.groups())
                if max(session, ordinal, metadata) <= 0xffffffff:
                    trace_count += 1
                    if session in traces or len(traces) < 64:
                        tail = traces.setdefault(session, [])
                        tail.append(dict(ordinal=ordinal, event=event, metadata=metadata))
                        del tail[:-16]
            match = re.fullmatch(r'connection-trace-capacity session=([0-9]{1,10})', line)
            if match and int(match.group(1)) <= 0xffffffff and len(trace_capacities) < 64:
                trace_capacities.append(int(match.group(1)))
            match = re.fullmatch(r'connection-frontier session=([0-9]{1,10}) ordinal=([0-9]{1,10}) event=(514|515|516) metadata=([0-9]{1,10}) finished=(true|false) elapsed_ms=([0-9]{1,7}) sent=([0-9]{1,10}) received=([0-9]{1,10})', line)
            if match:
                session, ordinal, event, metadata, finished, elapsed, sent, received = match.groups()
                values = tuple(map(int, (session, ordinal, event, metadata, elapsed, sent, received)))
                if max(values[:4] + values[5:]) <= 0xffffffff and values[4] <= 3600000:
                    frontier_count += 1
                    if session in frontiers or len(frontiers) < 64:
                        frontiers[session] = dict(zip(('session', 'ordinal', 'event', 'metadata', 'elapsed_ms', 'sent', 'received'), values), finished=finished == 'true')
                    else:
                        frontier_samples_omitted += 1
            match = re.fullmatch(r'connection-terminal index=([0-9]{1,6}) idle=([0-9]{1,6}) confirmed=(true|false) completed=([0-9]{1,6}) submitted=([0-9]{1,6}) acked=(true|false) closed=(true|false) elapsed_ms=([0-9]{1,7})', line)
            if match:
                index, idle, confirmed, completed, submitted, acked, closed, elapsed = match.groups()
                if int(elapsed) <= 3600000:
                    terminal_count += 1
                    if len(terminals) < 64:
                        terminals.append(dict(index=int(index), idle=int(idle), confirmed=confirmed == 'true', completed=int(completed), submitted=int(submitted), acked=acked == 'true', closed=closed == 'true', elapsed_ms=int(elapsed)))
        record['latest_connection_clocks'] = list(clocks.values())
        record['connection_trace_records'] = trace_count
        record['connection_trace_tails'] = [dict(session=session, events=events) for session, events in traces.items()]
        record['connection_trace_capacity_sessions'] = trace_capacities
        record['connection_trace_records_omitted'] = trace_count - sum(map(len, traces.values()))
        record['frontier_sample_count'] = frontier_count
        record['frontier_samples_omitted_for_capacity'] = frontier_samples_omitted
        record['latest_connection_frontiers'] = list(frontiers.values())
        record['connection_terminal_count'] = terminal_count
        record['connection_terminals'] = terminals
        record['connection_terminals_omitted'] = terminal_count - len(terminals)
        json_lines = [line.strip() for line in lines if line.lstrip().startswith('{')]
        record['json_record_count'] = len(json_lines)
        if len(json_lines) > MAX_JSON_RECORDS:
            record['json_state'] = 'too-many-records'
            record['json_records'] = []
        else:
            record['json_state'] = 'parsed'
            # First and latest samples preserve listener startup, the latest
            # stall position and final report without exporting an unbounded
            # timeline. Sampling does not alter any runner verdict.
            selected = json_lines if len(json_lines) <= MAX_JSON_SAMPLES else json_lines[:1] + json_lines[-(MAX_JSON_SAMPLES - 1):]
            record['json_records_omitted'] = len(json_lines) - len(selected)
            record['json_records'] = [endpoint_json(line) for line in selected]
        return record
    record['runner_classes'] = sorted(label for label, patterns in RUNNER_PATTERNS.items() if any(all(pattern in line for pattern in patterns) for line in lines))
    record['console_error_classes'] = console_classes('\n'.join(lines))
    exits = {role: set() for role in ('client', 'server', 'sim')}
    timeouts = []
    for line in lines:
        # Compose's fixed container names, never prefixes/peer-supplied names.
        for match in re.finditer(r'(?<![A-Za-z0-9_-])(client|server|sim) exited with code ([0-9]{1,3})(?![0-9])', line):
            role, code = match.groups()
            if int(code) <= 255:
                exits[role].add(int(code))
        timeouts += [int(value) for value in re.findall(r'Test failed: took longer than ([0-9]{1,4})s\.', line)]
    record['container_exit_codes'] = {role: sorted(codes) for role, codes in exits.items()}
    record['case_timeout_count'] = len(timeouts)
    record['case_timeout_seconds'] = sorted(set(timeouts))
    # Fixed runner diagnostics only. Never export log text, paths or secrets.
    # These counters explain a verdict; they cannot override the runner result.
    early_sizes = {label: set() for label in ('zero_rtt_payload_bytes', 'one_rtt_payload_bytes')}
    for line in lines:
        for label, marker in (('zero_rtt_payload_bytes', '0-RTT size:'), ('one_rtt_payload_bytes', '1-RTT size:')):
            match = re.search(re.escape(marker) + r' ([0-9]{1,13})(?![0-9])(?:\s|$)', line)
            if match and int(match.group(1)) <= MAX_BYTES and len(early_sizes[label]) < MAX_JSON_SAMPLES:
                early_sizes[label].add(int(match.group(1)))
    record['early_payload_diagnostics'] = {label: sorted(values) for label, values in early_sizes.items() if values}
    return record

def directory_sizes(root, parts):
    """Fixed runner application directory; metadata only, no names exported."""
    fd = None
    try:
        fd = _open_beneath(root, parts, directory=True)
        entries, sizes = 0, {}
        with os.scandir(fd) as children:
            for child in children:
                entries += 1
                if entries > MAX_DIRECTORY_ENTRIES:
                    return {'state': 'too-many-entries'}, None
                info = child.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= MAX_BYTES:
                    return {'state': 'rejected-entry'}, None
                sizes[child.name] = info.st_size
        if sum(sizes.values()) > MAX_BYTES:
            return {'state': 'size-out-of-range'}, None
        return {'state': 'present', 'file_count': len(sizes), 'total_bytes': sum(sizes.values()), 'file_sizes': sorted(sizes.values())}, sizes
    except (OSError, ValueError) as error:
        return {'state': _file_error(error)}, None
    finally:
        if fd is not None:
            os.close(fd)

# Public numeric dissector fields only; no TLS keys, payload, CID, address,
# hostname or arbitrary protocol text is exported. Field names verified against
# https://www.wireshark.org/docs/dfref/q/quic.html . Coalesced values are kept as
# independent lists: their positions do not imply cross-field correspondence.
CAPTURE_FIELDS = (
    'frame.number', 'frame.time_relative', 'udp.srcport', 'udp.dstport',
    'quic.connection.number', 'quic.long.packet_type', 'quic.packet_number',
    'quic.frame_type', 'quic.crypto.offset', 'quic.crypto.length',
    'quic.ack.largest_acknowledged', 'quic.ack.first_ack_range',
    'quic.ack.gap', 'quic.ack.ack_range',
)
MAX_CAPTURE_ROWS = 8192

def numeric_capture_rows(raw):
    state, lines = diagnostic_lines(raw)
    if state != 'parsed':
        return {'state': state}
    if len(lines) > MAX_CAPTURE_ROWS:
        return {'state': 'too-many-rows'}
    rows = []
    for line in lines:
        values = line.split('\t')
        if len(values) != len(CAPTURE_FIELDS):
            return {'state': 'invalid-fields'}
        row = {}
        for field, value in zip(CAPTURE_FIELDS, values):
            if not value:
                continue
            if field == 'frame.time_relative':
                if not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,9})?', value):
                    return {'state': 'invalid-time'}
                seconds, _, fraction = value.partition('.')
                row['time_us'] = int(seconds) * 1000000 + int((fraction + '000000')[:6])
                continue
            items = value.split(',')
            if len(items) > 64 or any(not re.fullmatch(r'(?:[0-9]{1,19}|0x[0-9a-fA-F]{1,16})', item) for item in items):
                return {'state': 'invalid-number'}
            numbers = [int(item, 16 if item.startswith('0x') else 10) for item in items]
            if any(number > (1 << 62) - 1 for number in numbers):
                return {'state': 'number-out-of-range'}
            row[field] = numbers
        rows.append(row)
    return {'state': 'parsed', 'rows': rows,
            'scope': 'numeric QUIC observations; payload and key material withheld',
            'frame_scan_limit': MAX_CAPTURE_ROWS,
            'complete_capture_not_claimed': True,
            'coalesced_fields_are_independent_lists': True}

def capture_observations(root, parts, key_parts=None):
    fd = key_fd = None
    key_state = 'not-requested'
    try:
        fd = _open_beneath(root, parts)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_CAPTURE_BYTES:
            return {'state': 'rejected-capture'}
        # The pinned runner already creates ephemeral test-connection keys.
        # Use only the fixed reference role's file inside this same CI process;
        # never read it into a report or publish its bytes/hash/path. No endpoint
        # key logging is added and no credential leaves the runner environment.
        if key_parts is not None:
            try:
                key_fd = _open_beneath(root, key_parts)
                info = os.fstat(key_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 1024 * 1024:
                    os.close(key_fd)
                    key_fd = None
                    key_state = 'rejected'
                else:
                    key_state = 'supplied-locally'
            except (OSError, ValueError):
                key_state = 'unavailable'
        key_option = 'tls.keylog_file:' + (('/proc/self/fd/' + str(key_fd)) if key_fd is not None else '')
        command = ['tshark', '-n', '-r', '/proc/self/fd/' + str(fd),
                   '-c', str(MAX_CAPTURE_ROWS), '-o', key_option,
                   '-Y', 'quic',
                   '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=a']
        for field in CAPTURE_FIELDS:
            command.extend(['-e', field])
        # A bounded capture plus a finite native tool timeout; output remains
        # private even on tool failure. Never export stderr or partial output.
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL,
                                    pass_fds=(fd,) + ((key_fd,) if key_fd is not None else ()), timeout=20, check=False)
            if result.returncode != 0:
                return {'state': 'dissector-failed'}
            if output.tell() > MAX_LOG_BYTES:
                return {'state': 'too-large'}
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                return {'state': 'changed-capture'}
            output.seek(0)
            parsed = numeric_capture_rows(output.read(MAX_LOG_BYTES + 1))
            parsed['reference_keylog'] = key_state
            return parsed
    except subprocess.TimeoutExpired:
        return {'state': 'dissector-timeout'}
    except (OSError, ValueError) as error:
        return {'state': _file_error(error)}
    finally:
        if key_fd is not None:
            os.close(key_fd)
        if fd is not None:
            os.close(fd)

def preserve_failed_capture(logs, client, server, phase_name, status):
    """Retain synthetic failure evidence only as authenticated ciphertext.

    The recipient private key never exists in CI or this repository. Plaintext
    lives only in unlinked temporary files, never in the uploaded directory.
    """
    if status == 'PASSED':
        return {'state': 'not-needed'}
    if client not in IMPLEMENTATIONS or server not in IMPLEMENTATIONS or phase_name not in {'bounded-client', 'bounded-server', 'quiche-baseline', 'neqo-baseline'}:
        return {'state': 'invalid-scope'}
    try:
        recipient = json.loads((ROOT / 'ci/failure-recipient.json').read_text())['certificate']
        if not isinstance(recipient, str) or len(recipient) > 8192 or 'PRIVATE KEY' in recipient or not recipient.startswith('-----BEGIN CERTIFICATE-----'):
            return {'state': 'invalid-recipient'}
        manifest = []
        with tempfile.TemporaryFile() as plain, tempfile.TemporaryFile() as encrypted, tempfile.TemporaryFile() as certificate:
            certificate.write(recipient.encode('ascii'))
            certificate.flush()
            with tarfile.open(fileobj=plain, mode='w') as archive:
                for case in sorted(EXPECTED):
                    if case not in CASE_ABBREVIATIONS:
                        return {'state': 'invalid-case'}
                    prefix = (server + '_' + client, case)
                    sources = [(('sim', 'trace_node_' + side + '.pcap'), MAX_CAPTURE_BYTES) for side in ('left', 'right')]
                    sources += [((role, filename), limit) for role in ('client', 'server') for filename, limit in [('keys.log', 1024 * 1024), ('log.txt', MAX_LOG_BYTES), (role + '.log', MAX_LOG_BYTES)]]
                    for parts, limit in sources:
                        fd = None
                        name = '/'.join((case,) + parts)
                        try:
                            fd = _open_beneath(logs, prefix + parts)
                            before = os.fstat(fd)
                            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= limit:
                                manifest.append({'file': name, 'state': 'rejected'})
                                continue
                            info = tarfile.TarInfo(name)
                            info.size, info.mode, info.mtime = before.st_size, 0o600, 0
                            with os.fdopen(os.dup(fd), 'rb') as source:
                                archive.addfile(info, source)
                            after = os.fstat(fd)
                            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                                return {'state': 'changed-input'}
                            manifest.append({'file': name, 'state': 'included', 'bytes': before.st_size})
                        except (OSError, ValueError):
                            manifest.append({'file': name, 'state': 'unavailable'})
                        finally:
                            if fd is not None:
                                os.close(fd)
                data = json.dumps({'phase': phase_name, 'status': status, 'files': manifest}).encode()
                import io
                info = tarfile.TarInfo('manifest.json')
                info.size, info.mode, info.mtime = len(data), 0o600, 0
                archive.addfile(info, io.BytesIO(data))
            plain.flush()
            plain.seek(0)
            command = ['openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm',
                       '-in', '/proc/self/fd/' + str(plain.fileno()), '-outform', 'DER',
                       '-out', '/proc/self/fd/' + str(encrypted.fileno()),
                       '/proc/self/fd/' + str(certificate.fileno())]
            certificate.seek(0)
            result = subprocess.run(command, pass_fds=(plain.fileno(), encrypted.fileno(), certificate.fileno()),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
            if result.returncode:
                return {'state': 'encryption-failed'}
            encrypted.seek(0, 2)
            size = encrypted.tell()
            if not 128 <= size <= len(EXPECTED) * (2 * MAX_CAPTURE_BYTES + 4 * MAX_LOG_BYTES + 4 * 1024 * 1024):
                return {'state': 'invalid-ciphertext-size'}
            encrypted.seek(0)
            name = phase_name + '-failure.cms'
            SAFE.mkdir(exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=SAFE, prefix='.ciphertext-', delete=False) as stage:
                staged = Path(stage.name)
                try:
                    shutil.copyfileobj(encrypted, stage)
                    stage.flush()
                    os.replace(staged, SAFE / name)
                finally:
                    staged.unlink(missing_ok=True)
            return {'state': 'encrypted', 'artifact': name, 'bytes': size,
                    'format': 'CMS AuthEnvelopedData AES-256-GCM',
                    'plaintext_not_published': True}
    except subprocess.TimeoutExpired:
        return {'state': 'encryption-timeout'}
    except (OSError, ValueError, KeyError, UnicodeError, tarfile.TarError):
        return {'state': 'preservation-failed'}

def collect_case_diagnostics(logs, client, server):
    if client not in IMPLEMENTATIONS or server not in IMPLEMENTATIONS:
        return {'state': 'invalid-matrix-identifiers'}
    cases = {}
    for case in sorted(EXPECTED):
        prefix = (server + '_' + client, case)
        record = {}
        for label, suffix in (('runner_output', ('output.txt',)), ('client_log', ('client', 'client.log')), ('server_log', ('server', 'server.log')), ('simulator_log', ('sim', 'sim.log'))):
            metadata, raw = diagnostic_file(logs, prefix + suffix)
            if raw is not None:
                metadata.update(summarize_log(raw, endpoint=label in ('client_log', 'server_log')))
            record[label] = metadata
        record['captures'] = {}
        for side in ('left', 'right'):
            metadata, _ = diagnostic_file(logs, prefix + ('sim', 'trace_node_' + side + '.pcap'), limit=MAX_CAPTURE_BYTES, content=False)
            if metadata.get('state') == 'present':
                reference_keys = prefix + (('server' if server == 'quiche' else 'client'), 'keys.log') if 'quiche' in (client, server) else None
                metadata['quic_observations'] = capture_observations(logs, prefix + ('sim', 'trace_node_' + side + '.pcap'), reference_keys)
            record['captures'][side] = metadata
        record['application_files'] = {}
        for source_role, destination_role in (('server', 'client'), ('client', 'server')):
            source, expected = directory_sizes(logs, prefix + (source_role + '_www',))
            downloads, received = directory_sizes(logs, prefix + (destination_role + '_downloads',))
            if expected is not None and received is not None:
                complete = [size for name, size in received.items() if name in expected and size == expected[name]]
                partial = [size for name, size in received.items() if (name in expected and size != expected[name]) or re.fullmatch(r'\.hibana-[0-9a-f]{16}\.part', name)]
                downloads.update({'length_complete_files': len(complete), 'length_complete_bytes': sum(complete),
                    'partial_files': len(partial), 'partial_bytes': sum(partial),
                    'unclassified_files': len(received) - len(complete) - len(partial),
                    'missing_expected_files': sum(name not in received for name in expected),
                    'length_only_not_content_verified': True})
            record['application_files'][source_role + '_www'] = source
            record['application_files'][destination_role + '_downloads'] = downloads
        cases[case] = record
    return cases

def code_frame(filename, line, function):
    # Source locations only. No source lines, locals, exception messages or data.
    path = Path(filename)
    module = 'external-source-withheld'
    for name in ('interop.py', 'run.py', 'testcase.py', 'testcases_quic.py', 'trace.py', 'implementations.py', 'result.py'):
        if path == RUNNER / name:
            module = 'runner/' + name
    if path == ROOT / 'ci/run_in_tools.py':
        module = 'ci/run_in_tools.py'
    return {'source': module, 'line': int(line) if 0 <= int(line) <= 1000000 else None,
        'location_sha256': withheld([filename, line, function])['sha256']}

def traceback_evidence(text):
    clean = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text)
    records, current = [], None
    for line in clean.splitlines():
        if line.strip() == 'Traceback (most recent call last):':
            current = {'frames': []}
        elif current is not None:
            frame = re.fullmatch(r'\s*File "([^"\n]+)", line ([0-9]{1,7}), in ([A-Za-z0-9_<>]+)\s*', line)
            if frame and len(current['frames']) < 24:
                current['frames'].append(code_frame(*frame.groups()))
            error = re.match(r'^([A-Za-z_][A-Za-z0-9_.]{0,99})(?::|$)', line)
            if error:
                value = error.group(1)
                current['exception_type'] = value if value in SAFE_EXCEPTION_TYPES else withheld(value)
                records.append(current)
                current = None
    if current and current['frames']:
        current['exception_type'] = 'unparsed-withheld'
        records.append(current)
    return records[-4:]

def docker_metadata():
    # Only fixed fields/classifications are published, never subprocess output.
    proc = subprocess.run(['docker', 'version', '--format', '{{json .Server}}'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    record = {'version_exit_code': proc.returncode,
        'error_classes': console_classes(proc.stderr), 'effective_uid': os.geteuid(),
        'runner_owner_uid': RUNNER.stat().st_uid,
        'socket_gid': Path('/var/run/docker.sock').stat().st_gid,
        'process_groups': os.getgroups()}
    if proc.returncode == 0:
        data = json.loads(proc.stdout)
        record['server'] = {key: data.get(key) for key in ('Version', 'ApiVersion', 'MinAPIVersion', 'GitCommit')}
    record['images'] = {}
    for key in ('REFERENCE_IMAGE', 'BOUNDED_IMAGE', 'SIM_IMAGE'):
        image = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', os.environ[key]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        value = image.stdout.strip()
        record['images'][key] = {'exit_code': image.returncode,
            'id': value if re.fullmatch(r'sha256:[a-f0-9]{64}', value) else None,
            'error_classes': console_classes(image.stderr)}
    write('docker-preflight.json', record)
    require(proc.returncode == 0 and all(v['exit_code'] == 0 and v['id'] for v in record['images'].values()), 'docker preflight failed')

def write(name, value):
    (SAFE / name).write_text(json.dumps(value, indent=2) + '\n')

def require(test, message):
    if not test:
        raise RuntimeError(message)

def checked_result(path, client, server):
    metadata, raw = diagnostic_file(path.parent, (path.name,), limit=MAX_JSON_BYTES)
    require(raw is not None, 'invalid result file')
    data = strict_json(raw, allow_floats=True)
    require(isinstance(data, dict), 'invalid result schema')
    require(data.get('quic_version') == '0x1', 'wrong QUIC version')
    require(data.get('clients') == [client] and data.get('servers') == [server], 'wrong matrix direction')
    rows = data.get('results')
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], list), 'missing result row')
    seen = set()
    normalized = []
    for entry in rows[0]:
        name, result, abbr = entry.get('name'), entry.get('result'), entry.get('abbr')
        require(name in EXPECTED and name not in seen, 'unexpected/duplicate case')
        require(abbr == CASE_ABBREVIATIONS[name] and data.get('tests', {}).get(abbr, {}).get('name') == name, 'case abbreviation mismatch')
        require(result in (None, 'succeeded', 'failed', 'unsupported'), 'unknown case result')
        seen.add(name)
        normalized.append({'name': name, 'result': result, 'abbr': abbr})
    require(seen == EXPECTED, 'missing case')
    return {'quic_version': '0x1', 'client': client, 'server': server,
            'results': normalized, 'original_json_sha256': metadata['sha256'],
            'non_null_case_results': sum(item['result'] is not None for item in normalized),
            'unexecuted_case_results': sum(item['result'] is None for item in normalized),
            'passed': all(item['result'] == 'succeeded' for item in normalized)}

def setup_workdir(name, candidate):
    work = ROOT / '.ci-work' / name
    work.mkdir()
    # Only registration/config lives outside the untouched source checkout.
    for path in RUNNER.iterdir():
        if path.name not in ('.git', 'implementations_quic.json'):
            (work / path.name).symlink_to(path)
    config = json.loads((RUNNER / 'implementations_quic.json').read_text())
    config[REFERENCE]['image'] = os.environ['REFERENCE_IMAGE']
    if candidate:
        config['hibana-quic'] = {'image': os.environ['BOUNDED_IMAGE'],
            'url': 'https://github.com/hibanaworks/hibana-quic', 'role': 'both'}
    (work / 'implementations_quic.json').write_text(json.dumps(config, indent=2) + '\n')
    overlay = work / 'pinned-images.override.yml'
    overlay.write_text('services:\n  sim:\n    image: ' + os.environ['SIM_IMAGE'] + '\n    pull_policy: never\n')
    return work, overlay

def phase(name, client, server, candidate):
    work, overlay = setup_workdir(name, candidate)
    output = RAW / (name + '.json')
    logs = RAW / (name + '-logs')
    console = RAW / (name + '-console.log')
    env = os.environ.copy()
    env['COMPOSE_FILE'] = str(RUNNER / 'docker-compose.yml') + ':' + str(overlay)
    env['COMPOSE_PROJECT_NAME'] = 'hibana-pilot'
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    cmd = [sys.executable, str(RUNNER / 'run.py'), '-s', server, '-c', client,
           '-d', '-t', ','.join(sorted(EXPECTED)), '-n', client + ',' + server,
           '-j', str(output), '-l', str(logs), '-f', 'true']
    record = {'phase': name, 'client': client, 'server': server, 'status': 'NOT_RUN'}
    started = time.monotonic()
    try:
        print('Starting ' + name, flush=True)
        with console.open('wb') as log:
            proc = subprocess.run(cmd, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        record['exit_code'] = proc.returncode
        record.update(checked_result(output, client, server))
        record['status'] = 'PASSED' if proc.returncode == 0 and record['passed'] else 'FAILED'
    except subprocess.TimeoutExpired:
        record['status'] = 'TIMEOUT'
    except Exception as error:
        record['status'] = 'INFRASTRUCTURE_OR_RESULT_FAILURE'
        # Only our bounded validation/exception class, never raw peer logs.
        record['error_type'] = type(error).__name__
        if isinstance(error, RuntimeError) and str(error) in SAFE_VALIDATION_ERRORS:
            record['validation_reason'] = str(error)
    finally:
        try:
            cleanup = subprocess.run(['docker', 'compose', '--env-file', 'empty.env', 'down', '--timeout', '1'], cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            record['cleanup_exit_code'] = cleanup.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            record['cleanup_error_type'] = type(error).__name__
        metadata, raw = diagnostic_file(RAW, (name + '-console.log',))
        record['console_file'] = metadata
        if raw is not None:
            parse_state, lines = diagnostic_lines(raw)
            record['console_parse_state'] = parse_state
            # Startup/copy errors can prevent creation of the per-case tree.
            record['console_diagnostics'] = summarize_log(raw)
            text = '\n'.join(lines)
            record['runner_log_sha256'] = metadata['sha256']
            record['console_error_classes'] = console_classes(text)
            record['runner_tracebacks'] = traceback_evidence(text)
            record['runner_progress'] = {
                'server_compliance_passed': server + ' server compliant.' in text,
                'client_compliance_passed': client + ' client compliant.' in text,
                'announced_cases': sorted(name for name in EXPECTED if 'Running test case: ' + name in text)}
        record['duration_seconds'] = round(time.monotonic() - started, 3)
        # Fixed paths only; keys, certificates, tickets, qlogs, raw messages and
        # filenames are never copied. Application bodies stay in the raw tree.
        record['case_diagnostics'] = collect_case_diagnostics(logs, client, server)
        record['captures'] = [dict(metadata, case=case, side=side)
            for case, evidence in record['case_diagnostics'].items()
            for side, metadata in evidence['captures'].items()
            if metadata['state'] == 'present']
        record['private_failure_capture'] = preserve_failed_capture(logs, client, server, name, record['status'])
        write(name + '.json', record)
        write(name + '-verdict.json', {key: record[key] for key in (
            'phase', 'client', 'server', 'status', 'exit_code', 'cleanup_exit_code',
            'passed', 'results', 'non_null_case_results', 'unexecuted_case_results',
            'original_json_sha256') if key in record})
        print(name + ': ' + record['status'], flush=True)
    return record

def requested_cases(value):
    require(isinstance(value, list) and value and all(isinstance(x, str) for x in value), 'invalid requested cases')
    require(len(value) == len(set(value)), 'duplicate requested case')
    require(set(value) <= set(CASE_ABBREVIATIONS), 'unqualified requested case')
    return set(value)

def requested_directions(value):
    require(isinstance(value, list) and value and all(isinstance(x, str) for x in value), 'invalid candidate directions')
    require(len(value) == len(set(value)), 'duplicate candidate direction')
    require(set(value) <= {'client', 'server'}, 'unknown candidate direction')
    return set(value)

def requested_reference(value):
    require(isinstance(value, str) and value in {'neqo', 'quiche'}, 'unknown reference implementation')
    return value

def qualification_groups(request):
    directions = requested_directions(request.get('candidate_directions'))
    require(directions == {'client', 'server'}, 'matrix requires both candidate directions')
    groups = request.get('groups')
    require(isinstance(groups, list) and groups, 'missing qualification groups')
    names, cases = set(), set()
    for group in groups:
        require(isinstance(group, dict), 'invalid qualification group')
        name = group.get('name')
        require(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', name), 'invalid qualification group name')
        require(name not in names, 'duplicate qualification group')
        names.add(name)
        requested_reference(group.get('reference_implementation'))
        selected = requested_cases(group.get('cases'))
        require(not cases & selected, 'duplicate matrix case')
        cases.update(selected)
    require(cases == set(CASE_ABBREVIATIONS), 'incomplete qualification matrix')
    require(len(cases) * len(directions) == request.get('candidate_case_direction_results') == 40,
            'qualification matrix must contain 40 candidate results')
    return groups

def selected_request(request, group_name):
    if 'groups' not in request:
        require(group_name is None, 'group supplied for a single pilot')
        return request
    groups = qualification_groups(request)
    selected = [group for group in groups if group['name'] == group_name]
    require(len(selected) == 1, 'unknown qualification group')
    return dict(request, **selected[0])

def verify_matrix(directory, source_commit, run_id, run_attempt):
    request = json.loads((ROOT / 'ci/interop-request.json').read_text())
    groups = qualification_groups(request)
    require(re.fullmatch(r'[0-9a-f]{40}', source_commit or ''), 'invalid source commit')
    require(re.fullmatch(r'[0-9]+', run_id or '') and re.fullmatch(r'[0-9]+', run_attempt or ''), 'invalid run identity')
    SAFE.mkdir(exist_ok=True)
    write('summary.json', {'status': 'NOT_PASSED', 'source_commit': source_commit,
                          'run_id': run_id, 'run_attempt': run_attempt,
                          'expected_candidate_results': 40, 'same_commit_all_40_executed': False})
    expected_pins = dict(line.split('=', 1) for line in (ROOT / 'ci/pins.env').read_text().splitlines()
                         if line and not line.startswith('#'))
    cells, controls, verified_groups = [], [], []
    simulator, quiche_image = None, None
    all_passed = True
    for group in groups:
        artifact = 'interop-pilot-' + run_id + '-' + run_attempt + '-' + group['name']
        def read(name):
            metadata, raw = diagnostic_file(directory, (artifact, name), limit=MAX_JSON_BYTES)
            require(raw is not None, 'missing or invalid matrix artifact')
            value = strict_json(raw, allow_floats=True)
            require(isinstance(value, dict), 'invalid matrix artifact schema')
            return value
        environment, pins, summary = read('environment.json'), read('pins.json'), read('summary.json')
        require(environment.get('source_commit') == source_commit, 'matrix source commit mismatch')
        require(str(environment.get('run_id')) == run_id and str(environment.get('run_attempt')) == run_attempt, 'matrix run identity mismatch')
        require(environment.get('interop_group') == group['name'] and summary.get('interop_group') == group['name'], 'matrix group identity mismatch')
        reference = group['reference_implementation']
        require(pins.get('REFERENCE_IMPLEMENTATION') == reference, 'matrix reference mismatch')
        for key in ('RUNNER_REVISION', 'HIBANA_REVISION', 'RUST_IMAGE', 'ENDPOINT_IMAGE', 'UBUNTU_IMAGE',
                    'PYTHON_IMAGE', 'DOCKER_ENGINE_VERSION', 'DOCKER_CLI_DEB_SHA256', 'DOCKER_ENGINE_DEB_SHA256'):
            require(pins.get(key) == expected_pins[key], 'matrix pin mismatch')
        if reference == 'neqo':
            require(pins.get('NEQO_REVISION') == expected_pins['NEQO_REVISION'], 'matrix Neqo pin mismatch')
        else:
            image = pins.get('REFERENCE_IMAGE')
            require(isinstance(image, str) and re.fullmatch(r'cloudflare/quiche-qns@sha256:[0-9a-f]{64}', image), 'matrix quiche image invalid')
            if quiche_image is None:
                quiche_image = image
            require(image == quiche_image, 'matrix quiche image changed')
        image = pins.get('SIM_IMAGE')
        require(isinstance(image, str) and re.fullmatch(r'martenseemann/quic-network-simulator@sha256:[0-9a-f]{64}', image), 'matrix simulator image invalid')
        if simulator is None:
            simulator = image
        require(image == simulator, 'matrix simulator image changed')
        expected = requested_cases(group['cases'])
        require(summary.get('selected_cases') == sorted(expected), 'matrix case scope mismatch')
        require(summary.get('candidate_directions') == ['client', 'server'], 'matrix direction scope mismatch')
        require(summary.get('reference_implementation') == reference and summary.get('runner_source_unchanged') is True, 'matrix runner or reference mismatch')
        phases = [reference + '-baseline', 'bounded-client', 'bounded-server']
        require(summary.get('phases') == phases, 'matrix missing execution phase')
        phase_passed, baseline_passed, non_null = [], False, 0
        for phase, client, server in [(phases[0], reference, reference), ('bounded-client', 'hibana-quic', reference), ('bounded-server', reference, 'hibana-quic')]:
            result = read(phase + '-verdict.json')
            require(result.get('phase') == phase and result.get('client') == client and result.get('server') == server, 'matrix phase direction mismatch')
            rows = result.get('results')
            require(isinstance(rows, list), 'missing matrix result rows')
            seen = set()
            for row in rows:
                require(isinstance(row, dict), 'invalid matrix result row')
                case, outcome = row.get('name'), row.get('result')
                require(case in expected and case not in seen, 'unexpected or duplicate matrix result')
                require(row.get('abbr') == CASE_ABBREVIATIONS[case], 'matrix case abbreviation mismatch')
                require(outcome in (None, 'succeeded', 'failed', 'unsupported'), 'unknown matrix case result')
                seen.add(case)
                non_null += outcome is not None
                cell = {'case': case, 'direction': phase.removeprefix('bounded-'), 'reference': reference, 'result': outcome, 'group': group['name']}
                (cells if phase.startswith('bounded-') else controls).append(cell)
            require(seen == expected, 'missing matrix case result')
            passed = all(row['result'] == 'succeeded' for row in rows)
            require(result.get('passed') is passed, 'matrix phase pass flag mismatch')
            require(result.get('non_null_case_results') == sum(row['result'] is not None for row in rows)
                    and result.get('unexecuted_case_results') == sum(row['result'] is None for row in rows), 'matrix phase result counts mismatch')
            require(re.fullmatch(r'[0-9a-f]{64}', result.get('original_json_sha256', '')), 'invalid matrix result hash')
            completed = all(type(result.get(key)) is int and result[key] == 0 for key in ('exit_code', 'cleanup_exit_code'))
            passed = passed and completed and result.get('status') == 'PASSED'
            phase_passed.append(passed)
            if phase == phases[0]:
                baseline_passed = passed
        require(summary.get('case_results') == len(expected) * 3 and summary.get('non_null_case_results') == non_null
                and summary.get('unexecuted_case_results') == len(expected) * 3 - non_null, 'matrix summary result counts mismatch')
        require(summary.get('baseline_passed') is baseline_passed, 'matrix baseline pass flag mismatch')
        passed = all(phase_passed) and summary.get('status') == 'PASSED' and summary.get('candidate_diagnostic_after_failed_control') is False
        all_passed = all_passed and passed
        verified_groups.append({'name': group['name'], 'reference': reference, 'cases': sorted(expected), 'status': 'PASSED' if passed else 'NOT_PASSED'})
    require(len(cells) == 40 and len({(cell['case'], cell['direction']) for cell in cells}) == 40, 'matrix candidate coverage mismatch')
    report = {'status': 'PASSED' if all_passed else 'NOT_PASSED', 'source_commit': source_commit,
              'run_id': run_id, 'run_attempt': run_attempt, 'same_commit_all_40_executed': all(cell['result'] is not None for cell in cells),
              'expected_candidate_results': 40, 'candidate_results': len(cells),
              'candidate_passed': sum(cell['result'] == 'succeeded' for cell in cells),
              'candidate_unexecuted': sum(cell['result'] is None for cell in cells),
              'control_results': len(controls), 'control_passed': sum(cell['result'] == 'succeeded' for cell in controls),
              'runner_source_unchanged': True, 'simulator_image': simulator, 'groups': verified_groups,
              'candidate_cells': cells, 'control_cells': controls, 'full_44_case_direction_matrix': False}
    output = SAFE
    output.mkdir(exist_ok=True)
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('candidate_cells', 'control_cells')}, indent=2))
    return 0 if all_passed else 1

def main():
    global EXPECTED, REFERENCE
    request=json.loads((ROOT / 'ci/interop-request.json').read_text())
    request=selected_request(request, os.environ.get('INTEROP_GROUP'))
    REFERENCE=requested_reference(request.get('reference_implementation', 'neqo'))
    EXPECTED=requested_cases(request.get('cases', ['handshake', 'transfer']))
    directions=requested_directions(request.get('candidate_directions', ['client', 'server']))
    SAFE.mkdir(exist_ok=True)
    RAW.mkdir(exist_ok=True)
    version = subprocess.check_output(['tshark', '--version'], text=True).splitlines()[0]
    match = re.search(r'(\d+)\.(\d+)\.\d+', version)
    require(match and tuple(map(int, match.groups())) >= (4, 5), 'tshark too old')
    write('tools.json', {'tshark': version, 'python': sys.version,
        'compose': subprocess.check_output(['docker', 'compose', 'version'], text=True).strip(),
        'python_packages': subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'], text=True).splitlines()})
    require(subprocess.check_output(['git', '-C', str(RUNNER), 'rev-parse', 'HEAD'], text=True).strip() == os.environ['RUNNER_REVISION'], 'runner pin mismatch')
    require(not subprocess.check_output(['git', '-C', str(RUNNER), 'status', '--porcelain'], text=True).strip(), 'runner checkout changed')
    docker_metadata()
    records = []
    baseline = phase(REFERENCE + '-baseline', REFERENCE, REFERENCE, False)
    records.append(baseline)
    # A completed negative control is diagnostic evidence, not an infrastructure
    # failure. Inspect the candidate too, but retain the control in the mandatory
    # all-passed gate below. Never continue after broken setup or failed cleanup.
    control_completed = (baseline['status'] in {'PASSED', 'FAILED'}
        and baseline.get('cleanup_exit_code') == 0
        and baseline.get('non_null_case_results') == len(EXPECTED)
        and baseline.get('unexecuted_case_results') == 0
        and (baseline['status'] == 'PASSED' or
             all(baseline.get('runner_progress', {}).get(key) is True for key in
                 ('client_compliance_passed', 'server_compliance_passed'))))
    if control_completed:
        if 'client' in directions:
            records.append(phase('bounded-client', 'hibana-quic', REFERENCE, True))
        if 'server' in directions:
            records.append(phase('bounded-server', REFERENCE, 'hibana-quic', True))
    clean = not subprocess.check_output(['git', '-C', str(RUNNER), 'status', '--porcelain'], text=True).strip()
    passed = len(records) == 1 + len(directions) and all(r['status'] == 'PASSED' for r in records) and clean
    write('summary.json', {'status': 'PASSED' if passed else 'NOT_PASSED',
        'scope': 'one unmodified runner pilot: selected reference baseline plus explicitly selected cases and candidate directions',
        'reference_implementation': REFERENCE,
        'interop_group': os.environ.get('INTEROP_GROUP'),
        'candidate_directions': sorted(directions),
        'baseline_passed': baseline['status'] == 'PASSED',
        'candidate_diagnostic_after_failed_control': control_completed and baseline['status'] != 'PASSED',
        'selected_cases': sorted(EXPECTED),
        'runner_source_unchanged': clean, 'phases': [r['phase'] for r in records],
        'case_results': sum(len(r.get('results', [])) for r in records),
        'non_null_case_results': sum(r.get('non_null_case_results', 0) for r in records),
        'unexecuted_case_results': sum(r.get('unexecuted_case_results', 0) for r in records),
        'full_runner_gate_passed': False,
        'not_claimed': ['remaining runner cases', 'three release attempts', 'Pico hardware', 'whole-host zero allocation'],
        'withheld': ['TLS secrets/key logs', 'private certificate keys', 'tickets', 'raw logs', 'raw packet captures']})
    return 0 if passed else 1

if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--matrix']:
            request = json.loads((ROOT / 'ci/interop-request.json').read_text())
            print(json.dumps({'include': [{'group': group['name']} for group in qualification_groups(request)]}, separators=(',', ':')))
            raise SystemExit(0)
        if len(sys.argv) == 3 and sys.argv[1] == '--verify-matrix':
            raise SystemExit(verify_matrix(Path(sys.argv[2]), os.environ.get('SOURCE_COMMIT'), os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_RUN_ATTEMPT')))
        require(len(sys.argv) == 1, 'unknown pilot arguments')
        raise SystemExit(main())
    except Exception as error:
        write('infrastructure-failure.json', {'status': 'NOT_PASSED', 'error_type': type(error).__name__,
            'frames': [code_frame(f.filename, f.lineno, f.name) for f in traceback.extract_tb(error.__traceback__)][-24:]})
        raise
