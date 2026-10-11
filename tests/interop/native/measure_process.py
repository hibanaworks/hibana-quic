#!/usr/bin/env python3
"""Measure only an explicitly launched child using its actual wait4 receipt."""
import json
import os
from pathlib import Path
import signal
import sys
import time

output, command = Path(sys.argv[1]), sys.argv[2:]
if not command:
    raise SystemExit('missing measured command')
started_ns = time.time_ns()
started = time.monotonic()
pid = os.fork()
if pid == 0:
    os.execvpe(command[0], command, os.environ)

def terminate(signum, _frame):
    try:
        os.kill(pid, signum)
    except ProcessLookupError:
        pass

signal.signal(signal.SIGTERM, terminate)
signal.signal(signal.SIGINT, terminate)
_, status, usage = os.wait4(pid, 0)
result = {'started_unix_ns': started_ns, 'wall_seconds': time.monotonic() - started,
          'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
          'max_rss_kib': usage.ru_maxrss, 'exit': os.waitstatus_to_exitcode(status)}
output.write_text(json.dumps(result) + '\n')
raise SystemExit(result['exit'] if result['exit'] >= 0 else 128 - result['exit'])
