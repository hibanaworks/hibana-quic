"""Reap simulator capture children before its container exits on termination."""
import argparse
import hashlib
import json
from pathlib import Path

OLD = '''trap "kill -SIGINT $PID" INT
trap "kill -SIGTERM $PID" TERM
trap "kill -SIGKILL $PID" KILL
wait
'''
NEW = '''forward_and_reap() {
  trap '' INT TERM
  kill -s "$1" $PID 2>/dev/null || :
  for child in $PID; do
    wait "$child" || :
  done
}
trap 'forward_and_reap INT' INT
trap 'forward_and_reap TERM' TERM
wait
'''


def patch(source):
    if source.count(OLD) != 1 or not source.endswith(OLD):
        raise ValueError('unknown simulator shutdown tail; do not patch')
    return source[:-len(OLD)] + NEW


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('metadata', type=Path)
    args = parser.parse_args()
    before = args.source.read_bytes()
    after = patch(before.decode('utf-8')).encode('utf-8')
    args.output.write_bytes(after)
    args.output.chmod(0o755)
    args.metadata.write_text(json.dumps({
        'change': 'forward termination and wait for capture children; scenarios unchanged',
        'original_sha256': hashlib.sha256(before).hexdigest(),
        'patched_sha256': hashlib.sha256(after).hexdigest(),
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
