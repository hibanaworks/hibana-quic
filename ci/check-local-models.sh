#!/usr/bin/env bash
# Explicitly requested abstract-model checks, not a claim of Rust verification.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-false} == true && ${PUBLIC_REPOSITORY:-false} == true ]] || {
  echo 'Run model tooling only in the authorized disposable public CI job'; exit 2;
}
mkdir -p .ci-work/model-tools ci-safe-results
curl --fail --location --silent --show-error --retry 2 --connect-timeout 30 --max-time 600 \
  https://github.com/leanprover/lean4/releases/download/v4.30.0/lean-4.30.0-linux.tar.zst \
  -o .ci-work/model-tools/lean.tar.zst
printf '%s  %s\n' 4dad74141c2c119ca1aa626656be83b8e14238afba97271fd7bf1eb3f081b319 \
  .ci-work/model-tools/lean.tar.zst | sha256sum --check --strict
mkdir -p .ci-work/model-tools/lean
tar --zstd -xf .ci-work/model-tools/lean.tar.zst -C .ci-work/model-tools/lean --strip-components=1
rm .ci-work/model-tools/lean.tar.zst
python3 -m venv .ci-work/model-tools/python
.ci-work/model-tools/python/bin/python -m pip install --disable-pip-version-check z3-solver==5.1.0.0
.ci-work/model-tools/python/bin/python - <<'PY'
import json, subprocess
from pathlib import Path
lean = str(Path('.ci-work/model-tools/lean/bin/lean').resolve())
python = str(Path('.ci-work/model-tools/python/bin/python').resolve())
models = [
    ('owned-body-input/Body.lean', 'owned-body-input/check_body.py'),
    ('stream-slot-binding/Binding.lean', 'stream-slot-binding/binding.py'),
    ('tls-input-cancellation/Cancellation.lean', 'tls-input-cancellation/cancellation.py'),
    ('direct-recovery-installation/Installation.lean', 'direct-recovery-installation/installation.py'),
    ('stream-reclaim/Reclaim.lean', 'stream-reclaim/reclaim.py'),
    ('reset-observation/Observation.lean', 'reset-observation/observation.py'),
]
report = {'scope': 'existing abstract ownership, EOF, cancellation and reclamation models; not verified Rust compilation or arbitrary native IO',
          'lean_version': subprocess.check_output([lean, '--version'], text=True).strip(),
          'z3_version': subprocess.check_output([python, '-c', 'import z3; print(z3.get_version_string())'], text=True).strip(),
          'results': [], 'status': 'RUNNING'}
path = Path('ci-safe-results/models.json')
for lean_source, z3_source in models:
    for tool, source in [(lean, lean_source), (python, z3_source)]:
        command = [tool, 'proofs/' + source]
        try:
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
            record = {'source': source, 'exit_code': done.returncode, 'output': done.stdout[:32768]}
        except subprocess.TimeoutExpired:
            record = {'source': source, 'exit_code': None, 'error': 'timeout'}
        report['results'].append(record)
        report['status'] = 'RUNNING' if record['exit_code'] == 0 else 'FAILED'
        path.write_text(json.dumps(report, indent=2) + '\n')
        if record['exit_code'] != 0:
            raise SystemExit('model check failed: ' + source)
report['status'] = 'PASSED'
path.write_text(json.dumps(report, indent=2) + '\n')
print('Selected Lean and Z3 abstract models passed')
PY
