#!/usr/bin/env bash
# Diagnostic source commit only; never emits an interoperability pass.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-false} == true && ${PUBLIC_REPOSITORY:-false} == true ]]
source tools/ci/pins.env
mkdir -p ci-safe-results .ci-work/compile-target
SOURCE_COMMIT=$(git rev-parse HEAD)
export SOURCE_COMMIT
python3 - <<'STATUS'
import json,os
from pathlib import Path
Path('ci-safe-results/compile-status.json').write_text(json.dumps({
 'source_commit':os.environ['SOURCE_COMMIT'], 'scope':'reconstructed-source compilation and focused runtime tests',
 'compile':'STARTED', 'interop':'NOT_RUN', 'tests':'NOT_RUN'
},indent=2)+'\n')
STATUS
set +e
docker run --rm --mount "type=bind,src=$PWD,dst=/source,readonly" \
 --mount "type=bind,src=$PWD/.ci-work/compile-target,dst=/target" \
 --workdir /source --env CARGO_TARGET_DIR=/target "$RUST_IMAGE" \
 bash -c 'set -euo pipefail; rustc --version; cargo check --locked --lib --tests; cargo check --locked --manifest-path pal/Cargo.toml --bin hq --tests'
compile_exit=$?
set -e
export compile_exit
python3 - <<'STATUS'
import json,os
from pathlib import Path
p=Path('ci-safe-results/compile-status.json');s=json.loads(p.read_text())
s['exit_code']=int(os.environ['compile_exit']);s['compile']='PASSED' if s['exit_code']==0 else 'FAILED'
p.write_text(json.dumps(s,indent=2)+'\n')
STATUS
if (( compile_exit != 0 )); then exit "$compile_exit"; fi
set +e
docker run --rm --mount "type=bind,src=$PWD,dst=/source,readonly" \
 --mount "type=bind,src=$PWD/.ci-work/compile-target,dst=/target" \
 --mount "type=bind,src=$PWD/ci-safe-results,dst=/results" \
 --workdir /source --env CARGO_TARGET_DIR=/target --env CARGO_BUILD_JOBS=2 \
 "$RUST_IMAGE" bash /source/tools/ci/test-recovery.sh
test_exit=$?
set -e
export test_exit
python3 - <<'STATUS'
import json,os
from pathlib import Path
p=Path('ci-safe-results/compile-status.json');s=json.loads(p.read_text())
s['tests']='PASSED' if int(os.environ['test_exit'])==0 else 'FAILED'
s['test_exit_code']=int(os.environ['test_exit'])
p.write_text(json.dumps(s,indent=2)+'\n')
STATUS
exit "$test_exit"
