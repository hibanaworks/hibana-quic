#!/usr/bin/env bash
# Executes only in the explicitly authorized public GitHub-hosted job.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-false} == true && ${PUBLIC_REPOSITORY:-false} == true ]] || {
  echo 'Refusing execution outside the public GitHub Actions pilot'; exit 2;
}
ROOT=$(pwd)
export ROOT
source ci/pins.env
mkdir -p ci-safe-results .ci-work/raw
python3 ci/audit_source.py --check
python3 - <<'PY'
import json,os,platform,subprocess
from pathlib import Path
Path('ci-safe-results/environment.json').write_text(json.dumps({
 'github_sha':os.environ.get('GITHUB_SHA'),'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'run_id':os.environ.get('GITHUB_RUN_ID'),'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
 'runner_os':os.environ.get('RUNNER_OS'),'runner_image':os.environ.get('ImageVersion'),
 'machine':platform.machine(),'public_repository':True,'scope':'one manual pilot; baseline plus handshake/transfer only',
 'not_claimed':['full 40-cell matrix','three release repetitions','Pico hardware','whole-host zero allocation']},indent=2)+'\n')
PY
docker version
docker compose version
# No host network/security configuration is changed here. Standard runner
# container capabilities/topology come from the unchanged reference Compose file.
git clone --quiet https://github.com/quic-interop/quic-interop-runner.git .ci-work/runner
git -C .ci-work/runner checkout --detach "$RUNNER_REVISION"
git clone --quiet https://github.com/mozilla/neqo.git .ci-work/neqo
git -C .ci-work/neqo checkout --detach "$NEQO_REVISION"
[[ $(git -C .ci-work/runner rev-parse HEAD) == "$RUNNER_REVISION" ]]
[[ $(git -C .ci-work/neqo rev-parse HEAD) == "$NEQO_REVISION" ]]
# Resolve the upstream simulator once, then use its immutable digest for every
# baseline/candidate execution. Never re-resolve a moving tag between cases.
docker pull --platform linux/amd64 "$SIMULATOR_TAG"
SIM_IMAGE=$(docker image inspect "$SIMULATOR_TAG" --format '{{index .RepoDigests 0}}')
[[ $SIM_IMAGE =~ ^martenseemann/quic-network-simulator@sha256:[a-f0-9]{64}$ ]]
export SIM_IMAGE
docker pull --platform linux/amd64 "$RUST_IMAGE"
docker pull --platform linux/amd64 "$ENDPOINT_IMAGE"
docker pull --platform linux/amd64 "$UBUNTU_IMAGE"
echo 'Building unchanged pinned Neqo QNS endpoint'
docker build --platform linux/amd64 --build-arg CARGO_BUILD_JOBS=2 -f .ci-work/neqo/qns/Dockerfile -t hibana-pilot-neqo .ci-work/neqo
echo 'Building bounded endpoint from audited source'
docker build --platform linux/amd64 --build-arg RUST_IMAGE="$RUST_IMAGE" --build-arg ENDPOINT_IMAGE="$ENDPOINT_IMAGE" -f interop/qns/Dockerfile -t hibana-pilot-bounded .
echo 'Building analysis tools with reference-runner requirements'
docker build --platform linux/amd64 --build-arg UBUNTU_IMAGE="$UBUNTU_IMAGE" -f ci/runner-tools.Dockerfile -t hibana-pilot-tools .ci-work/runner
NEQO_IMAGE=$(docker image inspect hibana-pilot-neqo --format '{{.Id}}')
BOUNDED_IMAGE=$(docker image inspect hibana-pilot-bounded --format '{{.Id}}')
TOOLS_IMAGE=$(docker image inspect hibana-pilot-tools --format '{{.Id}}')
export NEQO_IMAGE BOUNDED_IMAGE TOOLS_IMAGE RUNNER_REVISION NEQO_REVISION HIBANA_REVISION RUST_IMAGE ENDPOINT_IMAGE UBUNTU_IMAGE
python3 - <<'PY'
import json,os
from pathlib import Path
keys=['RUNNER_REVISION','NEQO_REVISION','HIBANA_REVISION','SIM_IMAGE','NEQO_IMAGE','BOUNDED_IMAGE','TOOLS_IMAGE','RUST_IMAGE','ENDPOINT_IMAGE','UBUNTU_IMAGE']
Path('ci-safe-results/pins.json').write_text(json.dumps({k:os.environ[k] for k in keys},indent=2)+'\n')
PY
# Keep /tmp at the identical path: upstream explicitly creates Docker bind
# mount sources there. The reference source and its verdicts are not patched.
# Match the checkout owner's host identity, preserving Git's ownership guard.
# The supplementary group grants this process only the Docker socket access
# already provided by the authorized mount; no host groups or modes are changed.
mkdir -p "$ROOT/.ci-work/tools-home"
docker run --rm --cpus=2 \
  --user "$(id -u):$(id -g)" \
  --group-add "$(stat -c '%g' /var/run/docker.sock)" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /tmp:/tmp -v "$ROOT:$ROOT" -w "$ROOT" \
  -e "HOME=$ROOT/.ci-work/tools-home" \
  -e ROOT -e SIM_IMAGE -e NEQO_IMAGE -e BOUNDED_IMAGE \
  -e RUNNER_REVISION -e NEQO_REVISION \
  "$TOOLS_IMAGE" python3 ci/run_in_tools.py
