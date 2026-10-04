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
if [[ -f ci/recovery-diagnostics ]]; then
  exec bash ci/compile-recovery.sh
fi
python3 - <<'PY'
import json,os,platform,subprocess
from pathlib import Path
Path('ci-safe-results/environment.json').write_text(json.dumps({
 'github_sha':os.environ.get('GITHUB_SHA'),'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'run_id':os.environ.get('GITHUB_RUN_ID'),'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
 'runner_os':os.environ.get('RUNNER_OS'),'runner_image':os.environ.get('ImageVersion'),
 'machine':platform.machine(),'public_repository':True,'scope':'one explicitly requested pilot; baseline plus explicitly selected registered cases',
 'not_claimed':['full 40-cell matrix','three release repetitions','Pico hardware','whole-host zero allocation']},indent=2)+'\n')
PY
# Upstream Compose uses interface_name, which requires daemon API >= 1.49.
# Upgrade only the existing Docker CE/CLI packages from Docker's official source.
# The user approved direct routing on this disposable GitHub runner only.
# Preserve all other daemon settings, firewall rules, socket modes and groups.
[[ $(. /etc/os-release; echo "$ID:$VERSION_CODENAME") == ubuntu:noble ]]
[[ $(dpkg --print-architecture) == amd64 ]]
dpkg-query -W docker-ce docker-ce-cli containerd.io
DOCKER_BEFORE=$(docker version --format '{{json .Server}}')
export DOCKER_BEFORE DOCKER_ENGINE_VERSION DOCKER_CLI_DEB_SHA256 DOCKER_ENGINE_DEB_SHA256
python3 - <<'PRECHECK'
import json,os
current=json.loads(os.environ['DOCKER_BEFORE'])['Version']
assert tuple(map(int,current.split('.'))) <= tuple(map(int,os.environ['DOCKER_ENGINE_VERSION'].split('.'))), 'refusing an engine downgrade'
PRECHECK
CONFIG_BEFORE=$(sudo python3 -c 'import json,pathlib; p=pathlib.Path("/etc/docker/daemon.json"); print(json.dumps(json.loads(p.read_text()) if p.exists() else {}))')
export CONFIG_BEFORE
SOCKET_BEFORE=$(stat -c '%g:%a' /var/run/docker.sock)
mkdir -p .ci-work/docker-packages
for package in docker-ce-cli docker-ce; do
  curl --fail --silent --show-error --location \
    "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/${package}_${DOCKER_ENGINE_VERSION}-1~ubuntu.24.04~noble_amd64.deb" \
    -o ".ci-work/docker-packages/$package.deb"
done
printf '%s  %s\n' "$DOCKER_CLI_DEB_SHA256" .ci-work/docker-packages/docker-ce-cli.deb \
  "$DOCKER_ENGINE_DEB_SHA256" .ci-work/docker-packages/docker-ce.deb | sha256sum --check --strict
sudo dpkg --force-confold -i .ci-work/docker-packages/docker-ce-cli.deb .ci-work/docker-packages/docker-ce.deb
# QNS routes through a simulator on a different bridge. Docker 28 otherwise
# drops that traffic in raw PREROUTING before the simulator can observe it.
sudo python3 - <<'ROUTING'
import json
from pathlib import Path
path=Path('/etc/docker/daemon.json')
settings=json.loads(path.read_text()) if path.exists() else {}
settings['allow-direct-routing']=True
path.parent.mkdir(parents=True,exist_ok=True)
path.write_text(json.dumps(settings,indent=2)+'\n')
ROUTING
sudo systemctl restart docker
for attempt in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
sudo --preserve-env=CONFIG_BEFORE python3 - <<'VERIFY_ROUTING'
import json,os
from pathlib import Path
actual=json.loads(Path('/etc/docker/daemon.json').read_text())
expected=json.loads(os.environ['CONFIG_BEFORE'])
expected['allow-direct-routing']=True
assert actual == expected, 'unexpected daemon configuration change'
VERIFY_ROUTING
[[ $(stat -c '%g:%a' /var/run/docker.sock) == "$SOCKET_BEFORE" ]]
python3 - <<'POSTCHECK'
import json,os,subprocess
from pathlib import Path
server=json.loads(subprocess.check_output(['docker','version','--format','{{json .Server}}'],text=True))
assert server['Version']==os.environ['DOCKER_ENGINE_VERSION'], 'engine pin mismatch'
assert tuple(map(int,server['ApiVersion'].split('.'))) >= (1,49), 'upstream interface_name needs API 1.49'
Path('ci-safe-results/docker-upgrade.json').write_text(json.dumps({
 'source':'https://download.docker.com/linux/ubuntu/dists/noble/stable/binary-amd64/Packages',
 'before_version':json.loads(os.environ['DOCKER_BEFORE'])['Version'],
 'after_version':server['Version'],'after_api':server['ApiVersion'],
 'cli_deb_sha256':os.environ['DOCKER_CLI_DEB_SHA256'],
 'engine_deb_sha256':os.environ['DOCKER_ENGINE_DEB_SHA256'],
 'daemon_config_change':'allow-direct-routing=true; user approved for disposable CI runner','socket_group_and_mode_unchanged':True},indent=2)+'\n')
POSTCHECK
docker version
docker compose version
# Apart from the explicitly approved direct-routing flag above, container
# capabilities/topology come from the unchanged reference Compose file.
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
docker pull --platform linux/amd64 "$PYTHON_IMAGE"
echo 'Building and smoke-testing analysis tools before endpoint compilation'
docker build --platform linux/amd64 --build-arg UBUNTU_IMAGE="$UBUNTU_IMAGE" --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" -f ci/runner-tools.Dockerfile -t hibana-pilot-tools .ci-work/runner
echo 'Building unchanged pinned Neqo QNS endpoint'
docker build --platform linux/amd64 --build-arg CARGO_BUILD_JOBS=2 -f .ci-work/neqo/qns/Dockerfile -t hibana-pilot-neqo .ci-work/neqo
echo 'Building bounded endpoint from audited source'
docker build --platform linux/amd64 --build-arg RUST_IMAGE="$RUST_IMAGE" --build-arg ENDPOINT_IMAGE="$ENDPOINT_IMAGE" -f interop/qns/Dockerfile -t hibana-pilot-bounded .
NEQO_IMAGE=$(docker image inspect hibana-pilot-neqo --format '{{.Id}}')
BOUNDED_IMAGE=$(docker image inspect hibana-pilot-bounded --format '{{.Id}}')
TOOLS_IMAGE=$(docker image inspect hibana-pilot-tools --format '{{.Id}}')
export NEQO_IMAGE BOUNDED_IMAGE TOOLS_IMAGE RUNNER_REVISION NEQO_REVISION HIBANA_REVISION RUST_IMAGE ENDPOINT_IMAGE UBUNTU_IMAGE PYTHON_IMAGE
python3 - <<'PY'
import json,os
from pathlib import Path
keys=['RUNNER_REVISION','NEQO_REVISION','HIBANA_REVISION','SIM_IMAGE','NEQO_IMAGE','BOUNDED_IMAGE','TOOLS_IMAGE','RUST_IMAGE','ENDPOINT_IMAGE','UBUNTU_IMAGE','PYTHON_IMAGE','DOCKER_ENGINE_VERSION','DOCKER_CLI_DEB_SHA256','DOCKER_ENGINE_DEB_SHA256']
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
