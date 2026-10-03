# Fresh-source recovery evidence

`status.json` records source identities, actual results and all 120 planned
cells. `commands.jsonl` records commands, exit codes, environment flags, original
log hashes and preserved log paths. `published-commits.json` maps the tested
local commits to GitHub API commits with identical verified trees; API commit
metadata changes the commit SHA.

The ordered six-command verification passed at published `02efcac4` with 38
Rust tests executed. Additional suites are recorded at their own source SHAs.
Broad Rust testing and the core compile-memory resource gate remain failed;
their failures are included. Python, Lean and Z3 results are stated only for
their modeled contracts.

`neqo-baseline.json` is the latest normal official baseline: handshake and
transfer both failed. `candidate-diagnostic.json` preserves the earlier four
failed candidate cells; its environment was not qualified. The formal 120-cell
matrix was not attempted. Its table is planned scope, extracted from the pinned
runner registry, with every cell marked not run. The 18 unimplemented endpoint
cases are distinct from upstream unsupported verdicts, of which none was
obtained for those cases. No file comparison or interoperability pass is claimed.

`network-reproduction.py` is the actual executed environment diagnosis snapshot,
not a portable test or the official runner. It requires the saved candidate
image, Docker host PID 198 and `/workspace/validation`, and creates only its own
two temporary bridges/three endpoints. Its process exits zero after recording
the experiment; that exit is not a networking pass. The destination endpoint's
`raw PREROUTING` DROP counter is in `logs/gateway-active-endpoint-raw.log`.
The correct daemon prerequisite is described in `ci/local/README.md`.

The restart helper subsequently stopped Docker and incorrectly treated zombie
PID 198 as running, as shown by `logs/dockerd-direct-routing.log`. Root recovery
is required before any more container checks. Restarting Docker has not been
claimed successful. Source/binaries/images/logs remain present. Raw TLS material,
certificates, qlogs, captures and downloads remain outside Git; no duplicate
source archive is included.

Resume with the root daemon recovery, a fresh image at the clean source SHA,
Neqo/Neqo baseline, both pilot directions, then the three matrix repetitions.
Separately resolve the unchanged core RSS gate, legacy early-owner projection /
retirement and path-owner fixture stack failures without changing limits or
assertions. Add a core contract model and Rust regression if the reduced failure
identifies a new core defect. QUIC performance still needs comparable measurement.
