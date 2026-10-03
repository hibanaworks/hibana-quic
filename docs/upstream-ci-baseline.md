# Upstream baseline evidence

Observed 2026-10-02. Hibana source: `102fc47e807d00318c75d7ad344fc99c2d5d3724`.

Run: https://github.com/hibanaworks/hibana/actions/runs/36951847710

- Kani job 110666291588: `check_kani.sh` reports `rg: command not found`; its assumption scan therefore did not execute. Inventory equality compares parsed JSON objects. A harness array order differs, causing failure before verification. Trailing-newline drift appears in the printed diff but is not a cause of the parsed-JSON inequality.
- Final-form job 110666291749: `compiled-program-atom-validation` actually ran **6 tests, all 6 passed**, 0 failed/ignored. The script expects 7. Its diagnostic `listed=7 passed=7 ignored=0` prints expected counts, not observed counts. This does not establish a failing Rust semantic test; it leaves the full gate unsuccessful.
- Local `PATH=/workspace/scratch/0915e8fbff81/tools/lean/lean-4.30.0-linux/bin:$PATH lake build` in the upstream `proofs/lean` directory succeeded, 56 jobs. Log: `artifacts/hibana-lean-baseline.log`. This is existing Lean-model compilation evidence, not a proof of the new QUIC implementation or Rust/model equivalence.

Read-only investigation of source and CI logs; no upstream source or gate changes made. Any core defect fix remains subject to the user's Lean-and-Z3-before-implementation requirement. Do not weaken tests or expected values simply to pass the gate.
