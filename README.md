# hibana-quic interoperability pilot

This repository is being prepared for a bounded, manually dispatched QUIC v1 interoperability experiment.

The test source lives on a separate `ci/interop-pilot-20261002` branch. The default branch contains only this bootstrap and the `workflow_dispatch` entry point. Pushing commits does not trigger a workflow.

Only a public repository on a standard GitHub-hosted Linux runner is eligible for execution. The experiment is limited to one job with a 60-minute maximum and short-lived, secret-free result artifacts. A published workflow is not evidence that any test has run or passed.

The initial subset is an unchanged pinned quic-interop-runner Neqo-to-Neqo baseline, followed by explicit `handshake` and `transfer` cases for the bounded endpoint in both directions. This is not the full runner matrix or a release/Pico qualification.
