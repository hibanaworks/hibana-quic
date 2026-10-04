# Rolled-route runtime continuation

## Source and scope

- QUIC starting point: `d49769c9d98e2e729262fea4c3505eea35737c92`, the newest published implementation on `recovery/direct-wire-20261003`. The default `main` is a manual workflow bootstrap, not the implementation.
- Requested Hibana branch: `development/rolled-route-ownership`, pinned at `9fbb84cdc932cbd0a81ee995a8689393f322763e`. Its complete tracked tree is vendored without local patches. Runtime sources are unchanged from the prior adea684 import; proof links and regression-test hygiene differ.
- Work branch: `development/rolled-route-runtime`.

The control protocol must be visible as Hibana global `g::send`, `g::route`, `g::par`, and `g::roll` and directly written local `send`, `recv`, and `offer`/resolver operations. No parallel handwritten protocol state machine or wrapper-only migration is acceptable. The existing caller-owned task scheduler and Linux epoll/eventfd reactor are the starting async implementation, not a claim of complete qualification.

## Execution plan

1. Reproduce focused and broad current-source tests on Rust 1.95.0 in the assistant's cloud environment.
2. Audit the readable correspondence between global and local roles, runtime wake/cancellation behavior, and currently failing regressions.
3. For Hibana defects or guarantees outside Hibana, retain Lean AND Z3 models, old-behavior witnesses where applicable, and source-linked regression tests before claiming a fix.
4. Run fresh local interoperability checks if the official Docker runner cannot execute here. Keep each local case's conditions and omissions explicit. After passing the corresponding local gates, execute the official runner in GitHub CI on the exact published SHA.
5. Push source/evidence checkpoints regularly. Do not count skip, unexecuted scenarios, local diagnosis, or stale results as official passes.

## Initial environment

Fresh Linux x86_64, unprivileged UID 1000. Rust 1.95.0, rustfmt and Clippy installed in the writable task workspace. Docker/daemon socket are not present. Approximate available resources at setup: 10 GiB RAM, 30 GiB disk. No claim that Docker topology is runnable here. No host security settings were changed.

Validation is in progress. No fresh interoperability result is claimed in this checkpoint.
