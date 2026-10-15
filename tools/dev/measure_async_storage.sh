#!/usr/bin/env bash
# The old controller probe was removed with its production architecture.
# Historical ELF reports remain readable by the Rust source-pair tool's
# --legacy-async-budget option. They do not measure the current runtime.
set -euo pipefail
printf '%s\n' 'UNAVAILABLE_NOT_MEASURED: the recovered independent-role full-connection target budget has no current probe; Pico work is deferred.' >&2
exit 2
