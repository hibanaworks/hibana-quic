#!/usr/bin/env python3
"""Regression guard for specifically removed controllers, not a correctness proof."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REMOVED = {
    "src/crypto.rs": [r"\bstruct\s+ApplicationKeys\b"],
    "src/crypto/directional.rs": [r"\benum\s+Pending\b", r"\bcurrent_acked\s*:\s*bool", r"\bhandshake_confirmed\s*:\s*bool"],
    "src/early_data.rs": [r"\benum\s+Phase\b", r"\bstruct\s+Quarantine\b", r"\b(fin_pending|marker_pending|opened_in_table|fin_released)\s*:\s*bool"],
    "src/path.rs": [r"\bstruct\s+(Paths|PathSlot)\b"],
    "src/ecn.rs": [r"\bstruct\s+PathEcn\b", r"\benum\s+State\b"],
    "src/retry.rs": [r"\bstruct\s+(ClientRetry|CommittedRetry)\b", r"\binitial_processed\s*:\s*bool"],
    "src/connection_id.rs": [r"\bretirement_acked\s*:\s*bool"],
    "src/quic/application/keys.rs": [r"\bretired\s*:\s*bool"],
    "src/quic/application/transmit.rs": [r"\bclosing\s*:\s*Cell<bool>"],
    "src/quic/recovery.rs": [r"\b(close_only|terminal)\s*:\s*bool"],
    "src/quic/tls.rs": [r"\bretired\s*:\s*bool"],
    "src/tls/schedule.rs": [r"\bstage\s*:\s*Stage\s*,"],
    "src/tls/handshake/key_source.rs": [r"\b(integrity_taken|early_taken|finished_taken)\s*:\s*bool"],
}

def main():
    failures = []
    for name, patterns in REMOVED.items():
        text = (ROOT / name).read_text()
        for pattern in patterns:
            if re.search(pattern, text):
                failures.append(f"removed controller returned: {name}: {pattern}")
    if failures:
        raise SystemExit("\n".join(failures))
    print("Known removed-controller regression guard passed; behavioral proof still requires projected runtime tests")

if __name__ == "__main__":
    main()
