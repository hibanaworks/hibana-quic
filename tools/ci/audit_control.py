#!/usr/bin/env python3
"""Regression guard for specifically removed controllers, not a correctness proof."""
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REMOVED = {
    "src/quic/mod.rs": [r"\bclaimed\s*:\s*Cell<bool>"],
    "src/crypto/mod.rs": [r"\bstruct\s+ApplicationKeys\b", r"\bfn\s+take_for_role\b"],
    "src/crypto/directional.rs": [r"\bactive\s*:\s*bool", r"\benum\s+Pending\b", r"\bcurrent_acked\s*:\s*bool", r"\bhandshake_confirmed\s*:\s*bool"],
    "src/quic/early_data.rs": [r"\benum\s+Phase\b", r"\bstruct\s+Quarantine\b", r"\b(fin_pending|marker_pending|opened_in_table|fin_released)\s*:\s*bool"],
    "src/quic/path.rs": [r"\bstruct\s+(Paths|PathSlot)\b"],
    "src/quic/ecn.rs": [r"\bstruct\s+PathEcn\b", r"\benum\s+State\b"],
    "src/quic/retry.rs": [r"\bstruct\s+(ClientRetry|CommittedRetry)\b", r"\binitial_processed\s*:\s*bool"],
    "src/quic/kernel/connection_id.rs": [r"\bretirement_acked\s*:\s*bool"],
    "src/quic/application/keys.rs": [r"\bretired\s*:\s*bool"],
    "src/quic/application/transmit.rs": [r"\bclosing\s*:\s*Cell<bool>"],
    "src/quic/recovery.rs": [r"\bparameters_bound\s*:\s*bool",r"\b(close_only|terminal)\s*:\s*bool"],
    "src/quic/transcript.rs": [r"\bNumericOwner\b", r"\bwith_crypto\b", r"\.material\("],
    "src/quic/tls.rs": [r"\bretired\s*:\s*bool"],
    "src/tls/handshake.rs": [r"\benum\s+State\b", r"\bstate\s*:\s*State", r"\b(handshake_created|application_created|handshake_discarded|application_discarded|key_handoff|tx_post_handshake)\s*:\s*bool"],
    "src/tls/handshake/key_source.rs": [r"\b(integrity_taken|early_taken|finished_taken)\s*:\s*bool"],
}

def main():
    failures = []
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    material = (ROOT.parent / "hibana-tls").resolve(strict=True)
    for name, patterns in REMOVED.items():
        path = material / name.replace("src/tls/", "src/", 1) if name.startswith("src/tls/handshake") else ROOT / name
        text = path.read_text()
        for pattern in patterns:
            if re.search(pattern, text):
                failures.append(f"removed controller returned: {name}: {pattern}")
    # Read the canonical material implementation, not the QUIC reexport facade.
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    dependency = cargo["dependencies"]["hibana-tls"]
    material = (ROOT.parent / "hibana-tls").resolve(strict=True)
    schedule = (material / "src/schedule.rs").read_text()
    if re.search(r"\b(?:enum\s+Stage|stage\s*:\s*Stage|with_psk\s*:\s*bool)\b", schedule):
        failures.append("stored schedule controller returned in canonical hibana-tls")
    packet = (material / "src/quic/packet_protection.rs").read_text()
    for pattern in REMOVED["src/crypto/mod.rs"] + [r"\bactive\s*:\s*bool"]:
        if re.search(pattern, packet):
            failures.append("removed packet material controller returned in canonical hibana-tls")
    source = (material / "src/handshake/key_source.rs").read_text()
    if re.search(r"\bpub\s+fn\s+material\b|\bpub\s+provider\s*:", source):
        failures.append("public mutable TLS material escape returned")
    local = (material / "src/handshake/local.rs").read_text()
    if re.search(r"\b(CryptoAccess|SourceAccess|with_crypto|client_source_owner|server_source_owner)\b", local):
        failures.append("removed TLS forwarding adapter returned")
    if re.search(r"\bfn\s+(material|client_transcript_role)\b", source):
        failures.append("removed KeySource forwarding/material API returned")
    ticket = (material / "src/ticket.rs").read_text()
    if re.search(r"\b(retired|occupied)\s*:\s*bool", ticket):
        failures.append("removed ticket-key/replay occupancy flags returned")
    if failures:
        raise SystemExit("\n".join(failures))
    print("Known removed-controller regression guard passed; behavioral proof still requires projected runtime tests")

if __name__ == "__main__":
    main()
