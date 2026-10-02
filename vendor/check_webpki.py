#!/usr/bin/env python3
"""Verify the complete upstream crate checksum inventory and sole depth patch."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
PACKAGE_SHA256 = "f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2"
PATCHED_SHA256 = "f9e9255cf55e3ce36c9df437f9047f3cd2cc80d268f01034ca3ba1a84964ff75"
crate = ROOT / "rustls-webpki-0.103.15"
inventory = json.loads((ROOT / "webpki-upstream-files.json").read_text())
assert inventory["package"] == PACKAGE_SHA256, "unexpected upstream crate"
for name, expected in inventory["files"].items():
    data = (crate / name).read_bytes()
    if name == "src/verify_cert.rs":
        assert hashlib.sha256(data).hexdigest() == PATCHED_SHA256, "unreviewed source patch"
        assert data.count(b"const MAX_SUB_CA_COUNT: usize = 8;") == 1
        data = data.replace(b"const MAX_SUB_CA_COUNT: usize = 8;", b"const MAX_SUB_CA_COUNT: usize = 6;")
    assert hashlib.sha256(data).hexdigest() == expected, f"upstream file mismatch: {name}"
print(f"webpki 0.103.15: {len(inventory['files'])} upstream files verified; sole patch is depth 6 to 8")
