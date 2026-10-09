#!/usr/bin/env python3
"""Direct localhost hash/FIN/close check; not an official runner result."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import selectors
import subprocess
import tempfile
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("direct_fixture", HERE / "test_direct_handshake_localhost.py")
HELP = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(HELP)
def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as file:
        while data := file.read(65536): value.update(data)
    return value.hexdigest()
def exercise(binary, root, names, timeout, protocol="hq", cipher="auto"):
    server = subprocess.Popen([str(binary), "server", "--listen", "127.0.0.1:0", "--cert", str(root / "server.pem"),
                               "--key", str(root / "server.key"), "--www", str(root / "www"), "--max-requests", str(len(names)),
                               "--timeout-seconds", str(timeout), "--http", protocol, "--cipher", cipher], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(server.stderr, selectors.EVENT_READ); assert selector.select(5), "server did not become ready"; ready = server.stderr.readline().strip()
        if ready.startswith("listening "): address = ready.split()[1]
        else:
            prefix = "direct Hibana server listening on "; assert ready.startswith(prefix), ready; address = ready[len(prefix):]
        command = [str(binary), "client", "--connect", address, "--server-name", "localhost", "--ca", str(root / "ca.pem"),
                   "--downloads", str(root / "downloads"), "--timeout-seconds", str(timeout), "--http", protocol, "--cipher", cipher]
        for name in names: command += ["--request", f"https://localhost:{address.rsplit(':', 1)[1]}/{name}"]
        client = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 5); server_output, server_error = server.communicate(timeout=timeout + 5)
        result = {"client_exit": client.returncode, "server_exit": server.returncode, "client_stdout": client.stdout, "server_stdout": server_output,
                  "client_stderr": client.stderr, "server_stderr": server_error, "files": []}
        for name in names:
            original, received = root / "www" / name, root / "downloads" / name
            result["files"].append({"name": name, "bytes": original.stat().st_size, "expected_sha256": digest(original), "exists": received.exists(), "received_sha256": digest(received) if received.exists() else None})
        result["staging_left"] = [str(path.relative_to(root / "downloads")) for path in (root / "downloads").rglob(".hibana-*.part")]
        return result
    finally:
        if server.poll() is None: server.kill(); server.communicate()
def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--binary", type=Path, required=True); parser.add_argument("--large", action="store_true")
    parser.add_argument("--http", choices=["hq", "3"], default="hq"); parser.add_argument("--cipher", choices=["auto", "aes128", "chacha20"], default="auto")
    parser.add_argument("--timeout-seconds", type=int, default=60); parser.add_argument("--output", type=Path, required=True); args = parser.parse_args(); binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="hibana-direct-transfer-") as tmp:
        root = Path(tmp); HELP.credentials(root); (root / "www").mkdir()
        sizes = [2 << 20, 3 << 20, 5 << 20] if args.large else [4096, 0]; names = [f"body-{index}.bin" for index in range(len(sizes))]
        for index, (name, size) in enumerate(zip(names, sizes)):
            with (root / "www" / name).open("wb") as file:
                for offset in range(0, size, 1024): file.write(bytes([(offset // 1024 + index * 17) % 251]) * min(1024, size - offset))
        result = exercise(binary, root, names, args.timeout_seconds, args.http, args.cipher)
    report = {"scope": "direct-native-file-single-connection", "http": args.http, "cipher_policy": args.cipher, "binary_sha256": digest(binary), "formal_interop_runner_verdict": None, "result": result}
    encoded = json.dumps(report, indent=2) + "\n"; args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(encoded); print(encoded, end="")
    assert result["client_exit"] == result["server_exit"] == 0, result
    for record in result["files"]: assert record["exists"] and record["expected_sha256"] == record["received_sha256"], record
    assert not result["staging_left"], result
    for raw in [result["client_stdout"], result["server_stdout"]]:
        endpoint = json.loads(raw); assert endpoint["backend"] == "direct-hibana-roles", endpoint
        assert endpoint["http_transfer_complete"] and endpoint["lifecycle_closed"], endpoint; assert endpoint["files_completed"] == len(names), endpoint
if __name__ == "__main__": main()
