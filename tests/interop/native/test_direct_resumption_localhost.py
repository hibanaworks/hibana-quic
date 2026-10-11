#!/usr/bin/env python3
"""Actual two-process/two-connection TLS resumption; not 0-RTT qualification."""
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
HELP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELP)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--files", type=int, default=2, choices=[2, 40])
    args = p.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="hibana-resumption-") as temp:
        root = Path(temp)
        HELP.credentials(root)
        (root / "www").mkdir()
        names = [f"{index:03d}" + "x" * 247 for index in range(args.files)]
        for index, name in enumerate(names):
            (root / "www" / name).write_bytes(bytes([index + 1]) * 32)
        server = subprocess.Popen([
            str(binary), "server", "--listen", "127.0.0.1:0", "--cert", str(root / "server.pem"),
            "--key", str(root / "server.key"), "--www", str(root / "www"), "--session", "resume",
            "--timeout-seconds", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(server.stderr, selectors.EVENT_READ)
                assert sel.select(5), "server readiness absent"
                ready = server.stderr.readline().strip()
            prefix = "direct Hibana server listening on "
            assert ready.startswith(prefix), ready
            address = ready[len(prefix):]
            client = subprocess.run([
                str(binary), "client", "--connect", address, "--server-name", "localhost", "--ca", str(root / "ca.pem"),
                "--downloads", str(root / "downloads"), "--session", "resume",
                "--timeout-seconds", "30", *[value for name in names for value in ("--request", "/" + name)]], capture_output=True, text=True, timeout=35)
            out, error = server.communicate(timeout=35)
            result = {"scope": "real-udp-two-connection-resumption", "zero_rtt_qualified": False, "requested_files": args.files,
                      "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "client_exit": client.returncode, "server_exit": server.returncode,
                      "client_stdout": client.stdout, "client_stderr": client.stderr,
                      "server_stdout": out, "server_stderr": error,
                      "files_match": all((root / "downloads" / name).exists() and
                                         (root / "downloads" / name).read_bytes() == (root / "www" / name).read_bytes()
                                         for name in names)}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
            assert client.returncode == server.returncode == 0, result
            assert result["files_match"], result
            for raw in [client.stdout, out]:
                report = json.loads(raw)
                assert report["connections"] == 2 and report["resumed"] is True, report
                assert report["files_completed"] == args.files and report["http_transfer_complete"] and report["lifecycle_closed"] and report["resources_retired"], report
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()

if __name__ == "__main__":
    main()
