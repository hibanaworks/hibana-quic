#!/usr/bin/env python3
"""Real bounded-HQ two-connection early acceptance/rejection and disabled-client tests.

Private test PKI stays in a temporary directory and is never copied to reports.
This is a localhost integration test, not the full external interoperability gate.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("hq_helpers", Path(__file__).with_name("test_hq_localhost.py"))
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=["accepted", "rejected", "disabled_client", "all"], default="all")
    parser.add_argument("--cipher-suite", choices=["default", "aes128", "chacha20"], default="default")
    parser.add_argument("--resumption-delay-ms", type=int, default=0)
    args = parser.parse_args()
    assert 0 <= args.resumption_delay_ms <= 60000
    binary = args.binary.resolve()
    os.umask(0o077)
    report = {"status": "FAILED", "scope": "localhost-explicit-safe-get-early-data", "binary_sha256": H.sha256(binary),
              "script_sha256": H.sha256(Path(__file__)), "cipher_policy": args.cipher_suite, "resumption_delay_ms": args.resumption_delay_ms, "cases": {}}
    try:
        cases = ["accepted", "rejected", "disabled_client"] if args.case == "all" else [args.case]
        for case in cases:
            with tempfile.TemporaryDirectory(prefix="hq-early-") as directory:
                root = Path(directory)
                (root / "www").mkdir()
                H.certificates(root)
                paths = ["warm.bin", "five-mib.bin"] + [f"small-{i}.txt" for i in range(7)]
                (root / "www/warm.bin").write_bytes(b"")
                (root / "www/five-mib.bin").write_bytes(bytes(range(256)) * (5 * 4096))
                for index, name in enumerate(paths[2:]):
                    (root / "www" / name).write_bytes((f"early-request-{index}\n" * (index + 1)).encode())
                server_flags = ["--max-connections", "2", "--early-data", "buffered-get", "--early-age-skew-ms", "1000", "--cipher-suite", args.cipher_suite]
                if case == "rejected":
                    server_flags += ["--reject-early-second", "true"]
                server, address = H.launch_server(binary, root, len(paths), 60, server_flags)
                command = [str(binary), "client", "--connect", address, "--server-name", "localhost", "--ca", str(root / "ca.pem"),
                           "--downloads", str(root / "downloads"), "--connections", "2", "--timeout-seconds", "60", "--cipher-suite", args.cipher_suite]
                command += ["--resumption-delay-ms", str(args.resumption_delay_ms)]
                if case != "disabled_client":
                    command += ["--early-data", "replay-safe-get", "--expect-early", case]
                for name in paths:
                    command += ["--request", "/" + name]
                result = {}
                report["cases"][case] = result
                try:
                    client = subprocess.run(command, capture_output=True, text=True, timeout=130)
                    output, error = server.communicate(timeout=65)
                    result.update(client_exit=client.returncode, server_exit=server.returncode, client_stdout=client.stdout,
                                  server_stdout=output, client_stderr=client.stderr, server_stderr=error)
                    result["client"] = json.loads(client.stdout)
                    result["server"] = json.loads(output)
                    assert client.returncode == server.returncode == 0, result
                    files = {}
                    for name in paths:
                        expected = H.sha256(root / "www" / name)
                        actual = H.sha256(root / "downloads" / name)
                        assert expected == actual
                        files[name] = {"bytes": (root / "www" / name).stat().st_size, "sha256": actual}
                    result["files"] = files
                    for role in ["client", "server"]:
                        connections = result[role]["connections"]
                        assert [r["files_completed"] for r in connections] == [1, len(paths) - 1]
                        assert [r["resumed"] for r in connections] == [False, True]
                        assert all(r["lifecycle_closed"] for r in connections)
                        assert connections[1]["connection_generation"] == connections[0]["connection_generation"] + 1
                    client_early = result["client"]["connections"][1]["early_data"]
                    server_early = result["server"]["connections"][1]["early_data"]
                    if case == "disabled_client":
                        assert client_early["packets_sent"] == server_early["admitted_packets"] == 0
                        assert client_early["decision"] == server_early["decision"] == "not_offered"
                    else:
                        assert client_early["packets_sent"] > 0 and client_early["requests_queued"] == 4
                        assert client_early["request_bytes_queued"] > 0
                        assert client_early["decision"] == server_early["decision"] == case
                        assert (server_early["admitted_packets"] > 0) == (case == "accepted")
                    assert not list((root / "downloads").rglob(".hibana-*.part"))
                    result["status"] = "PASSED"
                finally:
                    if server.poll() is None:
                        server.kill()
                        server.communicate()
        report["status"] = "PASSED"
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
