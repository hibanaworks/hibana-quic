#!/usr/bin/env python3
"""Real UDP file/hash regression for the bounded-TLS hq adapter.

Requires a built hq executable and OpenSSL. Uses isolated, short-lived test keys;
never saves keys/PEM material in the evidence report. Not an interop-runner test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def checked(command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"fixture command failed: {command[0]}: {result.stderr}")


def certificates(root):
    checked(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(root / "ca.key")])
    checked(["openssl", "req", "-new", "-x509", "-sha256", "-key", str(root / "ca.key"), "-out", str(root / "ca.pem"), "-days", "1", "-subj", "/CN=Hibana-HQ-Test-CA"])
    checked(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(root / "server.key")])
    checked(["openssl", "req", "-new", "-sha256", "-key", str(root / "server.key"), "-out", str(root / "server.csr"), "-subj", "/CN=localhost"])
    (root / "extensions").write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n")
    checked(["openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "ca.pem"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(root / "server.pem"), "-days", "1", "-sha256", "-extfile", str(root / "extensions")])


def launch_server(binary, root, count, timeout, extra_args=()):
    server = subprocess.Popen([str(binary), "server", "--listen", "127.0.0.1:0", "--cert", str(root / "server.pem"), "--key", str(root / "server.key"), "--www", str(root / "www"), "--max-requests", str(count), "--timeout-seconds", str(timeout), *extra_args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = server.stderr.readline().strip()
    if not line.startswith("listening "):
        output, error = server.communicate(timeout=10)
        raise RuntimeError(f"server startup failed: {line} {output} {error}")
    return server, line.split()[1]


def exercise(binary, root, requests, timeout, name="localhost", directory="downloads", ca=None):
    server, address = launch_server(binary, root, len(requests), timeout)
    command = [str(binary), "client", "--connect", address, "--server-name", name, "--ca", str(ca or root / "ca.pem"), "--downloads", str(root / directory), "--timeout-seconds", str(timeout)]
    for request in requests:
        command += ["--request", request.replace("{port}", address.rsplit(":", 1)[1])]
    try:
        client = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 5)
        output, error = server.communicate(timeout=timeout + 5)
        return {"client_exit": client.returncode, "server_exit": server.returncode,
                "client": json.loads(client.stdout), "server": json.loads(output),
                "client_stderr": client.stderr, "server_stderr": error}
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[3] / "pal/target/release/hq")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--negative-auth", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    os.umask(0o077)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="hibana-hq-loopback-") as directory:
        root = Path(directory)
        www = root / "www"
        (www / "nested").mkdir(parents=True)
        certificates(root)
        with (www / "five-mib.bin").open("wb") as stream:
            for block in range(5 * 1024):
                stream.write(bytes([block % 251]) * 1024)
        (www / "empty.bin").write_bytes(b"")
        (www / "nested/hello.txt").write_bytes(b"HTTP/0.9 over bounded QUIC TLS\n")
        for index in range(8):
            (www / f"small-{index}.txt").write_bytes((f"stream-{index}\n" * (index + 1)).encode())
        paths = ["five-mib.bin", "empty.bin", "nested/hello.txt"] + [f"small-{i}.txt" for i in range(8)]
        requests = ["https://localhost:{port}/five-mib.bin"] + [f"/{p}" for p in paths[1:]]
        results = exercise(binary, root, requests, args.timeout_seconds)
        assert results["client_exit"] == 0 and results["server_exit"] == 0, results
        hashes = {}
        for path in paths:
            source, target = www / path, root / "downloads" / path
            original, received = sha256(source), sha256(target)
            assert original == received, f"hash mismatch: {path}"
            assert source.stat().st_size == target.stat().st_size, f"length mismatch: {path}"
            hashes[path] = {"bytes": source.stat().st_size, "sha256": original, "received_sha256": received}
        expected_bytes = sum(item["bytes"] for item in hashes.values())
        for role in ("client", "server"):
            assert results[role]["files_completed"] == len(paths), results
            assert results[role]["body_bytes"] == expected_bytes, results
        assert not list((root / "downloads").rglob(".hibana-*.part"))
        negatives = {}
        if args.negative_auth:
            negative = exercise(binary, root, ["/small-0.txt"], 3, name="wrong.invalid", directory="wrong-name")
            assert negative["client_exit"] != 0 and negative["server_exit"] != 0, negative
            assert not list((root / "wrong-name").rglob("*.txt"))
            negatives["wrong_hostname"] = negative
            alternate = root / "alternate"
            alternate.mkdir()
            certificates(alternate)
            negative = exercise(binary, root, ["/small-0.txt"], 3, directory="wrong-ca", ca=alternate / "ca.pem")
            assert negative["client_exit"] != 0 and negative["server_exit"] != 0, negative
            assert not list((root / "wrong-ca").rglob("*.txt"))
            negatives["wrong_ca"] = negative
        report = {"status": "PASSED", "scope": "direct-localhost-http09", "backend": "bounded-profile", "alpn": "hq-interop", "binary_sha256": sha256(binary), "elapsed_seconds": round(time.monotonic() - started, 3), "result": results, "files": hashes, "negative_auth": negatives, "not_claimed": ["quic-interop-runner", "Neqo transfer", "whole-host zero allocation", "Pico hardware", "full mandatory TLS algorithms"]}
        encoded = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded)
        print(encoded, end="")


if __name__ == "__main__":
    main()
