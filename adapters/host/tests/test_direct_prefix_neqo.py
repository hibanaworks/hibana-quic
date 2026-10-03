#!/usr/bin/env python3
"""Observe direct TLS prefix with unchanged Neqo; never a runner verdict."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("direct_fixture", HERE / "test_direct_handshake_localhost.py")
HELP = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(HELP)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def checked(command, env):
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)
    if result.returncode: raise RuntimeError(f"fixture tool {Path(command[0]).name} failed: {result.stderr}")
def stop(process):
    if process.poll() is None: process.terminate()
    try: return process.communicate(timeout=3)
    except subprocess.TimeoutExpired: process.kill(); return process.communicate()
def ready_line(process, prefix):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stderr, selectors.EVENT_READ)
        if not selector.select(5): raise AssertionError("server did not report readiness")
        line = process.stderr.readline().strip()
    if prefix not in line: raise AssertionError(f"unexpected readiness line: {line}")
    return line
def forward(args, root, env, name):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0)); address = f"127.0.0.1:{probe.getsockname()[1]}"
    server = subprocess.Popen([str(args.neqo_server), "-a", "hq-interop", "-Q", "1", "--db", str(root / "nss"),
                               "--key", "direct-localhost", "--idle", "10", address], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready = ready_line(server, "Server waiting for connection on:")
        client = subprocess.run([str(args.binary), "client", "--connect", address, "--server-name", name,
                                 "--ca", str(root / "ca.pem"), "--timeout-seconds", "5"], env=env, capture_output=True, text=True, timeout=8)
        output, error = stop(server)
        return {"direction": "direct-hibana-client_to_unchanged-neqo-server", "server_name": name, "client_exit": client.returncode,
                "client": json.loads(client.stdout) if client.stdout.strip() else None, "client_stderr": client.stderr,
                "neqo_log": ready + "\n" + output + error, "neqo_tls_complete": "state -> Complete" in output + error,
                "neqo_connection_established": "Connection established" in output + error}
    finally: stop(server)
def reverse(args, root, env):
    server = subprocess.Popen([str(args.binary), "server", "--listen", "127.0.0.1:0", "--cert", str(root / "server.pem"),
                               "--key", str(root / "server.key"), "--timeout-seconds", "5"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready = ready_line(server, "direct Hibana server listening on "); address = ready.split("listening on ", 1)[1]
        client = subprocess.run([str(args.neqo_peer), "--connect", address, "--server-name", "localhost", "--ca", str(root / "ca.pem"),
                                 "--group", "p256", "--timeout-seconds", "5"], env=env, capture_output=True, text=True, timeout=8)
        output, error = server.communicate(timeout=8)
        return {"direction": "verifying-neqo-library-client_to_direct-hibana-server", "official_neqo_client_cli": False,
                "client_exit": client.returncode, "server_exit": server.returncode, "client": json.loads(client.stdout) if client.stdout.strip() else None,
                "server": json.loads(output) if output.strip() else None, "client_stderr": client.stderr, "server_stderr": error}
    finally: stop(server)
def main():
    parser = argparse.ArgumentParser()
    for name in ["binary", "neqo-server", "neqo-peer", "nss-dist", "output"]: parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    for name in ["binary", "neqo_server", "neqo_peer", "nss_dist"]: setattr(args, name, getattr(args, name).resolve(strict=True))
    env = os.environ.copy(); env["LD_LIBRARY_PATH"] = str(args.nss_dist / "lib"); env["RUST_LOG"] = "info"; env.pop("SSLKEYLOGFILE", None); os.umask(0o077)
    report = {"scope": "direct-authenticated-TLS-prefix-observation", "formal_interop_runner_verdict": None,
              "binaries": {name: {"path": str(getattr(args, name)), "sha256": sha(getattr(args, name))} for name in ["binary", "neqo_server", "neqo_peer"]}, "runs": []}
    with tempfile.TemporaryDirectory(prefix="hibana-direct-neqo-") as tmp:
        root = Path(tmp); HELP.credentials(root); database = root / "nss"; database.mkdir()
        checked([str(args.nss_dist / "bin/certutil"), "-N", "-d", str(database), "--empty-password"], env)
        checked(["openssl", "pkcs12", "-export", "-inkey", str(root / "server.key"), "-in", str(root / "server.pem"), "-certfile", str(root / "ca.pem"), "-name", "direct-localhost", "-passout", "pass:", "-out", str(root / "fixture.p12")], env)
        checked([str(args.nss_dist / "bin/pk12util"), "-i", str(root / "fixture.p12"), "-d", str(database), "-W", "", "-K", ""], env)
        report["runs"].append(forward(args, root, env, "localhost")); report["runs"].append(forward(args, root, env, "wrong.invalid")); report["runs"].append(reverse(args, root, env))
    args.output.parent.mkdir(parents=True, exist_ok=True); encoded = json.dumps(report, indent=2) + "\n"; args.output.write_text(encoded); print(encoded, end="")
    positive, negative, _reverse = report["runs"]
    assert positive["client_exit"] == 0 and positive["neqo_tls_complete"] and positive["neqo_connection_established"], positive
    assert negative["client_exit"] != 0 and not negative["neqo_tls_complete"], negative
if __name__ == "__main__": main()
