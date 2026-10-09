#!/usr/bin/env python3
"""Real UDP stateless version negotiation before an authenticated HQ transfer.

Pass a frozen HQ executable. This checks only the bounded server listener;
client VN state-policy checks are separate engine tests. No insecure TLS mode.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

SPEC = importlib.util.spec_from_file_location("hq_vn_fixtures", Path(__file__).with_name("test_hq_localhost.py"))
HELP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELP)


def require(test, message):
    if not test:
        raise RuntimeError(message)


def unknown(dcid, scid, version=0xFACEB00C, size=1200):
    packet = bytes([0x80]) + version.to_bytes(4, "big") + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return packet + bytes(max(0, size - len(packet)))


def response(packet):
    require(len(packet) >= 11 and packet[0] & 0x80, "invalid VN invariant header")
    require(packet[1:5] == bytes(4), "response was not version negotiation")
    n = packet[5]
    dcid = packet[6:6 + n]
    offset = 6 + n
    require(offset < len(packet), "truncated VN destination CID")
    n = packet[offset]
    scid = packet[offset + 1:offset + 1 + n]
    offset += n + 1
    require(offset < len(packet) and (len(packet) - offset) % 4 == 0, "invalid VN version vector")
    versions = [int.from_bytes(packet[i:i + 4], "big") for i in range(offset, len(packet), 4)]
    return dcid, scid, versions


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--ipv6", action="store_true")
    args = ap.parse_args()
    require(not args.output.exists(), "refusing to overwrite evidence")
    args.binary = args.binary.resolve()
    os.umask(0o077)
    report = {"status": "FAILED", "scope": "direct-host-v1-version-negotiation-listener", "binary_sha256": HELP.sha256(args.binary), "script_sha256": HELP.sha256(Path(__file__)), "family": "IPv6" if args.ipv6 else "IPv4", "events": [], "not_claimed": ["client version switching", "multiple supported versions", "quic-interop-runner pass"]}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="hq-version-negotiation-") as directory:
            root = Path(directory)
            HELP.certificates(root)
            (root / "www").mkdir()
            body = b"authenticated after stateless version negotiation\n" * 1024
            (root / "www/body.bin").write_bytes(body)
            address = "[::1]:0" if args.ipv6 else "127.0.0.1:0"
            server = subprocess.Popen([str(args.binary), "server", "--listen", address, "--cert", str(root / "server.pem"), "--key", str(root / "server.key"), "--www", str(root / "www"), "--max-requests", "1", "--timeout-seconds", "15"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                line = server.stderr.readline().strip()
                require(line.startswith("listening "), "server failed to listen: " + line)
                address = line.split()[1]
                host, port = address.rsplit(":", 1)
                target = (host.strip("[]"), int(port))
                with socket.socket(socket.AF_INET6 if args.ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.bind(("::1" if args.ipv6 else "127.0.0.1", 0))
                    probe.settimeout(.18)
                    for index, (dcid, scid) in enumerate([(b"destination", b"source"), (b"", b""), (bytes(range(255)), bytes(reversed(range(255))))]):
                        packet = unknown(dcid, scid)
                        probe.sendto(packet, target)
                        raw, source = probe.recvfrom(2048)
                        got_dcid, got_scid, versions = response(raw)
                        require(got_dcid == scid and got_scid == dcid and versions == [1], "CID swap or version list incorrect")
                        require(len(raw) <= 521 and len(raw) <= len(packet), "VN size/amplification bound exceeded")
                        require(source[0] == target[0] and source[1] == target[1], "unexpected VN source")
                        report["events"].append({"kind": "vn", "index": index, "at_ms": round((time.monotonic() - started) * 1000, 3), "request_bytes": len(packet), "response_bytes": len(raw), "destination_cid_bytes": len(dcid), "source_cid_bytes": len(scid), "versions": versions, "randomized_first_byte": raw[0]})
                    for label, packet in [("undersized", unknown(b"abcdefgh", b"ijklmnop", size=1199)), ("version_zero", unknown(b"abcdefgh", b"ijklmnop", version=0)), ("truncated_invariant_header", bytes([0x80, 0xfa, 0xce, 0xb0, 0x0c, 255]) + bytes(249))]:
                        probe.sendto(packet, target)
                        try:
                            probe.recvfrom(2048)
                            raise RuntimeError("unexpected response to " + label)
                        except socket.timeout:
                            report["events"].append({"kind": "silent-discard", "case": label, "bytes": len(packet)})
                    # Wait for a fresh fixed rate window; this is intentionally
                    # separate from the three earlier valid requests.
                    time.sleep(1.05)
                    burst_start = time.monotonic()
                    for i in range(65):
                        probe.sendto(unknown(b"rate-dcid", i.to_bytes(8, "big")), target)
                    replies = []
                    while True:
                        try:
                            raw, _ = probe.recvfrom(2048)
                            got_dcid, got_scid, versions = response(raw)
                            require(got_scid == b"rate-dcid" and versions == [1], "unexpected rate-test response")
                            replies.append(int.from_bytes(got_dcid, "big"))
                        except socket.timeout:
                            break
                    elapsed = time.monotonic() - burst_start
                    require(elapsed < 1, "rate-window experiment crossed its declared interval")
                    require(len(replies) == 64 and len(set(replies)) == 64, "prepared-response quota was not exactly 64")
                    report["rate_window"] = {"sent": 65, "received": len(replies), "elapsed_ms": round(elapsed * 1000, 3), "response_ids": replies}
                command = [str(args.binary), "client", "--connect", address, "--server-name", "localhost", "--ca", str(root / "ca.pem"), "--downloads", str(root / "downloads"), "--request", "/body.bin", "--timeout-seconds", "8"]
                client = subprocess.run(command, capture_output=True, text=True, timeout=12)
                stdout, stderr = server.communicate(timeout=12)
                report.update(client_exit=client.returncode, server_exit=server.returncode, client=json.loads(client.stdout), server=json.loads(stdout), client_stderr=client.stderr, server_stderr=stderr)
                require(client.returncode == server.returncode == 0, "valid authenticated transfer failed after VN traffic")
                require(report["client"]["certificate_chain_hostname_time_verified"], "missing certificate verification")
                output = root / "downloads/body.bin"
                require(output.read_bytes() == body, "post-VN body mismatch")
                report["file"] = {"bytes": len(body), "sha256": HELP.sha256(output)}
                report["status"] = "PASSED"
            finally:
                if server.poll() is None:
                    server.kill()
                    server.communicate()
    except Exception as error:
        report["error"] = str(error)
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["binary_sha256_after"] = HELP.sha256(args.binary)
        if report["binary_sha256_after"] != report["binary_sha256"]:
            report["status"] = "FAILED"
            report["error"] = "binary changed during execution"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
