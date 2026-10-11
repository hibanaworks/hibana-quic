#!/usr/bin/env python3
"""Real UDP v1-only client VN policy; unprotected indications are never authentication.

Uses a frozen HQ binary, a temporary public CA fixture, and a synthetic UDP VN
sender. This is a client policy regression, not an independent TLS handshake.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

SPEC = importlib.util.spec_from_file_location("hq_client_vn_fixture", Path(__file__).with_name("test_hq_localhost.py"))
HELP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELP)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def initial_ids(packet):
    require(len(packet) >= 1200 and packet[0] & 0x80, "not a full Initial datagram")
    require(packet[1:5] == (1).to_bytes(4, "big"), "client switched away from v1")
    dcid_len = packet[5]
    dcid = packet[6:6 + dcid_len]
    at = 6 + dcid_len
    require(at < len(packet), "short invariant header")
    scid_len = packet[at]
    scid = packet[at + 1:at + 1 + scid_len]
    require(len(dcid) == dcid_len and len(scid) == scid_len, "truncated connection IDs")
    return dcid, scid


def vn(dcid, scid, versions):
    return b"\x80\x00\x00\x00\x00" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"".join(v.to_bytes(4, "big") for v in versions)


def exercise(binary, root, ipv6, case):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as peer:
        peer.bind(("::1" if ipv6 else "127.0.0.1", 0))
        peer.settimeout(3)
        address = ("[::1]:" if ipv6 else "127.0.0.1:") + str(peer.getsockname()[1])
        command = [str(binary), "client", "--connect", address, "--server-name", "localhost", "--ca", str(root / "ca.pem"), "--downloads", str(root / case), "--request", "/body.bin", "--timeout-seconds", "6"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        start = time.monotonic()
        result = {"case": case, "status": "FAILED", "authenticated": False}
        try:
            packet, source = peer.recvfrom(65535)
            odcid, client_cid = initial_ids(packet)
            terminal = vn(client_cid, odcid, [0x6B3343CF])
            if case != "no-common-version":
                if case == "offered-v1-present":
                    ignored = vn(client_cid, odcid, [0x6B3343CF, 1, 0x0A0A0A0A])
                elif case == "wrong-destination-cid":
                    ignored = vn(bytes([client_cid[0] ^ 1]) + client_cid[1:], odcid, [2])
                elif case == "wrong-source-cid":
                    ignored = vn(client_cid, bytes([odcid[0] ^ 1]) + odcid[1:], [2])
                elif case == "truncated-version-list":
                    ignored = terminal[:-1]
                else:
                    raise RuntimeError("unknown case")
                peer.sendto(ignored, source)
                # Continued v1 Initial output after the injected indication is
                # observable progress, unlike merely checking process liveness.
                following, following_source = peer.recvfrom(65535)
                require(following_source == source, "client endpoint changed")
                require(initial_ids(following) == (odcid, client_cid), "client restarted or changed CIDs")
                require(process.poll() is None, "ignored VN terminated the client")
                result["continued_v1_initial"] = True
                result["continued_after_ms"] = round((time.monotonic() - start) * 1000, 3)
            peer.sendto(terminal, source)
            output, error = process.communicate(timeout=3)
            result.update(exit_code=process.returncode, client=json.loads(output), stderr=error)
            require(process.returncode != 0, "incompatible VN was reported as success")
            require("VersionNegotiationNoCommonVersion" in result["client"].get("error", ""), "wrong terminal cause")
            require(result["client"].get("status") == "failure", "client claimed successful connection")
            require(not (root / case / "body.bin").exists(), "application output published without a handshake")
            result["status"] = "PASSED"
        except Exception as error:
            result["error"] = str(error)
        finally:
            if process.poll() is None:
                process.kill()
                output, error = process.communicate()
                result.setdefault("terminated_stdout", output)
                result.setdefault("terminated_stderr", error)
            result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ipv6", action="store_true")
    args = parser.parse_args()
    require(not args.output.exists(), "refusing to overwrite evidence")
    args.binary = args.binary.resolve()
    os.umask(0o077)
    report = {"status": "FAILED", "scope": "direct-UDP-v1-only-client-VN-policy", "binary_sha256": HELP.sha256(args.binary), "script_sha256": HELP.sha256(Path(__file__)), "family": "IPv6" if args.ipv6 else "IPv4", "cases": [], "not_claimed": ["VN authentication", "multiple supported versions", "TLS handshake with the synthetic peer", "quic-interop-runner pass"]}
    try:
        with tempfile.TemporaryDirectory(prefix="hq-client-vn-") as directory:
            root = Path(directory)
            HELP.certificates(root)
            for case in ["no-common-version", "offered-v1-present", "wrong-destination-cid", "wrong-source-cid", "truncated-version-list"]:
                report["cases"].append(exercise(args.binary, root, args.ipv6, case))
        if all(case["status"] == "PASSED" for case in report["cases"]):
            report["status"] = "PASSED"
    except Exception as error:
        report["error"] = str(error)
    finally:
        report["binary_sha256_after"] = HELP.sha256(args.binary)
        if report["binary_sha256"] != report["binary_sha256_after"]:
            report["status"] = "FAILED"
            report["error"] = "binary changed during execution"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return int(report["status"] != "PASSED")


if __name__ == "__main__":
    raise SystemExit(main())
