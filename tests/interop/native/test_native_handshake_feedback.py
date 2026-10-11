#!/usr/bin/env python3
"""Native finite-loss regression for Initial ACK feedback and client Finished.

This is a deterministic recovery regression, not a QNS qualification result.
It drops the first Initial in each direction, then a bounded number of client
Handshake datagrams above a configurable protected-payload threshold (24 bytes
by default). Optional selectors also drop bounded Initial feedback and server
short-header packets, or suppress smaller Handshake packets during that window.
The payload-size predicate is a wire-level selector, not a frame classifier.
An unexercised selector makes the result incomplete rather than a pass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from test_direct_handshake_localhost import credentials
from udp_impairment import MultiEndpointProxy


def handshake_payload(data, minimum=24):
    def varint(at):
        size = 1 << (data[at] >> 6)
        if at + size > len(data):
            raise ValueError("truncated varint")
        return int.from_bytes(data[at:at + size], "big") & ((1 << (8 * size - 2)) - 1), at + size

    offset = 0
    try:
        while offset < len(data) and data[offset] & 0x80:
            kind = (data[offset] >> 4) & 3
            if len(data) - offset < 7 or kind == 3:
                return False
            at = offset + 5
            at += 1 + data[at]
            at += 1 + data[at]
            if kind == 0:
                token, at = varint(at)
                at += token
            length, at = varint(at)
            if at + length > len(data):
                return False
            if kind == 2 and length > minimum:
                return True
            offset = at + length
    except (IndexError, ValueError):
        return False
    return False


class FiniteLoss(MultiEndpointProxy):
    def __init__(self, server, limit, initial_feedback=0, server_short=0, payload_minimum=24, suppress_small=False):
        super().__init__(server, client_endpoints=1, delay=0.015, trace_routes=True)
        self.limit = limit
        self.matches = 0
        self.initial_drops = set()
        self.initial_feedback_limit = initial_feedback
        self.initial_feedback_matches = 0
        self.server_short_limit = server_short
        self.server_short_matches = 0
        self.server_initials = 0
        self.payload_minimum = payload_minimum
        self.suppress_small = suppress_small
        self.small_suppressed = 0

    def _enqueue(self, direction, data):
        selected = direction == "to_server" and handshake_payload(data, self.payload_minimum)
        if selected:
            self.matches += 1
        initial = bool(data and data[0] & 0x80 and (data[0] >> 4) & 3 == 0
                       and direction not in self.initial_drops)
        if initial:
            self.initial_drops.add(direction)
        is_initial = bool(data and data[0] & 0x80 and (data[0] >> 4) & 3 == 0)
        if direction == "to_client" and is_initial:
            self.server_initials += 1
        feedback = direction == "to_server" and is_initial and self.server_initials > 0
        if feedback:
            self.initial_feedback_matches += 1
        short = direction == "to_client" and bool(data) and not data[0] & 0x80
        if short:
            self.server_short_matches += 1
        small = (self.suppress_small and direction == "to_server"
                 and handshake_payload(data, 0) and not handshake_payload(data, self.payload_minimum)
                 and self.matches <= self.limit)
        if small:
            self.small_suppressed += 1
        self.drop_every = 1 if (
            initial or small or (selected and self.matches <= self.limit)
            or (feedback and self.initial_feedback_matches <= self.initial_feedback_limit)
            or (short and self.server_short_matches <= self.server_short_limit)
        ) else 0
        super()._enqueue(direction, data)
        self.drop_every = 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("hq", "quiche-client", "quiche-server", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--client", choices=("hq", "quiche"), default="quiche")
    parser.add_argument("--peer", choices=("hq", "quiche"), default="hq")
    parser.add_argument("--drop-handshake", type=int, default=5)
    parser.add_argument("--drop-initial-feedback", type=int, default=0)
    parser.add_argument("--drop-server-short", type=int, default=0)
    parser.add_argument("--handshake-payload-min", type=int, default=24)
    parser.add_argument("--suppress-small-handshake", action="store_true")
    args = parser.parse_args()
    if min(args.drop_handshake, args.drop_initial_feedback, args.drop_server_short, args.handshake_payload_min) < 0:
        parser.error("drop counts and the payload threshold must be nonnegative")
    hq, client_binary, server_binary = (p.resolve(strict=True) for p in
                                      (args.hq, args.quiche_client, args.quiche_server))
    logs = args.output.with_suffix(".logs")
    logs.mkdir(parents=True, exist_ok=False)
    report = {"scope": "finite loss regression, not QNS", "peer": args.peer,
              "requested_handshake_drops": args.drop_handshake,
              "requested_initial_feedback_drops": args.drop_initial_feedback,
              "requested_server_short_drops": args.drop_server_short,
              "handshake_payload_min": args.handshake_payload_min,
              "suppress_small_handshake": args.suppress_small_handshake, "passed": False,
              "started_unix_ns": time.time_ns(),
              "server_sha256": hashlib.sha256((hq if args.peer == "hq" else server_binary).read_bytes()).hexdigest(),
              "client": args.client,
              "client_sha256": hashlib.sha256((hq if args.client == "hq" else client_binary).read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix="hibana-feedback-") as temporary:
        root = Path(temporary)
        credentials(root)
        (root / "www").mkdir()
        (root / "downloads").mkdir()
        body = b"x" * 1024
        (root / "www/body").write_bytes(body)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            address = sock.getsockname()
        listen = f"{address[0]}:{address[1]}"
        if args.peer == "hq":
            command = [str(hq), "server", "--listen", listen, "--cert", str(root / "server.pem"),
                       "--key", str(root / "server.key"), "--www", str(root / "www"),
                       "--timeout-seconds", "45", "--max-requests", "1"]
        else:
            command = [str(server_binary), "--listen", listen, "--cert", str(root / "server.pem"),
                       "--key", str(root / "server.key"), "--root", str(root / "www"), "--no-retry",
                       "--http-version", "HTTP/0.9", "--idle-timeout", "30000", "--disable-gso", "--disable-pacing"]
        env = {**os.environ, "RUST_LOG": "quiche=trace,quiche_apps=info"}
        env.pop("SSLKEYLOGFILE", None)
        proxy = None
        started = time.monotonic()
        with (logs / "server.stderr").open("w") as stderr, (logs / "server.stdout").open("w") as stdout:
            server = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env)
            try:
                deadline = time.monotonic() + 5
                while "listening" not in (logs / "server.stderr").read_text().lower():
                    if server.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("server startup failed")
                    time.sleep(0.01)
                proxy = FiniteLoss(address, args.drop_handshake, args.drop_initial_feedback, args.drop_server_short, args.handshake_payload_min, args.suppress_small_handshake)
                with proxy:
                    connect = f"{proxy.address[0]}:{proxy.address[1]}"
                    command = [str(client_binary), "--http-version", "HTTP/0.9", "--wire-version", "1",
                               "--connect-to", connect, "--trust-origin-ca-pem", str(root / "ca.pem"),
                               "--dump-responses", str(root / "downloads"), "--idle-timeout", "30000",
                               f"https://localhost:{proxy.address[1]}/body"]
                    if args.client == "hq":
                        command = [str(hq), "client", "--connect", connect,
                                   "--server-name", "localhost", "--ca", str(root / "ca.pem"),
                                   "--downloads", str(root / "downloads"),
                                   "--timeout-seconds", "45", "--request", "/body"]
                    client = subprocess.run(command, capture_output=True, text=True, env=env, timeout=45)
                    (logs / "client.stderr").write_text(client.stderr)
                    (logs / "client.stdout").write_text(client.stdout)
                    report["client_exit"] = client.returncode
                    received = root / "downloads/body"
                    report["file_equal"] = received.exists() and received.read_bytes() == body
                    report["injection_complete"] = (proxy.matches >= args.drop_handshake and len(proxy.initial_drops) == 2
                                                    and proxy.initial_feedback_matches >= args.drop_initial_feedback
                                                    and proxy.server_short_matches >= args.drop_server_short
                                                    and (not args.suppress_small_handshake or proxy.small_suppressed > 0))
                    report["passed"] = client.returncode == 0 and report["file_equal"] and report["injection_complete"]
            except Exception as error:
                report["error"] = repr(error)
                if isinstance(error, subprocess.TimeoutExpired):
                    report["timeout_command"] = error.cmd
                    for name, value in (("stdout", error.stdout), ("stderr", error.stderr)):
                        if isinstance(value, bytes):
                            value = value.decode(errors="replace")
                        (logs / ("client." + name)).write_text(value or "")
            finally:
                if proxy:
                    report["proxy"] = dict(proxy.stats)
                    report["observed_handshake_datagrams"] = proxy.matches
                    report["observed_initial_feedback"] = proxy.initial_feedback_matches
                    report["observed_server_short"] = proxy.server_short_matches
                    report["small_handshake_suppressed"] = proxy.small_suppressed
                    report["route_trace"] = proxy.route_trace
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                report["elapsed_seconds"] = time.monotonic() - started
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS" if report["passed"] else "FAIL", args.output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
