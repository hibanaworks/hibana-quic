#!/usr/bin/env python3
"""Real UDP ECN/ACK_ECN, controlled CE/bleaching, corruption and replay tests.

Only IP ancillary markings are changed by the local relay. It never decrypts or
constructs an ACK. This is direct development evidence, not a router/QNS test.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading
import time

SPEC = importlib.util.spec_from_file_location("hq_localhost", Path(__file__).with_name("test_hq_localhost.py"))
HELP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELP)


class Relay:
    def __init__(self, server, mode):
        host, port = server.rsplit(":", 1)
        self.server = (host, int(port))
        self.mode = mode
        self.client = None
        self.front, self.back = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2))
        for sock in [self.front, self.back]:
            sock.bind(("127.0.0.1", 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
        self.address = "%s:%s" % self.front.getsockname()
        self.stop = threading.Event()
        self.counts = {"forwarded": 0, "observed_ect0": 0, "injected_ce": 0, "bleached": 0, "duplicated": 0, "duplicate_ce": 0, "corrupted": 0, "reordered": 0}
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        short_packets = 0
        front_packets = 0
        held = None
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.front, self.back], [], [], 0.05)
                for incoming in ready:
                    data, ancillary, flags, source = incoming.recvmsg(65535, socket.CMSG_SPACE(4))
                    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                        raise RuntimeError("relay received truncated UDP/metadata")
                    tos = [v[0] for level, kind, v in ancillary if level == socket.IPPROTO_IP and kind == socket.IP_TOS]
                    if len(tos) != 1:
                        raise RuntimeError("relay has no unique actual kernel TOS observation")
                    code = tos[0] & 3
                    if code == 2:
                        self.counts["observed_ect0"] += 1
                    if incoming is self.front:
                        if self.client is None:
                            self.client = source
                        if source != self.client:
                            continue
                        outgoing, destination = self.back, self.server
                    else:
                        if source != self.server or self.client is None:
                            continue
                        outgoing, destination = self.front, self.client
                    duplicate = False
                    if self.mode == "ce_loss_replay" and incoming is self.front and code == 2 and data and not (data[0] & 0x80):
                        front_packets += 1
                        if front_packets == 150:
                            held = (data, code, outgoing, destination)
                            continue
                    if self.mode == "bleach" and code in [1, 2]:
                        code = 0
                        self.counts["bleached"] += 1
                    if self.mode == "ce_loss_replay" and incoming is self.back and code == 2 and data and not (data[0] & 0x80):
                        short_packets += 1
                        if short_packets == 100:
                            duplicate = True
                            self.counts["duplicated"] += 1
                        elif short_packets == 200:
                            data = data[:-1] + bytes([data[-1] ^ 1])
                            self.counts["corrupted"] += 1
                        elif short_packets == 300:
                            code = 3
                            self.counts["injected_ce"] += 1
                    message = [(socket.IPPROTO_IP, socket.IP_TOS, bytes([code]))]
                    outgoing.sendmsg([data], message, 0, destination)
                    if duplicate:
                        # CE on a replay must not create another receive count
                        # or congestion event: duplicate QUIC packets are ignored.
                        outgoing.sendmsg([data], [(socket.IPPROTO_IP, socket.IP_TOS, bytes([3]))], 0, destination)
                        self.counts["duplicate_ce"] += 1
                    self.counts["forwarded"] += 1 + int(duplicate)
                    if incoming is self.front and held is not None:
                        old_data, old_code, old_socket, old_destination = held
                        old_socket.sendmsg([old_data], [(socket.IPPROTO_IP, socket.IP_TOS, bytes([old_code]))], 0, old_destination)
                        self.counts["forwarded"] += 1
                        self.counts["reordered"] += 1
                        held = None
        except Exception as error:
            self.error = repr(error)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.front.close()
        self.back.close()


def run(binary, root, mode):
    server, address = HELP.launch_server(binary, root, 1, 60, ["--ecn", "on"])
    relay = Relay(address, mode)
    directory = root / f"downloads-{mode}"
    try:
        client = subprocess.run([str(binary), "client", "--connect", relay.address, "--server-name", "localhost", "--ca", str(root / "ca.pem"), "--downloads", str(directory), "--request", "/five-mib.bin", "--timeout-seconds", "60", "--ecn", "on"], text=True, capture_output=True, timeout=65)
        stdout, stderr = server.communicate(timeout=65)
        return {"client_exit": client.returncode, "server_exit": server.returncode, "client": json.loads(client.stdout), "server": json.loads(stdout), "client_stderr": client.stderr, "server_stderr": stderr, "relay": relay.counts, "relay_error": relay.error, "download_sha256": HELP.sha256(directory / "five-mib.bin") if (directory / "five-mib.bin").exists() else None}
    finally:
        relay.close()
        if server.poll() is None:
            server.kill()
            server.communicate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    os.umask(0o077)
    started = time.monotonic()
    report = {"status": "FAILED", "scope": "real-udp-ecn-and-authenticated-ack-ecn", "binary_sha256": HELP.sha256(binary), "runs": {}, "not_claimed": ["quic-interop-runner", "production router CE marking", "Pico hardware", "whole-host no allocation"]}
    try:
        with tempfile.TemporaryDirectory(prefix="hibana-hq-ecn-") as directory:
            root = Path(directory)
            (root / "www").mkdir()
            HELP.certificates(root)
            with (root / "www/five-mib.bin").open("wb") as body:
                for index in range(5 * 1024):
                    body.write(bytes([index % 251]) * 1024)
            expected = HELP.sha256(root / "www/five-mib.bin")
            report["expected_sha256"] = expected
            for mode in ["pass", "ce_loss_replay", "bleach"]:
                result = run(binary, root, mode)
                report["runs"][mode] = result
                assert result["client_exit"] == result["server_exit"] == 0, result
                assert result["relay_error"] is None, result
                assert result["download_sha256"] == expected
                for role in ["client", "server"]:
                    peer = result[role]
                    assert peer["body_bytes"] == 5 * 1024 * 1024
                    ecn = peer["ecn"]
                    assert ecn["enabled"]
                    assert sum(space["sent_ect0"] for space in ecn["spaces"]) > 0
                    if mode == "bleach":
                        assert ecn["state"] == "Failed" and ecn["failure"] == "Bleached", result
                        assert all(space["received"]["ect0"] == 0 for space in ecn["spaces"])
                        assert ecn["validated_ce"] == 0
                    else:
                        assert ecn["state"] == "Capable" and ecn["failure"] is None, result
                        # Every processed packet has a real marked IP observation.
                        # Replay/corruption must not add a receive counter.
                        counted = sum(sum(space["received"].values()) for space in ecn["spaces"])
                        assert counted == peer["authenticated_packets"], result
                if mode == "ce_loss_replay":
                    assert result["relay"]["injected_ce"] == result["relay"]["duplicated"] == result["relay"]["corrupted"] == 1
                    assert result["relay"]["duplicate_ce"] == result["relay"]["reordered"] == 1
                    assert result["server"]["ecn"]["validated_ce"] == 1
                    assert result["server"]["ecn"]["congestion_events"] >= 1
                    assert result["client"]["discarded_packets"] >= 2
                elif mode == "bleach":
                    assert result["relay"]["bleached"] > 0
            report["status"] = "PASSED"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(report, indent=2) + "\n"
        args.output.write_text(encoded)
        print(encoded, end="")


if __name__ == "__main__":
    main()
