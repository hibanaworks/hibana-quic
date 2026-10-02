#!/usr/bin/env python3
"""Authenticated real-UDP HQ path migration development regressions.

The NAT relay routes opaque datagrams immediately and preserves actual kernel
TOS/ECN observations. It has no QUIC keys or frame parser, and retains at most
one protected datagram for optional replay/corruption. A rebinding happens only
after the client has written at least 128 KiB of the actual five-MiB body. The
retired mapping stops delivering packets to the client at that exact switch.

This is direct host development evidence, not quic-interop-runner, arbitrary
active migration, or an embedded memory measurement. Ephemeral certificates and
private keys stay inside the temporary fixture directory, never in the report.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time


SPEC = importlib.util.spec_from_file_location(
    "hq_localhost", Path(__file__).with_name("test_hq_localhost.py")
)
HELP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELP)

BODY_BYTES = 5 * 1024 * 1024
SWITCH_AFTER = 128 * 1024
CASES = (
    "baseline",
    "nat_port",
    "nat_ip",
    "preferred_concrete",
    "preferred_wildcard",
    "wrong_hostname",
    "wrong_ca",
)


def address_text(address):
    return f"{address[0]}:{address[1]}"


def udp_socket(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
        return sock
    except BaseException:
        sock.close()
        raise


class RebindingRelay:
    """One front socket and two bounded, distinct server-facing mappings."""

    def __init__(self, server_address, downloads, mode, perturb):
        host, port = server_address.rsplit(":", 1)
        self.server = (host, int(port))
        self.downloads = downloads
        self.client = None
        self.sockets = []
        try:
            for local in ("127.0.0.1", "127.0.0.1", "127.0.0.2" if mode == "nat_ip" else "127.0.0.1"):
                self.sockets.append(udp_socket(local))
        except BaseException:
            for sock in self.sockets:
                sock.close()
            raise
        self.front, self.old, self.new = self.sockets
        self.address = address_text(self.front.getsockname())
        self.switched = False
        self.perturb = perturb
        self.saved = None
        self.error = None
        self.stop = threading.Event()
        self.started = time.monotonic()
        self.metadata = {
            "mode": mode,
            "front": self.address,
            "initial_mapping": address_text(self.old.getsockname()),
            "replacement_mapping": address_text(self.new.getsockname()),
            "switch_threshold_body_bytes": SWITCH_AFTER,
            "switch_observed_body_bytes": None,
            "switch_elapsed_ms": None,
            "client_to_server_before": 0,
            "client_to_server_after": 0,
            "server_to_client_before": 0,
            "server_to_client_after": 0,
            "retired_mapping_dropped_datagrams": 0,
            "retired_mapping_dropped_bytes": 0,
            "unexpected_source_dropped": 0,
            "observed_ecn": {direction: {str(code): 0 for code in range(4)} for direction in ("client_to_server", "server_to_client")},
            "forwarded_ecn": {direction: {str(code): 0 for code in range(4)} for direction in ("client_to_server", "server_to_client")},
            "perturbations_requested": perturb,
            "replayed_pre_switch_protected_datagrams": 0,
            "corrupted_protected_datagrams": 0,
            "replay_source_mapping": None,
            "corruption_source_mapping": None,
            "maximum_retained_datagrams": 1 if perturb else 0,
            "routing": "immediate, no user-space forwarding queue",
            "ciphertext": "preserved except one explicitly requested corrupted duplicate",
            "ecn": "original kernel TOS forwarded unchanged with sendmsg ancillary data",
        }
        self.thread = threading.Thread(target=self.run, name="hq-path-relay", daemon=True)
        self.thread.start()

    def progress(self):
        # The application publishes its final filename only after receiving FIN.
        # stat() on its one temporary file observes real consumed body bytes.
        sizes = []
        for path in self.downloads.glob(".hibana-*.part"):
            try:
                sizes.append(path.stat().st_size)
            except FileNotFoundError:
                pass
        return max(sizes, default=0)

    @staticmethod
    def send(sock, destination, data, tos):
        sent = sock.sendmsg(
            [data], [(socket.IPPROTO_IP, socket.IP_TOS, bytes([tos]))], 0, destination
        )
        if sent != len(data):
            raise RuntimeError("relay UDP send did not accept the complete datagram")

    def run(self):
        try:
            while not self.stop.is_set():
                readable, _, _ = select.select(self.sockets, [], [], 0.02)
                for incoming in readable:
                    data, ancillary, flags, source = incoming.recvmsg(65535, socket.CMSG_SPACE(4))
                    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                        raise RuntimeError("truncated relay UDP datagram or ancillary metadata")
                    markings = [value[0] for level, kind, value in ancillary if level == socket.IPPROTO_IP and kind == socket.IP_TOS and value]
                    if len(markings) != 1:
                        raise RuntimeError("relay did not receive one actual kernel TOS observation")
                    tos = markings[0]
                    if incoming is self.front:
                        if self.client is None:
                            self.client = source
                        if source != self.client:
                            self.metadata["unexpected_source_dropped"] += 1
                            continue
                        direction = "client_to_server"
                        if not self.switched:
                            progress = self.progress()
                            if progress >= SWITCH_AFTER:
                                if progress >= BODY_BYTES:
                                    raise RuntimeError("NAT switch missed the in-progress body window")
                                self.switched = True
                                self.metadata["switch_observed_body_bytes"] = progress
                                self.metadata["switch_elapsed_ms"] = round((time.monotonic() - self.started) * 1000, 3)
                        outgoing = self.new if self.switched else self.old
                        destination = self.server
                        if self.perturb and not self.switched and data and data[0] & 0xC0 == 0x40:
                            self.saved = (data, tos)
                    else:
                        if source != self.server or self.client is None:
                            self.metadata["unexpected_source_dropped"] += 1
                            continue
                        direction = "server_to_client"
                        if self.switched and incoming is self.old:
                            self.metadata["retired_mapping_dropped_datagrams"] += 1
                            self.metadata["retired_mapping_dropped_bytes"] += len(data)
                            self.metadata["observed_ecn"][direction][str(tos & 3)] += 1
                            continue
                        if not self.switched and incoming is self.new:
                            raise RuntimeError("server sent to unused replacement mapping")
                        outgoing, destination = self.front, self.client
                    self.metadata["observed_ecn"][direction][str(tos & 3)] += 1
                    self.send(outgoing, destination, data, tos)
                    self.metadata["forwarded_ecn"][direction][str(tos & 3)] += 1
                    self.metadata[f"{direction}_{'after' if self.switched else 'before'}"] += 1
                    if (self.perturb and self.saved is not None and self.switched
                            and self.metadata["client_to_server_after"] >= 16
                            and self.metadata["server_to_client_after"] >= 16):
                        saved, original_tos = self.saved
                        # A delayed duplicate from the retired mapping must not
                        # undo a genuine change learned from authenticated traffic.
                        self.send(self.old, self.server, saved, original_tos)
                        self.metadata["replayed_pre_switch_protected_datagrams"] = 1
                        self.metadata["replay_source_mapping"] = self.metadata["initial_mapping"]
                        corrupted = saved[:-1] + bytes([saved[-1] ^ 1])
                        self.send(self.new, self.server, corrupted, original_tos)
                        self.metadata["corrupted_protected_datagrams"] = 1
                        self.metadata["corruption_source_mapping"] = self.metadata["replacement_mapping"]
                        self.saved = None
        except BaseException as error:
            self.error = f"{type(error).__name__}: {error}"
            self.stop.set()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("relay did not stop")
        for sock in self.sockets:
            sock.close()
        self.saved = None


class Processes:
    """Regular-file logging keeps subprocess pipes from blocking the transfer."""

    def __init__(self, root):
        self.root = root
        self.processes = {}
        self.files = []

    def start(self, role, command):
        output = (self.root / f"{role}.stdout").open("w")
        error = (self.root / f"{role}.stderr").open("w")
        self.files.extend((output, error))
        process = subprocess.Popen(command, stdout=output, stderr=error, text=True)
        self.processes[role] = process
        return process

    def text(self, role, kind):
        path = self.root / f"{role}.{kind}"
        return path.read_text() if path.exists() else ""

    def finish(self):
        for process in self.processes.values():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        for stream in self.files:
            stream.close()


def permission_denied(text):
    lowered = text.lower()
    return "permission denied" in lowered or "operation not permitted" in lowered


def run_case(binary, fixture, name, timeout, perturb=False):
    started = time.monotonic()
    root = fixture / name
    root.mkdir()
    downloads = root / "downloads"
    processes = Processes(root)
    relay = None
    result = {"case": name, "errors": [], "denied": False}
    try:
        preferred = None
        if name.startswith("preferred_"):
            # Reserve an available unprivileged port, then release it for hq.
            # A bind race fails this case; it is never concealed by a retry.
            with udp_socket("127.0.0.2") as reservation:
                preferred = address_text(reservation.getsockname())
        listen = "0.0.0.0:0" if name == "preferred_wildcard" else "127.0.0.1:0"
        server_command = [str(binary), "server", "--listen", listen, "--cert", str(fixture / "server.pem"), "--key", str(fixture / "server.key"), "--www", str(fixture / "www"), "--max-requests", "1", "--timeout-seconds", str(timeout), "--ecn", "on"]
        if preferred:
            server_command += ["--preferred-address", preferred]
        server = processes.start("server", server_command)
        startup_deadline = time.monotonic() + 5
        address = None
        while time.monotonic() < startup_deadline:
            for line in processes.text("server", "stderr").splitlines():
                if line.startswith("listening "):
                    address = line.split()[1]
                    break
            if address is not None:
                break
            if server.poll() is not None:
                raise RuntimeError(f"server startup failed: {processes.text('server', 'stderr')} {processes.text('server', 'stdout')}")
            time.sleep(0.01)
        if address is None:
            raise RuntimeError("server did not announce its listening address")
        if address.startswith("0.0.0.0:"):
            address = "127.0.0.1:" + address.rsplit(":", 1)[1]
        result["initial_server_address"] = address
        result["preferred_server_address"] = preferred
        connect = address
        if name in ("nat_port", "nat_ip"):
            relay = RebindingRelay(address, downloads, name, perturb)
            connect = relay.address
        ca = fixture / ("alternate/ca.pem" if name == "wrong_ca" else "ca.pem")
        hostname = "wrong.invalid" if name == "wrong_hostname" else "localhost"
        command = [str(binary), "client", "--connect", connect, "--server-name", hostname, "--ca", str(ca), "--downloads", str(downloads), "--request", "/five-mib.bin", "--timeout-seconds", str(timeout), "--ecn", "on"]
        processes.start("client", command)
        deadline = time.monotonic() + timeout + 5
        while any(process.poll() is None for process in processes.processes.values()):
            if relay is not None and relay.error:
                raise RuntimeError(f"relay failed: {relay.error}")
            if time.monotonic() >= deadline:
                raise RuntimeError("host processes exceeded their bounded timeout")
            time.sleep(0.01)
    except Exception as error:
        result["errors"].append(f"{type(error).__name__}: {error}")
        result["denied"] = isinstance(error, PermissionError) or permission_denied(str(error))
    finally:
        processes.finish()
        if relay is not None:
            relay.close()
            result["relay"] = relay.metadata
            result["relay_error"] = relay.error
            if relay.error and relay.error not in " ".join(result["errors"]):
                result["errors"].append(relay.error)
            result["denied"] |= permission_denied(relay.error or "")
        for role, process in processes.processes.items():
            result[f"{role}_exit"] = process.returncode
            output, error = processes.text(role, "stdout"), processes.text(role, "stderr")
            result[f"{role}_stderr"] = error
            result["denied"] |= permission_denied(output + error)
            try:
                result[role] = json.loads(output)
            except json.JSONDecodeError:
                result[role] = None
                result[f"{role}_unparsed_stdout"] = output
                result["errors"].append(f"{role} did not emit one valid JSON report")
        target = downloads / "five-mib.bin"
        result["download"] = {"exists": target.exists(), "bytes": target.stat().st_size if target.exists() else 0, "sha256": HELP.sha256(target) if target.exists() else None, "remaining_partial_files": len(list(downloads.glob(".hibana-*.part")))}
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def validate(result, expected_hash, perturb):
    def require(condition, message):
        if not condition:
            result["errors"].append(message)

    name = result["case"]
    if name in ("wrong_hostname", "wrong_ca"):
        for role in ("client", "server"):
            peer = result.get(role) or {}
            require(result.get(f"{role}_exit") not in (None, 0), f"{role} accepted invalid server authentication")
            require(peer.get("status") != "success", f"{role} incorrectly reported success")
        require(not result["download"]["exists"], "authentication failure published a body")
        require(result["download"]["remaining_partial_files"] == 0, "authentication failure retained partial body")
        client = result.get("client") or {}
        require(client.get("status") == "failure", "authentication negative did not produce explicit client failure")
        error = client.get("error", "")
        require("Authentication" in error and "Certificate" in error, "negative failed for a reason other than certificate authentication")
        if name == "wrong_hostname":
            require("CertNotValidForName" in error, "wrong-hostname negative did not reject the certificate name")
        else:
            require("InvalidSignatureForPublicKey" in error or "UnknownIssuer" in error, "wrong-CA negative did not reject the certificate issuer/signature")
        return
    for role in ("client", "server"):
        peer = result.get(role) or {}
        require(result.get(f"{role}_exit") == 0, f"{role} exited unsuccessfully")
        require(peer.get("status") == "success", f"{role} did not report success")
        require(peer.get("files_completed") == 1, f"{role} did not retire the FIN-complete stream")
        require(peer.get("body_bytes") == BODY_BYTES, f"{role} body byte total differs from exactly five MiB")
        require(peer.get("lifecycle_closed") is True, f"{role} did not reach real Closed state")
        require(peer.get("alpn") == "hq-interop", f"{role} negotiated unexpected ALPN")
        require(peer.get("authenticated_packets", 0) > 0, f"{role} has no authenticated packets")
        network = peer.get("network") or {}
        require(network.get("initial") is not None and network.get("active") is not None, f"{role} omitted actual network tuples")
    client, server = result.get("client") or {}, result.get("server") or {}
    require(client.get("authentication") == "verified-certificate", "client did not use full server-certificate authentication")
    require(client.get("certificate_chain_hostname_time_verified") is True, "client did not verify CA, hostname, and certificate time")
    require(server.get("authentication") == "peer-finished", "server did not authenticate the client Finished")
    require(result["download"]["bytes"] == BODY_BYTES, "published download length differs from exactly five MiB")
    require(result["download"]["sha256"] == expected_hash, "published download SHA-256 mismatch")
    require(result["download"]["remaining_partial_files"] == 0, "FIN-complete transfer left a partial file")
    networks = {role: (result.get(role) or {}).get("network") or {} for role in ("client", "server")}
    if name == "baseline":
        for role, network in networks.items():
            require(network.get("initial") == network.get("active"), f"{role} baseline changed address tuple")
            require(network.get("active_path_changes") == 0, f"{role} baseline changed active path")
    elif name in ("nat_port", "nat_ip"):
        relay = result.get("relay") or {}
        switched = relay.get("switch_observed_body_bytes")
        require(isinstance(switched, int) and SWITCH_AFTER <= switched < BODY_BYTES, "rebinding was not triggered by real mid-file progress")
        require(relay.get("client_to_server_after", 0) > 0 and relay.get("server_to_client_after", 0) > 0, "replacement mapping did not carry both directions")
        initial, active = networks["server"].get("initial") or {}, networks["server"].get("active") or {}
        require(initial.get("remote") == relay.get("initial_mapping"), "server initial remote differs from actual original NAT mapping")
        require(active.get("remote") == relay.get("replacement_mapping"), "server failed to adopt actual replacement NAT mapping")
        require(initial.get("local") == active.get("local"), "NAT rebinding unexpectedly changed server local address")
        require(networks["server"].get("active_path_changes", 0) >= 1, "server did not report an active path change")
        require(networks["server"].get("address_and_mtu_validated") is True, "replacement NAT path did not pass address and MTU validation")
        require(networks["client"].get("initial") == networks["client"].get("active"), "relay changed the client-visible tuple")
        require(networks["client"].get("active_path_changes") == 0, "NAT case unexpectedly changed client active path")
        old_host = (relay.get("initial_mapping") or "").split(":")[0]
        new_host = (relay.get("replacement_mapping") or "").split(":")[0]
        require(new_host == ("127.0.0.2" if name == "nat_ip" else old_host), "NAT replacement IP does not match case")
        require(relay.get("initial_mapping") != relay.get("replacement_mapping"), "NAT replacement mapping is unchanged")
        for direction in ("client_to_server", "server_to_client"):
            require(relay.get("observed_ecn", {}).get(direction, {}).get("2", 0) > 0, f"relay did not observe actual ECT(0) {direction}")
        if perturb:
            require(relay.get("replayed_pre_switch_protected_datagrams") == 1, "requested protected replay did not occur exactly once")
            require(relay.get("corrupted_protected_datagrams") == 1, "requested corruption did not occur exactly once")
            require(server.get("discarded_packets", 0) >= 2, "server did not discard replay and corruption")
    elif name.startswith("preferred_"):
        preferred = result["preferred_server_address"]
        for role, network in networks.items():
            require(network.get("active_path_changes", 0) >= 1, f"{role} did not report preferred-address path change")
            require(network.get("address_and_mtu_validated") is True, f"{role} preferred path did not pass address and MTU validation")
            require(network.get("initial") != network.get("active"), f"{role} preferred-address tuple stayed unchanged")
        ci, ca = networks["client"].get("initial") or {}, networks["client"].get("active") or {}
        si, sa = networks["server"].get("initial") or {}, networks["server"].get("active") or {}
        require(ci.get("remote") == si.get("local") == result["initial_server_address"], "preferred initial tuple does not match concrete received metadata")
        require(ca.get("remote") == sa.get("local") == preferred, "preferred advertised address was not adopted by both endpoints")
        require(ci.get("local") == ca.get("local") == si.get("remote") == sa.get("remote"), "preferred migration unexpectedly changed the client endpoint")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--inject-replay-corruption", action="store_true", help="after each NAT switch, inject one saved protected replay from the retired mapping and one corrupted duplicate from the replacement mapping")
    parser.add_argument("--case", action="append", choices=CASES, help="run only selected cases; report never claims the full suite")
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 300:
        parser.error("--timeout-seconds must be 1..300")
    if args.output.exists():
        parser.error("--output already exists; preserve prior evidence with a fresh output path")
    os.umask(0o077)
    binary = args.binary.resolve(strict=True)
    selected = list(dict.fromkeys(args.case or CASES))
    started = time.monotonic()
    report = {
        "status": "FAILED",
        "scope": "direct-host-udp-authenticated-path-migration",
        "binary": str(binary),
        "binary_sha256": HELP.sha256(binary),
        "harness_sha256": HELP.sha256(Path(__file__)),
        "suite_complete": selected == list(CASES),
        "selected_cases": selected,
        "expected_body_bytes": BODY_BYTES,
        "fin_evidence": "published file and files_completed=1 require consumed FIN and successful stream retirement in hq",
        "closed_evidence": "lifecycle_closed=true requires actual ConnectionState::Closed in hq",
        "authentication": "explicit ephemeral CA plus localhost SAN; full certificate chain, hostname and time verification; server verifies peer Finished",
        "not_claimed": ["quic-interop-runner", "third-party QUIC implementation interoperability", "arbitrary active migration", "client-certificate authentication", "embedded RAM bounds", "whole-host no allocation", "Pico hardware"],
        "runs": {},
        "errors": [],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="hibana-hq-paths-") as directory:
            fixture = Path(directory)
            (fixture / "www").mkdir()
            HELP.certificates(fixture)
            if "wrong_ca" in selected:
                (fixture / "alternate").mkdir()
                HELP.certificates(fixture / "alternate")
            source = fixture / "www/five-mib.bin"
            with source.open("wb") as body:
                for index in range(5 * 1024):
                    body.write(bytes([index % 251]) * 1024)
            report["expected_sha256"] = HELP.sha256(source)
            for name in selected:
                timeout = min(args.timeout_seconds, 4) if name in ("wrong_hostname", "wrong_ca") else args.timeout_seconds
                result = run_case(binary, fixture, name, timeout, args.inject_replay_corruption)
                report["runs"][name] = result
                validate(result, report["expected_sha256"], args.inject_replay_corruption)
                result["status"] = "FAILED" if result["errors"] else "PASSED"
                print(f"{name}: {result['status']} ({result['elapsed_seconds']}s)", file=sys.stderr, flush=True)
                if result["denied"]:
                    report["errors"].append(f"host network operation denied in {name}; stopped without an alternate route")
                    break
            report["binary_sha256_after"] = HELP.sha256(binary)
            if report["binary_sha256_after"] != report["binary_sha256"]:
                report["errors"].append("tested binary changed during suite execution")
            if (len(report["runs"]) == len(selected) and not report["errors"]
                    and all(run["status"] == "PASSED" for run in report["runs"].values())):
                report["status"] = "PASSED"
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(report, indent=2) + "\n"
        with args.output.open("x") as output:
            output.write(encoded)
        print(encoded, end="")
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
