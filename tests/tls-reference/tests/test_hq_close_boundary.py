#!/usr/bin/env python3
"""Authenticated HQ-only UDP qualification at the published-file boundary.

The server deliberately omits --max-requests. Its peer must exercise the
standalone client's completed-transfer close branch. Impairment starts only
when the client's final five-MiB file becomes visible after consumed FIN.
Datagrams are opaque: these tests never identify a protected packet as CLOSE.
Encrypted in-memory tests must independently identify actual CLOSE frames.

One fixed UDP relay preserves protected bytes and original kernel TOS/ECN.
Finite delay has strict queue byte/datagram caps; loss has explicit budgets.
All sockets, subprocesses, and waits are bounded. This harness uses no Neqo,
interface lookup, external network, or out-of-band body transfer.
"""

import argparse
import hashlib
import heapq
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import sys
import tempfile
import threading
import time

SPEC = importlib.util.spec_from_file_location("hq_paths", Path(__file__).with_name("test_hq_paths.py"))
PATHS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATHS)
HELP = PATHS.HELP
SIZE = 5 * 1024 * 1024
CASES = ("baseline", "finite_loss", "finite_delay", "permanent_outage")
FLOWS = ("client_to_server", "server_to_client")
MAX_QUEUE_DATAGRAMS = 64
MAX_QUEUE_BYTES = 96 * 1024
MAX_TRACE_EVENTS = 256
DELAY_SECONDS = 0.08
LOSS_LIMITS = {"client_to_server": 2, "server_to_client": 1}


class BoundaryRelay:
    def __init__(self, server, target, profile):
        host, port = server.rsplit(":", 1)
        self.server = (host, int(port))
        self.target = target
        self.profile = profile
        self.front = PATHS.udp_socket("127.0.0.1")
        try:
            self.back = PATHS.udp_socket("127.0.0.1")
        except BaseException:
            self.front.close()
            raise
        self.sockets = (self.front, self.back)
        self.address = PATHS.address_text(self.front.getsockname())
        self.client = None
        self.stop = threading.Event()
        self.error = None
        self.queue = []
        self.queued_bytes = 0
        self.sequence = 0
        self.started = time.monotonic()
        self.boundary = False
        self.boundary_at = None
        self.metadata = {
            "profile": profile,
            "front": self.address,
            "server_mapping": PATHS.address_text(self.back.getsockname()),
            "boundary": "first observation of the published FIN-complete client file",
            "boundary_observed_bytes": None,
            "boundary_elapsed_ms": None,
            "packet_classification": "opaque datagrams after final-file visibility; protected contents are not decoded or asserted",
            "ciphertext": "all forwarded bytes are unchanged; selected datagrams may be dropped or delayed",
            "ecn": "original kernel TOS forwarded unchanged with sendmsg ancillary data",
            "configured_delay_ms": DELAY_SECONDS * 1000 if profile == "finite_delay" else 0,
            "configured_loss_limits": LOSS_LIMITS if profile == "finite_loss" else None,
            "queue_limits": {"datagrams": MAX_QUEUE_DATAGRAMS, "bytes": MAX_QUEUE_BYTES},
            "peak_queue_datagrams": 0,
            "peak_queue_bytes": 0,
            "minimum_observed_delay_ms": None,
            "maximum_observed_delay_ms": None,
            "queue_discarded_at_cleanup_datagrams": 0,
            "queue_discarded_at_cleanup_bytes": 0,
            "unexpected_source_dropped": 0,
            "trace": [],
            "trace_events_omitted": 0,
            "flows": {flow: {"before": 0, "after": 0, "dropped_after": 0, "delayed_after": 0, "forwarded_after": 0, "observed_ecn": {str(i): 0 for i in range(4)}, "forwarded_ecn": {str(i): 0 for i in range(4)}} for flow in FLOWS},
        }
        self.thread = threading.Thread(target=self.run, name="hq-close-boundary-relay", daemon=True)
        self.thread.start()

    def observe_boundary(self):
        if self.boundary:
            return
        try:
            size = self.target.stat().st_size
        except FileNotFoundError:
            return
        if size != SIZE:
            raise RuntimeError("published boundary file is not exactly five MiB")
        self.boundary_at = time.monotonic()
        self.boundary = True
        self.metadata["boundary_observed_bytes"] = size
        self.metadata["boundary_elapsed_ms"] = round((self.boundary_at - self.started) * 1000, 3)

    def record(self, flow, data, tos, disposition, sequence):
        if len(self.metadata["trace"]) >= MAX_TRACE_EVENTS:
            self.metadata["trace_events_omitted"] += 1
            return
        self.metadata["trace"].append({"sequence": sequence, "elapsed_ms": round((time.monotonic() - self.started) * 1000, 3), "direction": flow, "bytes": len(data), "tos": tos, "sha256": hashlib.sha256(data).hexdigest(), "disposition": disposition})

    def forward(self, outgoing, destination, data, tos, flow, after, sequence):
        PATHS.RebindingRelay.send(outgoing, destination, data, tos)
        counts = self.metadata["flows"][flow]
        counts["forwarded_ecn"][str(tos & 3)] += 1
        if after:
            counts["forwarded_after"] += 1
            self.record(flow, data, tos, "forwarded", sequence)

    def flush_due(self):
        while self.queue and self.queue[0][0] <= time.monotonic():
            due, sequence, outgoing, destination, data, tos, flow = heapq.heappop(self.queue)
            self.queued_bytes -= len(data)
            delay_ms = (time.monotonic() - due + DELAY_SECONDS) * 1000
            old_min = self.metadata["minimum_observed_delay_ms"]
            old_max = self.metadata["maximum_observed_delay_ms"]
            self.metadata["minimum_observed_delay_ms"] = delay_ms if old_min is None else min(old_min, delay_ms)
            self.metadata["maximum_observed_delay_ms"] = delay_ms if old_max is None else max(old_max, delay_ms)
            self.forward(outgoing, destination, data, tos, flow, True, sequence)

    def run(self):
        try:
            while not self.stop.is_set():
                self.observe_boundary()
                self.flush_due()
                wait = 0.01
                if self.queue:
                    wait = min(wait, max(0, self.queue[0][0] - time.monotonic()))
                readable, _, _ = select.select(self.sockets, [], [], wait)
                for incoming in readable:
                    data, ancillary, flags, source = incoming.recvmsg(65535, socket.CMSG_SPACE(4))
                    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                        raise RuntimeError("truncated relay datagram or kernel TOS metadata")
                    markings = [value[0] for level, kind, value in ancillary if level == socket.IPPROTO_IP and kind == socket.IP_TOS and value]
                    if len(markings) != 1:
                        raise RuntimeError("expected one actual kernel TOS observation")
                    tos = markings[0]
                    if incoming is self.front:
                        if self.client is None:
                            self.client = source
                        if source != self.client:
                            self.metadata["unexpected_source_dropped"] += 1
                            continue
                        flow, outgoing, destination = "client_to_server", self.back, self.server
                    else:
                        if source != self.server or self.client is None:
                            self.metadata["unexpected_source_dropped"] += 1
                            continue
                        flow, outgoing, destination = "server_to_client", self.front, self.client
                    self.observe_boundary()
                    after = self.boundary
                    self.sequence += 1
                    sequence = self.sequence
                    counts = self.metadata["flows"][flow]
                    counts["after" if after else "before"] += 1
                    counts["observed_ecn"][str(tos & 3)] += 1
                    if after and (self.profile == "permanent_outage" or (self.profile == "finite_loss" and counts["dropped_after"] < LOSS_LIMITS[flow])):
                        counts["dropped_after"] += 1
                        self.record(flow, data, tos, "dropped", sequence)
                    elif after and self.profile == "finite_delay":
                        if len(self.queue) >= MAX_QUEUE_DATAGRAMS or self.queued_bytes + len(data) > MAX_QUEUE_BYTES:
                            raise RuntimeError("finite-delay relay queue capacity exceeded")
                        heapq.heappush(self.queue, (time.monotonic() + DELAY_SECONDS, sequence, outgoing, destination, data, tos, flow))
                        self.queued_bytes += len(data)
                        counts["delayed_after"] += 1
                        self.metadata["peak_queue_datagrams"] = max(self.metadata["peak_queue_datagrams"], len(self.queue))
                        self.metadata["peak_queue_bytes"] = max(self.metadata["peak_queue_bytes"], self.queued_bytes)
                        self.record(flow, data, tos, "delayed", sequence)
                    else:
                        self.forward(outgoing, destination, data, tos, flow, after, sequence)
        except BaseException as error:
            self.error = f"{type(error).__name__}: {error}"
            self.stop.set()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("close-boundary relay did not stop")
        self.metadata["queue_discarded_at_cleanup_datagrams"] = len(self.queue)
        self.metadata["queue_discarded_at_cleanup_bytes"] = self.queued_bytes
        self.queue.clear()
        self.queued_bytes = 0
        for sock in self.sockets:
            sock.close()


def run_case(binary, fixture, name, timeout, setup_timeout, post_trigger_timeout):
    root = fixture / name
    root.mkdir()
    downloads = root / "downloads"
    target = downloads / "five-mib.bin"
    processes = PATHS.Processes(root)
    relay = None
    started = time.monotonic()
    process_stopped_at = {}
    result = {"case": name, "timeout_seconds": timeout, "errors": [], "denied": False, "server_max_requests": None, "observed_body_high_water_bytes": 0}
    timing = result["boundary_timing"] = {
        "clock_origin": "run_case monotonic start, including server startup",
        "setup_timeout_seconds": setup_timeout if name == "permanent_outage" else None,
        "independent_post_trigger_timeout_seconds": post_trigger_timeout if name == "permanent_outage" else None,
        "independent_post_trigger_bound_enforced": name == "permanent_outage",
        "trigger_elapsed_seconds": None,
        "post_trigger_deadline_elapsed_seconds": None,
        "process_stop_elapsed_seconds": {},
        "observed_post_trigger_stop_interval_seconds": None,
        "supervisor_poll_interval_seconds": 0.01,
        "cleanup_wait_cap_seconds": 12,
        "setup_deadline_fired": False,
        "post_trigger_deadline_fired": False,
    }
    try:
        command = [str(binary), "server", "--listen", "127.0.0.1:0", "--cert", str(fixture / "server.pem"), "--key", str(fixture / "server.key"), "--www", str(fixture / "www"), "--timeout-seconds", str(timeout), "--ecn", "on"]
        result["server_command"] = command
        server = processes.start("server", command)
        startup = time.monotonic() + 5
        address = None
        while time.monotonic() < startup:
            for line in processes.text("server", "stderr").splitlines():
                if line.startswith("listening "):
                    address = line.split()[1]
                    break
            if address:
                break
            if server.poll() is not None:
                raise RuntimeError("HQ startup failed: " + processes.text("server", "stderr"))
            time.sleep(0.01)
        if address is None:
            raise RuntimeError("HQ server did not announce listening address")
        result["server_address"] = address
        relay = BoundaryRelay(address, target, name)
        command = [str(binary), "client", "--connect", relay.address, "--server-name", "localhost", "--ca", str(fixture / "ca.pem"), "--downloads", str(downloads), "--request", "/five-mib.bin", "--timeout-seconds", str(timeout), "--ecn", "on"]
        result["client_command"] = command
        processes.start("client", command)
        deadline = time.monotonic() + timeout + 5
        while any(process.poll() is None for process in processes.processes.values()):
            observed_now = time.monotonic()
            for role, process in processes.processes.items():
                if process.poll() is not None:
                    process_stopped_at.setdefault(role, observed_now)
            if name == "permanent_outage":
                if relay.boundary_at is None and observed_now >= started + setup_timeout:
                    timing["setup_deadline_fired"] = True
                    raise RuntimeError("setup deadline reached before final-file trigger; invalid outage fixture")
                if relay.boundary_at is not None and observed_now >= relay.boundary_at + post_trigger_timeout:
                    timing["post_trigger_deadline_fired"] = True
                    raise RuntimeError("independent post-trigger deadline reached; stopping remaining HQ processes")
            for path in (target, *downloads.glob(".hibana-*.part")):
                try:
                    result["observed_body_high_water_bytes"] = max(result["observed_body_high_water_bytes"], path.stat().st_size)
                except FileNotFoundError:
                    pass
            if relay.error:
                raise RuntimeError("relay failed: " + relay.error)
            if time.monotonic() >= deadline:
                raise RuntimeError("HQ processes exceeded bounded timeout")
            time.sleep(0.01)
        # Drain only the already bounded relay queue, without prolonging peer
        # execution or inventing delivery to a socket after process retirement.
        drain_deadline = time.monotonic() + DELAY_SECONDS + 0.1
        while relay.queue and time.monotonic() < drain_deadline:
            time.sleep(0.01)
    except Exception as error:
        result["errors"].append(f"{type(error).__name__}: {error}")
        result["denied"] = isinstance(error, PermissionError) or PATHS.permission_denied(str(error))
    finally:
        processes.finish()
        stopped_now = time.monotonic()
        for role in processes.processes:
            process_stopped_at.setdefault(role, stopped_now)
        timing["process_stop_elapsed_seconds"] = {role: round(at - started, 6) for role, at in process_stopped_at.items()}
        if relay:
            relay.close()
            timing["relay_started_elapsed_seconds"] = round(relay.started - started, 6)
            if relay.boundary_at is not None:
                timing["trigger_elapsed_seconds"] = round(relay.boundary_at - started, 6)
                if name == "permanent_outage":
                    timing["post_trigger_deadline_elapsed_seconds"] = round(relay.boundary_at + post_trigger_timeout - started, 6)
                if process_stopped_at:
                    timing["observed_post_trigger_stop_interval_seconds"] = round(max(process_stopped_at.values()) - relay.boundary_at, 6)
            result["relay"] = relay.metadata
            result["relay_error"] = relay.error
            if relay.error:
                result["errors"].append(relay.error)
                result["denied"] |= PATHS.permission_denied(relay.error)
        for role, process in processes.processes.items():
            result[f"{role}_exit"] = process.returncode
            stdout, stderr = processes.text(role, "stdout"), processes.text(role, "stderr")
            result[f"{role}_stderr"] = stderr
            result["denied"] |= PATHS.permission_denied(stdout + stderr)
            try:
                result[role] = json.loads(stdout)
            except json.JSONDecodeError:
                result[role] = None
                result[f"{role}_unparsed_stdout"] = stdout
                result["errors"].append(f"{role} did not emit one valid JSON report")
        result["download"] = {"exists": target.exists(), "bytes": target.stat().st_size if target.exists() else 0, "sha256": HELP.sha256(target) if target.exists() else None, "remaining_partial_files": len(list(downloads.glob(".hibana-*.part")))}
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def validate(result, expected):
    def require(condition, message):
        if not condition:
            result["errors"].append(message)

    client, server = result.get("client") or {}, result.get("server") or {}
    relay = result.get("relay") or {}
    flows = relay.get("flows") or {}
    download = result["download"]
    require(download["bytes"] == SIZE and download["sha256"] == expected, "actual final file length/hash mismatch")
    require(download["remaining_partial_files"] == 0, "transfer retained partial file")
    require(relay.get("boundary_observed_bytes") == SIZE, "relay did not observe published final-file boundary")
    require(relay.get("unexpected_source_dropped") == 0, "relay observed unexpected sender")
    require(relay.get("queue_discarded_at_cleanup_datagrams") == 0, "relay cleanup discarded delayed packets")
    require("--max-requests" not in result.get("server_command", []), "server incorrectly used explicit completion goal")
    for flow in FLOWS:
        counts = flows.get(flow) or {}
        require(counts.get("observed_ecn", {}).get("2", 0) > 0, f"relay did not observe kernel ECT(0) {flow}")
        require(counts.get("forwarded_ecn", {}).get("2", 0) > 0, f"relay did not forward original kernel ECT(0) {flow}")
    result["full_file_verified"] = download["bytes"] == SIZE and download["sha256"] == expected
    result["both_connections_closed"] = all(peer.get("lifecycle_closed") is True for peer in (client, server))
    result["overall_connection_success"] = all(result.get(f"{role}_exit") == 0 and (result.get(role) or {}).get("status") == "success" and (result.get(role) or {}).get("files_completed") == 1 and (result.get(role) or {}).get("body_bytes") == SIZE and (result.get(role) or {}).get("lifecycle_closed") is True for role in ("client", "server"))
    if result["case"] == "permanent_outage":
        require(not result["overall_connection_success"], "permanent boundary outage did not prevent overall connection completion")
        require(any(flows.get(flow, {}).get("dropped_after", 0) > 0 for flow in FLOWS), "permanent boundary outage dropped no datagrams")
        for flow in FLOWS:
            counts = flows.get(flow) or {}
            require(counts.get("forwarded_after") == 0, f"permanent outage leaked post-boundary datagrams {flow}")
        if client.get("status") == "success":
            require(client.get("files_completed") == 1 and client.get("body_bytes") == SIZE, "successful client report omitted the FIN-complete body")
            require(client.get("certificate_chain_hostname_time_verified") is True, "successful client report omitted verified certificate evidence")
        else:
            # HQ error reports deliberately omit successful-connection fields.
            # A published file is still independently hashed and requires FIN;
            # do not fabricate a success report after the close phase fails.
            require(client.get("status") == "failure" and result.get("client_exit") not in (0, None), "negative client lacks an explicit success or failure outcome")
        result["negative_fin_evidence"] = "actual final filename is published only after consumed FIN; exact file hash checked independently of connection outcome"
        return
    require(result["overall_connection_success"], "full-file transfer did not reach successful Closed on both peers")
    require(client.get("authentication") == "verified-certificate" and client.get("certificate_chain_hostname_time_verified") is True, "client did not fully authenticate server certificate")
    require(server.get("authentication") == "peer-finished", "server did not verify client Finished")
    for role, peer in (("client", client), ("server", server)):
        require(peer.get("alpn") == "hq-interop" and peer.get("authenticated_packets", 0) > 0, f"{role} lacks authenticated HQ packet evidence")
    if result["case"] == "finite_loss":
        for flow in FLOWS:
            require(flows.get(flow, {}).get("dropped_after") == LOSS_LIMITS[flow], f"finite loss budget was not actually exercised {flow}")
    elif result["case"] == "finite_delay":
        require(relay.get("peak_queue_datagrams", 0) > 0, "finite delay queued no packets")
        require((relay.get("minimum_observed_delay_ms") or 0) >= DELAY_SECONDS * 1000, "actual forwarding delay was shorter than configured")
        for flow in FLOWS:
            require(flows.get(flow, {}).get("delayed_after", 0) > 0, f"finite delay did not exercise {flow}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--negative-timeout-seconds", type=int, default=40)
    parser.add_argument("--outage-setup-timeout-seconds", type=int, default=25, help="independent maximum time from case start to published final file")
    parser.add_argument("--outage-post-trigger-timeout-seconds", type=int, default=30, help="independent maximum wait after the actual final-file trigger before stopping remaining peers")
    parser.add_argument("--case", action="append", choices=CASES)
    args = parser.parse_args()
    if any(not 1 <= value <= 300 for value in (args.timeout_seconds, args.negative_timeout_seconds, args.outage_setup_timeout_seconds, args.outage_post_trigger_timeout_seconds)):
        parser.error("timeouts must be 1..300 seconds")
    if args.output.exists():
        parser.error("--output exists; preserve earlier evidence with a fresh output path")
    os.umask(0o077)
    selected = list(dict.fromkeys(args.case or CASES))
    started = time.monotonic()
    report = {"status": "FAILED", "scope": "direct-hq-only-authenticated-udp-post-file-boundary", "selected_cases": selected, "suite_complete": selected == list(CASES), "runs": {}, "errors": [], "expected_body_bytes": SIZE, "server_max_requests": None, "packet_classification": "opaque protected datagrams after actual final-file visibility; no assertion that any packet contains CLOSE", "complementary_evidence_required": "independent encrypted in-memory tests must initiate and identify CLOSE explicitly", "not_claimed": ["Neqo interoperability", "quic-interop-runner", "decoded wire CLOSE coverage", "close packet delivery merely from local Closed", "embedded RAM limits", "Pico hardware"]}
    try:
        binary = args.binary.resolve(strict=True)
        report["binary"] = str(binary)
        report["expected_binary_sha256"] = args.expected_binary_sha256
        report["binary_sha256"] = HELP.sha256(binary)
        if report["binary_sha256"] != args.expected_binary_sha256:
            raise RuntimeError("binary differs from the explicitly frozen expected hash")
        for label, path in (("harness", Path(__file__)), ("shared_helper", Path(PATHS.__file__)), ("fixture_helper", Path(HELP.__file__))):
            report[label + "_sha256"] = HELP.sha256(path)
        with tempfile.TemporaryDirectory(prefix="hibana-hq-close-boundary-") as directory:
            fixture = Path(directory)
            (fixture / "www").mkdir()
            HELP.certificates(fixture)
            source = fixture / "www/five-mib.bin"
            with source.open("wb") as body:
                for block in range(5 * 1024):
                    body.write(bytes([block % 251]) * 1024)
            report["expected_sha256"] = HELP.sha256(source)
            for name in selected:
                timeout = args.negative_timeout_seconds if name == "permanent_outage" else args.timeout_seconds
                result = run_case(binary, fixture, name, timeout, args.outage_setup_timeout_seconds, args.outage_post_trigger_timeout_seconds)
                validate(result, report["expected_sha256"])
                if name == "permanent_outage" and (result.get("relay") or {}).get("boundary_observed_bytes") != SIZE:
                    result["status"] = "INVALID_FIXTURE"
                else:
                    result["status"] = "FAILED" if result["errors"] else ("PASSED_NEGATIVE" if name == "permanent_outage" else "PASSED")
                report["runs"][name] = result
                print(f"{name}: {result['status']} ({result['elapsed_seconds']}s)", file=sys.stderr, flush=True)
                if result["denied"]:
                    report["errors"].append(f"socket operation denied in {name}; stopped without an alternate route")
                    break
        report["binary_sha256_after"] = HELP.sha256(binary)
        if report["binary_sha256_after"] != report["binary_sha256"]:
            report["errors"].append("binary changed during execution")
        if len(report["runs"]) == len(selected) and not report["errors"] and all(run["status"] in ("PASSED", "PASSED_NEGATIVE") for run in report["runs"].values()):
            report["status"] = "PASSED"
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
        print(f"{report['status']}: {args.output}", flush=True)
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
