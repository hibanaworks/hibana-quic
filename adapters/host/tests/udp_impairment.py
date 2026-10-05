"""Bounded loopback UDP impairment fixture, not a QUIC implementation.

Packets remain opaque. Delay, deterministic loss and corruption are applied in
both directions without modifying host network settings or reference software.
This does not reproduce ns-3 and cannot issue an official interop verdict.
"""
from collections import Counter
import heapq
import selectors
import socket
import threading
import time


class UdpProxy:
    MAX_QUEUED_BYTES = 16 * 1024 * 1024

    def __init__(self, server, *, delay=0.0, drop_every=0, corrupt_every=0,
                 blackhole_after_bytes=0, blackhole_seconds=0.0):
        if blackhole_after_bytes < 0 or blackhole_seconds < 0 or bool(blackhole_after_bytes) != bool(blackhole_seconds):
            raise ValueError('blackhole requires a positive byte threshold and duration')
        self.server = server
        self.delay = delay
        self.drop_every = drop_every
        self.corrupt_every = corrupt_every
        self.blackhole_after_bytes = blackhole_after_bytes
        self.blackhole_seconds = blackhole_seconds
        self._wire_bytes = 0
        self._blackhole_started = None
        self.stats = Counter()
        self._counts = Counter()
        self._queue = []
        self._queued_bytes = 0
        self._sequence = 0
        self._stop = threading.Event()
        self._error = None
        self._client = None
        self._front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._front.bind(('127.0.0.1', 0))
        self.address = self._front.getsockname()
        self._back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._back.bind(('127.0.0.1', 0))
        self._back.connect(server)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join(timeout=2)
        self._front.close()
        self._back.close()
        if self._thread.is_alive():
            raise RuntimeError('UDP impairment fixture did not stop')
        if self._error is not None:
            raise RuntimeError('UDP impairment fixture failed') from self._error

    def _enqueue(self, direction, data):
        self._counts[direction] += 1
        number = self._counts[direction]
        self.stats[direction + '_received'] += 1
        self._wire_bytes += len(data)
        if self.blackhole_after_bytes and self._wire_bytes >= self.blackhole_after_bytes:
            now = time.monotonic()
            if self._blackhole_started is None:
                self._blackhole_started = now
            if now - self._blackhole_started < self.blackhole_seconds:
                self.stats[direction + '_blackhole_dropped'] += 1
                return
        if self.drop_every and number % self.drop_every == 0:
            self.stats[direction + '_dropped'] += 1
            return
        if self.corrupt_every and number % self.corrupt_every == 0:
            changed = bytearray(data)
            if changed:
                changed[-1] ^= 1
            data = bytes(changed)
            self.stats[direction + '_corrupted'] += 1
        if self._queued_bytes + len(data) > self.MAX_QUEUED_BYTES:
            self.stats['capacity_drops'] += 1
            return
        self._sequence += 1
        self._queued_bytes += len(data)
        heapq.heappush(self._queue, (
            time.monotonic() + self.delay, self._sequence, direction, data
        ))
        self.stats['peak_queued_bytes'] = max(
            self.stats['peak_queued_bytes'], self._queued_bytes
        )

    def _flush(self):
        now = time.monotonic()
        while self._queue and self._queue[0][0] <= now:
            _, _, direction, data = heapq.heappop(self._queue)
            self._queued_bytes -= len(data)
            if direction == 'to_server':
                self._back.send(data)
            elif self._client is not None:
                self._front.sendto(data, self._client)
            self.stats[direction + '_forwarded'] += 1

    def _run(self):
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self._front, selectors.EVENT_READ, 'to_server')
                selector.register(self._back, selectors.EVENT_READ, 'to_client')
                while not self._stop.is_set():
                    self._flush()
                    timeout = 0.02
                    if self._queue:
                        timeout = min(timeout, max(0, self._queue[0][0] - time.monotonic()))
                    for key, _ in selector.select(timeout):
                        try:
                            data, sender = key.fileobj.recvfrom(65535)
                        except ConnectionRefusedError:
                            self.stats['destination_unavailable'] += 1
                            continue
                        if key.data == 'to_server':
                            if self._client is not None and sender != self._client:
                                self.stats['foreign_client_drops'] += 1
                                continue
                            self._client = sender
                        self._enqueue(key.data, data)
                    # Flush zero-delay traffic in this readiness turn. Otherwise
                    # the select timeout injects an unrequested 20 ms delay.
                    self._flush()
        except Exception as error:
            self._error = error
            self._stop.set()

class EarlyWireProbe(UdpProxy):
    """Conservative packet-byte upper bounds, never decrypted payload claims."""
    def __init__(self, server):
        super().__init__(server)
        self._server_cids = set()

    def _enqueue(self, direction, data):
        if direction == 'to_client' and len(data) >= 7 and data[0] & 0xf0 == 0xc0 and data[1:5] == b'\x00\x00\x00\x01':
            at = 6 + data[5]
            if at < len(data) and data[at] <= 20 and at + 1 + data[at] <= len(data):
                if len(self._server_cids) < 16:
                    self._server_cids.add(data[at + 1:at + 1 + data[at]])
        if direction == 'to_server':
            try:
                offset = 0
                for kind, length in self.packet_lengths(data):
                    self.stats[kind + '_wire_bytes'] += length
                    self.stats[kind + '_packets'] += 1
                    if kind == 'one_rtt':
                        self.stats['one_rtt_protected_payload_upper_bound'] += self.short_payload_upper_bound(data[offset:offset + length], self._server_cids)
                    offset += length
            except ValueError as error:
                self.stats['unclassified_client_datagrams'] += 1
                self.stats['unclassified_client_wire_bytes'] += len(data)
                self.stats['parse_' + str(error)] += 1
        super()._enqueue(direction, data)

    @staticmethod
    def short_payload_upper_bound(packet, server_cids):
        lengths = [len(cid) for cid in server_cids if packet[1:1 + len(cid)] == cid]
        if not lengths:
            raise ValueError('unobserved server CID')
        # Remove only the clear first byte and an actually observed destination
        # CID. Keep the protected PN, AEAD tag and padding: this is at least the
        # runner's protected_payload length, without guessing decryption state.
        return len(packet) - 1 - min(lengths)

    @staticmethod
    def packet_lengths(data):
        def varint(at):
            if at >= len(data):
                raise ValueError('truncated varint')
            length = 1 << (data[at] >> 6)
            if at + length > len(data):
                raise ValueError('truncated varint')
            return int.from_bytes(data[at:at + length], 'big') & ((1 << (8 * length - 2)) - 1), at + length
        offset = 0
        packets = []
        while offset < len(data):
            first = data[offset]
            if offset and not any(data[offset:]):
                # Neqo's datagram-level zero suffix is outside the encoded
                # packet Length. Preserve it separately, not as a QUIC packet.
                packets.append(('trailing_zero_bytes', len(data) - offset))
                break
            # The reference can grease the fixed bit after negotiation. Header
            # form still identifies short packets; the caller additionally
            # requires an actually observed server CID before counting payload.
            if not first & 0x80:
                if len(data) - offset < 18:  # first byte + PN + AEAD tag
                    raise ValueError('short packet length')
                packets.append(('one_rtt', len(data) - offset))
                break
            if offset + 6 > len(data) or data[offset + 1:offset + 5] != b'\x00\x00\x00\x01':
                raise ValueError('not bounded QUIC v1')
            at = offset + 6 + data[offset + 5]
            if at >= len(data):
                raise ValueError('destination CID')
            at += 1 + data[at]
            if at > len(data):
                raise ValueError('source CID')
            kind = (first >> 4) & 3
            if kind == 3:
                packets.append(('retry', len(data) - offset))
                break
            if kind == 0:
                token, at = varint(at)
                at += token
            length, at = varint(at)
            end = at + length
            if end > len(data) or length == 0 or end <= offset:
                raise ValueError('packet length')
            packets.append((('initial', 'zero_rtt', 'handshake')[kind], end - offset))
            offset = end
        return packets
