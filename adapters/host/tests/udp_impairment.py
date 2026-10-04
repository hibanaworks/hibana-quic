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

    def __init__(self, server, *, delay=0.0, drop_every=0, corrupt_every=0):
        self.server = server
        self.delay = delay
        self.drop_every = drop_every
        self.corrupt_every = corrupt_every
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
        except Exception as error:
            self._error = error
            self._stop.set()
