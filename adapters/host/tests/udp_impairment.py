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
                 blackhole_after_bytes=0, blackhole_seconds=0.0, client_endpoints=1, burst=1):
        if blackhole_after_bytes < 0 or blackhole_seconds < 0 or bool(blackhole_after_bytes) != bool(blackhole_seconds):
            raise ValueError('blackhole requires a positive byte threshold and duration')
        if not 1 <= client_endpoints <= 64:
            raise ValueError("fixture permits 1..64 bounded sequential endpoints")
        if burst < 1 or any(period and burst > period for period in (drop_every, corrupt_every)):
            raise ValueError("burst must fit its impairment period")
        self.burst = burst
        self._client_endpoints = client_endpoints
        self._seen_clients = set()
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
        family = socket.AF_INET6 if ':' in server[0] else socket.AF_INET
        self._loopback = '::1' if family == socket.AF_INET6 else '127.0.0.1'
        self._front = socket.socket(family, socket.SOCK_DGRAM)
        self._front.bind((self._loopback, 0))
        self.address = self._front.getsockname()
        self._back = socket.socket(family, socket.SOCK_DGRAM)
        self._back.bind((self._loopback, 0))
        self._back.connect(server)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _accept_client(self, sender):
        if sender == self._client:
            return True
        if sender[0] != self._loopback or sender in self._seen_clients or len(self._seen_clients) >= self._client_endpoints:
            return False
        self._seen_clients.add(sender)
        self._client = sender
        return True

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
        if self.drop_every and number % self.drop_every < self.burst:
            self.stats[direction + '_dropped'] += 1
            return
        if self.corrupt_every and number % self.corrupt_every < self.burst:
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
                            if not self._accept_client(sender):
                                self.stats['foreign_client_drops'] += 1
                                continue
                        self._enqueue(key.data, data)
                    # Flush zero-delay traffic in this readiness turn. Otherwise
                    # the select timeout injects an unrequested 20 ms delay.
                    self._flush()
        except Exception as error:
            self._error = error
            self._stop.set()


class MultiEndpointProxy(UdpProxy):
    """Bounded opaque UDP routing that preserves every client's return path.

    Old connections can deliver their final ACK/close while a later connection
    is active. A delayed reply keeps its original destination, not the most
    recently observed client. No QUIC packet parsing or outcome is involved.
    """
    def __init__(self, server, **options):
        super().__init__(server, **options)
        self._routes = {}
        self._destinations = {}
        self._incoming_route = None

    def __exit__(self, *args):
        try:
            super().__exit__(*args)
        finally:
            for sock in self._routes.values():
                sock.close()

    def _enqueue(self, direction, data):
        previous = self._sequence
        super()._enqueue(direction, data)
        if self._sequence != previous:
            self._destinations[self._sequence] = self._incoming_route

    def _flush(self):
        now = time.monotonic()
        while self._queue and self._queue[0][0] <= now:
            _, sequence, direction, data = heapq.heappop(self._queue)
            self._queued_bytes -= len(data)
            client = self._destinations.pop(sequence)
            try:
                if direction == 'to_server':
                    self._routes[client].send(data)
                else:
                    self._front.sendto(data, client)
            except ConnectionRefusedError:
                # A real peer may close while a delayed datagram is queued.
                # Record the rejected send; never count it as forwarded.
                self.stats[direction + '_destination_unavailable'] += 1
                continue
            self.stats[direction + '_forwarded'] += 1

    def _run(self):
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self._front, selectors.EVENT_READ, ('to_server', None))
                while not self._stop.is_set():
                    self._flush()
                    timeout = 0.02
                    if self._queue:
                        timeout = min(timeout, max(0, self._queue[0][0] - time.monotonic()))
                    for key, _ in selector.select(timeout):
                        direction, client = key.data
                        try:
                            data, sender = key.fileobj.recvfrom(65535)
                        except ConnectionRefusedError:
                            self.stats['destination_unavailable'] += 1
                            continue
                        if direction == 'to_server':
                            client = sender
                            if client not in self._routes:
                                if client[0] != '127.0.0.1' or len(self._routes) >= self._client_endpoints:
                                    self.stats['foreign_client_drops'] += 1
                                    continue
                                back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                back.bind(('127.0.0.1', 0))
                                back.connect(self.server)
                                self._routes[client] = back
                                selector.register(back, selectors.EVENT_READ, ('to_client', client))
                        self._incoming_route = client
                        self._enqueue(direction, data)
                    self._flush()
        except Exception as error:
            self._error = error
            self._stop.set()


class EarlyWireProbe(UdpProxy):
    """Conservative packet-byte upper bounds, never decrypted payload claims."""
    def __init__(self, server, *, client_endpoints=1, drop_first_early=False):
        super().__init__(server, client_endpoints=client_endpoints)
        self._server_cids = set()
        self._drop_first_early = drop_first_early

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
        if direction == 'to_server' and self._drop_first_early and not self.stats['first_early_dropped']:
            try:
                if any(kind == 'zero_rtt' for kind, _ in self.packet_lengths(data)):
                    self.stats['first_early_dropped'] += 1
                    return
            except ValueError:
                pass  # Already counted as unclassified above; never hides a bad observation.
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


class VersionWireProbe(UdpProxy):
    """Read actual invariant headers without decrypting or changing packets."""
    @staticmethod
    def _varint(data, offset):
        if offset >= len(data): raise ValueError('truncated varint')
        n = 1 << (data[offset] >> 6)
        if offset+n > len(data): raise ValueError('truncated varint')
        return int.from_bytes(data[offset:offset+n],'big') & ((1 << (n*8-2))-1), offset+n
    def _enqueue(self,direction,data):
        offset=0
        try:
            while offset<len(data) and data[offset]&0x80:
                start=offset; version=int.from_bytes(data[start+1:start+5],'big')
                if version not in (1,0x6b3343cf): break
                kind=(data[start]>>4)&3
                if version==0x6b3343cf: kind=(kind-1)&3
                self.stats[f'{direction}_v{version:x}_type{kind}']+=1
                offset+=5; offset+=1+data[offset]; offset+=1+data[offset]
                if kind==3: break
                if kind==0:
                    n,offset=self._varint(data,offset); offset+=n
                n,offset=self._varint(data,offset);offset+=n
                if offset>len(data): raise ValueError('truncated packet')
        except (IndexError,ValueError): self.stats['malformed_invariant_headers']+=1
        super()._enqueue(direction,data)

class RebindingWireProbe(UdpProxy):
    """Finite loopback NAT changes; never changes host network settings."""
    def __init__(self,server,*,change_address=False):
        super().__init__(server,delay=0.002)
        self._change_address=change_address;self._next_change=1<<20;self._changes=0
        self.paths=[self._back.getsockname()]
    def _run(self):
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self._front,selectors.EVENT_READ,'to_server')
                selector.register(self._back,selectors.EVENT_READ,'to_client')
                while not self._stop.is_set():
                    if self._wire_bytes>=self._next_change and self._changes<2:
                        old=self._back;fresh=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self._changes+=1
                        fresh.bind((f'127.0.0.{self._changes+1}' if self._change_address else '127.0.0.1',0));fresh.connect(self.server)
                        selector.unregister(old);selector.register(fresh,selectors.EVENT_READ,'to_client');self._back=fresh;old.close()
                        self.paths.append(fresh.getsockname());self.stats['actual_rebindings']+=1;self._next_change+=2<<20
                    self._flush();timeout=0.01
                    if self._queue:timeout=min(timeout,max(0,self._queue[0][0]-time.monotonic()))
                    for key,_ in selector.select(timeout):
                        try:data,sender=key.fileobj.recvfrom(65535)
                        except ConnectionRefusedError:self.stats['destination_unavailable']+=1;continue
                        if key.data=='to_server' and not self._accept_client(sender):self.stats['foreign_client_drops']+=1;continue
                        self._enqueue(key.data,data)
        except BaseException as error:self._error=error;self._stop.set()
